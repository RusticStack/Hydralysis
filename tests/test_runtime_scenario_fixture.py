"""The runtime scenario end to end on the fake frida binding (Z11, audit C2-29): the CI mirror of
tools/scenarios/kotor_vfs_lookup.py.

The code under test is real: the scenario driver, the runtime host, a real worker process with its authenticated IPC,
the capture log, the snapshot, the evidence ledger and the bundle. Only Frida is the fake (tests/fakefrida): the
"game" is this Python executable, spawned for real and never injected into. What the fake cannot do is stated in
the run record as a skip, not hidden: it exposes the main module only (no export table to hook by name) and there is
no analysis engine (no writers step). The game-free analogue on a real process is `scenario` in
tests/fixtures/verify_fixtures.py (MSVC and Frida; manual); a live game run is not authorized here.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import evidence_bundle as bundles
from hydralysis import proc
from hydralysis.client import Client
from hydralysis.pe import Image
from support import REPOSITORY, workdir

sys.path.insert(0, str(REPOSITORY / "tools" / "scenarios"))
import kotor_vfs_lookup as scenario  # noqa: E402

FAKE_FRIDA = REPOSITORY / "tests" / "fakefrida" / "frida"
EXE = Path(sys.executable).resolve()
ENTRY = Image(EXE).pe.OPTIONAL_HEADER.AddressOfEntryPoint        # code: a prologue can be read from the file here
PROLOGUE = Image(EXE).read_rva(ENTRY, 5)
HEAD = EXE.read_bytes()[:5]            # a probe at rva 0 covers no call; the entry point's first bytes may hold one


def spec(**changes) -> dict:
    digest = hashlib.sha256(EXE.read_bytes()).hexdigest()
    head = " ".join("%02X" % byte for byte in HEAD)
    prologue = " ".join("%02X" % byte for byte in PROLOGUE)
    value = {"name": "mirror", "game": "fixture", "exe": EXE.name, "fixture": True, "sha256": digest,
             "capture_first": True,           # the fake probe fires when it is installed, not after the resume
             "argv": ["-c", "import time;time.sleep(120)"],
             "sites": [{"name": "head", "address": "rva:%#x" % ENTRY, "expect": prologue}],
             "observe": [{"module": EXE.name, "rva": "0x0", "sha256": digest, "expect": head, "limit": 3,
                          "capture": [{"arg": 0, "as": "hex", "size": 3, "label": "name"}]}],
             "exports": [],
             "run": {"min_events": 5, "timeout_s": 20, "record_first": 3, "limit_reached": True},
             "typed_read": {"module": EXE.name, "rva": "0x0", "size": 4, "layout": [{"name": "magic", "offset": 0, "type": "u16"}],
                            "expect": {"magic": 0x5A4D}},
             "snapshot": {"regions": [{"name": "head", "module": EXE.name, "rva": "0x0", "size": 16}]},
             "writers": None,
             "patch_sites": [{"module": EXE.name, "rva": hex(ENTRY), "name": "entry"}],
             "allowed_skips": {"export_hooks": "the fake binding exposes the main module only and python.exe exports nothing",
                               "writers": "no analysis engine in the unit suite"}}
    value.update(changes)
    return value


class Mirror(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = workdir("scenario")
        cls.root = Path(cls.work.name)
        shutil.copytree(FAKE_FRIDA, cls.root / "state" / "runtime-backend" / "frida-17.24.3" / "frida")
        cls.patches = [patch.dict(os.environ, {"HYDRALYSIS_ROOT": str(cls.root / "state"), "HYDRALYSIS_FAKE_HITS": "5"})]
        os.environ.pop("HYDRALYSIS_CONFIG", None)
        for patcher in cls.patches:
            patcher.start()
        cls.client = Client()
        cls.pids: list[tuple[int, int]] = []

    @classmethod
    def tearDownClass(cls):
        import time
        for pid, created in cls.pids:        # the programs this test started through the scenario, identity-checked
            if proc.identity(pid, created):
                subprocess.run(["taskkill", "/PID", str(pid), "/F"] if os.name == "nt" else ["kill", "-9", str(pid)],
                               capture_output=True)
        for patcher in cls.patches:
            patcher.stop()
        deadline = time.monotonic() + 10
        while Path(cls.work.name).exists() and time.monotonic() < deadline:
            cls.work.cleanup()
            time.sleep(0.2)

    def setUp(self):
        self.logs = []
        self.install = self.root / ("install-%d" % id(self))
        self.install.mkdir()
        (self.install / "data.bin").write_bytes(b"original")
        self.out = self.root / ("out-%d" % id(self))

    def run_one(self, value=None, twice=False, **options):
        result = scenario.run_scenario(value or spec(), self.client, EXE.parent, self.out, self.install, twice, log=self.logs.append)
        for run in result["runs"]:
            self.remember(run)
        return result

    def remember(self, run):
        # tear-down kills what the run started: the session's state file names the target
        state = self.root / "state" / "runtime-sessions" / str(run.get("session")) / "state.json"
        try:
            data = json.loads(state.read_text())
            self.pids.append((int(data["pid"]), int(data["target_created_ms"])))
        except (OSError, ValueError, KeyError):
            pass

    def test_the_steps_run_in_order_and_what_cannot_run_is_a_stated_skip(self):
        result = self.run_one()
        run = result["runs"][0]
        self.assertTrue(result["ok"], json.dumps(run["steps"], indent=1, default=str))
        self.assertEqual([row["step"] for row in run["steps"]], list(scenario.STEPS))
        self.assertEqual(run["pass_sequence"], run["expected_pass_sequence"])
        self.assertEqual(run["pass_sequence"], ["verify_sites", "spawn", "observe", "capture", "resume", "typed_read", "snapshot",
                                                "detach", "evidence_add", "bundle_export"])
        self.assertEqual(set(run["skipped"]), {"export_hooks", "writers"})
        self.assertIn("exposes the main module only", run["skipped"]["export_hooks"])
        self.assertEqual(run["silent_drops"], [])

    def test_the_program_is_spawned_paused_probed_and_left_alive_with_its_file_untouched(self):
        run = self.run_one()["runs"][0]
        by = {row["step"]: row["detail"] for row in run["steps"]}
        self.assertEqual(by["spawn"]["state"], "spawn_paused")
        self.assertEqual(by["detach"]["patched_after_unload"], 0)
        self.assertTrue(by["detach"]["target_alive_after_detach"])
        self.assertTrue(by["resume"]["log_verifies"])
        self.assertEqual(by["typed_read"]["magic"], 0x5A4D)
        self.assertTrue(by["snapshot"]["compare_equal"])

    def test_a_limited_probe_states_the_loss_and_nothing_is_silent(self):
        run = self.run_one()["runs"][0]
        self.assertEqual(run["coverage"]["status"], "partial")
        self.assertIn("hit_limit_reached", run["limitations"])
        by = {row["step"]: row["detail"] for row in run["steps"]}
        self.assertEqual(list(by["resume"]["seen"].values()), [5])        # the probe counted five, recorded three
        self.assertTrue(run["limit_as_designed"])
        self.assertEqual(run["silent_drops"], [])

    def test_the_install_tree_hash_is_taken_before_and_after_and_is_unchanged(self):
        run = self.run_one()["runs"][0]
        self.assertTrue(run["install_tree"]["checked"])
        self.assertEqual(run["install_tree"]["before"], run["install_tree"]["after"])
        self.assertEqual(run["install_tree"]["before"], scenario.tree_hash(self.install))

    def test_the_bundle_verifies_and_holds_the_runs_claims_without_the_run_specific_ids(self):
        run = self.run_one()["runs"][0]
        loaded = bundles.load_bundle(Path(run["bundle"]))
        names = sorted(record["content"]["name"] for record in loaded["records"])
        self.assertEqual(names, ["mirror:0x0", "mirror:typed_read"])
        for record in loaded["records"]:
            self.assertFalse(record["content"]["from_capture"])           # a per-run id would break run to run equality
            self.assertIn("fixture_only", record["content"]["limitations"])
            self.assertEqual(record["content"]["subject"]["sha256"] if isinstance(record["content"].get("subject"), dict)
                             else record["content"].get("subject_sha256"), hashlib.sha256(EXE.read_bytes()).hexdigest())
        hook = next(r for r in loaded["records"] if r["content"]["name"] == "mirror:0x0")
        self.assertEqual(hook["content"]["parameters"]["first_events"], ["41 42 43"] * 3)
        self.assertEqual(hook["content"]["coverage"]["status"], "partial")
        self.assertEqual(hook["meta"]["provenance"]["capture"], run["capture"])   # the run-specific id lives in the volatile part

    def test_two_runs_give_bundles_that_compare_with_no_difference(self):
        result = self.run_one(twice=True)
        first, second = result["runs"]
        self.assertTrue(result["ok"], result["compare"])
        self.assertNotEqual(first["capture"], second["capture"])            # two real runs, two captures
        self.assertNotEqual(first["session"], second["session"])
        self.assertEqual(result["compare"]["status"], "equal")
        self.assertEqual(result["compare"]["changes"], [])
        self.assertEqual(first["bundle_id"], second["bundle_id"])

    def test_a_different_observation_is_a_difference_the_comparison_reports(self):
        result = self.run_one(twice=True)
        changed = copy.deepcopy(spec())
        changed["observe"][0]["capture"] = [{"arg": 0, "as": "hex", "size": 2, "label": "name"}]
        other = scenario.run_scenario(changed, self.client, EXE.parent, self.root / ("other-%d" % id(self)), self.install, False,
                                      log=self.logs.append)
        self.remember(other["runs"][0])
        compared = bundles.compare_bundles(Path(result["runs"][0]["bundle"]), Path(other["runs"][0]["bundle"]))
        self.assertEqual(compared["status"], "different")
        self.assertTrue(any(c["classification"] == "changed" for c in compared["changes"]))

    def test_a_wrong_prologue_stops_the_run_before_anything_is_spawned(self):
        value = spec()
        value["sites"] = [{"name": "head", "address": "rva:%#x" % ENTRY, "expect": "00 00 00 00 00"}]
        result = self.run_one(value)
        run = result["runs"][0]
        self.assertFalse(result["ok"])
        status = {row["step"]: row["status"] for row in run["steps"]}
        self.assertEqual(status["verify_sites"], "fail")
        self.assertEqual({v for k, v in status.items() if k != "verify_sites"}, {"not_run"})
        self.assertIsNone(run["session"])

    def test_a_failed_typed_read_ends_the_run_and_still_detaches_the_program(self):
        value = spec()
        value["typed_read"]["expect"] = {"magic": 1}
        result = self.run_one(value)
        run = result["runs"][0]
        status = {row["step"]: row["status"] for row in run["steps"]}
        self.assertFalse(result["ok"])
        self.assertEqual(status["typed_read"], "fail")
        self.assertEqual([status[s] for s in ("snapshot", "writers", "evidence_add", "bundle_export")], ["not_run"] * 4)
        self.assertEqual(status["detach"], "not_run" if not run["session"] else status["detach"])
        state = json.loads((self.root / "state" / "runtime-sessions" / run["session"] / "state.json").read_text())
        self.assertTrue(state.get("detached"))

    def test_a_probe_site_that_changed_from_the_file_is_not_probed(self):
        value = spec()
        value["observe"][0]["expect"] = "00 00 00 00 00"
        run = self.run_one(value)["runs"][0]
        self.assertEqual({row["step"]: row["status"] for row in run["steps"]}["observe"], "fail")
        self.assertIn("PROLOGUE MISMATCH", [row for row in run["steps"] if row["step"] == "observe"][0]["detail"])

    def test_a_skip_the_spec_does_not_allow_makes_the_run_fail(self):
        value = spec(allowed_skips={"export_hooks": "x"})          # writers is skipped but not allowed
        result = self.run_one(value)
        self.assertFalse(result["ok"])
        self.assertIn("writers", result["runs"][0]["skipped"])

    def test_the_profile_must_be_a_separate_folder_from_the_install(self):
        with self.assertRaisesRegex(ValueError, "separate folder"):
            scenario.Scenario(spec(), self.client, EXE.parent, self.out, EXE.parent, log=self.logs.append).run()
        with self.assertRaisesRegex(ValueError, "separate folder"):
            scenario.Scenario(spec(), self.client, self.install, self.out, self.install.parent, log=self.logs.append).run()


class Verdict(unittest.TestCase):
    """The pass/fail rules, without a process."""

    def scenario(self, closed, spec_changes=None):
        run = scenario.Scenario({**spec(), **(spec_changes or {})}, object(), Path("."), Path("."), None)
        run.closed = closed
        return run

    def test_events_lost_with_no_limitation_are_a_silent_drop(self):
        run = self.scenario({"limitations": ["single_run"], "hooks": [{"hook_id": "h", "seen": 9, "recorded": 3, "lost": 6}]})
        self.assertEqual(len(run.silent_drops()), 1)
        self.assertIn("lost 6", run.silent_drops()[0])

    def test_the_same_loss_with_its_limitation_is_not_silent(self):
        run = self.scenario({"limitations": ["hit_limit_reached", "single_run"], "hooks": [{"hook_id": "h", "lost": 6}]})
        self.assertEqual(run.silent_drops(), [])

    def test_a_probe_that_could_not_count_needs_the_limitation_that_says_so(self):
        silent = self.scenario({"limitations": ["single_run"], "hooks": [{"hook_id": "h", "lost": None}]})
        stated = self.scenario({"limitations": ["runtime:counters_unavailable"], "hooks": [{"hook_id": "h", "lost": None}]})
        self.assertEqual(len(silent.silent_drops()), 1)
        self.assertEqual(stated.silent_drops(), [])

    def test_a_changed_install_tree_fails_the_run(self):
        run = self.scenario({"limitations": [], "hooks": []}, {"run": {}})
        run.steps = [{"step": s, "status": "pass", "detail": {}} for s in scenario.STEPS]
        run.spec["allowed_skips"] = {}
        self.assertTrue(run._result("a", "a")["ok"])
        result = run._result("a", "b")
        self.assertFalse(result["ok"])
        self.assertFalse(result["install_tree"]["unchanged"])

    def test_a_pass_sequence_that_differs_from_the_recorded_one_fails_the_run(self):
        run = self.scenario({"limitations": [], "hooks": []}, {"run": {}, "allowed_skips": {}})
        run.steps = [{"step": s, "status": "pass", "detail": {}} for s in scenario.STEPS]
        run.steps[3]["status"] = "skipped"
        self.assertFalse(run._result(None, None)["ok"])
        self.assertEqual(run._result(None, None)["pass_sequence"], [s for s in scenario.STEPS if s != "export_hooks"])

    def test_a_limit_the_spec_expects_to_be_reached_but_was_not_fails_the_run(self):
        run = self.scenario({"limitations": ["single_run"], "hooks": []}, {"allowed_skips": {}})
        run.steps = [{"step": s, "status": "pass", "detail": {}} for s in scenario.STEPS]
        self.assertFalse(run._result(None, None)["limit_as_designed"])
        self.assertFalse(run._result(None, None)["ok"])


class Pieces(unittest.TestCase):
    def test_tree_hash_changes_with_content_name_and_new_files(self):
        work = workdir("tree")
        self.addCleanup(work.cleanup)
        root = Path(work.name)
        (root / "a.txt").write_text("1")
        first = scenario.tree_hash(root)
        self.assertEqual(first, scenario.tree_hash(root))
        (root / "a.txt").write_text("2")
        second = scenario.tree_hash(root)
        (root / "b").mkdir()
        (root / "b" / "c").write_text("x")
        self.assertEqual(len({first, second, scenario.tree_hash(root)}), 3)

    def test_the_game_spec_lists_export_hooks_and_no_address_it_cannot_prove(self):
        game = scenario.load_spec("kotor")
        self.assertEqual([hook["export"] for hook in game["exports"]], ["CreateFileW", "CreateFileA"])
        self.assertEqual(game["observe"], [])
        self.assertEqual(game["sites"], [])
        self.assertTrue(all("rva" not in hook for hook in game["exports"]))
        self.assertIn("N4", game["owner_decision"])

    def test_the_game_is_never_started_from_a_folder_that_has_no_such_executable(self):
        work = workdir("noprofile")
        self.addCleanup(work.cleanup)
        class Client:
            def runtime(self, *args, **options):
                raise AssertionError("nothing may be asked of the runtime")
        with self.assertRaises(FileNotFoundError):
            scenario.Scenario(scenario.load_spec("kotor"), Client(), Path(work.name), Path(work.name) / "out").run()

    def test_the_fixture_spec_probes_by_rva_with_the_files_own_bytes_and_stops_through_a_file(self):
        digest = hashlib.sha256(EXE.read_bytes()).hexdigest()
        manifest = {"x64/flow_fixture.exe": {"path": str(EXE), "sha256": digest, "image_base": "0x140000000",
                                             "functions": {"fx_exported": hex(0x140000000 + ENTRY)}, "globals": {"g_config": "0x140000800"}}}
        value = scenario.fixture_spec(manifest, "x64", "C:/scratch/stop")
        self.assertEqual(value["stop_file"], "C:/scratch/stop")
        self.assertEqual(value["argv"], ["C:/scratch/stop"])
        self.assertEqual(value["observe"][0]["rva"], hex(ENTRY))
        self.assertEqual(value["observe"][0]["expect"], value["sites"][0]["expect"])
        self.assertEqual(len(value["observe"][0]["expect"].split()), 8)
        self.assertGreater(value["run"]["min_events"], value["observe"][0]["limit"])      # the limit is reached by design

    def test_the_command_line_names_its_options(self):
        process = subprocess.run([sys.executable, str(REPOSITORY / "tools" / "scenarios" / "kotor_vfs_lookup.py"), "--help"],
                                 capture_output=True, text=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stderr)
        for option in ("--profile", "--install", "--spec", "--twice"):
            self.assertIn(option, process.stdout)


if __name__ == "__main__":
    unittest.main()
