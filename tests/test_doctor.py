"""Y4b: `backend action=doctor` (PROTOCOL-3.md 7.1): read-only, starts nothing, one finding per section."""

from __future__ import annotations

import json
import os
import subprocess
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import api, doctor, hydra, lineage
from test_commit import World


class FakeDaemonHandle:
    """The launcher's Daemon: counts every attach so a test can prove none happened."""
    attaches = 0
    alive = False
    hello = {"protocol": 3, "hydraVersion": "12.3-hydra.4", "paths": {"state": "S"}, "platform": "windows-x64",
             "analysisIdentity": {"decompilerHash": "abc"}}

    def __init__(self, ghidra, state, instance):
        self.state, self.instance = state, instance

    def read_endpoint(self):
        return {"pid": 4242, "port": 1} if self.alive else None

    def jvm_alive(self):
        return self.alive

    def attach(self, client="", harness=""):
        type(self).attaches += 1
        return Session(type(self).hello)


class Session:
    def __init__(self, hello):
        self.hello, self.calls, self.closed = hello, [], False

    def call(self, command, **_):
        self.calls.append(command)
        if command == "health":
            return {"state": "ok", "schedulerLockOk": True}
        if command == "status":
            return {"clients": [{"id": 1, "protocol": 2}, {"id": 2, "protocol": 3}], "memory": {"usedMb": 10}}
        return {"pong": True}

    def close(self):
        self.closed = True


class FakeModule(fakehydra.FakeClientModule):
    Daemon = FakeDaemonHandle


class Doctor(World, unittest.TestCase):
    def setUp(self):
        super().setUp()
        FakeDaemonHandle.attaches, FakeDaemonHandle.alive = 0, False
        patcher = patch("hydralysis.hydra.load_client", return_value=FakeModule)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.settings["hydra_dir"] = str(self.root / "engine")
        self.settings["hydra_client"] = str(self.root / "engine" / "client.py")

    def run_doctor(self, **options):
        return json.loads(api.dispatch("doctor", "x", {"tool": "backend", "action": "doctor", "options": options, "args": {},
                                                       "settings": self.settings}))

    def test_the_doctor_is_registered_and_not_a_stub(self):
        self.assertIs(api.handler("doctor"), doctor)

    def test_no_daemon_means_zero_attaches_zero_engine_calls_and_no_process_started(self):
        before = list(self.daemon.calls)
        with patch.object(subprocess, "Popen", side_effect=AssertionError("a process was started")), \
                patch.object(subprocess, "run", side_effect=AssertionError("a process was started")), \
                patch("hydralysis.hydra.Engine", side_effect=AssertionError("an Engine was made")):
            reply = self.run_doctor(verbose=True)
        self.assertEqual(FakeDaemonHandle.attaches, 0)
        self.assertEqual(self.daemon.calls, before)
        self.assertEqual(reply["sections"]["daemon"]["daemon"], "not_running")

    def test_one_finding_per_section(self):
        report = doctor.diagnose(self.settings)
        self.assertEqual(list(report.sections), list(doctor.SECTIONS))
        for name, section in report.sections.items():
            self.assertTrue(section["findings"], name)

    def test_a_running_daemon_is_joined_once_and_the_hello_is_cited(self):
        FakeDaemonHandle.alive = True
        reply = self.run_doctor(verbose=True)
        self.assertEqual(FakeDaemonHandle.attaches, 1)
        engine = reply["sections"]["engine"]
        self.assertEqual(engine["paths"], {"state": "S"})
        self.assertEqual(engine["platform"], "windows-x64")
        self.assertEqual(engine["analysisIdentity"], {"decompilerHash": "abc"})
        self.assertEqual(reply["sections"]["clients"]["by_protocol"], {"2": 1, "3": 1})
        self.assertEqual(reply["sections"]["daemon"]["daemon"], "running")

    def test_a_hydra3_engine_gets_the_old_engine_warning(self):
        FakeDaemonHandle.alive = True
        with patch.object(FakeDaemonHandle, "hello", {"protocol": 2, "hydraVersion": "12.3-hydra.3"}):
            ids = [item["id"] for item in self.run_doctor()["findings"]]
        self.assertIn("engine_older_than_hydra4", ids)

    def test_a_wedged_daemon_is_an_error_finding(self):
        FakeDaemonHandle.alive = True
        with patch.object(FakeDaemonHandle, "attach", side_effect=FakeModule.LaunchError("no_answer")):
            reply = self.run_doctor()
        self.assertIn("daemon_no_answer", [item["id"] for item in reply["findings"]])
        self.assertEqual(reply["summary"]["errors"], 1)

    def test_leftover_tmp_files_are_reported_and_never_deleted(self):
        data = Path(self.settings["root"])
        data.mkdir(parents=True, exist_ok=True)
        old = data / "x.json.abc.tmp"
        old.write_text("x")
        os.utime(old, (time.time() - 3600, time.time() - 3600))
        young = data / "y.tmp"
        young.write_text("y")
        reply = self.run_doctor(verbose=True)
        self.assertIn("tmp_leftovers", [item["id"] for item in reply["findings"]])
        self.assertEqual(reply["sections"]["tmp"]["files"], [str(old)])
        self.assertTrue(old.exists() and young.exists())

    def test_abandoned_connections_of_both_budgets_are_listed(self):
        user = type("E", (), {"kind": "user", "key": "k"})()
        probe = type("P", (), {"kind": "probe", "key": "p"})()
        token = hydra.REGISTRY.abandon(user, "ping", None)
        token2 = hydra.REGISTRY.abandon(probe, "ping", None)
        self.addCleanup(hydra.REGISTRY.answered, token)
        self.addCleanup(hydra.REGISTRY.answered, token2)
        reply = self.run_doctor(verbose=True)
        ids = [item["id"] for item in reply["findings"]]
        self.assertIn("abandoned_user_calls", ids)
        self.assertIn("abandoned_probes", ids)
        self.assertEqual(reply["sections"]["connections"]["abandoned"]["probeCap"], 3)

    def test_filesystem_warns_on_system_drive_and_non_cow(self):
        drive = Path(self.settings["root"]).resolve().drive or "C:"
        with patch("hydralysis.paths.system_drive", return_value=drive.upper()):
            report = doctor.diagnose(self.settings, ["filesystem"], volume_probe=lambda path: "NTFS")
        ids = [item["id"] for item in report.findings()]
        self.assertIn("fs_root_on_system_drive", ids)
        self.assertIn("fs_root_not_cow", ids)
        refs = doctor.diagnose(self.settings, ["filesystem"], volume_probe=lambda path: "ReFS")
        self.assertNotIn("fs_root_not_cow", [item["id"] for item in refs.findings()])

    def test_generation_retention_warns_and_lineage_torn_tail_is_found(self):
        selected = self.runner.target("owned")
        lid = lineage.ensure(self.settings, {**selected, "origin_key": selected["key"]})["id"]
        lineage.append_current(self.settings, lid, {"gen": 1, "gpr": str(self.gpr), "reason": "commit"})
        folder = lineage.lineage_dir(self.settings, lid)
        for number in range(1, 5):
            (folder / "gen" / ("%04d" % number)).mkdir(parents=True)
        self.settings["generation_warn"] = 3
        with open(folder / "CURRENT.log", "ab") as handle:
            handle.write(b"{torn")
        ids = [item["id"] for item in self.run_doctor()["findings"]]
        self.assertIn("generation_retention", ids)
        self.assertIn("lineage_torn_tail", ids)
        self.assertIn("backups_none", ids)

    def test_unfinished_candidates_follow_the_last_intent_step(self):
        from hydralysis import commits
        selected = self.runner.target("owned")
        lid = lineage.ensure(self.settings, {**selected, "origin_key": selected["key"]})["id"]
        lineage.append_current(self.settings, lid, {"gen": 1, "gpr": str(self.gpr), "reason": "commit"})
        done, aborted, open_ = "c-0123456789ab", "c-0123456789ac", "c-0123456789ad"
        for cid, steps in ((done, ("PREPARE", "PUBLISHED", "FINALIZED")), (aborted, ("PREPARE", "ABORTED")), (open_, ("PREPARE", "PUBLISHED"))):
            intent = commits.Intent(self.settings, lid, cid, 1)
            for step in steps:
                intent.write(step)
        reply = self.run_doctor()
        row = [item for item in reply["findings"] if item["id"] == "lineage_unfinished_candidates"]
        self.assertEqual(len(row), 1)
        self.assertIn(open_, row[0]["what"] if "what" in row[0] else json.dumps(row[0]))
        self.assertNotIn(done, json.dumps(row[0]))
        self.assertNotIn(aborted, json.dumps(row[0]))
        # a finished-only lineage has no such finding
        intent = commits.Intent(self.settings, lid, open_, 1)
        intent.write("FINALIZED")
        self.assertNotIn("lineage_unfinished_candidates", [item["id"] for item in self.run_doctor()["findings"]])

    def test_sections_option_limits_and_rejects_unknown(self):
        self.assertEqual(list(self.run_doctor(sections=["jdk"], verbose=True)["sections"]), ["jdk"])
        with self.assertRaises(ValueError):
            self.run_doctor(sections=["nope"])

    def test_the_jdk_is_read_from_its_release_file_never_run(self):
        home = self.root / "jdk"
        home.mkdir()
        (home / "release").write_text('JAVA_VERSION="21.0.2"\n')
        self.settings["java_home"] = str(home)
        reply = self.run_doctor()
        self.assertIn("jdk_too_old", [item["id"] for item in reply["findings"]])

    def test_the_launch_outcome_warns_when_the_daemon_dies_with_the_harness(self):
        state = hydra.state_dir(self.settings)
        state.mkdir(parents=True, exist_ok=True)
        (state / (hydra.INSTANCE + ".launch.json")).write_text(json.dumps({"spawn": "ok", "survival": "daemon_dies_with_harness"}))
        ids = [item["id"] for item in self.run_doctor()["findings"]]
        self.assertIn("daemon_dies_with_harness", ids)


if __name__ == "__main__":
    unittest.main()
