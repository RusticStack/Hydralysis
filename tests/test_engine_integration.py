"""End to end on the real engine: prepare, query, overlays, revert, adopt.

Runs only when HYDRALYSIS_INTEGRATION_ENGINE (or RUSTICRE_INTEGRATION_ENGINE) names a Hydra install and
HYDRALYSIS_INTEGRATION_CLIENT its ghidra_session.py (optionally
HYDRALYSIS_INTEGRATION_JAVA a JDK and HYDRALYSIS_INTEGRATION_BINARY a small PE;
the default is Windows' whoami.exe). Everything lives in its own data root, with
its own daemon, which is stopped at the end.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from support import default_to_shared, workdir

def _env(name):
    """HYDRALYSIS_<name>, else the old RUSTICRE_<name>."""
    return os.environ.get("HYDRALYSIS_" + name) or os.environ.get("RUSTICRE_" + name)


ENGINE = _env("INTEGRATION_ENGINE")
CLIENT = _env("INTEGRATION_CLIENT")
BINARY = _env("INTEGRATION_BINARY") or (
    os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "System32", "whoami.exe") if os.name == "nt" else "")


def _prepare(cls, source, label, target):
    """Prepare SOURCE once under its own data root and daemon; leaves settings, runner and the env patch on CLS."""
    from hydralysis import preparation, query
    cls.work = workdir(label)
    cls.root = Path(cls.work.name)
    binary = cls.root / "fixture.exe"
    shutil.copy2(source, binary)
    cls.settings = {"root": str(cls.root / "data"), "hydra_dir": ENGINE, "hydra_client": CLIENT,
                    "hydra_idle_s": 600}
    if _env("INTEGRATION_UNPINNED"):
        # An engine that is not the release this Hydralysis pins (for instance the published hydra.3 before Y4a bumps the pin).
        cls.settings["hydra_allow_unpinned"] = True
    if _env("INTEGRATION_JAVA"):
        cls.settings["java_home"] = _env("INTEGRATION_JAVA")
    query._keys.clear()
    env = {"HYDRALYSIS_ROOT": cls.settings["root"], "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    cls.env = patch.dict(os.environ, env)
    cls.env.start()
    job = preparation.prepare(cls.settings, str(binary), target)
    deadline = time.monotonic() + 600
    while True:
        status = preparation.status(cls.settings, job["job_id"])
        if status["state"] not in preparation.ACTIVE or time.monotonic() > deadline:
            break
        time.sleep(1)
    if status["state"] != "done":
        raise AssertionError("prepare did not finish: %s" % json.dumps(status)[:3000])
    cls.prepared = status
    cls.runner = query.QueryRunner(cls.settings)


def _release(cls):
    from hydralysis import hydra
    engine = hydra.Engine(cls.settings)
    try:
        engine.stop(force=True)
    finally:
        # A daemon that ignored the stop must not outlive the test (it holds the work dir).
        daemon = engine.module().Daemon(str(engine.engine_dir), str(hydra.state_dir(cls.settings)), hydra.INSTANCE)
        if daemon.jvm_alive() or daemon.read_endpoint():
            daemon.kill()
        cls.env.stop()
        time.sleep(1)
        cls.work.cleanup()


def workcopy_store(case, view=None):
    from hydralysis import workcopy
    return workcopy.load_store(case.settings, workcopy.with_view(case.runner.target("fixture"), view or case.VIEW))


@unittest.skipUnless(ENGINE and CLIENT and BINARY and Path(BINARY).is_file(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class EngineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _prepare(cls, BINARY, "engine", "fixture")

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def ask(self, action, address="", **kwargs):
        return json.loads(self.runner.query("fixture", action, address, **kwargs))

    def revision(self, view=""):
        return self.ask("status", options={"view": view} if view else {})["view_revision"]

    def entry(self):
        listed = self.ask("functions", limit=5)
        self.assertTrue(listed["functions"])
        return listed["functions"][0]["address"]

    def test_queries_answer_from_the_prepared_project(self):
        address = self.entry()
        for action in ("decompile", "dossier", "blocks", "pcode", "variables"):
            with self.subTest(action=action):
                answer = self.ask(action, address)
                self.assertTrue(answer["ok"])
                self.assertEqual(answer["engine"]["mode"], "contained")
        traced = self.ask("trace", address, options={"brief": True, "depth": 4})
        for key in ("constants", "stops", "memory_edges", "selected_operations"):
            self.assertIn(key, traced)
        self.assertNotIn("result", traced)
        scanned = self.ask("vcalls", limit=5, options={"offset": "0x8"})
        self.assertIn("callers", scanned)
        self.assertGreater(scanned["instructions_scanned"], 0)
        self.assertIn("vtables", self.ask("vtables", address))
        orphans = self.ask("orphans", limit=5)
        self.assertIn("orphans", orphans)
        self.assertGreater(orphans["instructions_scanned"], 0)
        warm = [self.ask("decompile", address)["query_s"] for _ in range(3)]
        self.assertLess(min(warm), 1.0)

    def test_a_bulk_export_runs_in_its_own_worker(self):
        # The export worker ignores the user site; it must still find Hydralysis's dependencies.
        from hydralysis import exporting
        job = exporting.start(self.settings, "fixture", {"mode": "decompile", "limit": 5})
        deadline = time.monotonic() + 300
        while job["state"] in exporting.ACTIVE and time.monotonic() < deadline:
            time.sleep(1)
            job = exporting.status(self.settings, job["id"])
        self.assertEqual(job["state"], "done", job.get("log_tail", "")[-2000:])
        self.assertEqual(job["succeeded"], 5)

    def test_overlay_edit_read_and_revert(self):
        address = self.entry()
        original = self.ask("decompile", address)["function"]["name"]
        edited = json.loads(self.runner.query("fixture", "type_edit", address, timeout_s=300,
                                              options={"kind": "rename", "name": "integration_named", "source": "integration test",
                                                       "expect_revision": self.revision()}))
        self.assertTrue(edited["ok"])
        self.assertEqual(edited["view_revision"], edited["revision"])
        self.assertIn("phases_ms", edited["sync"])
        self.assertEqual(self.ask("decompile", address)["function"]["name"], "integration_named")
        reverted = json.loads(self.runner.query("fixture", "type_edit", options={
            "kind": "revert", "ids": [edited["overlay_id"]], "expect_revision": self.revision()}))
        self.assertEqual(reverted["reverted"], 1)
        self.assertEqual(self.ask("decompile", address, timeout_s=300)["function"]["name"], original)

    def test_revision_is_mandatory_and_stale_edits_are_subject_aware(self):
        listed = self.ask("functions", limit=5)["functions"]
        self.assertGreaterEqual(len(listed), 2)
        first, second = listed[0]["address"], listed[1]["address"]
        view = "concurrency-fixture"

        def rename(address, name, revision):
            return json.loads(self.runner.query("fixture", "type_edit", address, timeout_s=300, options={
                "kind": "rename", "name": name, "source": "integration test", "view": view, "expect_revision": revision}))
        with self.assertRaises(RuntimeError) as missing:
            self.runner.query("fixture", "type_edit", first, options={"kind": "rename", "name": "x", "source": "s", "view": view})
        self.assertEqual(json.loads(str(missing.exception))["current_revision"], 0)
        one = rename(first, "concurrency_one", 0)
        self.assertEqual((one["revision"], one["rebased"]), (1, False))
        other = rename(second, "concurrency_two", 0)
        self.assertEqual((other["revision"], other["rebased"], other["rebased_from"]), (2, True, 0))
        with self.assertRaises(RuntimeError) as clash:
            rename(first, "concurrency_clash", 0)
        body = json.loads(str(clash.exception))
        self.assertEqual((body["current_revision"], body["overlapping"]), (2, ["address:%s" % hex(int(first, 16))]))
        self.assertEqual(self.ask("decompile", first, options={"view": view})["function"]["name"], "concurrency_one")
        self.assertEqual(self.revision(view), 2)

    def test_cited_data_label_is_visible_and_revertible(self):
        from hydralysis.pe import Image
        image = Image(Path(self.root / "fixture.exe"))
        section = next(s for s in image.sections if not (s.Characteristics & 0x20000000) and s.SizeOfRawData)
        address = hex(image.base + section.VirtualAddress)
        edited = self.ask("type_edit", address, timeout_s=300,
                          options={"kind": "label", "name": "integration_global", "source": "fixture section table",
                                   "expect_revision": self.revision()})
        data = self.ask("data", address, options={"table": True})
        self.assertIn("integration_global", [item["name"] for item in data["labels"]])
        self.ask("type_edit", options={"kind": "revert", "ids": [edited["overlay_id"]], "expect_revision": self.revision()})
        data = self.ask("data", address, options={"table": True})
        self.assertNotIn("integration_global", [item["name"] for item in data["labels"]])

    def test_gdt_archive_import_and_revert(self):
        from hydralysis import overlayjobs
        archive = Path(ENGINE) / "Ghidra/Features/Base/data/pcodetest/EmuTesting.gdt"
        self.assertTrue(archive.is_file(), str(archive))
        def submit(paths, revision):
            job = self.ask("type_edit", options={"kind": "import_archive", "archive": str(archive),
                                                "paths": paths, "source": "bundled EmuTesting.gdt",
                                                "view": "archive-fixture", "expect_revision": revision})
            deadline = time.monotonic() + 300
            while job["state"] in overlayjobs.ACTIVE and time.monotonic() < deadline:
                time.sleep(1)
                job = overlayjobs.status(self.settings, job["id"])
            return job
        job = submit(["/u4"], 0)
        self.assertEqual(job["state"], "done", job)
        self.assertEqual(self.ask("type", options={"path": "/u4", "view": "archive-fixture"})["type"]["length"], 4)
        self.assertEqual(job["result"]["import_report"]["records"], 1)
        self.assertEqual(job["result"]["import_report"]["archive_types"], 1)
        # A bulk import has one effect: its report, with no per-subject before (drift is by input hash).
        (record,) = workcopy_store(self, "archive-fixture")["edits"]
        (effect,) = record["effects"]
        self.assertEqual((effect["subject"], effect["field"], effect["before"]), ("*", "report", None))
        self.assertRegex(effect["after"], r"^sha256:[0-9a-f]{64}$")
        mismatch = submit(["/pointer"], 1)
        self.assertEqual(mismatch["state"], "failed", mismatch)
        self.assertIn("differs", mismatch.get("error", "").lower())
        self.assertEqual(self.ask("status", options={"view": "archive-fixture"})["overlays"]["revision"], 1)
        self.assertEqual(self.ask("type", options={"path": "/u4", "view": "archive-fixture"})["type"]["length"], 4)
        with self.assertRaises(RuntimeError):
            self.ask("type", options={"path": "/u4"})
        self.ask("type_edit", options={"kind": "revert", "ids": [job["result"]["overlay_id"]],
                                       "view": "archive-fixture", "expect_revision": 1})
        with self.assertRaises(RuntimeError):
            self.ask("type", options={"path": "/u4", "view": "archive-fixture"})

    # ---- store v3: the subject record (effects), the probe and verify_before, on the real engine ----------------

    VIEW = "subject-record"

    def edit_in_view(self, address, **options):
        view = options.pop("view", self.VIEW)
        return json.loads(self.runner.query("fixture", "type_edit", address, timeout_s=300, options={
            "source": "integration test", "view": view, "expect_revision": self.revision(view), **options}))

    def data_address(self):
        from hydralysis.pe import Image
        image = Image(Path(self.root / "fixture.exe"))
        section = next(s for s in image.sections if not (s.Characteristics & 0x20000000) and s.SizeOfRawData)
        return hex(image.base + section.VirtualAddress)

    def test_effects_are_reported_for_rename_comment_signature_label_and_struct(self):
        from hydralysis import revisions
        address = self.entry()
        subject = "address:%s" % hex(int(address, 16))
        original = self.ask("decompile", address, options={"view": self.VIEW})["function"]["name"]
        renamed = self.edit_in_view(address, kind="rename", name="effect_one")
        self.assertEqual(renamed["effects"], [{"subject": subject, "field": "name", "before": original, "after": "effect_one"}])
        again = self.edit_in_view(address, kind="rename", name="effect_two")
        self.assertEqual(again["effects"], [{"subject": subject, "field": "name", "before": "effect_one", "after": "effect_two"}])
        commented = self.edit_in_view(address, kind="comment", comment="what it does")
        (effect,) = commented["effects"]
        self.assertEqual((effect["subject"], effect["field"], effect["before"]), (subject, "comment:plate", "absent"))
        self.assertTrue(effect["after"].startswith("what it does\nsource: integration test"), effect)
        signed = self.edit_in_view(address, kind="signature", prototype="int effect_two(int first)")
        (effect,) = signed["effects"]
        self.assertEqual((effect["subject"], effect["field"]), (subject, "signature"))
        self.assertEqual(effect["after"], "int effect_two(int first)")
        self.assertNotEqual(effect["before"], effect["after"])
        data = self.data_address()
        labelled = self.edit_in_view(data, kind="label", name="effect_global")
        self.assertEqual(labelled["effects"], [{"subject": "address:%s" % hex(int(data, 16)), "field": "label:effect_global",
                                                "before": "absent", "after": "present"}])
        struct = self.edit_in_view("", kind="struct", path="/RusticRE/EffectFixture", size=8,
                                   fields=[{"offset": 0, "type": "int", "name": "count", "length": 4}])
        (effect,) = struct["effects"]
        self.assertEqual((effect["subject"], effect["field"], effect["before"]), ("type:/RusticRE/EffectFixture", "definition", "absent"))
        self.assertRegex(effect["after"], r"^sha256:[0-9a-f]{64}$")
        # What the store keeps is what the engine reported, and every effect's subject is one the journal knows.
        store = workcopy_store(self)
        by_id = {record["id"]: record for record in store["edits"]}
        for answer in (renamed, again, commented, signed, labelled, struct):
            record = by_id[answer["overlay_id"]]
            self.assertEqual(record["effects"], answer["effects"])
            self.assertNotIn("before_unknown", record)
            allowed = set(revisions.subjects_of(record["address"], record["options"]))
            self.assertLessEqual({item["subject"] for item in record["effects"]}, allowed)
        self.assertEqual([record["seq"] for record in store["edits"]], list(range(1, len(store["edits"]) + 1)))

    def test_function_edits_report_existence_body_and_name_and_chain_through_delete_and_create(self):
        from hydralysis.pe import Image
        row = self.ask("functions", limit=5)["functions"][0]
        entry = int(row["address"], 16)
        ranges = [tuple(int(part, 16) for part in re.findall(r"[0-9a-fA-F]+", text)) for text in row["body"]]
        if len(ranges) != 1:
            self.skipTest("the first function of the fixture has more than one body range")
        image = Image(Path(self.root / "fixture.exe"))
        expect = " ".join("%02X" % byte for byte in image.read_rva(entry - image.base, 3))
        view, subject = "subject-function", "address:%s" % hex(entry)
        body = "0x%x-0x%x" % ranges[0]
        original = row["name"]
        deleted = self.edit_in_view(row["address"], kind="function_delete", expect=expect, view=view)
        self.assertEqual({(item["field"], item["before"], item["after"]) for item in deleted["effects"]},
                         {("existence", "present", "absent"), ("body", body, "absent"), ("name", original, "absent")})
        created = self.edit_in_view(row["address"], kind="function_create", expect=expect, name="effect_recreated", view=view,
                                    ranges=[{"start": hex(ranges[0][0]), "end": hex(ranges[0][1])}])
        self.assertEqual({(item["field"], item["before"], item["after"]) for item in created["effects"]},
                         {("existence", "absent", "present"), ("body", "absent", body), ("name", "absent", "effect_recreated")})
        self.assertTrue(all(item["subject"] == subject for item in created["effects"]))
        resized = self.edit_in_view(row["address"], kind="function_body", expect=expect, name="effect_again", view=view,
                                    ranges=[{"start": hex(ranges[0][0]), "end": hex(ranges[0][1])}])
        self.assertEqual({(item["field"], item["before"], item["after"]) for item in resized["effects"]},
                         {("body", body, body), ("name", "effect_recreated", "effect_again")})

    def test_a_bundle_exports_reports_drift_on_a_dry_run_and_applies_as_proposals_on_the_real_engine(self):
        from hydralysis import annotations
        address = self.entry()
        subject = "address:%s" % hex(int(address, 16))
        original = self.ask("decompile", address, options={"view": "bundle-source"})["function"]["name"]
        edited = self.edit_in_view(address, kind="rename", name="bundled_name", view="bundle-source")
        data = self.data_address()
        self.edit_in_view(data, kind="label", name="bundled_label", view="bundle-source")
        exported = annotations.export_bundle(self.settings, "fixture", view="bundle-source", path=self.root / "bundles" / "one")
        bundle = json.loads(Path(exported["path"]).read_text(encoding="utf-8"))
        self.assertEqual((bundle["program"]["sha256"], bundle["records"][0]["effects"]), (self.prepared["sha256"], edited["effects"]))
        self.assertTrue(bundle["program"]["language"] and bundle["program"]["compiler"] and bundle["program"]["image_base"])
        self.assertNotIn(str(self.root), json.dumps(bundle))
        fresh = annotations.import_bundle(self.settings, "fixture", exported["path"], view="bundle-fresh")
        self.assertTrue(fresh["ok"], fresh)
        self.assertEqual((fresh["bundle"]["hash_ok"], fresh["bundle"]["program_sha256_ok"], fresh["base_drift"]), (True, True, []))
        self.edit_in_view(address, kind="rename", name="somebody_elses_name", view="bundle-drifted")
        drifted = annotations.import_bundle(self.settings, "fixture", exported["path"], view="bundle-drifted")
        self.assertEqual(drifted["base_drift"], [{"id": edited["overlay_id"], "subject": subject, "field": "name",
                                                  "expected": original, "found": "somebody_elses_name"}])
        applied = annotations.import_bundle(self.settings, "fixture", exported["path"], view="bundle-fresh", apply=True,
                                            expect_revision=self.revision("bundle-fresh"))
        self.assertEqual(len(applied["added"]), 2)
        self.assertEqual(self.ask("decompile", address, options={"view": "bundle-fresh"})["function"]["name"], "bundled_name")
        records = workcopy_store(self, "bundle-fresh")["edits"]
        self.assertEqual(records[0]["effects"], edited["effects"])  # the same program: the same before and after
        self.assertEqual(records[0]["imported_from"]["id"], edited["overlay_id"])
        again = annotations.import_bundle(self.settings, "fixture", exported["path"], view="bundle-fresh")
        self.assertEqual((again["would_add"], len(again["already_present"])), ([], 2))

    def test_a_data_type_applied_to_data_reports_its_type_before_and_after(self):
        data = self.data_address()
        applied = self.edit_in_view(data, kind="apply", type="int", view="subject-apply")
        (effect,) = applied["effects"]
        self.assertEqual((effect["subject"], effect["field"], effect["after"]), ("address:%s" % hex(int(data, 16)), "type", "int"))
        self.assertIn("before", effect)

    def test_a_variable_edit_reports_name_and_type_before_and_after(self):
        for row in self.ask("functions", limit=5)["functions"]:
            try:
                variables = self.ask("variables", row["address"], options={"view": self.VIEW}).get("variables") or []
            except RuntimeError:
                continue
            local = next((item for item in variables if item.get("variable") and item.get("name")), None)
            if local:
                break
        else:
            self.skipTest("no decompiled variable in the first functions of the fixture")
        renamed = self.edit_in_view(row["address"], kind="variable", variable=local["variable"], type=local["name"],
                                    name="effect_local", view="subject-variable")
        (effect,) = renamed["effects"]
        self.assertEqual(effect["field"], "variable:%s" % local["variable"])
        self.assertTrue(effect["before"].startswith(local["variable"] + ":"), effect)
        self.assertTrue(effect["after"].startswith("effect_local:"), effect)

    def test_the_probe_reads_what_the_effects_reported_and_verify_before_rolls_back_on_a_mismatch(self):
        from hydralysis import hydra, query, workcopy
        view = "subject-verify"
        address = self.entry()
        subject = "address:%s" % hex(int(address, 16))
        original = self.ask("decompile", address, options={"view": view})["function"]["name"]
        renamed = self.edit_in_view(address, kind="rename", name="verify_one", view=view)
        selected = workcopy.with_view(self.runner.target("fixture"), view)
        program = self.runner.program_for(selected)
        engine = self.runner.engine
        values = workcopy.probe(engine, program, [(subject, "name"), (subject, "existence"), (subject, "label:nothing_here"),
                                                  ("type:/RusticRE/NotThere", "definition"), ("*", "report")])
        self.assertEqual(values[(subject, "name")], "verify_one")
        self.assertEqual(values[(subject, "existence")], "present")
        self.assertEqual(values[(subject, "label:nothing_here")], "absent")
        self.assertEqual(values[("type:/RusticRE/NotThere", "definition")], "absent")
        self.assertIsNone(values[("*", "report")])
        # verify_before on the working copy's own writer: a record whose before is wrong is refused, and the
        # transaction (the earlier records of the same call included) is rolled back, the marker untouched.
        writer = hydra.Engine(self.settings, role="writer")
        try:
            state = workcopy._state(self.settings, selected)
            held = query.open_program(writer, state["fork_gpr"], selected["program"], selected["sha256"], writable=True,
                                      upgrade=True, refresh=True)
            marker = workcopy._marker(writer, held)
            good = {"id": "1" * 32, "address": address, "effects": [{"subject": subject, "field": "name", "before": "verify_one",
                                                                      "after": "verify_two"}],
                    "options": {"kind": "rename", "name": "verify_two", "source": "integration test"}}
            bad = {"id": "2" * 32, "address": address, "effects": [{"subject": subject, "field": "name", "before": "not_this",
                                                                     "after": "verify_three"}],
                   "options": {"kind": "rename", "name": "verify_three", "source": "integration test"}}
            with self.assertRaises(workcopy.VerifyMismatch) as raised:
                workcopy._apply(self.settings, writer, held, [good, bad], marker, 120, verify_before=True)
            self.assertEqual({key: raised.exception.detail[key] for key in ("id", "subject", "field", "expected", "found")},
                             {"id": "2" * 32, "subject": subject, "field": "name", "expected": "not_this", "found": "verify_two"})
            self.assertEqual(workcopy.probe(engine, held, [(subject, "name")])[(subject, "name")], "verify_one")
            self.assertEqual(workcopy._marker(writer, held), marker)
            # The first effect on a (subject, field) is the one checked: a chain inside one call passes.
            chain = {**bad, "effects": [{**bad["effects"][0], "before": "verify_two"}]}
            workcopy._apply(self.settings, writer, held, [good, chain], marker, 120, verify_before=True)
            self.assertEqual(workcopy.probe(engine, held, [(subject, "name")])[(subject, "name")], "verify_three")
            # state:null clears the marker (the generation base of 4.6 step 5 holds none).
            workcopy._apply(self.settings, writer, held, [], None, 60)
            self.assertIsNone(workcopy._marker(writer, held))
        finally:
            writer.reset()
            query.forget(writer)
        # Put the working copy back in step with the store (it replays the one recorded record, not the two applied here).
        workcopy.repair(self.settings, self.runner.engine, selected)
        self.assertEqual(self.ask("decompile", address, options={"view": view})["function"]["name"], "verify_one")
        self.assertNotEqual(original, "verify_one")
        self.assertEqual(renamed["effects"][0]["before"], original)

    def test_a_removed_main_store_with_an_intact_backup_still_serves_the_overlays(self):
        from hydralysis import durable, workcopy
        view = "subject-backup"
        address = self.entry()
        self.edit_in_view(address, kind="rename", name="backup_one", view=view)
        self.edit_in_view(address, kind="rename", name="backup_two", view=view)
        selected = workcopy.with_view(self.runner.target("fixture"), view)
        path = workcopy._store_path(self.settings, selected)
        path.unlink()
        self.assertTrue(workcopy.has_overlays(self.settings, selected))
        self.assertEqual(self.ask("decompile", address, options={"view": view})["function"]["name"], "backup_one")
        self.assertTrue(durable.exists(path))

    def test_adopt_registers_the_prepared_project_in_place(self):
        from hydralysis import hydra, targets
        gpr = self.prepared["project"]["gpr"]
        result = targets.adopt(self.settings, hydra.Engine(self.settings), str(Path(gpr).parent),
                               expected=self.prepared["sha256"], target="adopted-fixture")
        self.assertTrue(result["registered"], result)
        self.assertFalse(result["copied"])


@unittest.skipUnless(ENGINE and CLIENT and BINARY and Path(BINARY).is_file(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class EngineCommit(unittest.TestCase):
    """PROTOCOL-3.md 4.6 on the real engine: a commit makes a verified, sealed generation, the adopted project stays
    byte-identical, the name is read from the generation, a second commit archives the first, and a revert chain returns
    both records to pending with the pointer at generation 0."""

    @classmethod
    def setUpClass(cls):
        _prepare(cls, BINARY, "commit", "fixture")
        # The round trip below drives commits.run_commit on the `shared` view, so a bare call must name it too. A caller with
        # neither a view nor an agent has a view of its own since Y5 (D43): its edits would land there, and a commit of the
        # shared view would find nothing pending. `test_caller_commit_without_a_view_sees_its_own_edits` covers that path.
        default_to_shared(cls.runner)

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def ask(self, action, address="", **kwargs):
        return json.loads(self.runner.query("fixture", action, address, **kwargs))

    def test_caller_commit_without_a_view_sees_its_own_edits(self):
        """D43/D59: a commit that names no view is the caller's own view's commit. The edit of an agent (`as`) lands in its view;
        the same agent's dry-run commit finds that record, and a commit of the `shared` view does not (isolation, K11). It
        runs before the round trip, which leaves records pending in the shared view."""
        from hydralysis import commits, workcopy
        agent = "y6-own-edits"  # already a view name, so the agent's view is called the same
        first = self.ask("functions", limit=5)["functions"][0]["address"]
        base = self.runner.target("fixture")
        mine = workcopy.with_view(base, agent)
        edited = json.loads(self.runner.query("fixture", "type_edit", first, timeout_s=300, options={
            "kind": "rename", "name": "own_edit_probe", "source": "commit integration test", "as": agent,
            "expect_revision": workcopy.load_store(self.settings, mine).get("revision")}))
        self.assertEqual(edited["view"], agent, edited)
        plan = json.loads(self.runner.query("fixture", "type_edit", "", timeout_s=300, options={
            "kind": "commit", "dry_run": True, "confirm_one_way_upgrade": True, "as": agent,
            "expect_revision": workcopy.load_store(self.settings, mine)["revision"]}))
        self.assertTrue(plan["dry_run"] and plan["ok"], plan)
        self.assertEqual(plan["view"], agent)
        with self.assertRaises(RuntimeError) as refused:  # the shared view holds none of it
            self.runner.query("fixture", "type_edit", "", timeout_s=300, options={
                "kind": "commit", "dry_run": True, "confirm_one_way_upgrade": True, "view": "shared",
                "expect_revision": workcopy.load_store(self.settings, workcopy.with_view(base, ""))["revision"]})
        self.assertEqual(json.loads(str(refused.exception))["error"], "nothing_to_commit")
        self.assertNotEqual(self.ask("decompile", first, options={"view": "shared"})["function"]["name"], "own_edit_probe")

    def test_commit_round_trip_archival_and_revert_chain(self):
        from hydralysis import commits, hydra, lineage, workcopy
        listed = self.ask("functions", limit=5)["functions"]
        first, second = listed[0]["address"], listed[1]["address"]
        master = Path(self.prepared["project"]["gpr"]).parent
        master_tree = lineage.tree_hash(master)

        def edit(address, name):
            revision = workcopy.load_store(self.settings, workcopy.with_view(self.runner.target("fixture"), "")).get("revision")
            return json.loads(self.runner.query("fixture", "type_edit", address, timeout_s=300, options={
                "kind": "rename", "name": name, "source": "commit integration test", "expect_revision": revision}))

        def commit(**options):
            selected = workcopy.with_view(self.runner.target("fixture"), "")
            body = {"kind": "commit", "confirm_one_way_upgrade": True,
                    "expect_revision": workcopy.load_store(self.settings, selected)["revision"], **options}
            return commits.run_commit(self.settings, selected, body, hydra.Engine(self.settings), timeout_s=600)

        original = self.ask("decompile", first)["function"]["name"]
        edit(first, "committed_one")
        plan = commit(dry_run=True)
        self.assertTrue(plan["dry_run"] and plan["ok"], plan)
        self.assertEqual(lineage.tree_hash(master), master_tree)
        c1 = commit()
        self.assertEqual((c1["ok"], c1["generation"]), (True, 1), c1)
        selected = self.runner.target("fixture")
        self.assertEqual(selected["lineage"]["generation"], 1)
        self.assertTrue(lineage.verify_head(self.settings, selected["lineage"]["id"])["ok"])
        self.assertEqual(lineage.tree_hash(master), master_tree, "the adopted project must stay byte-identical (O1)")
        folder = lineage.generation_dir(self.settings, selected["lineage"]["id"], 1)
        self.assertTrue((folder / "SEALED.json").is_file())
        self.assertEqual(self.ask("decompile", first)["function"]["name"], "committed_one")  # read from the generation
        self.assertNotEqual(original, "committed_one")
        status = json.loads(self.runner.query("fixture", "status", "", options={"show": "lineage"}))
        self.assertEqual((status["generation"], status["reason"]), (1, "commit"))
        # a sealed generation is never opened writable: the engine of this release has no seal, so it is client discipline
        edit(second, "committed_two")
        c2 = commit()
        self.assertEqual(c2["generation"], 2)
        store = workcopy.load_store(self.settings, workcopy.with_view(self.runner.target("fixture"), ""))
        self.assertEqual([entry["cid"] for entry in store["archived"]], [c1["cid"]])
        self.assertEqual(self.ask("decompile", second)["function"]["name"], "committed_two")
        selected = workcopy.with_view(self.runner.target("fixture"), "")
        commits.revert(self.settings, selected, {"kind": "commit_revert", "expect_revision": store["revision"]})
        selected = workcopy.with_view(self.runner.target("fixture"), "")
        commits.revert(self.settings, selected, {"kind": "commit_revert",
                                                 "expect_revision": workcopy.load_store(self.settings, selected)["revision"]})
        selected = self.runner.target("fixture")
        self.assertEqual(selected["lineage"]["generation"], 0)
        store = workcopy.load_store(self.settings, workcopy.with_view(selected, ""))
        self.assertEqual([record["id"] for record in workcopy.pending_of(store)], c1["ids"] + c2["ids"])
        self.assertEqual(self.ask("decompile", first)["function"]["name"], "committed_one")   # replayed onto generation 0 again
        self.assertEqual(self.ask("decompile", second)["function"]["name"], "committed_two")
        self.assertEqual(lineage.tree_hash(master), master_tree)

    def test_subset_missing_type_on_the_real_engine(self):
        """4.2: a subset commit of a signature without the struct it uses must fail closed (ABORTED, nothing published). If the
        engine instead accepted it and substituted an undefined type, this test fails and the closure must be extended."""
        from hydralysis import commits, hydra, lineage, workcopy
        listed = self.ask("functions", limit=5)["functions"]
        address = listed[2]["address"] if len(listed) > 2 else listed[-1]["address"]
        view = "subset-missing-type"

        def edit(options, at=address):
            selected = workcopy.with_view(self.runner.target("fixture"), view)
            return json.loads(self.runner.query("fixture", "type_edit", at, timeout_s=300, options={
                **options, "source": "commit integration test", "view": view,
                "expect_revision": workcopy.load_store(self.settings, selected)["revision"]}))

        edit({"kind": "struct", "path": "/HydralysisSubsetProbe", "size": 8,
              "fields": [{"offset": 0, "type": "int", "name": "first"}]}, "")
        signature = edit({"kind": "signature", "prototype": "void probe_subset(HydralysisSubsetProbe *item)"})
        selected = workcopy.with_view(self.runner.target("fixture"), view)
        store = workcopy.load_store(self.settings, selected)
        self.assertEqual(len(store["edits"]), 2)
        outcome = None
        try:
            outcome = commits.run_commit(self.settings, selected, {
                "kind": "commit", "confirm_one_way_upgrade": True, "expect_revision": store["revision"],
                "only": {"ids": [signature["overlay_id"]]}}, hydra.Engine(self.settings), timeout_s=600)
        except commits.CommitError as error:
            self.assertEqual(error.code, "apply_refused", error.payload())  # fail closed, the effect is named
            self.assertIn(("HydralysisSubsetProbe"), str(error) + json.dumps(error.payload()))
        self.assertIsNone(outcome, "the engine applied a signature whose struct was not in the commit: extend the closure with type references")
        link = self.runner.target("fixture").get("lineage")
        if link:  # a lineage may exist from an earlier test of this class; nothing of this commit was published
            self.assertEqual([row for row in lineage.history(self.settings, link["id"]) if row.get("cid") and
                              commits.last_steps(self.settings, link["id"], row["cid"])["data"].get("view") == view], [])
        self.assertEqual(len(workcopy.pending_of(workcopy.load_store(self.settings, selected))), 2)


if __name__ == "__main__":
    unittest.main()
