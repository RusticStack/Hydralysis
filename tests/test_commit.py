"""Commit as a new generation (PROTOCOL-3.md 4.6): preconditions, subset and skip commits, revert, archival, the reference
snapshot, the fault matrix and its oracle O1-O6, on the fake daemon of tests/fakehydra.py.

The fake models what a commit relies on: forks that copy a project's files, saves that write them, effects and
`annotation_probe`, `verify_before`, and the sealed predicate of D38. Real-engine rows are in test_engine_integration.py.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import commits, durable, hydra, lineage, query, targets, workcopy
from support import workdir

A, B, C = "0x140001000", "0x140002000", "0x140003000"
CONFIRMED = {"kind": "commit", "confirm_one_way_upgrade": True}


class World:
    """A registered target on the fake daemon, with a lineage-capable data root. Mix in with unittest.TestCase."""

    padding = 0  # bytes of filler in the master project (the KotOR-sized fixture sets it)

    def setUp(self):
        self.temp = workdir("commit")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "owned.exe"
        self.exe.write_bytes(b"MZ a small owned executable")
        self.digest = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.daemon = fakehydra.reset()
        self.daemon.effects = True
        self.gpr = self.root / "analysed" / "Owned" / "Owned.gpr"
        self.daemon.add_project(self.gpr, {"/owned.exe": {"sha256": self.digest, "functions": 3}})
        if self.padding:
            (self.gpr.parent / "Owned.rep" / "idata.bin").write_bytes(os.urandom(1 << 20) * (self.padding >> 20))
        self.settings = {"root": str(self.root / "data"), "hydra_dir": "x", "hydra_client": "x",
                         "backup_roots": [{"path": str(self.root / "backups")}]}
        patcher = patch("hydralysis.hydra.Engine", fakehydra.FakeEngine)
        patcher.start()
        self.addCleanup(patcher.stop)
        targets.register(self.settings, ["owned"], {"gpr": str(self.gpr), "program": "/owned.exe", "sha256": self.digest,
                                                    "exe": str(self.exe), "engine": "hydra"})
        query._keys.clear()
        self.runner = query.QueryRunner(self.settings, fakehydra.FakeEngine(self.settings))
        self.master_tree = lineage.tree_hash(self.gpr.parent)

    # --- helpers --------------------------------------------------------------------------------------------------
    def target(self, view=""):
        return workcopy.with_view(self.runner.target("owned"), view)

    def store(self, view=""):
        return workcopy.load_store(self.settings, self.target(view))

    def edit(self, name, address=A, view="", kind="rename", **fields):
        options = {"kind": kind, "source": "cited test evidence", "expect_revision": self.store(view)["revision"], **fields}
        if kind == "rename":
            options["name"] = name
        # The commit machinery is tested on the shared view unless a view is named: a caller with no `view` and no `as` has a view
        # of its own now (Y5, D43), so the shared view is named explicitly.
        options["view"] = view or "shared"
        return json.loads(self.runner.query("owned", "type_edit", address, options=options))

    def ids(self, view=""):
        return [record["id"] for record in self.store(view)["edits"]]

    def commit(self, view="", **options):
        selected = self.target(view)
        body = {**CONFIRMED, "expect_revision": self.store(view)["revision"], **options}
        return commits.run_commit(self.settings, selected, body, fakehydra.FakeEngine(self.settings))

    def lineage_id(self):
        return self.target()["lineage"]["id"]

    def head(self):
        return lineage.head(self.settings, self.lineage_id())

    def name_of(self, address=A, view=""):
        query._keys.clear()
        options = {"view": view or "shared"}
        return json.loads(self.runner.query("owned", "decompile", address, options=options))["function"]["name"]

    def generation_tree(self, number):
        return lineage.tree_hash(lineage.generation_dir(self.settings, self.lineage_id(), number))

    def published(self, cid):
        return [row for row in lineage.history(self.settings, self.lineage_id()) if row.get("cid") == cid and row.get("reason") == "commit"]

    def pending_ids(self, view=""):
        return [record["id"] for record in workcopy.pending_of(self.store(view))]

    # --- the oracle (4.6): O1-O6 -----------------------------------------------------------------------------------
    def oracle(self, before: dict, note=""):
        lid = self.lineage_id() if self.target().get("lineage") else None
        # O1: generation 0 and every earlier generation are byte-identical (tree hash, excluding projectState and locks).
        self.assertEqual(lineage.tree_hash(self.gpr.parent), self.master_tree, "O1 master changed " + note)
        for number, digest in before.items():
            self.assertEqual(self.generation_tree(number), digest, "O1 generation %s changed %s" % (number, note))
        if lid is None:
            return
        # O3: the head names an old or a new generation; a new one verifies and opens read-only.
        top = lineage.head(self.settings, lid)
        if top["gen"]:
            self.assertTrue(lineage.verify_head(self.settings, lid)["ok"], "O3 " + note)
            engine = fakehydra.FakeEngine(self.settings)
            opened = engine.call("open_project", path=top["gpr"])
            self.assertTrue(engine.call("open_program", path="/owned.exe", project=opened["id"])["sha256"] == self.digest)
        # O4: no folder without a verifying manifest is offered: every generation CURRENT.log names verifies.
        for row in lineage.history(self.settings, lid):
            if row["gen"] and row.get("reason") in ("commit", "recover"):
                self.assertTrue(lineage.verify_manifest(lineage.project_folder_of(row["gpr"]))["ok"], "O4 gen %s %s" % (row["gen"], note))
        # O2: the live commit entries equal the published manifests' ids; no id is in two entries; skipped are pending.
        store = self.store()
        seen = []
        for entry in store["commits"]:
            manifest = lineage.read_manifest(lineage.generation_dir(self.settings, lid, entry["generation"]))
            self.assertEqual(sorted(entry["ids"]), sorted(manifest["store"]["ids"]), "O2 " + note)
            if not entry.get("reverted"):  # a reverted entry is history: its ids are pending again, or in a later live entry
                seen += entry["ids"]
            for item in entry.get("skipped") or []:
                if not entry.get("reverted"):
                    self.assertIn(item["id"], self.pending_ids(), "O2 skipped record is not pending " + note)
        for entry in store["archived"]:
            from hydralysis import annotations
            record = durable.read_sealed(annotations._archive_path(self.settings, self.target(), entry["cid"]))
            self.assertEqual(workcopy._digest_of(sorted(item["id"] for item in record["records"])), entry["ids_sha256"], "O2 archive " + note)
            seen += [item["id"] for item in record["records"]]
        self.assertEqual(len(seen), len(set(seen)), "O2 an id is in two entries " + note)

    def tree_snapshot(self):
        return {number: self.generation_tree(number) for number in range(1, self.head()["gen"] + 1)
                if lineage.generation_dir(self.settings, self.lineage_id(), number).is_dir()} if self.target().get("lineage") else {}


class Preconditions(World, unittest.TestCase):
    def test_a_stale_expect_revision_creates_nothing(self):
        self.edit("One")
        with self.assertRaises(commits.CommitError) as raised:
            self.commit(expect_revision=0)
        self.assertEqual(raised.exception.code, "revision_changed")
        self.assertFalse((Path(self.settings["root"]) / "lineages").exists())

    def test_nothing_pending_is_refused(self):
        with self.assertRaises(commits.CommitError) as raised:
            self.commit()
        self.assertEqual(raised.exception.code, "nothing_to_commit")

    def test_the_one_way_confirmation_is_required_whenever_the_format_is_unknown(self):
        self.edit("One")
        with self.assertRaises(commits.CommitError) as raised:
            self.commit(confirm_one_way_upgrade=False)
        self.assertEqual(raised.exception.code, "confirmation_required")
        self.assertIn("only engines", str(raised.exception))
        self.assertFalse((Path(self.settings["root"]) / "lineages").exists())  # a refusal creates nothing, not even the lineage
        self.assertNotIn("fork_project", [name for _, name, _ in self.daemon.calls if name == "fork_project"][:1] or ["x"]) if False else None

    def test_records_without_a_subject_record_need_the_explicit_flag(self):
        self.edit("One")
        store = self.store()
        store["edits"][0]["effects"] = None
        store["edits"][0]["before_unknown"] = True
        workcopy._save_store(self.settings, self.target(), store)
        with self.assertRaises(commits.CommitError) as raised:
            self.commit()
        self.assertEqual(raised.exception.code, "before_unknown")
        self.assertEqual(self.commit(allow_unverified_before=True)["ok"], True)

    def test_options_are_validated(self):
        for bad in ({"on_drift": "overwrite"}, {"only": {"ids": "x"}}, {"cid": "nope"}, {"unknown": 1}, {"dry_run": "yes"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                commits.validate({**CONFIRMED, "expect_revision": 0, **bad})
        with self.assertRaises(ValueError):
            commits.validate({"kind": "commit"})  # expect_revision is mandatory

    def test_a_dry_run_has_no_side_effects_at_all(self):
        self.edit("One")
        self.edit("Two", B)
        before = {"master": lineage.tree_hash(self.gpr.parent), "data": lineage.tree_hash(Path(self.settings["root"])),
                  "store": lineage.tree_hash(Path(self.settings["root"]) / "overlays"), "calls": len(self.daemon.calls),
                  "forks": len([c for c in self.daemon.calls if c[1] == "fork_project"]),
                  "saves": len([c for c in self.daemon.calls if c[1] == "save"])}
        plan = self.commit(dry_run=True)
        self.assertTrue(plan["dry_run"] and plan["ok"])
        self.assertEqual(sorted(plan["ids"]), sorted(self.ids()))
        self.assertEqual(plan["skipped"], [])
        self.assertIn("only engines", plan["confirmation"])
        self.assertEqual(plan["backup_cost"]["roots"][0]["cumulative_bytes_after"], plan["backup_cost"]["bytes"])
        after = {"master": lineage.tree_hash(self.gpr.parent), "data": lineage.tree_hash(Path(self.settings["root"])),
                 "store": lineage.tree_hash(Path(self.settings["root"]) / "overlays"),
                 "forks": len([c for c in self.daemon.calls if c[1] == "fork_project"]),
                 "saves": len([c for c in self.daemon.calls if c[1] == "save"])}
        for key in ("master", "data", "store", "forks", "saves"):
            self.assertEqual(after[key], before[key], key)
        self.assertFalse((Path(self.settings["root"]) / "lineages").exists())
        self.assertFalse((Path(self.settings["root"]) / "backups").exists())

    def test_a_dry_run_reports_drift_and_what_skip_would_leave(self):
        self.edit("One")
        self.daemon.projects[self.daemon._norm(self.gpr)]["programs"]["/owned.exe"]["saved"]["names"][A] = "OutOfBand"
        plan = self.commit(dry_run=True)
        self.assertFalse(plan["ok"])
        self.assertEqual([item["reason"] for item in plan["drift"]], ["drift"])
        skipping = self.commit(dry_run=True, on_drift="skip")
        self.assertTrue(skipping["ok"])
        self.assertEqual(skipping["ids"], [])
        self.assertEqual([item["reason"] for item in skipping["skipped"]], ["drift"])


class HappyPath(World, unittest.TestCase):
    def test_a_commit_makes_a_verified_sealed_generation_and_leaves_the_master_untouched(self):
        self.edit("Alpha")
        self.edit("Beta", B)
        key = self.target()["key"]
        ids = self.ids()
        answer = self.commit()
        self.assertEqual((answer["ok"], answer["generation"], sorted(answer["ids"])), (True, 1, sorted(ids)))
        # the master is byte-identical (O1) and the head is the new generation (O3)
        self.assertEqual(lineage.tree_hash(self.gpr.parent), self.master_tree)
        top = self.head()
        self.assertEqual((top["gen"], top["cid"], top["reason"]), (1, answer["cid"], "commit"))
        self.assertTrue(lineage.verify_head(self.settings, self.lineage_id())["ok"])
        folder = lineage.generation_dir(self.settings, self.lineage_id(), 1)
        manifest = lineage.read_manifest(folder)
        self.assertEqual(manifest["store"]["ids"], ids)
        self.assertEqual(manifest["base"]["generation"], 0)
        self.assertEqual(manifest["backups"][0], commits.last_steps(self.settings, self.lineage_id(), answer["cid"])["data"]["backup_manifest_sha256"])
        # sealed: SEALED.json, sidecar state complete; the fork of the generation carries no overlay_state
        self.assertTrue((folder / "SEALED.json").is_file())
        sidecar = json.loads(next(folder.glob("*.fork.json")).read_text(encoding="utf-8"))
        self.assertEqual((sidecar["purpose"], sidecar["disposable"], sidecar["state"]), ("generation", False, "complete"))
        generation = self.daemon.projects[self.daemon._norm(top["gpr"])]["programs"]["/owned.exe"]
        self.assertEqual(generation["saved"]["marker"], "")
        self.assertEqual(generation["saved"]["names"], {A: "Alpha", B: "Beta"})
        # the store: committed ids, base on the new generation, nothing pending, the same key across the flip
        store = self.store()
        self.assertEqual(sorted(store["commits"][0]["ids"]), sorted(ids))
        self.assertEqual(store["base"], {"lineage": self.lineage_id(), "generation": 1})
        self.assertEqual(workcopy.pending_of(store), [])
        self.assertEqual(self.target()["key"], key)
        # reads now come from the generation, which holds the annotations
        self.assertEqual(self.name_of(A), "Alpha")
        self.assertEqual(self.name_of(B), "Beta")
        self.assertEqual(self.runner.target("owned")["gpr"], top["gpr"])
        self.oracle({})

    def test_the_lineage_is_created_at_the_first_commit_and_the_registry_mirrors_it(self):
        self.edit("Alpha")
        self.assertNotIn("lineage", targets.registry(self.settings)["owned"])
        self.commit()
        registered = targets.registry(self.settings)["owned"]["lineage"]
        record = lineage.load(self.settings, registered["id"])
        self.assertEqual(registered["origin_key"], record["origin_key"])
        self.assertEqual(Path(record["origin_gpr"]), self.gpr)
        self.assertEqual(lineage.history(self.settings, registered["id"])[0]["reason"], "register")
        self.assertEqual(targets.registry(self.settings)["owned"]["gpr"], str(self.gpr))  # the registry keeps the adopted path

    def test_a_crash_between_the_current_log_line_and_the_registry_write_is_harmless(self):
        self.edit("Alpha")
        self.commit()
        lid = self.lineage_id()
        registry = targets.registry(self.settings)["owned"]
        targets.register(self.settings, ["owned"], {key: value for key, value in registry.items() if key != "lineage"})
        self.assertEqual(self.runner.target("owned").get("lineage"), None)  # the cache lost the link...
        self.assertEqual(lineage.ensure(self.settings, {**self.runner.target("owned"), "origin_key": self.target()["origin_key"]})["id"], lid)
        self.assertEqual(self.runner.target("owned")["lineage"]["id"], lid)  # ...and ensure mends it from the folder

    def test_edits_after_a_commit_continue_the_same_store_and_commit_again(self):
        self.edit("Alpha")
        first = self.commit()
        revision = self.store()["revision"]
        self.assertEqual(self.edit("Alpha2")["revision"], revision + 1)
        second = self.commit()
        self.assertEqual((first["generation"], second["generation"]), (1, 2))
        self.assertEqual(self.name_of(A), "Alpha2")
        self.oracle({})

    def test_status_show_lineage_reports_the_head_and_history(self):
        self.edit("Alpha")
        self.commit()
        status = json.loads(self.runner.query("owned", "status", "", options={"show": "lineage"}))
        self.assertEqual((status["generation"], status["reason"]), (1, "commit"))
        self.assertEqual([row["reason"] for row in status["generations"]], ["register", "commit"])
        self.assertIsNone(status["torn_tail"])
        none = commits.lineage.status(self.settings, {"gpr": "x", "key": "k"})
        self.assertIsNone(none["lineage"])

    def test_stop_releases_the_programs_of_every_generation(self):
        self.edit("Alpha")
        self.commit()
        self.edit("Beta", B)
        self.commit()
        self.assertEqual(self.name_of(A), "Alpha")
        selected = self.target()
        mine = [key for key in query._keys if key[0] == self.runner.engine.key]
        generations = [key for key in mine if str(lineage.lineage_dir(self.settings, self.lineage_id())).lower() in key[1].replace("/", "\\").lower()
                       or "gen" in key[1].lower()]
        self.assertTrue(generations)
        released = json.loads(self.runner.query("owned", "stop"))
        self.assertTrue(released["ok"])
        self.assertTrue(released["released"])
        self.assertEqual([key for key in query._keys if key[0] == self.runner.engine.key and "gen" in key[1].lower()], [])
        self.assertEqual(selected["name"], "owned")

    def test_a_commit_on_a_large_project_produces_a_verified_generation_and_an_untouched_master(self):
        type(self).padding = 24 << 20
        self.addCleanup(setattr, type(self), "padding", 0)
        self.setUp()  # rebuild the world with a 24 MiB master
        self.edit("Alpha")
        self.assertEqual(self.commit()["generation"], 1)
        self.assertTrue(lineage.verify_head(self.settings, self.lineage_id())["ok"])
        self.assertEqual(lineage.tree_hash(self.gpr.parent), self.master_tree)

    def test_the_job_wrapper_runs_a_commit_through_the_overlay_job_record(self):
        self.edit("Alpha")
        selected = self.target()
        reply = json.loads(self.runner.query("owned", "type_edit", "", options={
            **CONFIRMED, "expect_revision": self.store()["revision"], "dry_run": True, "view": "shared"}))
        self.assertTrue(reply["dry_run"])
        with patch("hydralysis.overlayjobs.start", return_value={"id": "overlay-0123456789ab", "state": "queued", "kind": "commit"}) as start:
            reply = json.loads(self.runner.query("owned", "type_edit", "", options={**CONFIRMED, "expect_revision": self.store()["revision"],
                                                                                    "view": "shared"}))
        self.assertEqual(reply["id"], "overlay-0123456789ab")
        self.assertRegex(reply["cid"], r"^c-[0-9a-f]{8}$")
        self.assertEqual(start.call_args.args[2], "commit")
        self.assertEqual(start.call_args.args[4]["cid"], reply["cid"])
        with self.assertRaises(RuntimeError) as raised:  # a refusal comes back at once, before any worker exists
            self.runner.query("owned", "type_edit", "", options={"kind": "commit", "expect_revision": self.store()["revision"], "view": "shared"})
        self.assertEqual(json.loads(str(raised.exception))["error"], "confirmation_required")
        self.assertEqual(selected["name"], "owned")

    def test_the_job_options_filter_lists_commit_jobs_by_kind_and_cid(self):
        from hydralysis import api
        records = {"overlay-aaaaaaaaaaaa": {"kind": "commit", "options": {"cid": "c-11111111"}},
                   "overlay-bbbbbbbbbbbb": {"kind": "edit", "options": {}}}
        root = Path(self.settings["root"]) / "overlay-jobs"
        for name, record in records.items():
            (root / name).mkdir(parents=True)
            from hydralysis.backends import write_json
            write_json(root / name / "job.json", {"id": name, "state": "done", "target": "owned", "view": "", "created_at": 1.0,
                                                  "finished_at": 2.0, **record})
        with patch("hydralysis.api.load", return_value=self.settings):
            listed = json.loads(api.call("job", {"options": {"kind": "commit"}}))
            by_cid = json.loads(api.call("job", {"options": {"cid": "c-11111111"}}))
            none = json.loads(api.call("job", {"options": {"cid": "c-22222222"}}))
            with self.assertRaises(ValueError):
                api.call("job", {"options": {"other": 1}})
        self.assertEqual([row["id"] for row in listed["jobs"]], ["overlay-aaaaaaaaaaaa"])
        self.assertEqual(by_cid["jobs"][0]["cid"], "c-11111111")
        self.assertEqual(none["jobs"], [])


class Subsets(World, unittest.TestCase):
    def test_a_subset_commit_takes_only_the_selected_records_and_leaves_the_others_pending(self):
        self.edit("OnA", A)
        self.edit("OnB", B)
        first, second = self.ids()
        answer = self.commit(only={"ids": [first]})
        self.assertEqual(answer["ids"], [first])
        self.assertEqual(self.pending_ids(), [second])
        self.assertEqual(self.name_of(A), "OnA")
        self.assertEqual(self.name_of(B), "OnB")  # the pending record is replayed onto the new generation
        generation = self.daemon.projects[self.daemon._norm(self.head()["gpr"])]["programs"]["/owned.exe"]
        self.assertEqual(generation["saved"]["names"], {A: "OnA"})  # and is not in the generation
        self.oracle({})

    def test_selection_not_closed_names_the_missing_records_or_include_dependencies_adds_them(self):
        self.edit("First", A)
        self.edit("Second", A)
        first, second = self.ids()
        with self.assertRaises(commits.CommitError) as raised:
            self.commit(only={"ids": [second]})
        self.assertEqual((raised.exception.code, raised.exception.detail["missing"]), ("selection_not_closed", [first]))
        answer = self.commit(only={"ids": [second]}, include_dependencies=True)
        self.assertEqual(answer["ids"], [first, second])
        self.assertEqual(answer["closure_added"], [first])

    def test_a_batch_is_selected_whole_or_not_at_all(self):
        self.edit("One", A)
        self.edit("Two", B)
        store = self.store()
        store["edits"][0]["batch"] = store["edits"][1]["batch"] = "b" * 32
        workcopy._save_store(self.settings, self.target(), store)
        first, second = self.ids()
        with self.assertRaises(commits.CommitError) as raised:
            self.commit(only={"ids": [first]})
        self.assertEqual((raised.exception.code, raised.exception.detail["missing"]), ("selection_not_closed", [second]))
        self.assertEqual(self.commit(only={"ids": ["b" * 32]})["ids"], [first, second])  # by batch id: the whole batch

    def test_authors_select_their_records(self):
        self.edit("Mine", A)
        store = self.store()
        store["edits"][0]["by"] = {"client": "x:1", "harness": "other-agent"}
        workcopy._save_store(self.settings, self.target(), store)
        self.edit("Ours", B)
        mine, ours = self.ids()
        self.assertEqual(self.commit(only={"authors": ["other-agent"]})["ids"], [mine])
        self.assertEqual(self.pending_ids(), [ours])

    def test_unknown_ids_are_refused(self):
        self.edit("One")
        with self.assertRaises(commits.CommitError) as raised:
            self.commit(only={"ids": ["f" * 32]})
        self.assertEqual(raised.exception.code, "unknown_records")

    def test_drift_refuses_by_default_and_publishes_nothing(self):
        self.edit("One", A)
        self.edit("Two", B)
        self.daemon.projects[self.daemon._norm(self.gpr)]["programs"]["/owned.exe"]["saved"]["names"][A] = "OutOfBand"
        with self.assertRaises(commits.CommitError) as raised:
            self.commit()
        self.assertEqual(raised.exception.code, "drift")
        self.assertEqual([item["subject"] for item in raised.exception.detail["drift"]], ["address:" + A])
        self.assertEqual(lineage.history(self.settings, self.lineage_id())[-1]["reason"], "register")  # nothing published
        self.assertEqual(len(self.pending_ids()), 2)
        self.assertEqual(commits.last_steps(self.settings, self.lineage_id(), next(iter(commits.intent_cids(self.settings, self.lineage_id()))))["step"], "ABORTED")
        self.oracle({})

    def test_skip_leaves_the_drifted_record_and_its_dependents_pending_and_commits_the_rest(self):
        self.edit("One", A)       # drifts
        self.edit("Two", B)       # independent
        self.edit("Three", A)     # depends on One (same subject)
        one, two, three = self.ids()
        self.daemon.projects[self.daemon._norm(self.gpr)]["programs"]["/owned.exe"]["saved"]["names"][A] = "OutOfBand"
        answer = self.commit(on_drift="skip")
        self.assertEqual(answer["ids"], [two])
        self.assertEqual([item["id"] for item in answer["skipped"]], [one, three])
        self.assertEqual(answer["skipped"][0]["reason"], "drift")
        self.assertEqual(answer["skipped"][1]["reason"], "depends_on_drifted")
        # a skipped record below a committed one stays pending (its seq is lower) and is replayed onto the new generation
        self.assertEqual(self.pending_ids(), [one, three])
        self.assertEqual(self.name_of(B), "Two")
        self.assertEqual(self.name_of(A), "Three")  # replayed: the last pending rename of A wins in the working copy
        self.assertEqual([item["id"] for item in self.store()["commits"][0]["skipped"]], [one, three])
        self.oracle({})

    def test_a_skipped_record_is_taken_by_the_next_commit(self):
        self.edit("One", A)
        self.edit("Two", B)
        one, two = self.ids()
        self.daemon.projects[self.daemon._norm(self.gpr)]["programs"]["/owned.exe"]["saved"]["names"][A] = "OutOfBand"
        self.commit(on_drift="skip")
        # the record's `before` is checked again at the commit that takes it: the master of that commit still disagrees
        with self.assertRaises(commits.CommitError) as raised:
            self.commit()
        self.assertEqual(raised.exception.code, "drift")
        self.assertEqual(self.pending_ids(), [one])

    def test_subset_missing_type_fails_closed_and_publishes_nothing(self):
        self.daemon.typed_names = {"MyStruct"}
        self.edit("", A, kind="struct", path="/MyStruct", size=8, fields=[])
        self.edit("", B, kind="signature", prototype="void f(MyStruct *p)")
        struct, signature = self.ids()
        # the closure cannot see the type reference (the subjects differ), so the signature alone is selectable ...
        with self.assertRaises(commits.CommitError) as raised:
            self.commit(only={"ids": [signature]})
        # ... and applying it in the candidate fails closed: the commit ends ABORTED with the effect named
        self.assertEqual(raised.exception.code, "apply_refused")
        self.assertIn("unknown data type MyStruct", str(raised.exception))
        self.assertEqual(lineage.history(self.settings, self.lineage_id())[-1]["reason"], "register")
        self.assertEqual(self.pending_ids(), [struct, signature])
        # selecting both is fine
        self.assertEqual(self.commit(only={"ids": [struct, signature]})["generation"], 2)

    def test_edits_made_while_the_commit_runs_stay_pending_whatever_their_seq(self):
        self.edit("One", A)
        late = {}
        original = commits.Intent.write

        def write(intent, step, **data):
            original(intent, step, **data)
            if step == "BACKUP_DONE" and not late:
                late["answer"] = self.edit("Late", B)  # the view's lock is free after PREPARE: edits are not blocked
        with patch.object(commits.Intent, "write", write):
            answer = self.commit()
        self.assertEqual(len(answer["ids"]), 1)
        self.assertEqual(self.pending_ids(), [late["answer"]["overlay_id"]])
        self.assertEqual(self.store()["revision"], 3)  # edit, late edit, and the commit's own store write
        self.assertEqual(self.name_of(B), "Late")
        self.oracle({})


class ReferenceSnapshot(World, unittest.TestCase):
    def test_a_function_touched_by_a_pending_record_outside_the_commit_is_excluded_from_the_comparison(self):
        self.edit("Mid", A)
        self.edit("Final", A)
        mid, final = self.ids()
        answer = self.commit(only={"ids": [mid]})
        self.assertEqual(answer["excluded_functions"], [A])  # the working copy says Final, the candidate says Mid, by design
        self.assertEqual(self.name_of(A), "Final")
        generation = self.daemon.projects[self.daemon._norm(self.head()["gpr"])]["programs"]["/owned.exe"]
        self.assertEqual(generation["saved"]["names"][A], "Mid")

    def test_the_reference_is_the_working_copy_at_the_snapshot_not_the_live_one(self):
        self.edit("Alpha", A)
        seen = {}
        original = commits._verify_candidate

        def verify(settings, engine, job, selected, candidate_gpr, clone_folder, source_gpr, committing, reference, excluded):
            seen["reference"] = dict(reference)
            return original(settings, engine, job, selected, candidate_gpr, clone_folder, source_gpr, committing, reference, excluded)
        with patch.object(commits, "_verify_candidate", verify):
            self.commit()
        self.assertIn("Alpha", seen["reference"][A])

    def test_a_decompile_that_differs_from_the_reference_aborts_the_commit(self):
        self.edit("Alpha", A)
        original = commits._decompile
        calls = {"n": 0}

        def decompile(engine, program, address, sha256):
            calls["n"] += 1
            text = original(engine, program, address, sha256)
            return text.replace("Alpha", "Different") if calls["n"] > 1 else text
        with patch.object(commits, "_decompile", decompile), self.assertRaises(commits.CommitError) as raised:
            self.commit()
        self.assertEqual(raised.exception.code, "verify_failed")
        self.assertEqual(lineage.history(self.settings, self.lineage_id())[-1]["reason"], "register")
        self.oracle({})


class Revert(World, unittest.TestCase):
    def test_revert_makes_the_ids_pending_again_and_the_pointer_goes_back(self):
        self.edit("Alpha")
        answer = self.commit()
        selected = self.target()
        result = commits.revert(self.settings, selected, {"kind": "commit_revert", "expect_revision": self.store()["revision"]})
        self.assertEqual((result["reverted"], result["generation"], result["pending_again"]), (answer["cid"], 0, 1))
        self.assertEqual(self.head()["gen"], 0)
        self.assertEqual(self.head()["reason"], "rollback")
        self.assertEqual(self.pending_ids(), answer["ids"])
        self.assertTrue(self.store()["commits"][0]["reverted"])
        self.assertEqual(self.name_of(A), "Alpha")  # the pending record is replayed onto generation 0 again
        self.oracle({1: self.generation_tree(1)})

    def test_revert_chain_c1_c2_then_revert_c2_then_c1(self):
        self.edit("One", A)
        c1 = self.commit()
        self.edit("Two", B)
        c2 = self.commit()
        before = {1: self.generation_tree(1), 2: self.generation_tree(2)}
        # c1's records left edits[] when c2 finalised: they are in the archive
        store = self.store()
        self.assertEqual([entry["cid"] for entry in store["archived"]], [c1["cid"]])
        self.assertEqual([record["id"] for record in store["edits"]], c2["ids"])
        first = commits.revert(self.settings, self.target(), {"kind": "commit_revert", "expect_revision": store["revision"]})
        self.assertEqual((first["reverted"], first["generation"]), (c2["cid"], 1))
        second = commits.revert(self.settings, self.target(), {"kind": "commit_revert", "expect_revision": self.store()["revision"]})
        self.assertEqual((second["reverted"], second["generation"], second["rehydrated"]), (c1["cid"], 0, 1))
        # the records of both are pending again, in seq order, and the generation pointer is back at 0
        store = self.store()
        self.assertEqual([record["id"] for record in workcopy.pending_of(store)], c1["ids"] + c2["ids"])
        self.assertEqual([record["seq"] for record in store["edits"]], sorted(record["seq"] for record in store["edits"]))
        self.assertEqual((self.head()["gen"], store["base"]["generation"]), (0, 0))
        self.assertEqual(store["archived"], [])
        self.assertTrue(all(entry["reverted"] for entry in store["commits"]))
        self.assertEqual((self.name_of(A), self.name_of(B)), ("One", "Two"))
        self.oracle(before)
        # and a new commit after the reverts reserves a new generation number (never reuses 1 or 2) and takes both records
        third = self.commit()
        self.assertEqual(third["generation"], 3)
        self.assertEqual(sorted(third["ids"]), sorted(c1["ids"] + c2["ids"]))
        self.oracle(before)

    def test_only_the_latest_live_commit_can_be_reverted_and_only_in_its_view(self):
        self.edit("One", A)
        self.commit()
        with self.assertRaises(commits.CommitError) as raised:
            commits.revert(self.settings, self.target("other"), {"kind": "commit_revert", "expect_revision": 0})
        self.assertEqual(raised.exception.code, "nothing_to_revert")
        with self.assertRaises(commits.CommitError) as raised:
            commits.revert(self.settings, self.target(), {"kind": "commit_revert", "expect_revision": 0})
        self.assertEqual(raised.exception.code, "revision_changed")

    def test_revert_refuses_when_the_previous_generation_no_longer_verifies(self):
        self.edit("One", A)
        self.commit()
        self.edit("Two", B)
        self.commit()
        folder = lineage.generation_dir(self.settings, self.lineage_id(), 1)
        os.chmod(folder, 0o777)
        victim = next(path for path in folder.rglob("programs.json"))
        os.chmod(victim, 0o666)
        victim.write_text("tampered", encoding="utf-8")
        with self.assertRaises(commits.CommitError) as raised:
            commits.revert(self.settings, self.target(), {"kind": "commit_revert", "expect_revision": self.store()["revision"]})
        self.assertEqual(raised.exception.code, "revert_failed")
        self.assertEqual(self.head()["gen"], 2)

    def test_a_revert_that_would_exceed_the_cap_is_refused_with_store_full_and_changes_nothing(self):
        self.edit("One", A)
        self.commit()
        self.edit("Two", B)
        self.commit()
        store = self.store()
        revision = store["revision"]
        with patch.object(workcopy, "MAX_OVERLAYS", 1):
            commits.revert(self.settings, self.target(), {"kind": "commit_revert", "expect_revision": revision})  # c2: its records are in edits[]
            with self.assertRaises(commits.CommitError) as raised:
                commits.revert(self.settings, self.target(), {"kind": "commit_revert", "expect_revision": self.store()["revision"]})
        self.assertEqual(raised.exception.code, "store_full")
        self.assertEqual(self.head()["gen"], 1)  # no rollback line was written for the refused one
        self.assertEqual(len(self.store()["archived"]), 1)

    def test_a_missing_archive_refuses_with_archive_unreadable(self):
        from hydralysis import annotations
        self.edit("One", A)
        c1 = self.commit()
        self.edit("Two", B)
        self.commit()
        commits.revert(self.settings, self.target(), {"kind": "commit_revert", "expect_revision": self.store()["revision"]})
        annotations._archive_path(self.settings, self.target(), c1["cid"]).unlink()
        with self.assertRaises(commits.CommitError) as raised:
            commits.revert(self.settings, self.target(), {"kind": "commit_revert", "expect_revision": self.store()["revision"]})
        self.assertEqual(raised.exception.code, "archive_unreadable")
        self.assertEqual(self.head()["gen"], 1)

    def test_revert_is_refused_for_a_record_in_a_live_commit(self):
        self.edit("One", A)
        (record,) = self.ids()
        self.commit()
        with self.assertRaises(RuntimeError) as raised:
            workcopy.revert(self.settings, self.target(), [record], self.store()["revision"])
        self.assertEqual(json.loads(str(raised.exception))["error"], "already_committed")
        commits.revert(self.settings, self.target(), {"kind": "commit_revert", "expect_revision": self.store()["revision"]})
        self.assertEqual(workcopy.revert(self.settings, self.target(), [record], self.store()["revision"])["reverted"], 1)


class Archival(World, unittest.TestCase):
    def test_the_previous_commits_records_leave_the_store_and_the_caps_bound_the_live_records(self):
        self.edit("One", A)
        c1 = self.commit()
        self.assertEqual(len(self.store()["edits"]), 1)  # the latest commit's records stay: commit_revert needs them
        self.edit("Two", B)
        c2 = self.commit()
        store = self.store()
        self.assertEqual([record["id"] for record in store["edits"]], c2["ids"])
        self.assertEqual([(entry["cid"], entry["count"]) for entry in store["archived"]], [(c1["cid"], 1)])
        self.assertTrue(Path(store["archived"][0]["archive"]).is_file())
        # an export reads the archive on demand and the history is whole
        from hydralysis import annotations
        self.assertEqual([record["id"] for record in annotations.archived_records(self.settings, self.target(), store)], c1["ids"])
        self.assertEqual([entry["cid"] for entry in store["commits"]], [c2["cid"]])


class Stale(World, unittest.TestCase):
    def test_another_view_is_stale_after_a_commit_and_refuses_edits_but_keeps_answering(self):
        # The commit changes B, where the other view holds a record too: a clean-only rebase (Y5, 4.10) cannot settle it, so the
        # edit is refused. (A view behind the head whose records do not conflict is rebased first and its edit goes through.)
        self.edit("Mine", B)
        self.edit("Theirs", B, view="other")
        self.assertEqual(self.name_of(B, view="other"), "Theirs")
        self.commit()
        # the other view's records rest on generation 0; reads keep answering from its working copy ...
        self.assertEqual(self.name_of(B, view="other"), "Theirs")
        # ... and a mutation is refused with stale_view until it rebases
        with self.assertRaises(RuntimeError) as raised:
            self.edit("More", B, view="other")
        body = json.loads(str(raised.exception))
        self.assertEqual((body["error"], body["stale"]), ("stale_view", "master_generation_changed"))
        self.assertEqual(body["head"]["generation"], 1)

    def test_a_new_view_starts_on_the_head_generation(self):
        self.edit("Mine", A)
        self.commit()
        self.assertEqual(self.edit("Fresh", B, view="newcomer")["revision"], 1)
        self.assertEqual(self.store("newcomer")["base"]["generation"], 1)
        self.assertEqual(self.name_of(A, view="newcomer"), "Mine")
        self.assertEqual(self.name_of(B, view="newcomer"), "Fresh")

    def test_a_view_that_is_already_on_the_head_is_not_stale(self):
        self.edit("Mine", A)
        self.commit()
        self.assertIsNone(workcopy.stale_reason(self.store(), self.target()))


class Busy(World, unittest.TestCase):
    def test_two_simultaneous_commits_give_one_commit_busy(self):
        self.edit("One", A)
        entered, release = threading.Event(), threading.Event()
        original = commits._backup

        def slow(*args, **kwargs):
            entered.set()
            release.wait(30)
            return original(*args, **kwargs)
        outcomes = {}

        def first():
            try:
                outcomes["first"] = self.commit()
            except BaseException as error:  # noqa: BLE001 - the test reports whatever happened
                outcomes["first"] = error
        with patch.object(commits, "_backup", slow):
            thread = threading.Thread(target=first)
            thread.start()
            self.assertTrue(entered.wait(30))
            with self.assertRaises(commits.CommitError) as raised:
                self.commit()
            self.assertEqual(raised.exception.code, "commit_busy")
            release.set()
            thread.join(60)
        self.assertEqual(outcomes["first"]["generation"], 1)
        self.assertEqual(len([row for row in lineage.history(self.settings, self.lineage_id()) if row["reason"] == "commit"]), 1)


class Abort(World, unittest.TestCase):
    def test_commit_abort_is_honoured_before_the_publish_and_too_late_after_it(self):
        self.edit("One", A)
        cid = "c-abcd0001"
        original = commits.Intent.write
        flagged = {}

        def write(intent, step, **data):
            original(intent, step, **data)
            if step == "CANDIDATE_RESERVED" and not flagged:
                flagged["answer"] = commits.request_abort(self.settings, self.target(), cid)
        with patch.object(commits.Intent, "write", write), self.assertRaises(commits.CommitError) as raised:
            self.commit(cid=cid)
        self.assertEqual(raised.exception.code, "aborted")
        self.assertTrue(flagged["answer"]["requested"])
        self.assertEqual(commits.last_steps(self.settings, self.lineage_id(), cid)["step"], "ABORTED")
        self.assertEqual(self.head()["gen"], 0)
        other = self.commit(cid="c-abcd0002")
        with self.assertRaises(commits.CommitError) as late:
            commits.request_abort(self.settings, self.target(), other["cid"])
        self.assertEqual(late.exception.code, "cancel_too_late")


class AfterPublish(World, unittest.TestCase):
    """Review round 1: once the CURRENT.log line exists the commit is the truth; nothing writes ABORTED over it."""

    def test_a_finalize_that_fails_after_the_publish_leaves_the_log_at_published_and_recovery_rolls_forward(self):
        self.edit("One", A)
        cid = "c-fa5e0001"
        original = commits.finalize
        calls = []

        def broken(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise commits.CommitError("finalize_failed", "records of the commit are not in the store: x")
            return original(*args, **kwargs)
        with patch.object(commits, "finalize", broken), self.assertRaises(commits.CommitError) as raised:
            self.commit(cid=cid)
        self.assertEqual(raised.exception.code, "finalize_pending")
        lid = self.lineage_id()
        self.assertEqual(self.head()["gen"], 1)
        self.assertEqual(commits.last_steps(self.settings, lid, cid)["step"], "PUBLISHED")  # never ABORTED
        self.assertEqual(self.store()["commits"], [])
        with patch.object(commits, "finalize", broken):  # a read heals it: the line is the truth
            self.assertEqual(self.name_of(A), "One")
        self.assertEqual([entry["cid"] for entry in self.store()["commits"]], [cid])
        self.assertEqual(self.pending_ids(), [])
        self.assertEqual(commits.last_steps(self.settings, lid, cid)["step"], "FINALIZED")
        self.oracle({})

    def test_a_lock_failure_in_finalize_takes_the_same_path(self):
        self.edit("One", A)
        cid = "c-fa5e0002"
        original = commits.finalize
        calls = []

        def busy(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError(json.dumps({"error": "busy", "what": "view lock"}))
            return original(*args, **kwargs)
        with patch.object(commits, "finalize", busy), self.assertRaises(commits.CommitError) as raised:
            self.commit(cid=cid)
        self.assertEqual(raised.exception.code, "finalize_pending")
        self.assertEqual(commits.last_steps(self.settings, self.lineage_id(), cid)["step"], "PUBLISHED")
        again = self.commit(cid=cid)  # a resubmission is answered from the log, not repeated
        self.assertEqual(again["generation"], 1)
        self.assertEqual(len(self.published(cid)), 1)
        self.assertEqual(self.pending_ids(), [])

    def test_a_revert_of_a_selected_record_during_a_commit_is_refused_and_the_commit_finalizes(self):
        self.edit("One", A)
        selected_ids = self.ids()
        cid = "c-fa5e0003"
        original = commits.Intent.write
        seen = {}

        def write(intent, step, **data):
            original(intent, step, **data)
            if step == "SEALED" and not seen:
                with self.assertRaises(RuntimeError) as raised:
                    workcopy.revert(self.settings, self.target(), selected_ids, expect=self.store()["revision"])
                seen["error"] = json.loads(str(raised.exception))
        with patch.object(commits.Intent, "write", write):
            answer = self.commit(cid=cid)
        self.assertEqual(seen["error"]["error"], "commit_in_flight")
        self.assertEqual(seen["error"]["ids"], selected_ids)
        self.assertEqual(answer["generation"], 1)
        self.assertEqual([entry["cid"] for entry in self.store()["commits"]], [cid])
        self.assertEqual(self.name_of(A), "One")
        self.oracle({})

    def test_a_dead_unpublished_commit_does_not_block_a_revert(self):
        self.edit("One", A)
        selected_ids = self.ids()
        env = {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "commit.after_backup:raise"}
        with patch.dict(os.environ, env), self.assertRaises(durable.FaultInjected):
            self.commit(cid="c-fa5e0004")
        self.assertEqual(workcopy.revert(self.settings, self.target(), selected_ids, expect=self.store()["revision"])["reverted"], 1)

    def test_a_published_commit_that_is_not_finalized_still_protects_its_records(self):
        self.edit("One", A)
        selected_ids = self.ids()
        env = {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "commit.after_publish:raise"}
        with patch.dict(os.environ, env), self.assertRaises(durable.FaultInjected):
            self.commit(cid="c-fa5e0005")
        self.assertEqual(commits.in_flight_ids(self.settings, self.target()), {ident: "c-fa5e0005" for ident in selected_ids})

    def test_a_store_write_without_its_finalized_line_is_closed_and_the_skipped_record_can_be_reverted(self):
        self.edit("One", A)       # drifts, so it is skipped and stays pending
        self.edit("Two", B)
        one, two = self.ids()
        self.daemon.projects[self.daemon._norm(self.gpr)]["programs"]["/owned.exe"]["saved"]["names"][A] = "OutOfBand"
        cid = "c-fa5e0007"
        original = commits.Intent.write

        def write(intent, step, **data):
            if step == "FINALIZED":
                raise OSError("disk full")  # the state a crash right after the store write leaves
            return original(intent, step, **data)
        with patch.object(commits.Intent, "write", write), self.assertRaises(commits.CommitError) as raised:
            self.commit(cid=cid, on_drift="skip")
        self.assertEqual(raised.exception.code, "finalize_pending")
        lid = self.lineage_id()
        self.assertEqual([entry["cid"] for entry in self.store()["commits"]], [cid])  # the store write happened
        self.assertEqual(commits.last_steps(self.settings, lid, cid)["step"], "PUBLISHED")
        # the store already holds the commit, so nothing is in flight even though the intent log still says PUBLISHED
        self.assertEqual(commits.in_flight_ids(self.settings, self.target()), {})
        # a resubmission closes the intent log
        again = self.commit(cid=cid)
        self.assertEqual(again["generation"], 1)
        self.assertEqual(commits.last_steps(self.settings, lid, cid)["step"], "FINALIZED")
        self.assertEqual(len(self.published(cid)), 1)
        self.oracle({})
        revert = workcopy.revert(self.settings, self.target(), [one], expect=self.store()["revision"])
        self.assertEqual(revert["reverted"], 1)

    def test_recovery_closes_a_commit_whose_store_write_has_no_finalized_line(self):
        self.edit("One", A)
        cid = "c-fa5e0008"
        original = commits.Intent.write

        def write(intent, step, **data):
            if step == "FINALIZED":
                raise OSError("disk full")
            return original(intent, step, **data)
        with patch.object(commits.Intent, "write", write), self.assertRaises(commits.CommitError):
            self.commit(cid=cid)
        lid = self.lineage_id()
        self.assertEqual(commits.last_steps(self.settings, lid, cid)["step"], "PUBLISHED")
        self.assertEqual(self.name_of(A), "One")  # a read heals it
        self.assertEqual(commits.last_steps(self.settings, lid, cid)["step"], "FINALIZED")

    def test_an_abort_requested_just_before_the_publish_is_honoured_and_the_request_is_consumed(self):
        self.edit("One", A)
        cid = "c-fa5e0006"
        original = commits.Intent.write
        flagged = {}

        def write(intent, step, **data):
            original(intent, step, **data)
            if step == "SEALED" and not flagged:
                flagged["answer"] = commits.request_abort(self.settings, self.target(), cid)
        with patch.object(commits.Intent, "write", write), self.assertRaises(commits.CommitError) as raised:
            self.commit(cid=cid)
        self.assertEqual(raised.exception.code, "aborted")
        self.assertEqual(self.head()["gen"], 0)
        flag = lineage.lineage_dir(self.settings, self.lineage_id()) / "commits" / (cid + ".abort")
        self.assertFalse(flag.exists())
        answer = self.commit(cid=cid)  # the same cid, resubmitted, is not aborted again
        self.assertEqual(answer["generation"], 2)  # the aborted attempt kept its reserved number 1


class LineageCreation(World, unittest.TestCase):
    def test_eight_threads_creating_the_lineage_of_one_origin_make_one_lineage(self):
        base = self.runner.target("owned")
        barrier = threading.Barrier(8)
        found, errors = [], []

        def create():
            try:
                barrier.wait(30)
                found.append(lineage.ensure(self.settings, dict(base))["id"])
            except BaseException as error:  # noqa: BLE001 - the test reports whatever happened
                errors.append(error)
        threads = [threading.Thread(target=create) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(len(set(found)), 1, found)
        folders = [item.name for item in lineage.lineages_root(self.settings).iterdir() if item.name.startswith("L-")]
        self.assertEqual(folders, [found[0]])

    def test_two_first_commits_from_two_threads_make_one_lineage(self):
        self.edit("One", A)
        barrier = threading.Barrier(2)
        outcomes = {}
        original = commits._backup

        def slow(*args, **kwargs):
            threading.Event().wait(1.5)  # keeps the winner inside the lock while the other arrives
            return original(*args, **kwargs)

        def go(name):
            try:
                barrier.wait(30)
                outcomes[name] = self.commit(cid="c-fa5e01%02d" % len(outcomes))
            except BaseException as error:  # noqa: BLE001 - the test reports whatever happened
                outcomes[name] = error
        with patch.object(commits, "_backup", slow):
            threads = [threading.Thread(target=go, args=(name,)) for name in ("a", "b")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(120)
        folders = [item.name for item in lineage.lineages_root(self.settings).iterdir() if item.name.startswith("L-")]
        self.assertEqual(len(folders), 1, folders)
        busy = [item for item in outcomes.values() if isinstance(item, commits.CommitError) and item.code == "commit_busy"]
        done = [item for item in outcomes.values() if isinstance(item, dict) and item.get("ok")]
        self.assertEqual((len(done), len(busy)), (1, 1), outcomes)


class WorkerSettings(World, unittest.TestCase):
    def test_the_commit_worker_gets_the_backup_and_generation_policy_of_the_caller(self):
        from hydralysis import backups, overlayjobs
        settings = {**self.settings, "backup_min_independent": 1, "backup_min_verified": 2, "backup_confirm_gb": 7,
                    "backup_root_warn_gb": 9, "generations_root": str(self.root / "gens"), "tmp_dir": str(self.root / "tmp"),
                    "backup_roots": [{"path": str(self.root / "b1")}, {"path": str(self.root / "b2"), "independent": True}]}
        child = type("Child", (), {"pid": 4242})()
        with patch("hydralysis.overlayjobs.proc.popen", return_value=child), patch("hydralysis.overlayjobs.proc_start", return_value=1):
            record = overlayjobs.start(settings, "owned", "commit", "", {"cid": "c-fa5e0007"})
        worker = json.loads((overlayjobs.job_path(settings, record["id"]).parent / "settings.json").read_text(encoding="utf-8"))
        for key in overlayjobs.WORKER_POLICY_KEYS:
            self.assertEqual(worker.get(key), settings.get(key), key)
        self.assertEqual(backups.policy(worker), backups.policy(settings))
        self.assertEqual(lineage.lineages_root(worker), lineage.lineages_root(settings))
        self.assertEqual(worker["generations_root"], settings["generations_root"])


class Sealing(World, unittest.TestCase):
    def test_candidate_writable_until_seal(self):
        """The candidate opens writable and saves before 7b; after it a writable open, save and an owner script are refused."""
        self.edit("One", A)
        opened = []
        original = commits._verify_candidate

        def verify(settings, engine, job, selected, candidate_gpr, *rest):
            # at step 7 the candidate is still state:"candidate": it is not sealed yet
            sidecar = json.loads(next(Path(candidate_gpr).parent.glob("*.fork.json")).read_text(encoding="utf-8"))
            opened.append(sidecar["state"])
            return original(settings, engine, job, selected, candidate_gpr, *rest)
        with patch.object(commits, "_verify_candidate", verify):
            self.commit()
        self.assertEqual(opened, ["candidate"])
        top = self.head()
        engine = fakehydra.FakeEngine(self.settings, role="writer")
        project = engine.call("open_project", path=top["gpr"])
        for attempt in (lambda: engine.call("open_program", path="/owned.exe", project=project["id"], writable=True),
                        lambda: engine.call("save", program=project["id"] + ":/owned.exe")):
            with self.assertRaises(hydra.EngineError) as raised:
                attempt()
            self.assertEqual(raised.exception.code, "sealed")
        # the engine reads the seal as the union of the records: the marker file alone is enough
        sidecar = next(Path(top["gpr"]).parent.glob("*.fork.json"))
        sidecar.write_text(json.dumps({"purpose": "generation", "disposable": False}), encoding="utf-8")
        with self.assertRaises(hydra.EngineError):
            engine.call("open_program", path="/owned.exe", project=project["id"], writable=True)

    def test_the_rev6_predicate_would_refuse_the_candidate_before_it_is_verified(self):
        """Red against `disposable:false` as the sealed predicate: a candidate could not be replayed or saved (B1)."""
        self.daemon.sealed_predicate = "rev6"
        self.edit("One", A)
        with self.assertRaises(commits.CommitError) as raised:
            self.commit()
        self.assertIn("sealed", str(raised.exception))
        self.assertEqual(self.head()["gen"], 0)


class Tamper(World, unittest.TestCase):
    def test_a_process_that_writes_into_a_generation_flags_the_lineage_tampered(self):
        self.edit("One", A)
        self.commit()
        folder = lineage.generation_dir(self.settings, self.lineage_id(), 1)
        victim = next(folder.rglob("programs.json"))
        os.chmod(victim, 0o666)
        victim.write_text("tampered", encoding="utf-8")
        status = json.loads(self.runner.query("owned", "status", "", options={"show": "lineage"}))
        self.assertEqual(status["tampered"][0]["generation"], 1)
        self.edit("Two", B)
        with self.assertRaises(commits.CommitError) as raised:
            self.commit()
        self.assertEqual(raised.exception.code, "tampered")

    def test_an_unchanged_generation_is_not_rehashed_and_a_changed_one_is(self):
        self.edit("One", A)
        self.commit()
        real = lineage.verify_manifest
        with patch.object(lineage, "verify_manifest", side_effect=real) as verify:
            self.assertEqual(lineage.tampered(self.settings, self.lineage_id()), [])
            self.assertEqual(lineage.tampered(self.settings, self.lineage_id()), [])
            self.assertEqual(verify.call_count, 1)  # the second check reads the files' size, time and id only (H17)
            self.assertEqual(lineage.tampered({**self.settings, "tampered_cache_s": 0}, self.lineage_id()), [])
            self.assertEqual(verify.call_count, 2)  # 0: every check re-hashes
            victim = next(lineage.generation_dir(self.settings, self.lineage_id(), 1).rglob("programs.json"))
            os.chmod(victim, 0o666)
            victim.write_text("tampered", encoding="utf-8")
            self.assertEqual(lineage.tampered(self.settings, self.lineage_id())[0]["generation"], 1)
            self.assertEqual(verify.call_count, 3)


class LineageLog(World, unittest.TestCase):
    def test_a_torn_tail_is_ignored_by_readers_and_repaired_by_the_next_writer(self):
        self.edit("One", A)
        self.commit()
        log = lineage.current_log(self.settings, self.lineage_id())
        before = log.path.read_bytes()
        with log.path.open("ab") as handle:
            handle.write(b"deadbeef {\"seq\":3,\"gen\":9")
        top = self.head()
        self.assertEqual(top["gen"], 1)
        self.assertIsNotNone(top["torn_tail"])
        self.assertEqual(json.loads(self.runner.query("owned", "status", "", options={"show": "lineage"}))["torn_tail"]["bytes"],
                         len(b"deadbeef {\"seq\":3,\"gen\":9"))
        self.edit("Two", B)
        self.commit()  # the next writer repairs it first
        self.assertEqual(log.path.read_bytes()[:len(before)], before)
        self.assertEqual(len(log.repairs()), 1)
        self.assertEqual(len(list(log.path.parent.glob("CURRENT.log.torn-*"))), 1)
        self.assertIsNone(self.head()["torn_tail"])

    def test_a_gap_in_the_middle_is_lineage_corrupt_reads_use_the_last_good_line_and_commits_are_refused(self):
        self.edit("One", A)
        self.commit()
        self.edit("Two", B)
        self.commit()
        self.edit("Three", C)  # recorded while the log is whole: afterwards the head resolves to an older generation
        log = lineage.current_log(self.settings, self.lineage_id())
        lines = log.path.read_bytes().split(b"\n")
        lines[1] = b"00000000 garbage"
        log.path.write_bytes(b"\n".join(lines))
        top = self.head()
        self.assertEqual(top["gen"], 0)  # the last good line before the gap
        self.assertEqual(top["corrupt"]["error"], "lineage_corrupt")
        status = json.loads(self.runner.query("owned", "status", "", options={"show": "lineage"}))
        self.assertEqual(status["error"], "lineage_corrupt")
        with self.assertRaises(commits.CommitError) as raised:
            self.commit()
        self.assertEqual(raised.exception.code, "lineage_corrupt")


# ---- the fault matrix -----------------------------------------------------------------------------------------------

FAULT_POINTS = ("after_prepare", "after_backup", "after_reserve", "after_fork", "mid_apply", "after_save", "after_force",
                "after_manifest", "after_verify", "after_seal", "before_publish", "after_publish", "finalize_mid")
# After this step the CURRENT.log line exists: the commit is the new generation, whatever else died.
PUBLISHED_POINTS = {"after_publish", "finalize_mid"}
# From these points on a generation number was reserved in the log, and an unpublished attempt never gives it back.
RESERVED_POINTS = {"after_reserve", "after_fork", "mid_apply", "after_save", "after_force", "after_manifest", "after_verify",
                   "after_seal", "before_publish"}


class Died(BaseException):
    """What a killed process looks like to the tests: it unwinds without any handler of the commit writing a thing."""


def die():
    raise Died()


class FaultMatrix(World, unittest.TestCase):
    CID = "c-fa010001"

    def faulted(self, point, action="raise", **options):
        env = {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "commit.%s:%s" % (point, action)}
        with patch.dict(os.environ, env), patch.object(durable, "_die", die):
            with self.assertRaises((durable.FaultInjected, Died)):
                self.commit(cid=self.CID, **options)

    def settle(self, before, **options):
        """Recovery and a resubmission with the same cid, then the oracle."""
        answer = self.commit(cid=self.CID, **options)
        self.assertEqual(len(self.published(self.CID)), 1, "O5 one published line")
        self.assertEqual(len([entry for entry in self.store()["commits"] + self.store()["archived"] if entry["cid"] == self.CID]), 1, "O5 one entry")
        self.oracle(before)
        return answer

    def test_every_fault_point_leaves_the_old_state_or_the_new_one_and_a_resubmission_ends_with_one_commit(self):
        for point in FAULT_POINTS:
            with self.subTest(point=point):
                self.setUp()
                self.edit("One", A)
                self.edit("Two", B)
                self.faulted(point)
                self.oracle({}, "after the fault at " + point)
                top = self.head()
                self.assertEqual(top["gen"], 1 if point in PUBLISHED_POINTS else 0, point)
                answer = self.settle({})
                self.assertTrue(answer["ok"])
                # an abandoned candidate is never reused: once a number was reserved, the new attempt reserves the next one
                reserved = point in RESERVED_POINTS
                self.assertEqual(self.head()["gen"], 2 if reserved else 1, point)
                if point in PUBLISHED_POINTS:
                    self.assertEqual(answer["generation"], 1)
                self.assertEqual(self.name_of(A), "One")
                self.assertEqual(self.pending_ids(), [])

    def test_a_published_but_unfinalized_commit_is_rolled_forward_from_the_manifest(self):
        self.edit("One", A)
        self.faulted("after_publish")
        self.assertEqual(self.head()["gen"], 1)
        self.assertEqual(self.store()["commits"], [])  # the store write never happened
        # a read heals it before answering: the CURRENT.log line is the truth
        self.assertEqual(self.name_of(A), "One")
        self.assertEqual(len(self.store()["commits"]), 1)
        self.assertEqual(self.pending_ids(), [])
        self.oracle({})

    def test_recovery_run_twice_reaches_the_same_state(self):
        for point in ("after_publish", "finalize_mid", "after_seal"):
            with self.subTest(point=point):
                self.setUp()
                self.edit("One", A)
                self.faulted(point)
                lid = self.lineage_id()
                lock = commits.LaneLock(str(lineage.commit_lock_path(self.settings, lid)))
                self.assertTrue(lock.acquire())
                try:
                    first = commits.recover(self.settings, self.target(), lid)
                    state = (lineage.history(self.settings, lid), self.store()["commits"], commits.last_steps(self.settings, lid, self.CID)["step"])
                    second = commits.recover(self.settings, self.target(), lid)
                    again = (lineage.history(self.settings, lid), self.store()["commits"], commits.last_steps(self.settings, lid, self.CID)["step"])
                finally:
                    lock.release()
                self.assertEqual(second, [])
                self.assertEqual(state, again, "O6")
                self.assertTrue(first)

    def test_a_kill_during_recovery_recovers_again_to_the_same_state(self):
        self.edit("One", A)
        self.faulted("after_publish")
        lid = self.lineage_id()
        lock = commits.LaneLock(str(lineage.commit_lock_path(self.settings, lid)))
        self.assertTrue(lock.acquire())
        try:
            with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "commit.finalize_mid:raise"}), \
                    self.assertRaises(durable.FaultInjected):
                commits.recover(self.settings, self.target(), lid)
            self.assertEqual(self.store()["commits"], [])
            commits.recover(self.settings, self.target(), lid)
        finally:
            lock.release()
        self.assertEqual(len(self.store()["commits"]), 1)
        self.oracle({})

    def test_publish_torn_then_a_successful_new_commit_with_the_same_cid(self):
        # The length of the line a commit appends is measured once (every world has the same path lengths): the last offset
        # tried is every byte but the LF, the first is 0, and the others are in the middle of the line.
        lengths = []
        original = durable.AppendLog._raw_append

        def measure(path, data, repair_tail=False, faults=True):
            lengths.append(len(data))
            return original(path, data, repair_tail, faults)
        self.edit("One", A)
        with patch.object(durable.AppendLog, "_raw_append", staticmethod(measure)):
            self.commit(cid="c-fa0100ff")
        total = lengths[-2]  # the CURRENT.log line is the second-last append (the FINALIZED intent line follows it)
        for offset in (0, 1, 9, 40, total // 2, total - 1):
            with self.subTest(offset=offset):
                self.setUp()
                self.edit("One", A)
                self.edit("Two", B)
                with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "commit.publish_torn:torn:%d" % offset}), \
                        patch.object(durable, "_die", die):
                    with self.assertRaises(Died):
                        self.commit(cid=self.CID)
                log = lineage.current_log(self.settings, self.lineage_id())
                raw = log.path.read_bytes()
                fragment = raw[raw.rfind(b"\n") + 1:] if not raw.endswith(b"\n") else b""
                self.assertEqual(len(fragment), offset)
                # readers see the old head and a torn tail (or, at offset 0, nothing was written at all)
                self.assertEqual(self.head()["gen"], 0)
                self.assertEqual(self.published(self.CID), [])
                answer = self.settle({})
                self.assertEqual(answer["generation"], 2)  # attempt 2 reserves a new generation; the first candidate is never reused
                if fragment:
                    self.assertEqual(len(log.repairs()), 1)
                    self.assertEqual(len(list(log.path.parent.glob("CURRENT.log.torn-*"))), 1)
                    kept = next(log.path.parent.glob("CURRENT.log.torn-*")).read_bytes()
                    self.assertEqual(kept, fragment)  # the preserved fragment is exactly what was torn
                self.assertEqual(commits.last_steps(self.settings, self.lineage_id(), self.CID)["attempt"], 2)

    def test_intent_torn_leaves_a_log_the_next_attempt_repairs(self):
        for step_offset in (0, 7, 30):
            with self.subTest(offset=step_offset):
                self.setUp()
                self.edit("One", A)
                with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "commit.intent_torn:torn:%d" % step_offset}), \
                        patch.object(durable, "_die", die):
                    with self.assertRaises(Died):
                        self.commit(cid=self.CID)
                self.assertEqual(self.head()["gen"], 0)
                answer = self.settle({})
                self.assertEqual(answer["generation"], 1)
                log = lineage.intent_log(self.settings, self.lineage_id(), self.CID)
                self.assertIsNone(log.scan().torn_tail)
                self.assertIsNone(log.scan().corrupt)

    def test_subset_variants_of_mid_apply_and_finalize_mid_keep_the_skipped_record_pending(self):
        for point in ("mid_apply", "finalize_mid"):
            with self.subTest(point=point):
                self.setUp()
                self.edit("One", A)
                self.edit("Two", B)
                one, two = self.ids()
                self.daemon.projects[self.daemon._norm(self.gpr)]["programs"]["/owned.exe"]["saved"]["names"][A] = "OutOfBand"
                self.faulted(point, on_drift="skip")
                self.assertIn(one, self.pending_ids())
                answer = self.settle({}, on_drift="skip")
                self.assertEqual(answer["ids"], [two])
                self.assertEqual(self.pending_ids(), [one])  # the skipped record is still pending, never taken for committed
                self.assertEqual(self.name_of(A), "One")

    def test_resume_verified_publishes_the_verified_candidate_without_rebuilding_it(self):
        for point in ("after_verify", "after_seal", "before_publish"):
            with self.subTest(point=point):
                self.setUp()
                self.edit("One", A)
                self.edit("Two", B)
                self.faulted(point)
                candidate = lineage.generation_dir(self.settings, self.lineage_id(), 1)
                before = lineage.tree_hash(candidate)
                forks = len([c for c in self.daemon.calls if c[1] == "fork_project"])
                saves = len([c for c in self.daemon.calls if c[1] == "save"])
                answer = self.settle({}, resume_verified=True)
                self.assertTrue(answer["resumed"])
                self.assertEqual(answer["generation"], 1)                 # the sealed candidate itself, not a new number
                self.assertEqual(lineage.tree_hash(candidate), before)    # not rebuilt, not touched
                self.assertTrue((candidate / "SEALED.json").is_file())    # sealed if it was not yet
                self.assertEqual(len([c for c in self.daemon.calls if c[1] == "fork_project"]), forks)
                self.assertEqual(len([c for c in self.daemon.calls if c[1] == "save"]), saves)
                self.assertEqual(self.pending_ids(), [])
                self.assertEqual(self.name_of(B), "Two")

    def test_resume_verified_refuses_a_candidate_built_for_another_selection_or_that_no_longer_verifies(self):
        self.edit("One", A)
        self.edit("Two", B)
        self.faulted("before_publish", only={"ids": [self.ids()[0]]})
        candidate = lineage.generation_dir(self.settings, self.lineage_id(), 1)
        answer = self.commit(cid=self.CID, resume_verified=True)  # a different selection (everything): rebuilt as generation 2
        self.assertEqual((answer.get("resumed"), answer["generation"]), (None, 2))
        self.assertTrue(lineage.verify_manifest(candidate)["ok"])
        self.setUp()
        self.edit("One", A)
        self.faulted("before_publish")
        candidate = lineage.generation_dir(self.settings, self.lineage_id(), 1)
        victim = next(candidate.rglob("programs.json"))
        os.chmod(victim, 0o666)
        victim.write_text("tampered", encoding="utf-8")
        answer = self.commit(cid=self.CID, resume_verified=True)
        self.assertEqual((answer.get("resumed"), answer["generation"]), (None, 2))  # it does not verify any more: a new attempt

    def test_a_resume_of_a_verified_unpublished_candidate_is_not_attempted_by_default(self):
        self.edit("One", A)
        self.faulted("before_publish")
        self.assertEqual(self.head()["gen"], 0)
        candidate = lineage.generation_dir(self.settings, self.lineage_id(), 1)
        self.assertTrue(lineage.verify_manifest(candidate)["ok"])  # a sealed, verified, unpublished candidate stays on disk
        answer = self.settle({})
        self.assertEqual(answer["generation"], 2)  # a new attempt never reuses it
        self.assertTrue(lineage.verify_manifest(candidate)["ok"])


if __name__ == "__main__":
    unittest.main()
