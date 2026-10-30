"""Backups on hydra.2/3 (PROTOCOL-3.md 4.5, 3.4, D28, D66): a fork with `writable:false`, a Python re-hash, `backup.json` written
last, the seal, `backups.log`, the policy, and `backend action=backups options.op=list|verify|remove`."""

from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import api, backups, hydra, lineage, query, workcopy
import test_commit
from test_commit import A, B, World


# What a real hydra.4 engine advertises in `hello.capabilities` (captured from the integration build, 2026-10-29).
REAL_HYDRA4_CAPABILITIES = ("errorNext", "expectAll", "idempotency", "laneHint", "maintLane", "queueInfo", "cancelWait", "forkReport",
                            "format", "backup", "upgradeGate", "scriptIsolation", "scriptSha256", "attemptedChanges", "health",
                            "identity", "seal", "forkAtomic", "admission")

class Backups(World, unittest.TestCase):
    def setUp(self):
        super().setUp()
        selected = self.runner.target("owned")
        self.lid = lineage.ensure(self.settings, {**selected, "origin_key": selected["key"]})["id"]
        self.engine = fakehydra.FakeEngine(self.settings)

    def make(self, **kwargs):
        return backups.make(self.settings, self.engine, self.lid, str(self.gpr), kwargs.pop("purpose", "pre-commit"), "3fa9c2d1aa01bb42", 0, **kwargs)

    # --- making one -----------------------------------------------------------------------------------------------
    def test_a_backup_is_a_verified_sealed_copy_with_backup_json_written_last(self):
        made = self.make()["backup"]
        folder = Path(made["folder"])
        manifest = json.loads((folder / "backup.json").read_text(encoding="utf-8"))
        self.assertEqual((manifest["kind"], manifest["writer"], manifest["purpose"], manifest["format"]),
                         ("ghidra-session-backup", "hydralysis", "pre-commit", 1))
        self.assertRegex(manifest["id"], r"^\d{8}T\d{6}Z-3fa9c2d1-pre-commit$")
        self.assertEqual(folder.name, manifest["id"])
        self.assertEqual(folder.parent.name, self.lid)
        self.assertEqual(manifest["source"], {"gpr": str(self.gpr), "name": "Owned", "revision": "3fa9c2d1aa01bb42", "lineage": self.lid, "generation": 0})
        self.assertTrue(manifest["verify"]["ok"])
        self.assertFalse(manifest["copy"]["independent"])  # a block clone on the same volume protects against a bad commit only
        self.assertEqual(manifest["selfSha256"], lineage.self_hash(manifest))
        self.assertTrue(backups.verify(folder)["ok"])
        project = folder / "project"
        sidecar = json.loads(next(project.glob("*.fork.json")).read_text(encoding="utf-8"))
        self.assertEqual((sidecar["purpose"], sidecar["disposable"], sidecar["state"]), ("backup", False, "complete"))
        self.assertTrue((project / "SEALED.json").is_file())
        self.assertEqual(lineage.tree_hash(self.gpr.parent), self.master_tree)

    def test_the_python_manifest_lists_what_the_engine_gate_checks_raw_sizes_and_no_sidecar(self):
        # The real hydra.4 gate checks every listed file's size on disk (ProjectBackup.check). The sidecar is rewritten at seal time,
        # so a listed sidecar made the real gate refuse a Python-written backup with `file_size` (found on the real engine, Y4d).
        made = self.make()["backup"]
        folder = Path(made["folder"])
        rows = made["manifest"]["files"]
        self.assertTrue(rows)
        self.assertFalse([row["path"] for row in rows if row["path"].endswith(".fork.json")])
        for row in rows:
            self.assertEqual((folder / row["path"]).stat().st_size, row["size"], row["path"])
        self.assertTrue(backups.verify(folder)["ok"])

    def test_an_unlisted_sidecar_is_not_an_unlisted_file(self):
        # An engine-written backup lists the project's files only (UpgradeCache.sourceFiles); its sidecar sits beside them unlisted.
        made = self.make()["backup"]
        folder = Path(made["folder"])
        stray = folder / "project" / "stray.bin"
        stray.write_bytes(b"x")
        self.assertIn("unlisted file project/stray.bin", backups.verify(folder)["problems"])
        stray.unlink()
        sidecar = next((folder / "project").glob("*.fork.json"))
        manifest = json.loads((folder / "backup.json").read_text(encoding="utf-8"))
        manifest["files"] = [row for row in manifest["files"] if row["path"] != "project/" + sidecar.name]
        manifest["filesetSha256"] = lineage.fileset_sha256(manifest["files"])
        manifest["selfSha256"] = lineage.self_hash(manifest)
        os.chmod(folder / "backup.json", 0o666)
        (folder / "backup.json").write_bytes(lineage.canonical(manifest))
        self.assertTrue(backups.verify(folder)["ok"], backups.verify(folder)["problems"])

    def test_the_fork_is_not_writable(self):
        self.make()
        forks = [fields for _, name, fields in self.daemon.calls if name == "fork_project"]
        self.assertEqual([fields["writable"] for fields in forks], [False])
        self.assertEqual([name for _, name, _ in self.daemon.calls if name in ("close_project",)], ["close_project"])  # nothing is held open

    def test_backups_log_records_each_copy(self):
        made = self.make()["backup"]
        (row,) = backups.logged(self.settings, self.lid)
        self.assertEqual((row["id"], row["manifestSha256"], row["root"]), (made["id"], made["manifestSha256"], str(self.root / "backups")))
        self.assertGreater(row["bytes"], 0)
        self.assertEqual(row["manifestSha256"], lineage.sha256_hex((Path(made["folder"]) / "backup.json").read_bytes()))

    def test_a_backup_never_overwrites_and_a_retry_in_the_same_second_gets_its_own_folder(self):
        first = self.make()["backup"]
        second = self.make()["backup"]
        self.assertNotEqual(first["folder"], second["folder"])
        self.assertTrue(second["id"].startswith(first["id"].split("-")[0][:8]))

    # --- invisible until verified ---------------------------------------------------------------------------------
    def test_a_copy_that_does_not_match_its_source_writes_no_manifest_and_stays_invisible(self):
        original = backups._fork_into

        def corrupt(settings, engine, source, destination, mode):
            forked = original(settings, engine, source, destination, mode)
            (Path(destination) / "Owned.rep" / "damaged.bin").write_bytes(b"x")
            for path in Path(destination).rglob("Owned.gpr"):
                path.write_text("different", encoding="utf-8")
            return forked
        with patch.object(backups, "_fork_into", corrupt), self.assertRaises(backups.BackupError) as raised:
            self.make()
        self.assertEqual(raised.exception.code, "backup_failed")
        self.assertIn("does not match its source", str(raised.exception))
        listed = backups.listing(self.settings, self.lid)
        self.assertEqual(listed["backups"], [])
        self.assertEqual(len(listed["invisible"]), 1)
        self.assertIn("manual removal", listed["invisible"][0]["note"])
        self.assertEqual(backups.logged(self.settings, self.lid), [])

    def test_a_source_that_changes_while_it_is_copied_makes_no_backup(self):
        original = backups._fork_into

        def moving(settings, engine, source, destination, mode):
            forked = original(settings, engine, source, destination, mode)
            (Path(source).parent / "Owned.rep" / "moved.bin").write_bytes(b"late")
            return forked
        with patch.object(backups, "_fork_into", moving), self.assertRaises(backups.BackupError) as raised:
            self.make()
        self.assertIn("source changed", str(raised.exception))
        self.assertEqual(backups.listing(self.settings, self.lid)["backups"], [])

    def test_a_folder_without_a_valid_backup_json_is_not_a_usable_backup(self):
        made = self.make()["backup"]
        (Path(made["folder"]) / "backup.json").write_text("{}", encoding="utf-8")
        self.assertIsNone(backups.usable(self.settings, self.lid, made["id"]))
        self.assertEqual(len(backups.listing(self.settings, self.lid)["invisible"]), 1)

    # --- verifying ------------------------------------------------------------------------------------------------
    def test_verify_rehashes_every_file_and_names_what_changed(self):
        made = self.make()["backup"]
        folder = Path(made["folder"])
        victim = next((folder / "project").rglob("Owned.gpr"))
        os.chmod(victim, 0o666)
        victim.write_text("tampered", encoding="utf-8")
        (folder / "project" / "stray.bin").write_bytes(b"x")
        result = backups.verify(folder)
        self.assertFalse(result["ok"])
        self.assertTrue(any(problem.startswith("changed file project/Owned.gpr") for problem in result["problems"]))
        self.assertIn("unlisted file project/stray.bin", result["problems"])
        self.assertIsNone(backups.usable(self.settings, self.lid, made["id"]))

    def test_usable_checks_the_manifest_the_log_names(self):
        made = self.make()["backup"]
        self.assertIsNotNone(backups.usable(self.settings, self.lid, made["id"], made["manifestSha256"]))
        self.assertIsNone(backups.usable(self.settings, self.lid, made["id"], "0" * 64))

    def test_a_replaced_backup_is_detected_by_the_log(self):
        made = self.make()["backup"]
        folder = Path(made["folder"])
        manifest = json.loads((folder / "backup.json").read_text(encoding="utf-8"))
        manifest["createdAt"] = "2000-01-01T00:00:00Z"
        manifest["selfSha256"] = lineage.self_hash(manifest)
        os.chmod(folder / "backup.json", 0o666)
        (folder / "backup.json").write_bytes(lineage.canonical(manifest))
        row = backups.listing(self.settings, self.lid)["backups"][0]
        self.assertTrue(row["replaced"])

    def test_a_deleted_backup_is_reported_as_logged_but_missing(self):
        import shutil
        made = self.make()["backup"]
        backups._writable_tree(Path(made["folder"]))
        shutil.rmtree(made["folder"])
        listed = backups.listing(self.settings, self.lid)
        self.assertEqual(listed["backups"], [])
        self.assertEqual(listed["logged_but_missing"], [{"id": made["id"], "root": made["root"]}])

    def test_a_newer_format_is_refused_not_guessed(self):
        made = self.make()["backup"]
        folder = Path(made["folder"])
        manifest = json.loads((folder / "backup.json").read_text(encoding="utf-8"))
        manifest["format"] = 7
        manifest["selfSha256"] = lineage.self_hash(manifest)
        os.chmod(folder / "backup.json", 0o666)
        (folder / "backup.json").write_bytes(lineage.canonical(manifest))
        self.assertTrue(any("format_unreadable" in problem for problem in backups.verify(folder)["problems"]))

    def test_a_legacy_backup_without_a_seal_is_listed_unsealed_and_verify_adopts_it(self):
        made = self.make()["backup"]
        project = Path(made["folder"]) / "project"
        os.chmod(project / "SEALED.json", 0o666)
        (project / "SEALED.json").unlink()
        row = backups.listing(self.settings, self.lid)["backups"][0]
        self.assertFalse(row["sealed"])
        self.assertIn("client discipline", row["note"])
        outcome = backups.adopt_legacy(Path(made["folder"]))
        self.assertEqual(outcome, {"ok": True, "adopted": True})
        self.assertTrue(backups.listing(self.settings, self.lid)["backups"][0]["sealed"])
        self.assertTrue(backups.verify(Path(made["folder"]))["ok"])

    def test_a_legacy_backup_that_fails_the_rehash_is_labelled_and_never_adopted(self):
        made = self.make()["backup"]
        project = Path(made["folder"]) / "project"
        victim = next(project.rglob("Owned.gpr"))
        os.chmod(victim, 0o666)
        victim.write_text("bad", encoding="utf-8")
        os.chmod(project / "SEALED.json", 0o666)
        (project / "SEALED.json").unlink()
        outcome = backups.adopt_legacy(Path(made["folder"]))
        self.assertEqual(outcome["label"], "legacy_unverified")
        self.assertFalse((project / "SEALED.json").exists())

    # --- policy ---------------------------------------------------------------------------------------------------
    def test_the_default_policy(self):
        wanted = backups.policy({"root": str(self.root / "data")})
        self.assertEqual((wanted["backup_min_verified"], wanted["backup_min_independent"], wanted["backup_confirm_gb"], wanted["backup_root_warn_gb"]),
                         (1, 0, 50, 200))
        self.assertEqual(wanted["roots"][0]["path"], str(self.root / "data" / "backups"))
        with self.assertRaises(ValueError):
            backups.policy({**self.settings, "backup_roots": [{"path": "x", "mode": "snapshot"}]})
        with self.assertRaises(ValueError):
            backups.policy({**self.settings, "backup_min_verified": -1})

    def test_a_secondary_root_is_always_a_full_copy(self):
        wanted = backups.policy({**self.settings, "backup_roots": [{"path": "a", "mode": "auto"}, {"path": "b", "mode": "auto"}]})
        self.assertEqual([root["mode"] for root in wanted["roots"]], ["auto", "copy"])
        self.assertEqual([root["required"] for root in wanted["roots"]], [True, False])

    def test_two_roots_give_two_verified_copies_and_a_failed_secondary_only_warns(self):
        self.settings["backup_roots"] = [{"path": str(self.root / "backups")}, {"path": str(self.root / "second")}]
        made = self.make()
        self.assertEqual(len(made["all"]), 2)
        self.assertEqual(made["warnings"], [])
        self.settings["backup_roots"] = [{"path": str(self.root / "backups2")}, {"path": str(self.root / "third")}]
        original = backups._make_one

        def failing(settings, engine, lid, source, folder, identifier, purpose, revision, generation, root, by):
            if root["path"].endswith("third"):
                raise OSError("disk full")
            return original(settings, engine, lid, source, folder, identifier, purpose, revision, generation, root, by)
        with patch.object(backups, "_make_one", failing):
            made = self.make()
        self.assertEqual(len(made["all"]), 1)
        self.assertEqual(made["warnings"][0]["root"], str(self.root / "third"))

    def test_a_failed_primary_aborts_and_so_does_a_failed_secondary_the_policy_needs(self):
        self.settings["backup_roots"] = [{"path": str(self.root / "backups")}, {"path": str(self.root / "second")}]
        original = backups._make_one

        def failing(settings, engine, lid, source, folder, identifier, purpose, revision, generation, root, by):
            if "backups" in root["path"] or "second" in root["path"]:
                raise OSError("disk full")
            return original(settings, engine, lid, source, folder, identifier, purpose, revision, generation, root, by)
        with patch.object(backups, "_make_one", failing), self.assertRaises(backups.BackupError) as raised:
            self.make()
        self.assertEqual(raised.exception.code, "backup_failed")
        self.settings["backup_min_verified"] = 2
        self.settings["backup_roots"] = [{"path": str(self.root / "ok")}, {"path": str(self.root / "bad")}]

        def half(settings, engine, lid, source, folder, identifier, purpose, revision, generation, root, by):
            if root["path"].endswith("bad"):
                raise OSError("disk full")
            return original(settings, engine, lid, source, folder, identifier, purpose, revision, generation, root, by)
        with patch.object(backups, "_make_one", half), self.assertRaises(backups.BackupError) as raised:
            self.make()
        self.assertIn("backup_min_verified=2", str(raised.exception))

    def test_a_policy_that_wants_an_independent_copy_refuses_a_block_clone(self):
        self.settings["backup_min_independent"] = 1
        with self.assertRaises(backups.BackupError) as raised:
            self.make()
        self.assertIn("backup_min_independent=1", str(raised.exception))

    def test_a_large_backup_needs_confirmation_and_states_the_cumulative_cost(self):
        self.make()
        self.settings["backup_confirm_gb"] = 1e-10
        with self.assertRaises(backups.BackupError) as raised:
            self.make()
        self.assertEqual(raised.exception.code, "confirm_large_backup")
        row = raised.exception.detail["plan"]["roots"][0]
        self.assertGreater(row["cumulative_bytes_before"], 0)  # the first backup counts
        self.assertEqual(row["cumulative_bytes_after"], row["cumulative_bytes_before"] + row["this_backup_bytes"])
        self.assertIsNotNone(row["free_bytes"])
        self.assertIn("overstates", row["note"])
        self.assertEqual(len(backups.listing(self.settings, self.lid)["backups"]), 1)  # the refusal made nothing
        self.assertTrue(self.make(confirm_large=True)["backup"]["id"])

    def test_the_doctor_warning_threshold_is_in_the_plan(self):
        self.settings["backup_root_warn_gb"] = 1e-10
        plan = backups.preview(self.settings, self.lid, str(self.gpr))
        self.assertTrue(plan["roots"][0]["warn"])


class RemoveAndHandler(World, unittest.TestCase):
    def setUp(self):
        super().setUp()
        selected = self.runner.target("owned")
        self.lid = lineage.ensure(self.settings, {**selected, "origin_key": selected["key"]})["id"]
        self.engine = fakehydra.FakeEngine(self.settings)

    def call(self, **options):
        with patch("hydralysis.api.load", return_value=self.settings), patch("hydralysis.api._settings", return_value=self.settings):
            return json.loads(api.call("backend", {"action": "backups", "options": {"target": "owned", **options}}))

    def make(self):
        return backups.make(self.settings, self.engine, self.lid, str(self.gpr), "pre-commit", "3fa9c2d1aa01bb42", 0)["backup"]

    def test_the_handler_needs_a_lineage(self):
        from hydralysis import targets
        targets.register(self.settings, ["bare"], {"gpr": str(self.gpr), "program": "/owned.exe", "sha256": self.digest, "exe": str(self.exe)})
        reply = self.call(target="bare")
        self.assertEqual(reply["error"], "no_lineage")
        self.assertEqual(self.call(op="list")["lineage"], self.lid)
        with patch("hydralysis.api.load", return_value=self.settings), patch("hydralysis.api._settings", return_value=self.settings),                 self.assertRaises(ValueError):
            api.call("backend", {"action": "backups", "options": {"op": "list"}})  # neither target nor lineage

    def test_list_verify_and_remove_through_backend_action_backups(self):
        # the handler finds the lineage through the registry, so register it the way a commit does
        selected = self.runner.target("owned")
        lineage.register(self.settings, selected, self.lid, selected["key"])
        made = self.make()
        listed = self.call(op="list")
        self.assertEqual(listed["op"], "list")
        self.assertEqual([row["id"] for row in listed["backups"]], [made["id"]])
        self.assertEqual(listed["independent_verified"], 0)
        self.assertEqual(listed["policy"]["backup_min_verified"], 1)
        verified = self.call(op="verify", id=made["id"])
        self.assertEqual([(row["id"], row["ok"]) for row in verified["results"]], [(made["id"], True)])
        self.assertEqual(self.call(op="verify", id=made["id"]) and True, True)

    def test_remove_is_a_dry_run_unless_confirmed_and_never_drops_below_the_policy(self):
        selected = self.runner.target("owned")
        lineage.register(self.settings, selected, self.lid, selected["key"])
        made = self.make()
        refused = self.call(op="remove", id=made["id"], confirm=True)
        self.assertEqual(refused["refused"], "backup_min_verified")
        self.assertTrue(Path(made["folder"]).is_dir())
        second = backups.make(self.settings, self.engine, self.lid, str(self.gpr), "pre-commit", "3fa9c2d1aa01bb42", 0)["backup"]
        dry = self.call(op="remove", id=made["id"])
        self.assertTrue(dry["dry_run"])
        self.assertFalse(dry["removed"])
        self.assertTrue(Path(made["folder"]).is_dir())
        self.assertGreater(dry["bytes"], 0)
        done = self.call(op="remove", id=made["id"], confirm=True)
        self.assertTrue(done["removed"])
        self.assertFalse(Path(made["folder"]).exists())
        self.assertTrue(Path(second["folder"]).is_dir())
        # the removal is recorded; the other backup stays; a missing id is an error, not a silent success
        self.assertTrue(any(row.get("removed") for row in backups.logged(self.settings, self.lid)))
        self.assertEqual(len(backups.listing(self.settings, self.lid)["backups"]), 1)
        self.assertEqual(backups.listing(self.settings, self.lid)["logged_but_missing"], [])

    def test_remove_needs_exactly_one_selector_and_a_boolean_confirm(self):
        with self.assertRaises(ValueError):
            backups.remove(self.settings, self.lid, {})
        with self.assertRaises(ValueError):
            backups.remove(self.settings, self.lid, {"id": "x", "generation": 1})
        with self.assertRaises(ValueError):
            backups.remove(self.settings, self.lid, {"id": "x", "confirm": "yes"})

    def test_remove_refuses_generation_zero_the_head_the_revert_target_and_a_live_views_base(self):
        # build a lineage of three published generations by writing the log the way a commit does
        for number in (1, 2, 3):
            lineage.generation_dir(self.settings, self.lid, number).mkdir(parents=True)
            lineage.append_current(self.settings, self.lid, {"gen": number, "cid": "c-%08x" % number, "reason": "commit", "gpr": "g%d" % number,
                                                            "manifestSha256": "m"})
        reasons = {}
        for number in (0, 3, 2):
            reply = backups.remove(self.settings, self.lid, {"generation": number, "confirm": True})
            reasons[number] = reply["message"]
            self.assertEqual(reply["refused"], "protected_generation")
        self.assertIn("never removed", reasons[0])
        self.assertIn("head", reasons[3])
        self.assertIn("revert target", reasons[2])
        # every earlier published generation is a revert target too: commit_revert walks back c3, c2, c1
        chain = backups.remove(self.settings, self.lid, {"generation": 1, "confirm": True})
        self.assertEqual(chain["refused"], "protected_generation")
        self.assertIn("revert chain", chain["message"])
        # a live view's base protects a generation above the head, which nothing else protects
        lineage.generation_dir(self.settings, self.lid, 4).mkdir(parents=True)
        base = Path(self.settings["root"]) / "bases" / "origin" / "key"
        base.mkdir(parents=True)
        (base / "COMPLETE.json").write_text(json.dumps({"gpr": "x", "generation": 4, "lineage": self.lid}), encoding="utf-8")
        self.assertEqual(backups.remove(self.settings, self.lid, {"generation": 4, "confirm": True})["message"], "the base of a live view")
        (base / "COMPLETE.json").unlink()
        folder = lineage.generation_dir(self.settings, self.lid, 4)
        (folder / "payload.bin").write_bytes(b"x" * 100)
        dry = backups.remove(self.settings, self.lid, {"generation": 4})
        self.assertEqual((dry["removed"], dry["dry_run"]), (False, True))
        self.assertTrue(folder.exists())
        done = backups.remove(self.settings, self.lid, {"generation": 4, "confirm": True})
        self.assertTrue(done["removed"])
        self.assertFalse(folder.exists())

    def test_the_revert_chain_stays_protected_after_a_revert_and_a_rolled_back_generation_is_removable(self):
        for number in (1, 2, 3):
            lineage.generation_dir(self.settings, self.lid, number).mkdir(parents=True)
            lineage.append_current(self.settings, self.lid, {"gen": number, "cid": "c-%08x" % number, "reason": "commit", "gpr": "g%d" % number,
                                                            "manifestSha256": "m"})
        # reverting c3 appends a rollback line at generation 2: generation 1 is now the next revert target
        lineage.append_current(self.settings, self.lid, {"gen": 2, "cid": "c-00000003", "reason": "rollback", "gpr": "g2",
                                                        "manifestSha256": "m"})
        kept = backups.protected_generations(self.settings, self.lid)
        self.assertEqual(sorted(kept), [0, 1, 2])
        self.assertIn("revert target", kept[1])
        self.assertNotIn(3, kept)
        self.assertTrue(backups.remove(self.settings, self.lid, {"generation": 3, "confirm": True})["removed"])
        self.assertEqual(backups.remove(self.settings, self.lid, {"generation": 1, "confirm": True})["refused"], "protected_generation")

    def test_op_remove_is_in_the_option_bags_help_text(self):
        self.assertIn("remove", api.OPTION_BAGS["backend"])
        self.assertIn("dry run", api.OPTION_BAGS["backend"])


class E2Engine(fakehydra.FakeEngine):
    """The E2 surface Y4d needs on top of fakehydra's own (`format_info`, `backup_required` and the engine-written manifest of
    `fork_project purpose:"backup"` live in fakehydra.py since Y4a): a stricter gate that reads the manifest the client passes
    (verify.ok, selfSha256), a `fork_project open:false` that registers nothing and seals, `seal_project`, and the capabilities.
    The gate here runs first and then hands `backup` on to fakehydra's own gate, which refuses an upgrading writable open of a
    non-disposable project that carries no backup: dropping `backup` on that hand-over was what made every commit of the E2
    matrix refuse with `backup_required`. Daemon switches: e2, format_info, backup_required, sealed_by_call, break_engine_backup."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, value in (("e2", False), ("format_info", None), ("backup_required", False), ("sealed_by_call", []),
                            ("break_engine_backup", None)):
            if not hasattr(self.daemon, name):
                setattr(self.daemon, name, value)

    def capabilities(self):
        found = {"laneHint": 1, "queueInfo": 1} if self.daemon.queue_info else {}
        if self.daemon.e2:
            found.update(forkPurposes=1, upgradeGate=1, format=1, backup=1)
        return found

    def _open_project(self, path, writable=False, **_):
        opened = super()._open_project(path, writable=writable)
        if self.daemon.e2 and self.daemon.format_info is not None:
            opened["format"] = dict(self.daemon.format_info)
        return opened

    def _check_backup_gate(self, project, backup):
        sidecar = self._sidecar(project)
        if sidecar is not None and sidecar.get("disposable") is not False:
            return
        problem = "no backup was given"
        if backup:
            try:
                manifest = json.loads(Path(backup).read_text(encoding="utf-8"))
                body = {key: item for key, item in manifest.items() if key != "selfSha256"}
                if manifest.get("kind") != "ghidra-session-backup" or not (manifest.get("verify") or {}).get("ok"):
                    problem = "the backup does not say it verified"
                elif manifest.get("selfSha256") != hashlib.sha256(lineage.canonical(body)).hexdigest():
                    problem = "the backup's selfSha256 is wrong"
                elif getattr(self.daemon, "copy_revisions", False) and (manifest.get("source") or {}).get("revision") != project["revision"]:
                    problem = "revision: the backup was made at revision %s, the project is at %s" % (
                        (manifest.get("source") or {}).get("revision"), project["revision"])
                else:
                    return
            except (OSError, ValueError):
                problem = "the backup cannot be read"
        raise hydra.EngineError("backup_required", "upgrading %s is one-way: %s" % (project["gpr"], problem),
                                {"project": project["gpr"], "suggest": "fork_project purpose backup"})

    def _open_program(self, path, project, writable=False, share=False, upgrade=False, backup=None, **rest):
        if writable and upgrade and self.daemon.backup_required:
            self._check_backup_gate(self.daemon.project_by_id(project), backup)
        return super()._open_program(path, project, writable=writable, share=share, upgrade=upgrade, backup=backup, **rest)

    def _fork_project(self, project, path, writable=True, mode="auto", purpose=None, open=True, verify="hash", **rest):
        if not (purpose == "backup" and open is False):
            result = super()._fork_project(project, path, writable=writable, mode=mode, purpose=purpose, **rest)
            if getattr(self.daemon, "copy_revisions", False):
                # A full copy (NTFS): the copied files have new modification times, so the fork is another revision than its
                # source (the engine's Revision.of hashes path, size and mtime of every project file).
                self.daemon.projects[self.daemon._norm(result["gpr"])]["revision"] = "rev-copy-%d" % next(self.daemon.backup_seq)
            return result
        source = self.daemon.projects[self.daemon._norm(project)]
        result = super()._fork_project(project, path, writable=writable, mode=mode, purpose=purpose, **rest)
        gpr = Path(result["gpr"])
        destination, name = gpr.parent, gpr.stem
        sidecar_path = destination / (name + ".fork.json")
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar.update(disposable=False, state="complete")
        sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")
        (destination / "SEALED.json").write_text(json.dumps({"by": "engine"}), encoding="utf-8")
        self.daemon.projects.pop(self.daemon._norm(gpr), None)   # open:false registers nothing
        if self.daemon.break_engine_backup:
            self.daemon.break_engine_backup(destination)
        rows = []
        for item in sorted(destination.rglob("*")):
            # As the real engine lists them (UpgradeCache.sourceFiles): the project's files; the sidecar and the markers are not listed.
            if item.is_file() and item.name not in ("SEALED.json", "backup.json", "projectState") \
                    and not item.name.endswith((".lock", ".lock~", ".fork.json")):
                data = item.read_bytes()
                rows.append({"path": item.relative_to(destination).as_posix(), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        manifest = {"format": 1, "kind": "ghidra-session-backup", "writer": "engine", "id": destination.name, "purpose": "backup",
                    "createdAt": "2026-10-29T00:00:00Z", "source": {"gpr": source["gpr"], "name": name, "revision": source["revision"]},
                    "files": rows, "filesetSha256": hashlib.sha256(lineage.canonical(rows)).hexdigest(),
                    "copy": {"method": "clone", "sameVolume": True, "independent": False},
                    "verify": {"level": "hash", "ok": True}}
        manifest["selfSha256"] = hashlib.sha256(lineage.canonical(manifest)).hexdigest()
        (destination / "backup.json").write_bytes(lineage.canonical(manifest))
        return {"project": None, "gpr": str(gpr), "purpose": "backup", "method": "clone", "cloned": True, "bytes": 1,
                "manifest": {"path": str(destination / "backup.json"), "verified": True, "files": len(rows)}}

    def _seal_project(self, project, lineage=None, **_):
        self.daemon.sealed_by_call.append(project)
        return {"sealed": True}


class EngineBackups(World, unittest.TestCase):
    """Y4d: on hydra.4 (E2) the backup is the engine's (`fork_project purpose:"backup"`, writer "engine"); one schema, two writers."""

    def setUp(self):
        super().setUp()
        patcher = patch.object(fakehydra, "FakeEngine", E2Engine)   # test_commit's helpers build their engine through the module
        patcher.start()
        self.addCleanup(patcher.stop)
        self.daemon.e2 = True
        self.daemon.backup_required = True
        self.daemon.sealed_by_call = []
        self.daemon.break_engine_backup = None
        self.daemon.format_info = None
        self.daemon.copy_revisions = False
        selected = self.runner.target("owned")
        self.lid = lineage.ensure(self.settings, {**selected, "origin_key": selected["key"]})["id"]
        self.engine = E2Engine(self.settings)

    def make(self, **kwargs):
        return backups.make(self.settings, self.engine, self.lid, str(self.gpr), "pre-commit", "3fa9c2d1aa01bb42", 0, **kwargs)

    def python_backup(self):
        with patch.object(backups, "_engine_backup", return_value=False):
            return self.make()["backup"]

    def gate_open(self, backup_json):
        opened = self.engine.call("open_project", path=str(self.gpr))
        return self.engine.call("open_program", path="/owned.exe", project=opened["id"], writable=True, upgrade=True,
                                **({"backup": backup_json} if backup_json else {}))

    def test_the_engine_writes_the_backup_with_purpose_backup_and_the_client_reverifies_it(self):
        made = self.make()["backup"]
        forks = [fields for _, name, fields in self.daemon.calls if name == "fork_project"]
        self.assertEqual([(f["purpose"], f["open"], f["verify"]) for f in forks], [("backup", False, "hash")])
        self.assertEqual(made["manifest"]["writer"], "engine")
        folder = Path(made["folder"])
        self.assertTrue(backups.verify(folder)["ok"])
        self.assertEqual(backups.listing(self.settings, self.lid)["backups"][0]["sealed"], True)
        self.assertEqual(backups.logged(self.settings, self.lid)[0]["manifestSha256"], made["manifestSha256"])
        self.assertEqual(lineage.tree_hash(self.gpr.parent), self.master_tree)

    def test_the_capabilities_a_real_hydra_4_advertises_select_the_engine_backup_and_the_generation_purpose(self):
        # The exact set the hydra.4 engine advertises (Advertised.java, PROTOCOL-3.md 3.1): `backup`, never a `forkPurposes`.
        # The old check looked for `forkPurposes`, so on the real engine every backup was the Python one and no candidate was
        # forked with purpose "generation".
        self.engine.capabilities = lambda: dict.fromkeys(REAL_HYDRA4_CAPABILITIES, 1)
        self.assertTrue(backups._engine_backup(self.engine))
        self.assertEqual(self.make()["backup"]["manifest"]["writer"], "engine")
        with patch.object(fakehydra.FakeEngine, "capabilities", lambda engine: dict.fromkeys(REAL_HYDRA4_CAPABILITIES, 1)):
            self.edit("renamed")
            self.assertTrue(self.commit()["ok"])
        purposes = [fields.get("purpose") for _, name, fields in self.daemon.calls if name == "fork_project"]
        self.assertIn("generation", purposes)

    def test_an_engine_backup_is_accepted_by_the_gate_and_the_python_one_too(self):
        engine_made = self.make()["backup"]
        self.assertIn("key", self.gate_open(str(Path(engine_made["folder"]) / "backup.json")))
        python_made = self.python_backup()
        self.assertEqual(python_made["manifest"]["writer"], "hydralysis")
        self.assertIn("key", self.gate_open(str(Path(python_made["folder"]) / "backup.json")))

    def test_the_gate_refuses_without_a_backup_and_with_a_tampered_manifest(self):
        with self.assertRaises(hydra.EngineError) as raised:
            self.gate_open(None)
        self.assertEqual(raised.exception.code, "backup_required")
        made = self.python_backup()
        path = Path(made["folder"]) / "backup.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["id"] = "changed"
        os.chmod(path, 0o666)
        path.write_bytes(lineage.canonical(manifest))
        with self.assertRaises(hydra.EngineError):
            self.gate_open(str(path))

    def test_an_engine_backup_that_does_not_verify_is_refused_and_stays_invisible_to_use(self):
        def flip(destination):
            victim = next(destination.rglob("Owned.gpr"))
            victim.write_text("flipped after the engine hashed", encoding="utf-8")
        self.daemon.break_engine_backup = flip
        with self.assertRaises(backups.BackupError) as raised:
            self.make()
        self.assertEqual(raised.exception.code, "backup_failed")
        self.assertFalse(backups.logged(self.settings, self.lid))

    def test_commit_uses_the_engine_backup_and_passes_it_to_the_candidate_open(self):
        self.daemon.format_info = {"upgradeRequired": False}   # a project at this engine's format: no pre-upgrade backup
        self.edit("renamed")
        result = self.commit()
        self.assertTrue(result.get("backup"))
        gated = [fields for _, name, fields in self.daemon.calls if name == "open_program" and fields.get("backup")]
        self.assertEqual([Path(fields["backup"]).name for fields in gated], ["backup.json"])  # the candidate's open names the backup
        (row,) = [row for row in backups.listing(self.settings, self.lid)["backups"]]
        self.assertEqual(row["writer"], "engine")

    def test_an_older_format_project_commits_when_the_candidate_is_a_full_copy(self):
        """Defect 3 (Y4d2): a full-copy fork (NTFS) is another revision than its source, so the gate refuses the backup of
        the source generation for the candidate. The commit backs up the candidate itself (`pre-upgrade`) and names that."""
        self.daemon.copy_revisions = True
        self.daemon.format_info = {"upgradeRequired": True, "programDb": 32}
        self.edit("renamed")
        result = self.commit()
        self.assertTrue(result["ok"], result)
        purposes = sorted(row["purpose"] for row in backups.logged(self.settings, self.lid))
        self.assertEqual(purposes, ["pre-commit", "pre-upgrade"])
        gated = [fields["backup"] for _, name, fields in self.daemon.calls if name == "open_program" and fields.get("backup")]
        (pre_upgrade,) = [row for row in backups.logged(self.settings, self.lid) if row["purpose"] == "pre-upgrade"]
        self.assertEqual([Path(item).parent.name for item in gated], [pre_upgrade["id"]])
        manifest = json.loads((lineage.generation_dir(self.settings, self.lid, result["generation"]) / "MANIFEST.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["backups"]), 2, "the manifest names both backups")
        rows = lineage.intent_log(self.settings, self.lid, result["cid"]).scan().records
        self.assertTrue(any(row["step"] == "FORKED" and row.get("gate_backup") == pre_upgrade["id"] for row in rows))

    def test_a_project_at_this_engines_format_gets_no_pre_upgrade_backup(self):
        self.daemon.copy_revisions = True
        self.daemon.format_info = {"upgradeRequired": False}
        self.edit("renamed")
        self.assertTrue(self.commit()["ok"])
        self.assertEqual([row["purpose"] for row in backups.logged(self.settings, self.lid)], ["pre-commit"])

    def test_the_format_the_engine_reports_decides_the_confirmation(self):
        from hydralysis import commits
        selected = self.target()
        self.edit("renamed")
        body = {"kind": "commit", "expect_revision": self.store()["revision"]}
        self.daemon.format_info = {"upgradeRequired": True, "programDb": 32}
        with self.assertRaises(commits.CommitError) as raised:
            commits.run_commit(self.settings, selected, body, self.engine)
        self.assertEqual(raised.exception.code, "confirmation_required")
        self.assertEqual(raised.exception.payload()["format"]["programDb"], 32)
        self.daemon.format_info = {"upgradeRequired": False}
        self.assertTrue(commits.run_commit(self.settings, self.target(), body, self.engine))

    def test_legacy_backup_adoption(self):
        made = self.python_backup()
        folder = Path(made["folder"])
        project = folder / "project"
        os.chmod(project / "SEALED.json", 0o666)
        (project / "SEALED.json").unlink()
        sidecar = next(project.glob("*.fork.json"))
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        record["state"] = "candidate"
        os.chmod(sidecar, 0o666)
        sidecar.write_text(json.dumps(record), encoding="utf-8")
        self.assertFalse(backups.listing(self.settings, self.lid)["backups"][0]["sealed"])
        self.assertEqual(backups.listing(self.settings, self.lid)["backups"][0]["label"], "legacy_unverified")
        outcome = backups.adopt_legacy(folder, self.engine, self.lid)
        self.assertEqual((outcome["ok"], outcome["adopted"], outcome["engine_sealed"]), (True, True, True))
        self.assertTrue(backups.listing(self.settings, self.lid)["backups"][0]["sealed"])
        self.assertEqual(len(self.daemon.sealed_by_call), 1)
        # adopted, so a writable open is refused (sealed)
        opened = self.engine.call("open_project", path=str(project / "Owned.gpr"))
        with self.assertRaises(hydra.EngineError) as raised:
            self.engine.call("open_program", path="/owned.exe", project=opened["id"], writable=True)
        self.assertEqual(raised.exception.code, "sealed")

    def test_a_legacy_backup_with_a_flipped_byte_is_labelled_and_unusable_as_a_source(self):
        made = self.python_backup()
        folder = Path(made["folder"])
        project = folder / "project"
        os.chmod(project / "SEALED.json", 0o666)
        (project / "SEALED.json").unlink()
        victim = next(project.rglob("Owned.gpr"))
        os.chmod(victim, 0o666)
        victim.write_bytes(victim.read_bytes() + b"x")
        outcome = backups.adopt_legacy(folder, self.engine, self.lid)
        self.assertEqual(outcome["label"], "legacy_unverified")
        self.assertEqual(self.daemon.sealed_by_call, [])
        self.assertFalse((project / "SEALED.json").exists())
        self.assertIsNone(backups.usable(self.settings, self.lid, made["id"]))


class FaultMatrixOnE2(test_commit.FaultMatrix):
    """Y4d spec test "fault matrix re-run": the whole commit fault matrix of test_commit, with the E2 engine (engine-written backups,
    the format gate, the backup argument) in place of the plain fake."""

    def setUp(self):
        patcher = patch.object(fakehydra, "FakeEngine", E2Engine)
        patcher.start()
        self.addCleanup(patcher.stop)
        super().setUp()
        self.daemon.e2 = True
        self.daemon.backup_required = True

    def test_the_e2_path_is_the_one_exercised(self):
        self.edit("One", A)
        self.assertTrue(self.commit(cid=self.CID)["ok"])
        self.assertTrue(self.daemon.e2 and isinstance(fakehydra.FakeEngine(self.settings), E2Engine))
        backups_made = list(Path(self.settings["backup_roots"][0]["path"]).rglob("backup.json"))
        engine_written = [path for path in backups_made if json.loads(path.read_text(encoding="utf-8")).get("writer") == "engine"]
        self.assertTrue(backups_made, "the commit made a backup")
        self.assertEqual(len(engine_written), len(backups_made), "every backup the commit made is the engine's")



# ---- the real engine (Y4d against hydra.4: the engine-written backup, the upgrade gate, the fault matrix re-run) ------------------
#
class CallerEngine(fakehydra.FakeEngine):
    """The fake daemon with callers, for the spot check of a commit: CALLEES[address] lists the functions it calls (its
    decompile prints their current names) and ROWS replaces the one-row `functions` listing."""

    CALLEES: dict[str, list[str]] = {}
    ROWS: list[dict] | None = None

    def _script(self, script, program=None, args=(), **rest):
        result = super()._script(script, program=program, args=args, **rest)
        if script != "RusticQuery.java":
            return result
        out = json.loads(result["output"])
        if "function" in out and self.CALLEES.get(out["function"]["address"]):
            entry = self._program(program)
            view = self._view(entry) if program in self.writable or entry["live"] is not None else entry["saved"]
            calls = "".join("  %s();\n" % view["names"].get(callee, "FUN_" + callee.removeprefix("0x"))
                            for callee in self.CALLEES[out["function"]["address"]])
            out["c"] = "void %s(void) {\n%s}\n" % (out["function"]["name"], calls)
        elif "functions" in out and self.ROWS is not None:
            out["functions"] = [dict(row) for row in self.ROWS]
        return {**result, "output": json.dumps(out) + "\n"}


class CommitHygiene(World, unittest.TestCase):
    """Y4d2 on the fake daemon: what a commit leaves on the caller's connection (defect 1) and the spot check's treatment of the
    callers of a renamed function (defect 2)."""

    def shared_rows(self, engine):
        return {key[1] for key in list(query._keys) if key[0] == engine.key}

    def test_a_commit_leaves_nothing_of_its_own_open_on_the_callers_connection(self):
        from hydralysis import commits
        self.edit("renamed")
        engine = fakehydra.FakeEngine(self.settings)
        working = workcopy._state(self.settings, self.target()).get("fork_gpr")
        body = {**test_commit.CONFIRMED, "expect_revision": self.store()["revision"]}
        result = commits.run_commit(self.settings, self.target(), body, engine)
        self.assertTrue(result["ok"], result)
        self.assertNotIn("unreleased", result)
        left = self.shared_rows(engine)
        for gpr in (str(self.gpr), working):
            self.assertNotIn(str(Path(gpr)).lower(), left, "the superseded head and working copy are let go")
        self.assertFalse([gpr for gpr in left if "commit-verify" in gpr], "the verify clone is closed")
        closes = [fields for role, name, fields in self.daemon.calls if role == engine.role and name == "close_program"]
        self.assertTrue(closes, "the programs are closed on the daemon, not only forgotten")

    def test_a_close_that_fails_is_reported_not_swallowed(self):
        from hydralysis import commits
        self.edit("renamed")
        engine = fakehydra.FakeEngine(self.settings)
        real = fakehydra.FakeEngine.call

        def call(engine_self, command, **fields):
            if command == "close_program" and engine_self.role == "reader":
                raise hydra.EngineError("busy", "the program is busy", {})
            return real(engine_self, command, **fields)

        body = {**test_commit.CONFIRMED, "expect_revision": self.store()["revision"]}
        with patch.object(fakehydra.FakeEngine, "call", call):
            with self.assertRaises(commits.CommitError) as raised:
                commits.run_commit(self.settings, self.target(), body, engine)
        self.assertEqual(raised.exception.code, "release_failed")
        self.assertTrue(raised.exception.payload()["left_open"])

    def callers(self, rows, callees):
        patcher = patch.multiple(CallerEngine, ROWS=rows, CALLEES=callees)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("hydralysis.hydra.Engine", "fakehydra.FakeEngine"):
            engine = patch(name, CallerEngine)
            engine.start()
            self.addCleanup(engine.stop)

    def test_a_rename_of_a_function_with_callers_passes_the_spot_check(self):
        self.callers([{"address": A, "name": "FUN_140001000"}, {"address": B, "name": "FUN_140002000"},
                      {"address": test_commit.C, "name": "FUN_140003000"}], {B: [A]})   # B calls A: it prints A's name
        self.edit("renamed_callee", address=A)
        result = self.commit()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["spot_check"]["users_of_changed_symbols"], [B])
        self.assertEqual(result["spot_check"]["compared"], 1, "C, which does not use A, is still compared")

    def test_a_caller_that_changes_for_another_reason_still_fails_the_spot_check(self):
        from hydralysis import commits
        self.callers([{"address": A, "name": "FUN_140001000"}, {"address": test_commit.C, "name": "FUN_140003000"}], {})
        self.edit("renamed_callee", address=A)
        real = commits._decompile

        def drifted(engine, program, address, sha256):
            text = real(engine, program, address, sha256)
            return text + "x" if address == test_commit.C and "commit-verify" in str(program.get("gpr", "")).lower() else text

        with patch.object(commits, "_decompile", drifted):
            with self.assertRaises(commits.CommitError) as raised:
                self.commit()
        self.assertEqual((raised.exception.code, raised.exception.detail.get("address")), ("verify_failed", test_commit.C))


# Gated like test_engine_integration.py: HYDRALYSIS_INTEGRATION_ENGINE (a Hydra install) and HYDRALYSIS_INTEGRATION_CLIENT (its
# ghidra_session.py); HYDRALYSIS_INTEGRATION_UNPINNED for a build that is not the pinned release. The gate cases need a project in an
# older format: HYDRALYSIS_INTEGRATION_LEGACY_PROJECT names one (the engine's examples/fixtures/legacy-12.1.4, a Ghidra 12.1.4
# project of /flow_fixture.exe). Each class has its own data root and daemon, stopped at the end.

import test_engine_integration as integration   # noqa: E402  (its _prepare/_release and gates; no test class is imported)
from support import Hydra4Only, hydra4_missing   # noqa: E402  (the hydra.3 degraded set, docs/versioning.md)

LEGACY = os.environ.get("HYDRALYSIS_INTEGRATION_LEGACY_PROJECT") or os.environ.get("RUSTICRE_INTEGRATION_LEGACY_PROJECT")
LEGACY_PROGRAM = "/flow_fixture.exe"
HAVE_ENGINE = bool(integration.ENGINE and integration.CLIENT)


def _legacy_copy(source: str, destination: Path) -> Path:
    """A private copy of the legacy project with its times kept (a project's revision includes them) and its owner rewritten to the
    user running the tests (Ghidra refuses a writable open of a project another user owns)."""
    import getpass
    import re
    import shutil
    folder = Path(source)
    folder = folder.parent if folder.suffix == ".gpr" else folder
    shutil.copytree(folder, destination, copy_function=shutil.copy2)
    user = getpass.getuser().encode("utf-8")
    for prp in destination.glob("*.rep/project.prp"):
        stat = prp.stat()
        prp.write_bytes(re.sub(rb'(<STATE NAME="OWNER" TYPE="string" VALUE=")[^"]*(")', lambda m: m.group(1) + user + m.group(2),
                               prp.read_bytes()))
        os.utime(prp, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    return next(destination.glob("*.gpr"))


@unittest.skipUnless(HAVE_ENGINE, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
@unittest.skipUnless(LEGACY and Path(LEGACY).exists(), "set HYDRALYSIS_INTEGRATION_LEGACY_PROJECT (an older-format project, e.g. the "
                     "engine's examples/fixtures/legacy-12.1.4) for the upgrade-gate cases")
class RealEngineBackups(Hydra4Only, unittest.TestCase):
    """One schema, two writers, on the real engine (4.5, 3.4): the engine's `fork_project purpose:"backup"` is re-verified by
    Hydralysis and accepted by the engine's upgrade gate; a Python-written backup (writer "hydralysis") is accepted by the same gate;
    without a backup, or with a tampered one, the gate refuses; a flipped byte passes the gate (it checks sizes) but not Hydralysis."""

    @classmethod
    def setUpClass(cls):
        from support import workdir
        cls.work = workdir("y4d-real")
        cls.root = Path(cls.work.name)
        cls.settings = {"root": str(cls.root / "data"), "hydra_dir": integration.ENGINE, "hydra_client": integration.CLIENT,
                        "hydra_idle_s": 600, "hydra_allow_unpinned": True, "backup_roots": [{"path": str(cls.root / "backups")}]}
        if integration._env("INTEGRATION_JAVA"):
            cls.settings["java_home"] = integration._env("INTEGRATION_JAVA")
        cls.env = patch.dict(os.environ, {"HYDRALYSIS_ROOT": cls.settings["root"]})
        cls.env.start()
        cls.engine = hydra.Engine(cls.settings)
        cls.serial = 0
        cls.degraded = hydra4_missing(cls.engine, "the engine-written backup (capability `backup`, E2) and its upgrade gate")

    @classmethod
    def tearDownClass(cls):
        integration._release(cls)

    def copy(self, tag: str) -> Path:
        type(self).serial += 1
        return _legacy_copy(LEGACY, self.root / ("%s-%d" % (tag, self.serial)))

    def make(self, gpr: Path, python: bool = False) -> dict:
        lid = "L-%08x" % (0xd4000000 + self.serial)   # a lineage id of its own per backup (the L-<8 hex> form)
        revision = self.engine.call("open_project", path=str(gpr))["revision"]
        if python:
            with patch.object(backups, "_engine_backup", return_value=False):
                made = backups.make(self.settings, self.engine, lid, str(gpr), "pre-commit", revision, 0)["backup"]
        else:
            made = backups.make(self.settings, self.engine, lid, str(gpr), "pre-commit", revision, 0)["backup"]
        self.close(gpr)
        return {**made, "lid": lid, "json": str(Path(made["folder"]) / "backup.json")}

    def close(self, gpr: Path, discard: bool = False) -> None:
        for project in self.engine.call("status").get("projects") or []:
            if Path(project.get("gpr", "")).resolve() == gpr.resolve():
                try:
                    self.engine.call("close_project", project=project["id"], **({"discard": True} if discard else {}))
                except hydra.EngineError:
                    pass

    def gate_open(self, gpr: Path, backup_json):
        opened = self.engine.call("open_project", path=str(gpr), writable=True)
        try:
            return self.engine.call("open_program", path=LEGACY_PROGRAM, project=opened["id"], writable=True, upgrade=True,
                                    **({"backup": backup_json} if backup_json else {}))
        finally:
            self.close(gpr, discard=True)

    def refused(self, gpr: Path, backup_json) -> dict:
        with self.assertRaises(hydra.EngineError) as raised:
            self.gate_open(gpr, backup_json)
        self.assertEqual(raised.exception.code, "backup_required", raised.exception)
        return raised.exception.details or {}

    def test_the_engine_reports_the_capabilities_and_the_one_way_format_of_the_fixture(self):
        self.assertTrue(backups._engine_backup(self.engine), "a hydra.4 engine advertises `backup`: %s" % self.engine.capabilities())
        self.assertIn("upgradeGate", self.engine.capabilities())
        gpr = self.copy("format")
        info = self.engine.call("open_project", path=str(gpr))["format"]
        self.close(gpr)
        self.assertEqual((info["upgradeRequired"], info["oneWay"]), (True, True))

    def test_the_engine_writes_the_backup_and_hydralysis_reverifies_it(self):
        gpr = self.copy("engine-written")
        tree = lineage.tree_hash(gpr.parent)
        made = self.make(gpr)
        self.assertEqual(made["manifest"]["writer"], "engine")
        self.assertEqual(made["manifest"]["purpose"], "backup")
        folder = Path(made["folder"])
        self.assertTrue(backups.verify(folder)["ok"], backups.verify(folder)["problems"])
        (row,) = backups.listing(self.settings, made["lid"])["backups"]
        self.assertTrue(row["sealed"], row)
        self.assertIsNotNone(backups.usable(self.settings, made["lid"], made["id"], made["manifestSha256"]))
        self.assertEqual(lineage.tree_hash(gpr.parent), tree, "a backup leaves its source byte-identical")

    def test_an_engine_written_backup_is_accepted_by_the_engine_gate(self):
        gpr = self.copy("engine-gate")
        made = self.make(gpr)
        self.assertIn("key", self.gate_open(gpr, made["json"]))

    def test_a_python_written_backup_is_accepted_by_the_engine_gate(self):
        gpr = self.copy("python-gate")
        made = self.make(gpr, python=True)
        self.assertEqual(made["manifest"]["writer"], "hydralysis")
        self.assertTrue(backups.verify(Path(made["folder"]))["ok"])
        self.assertIn("key", self.gate_open(gpr, made["json"]))

    def test_the_gate_refuses_without_a_backup_and_with_a_tampered_manifest_of_either_writer(self):
        details = self.refused(self.copy("no-backup"), None)
        self.assertTrue(details.get("format"), details)
        for python in (False, True):
            with self.subTest(writer="hydralysis" if python else "engine"):
                gpr = self.copy("tampered")
                made = self.make(gpr, python=python)
                path = Path(made["json"])
                manifest = json.loads(path.read_text(encoding="utf-8"))
                manifest["id"] = "changed after signing"
                os.chmod(path, 0o666)
                path.write_bytes(lineage.canonical(manifest))
                self.assertFalse(backups.verify(Path(made["folder"]))["ok"], "Hydralysis refuses it too")
                self.assertEqual((self.refused(gpr, str(path)).get("backupCheck") or {}).get("reason"), "self_hash")

    def test_a_backup_of_another_revision_is_refused(self):
        made = self.make(self.copy("stale"))
        other = self.copy("other")
        index = next(other.parent.rglob("~index.dat"))
        moved = index.stat().st_mtime + 7
        os.utime(index, (moved, moved))   # a touched file moves the project's revision
        self.assertEqual((self.refused(other, made["json"]).get("backupCheck") or {}).get("reason"), "revision")

    def test_a_flipped_byte_passes_the_engine_gate_but_not_the_client_rehash(self):
        gpr = self.copy("flipped")
        made = self.make(gpr)
        folder = Path(made["folder"])
        victim = sorted(folder.rglob("*.gbf"))[0]
        os.chmod(victim, 0o666)
        data = bytearray(victim.read_bytes())
        data[len(data) // 2] ^= 0xFF
        victim.write_bytes(bytes(data))
        self.assertFalse(backups.verify(folder)["ok"])
        self.assertIsNone(backups.usable(self.settings, made["lid"], made["id"], made["manifestSha256"]))
        # 3.4: the engine's gate checks sizes, not content (by design); the client's re-hash is the content check.
        self.assertIn("key", self.gate_open(gpr, made["json"]))

    def test_a_generation_candidate_of_an_older_project_opens_through_the_gate(self):
        """Step 4 of 4.6 as commits._commit does it (Y4d2, defect 3): the candidate is forked with purpose "generation" (gated,
        not disposable) and opened writable with upgrade by the job alone. A full-copy fork (NTFS, the baseline) is another
        revision than its source, so the backup of the source generation alone does not pass the gate (it was the known issue
        here); `_open_candidate` backs up the candidate itself and names that backup, and the gate accepts it."""
        from hydralysis import commits
        gpr = self.copy("candidate-source")
        made = self.make(gpr)
        opened = self.engine.call("open_project", path=str(gpr))
        (entry,) = [row for row in self.engine.call("list", project=opened["id"])["entries"] if row.get("program")]
        self.close(gpr)
        target = {"program": LEGACY_PROGRAM, "sha256": entry["sha256"].lower()}
        candidate = self.root / ("candidate-%d" % self.serial)
        job = hydra.Engine(self.settings, role="commit", lane="y4d2-gate-%d" % self.serial)
        try:
            forked = job.call("fork_project", project=str(gpr), path=str(candidate), writable=True, purpose="generation")
            sidecar = json.loads(next(candidate.glob("*.fork.json")).read_text(encoding="utf-8"))
            self.assertEqual((sidecar.get("purpose"), sidecar.get("disposable")), ("generation", False), sidecar)
            program, gate_backup = commits._open_candidate(self.settings, self.engine, job, target, made["lid"], forked["gpr"],
                                                           forked, {"backup": made}, 1, {}, True)
            self.assertIn("key", program)
            self.assertIsNotNone(gate_backup, "an older-format candidate gets its own pre-upgrade backup")
            self.assertTrue(backups.verify(Path(gate_backup["folder"]))["ok"])
            job.call("close_project", project=program["project"], discard=True)
        finally:
            job.reset()


@unittest.skipUnless(HAVE_ENGINE and integration.BINARY and Path(integration.BINARY).is_file(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class RealEngineFaultMatrix(Hydra4Only, unittest.TestCase):
    """Y4d's "fault matrix re-run" on the real E2 path: test_commit's fault points injected into commits.run_commit against the real
    hydra.4 engine (engine-written backups, candidates forked with purpose "generation"). After each fault the master is
    byte-identical and the head names the old generation or (published points) the new one; a resubmission with the same cid ends
    with exactly one published commit, the name is read from the head generation and nothing is left pending."""

    POINTS = ("after_backup", "after_fork", "mid_apply", "after_save", "after_seal", "before_publish", "after_publish", "finalize_mid")

    @classmethod
    def setUpClass(cls):
        from support import default_to_shared
        integration._prepare(cls, integration.BINARY, "y4d-matrix", "fixture")
        cls.settings["backup_roots"] = [{"path": str(cls.root / "backups")}]
        default_to_shared(cls.runner)
        cls.degraded = hydra4_missing(cls.runner.engine, "the E2 commit path (engine-written backups, generation candidates)")

    @classmethod
    def tearDownClass(cls):
        integration._release(cls)

    def ask(self, action, address="", **kwargs):
        return json.loads(self.runner.query("fixture", action, address, **kwargs))

    def selected(self):
        from hydralysis import workcopy
        return workcopy.with_view(self.runner.target("fixture"), "")

    def store(self):
        from hydralysis import workcopy
        return workcopy.load_store(self.settings, self.selected())

    def edit(self, address, name, kind="rename"):
        fields = {"name": name} if kind == "rename" else {"comment": name}
        return self.ask("type_edit", address, timeout_s=300, options={"kind": kind, **fields, "source": "y4d fault matrix",
                                                                       "expect_revision": self.store().get("revision")})

    def commit(self, cid):
        from hydralysis import commits
        body = {"kind": "commit", "confirm_one_way_upgrade": True, "expect_revision": self.store()["revision"], "cid": cid}
        return commits.run_commit(self.settings, self.selected(), body, hydra.Engine(self.settings), timeout_s=600)

    def fresh_reader(self):
        hydra.Engine(self.settings).reset()
        query._keys.clear()

    def reader_programs(self):
        engine = hydra.Engine(self.settings)
        me = engine.hello().get("client")
        if me is None:
            self.skipTest("the engine's hello names no client id")
        clients = [client for client in engine.call("status").get("clients") or [] if client.get("id") == me]
        return list(clients[0].get("programs") or []) if clients else []

    def test_commits_leave_no_program_open_on_the_shared_connection(self):
        """Y4d2, defect 1 (found here on the real hydra.4): a commit opened the working copy, the old head and the verify clone
        on the caller's shared connection and left them there (the clone's close named the job's project id and its failure
        was swallowed). hydra.4 caps a connection at maxViewsPerClient (4), so the second commit of a process was refused
        `busy`. Now the commit closes what it opened and lets go of the superseded head and working copy: three commits in a
        row on one connection, and after each the connection holds no more programs than before."""
        self.fresh_reader()
        functions = [row["address"] for row in self.ask("functions", limit=4)["functions"]]
        for index, cid in enumerate(("c-d4e1aa01", "c-d4e1aa02", "c-d4e1aa03")):
            with self.subTest(commit=cid):
                address = functions[index % len(functions)]
                self.edit(address, "leak_probe_%d" % index, kind="comment")
                self.ask("decompile", address)
                before = self.reader_programs()
                result = self.commit(cid)
                self.assertTrue(result["ok"], result)
                self.assertNotIn("unreleased", result)
                self.ask("decompile", address)
                after = self.reader_programs()
                self.assertLessEqual(len(after), len(before), "programs left open on the shared connection: %s -> %s" % (before, after))

    def test_a_rename_of_a_function_with_callers_commits(self):
        """Y4d2, defect 2: renaming a function changes how its callers decompile; the verify's spot check of untouched
        functions sets those users aside (reported) instead of refusing the commit, and still compares the others."""
        import re
        self.fresh_reader()
        rows = self.ask("functions", limit=200)["functions"]
        texts = {row["address"]: json.dumps(self.ask("decompile", row["address"])) for row in rows[:60]}
        callee = None
        for row in rows:
            pattern = re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(row["name"]))
            if any(other != row["address"] and pattern.search(text) for other, text in texts.items()):
                callee = row["address"]
                break
        if callee is None:
            self.skipTest("the fixture has no function called by another among the first 60")
        self.edit(callee, "renamed_callee_y4d2")
        result = self.commit("c-d4e2bb01")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["spot_check"]["users_of_changed_symbols"], result["spot_check"])
        self.assertGreater(result["spot_check"]["compared"], 0, result["spot_check"])
        query._keys.clear()
        self.assertIn("renamed_callee_y4d2", json.dumps(self.ask("decompile", callee)))

    def test_every_fault_point_leaves_the_old_or_the_new_state_and_a_resubmission_ends_with_one_commit(self):
        from hydralysis import durable, workcopy
        functions = [row["address"] for row in self.ask("functions", limit=len(self.POINTS) + 2)["functions"]]
        self.assertGreaterEqual(len(functions), len(self.POINTS))
        master = Path(self.prepared["project"]["gpr"]).parent
        master_tree = lineage.tree_hash(master)
        self.assertTrue(backups._engine_backup(hydra.Engine(self.settings)), "the real engine must take the E2 path")
        lid = None
        for index, point in enumerate(self.POINTS):
            with self.subTest(point=point):
                # A fresh shared connection per point: it keeps the points independent of each other; what a
                # commit leaves on a connection is tested by its own test.
                self.fresh_reader()
                cid = "c-d4e0%04x" % index
                name = "fault_%s" % point
                address = functions[index]
                # A plate comment, so the head generation's decompile shows it; renames have their own test.
                self.edit(address, name, kind="comment")
                link = self.selected().get("lineage")
                before = lineage.head(self.settings, link["id"])["gen"] if link else 0
                env = {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "commit.%s:raise" % point}
                with patch.dict(os.environ, env), patch.object(durable, "_die", test_commit.die):
                    with self.assertRaises((durable.FaultInjected, test_commit.Died)):
                        self.commit(cid)
                lid = self.selected()["lineage"]["id"]
                self.assertEqual(lineage.tree_hash(master), master_tree, "O1 the master changed at %s" % point)
                published = point in test_commit.PUBLISHED_POINTS
                self.assertEqual(lineage.head(self.settings, lid)["gen"] > before, published, point)
                answer = self.commit(cid)
                self.assertTrue(answer["ok"], answer)
                rows = [row for row in lineage.history(self.settings, lid) if row.get("cid") == cid and row.get("reason") == "commit"]
                self.assertEqual(len(rows), 1, "O5 one published line for %s" % cid)
                entries = [entry for entry in self.store()["commits"] + self.store()["archived"] if entry["cid"] == cid]
                self.assertEqual(len(entries), 1, "O5 one store entry")
                self.assertTrue(lineage.verify_head(self.settings, lid)["ok"], "O3")
                for row in lineage.history(self.settings, lid):
                    if row["gen"] and row.get("reason") in ("commit", "recover"):
                        self.assertTrue(lineage.verify_manifest(lineage.project_folder_of(row["gpr"]))["ok"], "O4 gen %s" % row["gen"])
                query._keys.clear()
                self.assertIn(name, json.dumps(self.ask("decompile", address)), "the comment is read from the head generation")
                self.assertEqual(workcopy.pending_of(self.store()), [])
        writers = {json.loads(path.read_text(encoding="utf-8")).get("writer")
                   for path in Path(self.settings["backup_roots"][0]["path"]).rglob("backup.json")}
        self.assertEqual(writers, {"engine"}, "every backup the commits made is the engine's")
        purposes = {json.loads(path.read_text(encoding="utf-8")).get("purpose")
                    for path in lineage.lineage_dir(self.settings, lid).rglob("*.fork.json")}
        self.assertIn("generation", purposes)


if __name__ == "__main__":
    unittest.main()
