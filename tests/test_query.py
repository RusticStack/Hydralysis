"""Queries, adopt and cited overlays through the engine, against a fake daemon."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import hydra, query, targets, workcopy
from support import workdir


class EngineCase(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("query")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "owned.exe"
        self.exe.write_bytes(b"MZ a small owned executable")
        self.digest = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.daemon = fakehydra.reset()
        self.gpr = self.root / "analysed" / "Owned" / "Owned.gpr"
        self.daemon.add_project(self.gpr, {"/owned.exe": {"sha256": self.digest}})
        self.settings = {"root": str(self.root / "data"), "hydra_dir": "x", "hydra_client": "x",
                         "targets": {"owned": {"gpr": str(self.gpr), "program": "/owned.exe", "exe": str(self.exe)}}}
        patches = [patch("hydralysis.hydra.Engine", fakehydra.FakeEngine)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        query._keys.clear()
        self.runner = query.QueryRunner(self.settings, fakehydra.FakeEngine(self.settings))

    def ask(self, action="decompile", address="0x140001000", **kwargs):
        return json.loads(self.runner.query("owned", action, address, **kwargs))

    def revision(self, view=""):
        return workcopy.load_store(self.settings, workcopy.with_view(self.runner.target("owned"), view))["revision"]

    def edit(self, **options):
        """One cited edit; expect_revision defaults to the view's current revision (pass None to omit it)."""
        if "expect_revision" not in options:
            options["expect_revision"] = self.revision(options.get("view", ""))
        elif options["expect_revision"] is None:
            del options["expect_revision"]
        return json.loads(self.runner.query("owned", "type_edit", options.pop("address", "0x140001000"),
                                            options={"source": "cited test evidence", **options}))


class Queries(EngineCase):
    def test_user_script_receives_the_selected_named_view(self):
        from unittest.mock import Mock
        from hydralysis import userscripts
        folder = self.root / "scripts"
        folder.mkdir()
        (folder / "Inspect.java").write_text("// fixture", encoding="utf-8")
        self.settings["targets"]["owned"]["scripts"] = str(folder)
        runner = Mock()
        runner.program_for.return_value = {"key": "program-key"}
        runner.engine.call.return_value = {"mode": "contained", "output": "ok"}
        with patch("hydralysis.query.QueryRunner", return_value=runner), patch("hydralysis.userscripts._stage", return_value="Inspect.java"):
            userscripts.run(self.settings, "owned", "Inspect.java", [], view="alice")
        selected = runner.program_for.call_args.args[0]
        self.assertEqual(selected["view"], "alice")
        self.assertEqual(selected["key"], workcopy.with_view(self.runner.target("owned"), "alice")["key"])

    def test_user_script_view_is_forwarded_from_mcp_and_cli(self):
        import contextlib
        import io
        from hydralysis import api, cli
        with patch("hydralysis.api._settings", return_value=self.settings), \
             patch("hydralysis.userscripts.run", return_value="done") as run:
            api.call("ghidra_run", {"target": "owned", "script": "Inspect", "view": "alice"})
        self.assertEqual(run.call_args.args[-1], "alice")
        with patch("hydralysis.cli.call", return_value="done") as call, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["ghidra-run", "--target", "owned", "--view", "alice", "Inspect"]), 0)
        self.assertEqual(call.call_args.args[1]["view"], "alice")

    def test_stop_releases_only_the_selected_target_and_its_working_copy(self):
        other_gpr = self.root / "other" / "Other.gpr"
        self.daemon.add_project(other_gpr, {"/owned.exe": {"sha256": self.digest}})
        self.settings["targets"]["other"] = {"gpr": str(other_gpr), "program": "/owned.exe", "exe": str(self.exe)}
        self.ask()
        self.edit(kind="rename", name="Named")
        self.ask()
        self.runner.query("other", "decompile", "0x140001000")
        before = dict(query._keys)
        result = json.loads(self.runner.query("owned", "stop"))
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["released"]), 2)
        other_key = next(key for key in before if key[1] == str(other_gpr).lower())
        self.assertIs(query._keys[other_key], before[other_key])
        opened_before = sum(command == "open_program" for _, command, _ in self.daemon.calls)
        self.runner.query("other", "decompile", "0x140001000")
        self.assertEqual(sum(command == "open_program" for _, command, _ in self.daemon.calls), opened_before)

    def test_stop_reports_failed_close_and_keeps_the_key_for_retry(self):
        self.ask()
        self.daemon.fail_next["close_program"] = fakehydra.EngineError("busy", "still in use")
        result = json.loads(self.runner.query("owned", "stop"))
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["failed"]), 1)
        self.assertIn("still in use", result["failed"][0]["error"])
        self.assertTrue(query._keys)
        retry = json.loads(self.runner.query("owned", "stop"))
        self.assertTrue(retry["ok"])
        self.assertEqual(len(retry["released"]), 1)

    def test_query_opens_master_in_place_and_checks_the_build(self):
        answer = self.ask()
        self.assertTrue(answer["ok"])
        self.assertEqual(answer["engine"]["mode"], "contained")
        self.assertEqual(answer["function"]["name"], "FUN_140001000")
        commands = [command for _, command, _ in self.daemon.calls]
        self.assertNotIn("fork_project", commands)
        self.assertNotIn("import", commands)

    def test_wrong_build_is_refused_before_any_answer(self):
        self.daemon.projects[self.daemon._norm(self.gpr)]["programs"]["/owned.exe"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "not the target build"):
            self.ask()

    def test_symbols_and_bad_cursors_are_refused_before_the_engine(self):
        for kwargs in ({"address": "main"}, {"address": "0x1", "cursor": "next"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.ask(**kwargs)
        self.assertEqual(self.daemon.calls, [])

    def test_a_lost_program_key_is_reopened_once(self):
        self.ask()
        self.daemon.fail_next["script"] = fakehydra.EngineError("no_program", "closed by restart")
        self.assertTrue(self.ask()["ok"])

    def test_unknown_target_names_adopt_and_prepare(self):
        with self.assertRaisesRegex(ValueError, "prepare action=adopt"):
            self.runner.query("missing", "decompile", "0x1")


class Adopt(EngineCase):
    def test_parent_folder_without_a_hash_lists_candidates_and_registers_nothing(self):
        result = targets.adopt(self.settings, fakehydra.FakeEngine(self.settings), str(self.root / "analysed"))
        self.assertEqual(result["state"], "needs_build_hash")
        self.assertEqual(result["candidates"][0]["sha256"], self.digest)
        self.assertEqual(targets.registry(self.settings), {})

    def test_exe_hash_selects_and_registers_the_program_without_copying(self):
        result = targets.adopt(self.settings, fakehydra.FakeEngine(self.settings), str(self.gpr), exe=str(self.exe), target="adopted")
        self.assertTrue(result["registered"])
        self.assertFalse(result["copied"])
        self.assertEqual(targets.registry(self.settings)["adopted"]["sha256"], self.digest)
        self.assertNotIn("fork_project", [command for _, command, _ in self.daemon.calls])

    def test_a_hash_no_program_has_is_not_registered(self):
        result = targets.adopt(self.settings, fakehydra.FakeEngine(self.settings), str(self.gpr), expected="1" * 64)
        self.assertEqual(result["state"], "no_match")
        self.assertEqual(targets.registry(self.settings), {})

    def test_a_target_name_cannot_be_moved_to_another_build(self):
        targets.register(self.settings, ["name"], {"sha256": "a" * 64})
        with self.assertRaisesRegex(ValueError, "another build"):
            targets.register(self.settings, ["name"], {"sha256": "b" * 64})

    def test_legacy_dir_name_entries_still_resolve(self):
        settings = {**self.settings, "targets": {"old": {"dir": str(self.gpr.parent), "name": "Owned", "program": "owned.exe",
                                                         "sha256": self.digest}}}
        self.assertEqual(Path(targets.resolve(settings, "old")["gpr"]), self.gpr)


class Overlays(EngineCase):
    def test_named_views_isolate_annotations_and_require_revision_checks(self):
        status = json.loads(self.runner.query("owned", "status", options={"view": "alice"}))
        self.assertEqual(status["target"]["view"], "alice")
        self.assertEqual(status["overlays"]["revision"], 0)
        with self.assertRaisesRegex(RuntimeError, "expect_revision_required"):
            self.edit(kind="rename", name="Alice", view="alice", expect_revision=None)
        self.edit(kind="rename", name="Alice", view="alice", expect_revision=0)
        self.edit(kind="rename", name="Bob", view="bob", expect_revision=0)
        self.assertEqual(self.ask(options={"view": "alice"})["function"]["name"], "Alice")
        self.assertEqual(self.ask(options={"view": "bob"})["function"]["name"], "Bob")
        self.assertEqual(self.ask()["function"]["name"], "FUN_140001000")
        with self.assertRaisesRegex(RuntimeError, "overlay revision changed"):
            self.edit(kind="rename", name="Stale", view="alice", expect_revision=0)
        self.assertEqual(self.ask(options={"view": "alice"})["function"]["name"], "Alice")

    def test_revision_is_mandatory_on_the_shared_view_and_the_error_carries_it(self):
        for options in ({"kind": "rename", "name": "Nope"}, {"kind": "revert", "ids": ["0" * 32]},
                        {"kind": "import_types", "corpus": str(self.corpus())}):
            with self.subTest(kind=options["kind"]), self.assertRaises(RuntimeError) as raised:
                self.edit(**options, expect_revision=None)
            body = json.loads(str(raised.exception))
            self.assertEqual((body["error"], body["view"], body["current_revision"]), ("expect_revision_required", "shared", 0))
            self.assertEqual(body["view_revision"], 0)
        self.assertEqual(self.revision(), 0)
        self.edit(kind="rename", name="One")
        with self.assertRaises(RuntimeError) as raised:
            self.edit(kind="rename", name="Two", expect_revision=None)
        self.assertEqual(json.loads(str(raised.exception))["current_revision"], 1)
        with self.assertRaises(RuntimeError) as raised:
            workcopy.edit(self.settings, fakehydra.FakeEngine(self.settings), self.runner.target("owned"), "0x1",
                          {"kind": "rename", "name": "Direct", "source": "s"}, 60)
        self.assertIn("expect_revision_required", str(raised.exception))
        self.assertEqual(self.revision(), 1)

    def test_every_edit_and_status_answer_reports_view_revision(self):
        self.assertEqual(json.loads(self.runner.query("owned", "status"))["view_revision"], 0)
        first = self.edit(kind="rename", name="One")
        self.assertEqual((first["revision"], first["view_revision"], first["rebased"]), (1, 1, False))
        status = json.loads(self.runner.query("owned", "status"))
        self.assertEqual((status["view_revision"], status["overlays"]["view_revision"]), (1, 1))
        self.assertEqual(status["overlays"]["latest_editor"]["by"], first["by"])
        reverted = json.loads(self.runner.query("owned", "type_edit", options={
            "kind": "revert", "ids": [first["overlay_id"]], "expect_revision": 1}))
        self.assertEqual((reverted["revision"], reverted["view_revision"]), (2, 2))
        with patch("hydralysis.overlayjobs.start", return_value={"id": "overlay-0123456789ab", "state": "queued"}):
            job = json.loads(self.runner.query("owned", "type_edit", options={
                "kind": "import_types", "corpus": str(self.corpus()), "source": "dump", "expect_revision": 2}))
        self.assertEqual(job["view_revision"], 2)

    def test_a_stale_edit_on_untouched_subjects_is_rebased(self):
        self.edit(kind="rename", name="One", address="0x140001000")
        other = self.edit(kind="rename", name="Elsewhere", address="0x140002000", expect_revision=0)
        self.assertTrue(other["rebased"])
        self.assertEqual((other["rebased_from"], other["revision"]), (0, 2))
        self.assertEqual(other["subjects_changed_since"], ["address:0x140001000"])
        self.assertEqual(self.ask()["function"]["name"], "One")
        self.assertEqual(self.ask(address="0x140002000")["function"]["name"], "Elsewhere")

    def test_a_stale_edit_on_a_touched_subject_gets_the_subject_aware_conflict(self):
        one = self.edit(kind="rename", name="One", address="0x140001000")
        self.edit(kind="comment", comment="note", address="0x140003000")
        with self.assertRaises(RuntimeError) as raised:
            self.edit(kind="rename", name="Two", address="0x140001000", expect_revision=0)
        body = json.loads(str(raised.exception))
        self.assertEqual(body["conflict"], "overlay revision changed")
        self.assertEqual((body["expected_revision"], body["current_revision"]), (0, 2))
        self.assertEqual(body["latest_editor"]["by"], one["by"])
        self.assertEqual(body["subjects_changed_since"], ["address:0x140001000", "address:0x140003000"])
        self.assertEqual(body["overlapping"], ["address:0x140001000"])
        self.assertEqual(self.revision(), 2)
        self.assertEqual(self.ask()["function"]["name"], "One")

    def test_rebase_applies_to_revert_and_refuses_when_history_is_missing(self):
        first = self.edit(kind="rename", name="One", address="0x140001000")
        self.edit(kind="rename", name="Two", address="0x140002000")
        stale_revert = {"kind": "revert", "ids": [first["overlay_id"]], "expect_revision": 1}
        reverted = json.loads(self.runner.query("owned", "type_edit", options=stale_revert))
        self.assertTrue(reverted["rebased"])
        self.assertEqual(self.ask(address="0x140002000")["function"]["name"], "Two")
        # A store written before the journal existed cannot prove independence.
        path = workcopy._store_path(self.settings, self.runner.target("owned"))
        record = json.loads(path.read_text(encoding="utf-8"))
        # A version-2 store before the journal: no journal, no seal (a pre-seal record, which v1 and v2 may be).
        # Its edits keep their ids; a v3-only key would not exist in it.
        record = {key: record[key] for key in ("sha256", "revision", "edits", "reverted")}
        record.update(version=2, edits=[{key: edit[key] for key in ("id", "address", "options", "by", "at")}
                                        for edit in record["edits"]])
        path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(RuntimeError) as raised:
            self.edit(kind="rename", name="Late", address="0x140009000", expect_revision=0)
        body = json.loads(str(raised.exception))
        self.assertFalse(body["history_complete"])
        self.assertIn("incomplete", body["reason"])

    def test_a_stale_shared_view_edit_conflicts_like_a_named_one(self):
        self.edit(kind="rename", name="One")
        with self.assertRaisesRegex(RuntimeError, "overlay revision changed"):
            self.edit(kind="rename", name="Two", expect_revision=0)

    def test_sync_reports_stable_phase_timings(self):
        self.daemon.fork_copy_ms = 41
        first = self.edit(kind="rename", name="One", view="alice")
        phases = first["sync"]["phases_ms"]
        self.assertEqual(sorted(phases), sorted(workcopy.PHASES + ("total",)))
        self.assertTrue(all(isinstance(value, int) and value >= 0 for value in phases.values()))
        self.assertEqual(phases["copy"], 82)  # the base fork and the working-copy fork, as the engine reports them
        second = self.edit(kind="rename", name="Two", view="alice")
        self.assertFalse(second["sync"]["rebuilt"])
        self.assertEqual((second["sync"]["phases_ms"]["fork"], second["sync"]["phases_ms"]["copy"]), (0, 0))
        status = json.loads(self.runner.query("owned", "status", options={"view": "alice"}))
        self.assertEqual(sorted(status["overlays"]["last_sync"]["phases_ms"]), sorted(phases))

    def test_base_is_rebuilt_when_the_engine_release_changes_and_reused_otherwise(self):
        self.edit(kind="rename", name="One")
        base = workcopy._state(self.settings, self.runner.target("owned"))["base"]
        self.assertEqual(base["engine"], {"hydraVersion": "12.3-hydra.2", "ghidraVersion": "12.3"})
        self.edit(kind="rename", name="Two")
        self.assertEqual(workcopy._state(self.settings, self.runner.target("owned"))["base"]["gpr"], base["gpr"])
        self.daemon.release = {"hydraVersion": "12.3-hydra.3", "ghidraVersion": "12.3"}
        revert = json.loads(self.runner.query("owned", "type_edit", options={
            "kind": "revert", "ids": [workcopy.load_store(self.settings, self.runner.target("owned"))["edits"][-1]["id"]],
            "expect_revision": 2}))
        self.assertTrue(revert["ok"])
        self.ask()  # the rebuild after a revert forks from the base
        rebuilt = workcopy._state(self.settings, self.runner.target("owned"))["base"]
        self.assertNotEqual(rebuilt["gpr"], base["gpr"])
        self.assertEqual(rebuilt["engine"]["hydraVersion"], "12.3-hydra.3")

    def test_stopping_named_view_keeps_other_views_and_shared_source_open(self):
        self.ask()
        self.edit(kind="rename", name="Alice", view="alice", expect_revision=0)
        self.edit(kind="rename", name="Bob", view="bob", expect_revision=0)
        self.ask(options={"view": "alice"})
        self.ask(options={"view": "bob"})
        before = dict(query._keys)
        result = json.loads(self.runner.query("owned", "stop", options={"view": "alice"}))
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["released"]), 1)
        master_key = next(key for key in before if key[1] == str(self.gpr).lower())
        self.assertIn(master_key, query._keys)
        opened_before = sum(command == "open_program" for _, command, _ in self.daemon.calls)
        self.assertEqual(self.ask(options={"view": "bob"})["function"]["name"], "Bob")
        self.assertEqual(sum(command == "open_program" for _, command, _ in self.daemon.calls), opened_before)

    def test_named_view_rejects_invalid_names_and_routes_crossbuild_views(self):
        for view in ("../escape", "", 123, "a" * 65):
            if view == "":
                continue  # Empty selects the backwards-compatible shared view.
            with self.subTest(view=view), self.assertRaises(ValueError):
                self.runner.query("owned", "status", options={"view": view})
        with patch("hydralysis.overlayjobs.start", return_value={"id": "overlay-0123456789ab"}) as start:
            self.runner.query("owned", "diff", options={"view": "alice", "against": "owned", "against_view": "bob"})
            self.assertEqual(start.call_args.kwargs["view"], "alice")
            self.assertEqual(start.call_args.args[4]["against_view"], "bob")
        with self.assertRaises(ValueError):
            self.runner.query("owned", "diff", options={"against": "owned", "against_view": "../escape"})

    def test_bulk_job_and_rebuild_keep_the_named_view(self):
        with patch("hydralysis.overlayjobs.start", return_value={"id": "overlay-0123456789ab", "state": "queued"}) as start:
            self.runner.query("owned", "type_edit", options={"kind": "import_types", "view": "alice",
                              "expect_revision": 0, "corpus": str(self.corpus()), "source": "reflection dump"})
            self.assertEqual(start.call_args.kwargs["view"], "alice")
            self.assertNotIn("view", start.call_args.args[4])
            with self.assertRaisesRegex(RuntimeError, "synchronizing"):
                workcopy.rebuilding(self.settings, workcopy.with_view(self.runner.target("owned"), "alice"))
            self.assertEqual(start.call_args.kwargs["view"], "alice")

    def test_overlay_worker_resolves_and_edits_the_requested_view(self):
        from hydralysis import overlayjobs
        with patch("hydralysis.overlayjobs.proc.popen", return_value=type("Child", (), {"pid": 1111})()), \
             patch("hydralysis.overlayjobs.proc_start", return_value=4444):
            job = overlayjobs.start(self.settings, "owned", "edit", "0x140001000",
                                    {"kind": "rename", "name": "Alice", "source": "test", "expect_revision": 0},
                                    view="alice")
        with patch("hydralysis.overlayjobs.threading.Thread"), \
             patch("hydralysis.workcopy.edit", return_value={"ok": True}) as edit:
            overlayjobs.run(overlayjobs.job_path(self.settings, job["id"]))
        self.assertEqual(edit.call_args.args[2]["view"], "alice")
        self.assertEqual(edit.call_args.args[2]["key"], workcopy.with_view(self.runner.target("owned"), "alice")["key"])
        self.assertEqual(overlayjobs.status(self.settings, job["id"])["state"], "done")

    def test_first_edit_forks_and_reads_come_from_the_working_copy(self):
        result = self.edit(kind="rename", name="Named")
        self.assertEqual(result["revision"], 1)
        self.assertTrue(result["sync"]["rebuilt"])
        self.assertEqual(result["by"]["client"].split(":")[0], hydra.ATTRIBUTION)
        answer = self.ask()
        self.assertEqual(answer["function"]["name"], "Named")
        self.assertEqual(answer["overlays"]["revision"], 1)
        master = self.daemon.projects[self.daemon._norm(self.gpr)]["programs"]["/owned.exe"]
        self.assertEqual(master["saved"]["names"], {})
        self.assertIsNone(master["live"])

    def test_later_edits_apply_incrementally(self):
        self.edit(kind="rename", name="One")
        second = self.edit(kind="rename", name="Two")
        self.assertFalse(second["sync"]["rebuilt"])
        self.assertEqual(second["sync"]["applied_now"], 1)
        self.assertEqual(self.ask()["function"]["name"], "Two")

    def test_a_stale_editor_gets_a_conflict_naming_the_last_editor(self):
        self.edit(kind="rename", name="One")
        with self.assertRaisesRegex(RuntimeError, "overlay revision changed") as raised:
            self.edit(kind="rename", name="Two", expect_revision=0)
        self.assertIn("latest_editor", str(raised.exception))
        self.assertEqual(self.ask()["function"]["name"], "One")

    def test_a_refused_record_leaves_store_and_copy_unchanged(self):
        self.edit(kind="rename", name="One")
        with self.assertRaisesRegex(ValueError, "refused"):
            self.edit(kind="rename", name="FAIL")
        self.assertEqual(workcopy.load_store(self.settings, self.runner.target("owned"))["revision"], 1)
        self.assertEqual(self.ask()["function"]["name"], "One")

    def test_revert_rebuilds_from_the_master_in_one_step(self):
        first = self.edit(kind="rename", name="One")
        self.edit(kind="rename", name="Two")
        reverted = json.loads(self.runner.query("owned", "type_edit", options={"kind": "revert", "expect_revision": 2, "ids": [
            workcopy.load_store(self.settings, self.runner.target("owned"))["edits"][-1]["id"]]}))
        self.assertEqual(reverted["reverted"], 1)
        self.assertEqual(self.ask()["function"]["name"], "One")
        self.assertTrue(first["ok"])

    def test_lost_unsaved_changes_are_replayed_from_the_store(self):
        self.edit(kind="rename", name="One")
        state = workcopy._state(self.settings, self.runner.target("owned"))
        fork = self.daemon.projects[self.daemon._norm(state["fork_gpr"])]["programs"]["/owned.exe"]
        fork["live"] = None  # the daemon restarted: nothing ever saved the working copy (D61)
        query._keys.clear()
        self.assertEqual(self.ask()["function"]["name"], "One")

    def corpus(self, text='{"kind":"struct","name":"Thing","size":8}\n'):
        path = self.root / "types.jsonl"
        path.write_text(text, encoding="utf-8")
        return path

    def test_type_import_validates_and_runs_as_a_job(self):
        from hydralysis.analysis import validate_options
        with self.assertRaisesRegex(ValueError, "absolute path"):
            validate_options("type_edit", {"kind": "import_types", "corpus": "types.jsonl", "source": "s"})
        with self.assertRaisesRegex(ValueError, "corpus_sha256"):
            validate_options("type_edit", {"kind": "import_types", "corpus": str(self.corpus()), "source": "s",
                                           "corpus_sha256": "0" * 64})
        with patch("hydralysis.overlayjobs.start", return_value={"id": "overlay-0123456789ab", "state": "queued"}) as start:
            answer = json.loads(self.runner.query("owned", "type_edit", options={
                "kind": "import_types", "corpus": str(self.corpus()), "source": "reflection dump", "expect_revision": 0}))
        self.assertEqual(answer["id"], "overlay-0123456789ab")
        self.assertEqual(start.call_args.args[2], "edit")

    def test_corpus_is_stored_once_under_its_hash_and_recorded_by_hash(self):
        source = self.corpus()
        result = workcopy.edit(self.settings, fakehydra.FakeEngine(self.settings), self.runner.target("owned"), "",
                               {"kind": "import_types", "corpus": str(source), "source": "dump", "expect_revision": 0}, 60)
        self.assertTrue(result["ok"])
        record = workcopy.load_store(self.settings, self.runner.target("owned"))["edits"][0]
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(record["options"]["corpus_sha256"], digest)
        self.assertNotIn("corpus", record["options"])
        self.assertEqual(workcopy.corpus_path(self.settings, digest).read_bytes(), source.read_bytes())

    def test_a_rebuild_that_replays_a_corpus_is_handed_to_a_job(self):
        target = self.runner.target("owned")
        workcopy.edit(self.settings, fakehydra.FakeEngine(self.settings), target, "",
                      {"kind": "import_types", "corpus": str(self.corpus()), "source": "dump", "expect_revision": 0}, 60)
        workcopy.edit(self.settings, fakehydra.FakeEngine(self.settings), target, "0x140001000",
                      {"kind": "rename", "name": "Named", "source": "s", "expect_revision": 1}, 60)
        last = workcopy.load_store(self.settings, target)["edits"][-1]["id"]
        workcopy.revert(self.settings, target, [last], 2)
        with patch("hydralysis.overlayjobs.start", return_value={"id": "overlay-0123456789ab", "state": "queued"}):
            with self.assertRaisesRegex(RuntimeError, "overlay-0123456789ab"):
                self.ask()

    def test_rva_edits_are_recorded_as_plain_vas(self):
        self.edit(address="rva:0x1000", kind="rename", name="Named")
        record = workcopy.load_store(self.settings, self.runner.target("owned"))["edits"][0]
        self.assertEqual(record["address"], "0x140001000")



class ViewLifecycle(EngineCase):
    """PROTOCOL-3.md D44/D61, 4.10: one lifecycle per view, no second writer, one shared base, a typed `busy`."""

    def sync_calls(self, command):
        return [fields for _, name, fields in self.daemon.calls if name == command]

    def test_view_lifecycle_has_no_saver_and_no_saved_state(self):
        import importlib.util
        import re
        src = Path(workcopy.__file__).parent
        self.assertIsNone(importlib.util.find_spec("hydralysis.workcopy_saver"))
        self.assertFalse((src / "workcopy_saver.py").exists())
        self.assertFalse(hasattr(workcopy, "_start_saver"))
        for path in sorted(src.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"workcopy_saver|_start_saver|saver\.lock|saver-settings|overlay_save_debounce_s|saved_at", text),
                              path.name)
        self.edit(kind="rename", name="Lifecycle")
        state = workcopy._state(self.settings, self.runner.target("owned"))
        self.assertNotIn("saved_at", state)
        status = self.ask("status")
        self.assertNotIn("saved", status["overlays"])
        self.assertEqual(status["overlays"]["pending"], 1)
        # No process other than the caller's ever opened a fork for writing: every writer is a sync's own connection.
        roles = {role for role, name, fields in self.daemon.calls if name == "open_program" and fields.get("writable")}
        self.assertEqual(roles, {"writer"})

    def test_closing_a_views_program_with_discard_keeps_the_folder_and_a_reopen_replays_what_was_lost(self):
        self.edit(kind="rename", name="Kept", view="alice")
        target = workcopy.with_view(self.runner.target("owned"), "alice")
        state = workcopy._state(self.settings, target)
        folder = Path(state["fork_gpr"]).parent
        project = self.daemon.projects[self.daemon._norm(state["fork_gpr"])]
        forks = len(self.sync_calls("fork_project"))
        engine = fakehydra.FakeEngine(self.settings, role="writer", lane="evict")
        engine.call("close_project", project=project["id"], discard=True)  # what an eviction does
        self.assertTrue(folder.is_dir())
        self.assertIsNone(project["programs"]["/owned.exe"]["live"])  # the daemon lost the unsaved change
        query._keys.clear()
        self.assertEqual(self.ask(options={"view": "alice"})["function"]["name"], "Kept")  # replayed from the store
        self.assertEqual(len(self.sync_calls("fork_project")), forks)  # the same folder was reused, nothing re-forked
        self.assertEqual(workcopy._state(self.settings, target)["fork_gpr"], state["fork_gpr"])

    def test_a_lock_wait_that_runs_out_reaches_the_caller_as_the_structured_busy(self):
        from hydralysis.locks import LaneLock
        target = self.runner.target("owned")
        folder = workcopy._directory(self.settings, target)
        folder.mkdir(parents=True, exist_ok=True)
        holder = LaneLock(str(folder / ".view.lock"))
        self.assertTrue(holder.acquire())
        self.addCleanup(holder.release)
        before = self.revision()
        with patch("hydralysis.workcopy.SYNC_LOCK_S", 0.2):
            with self.assertRaises(RuntimeError) as raised:
                self.edit(kind="rename", name="Blocked", expect_revision=before)
        busy = json.loads(str(raised.exception))
        self.assertEqual(busy["error"], "busy")
        self.assertEqual(busy["what"], "working copy")
        self.assertGreater(busy["retryAfterMs"], 0)
        self.assertEqual(self.revision(), before)  # nothing was recorded
        holder.release()
        self.assertTrue(self.edit(kind="rename", name="Free", expect_revision=before)["ok"])

    def test_the_default_bounds_are_thirty_seconds(self):
        self.assertEqual(workcopy.SYNC_LOCK_S, 30)
        self.assertEqual(workcopy.BASE_WAIT_S, 30)

    def test_a_writer_connection_of_one_view_does_not_release_another_views_programs(self):
        self.edit(kind="rename", name="One", view="a")
        one = workcopy.with_view(self.runner.target("owned"), "a")
        two = workcopy.with_view(self.runner.target("owned"), "b")
        first, second = workcopy.writer_for(self.settings, one), workcopy.writer_for(self.settings, two)
        self.assertNotEqual(first.key, second.key)
        project_one = first.call("open_project", path=workcopy._state(self.settings, one)["fork_gpr"], writable=True)
        project_two = second.call("open_project", path=str(self.gpr), writable=True)
        key_one = first.call("open_program", path="/owned.exe", project=project_one["id"], writable=True)["key"]
        key_two = second.call("open_program", path="/owned.exe", project=project_two["id"], writable=True)["key"]
        first.reset()
        self.assertEqual(second.writable, {key_two})
        self.assertEqual(first.writable, set())
        self.assertIn(second.conn, second._program(key_two)["writers"])
        self.assertNotIn(first.conn, first._program(key_one)["writers"])


class SharedBase(EngineCase):
    """PROTOCOL-3.md 4.10: one base per (origin, generation, master revision, engine release), shared by every view."""

    def bases(self):
        return [fields["path"] for _, name, fields in self.daemon.calls
                if name == "fork_project" and Path(fields["path"]).name.startswith("base-")]

    def folder(self):
        (folder,) = [path for path in workcopy.bases_root(self.settings).iterdir() if path.is_dir()]
        return folder

    def test_the_first_edits_of_many_views_build_one_base(self):
        for view in ("a", "b", "c", "d"):
            self.edit(kind="rename", name="N_" + view, view=view)
        self.assertEqual(len(self.bases()), 1, self.bases())
        folder = self.folder()
        self.assertTrue((folder / "COMPLETE.json").is_file())
        ready = workcopy._base_ready(folder)
        phases = {}
        for view in ("a", "b", "c", "d"):
            state = workcopy._state(self.settings, workcopy.with_view(self.runner.target("owned"), view))
            self.assertEqual(state["base"]["gpr"], ready["gpr"])
            phases[view] = state["last_sync"]["phases_ms"]["base_upgrade"]
        # Only the builder spent time on the upgrade phase; the second to last view found the base in place.
        self.assertEqual([phases[view] for view in ("b", "c", "d")], [0, 0, 0])

    def test_a_new_engine_release_is_a_new_base(self):
        self.edit(kind="rename", name="One", view="a")
        self.daemon.release = {"hydraVersion": "12.3-hydra.9", "ghidraVersion": "12.3"}
        self.edit(kind="rename", name="Two", view="b")
        self.assertEqual(len(self.bases()), 2)

    def test_a_base_without_its_completion_marker_is_invisible_and_is_rebuilt(self):
        self.edit(kind="rename", name="One", view="a")
        folder = self.folder()
        for path in folder.glob("COMPLETE.json*"):
            path.unlink()
        self.edit(kind="rename", name="Two", view="b")
        self.assertEqual(len(self.bases()), 2)
        self.assertTrue((folder / "COMPLETE.json").is_file())

    def test_a_waiter_gets_a_structured_busy_when_the_builder_never_finishes(self):
        from hydralysis.locks import LaneLock
        self.edit(kind="rename", name="One", view="a")
        folder = self.folder()
        for path in folder.glob("COMPLETE.json*"):
            path.unlink()
        holder = LaneLock(str(workcopy.bases_root(self.settings) / (folder.name + ".lock")))
        self.assertTrue(holder.acquire())
        self.addCleanup(holder.release)
        with patch("hydralysis.workcopy.BASE_WAIT_S", 0.3):
            with self.assertRaises(RuntimeError) as raised:
                self.edit(kind="rename", name="Two", view="b")
        busy = json.loads(str(raised.exception))
        self.assertEqual((busy["error"], busy["what"]), ("busy", "shared base"))
        self.assertEqual(self.revision("b"), 0)

    def test_a_waiter_takes_the_base_the_builder_finishes(self):
        import threading
        import time
        from hydralysis.locks import LaneLock
        self.edit(kind="rename", name="One", view="a")
        folder = self.folder()
        record = workcopy._base_ready(folder)
        marker = folder / "COMPLETE.json"
        saved = marker.read_bytes()
        for path in folder.glob("COMPLETE.json*"):
            path.unlink()
        holder = LaneLock(str(workcopy.bases_root(self.settings) / (folder.name + ".lock")))
        self.assertTrue(holder.acquire())

        def finish():
            time.sleep(0.3)
            marker.write_bytes(saved)
            holder.release()
        thread = threading.Thread(target=finish)
        thread.start()
        self.addCleanup(thread.join)
        self.edit(kind="rename", name="Two", view="b")
        self.assertEqual(len(self.bases()), 1)  # the waiter forked nothing of its own
        self.assertEqual(workcopy._state(self.settings, workcopy.with_view(self.runner.target("owned"), "b"))["base"]["gpr"],
                         record["gpr"])

    def test_a_stale_overlay_state_on_a_fresh_base_is_cleared_before_a_view_forks_from_it(self):
        master = self.daemon.projects[self.daemon._norm(self.gpr)]["programs"]["/owned.exe"]
        master["saved"]["marker"] = json.dumps({"revision": 9, "edits": 9, "ids_sha256": "x"}, separators=(",", ":"))
        self.edit(kind="rename", name="One")
        state = workcopy._state(self.settings, self.runner.target("owned"))
        self.assertTrue(state["base"]["marker_cleared"])
        base = self.daemon.projects[self.daemon._norm(state["base"]["gpr"])]["programs"]["/owned.exe"]
        self.assertEqual(base["saved"]["marker"], "")
        self.assertEqual(self.ask()["function"]["name"], "One")


class LaunchConfiguration(unittest.TestCase):
    """D54: the lane caps of the daemon this client launches come from the expected number of agents."""

    def test_defaults_follow_sixteen_expected_agents(self):
        config = hydra.daemon_config({"root": "r"})
        self.assertEqual((config["maxLong"], config["maxQuick"]), (24, 32))

    def test_the_caps_scale_with_expected_agents_and_never_fall_below_the_floor(self):
        small = hydra.daemon_config({"root": "r", "expected_agents": 2})
        large = hydra.daemon_config({"root": "r", "expected_agents": 40})
        self.assertEqual((small["maxLong"], small["maxQuick"]), (8, 16))
        self.assertEqual((large["maxLong"], large["maxQuick"]), (60, 80))

    def test_an_explicit_hydra_setting_wins(self):
        config = hydra.daemon_config({"root": "r", "expected_agents": 16, "hydra": {"maxLong": 5, "maxQuick": 7, "maxImports": 3}})
        self.assertEqual((config["maxLong"], config["maxQuick"], config["maxImports"]), (5, 7, 3))

    def test_a_bad_count_is_refused(self):
        for bad in (0, 257, -1, True, "16", 1.5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                hydra.daemon_config({"root": "r", "expected_agents": bad})

    def test_the_launch_writes_the_caps_into_the_config_the_engine_reads(self):
        with workdir("launch") as folder:
            path = hydra.write_daemon_config({"root": folder, "expected_agents": 10})
            written = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual((written["maxLong"], written["maxQuick"]), (15, 20))


if __name__ == "__main__":
    unittest.main()
