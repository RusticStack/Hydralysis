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
        patches = [patch("hydralysis.hydra.Engine", fakehydra.FakeEngine),
                   patch("hydralysis.workcopy._start_saver")]
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
        fork["live"] = None  # the daemon restarted before the saver ran
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


if __name__ == "__main__":
    unittest.main()
