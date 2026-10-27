"""Queries, adopt and cited overlays through the engine, against a fake daemon."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from rusticre import query, targets, workcopy
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
        patches = [patch("rusticre.hydra.Engine", fakehydra.FakeEngine),
                   patch("rusticre.workcopy._start_saver")]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        query._keys.clear()
        self.runner = query.QueryRunner(self.settings, fakehydra.FakeEngine(self.settings))

    def ask(self, action="decompile", address="0x140001000", **kwargs):
        return json.loads(self.runner.query("owned", action, address, **kwargs))

    def edit(self, **options):
        return json.loads(self.runner.query("owned", "type_edit", options.pop("address", "0x140001000"),
                                            options={"source": "cited test evidence", **options}))


class Queries(EngineCase):
    def test_user_script_receives_the_selected_named_view(self):
        from unittest.mock import Mock
        from rusticre import userscripts
        folder = self.root / "scripts"
        folder.mkdir()
        (folder / "Inspect.java").write_text("// fixture", encoding="utf-8")
        self.settings["targets"]["owned"]["scripts"] = str(folder)
        runner = Mock()
        runner.program_for.return_value = {"key": "program-key"}
        runner.engine.call.return_value = {"mode": "contained", "output": "ok"}
        with patch("rusticre.query.QueryRunner", return_value=runner), patch("rusticre.userscripts._stage", return_value="Inspect.java"):
            userscripts.run(self.settings, "owned", "Inspect.java", [], view="alice")
        selected = runner.program_for.call_args.args[0]
        self.assertEqual(selected["view"], "alice")
        self.assertEqual(selected["key"], workcopy.with_view(self.runner.target("owned"), "alice")["key"])

    def test_user_script_view_is_forwarded_from_mcp_and_cli(self):
        import contextlib
        import io
        from rusticre import api, cli
        with patch("rusticre.api._settings", return_value=self.settings), \
             patch("rusticre.userscripts.run", return_value="done") as run:
            api.call("ghidra_run", {"target": "owned", "script": "Inspect", "view": "alice"})
        self.assertEqual(run.call_args.args[-1], "alice")
        with patch("rusticre.cli.call", return_value="done") as call, contextlib.redirect_stdout(io.StringIO()):
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
        with self.assertRaisesRegex(ValueError, "requires expect_revision"):
            self.edit(kind="rename", name="Alice", view="alice")
        self.edit(kind="rename", name="Alice", view="alice", expect_revision=0)
        self.edit(kind="rename", name="Bob", view="bob", expect_revision=0)
        self.assertEqual(self.ask(options={"view": "alice"})["function"]["name"], "Alice")
        self.assertEqual(self.ask(options={"view": "bob"})["function"]["name"], "Bob")
        self.assertEqual(self.ask()["function"]["name"], "FUN_140001000")
        with self.assertRaisesRegex(RuntimeError, "overlay revision changed"):
            self.edit(kind="rename", name="Stale", view="alice", expect_revision=0)
        self.assertEqual(self.ask(options={"view": "alice"})["function"]["name"], "Alice")

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
        with patch("rusticre.overlayjobs.start", return_value={"id": "overlay-0123456789ab"}) as start:
            self.runner.query("owned", "diff", options={"view": "alice", "against": "owned", "against_view": "bob"})
            self.assertEqual(start.call_args.kwargs["view"], "alice")
            self.assertEqual(start.call_args.args[4]["against_view"], "bob")
        with self.assertRaises(ValueError):
            self.runner.query("owned", "diff", options={"against": "owned", "against_view": "../escape"})

    def test_bulk_job_and_rebuild_keep_the_named_view(self):
        with patch("rusticre.overlayjobs.start", return_value={"id": "overlay-0123456789ab", "state": "queued"}) as start:
            self.runner.query("owned", "type_edit", options={"kind": "import_types", "view": "alice",
                              "expect_revision": 0, "corpus": str(self.corpus()), "source": "reflection dump"})
            self.assertEqual(start.call_args.kwargs["view"], "alice")
            self.assertNotIn("view", start.call_args.args[4])
            with self.assertRaisesRegex(RuntimeError, "synchronizing"):
                workcopy.rebuilding(self.settings, workcopy.with_view(self.runner.target("owned"), "alice"))
            self.assertEqual(start.call_args.kwargs["view"], "alice")

    def test_overlay_worker_resolves_and_edits_the_requested_view(self):
        from rusticre import overlayjobs
        with patch("rusticre.overlayjobs.proc.popen", return_value=type("Child", (), {"pid": 1111})()), \
             patch("rusticre.overlayjobs.proc_start", return_value=4444):
            job = overlayjobs.start(self.settings, "owned", "edit", "0x140001000",
                                    {"kind": "rename", "name": "Alice", "source": "test", "expect_revision": 0},
                                    view="alice")
        with patch("rusticre.overlayjobs.threading.Thread"), \
             patch("rusticre.workcopy.edit", return_value={"ok": True}) as edit:
            overlayjobs.run(overlayjobs.job_path(self.settings, job["id"]))
        self.assertEqual(edit.call_args.args[2]["view"], "alice")
        self.assertEqual(edit.call_args.args[2]["key"], workcopy.with_view(self.runner.target("owned"), "alice")["key"])
        self.assertEqual(overlayjobs.status(self.settings, job["id"])["state"], "done")

    def test_first_edit_forks_and_reads_come_from_the_working_copy(self):
        result = self.edit(kind="rename", name="Named")
        self.assertEqual(result["revision"], 1)
        self.assertTrue(result["sync"]["rebuilt"])
        self.assertEqual(result["by"]["client"].split(":")[0], "rusticre")
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
        self.assertIn("last_edit_by", str(raised.exception))
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
        reverted = json.loads(self.runner.query("owned", "type_edit", options={"kind": "revert", "ids": [
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
        from rusticre.analysis import validate_options
        with self.assertRaisesRegex(ValueError, "absolute path"):
            validate_options("type_edit", {"kind": "import_types", "corpus": "types.jsonl", "source": "s"})
        with self.assertRaisesRegex(ValueError, "corpus_sha256"):
            validate_options("type_edit", {"kind": "import_types", "corpus": str(self.corpus()), "source": "s",
                                           "corpus_sha256": "0" * 64})
        with patch("rusticre.overlayjobs.start", return_value={"id": "overlay-0123456789ab", "state": "queued"}) as start:
            answer = json.loads(self.runner.query("owned", "type_edit", options={
                "kind": "import_types", "corpus": str(self.corpus()), "source": "reflection dump"}))
        self.assertEqual(answer["id"], "overlay-0123456789ab")
        self.assertEqual(start.call_args.args[2], "edit")

    def test_corpus_is_stored_once_under_its_hash_and_recorded_by_hash(self):
        source = self.corpus()
        result = workcopy.edit(self.settings, fakehydra.FakeEngine(self.settings), self.runner.target("owned"), "",
                               {"kind": "import_types", "corpus": str(source), "source": "dump"}, 60)
        self.assertTrue(result["ok"])
        record = workcopy.load_store(self.settings, self.runner.target("owned"))["edits"][0]
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(record["options"]["corpus_sha256"], digest)
        self.assertNotIn("corpus", record["options"])
        self.assertEqual(workcopy.corpus_path(self.settings, digest).read_bytes(), source.read_bytes())

    def test_a_rebuild_that_replays_a_corpus_is_handed_to_a_job(self):
        target = self.runner.target("owned")
        workcopy.edit(self.settings, fakehydra.FakeEngine(self.settings), target, "",
                      {"kind": "import_types", "corpus": str(self.corpus()), "source": "dump"}, 60)
        workcopy.edit(self.settings, fakehydra.FakeEngine(self.settings), target, "0x140001000",
                      {"kind": "rename", "name": "Named", "source": "s"}, 60)
        last = workcopy.load_store(self.settings, target)["edits"][-1]["id"]
        workcopy.revert(self.settings, target, [last])
        with patch("rusticre.overlayjobs.start", return_value={"id": "overlay-0123456789ab", "state": "queued"}):
            with self.assertRaisesRegex(RuntimeError, "overlay-0123456789ab"):
                self.ask()

    def test_rva_edits_are_recorded_as_plain_vas(self):
        self.edit(address="rva:0x1000", kind="rename", name="Named")
        record = workcopy.load_store(self.settings, self.runner.target("owned"))["edits"][0]
        self.assertEqual(record["address"], "0x140001000")


if __name__ == "__main__":
    unittest.main()
