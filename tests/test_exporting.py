import hashlib
import io
import json
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from hydralysis import exporting, targets, workcopy
from hydralysis import export_worker
from hydralysis.backends import read_json

from support import workdir


class FakeRunner:
    def __init__(self, settings, rows=None, failing=None, truncated=False, busy=False):
        self.settings = settings
        self.digest = settings["targets"]["fixture"]["sha256"]
        self.rows = rows or [{"address": "0x401000", "name": "first", "body": ["[00401000, 00401004]"], "body_truncated": False},
                             {"address": "0x401010", "name": "second", "body": ["[00401010, 00401014]"], "body_truncated": False}]
        self.failing = failing
        self.truncated = truncated
        self.busy = busy
        self.calls = []

    def query(self, target, action, **options):
        self.calls.append((action, options))
        if self.busy:
            raise RuntimeError("target worker is busy")
        base = {"ok": True, "sha256": self.digest, "image_base": "0x400000", "program": "owned.exe"}
        if action == "functions":
            return json.dumps({**base, "functions": self.rows, "truncated": False})
        if action == "types":
            return json.dumps({**base, "types": [{"path": "/Sample", "length": 8}], "truncated": False})
        if action == "type":
            return json.dumps({**base, "type": {"path": options["options"]["path"], "fields": []}, "truncated": False})
        if options["address"] == self.failing:
            raise RuntimeError("decompile refused: known fixture failure")
        function = next(item for item in self.rows if item["address"] == options["address"])
        return json.dumps({**base, "function": function, "c": "int %s(void) { return 7; }\n" % function["name"], "truncated": self.truncated})


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = workdir()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        master = self.root / "master"
        master.mkdir()
        (master / "owned.gpr").write_bytes(b"project")
        (master / "owned.rep").mkdir()
        self.analysis = master / "owned.rep" / "analysis"
        self.analysis.write_bytes(b"saved analysis")
        exe = self.root / "owned.exe"
        exe.write_bytes(b"a tiny test owned executable")
        self.project = {"dir": str(master), "name": "owned", "program": "owned.exe", "exe": str(exe)}
        self.settings = {"root": str(self.root / "root"), "hydra_dir": str(self.root / "hydra"), "targets": {"fixture": self.project}}
        # The engine computes the master's revision; a save there changes it.
        self.revision = "rev-1"
        for name in ("hydralysis.exporting.master_revision", "hydralysis.export_worker.master_revision"):
            patcher = patch(name, side_effect=lambda settings, selected: self.revision)
            patcher.start()
            self.addCleanup(patcher.stop)

    def make(self, **options):
        with patch("hydralysis.exporting._launch", side_effect=lambda path, record, settings: record):
            result = exporting.start(self.settings, "fixture", options)
        self.token = result.get("owner_token", "")
        path = exporting.job_path(self.settings, result["id"])
        exporting.update(path, generation="test", state="interrupted")
        return path

    def run_job(self, path, **kwargs):
        instances = []
        def factory(settings):
            runner = FakeRunner(settings, **kwargs)
            instances.append(runner)
            return runner
        with patch("hydralysis.export_worker.Image", return_value=None), redirect_stdout(io.StringIO()):
            export_worker.run(path, "test", runner_factory=factory)
        return read_json(path), instances[0]

    def rows(self, path):
        output = Path(read_json(path)["output_path"])
        return [json.loads(line) for line in output.read_text().splitlines()]

    def test_named_view_export_passes_view_to_queries_and_binds_resume_to_its_history(self):
        selected = targets.resolve(self.settings, "fixture")
        alice = workcopy.with_view(selected, "alice")
        shared = workcopy.with_view(selected)

        def add_edit(target, edit_id):
            store = workcopy.load_store(self.settings, target)
            store["revision"] += 1
            store["edits"].append({"id": edit_id * 32, "address": "0x401000", "seq": store["revision"],
                                   "effects": None, "before_unknown": True,
                                   "options": {"kind": "rename", "name": "Named", "source": "evidence"}})
            workcopy._save_store(self.settings, target, store)

        add_edit(alice, "a")
        path = self.make(view="alice")
        record, runner = self.run_job(path)
        self.assertEqual(record["state"], "done")
        self.assertEqual(record["provenance"]["view"], "alice")
        self.assertTrue(all(options["options"]["view"] == "alice" for _, options in runner.calls))
        add_edit(shared, "b")
        with patch("hydralysis.exporting._launch") as launch:
            resumed = exporting.start(self.settings, "fixture", {"resume": record["id"]})
        self.assertTrue(resumed["reused"])
        launch.assert_not_called()
        with self.assertRaisesRegex(ValueError, "cannot change"):
            exporting.start(self.settings, "fixture", {"resume": record["id"], "view": "bob"})
        add_edit(alice, "c")
        with self.assertRaisesRegex(ValueError, "overlays changed"):
            exporting.start(self.settings, "fixture", {"resume": record["id"]})

    def test_invalid_export_view_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "view must be"):
            exporting.normalized({"view": "../wrong"})

    def test_worker_streams_c_and_hashes_outside_the_job_response(self):
        path = self.make()
        record, runner = self.run_job(path)
        rows = self.rows(path)
        self.assertEqual(record["state"], "done")
        self.assertTrue(record["complete"])
        self.assertEqual(record["completed"], 2)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["c_sha256"], hashlib.sha256(rows[0]["result"]["c"].encode()).hexdigest())
        self.assertEqual([options["options"]["max_characters"] for action, options in runner.calls if action == "decompile"], [2097152, 2097152])
        public = exporting.status(self.settings, record["id"])
        self.assertNotIn("settings", public)
        self.assertNotIn("c", public)
        self.assertTrue(Path(public["imports_path"]).exists())

    def test_a_decompile_the_engine_stopped_is_a_partial_row_not_a_failure(self):
        partial = {"c": "int first(void) {", "truncated": True, "bytes_emitted": 1048576, "reason": "max_result_mb",
                   "fragments": [{"start": "0x401000", "end": "0x401004", "class": "code"},
                                 {"start": "0x401004", "end": "0x401008", "class": "data"}]}

        class Stopped(FakeRunner):
            def query(self, target, action, **options):
                if action == "decompile" and options["address"] == "0x401000":
                    self.calls.append((action, options))
                    raise RuntimeError(json.dumps({"ok": False, **partial}))
                return super().query(target, action, **options)

        path = self.make()
        instances = []
        def factory(settings):
            instances.append(Stopped(settings))
            return instances[0]
        with patch("hydralysis.export_worker.Image", return_value=None), redirect_stdout(io.StringIO()):
            export_worker.run(path, "test", runner_factory=factory)
        record, rows = read_json(path), self.rows(path)
        self.assertEqual((record["state"], record["failed"], record["truncated"]), ("done", 0, 1))
        self.assertEqual((rows[0]["state"], rows[0]["truncated"]), ("done", True))
        self.assertEqual(rows[0]["coverage"], {"status": "partial", "limitations": ["decompile_truncated"]})
        self.assertEqual(rows[0]["limitations"], ["decompile_truncated", "non_code_fragments"])
        self.assertEqual(rows[0]["decompile"]["reason"], "max_result_mb")
        self.assertEqual(rows[0]["result"]["fragments"], partial["fragments"])
        self.assertEqual(rows[0]["c_sha256"], hashlib.sha256(partial["c"].encode()).hexdigest())
        self.assertEqual(rows[1]["state"], "done")
        self.assertNotIn("coverage", rows[1])           # an engine reply without the fields adds nothing

    def test_limit_in_the_middle_of_a_page_is_not_claimed_complete(self):
        path = self.make(limit=1)
        record, _ = self.run_job(path)
        self.assertTrue(record["limited"])
        self.assertFalse(record["complete"])
        self.assertEqual(record["cursor"], "")
        self.assertEqual(len(self.rows(path)), 1)

    def test_known_function_failure_is_retained_and_next_function_exports(self):
        path = self.make()
        record, _ = self.run_job(path, failing="0x401000")
        self.assertEqual(record["state"], "done")
        self.assertEqual(record["failed"], 1)
        self.assertEqual(record["succeeded"], 1)
        self.assertFalse(record["complete"])
        self.assertEqual([row["state"] for row in self.rows(path)], ["failed", "done"])

    def test_truncated_text_is_hashed_as_exported_and_not_claimed_complete(self):
        path = self.make()
        record, _ = self.run_job(path, truncated=True)
        self.assertEqual(record["truncated"], 2)
        self.assertFalse(record["complete"])
        self.assertIn("exact exported", self.rows(path)[0]["c_hash_scope"])

    def test_busy_backend_retries_once_then_pauses_without_skipping_rows(self):
        path = self.make()
        with patch("hydralysis.export_worker.time.sleep"):
            record, runner = self.run_job(path, busy=True)
        self.assertEqual(record["state"], "paused")
        self.assertIn("one retry", record["error"])
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(record["completed"], 0)

    def test_crash_after_durable_row_before_checkpoint_resumes_without_duplicate(self):
        path = self.make()
        actual_update = exporting.update
        def crash(path, **changes):
            if str(changes.get("stage", "")).startswith("exporting "):
                raise KeyboardInterrupt("simulated worker death after fsync")
            return actual_update(path, **changes)
        with patch("hydralysis.export_worker.update", side_effect=crash), self.assertRaises(KeyboardInterrupt):
            self.run_job(path)
        self.assertEqual(read_json(path)["completed"], 0)
        self.assertEqual(len(self.rows(path)), 1)
        exporting.update(path, state="interrupted")
        record, runner = self.run_job(path)
        self.assertEqual(record["completed"], 2)
        self.assertEqual(len(self.rows(path)), 2)
        decompiled = [options["address"] for action, options in runner.calls if action == "decompile"]
        self.assertEqual(decompiled, ["0x401010"])

    def test_caller_chosen_output_path(self):
        chosen = self.root / "chosen" / "functions.jsonl"
        chosen.parent.mkdir()
        path = self.make(out=str(chosen))
        record, _ = self.run_job(path)
        self.assertEqual(record["state"], "done")
        self.assertEqual(len(chosen.read_text().splitlines()), 2)
        with self.assertRaisesRegex(ValueError, "absolute"):
            exporting.normalized({"out": "relative.jsonl"})

    def test_regex_and_address_range_filters(self):
        record, runner = self.run_job(self.make(regex="^sec"))
        self.assertEqual([row["key"] for row in self.rows(exporting.job_path(self.settings, record["id"]))], ["0x401010"])
        record, runner = self.run_job(self.make(start="0x401000", end="0x401008"))
        self.assertEqual([row["key"] for row in self.rows(exporting.job_path(self.settings, record["id"]))], ["0x401000"])
        self.assertTrue(record["complete"])
        self.assertEqual(runner.calls[0][1]["cursor"], "0x401000")
        with self.assertRaisesRegex(ValueError, "end precedes"):
            exporting.normalized({"start": "0x2000", "end": "0x1000"})

    def test_cancel_is_observed_between_functions(self):
        path = self.make()
        actual_update = exporting.update
        def cancel_after_row(path, **changes):
            result = actual_update(path, **changes)
            if str(changes.get("stage", "")).startswith("exporting "):
                actual_update(path, cancel_requested=True, state="cancelling")
            return result
        with patch("hydralysis.export_worker.update", side_effect=cancel_after_row):
            record, runner = self.run_job(path)
        self.assertEqual(record["state"], "cancelled")
        self.assertEqual(len(self.rows(path)), 1)
        self.assertEqual(sum(action == "decompile" for action, _ in runner.calls), 1)

    def test_the_header_names_the_lineage_and_generation_and_a_new_generation_refuses_the_resume(self):
        selected = targets.resolve(self.settings, "fixture")
        with patch("hydralysis.exporting.targets.resolve", return_value={**selected, "lineage": {"id": "L-0123abcd", "origin_key": selected["key"],
                                                                                              "generation": 1, "cid": "c-00000001"}}):
            _, header = exporting.provenance(self.settings, "fixture")
        self.assertEqual((header["lineage"], header["generation"]), ("L-0123abcd", 1))
        for key in ("master_revision", "engine_release"):
            self.assertIn(key, header)
        path = self.make()
        record, _ = self.run_job(path)
        self.assertNotIn("lineage", record["provenance"])  # a target with no commit has no lineage in its header
        flipped = {**record["provenance"], "lineage": "L-0123abcd", "generation": 1, "master_revision": "rev-gen1"}
        with patch("hydralysis.exporting.provenance", return_value=(self.project, flipped)), patch("hydralysis.exporting._launch") as launch, \
                self.assertRaisesRegex(ValueError, "changed; resume refused"):
            exporting.start(self.settings, "fixture", {"resume": record["id"]})
        launch.assert_not_called()
        for key, value in (("generation", 2), ("lineage", "L-ffffffff"), ("engine_release", "12.3-hydra.9")):
            moved = {**record["provenance"], "lineage": "L-0123abcd", "generation": 1, key: value}
            with self.subTest(changed=key), patch("hydralysis.exporting.provenance", return_value=(self.project, moved)), \
                    patch("hydralysis.exporting._launch"), self.assertRaisesRegex(ValueError, "resume refused"):
                exporting.start(self.settings, "fixture", {"resume": record["id"]})

    def test_resume_refuses_changed_source_and_preserves_output(self):
        path = self.make()
        record, _ = self.run_job(path)
        output = Path(record["output_path"])
        before = output.read_bytes()
        self.analysis.write_bytes(b"new saved analysis")
        self.revision = "rev-2"
        with patch("hydralysis.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "changed"):
            exporting.start(self.settings, "fixture", {"resume": record["id"]})
        launch.assert_not_called()
        self.assertEqual(output.read_bytes(), before)

    def test_torn_jsonl_resume_refuses_without_truncating_or_launching(self):
        path = self.make()
        record, _ = self.run_job(path)
        output = Path(record["output_path"])
        with output.open("ab") as handle:
            handle.write(b'{"torn":')
        before = output.read_bytes()
        with patch("hydralysis.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "torn"):
            exporting.start(self.settings, "fixture", {"resume": record["id"]})
        launch.assert_not_called()
        self.assertEqual(output.read_bytes(), before)

    def test_resume_cannot_take_a_user_supplied_cursor_or_change_options(self):
        path = self.make()
        record = read_json(path)
        for extra in ({"cursor": "0xdead"}, {"limit": 1}, {"mode": "types"}):
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "cannot change"):
                exporting.start(self.settings, "fixture", {"resume": record["id"], **extra})

    def test_duplicate_active_start_returns_existing_job(self):
        with patch("hydralysis.exporting._launch", side_effect=lambda path, record, settings: record) as launch:
            first = exporting.start(self.settings, "fixture", {})
            second = exporting.start(self.settings, "fixture", {})
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["reused"])
        self.assertEqual(launch.call_count, 1)

    def test_dead_worker_is_reported_interrupted_without_losing_progress(self):
        path = self.make()
        record = exporting.update(path, state="running", queued_at=time.time() - 10, worker_pid=555, worker_started_ms=77)
        with patch("hydralysis.exporting.process_start_ms", return_value=0):
            status = exporting.status(self.settings, record["id"])
        self.assertEqual(status["state"], "interrupted")
        self.assertIn("resume", status["error"])

    def test_types_mode_streams_inspected_types(self):
        path = self.make(mode="types")
        record, _ = self.run_job(path)
        self.assertTrue(record["complete"])
        self.assertEqual(self.rows(path)[0]["key"], "/Sample")
        self.assertEqual(self.rows(path)[0]["result"]["type"]["path"], "/Sample")

    def test_nested_type_truncation_is_not_mistaken_for_complete_data(self):
        self.assertTrue(export_worker.partial({"type": {"fields": [{"type": {"truncated": True}}]}}))
        self.assertFalse(export_worker.partial({"type": {"fields": [], "truncated": False}}))

    def test_queued_cancel_does_not_create_imports_or_query_runner(self):
        path = self.make()
        exporting.update(path, state="cancelling", cancel_requested=True)
        with patch("hydralysis.export_worker.imports") as imports, patch("hydralysis.export_worker.QueryRunner") as runner:
            export_worker.run(path, "test", runner_factory=runner)
        self.assertEqual(read_json(path)["state"], "cancelled")
        self.assertIn("finished_at", read_json(path))
        imports.assert_not_called()
        runner.assert_not_called()

    def test_nonobject_options_are_rejected_before_source_access(self):
        for options in ([], [["mode", "types"]], "decompile"):
            with self.subTest(options=options), patch("hydralysis.exporting.provenance") as source, self.assertRaisesRegex(ValueError, "object"):
                exporting.start(self.settings, "fixture", options)
            source.assert_not_called()

    def test_resuming_completed_valid_output_does_not_launch_again(self):
        path = self.make(limit=2)
        record, _ = self.run_job(path)
        with patch("hydralysis.exporting._launch") as launch:
            resumed = exporting.start(self.settings, "fixture", {"resume": record["id"]})
        launch.assert_not_called()
        self.assertTrue(resumed["reused"])
        self.assertTrue(resumed["complete"])

    def test_interrupted_replay_refuses_changed_c_with_unchanged_row_hash(self):
        path = self.make()
        record, _ = self.run_job(path)
        exporting.update(path, state="interrupted")
        output = Path(record["output_path"])
        rows = self.rows(path)
        rows[0]["result"]["c"] = "int changed(void) { return 99; }\n"
        output.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        before = output.read_bytes()
        with patch("hydralysis.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "C SHA-256 mismatch"):
            exporting.start(self.settings, "fixture", {"resume": record["id"]})
        launch.assert_not_called()
        self.assertEqual(output.read_bytes(), before)

    def test_completed_reuse_refuses_json_changes_with_valid_per_row_c_hashes(self):
        path = self.make()
        record, _ = self.run_job(path)
        output = Path(record["output_path"])
        rows = self.rows(path)
        rows[0]["result"]["function"]["name"] = "changed_label"
        output.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        before = output.read_bytes()
        for options in ({"resume": record["id"]}, {}):
            with self.subTest(options=options), patch("hydralysis.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "output SHA-256 mismatch"):
                exporting.start(self.settings, "fixture", options)
            launch.assert_not_called()
            self.assertEqual(output.read_bytes(), before)

    def test_completed_reuse_refuses_changed_imports_with_matching_build(self):
        path = self.make()
        record, _ = self.run_job(path)
        imports = Path(record["imports_path"])
        saved = read_json(imports)
        saved["source"] = "changed source while retaining the same build hash"
        imports.write_text(json.dumps(saved), encoding="utf-8")
        before = imports.read_bytes()
        with patch("hydralysis.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "imports SHA-256 mismatch"):
            exporting.start(self.settings, "fixture", {"resume": record["id"]})
        launch.assert_not_called()
        self.assertEqual(imports.read_bytes(), before)

    def test_interrupted_replay_validates_import_json_and_full_build(self):
        for content, message in (("[]", "JSON object"), ("{broken", "Expecting property"),
                                 (json.dumps({"build_sha256": "b" * 64, "state": "done", "imports": []}), "another build")):
            with self.subTest(content=content):
                path = self.make(limit=1)
                record, _ = self.run_job(path)
                exporting.update(path, state="interrupted")
                imports = Path(record["imports_path"])
                imports.write_text(content, encoding="utf-8")
                before = imports.read_bytes()
                with patch("hydralysis.exporting._launch") as launch, self.assertRaisesRegex(ValueError, message):
                    exporting.start(self.settings, "fixture", {"resume": record["id"]})
                launch.assert_not_called()
                self.assertEqual(imports.read_bytes(), before)

    def test_non_c_modes_replay_without_inventing_c_hashes(self):
        for mode in ("types", "functions"):
            with self.subTest(mode=mode):
                path = self.make(mode=mode)
                record, _ = self.run_job(path)
                self.assertTrue(all("c_sha256" not in row for row in self.rows(path)))
                with patch("hydralysis.exporting._launch") as launch:
                    reused = exporting.start(self.settings, "fixture", {"resume": record["id"]})
                launch.assert_not_called()
                self.assertTrue(reused["reused"])

    def test_body_hash_is_labelled_raw_bytes_and_missing_ranges_are_explicit(self):
        image = Mock()
        image.read_rva.return_value = b"\x90" * 5
        response = {"image_base": "0x400000", "function": {"body": ["[00401000, 00401004]"]}}
        result = export_worker.body_hash(response, image)
        self.assertEqual(len(result["body_sha256"]), 64)
        self.assertIn("raw file-backed", result["body_hash_method"])
        image.read_rva.assert_called_with(0x1000, 5)
        response["function"]["body_truncated"] = True
        self.assertIsNone(export_worker.body_hash(response, image)["body_sha256"])

    # ---- Z6: the snapshot at export start, parity, kill and resume, cancel ----

    def corpus(self, count):
        return [{"address": hex(0x401000 + 16 * index), "name": "f%d" % index,
                 "body": ["[%08x, %08x]" % (0x401000 + 16 * index, 0x401004 + 16 * index)], "body_truncated": False}
                for index in range(count)]

    def resume_in_process(self, record, **kwargs):
        """Resume through exporting.start, running the worker in this process in place of a launched one."""
        def launch(path, current, settings):
            exporting.update(path, state="queued", generation="test", cancel_requested=False)
            return current
        with patch("hydralysis.exporting._launch", side_effect=launch):
            exporting.start(self.settings, "fixture", {"resume": record["id"]})
        return self.run_job(exporting.job_path(self.settings, record["id"]), **kwargs)

    def test_the_snapshot_fixes_the_expected_count_and_parity_is_kept_apart_from_all_succeeded(self):
        path = self.make()
        record, _ = self.run_job(path, rows=self.corpus(7))
        self.assertEqual(record["parity"]["expected"], 7)
        self.assertEqual((record["parity"]["written"], record["parity"]["failed"]), (7, 0))
        self.assertTrue(record["parity"]["ok"] and record["all_succeeded"] and record["complete"])
        snapshot = read_json(path.parent / "snapshot.json")
        self.assertEqual((snapshot["count"], len(snapshot["keys"])), (7, 7))
        self.assertEqual(record["snapshot_sha256"], snapshot["keys_sha256"])
        failing = self.make(contains="f")
        failed, _ = self.run_job(failing, rows=self.corpus(7), failing=self.corpus(7)[3]["address"])
        # One known failure: every expected row is accounted for (written + failed == expected) but not all succeeded.
        self.assertEqual((failed["parity"]["written"], failed["parity"]["failed"], failed["parity"]["expected"]), (6, 1, 7))
        self.assertTrue(failed["parity"]["ok"])
        self.assertFalse(failed["all_succeeded"])
        self.assertFalse(failed["complete"])

    def test_parity_names_missing_and_unexpected_rows(self):
        snapshot = {"keys": ["a", "b", "c"], "count": 3}
        progress = {"keys": {"a", "z"}, "succeeded": 2, "failed": 0}
        result = export_worker.parity(snapshot, {"limit": 100}, progress)
        self.assertFalse(result["ok"])
        self.assertEqual((result["expected"], result["missing"], result["unexpected"]), (3, 2, 1))
        full = export_worker.parity(snapshot, {"limit": 2}, {"keys": {"a", "b"}, "succeeded": 1, "failed": 1})
        self.assertTrue(full["ok"])  # a limit of 2 expects the first two keys of the snapshot

    def test_a_limit_below_the_corpus_expects_the_limit(self):
        path = self.make(limit=3)
        record, _ = self.run_job(path, rows=self.corpus(8))
        self.assertEqual((record["parity"]["expected"], record["parity"]["snapshot_count"], record["completed"]), (3, 8, 3))
        self.assertTrue(record["parity"]["ok"])
        self.assertTrue(record["limited"])

    def test_a_corpus_that_changes_after_the_snapshot_pauses_the_export(self):
        class Drifting(FakeRunner):
            def query(self, target, action, **options):
                if action == "functions" and sum(call[0] == "functions" for call in self.calls) == 1:
                    # the second enumeration (the export's own, after the snapshot) sees one more function
                    self.rows.append({"address": "0x409000", "name": "late", "body": [], "body_truncated": False})
                return super().query(target, action, **options)
        path = self.make()
        with patch("hydralysis.export_worker.Image", return_value=None), redirect_stdout(io.StringIO()):
            export_worker.run(path, "test", runner_factory=lambda settings: Drifting(settings, rows=self.corpus(3)))
        record = read_json(path)
        self.assertEqual(record["state"], "paused")
        self.assertIn("snapshot does not list", record["error"])
        self.assertFalse(record["all_succeeded"])

    def test_a_kill_at_half_and_a_resume_equal_an_uninterrupted_run(self):
        corpus = self.corpus(20)
        whole = self.make()
        done, _ = self.run_job(whole, rows=corpus)
        self.assertEqual(done["state"], "done")

        class Killed(BaseException):
            pass

        class Dies(FakeRunner):
            def query(self, target, action, **options):
                if action == "decompile" and sum(call[0] == "decompile" for call in self.calls) >= 10:
                    raise Killed()
                return super().query(target, action, **options)
        path = self.make(timeout_s=31)  # a distinct job (different options), same corpus
        with patch("hydralysis.export_worker.Image", return_value=None), redirect_stdout(io.StringIO()):
            with self.assertRaises(Killed):
                export_worker.run(path, "test", runner_factory=lambda settings: Dies(settings, rows=corpus))
        killed = read_json(path)
        self.assertEqual(killed["state"], "running")  # nothing marked the end: a kill
        self.assertEqual(len(self.rows(path)), 10)
        snapshot_bytes = (path.parent / "snapshot.json").read_bytes()
        exporting.update(path, state="interrupted")
        resumed, _ = self.resume_in_process(killed, rows=corpus)
        self.assertEqual(resumed["state"], "done")
        self.assertEqual((path.parent / "snapshot.json").read_bytes(), snapshot_bytes)  # the snapshot is not retaken
        self.assertEqual(resumed["parity"]["expected"], 20)
        self.assertTrue(resumed["parity"]["ok"] and resumed["complete"])

        def normal(job_path):
            record = read_json(job_path)
            text = Path(record["output_path"]).read_text(encoding="utf-8")
            return text.replace(record["id"], "JOB").replace('"timeout_s": 31', '"timeout_s": 30')
        # Row for row, the resumed export is the uninterrupted one apart from the job id and the timeout that told them apart.
        first = [json.loads(line) for line in normal(path).splitlines()]
        second = [json.loads(line) for line in normal(whole).splitlines()]
        for rows in (first, second):
            for row in rows:
                row.pop("provenance")
        self.assertEqual(first, second)
        self.assertEqual(resumed["succeeded"], done["succeeded"])

    def test_a_kill_during_the_snapshot_resumes_by_taking_it_again(self):
        class Killed(BaseException):
            pass

        class Dies(FakeRunner):
            def query(self, target, action, **options):
                if action == "functions":
                    raise Killed()
                return super().query(target, action, **options)
        path = self.make()
        with patch("hydralysis.export_worker.Image", return_value=None), redirect_stdout(io.StringIO()):
            with self.assertRaises(Killed):
                export_worker.run(path, "test", runner_factory=lambda settings: Dies(settings, rows=self.corpus(4)))
        self.assertFalse((path.parent / "snapshot.json").exists())
        exporting.update(path, state="interrupted")
        resumed, _ = self.resume_in_process(read_json(path), rows=self.corpus(4))
        self.assertEqual((resumed["state"], resumed["parity"]["expected"]), ("done", 4))

    def test_resume_refuses_a_missing_or_edited_snapshot(self):
        path = self.make()
        record, _ = self.run_job(path, rows=self.corpus(5))
        snapshot = path.parent / "snapshot.json"
        original = snapshot.read_bytes()
        edited = json.loads(original)
        edited["keys"] = edited["keys"][:-1]
        edited["count"] = len(edited["keys"])
        for label, change in (("edited", lambda: snapshot.write_text(json.dumps(edited))),
                              ("missing", lambda: snapshot.unlink())):
            with self.subTest(case=label):
                change()
                with patch("hydralysis.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "snapshot"):
                    exporting.start(self.settings, "fixture", {"resume": record["id"]})
                launch.assert_not_called()
                snapshot.write_bytes(original)
        with patch("hydralysis.exporting._launch") as launch:
            self.assertTrue(exporting.start(self.settings, "fixture", {"resume": record["id"]})["reused"])
        launch.assert_not_called()

    def test_job_json_is_not_rewritten_for_every_row(self):
        path = self.make()
        writes = []
        actual = export_worker.update

        def counting(path, **changes):
            writes.append(str(changes.get("stage", "")))
            return actual(path, **changes)
        with patch("hydralysis.export_worker.update", side_effect=counting):
            record, _ = self.run_job(path, rows=self.corpus(40))
        self.assertEqual(record["succeeded"], 40)
        self.assertLessEqual(sum(stage.startswith("exporting ") for stage in writes), 3)

    def test_cancel_latency_is_one_bounded_query(self):
        import threading

        class Slow(FakeRunner):
            def query(self, target, action, **options):
                if action == "decompile":
                    time.sleep(0.25)
                return super().query(target, action, **options)
        path = self.make()

        def work():
            with patch("hydralysis.export_worker.Image", return_value=None), redirect_stdout(io.StringIO()):
                export_worker.run(path, "test", runner_factory=lambda settings: Slow(settings, rows=self.corpus(40)))
        thread = threading.Thread(target=work)
        thread.start()
        deadline = time.monotonic() + 30
        output = Path(read_json(path)["output_path"])
        while time.monotonic() < deadline and not (output.exists() and len(output.read_text().splitlines()) >= 2):
            time.sleep(0.02)
        started = time.monotonic()
        exporting.update(path, cancel_requested=True, state="cancelling")
        thread.join(30)
        latency = time.monotonic() - started
        self.assertEqual(read_json(path)["state"], "cancelled")
        self.assertLess(latency, 3.0)  # one 0.25 s query plus the bookkeeping, nowhere near the 40 rows
        self.assertLess(len(self.rows(path)), 10)

    def test_cancel_while_paused_closes_the_job_and_the_job_can_still_resume(self):
        path = self.make()
        record, _ = self.run_job(path, rows=self.corpus(5), busy=True)
        self.assertEqual(record["state"], "paused")
        result = exporting.cancel(self.settings, record["id"], self.token)
        self.assertEqual(result["state"], "cancelled")
        self.assertFalse(result["cancel_requested"])
        resumed, _ = self.resume_in_process(result, rows=self.corpus(5))
        self.assertEqual((resumed["state"], resumed["parity"]["expected"]), ("done", 5))

    def test_cancel_of_a_finished_job_changes_nothing(self):
        path = self.make()
        record, _ = self.run_job(path, rows=self.corpus(2))
        self.assertEqual(exporting.cancel(self.settings, record["id"], self.token)["state"], "done")


if __name__ == "__main__":
    unittest.main()
