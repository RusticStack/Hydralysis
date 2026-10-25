import hashlib
import io
import json
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from rusticre import exporting
from rusticre import export_worker
from rusticre.backends import read_json


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
        self.temp = tempfile.TemporaryDirectory()
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
        self.settings = {"root": str(self.root / "root"), "ghidra_dir": str(self.root / "ghidra"), "targets": {"fixture": self.project}}

    def make(self, **options):
        with patch("rusticre.exporting._launch", side_effect=lambda path, record, settings: record):
            result = exporting.start(self.settings, "fixture", options)
        path = exporting.job_path(self.settings, result["id"])
        exporting.update(path, generation="test", state="interrupted")
        return path

    def run_job(self, path, **kwargs):
        instances = []
        def factory(settings):
            runner = FakeRunner(settings, **kwargs)
            instances.append(runner)
            return runner
        with patch("rusticre.export_worker.Image", return_value=None), redirect_stdout(io.StringIO()):
            export_worker.run(path, "test", runner_factory=factory)
        return read_json(path), instances[0]

    def rows(self, path):
        output = Path(read_json(path)["output_path"])
        return [json.loads(line) for line in output.read_text().splitlines()]

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
        with patch("rusticre.export_worker.time.sleep"):
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
        with patch("rusticre.export_worker.update", side_effect=crash), self.assertRaises(KeyboardInterrupt):
            self.run_job(path)
        self.assertEqual(read_json(path)["completed"], 0)
        self.assertEqual(len(self.rows(path)), 1)
        exporting.update(path, state="interrupted")
        record, runner = self.run_job(path)
        self.assertEqual(record["completed"], 2)
        self.assertEqual(len(self.rows(path)), 2)
        decompiled = [options["address"] for action, options in runner.calls if action == "decompile"]
        self.assertEqual(decompiled, ["0x401010"])

    def test_cancel_is_observed_between_functions(self):
        path = self.make()
        actual_update = exporting.update
        def cancel_after_row(path, **changes):
            result = actual_update(path, **changes)
            if str(changes.get("stage", "")).startswith("exporting "):
                actual_update(path, cancel_requested=True, state="cancelling")
            return result
        with patch("rusticre.export_worker.update", side_effect=cancel_after_row):
            record, runner = self.run_job(path)
        self.assertEqual(record["state"], "cancelled")
        self.assertEqual(len(self.rows(path)), 1)
        self.assertEqual(sum(action == "decompile" for action, _ in runner.calls), 1)

    def test_resume_refuses_changed_source_and_preserves_output(self):
        path = self.make()
        record, _ = self.run_job(path)
        output = Path(record["output_path"])
        before = output.read_bytes()
        self.analysis.write_bytes(b"new saved analysis")
        with patch("rusticre.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "changed"):
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
        with patch("rusticre.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "torn"):
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
        with patch("rusticre.exporting._launch", side_effect=lambda path, record, settings: record) as launch:
            first = exporting.start(self.settings, "fixture", {})
            second = exporting.start(self.settings, "fixture", {})
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["reused"])
        self.assertEqual(launch.call_count, 1)

    def test_dead_worker_is_reported_interrupted_without_losing_progress(self):
        path = self.make()
        record = exporting.update(path, state="running", queued_at=time.time() - 10, worker_pid=555, worker_started_ms=77)
        with patch("rusticre.exporting.process_start_ms", return_value=0):
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
        with patch("rusticre.export_worker.imports") as imports, patch("rusticre.export_worker.QueryRunner") as runner:
            export_worker.run(path, "test", runner_factory=runner)
        self.assertEqual(read_json(path)["state"], "cancelled")
        self.assertIn("finished_at", read_json(path))
        imports.assert_not_called()
        runner.assert_not_called()

    def test_nonobject_options_are_rejected_before_source_access(self):
        for options in ([], [["mode", "types"]], "decompile"):
            with self.subTest(options=options), patch("rusticre.exporting.provenance") as source, self.assertRaisesRegex(ValueError, "object"):
                exporting.start(self.settings, "fixture", options)
            source.assert_not_called()

    def test_resuming_completed_valid_output_does_not_launch_again(self):
        path = self.make(limit=2)
        record, _ = self.run_job(path)
        with patch("rusticre.exporting._launch") as launch:
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
        with patch("rusticre.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "C SHA-256 mismatch"):
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
            with self.subTest(options=options), patch("rusticre.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "output SHA-256 mismatch"):
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
        with patch("rusticre.exporting._launch") as launch, self.assertRaisesRegex(ValueError, "imports SHA-256 mismatch"):
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
                with patch("rusticre.exporting._launch") as launch, self.assertRaisesRegex(ValueError, message):
                    exporting.start(self.settings, "fixture", {"resume": record["id"]})
                launch.assert_not_called()
                self.assertEqual(imports.read_bytes(), before)

    def test_non_c_modes_replay_without_inventing_c_hashes(self):
        for mode in ("types", "functions"):
            with self.subTest(mode=mode):
                path = self.make(mode=mode)
                record, _ = self.run_job(path)
                self.assertTrue(all("c_sha256" not in row for row in self.rows(path)))
                with patch("rusticre.exporting._launch") as launch:
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


if __name__ == "__main__":
    unittest.main()
