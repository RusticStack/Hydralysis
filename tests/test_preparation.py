import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from rusticre import preparation as prep
from rusticre.backends import sha256, write_json
from rusticre.preparation_worker import build_analysis_command, run


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.exe = self.root / "fresh.exe"
        self.exe.write_bytes(b"owned executable fixture")
        self.settings = {"root": str(self.root / "data"), "ghidra_dir": str(self.root / "engine"), "java_home": str(self.root / "jdk")}

    def prepare(self, **kwargs):
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), patch("rusticre.preparation.subprocess.Popen", return_value=Mock(pid=1234)), patch("rusticre.preparation.process_start_ms", return_value=123456):
            return prep.prepare(self.settings, str(self.exe), target="fresh", install=False, **kwargs)

    def test_returns_durable_job_immediately_and_deduplicates_same_build(self):
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), patch("rusticre.preparation.subprocess.Popen", return_value=Mock(pid=1234)) as launch, patch("rusticre.preparation.process_start_ms", return_value=123456):
            first = prep.prepare(self.settings, str(self.exe), "fresh", install=False)
            second = prep.prepare(self.settings, str(self.exe), "another-alias", install=False)
        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(launch.call_count, 1)
        self.assertTrue(prep.job_path(self.settings, first["job_id"]).is_file())
        self.assertFalse(prep.registry(self.settings))
        self.assertEqual(second["aliases"], ["another-alias", "fresh"])

    def test_completed_hash_reuses_saved_analysis_and_registers_alias_without_launch(self):
        record = self.prepare()
        project = self.root / "saved"
        project.mkdir()
        (project / "analysis.gpr").write_text("saved")
        (project / "analysis.rep").mkdir()
        item = {"dir": str(project), "name": "analysis", "program": "fresh.exe", "sha256": sha256(self.exe), "exe": str(self.exe)}
        prep.update_job(prep.job_path(self.settings, record["job_id"]), state="done", finished_at=time.time(), project=item)
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), patch("rusticre.preparation.subprocess.Popen") as launch:
            result = prep.prepare(self.settings, str(self.exe), "second", install=False)
        launch.assert_not_called()
        self.assertTrue(result["reused"])
        self.assertEqual(prep.registry(self.settings)["second"]["sha256"], item["sha256"])

    def test_cancel_is_a_durable_request_and_does_not_kill_arbitrary_pid(self):
        record = self.prepare()
        result = prep.cancel(self.settings, record["job_id"])
        self.assertEqual(result["state"], "cancelling")
        self.assertTrue((prep.job_path(self.settings, record["job_id"]).parent / "cancel.request").exists())
        self.assertFalse(prep.registry(self.settings))

    def test_dead_worker_is_interrupted_not_successful(self):
        record = self.prepare()
        path = prep.job_path(self.settings, record["job_id"])
        prep.update_job(path, created_at=time.time() - 60)
        with patch("rusticre.preparation.process_start_ms", return_value=0):
            result = prep.status(self.settings, record["job_id"])
        self.assertEqual(result["state"], "interrupted")
        self.assertFalse(prep.registry(self.settings))

    def test_unconfirmed_cleanup_reserves_build_and_never_starts_another_import(self):
        record = self.prepare()
        path = prep.job_path(self.settings, record["job_id"])
        prep.update_job(path, state="cleanup_failed", headless_pid=4321, headless_started_ms=987654)
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), patch("rusticre.preparation.subprocess.Popen") as launch:
            with self.assertRaisesRegex(ValueError, "cleanup is unconfirmed"):
                prep.prepare(self.settings, str(self.exe), "new-alias", install=False)
        launch.assert_not_called()
        self.assertFalse(prep.registry(self.settings))

    def test_orphan_worker_with_live_headless_tree_is_not_retryable_interrupted(self):
        record = self.prepare()
        path = prep.job_path(self.settings, record["job_id"])
        prep.update_job(path, created_at=time.time() - 60, headless_pid=4321, headless_started_ms=987654)
        with patch("rusticre.preparation.process_start_ms", side_effect=lambda pid: 987654 if pid == 4321 else 0):
            result = prep.status(self.settings, record["job_id"])
        self.assertEqual(result["state"], "cleanup_failed")
        self.assertIn("still live", result["error"])

    def test_cancel_cleanup_refuses_recycled_pid_and_preserves_reservation(self):
        record = self.prepare()
        path = prep.job_path(self.settings, record["job_id"])
        prep.update_job(path, state="cleanup_failed", headless_pid=4321, headless_started_ms=987654)
        with patch("rusticre.preparation.process_start_ms", return_value=987655), patch("rusticre.preparation.subprocess.run") as kill:
            with self.assertRaisesRegex(RuntimeError, "cannot verify"):
                prep.cancel(self.settings, record["job_id"])
        kill.assert_not_called()
        self.assertEqual(prep.status(self.settings, record["job_id"])["state"], "cleanup_failed")

    @unittest.skipUnless(os.name == "nt", "Windows owned-tree cleanup retry")
    def test_cancel_cleanup_retries_only_verified_identity_and_confirms_exit(self):
        record = self.prepare()
        path = prep.job_path(self.settings, record["job_id"])
        prep.update_job(path, state="cleanup_failed", headless_pid=4321, headless_started_ms=987654)
        with patch("rusticre.preparation.process_start_ms", side_effect=[987654, 0, 0]), patch("rusticre.preparation.subprocess.run", return_value=Mock(returncode=0)) as kill:
            result = prep.cancel(self.settings, record["job_id"])
        self.assertEqual(result["state"], "cancelled")
        self.assertTrue(result["cleanup_confirmed"])
        self.assertEqual(kill.call_args.args[0], ["taskkill.exe", "/PID", "4321", "/T", "/F"])

    def test_wrapper_preflight_blocks_before_backend_setup_or_launch(self):
        self.exe.write_bytes(b"MZwrapper fixture")
        observed = {"sha256": sha256(self.exe), "packing_status": "suspected", "analysis_warnings": ["known wrapper/packer indicator"]}
        image = SimpleNamespace(bits=32, sections=[SimpleNamespace(Name=b".bind\0")], fingerprint=lambda: observed)
        with patch("rusticre.pe.Image", return_value=image), patch("rusticre.preparation.inspect") as inspect, patch("rusticre.preparation.subprocess.Popen") as launch:
            result = prep.prepare(self.settings, str(self.exe))
        self.assertEqual(result["state"], "blocked")
        self.assertIn("needs_unwrapped_artifact", result["error"])
        inspect.assert_not_called()
        launch.assert_not_called()

    def test_install_jobs_are_component_scoped(self):
        with patch("rusticre.preparation.subprocess.Popen", return_value=Mock(pid=1234)), patch("rusticre.preparation.process_start_ms", return_value=123456):
            first = prep.start_install(self.settings, "analysis")
            duplicate = prep.start_install(self.settings, "analysis")
            runtime = prep.start_install(self.settings, "runtime")
        self.assertEqual(first["job_id"], duplicate["job_id"])
        self.assertNotEqual(first["job_id"], runtime["job_id"])
        self.assertEqual(runtime["component"], "runtime")

    def test_fast_worker_identity_is_not_replaced_by_venv_launcher_pid(self):
        def launched(command, **kwargs):
            path = Path(command[-1])
            prep.update_job(path, state="running", worker_pid=2222, worker_started_ms=999)
            return Mock(pid=1111)
        with patch("rusticre.preparation.subprocess.Popen", side_effect=launched), patch("rusticre.preparation.process_start_ms", return_value=123456):
            record = prep.start_install(self.settings, "analysis")
        self.assertEqual(record["worker_pid"], 2222)
        self.assertEqual(record["worker_started_ms"], 999)

    def test_analysis_command_imports_once_without_query_flags(self):
        command = build_analysis_command(self.settings, self.root / "project", self.exe, self.root / "verified.json", 3600)
        self.assertIn("-import", command)
        self.assertNotIn("-process", command)
        self.assertNotIn("-readOnly", command)
        self.assertNotIn("-noanalysis", command)
        self.assertIn("RusticPrepare.java", command)
        self.assertIn(sha256(self.exe), command)

    def test_plan_never_creates_job_registry_download_or_import(self):
        with patch("rusticre.preparation.inspect", return_value={"ready": False}), patch("rusticre.preparation.subprocess.Popen") as launch:
            result = prep.plan(self.settings, str(self.exe))
        launch.assert_not_called()
        self.assertEqual(result["state"], "planned")
        self.assertFalse(result["started"])
        self.assertTrue(result["would_import"])
        self.assertTrue(result["would_install"])
        self.assertFalse(Path(self.settings["root"]).exists())

    def test_manually_configured_analysis_is_never_reimported(self):
        self.settings["targets"] = {"known": {"dir": "saved", "name": "analysis", "program": "fresh.exe", "exe": str(self.exe)}}
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), patch("rusticre.preparation.subprocess.Popen") as launch:
            proposed = prep.plan(self.settings, str(self.exe), "known")
            result = prep.prepare(self.settings, str(self.exe), "known", install=False)
        self.assertFalse(proposed["would_import"])
        self.assertFalse(result["started"])
        self.assertEqual(result["state"], "configured")
        launch.assert_not_called()

    def test_legacy_configured_project_is_never_reimported(self):
        self.settings["projects"] = {"known": {"dir": "saved", "name": "analysis", "program": "fresh.exe", "exe": str(self.exe)}}
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), patch("rusticre.preparation.subprocess.Popen") as launch:
            result = prep.prepare(self.settings, str(self.exe), "known", install=False)
        self.assertEqual(result["state"], "configured")
        launch.assert_not_called()

    def test_cancelled_queued_setup_never_starts_installation(self):
        for component in ("analysis", "runtime"):
            with self.subTest(component=component), patch("rusticre.preparation.subprocess.Popen", return_value=Mock(pid=1234)), patch("rusticre.preparation.process_start_ms", return_value=123456):
                record = prep.start_install(self.settings, component)
            path = prep.job_path(self.settings, record["job_id"])
            prep.cancel(self.settings, record["job_id"])
            with patch("rusticre.preparation_worker.ensure") as setup_analysis, patch("rusticre.runtime.setup") as setup_runtime:
                run(path)
            setup_analysis.assert_not_called()
            setup_runtime.assert_not_called()
            self.assertEqual(prep.status(self.settings, record["job_id"])["state"], "cancelled")

    def test_dot_root_is_refused_before_any_job_or_launch(self):
        self.settings["root"] = str(self.root / ".hidden" / "data")
        with patch("rusticre.preparation.subprocess.Popen") as launch:
            with self.assertRaisesRegex(ValueError, "dot-prefixed"):
                prep.prepare(self.settings, str(self.exe), "fresh")
        self.assertFalse(Path(self.settings["root"]).exists())
        launch.assert_not_called()

    def test_default_or_new_alias_does_not_reimport_a_manually_named_build(self):
        self.settings["targets"] = {"existing-analysis": {"dir": "saved", "name": "analysis", "program": "fresh.exe", "exe": str(self.exe)}}
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), patch("rusticre.preparation.subprocess.Popen") as launch:
            proposed = prep.plan(self.settings, str(self.exe))
            result = prep.prepare(self.settings, str(self.exe), "another-agent-alias", install=False)
        self.assertFalse(proposed["would_import"])
        self.assertEqual(proposed["matching_configured_target"], "existing-analysis")
        self.assertFalse(result["started"])
        self.assertEqual(result["target"], "existing-analysis")
        self.assertEqual(result["requested_target"], "another-agent-alias")
        launch.assert_not_called()

    def test_worker_refuses_failed_analysis_and_preserves_diagnostics_without_registration(self):
        record = self.prepare()
        path = prep.job_path(self.settings, record["job_id"])
        with patch("rusticre.preparation_worker.ensure", return_value=self.settings), patch("rusticre.preparation_worker.subprocess.Popen", return_value=Mock(pid=4321, returncode=0, poll=Mock(return_value=0))):
            run(path)
        result = prep.status(self.settings, record["job_id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("did not verify", result["error"])
        self.assertFalse(prep.registry(self.settings))

    def test_worker_metadata_failure_cleans_owned_child_or_reserves_build(self):
        for cleanup_fails in (False, True):
            with self.subTest(cleanup_fails=cleanup_fails):
                record = self.prepare()
                path = prep.job_path(self.settings, record["job_id"])
                process = Mock(pid=4321, returncode=None, poll=Mock(return_value=None))
                failed = False

                def update(target, **changes):
                    nonlocal failed
                    if "headless_pid" in changes and not failed:
                        failed = True
                        raise OSError("fixture PID metadata write failure")
                    return prep.update_job(target, **changes)

                with patch("rusticre.preparation_worker.ensure", return_value=self.settings), \
                     patch("rusticre.preparation_worker.subprocess.Popen", return_value=process), \
                     patch("rusticre.preparation_worker.update_job", side_effect=update), \
                     patch("rusticre.preparation_worker.process_start_ms", return_value=987654), \
                     patch("rusticre.preparation_worker._terminate_owned_tree", side_effect=RuntimeError("fixture cleanup refused") if cleanup_fails else None) as cleanup:
                    run(path)
                cleanup.assert_called_once_with(process)
                result = prep.status(self.settings, record["job_id"])
                self.assertEqual(result["state"], "cleanup_failed" if cleanup_fails else "failed")
                self.assertIn("metadata write failure", result["error"])
                if cleanup_fails:
                    self.assertEqual(result["headless_pid"], 4321)
                    self.assertEqual(result["headless_started_ms"], 987654)
                self.assertFalse(prep.registry(self.settings))


if __name__ == "__main__":
    unittest.main()
