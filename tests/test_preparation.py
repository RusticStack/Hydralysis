import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import fakehydra
from rusticre import preparation as prep
from rusticre import preparation_worker
from rusticre.backends import sha256

from support import workdir


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = workdir()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.exe = self.root / "fresh.exe"
        self.exe.write_bytes(b"owned executable fixture")
        self.settings = {"root": str(self.root / "data"), "hydra_dir": str(self.root / "engine"), "java_home": str(self.root / "jdk")}

    def launch(self, **kwargs):
        return patch("rusticre.preparation.proc.popen", **({"return_value": Mock(pid=1234)} | kwargs))

    def prepare(self, **kwargs):
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), self.launch(), \
                patch("rusticre.preparation.process_start_ms", return_value=123456):
            return prep.prepare(self.settings, str(self.exe), target="fresh", install=False, **kwargs)

    def test_returns_durable_job_immediately_and_deduplicates_same_build(self):
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), self.launch() as launch, \
                patch("rusticre.preparation.process_start_ms", return_value=123456):
            first = prep.prepare(self.settings, str(self.exe), "fresh", install=False)
            second = prep.prepare(self.settings, str(self.exe), "another-alias", install=False)
        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(launch.call_count, 1)
        self.assertFalse(prep.registry(self.settings))
        self.assertEqual(second["aliases"], ["another-alias", "fresh"])

    def test_completed_hash_reuses_saved_analysis_and_registers_alias_without_launch(self):
        record = self.prepare()
        gpr = self.root / "saved" / "analysis.gpr"
        gpr.parent.mkdir()
        gpr.write_text("saved")
        item = {"gpr": str(gpr), "program": "/fresh.exe", "sha256": sha256(self.exe), "exe": str(self.exe)}
        prep.update_job(prep.job_path(self.settings, record["job_id"]), state="done", finished_at=time.time(), project=item)
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), self.launch() as launch:
            result = prep.prepare(self.settings, str(self.exe), "second", install=False)
        launch.assert_not_called()
        self.assertTrue(result["reused"])
        self.assertEqual(prep.registry(self.settings)["second"]["sha256"], item["sha256"])

    def test_engines_are_not_installed_unless_asked(self):
        with patch("rusticre.preparation.inspect", return_value={"ready": False}), self.launch() as launch:
            with self.assertRaisesRegex(ValueError, "backend install"):
                prep.prepare(self.settings, str(self.exe), "fresh")
        launch.assert_not_called()

    def test_cancel_is_a_durable_request_and_does_not_kill_arbitrary_pid(self):
        record = self.prepare()
        result = prep.cancel(self.settings, record["job_id"])
        self.assertEqual(result["state"], "cancelling")
        self.assertTrue((prep.job_path(self.settings, record["job_id"]).parent / "cancel.request").exists())

    def test_dead_worker_is_interrupted_not_successful(self):
        record = self.prepare()
        path = prep.job_path(self.settings, record["job_id"])
        prep.update_job(path, created_at=time.time() - 60)
        with patch("rusticre.preparation.process_start_ms", return_value=0):
            result = prep.status(self.settings, record["job_id"])
        self.assertEqual(result["state"], "interrupted")
        self.assertFalse(prep.registry(self.settings))

    def test_wrapper_preflight_blocks_before_backend_setup_or_launch(self):
        self.exe.write_bytes(b"MZwrapper fixture")
        observed = {"sha256": sha256(self.exe), "packing_status": "suspected", "analysis_warnings": ["known wrapper/packer indicator"]}
        image = SimpleNamespace(bits=32, sections=[SimpleNamespace(Name=b".bind\0")], fingerprint=lambda: observed)
        with patch("rusticre.pe.Image", return_value=image), patch("rusticre.preparation.inspect") as inspect, self.launch() as launch:
            result = prep.prepare(self.settings, str(self.exe))
        self.assertEqual(result["state"], "blocked")
        self.assertIn("needs_unwrapped_artifact", result["error"])
        inspect.assert_not_called()
        launch.assert_not_called()

    def test_install_jobs_are_component_scoped(self):
        with self.launch(), patch("rusticre.preparation.process_start_ms", return_value=123456):
            first = prep.start_install(self.settings, "analysis")
            duplicate = prep.start_install(self.settings, "analysis")
            runtime = prep.start_install(self.settings, "runtime")
        self.assertEqual(first["job_id"], duplicate["job_id"])
        self.assertNotEqual(first["job_id"], runtime["job_id"])

    def test_fast_worker_identity_is_not_replaced_by_venv_launcher_pid(self):
        def launched(command, **kwargs):
            prep.update_job(Path(command[-1]), state="running", worker_pid=2222, worker_started_ms=999)
            return Mock(pid=1111)
        with patch("rusticre.preparation.proc.popen", side_effect=launched), patch("rusticre.preparation.process_start_ms", return_value=123456):
            record = prep.start_install(self.settings, "analysis")
        self.assertEqual(record["worker_pid"], 2222)

    def test_plan_never_creates_job_registry_download_or_import(self):
        with patch("rusticre.preparation.inspect", return_value={"ready": False}), self.launch() as launch:
            result = prep.plan(self.settings, str(self.exe), install=True)
        launch.assert_not_called()
        self.assertTrue(result["would_import"])
        self.assertTrue(result["would_install"])
        self.assertIn("adopt", result["reason"])
        self.assertFalse(Path(self.settings["root"]).exists())

    def test_configured_or_aliased_analysis_is_never_reimported(self):
        self.settings["targets"] = {"existing": {"gpr": "saved/analysis.gpr", "program": "fresh.exe", "exe": str(self.exe)}}
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), self.launch() as launch:
            proposed = prep.plan(self.settings, str(self.exe))
            known = prep.prepare(self.settings, str(self.exe), "existing")
            alias = prep.prepare(self.settings, str(self.exe), "another-agent-alias")
        self.assertFalse(proposed["would_import"])
        self.assertEqual(proposed["matching_target"], "existing")
        self.assertEqual(known["state"], "configured")
        self.assertEqual(alias["target"], "existing")
        launch.assert_not_called()

    def test_cancelled_queued_setup_never_starts_installation(self):
        for component in ("analysis", "runtime"):
            with self.subTest(component=component), self.launch(), patch("rusticre.preparation.process_start_ms", return_value=123456):
                record = prep.start_install(self.settings, component)
            path = prep.job_path(self.settings, record["job_id"])
            prep.cancel(self.settings, record["job_id"])
            with patch("rusticre.preparation_worker.ensure") as setup_analysis, patch("rusticre.runtime.setup") as setup_runtime:
                preparation_worker.run(path)
            setup_analysis.assert_not_called()
            setup_runtime.assert_not_called()
            self.assertEqual(prep.status(self.settings, record["job_id"])["state"], "cancelled")

    def test_dot_root_is_refused_before_any_job_or_launch(self):
        self.settings["root"] = str(self.root / ".hidden" / "data")
        with self.launch() as launch:
            with self.assertRaisesRegex(ValueError, "dot-prefixed"):
                prep.prepare(self.settings, str(self.exe), "fresh")
        launch.assert_not_called()


class WorkerTests(unittest.TestCase):
    """The import itself, against a fake engine."""

    def setUp(self):
        self.tmp = workdir()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.exe = self.root / "fresh.exe"
        self.exe.write_bytes(b"owned executable fixture")
        self.digest = sha256(self.exe)
        self.settings = {"root": str(self.root / "data"), "hydra_dir": "x", "hydra_client": "x", "java_home": "x"}
        self.daemon = fakehydra.reset()
        with patch("rusticre.preparation.inspect", return_value={"ready": True}), \
                patch("rusticre.preparation.proc.popen", return_value=Mock(pid=1)), \
                patch("rusticre.preparation.process_start_ms", return_value=1):
            self.record = prep.prepare(self.settings, str(self.exe), "fresh")
        self.path = prep.job_path(self.settings, self.record["job_id"])
        engine = fakehydra.FakeEngine

        def script(engine_self, script, program=None, args=(), **_):
            gpr = Path(args[0]) / (args[1] + ".gpr")
            self.daemon.add_project(gpr, {})
            return {"output": '{"created":true}\n', "mode": "none"}

        def send(engine_self, command, **fields):
            project = self.daemon.project_by_id(fields["project"])
            name = "/" + Path(fields["file"]).name
            project["programs"][name] = {"sha256": self.digest, "analyzed": self.analyzed, "functions": 3,
                                         "imageBase": "0x400000", "saved": {"marker": "", "names": {}}, "live": None,
                                         "writers": set()}
            engine_self.result = {"imported": True, "path": name, "key": project["id"] + ":" + name, "analysis": {}}
            return 1

        self.analyzed = True
        patches = [patch("rusticre.hydra.Engine", engine),
                   patch.object(engine, "_script", script, create=True),
                   patch.object(engine, "send", send, create=True),
                   patch.object(engine, "wait", lambda engine_self, rid, command="": engine_self.result, create=True),
                   patch.object(engine, "cancel", Mock(), create=True),
                   patch("rusticre.preparation_worker.ensure", side_effect=lambda settings, install, cancelled: settings),
                   patch("rusticre.preparation_worker.resolved", side_effect=lambda settings: settings)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_import_verifies_and_registers_every_alias(self):
        preparation_worker.run(self.path)
        result = prep.status(self.settings, self.record["job_id"])
        self.assertEqual(result["state"], "done", result.get("error"))
        registered = prep.registry(self.settings)["fresh"]
        self.assertEqual(registered["sha256"], self.digest)
        self.assertTrue(Path(registered["gpr"]).is_file())

    def test_unanalysed_result_is_refused_without_registration(self):
        self.analyzed = False
        preparation_worker.run(self.path)
        result = prep.status(self.settings, self.record["job_id"])
        self.assertEqual(result["state"], "failed")
        self.assertIn("did not verify", result["error"])
        self.assertFalse(prep.registry(self.settings))


if __name__ == "__main__":
    unittest.main()
