import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from rusticre.ghidra import GhidraJobError, GhidraRunner, _held, _release, ghidra_environment, ghidra_locked, build_command, launch_command

from support import workdir


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = workdir()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        master = root / "master"
        master.mkdir()
        (master / "client.gpr").write_bytes(b"")
        (master / "client.rep").mkdir()
        (master / "client.rep" / "analysis").write_bytes(b"saved analysis")
        (master / "unrelated.gpr").write_text("must not be copied")
        (root / "Broken.java").write_text("// fixture script")
        (root / "Slow.java").write_text("// fixture script")
        self.project = {"dir": str(master), "name": "client", "program": "test.exe", "scripts": str(root), "sha256": "0" * 64}
        self.runner = GhidraRunner({"root": str(root / "runs"), "targets": {"test": self.project}, "ghidra_dir": str(root)})

    def claim(self):
        directory = self.runner._claim("test", self.project, "lane")
        self.addCleanup(_release, os.path.join(directory, ".rusticre.lock"))
        return Path(directory)

    def test_claim_locks_before_copy_and_copies_only_named_project(self):
        original = self.runner._ensure

        def ensure(directory, project):
            self.assertTrue(_held(os.path.join(directory, ".rusticre.lock")))
            original(directory, project)

        with patch.object(self.runner, "_ensure", side_effect=ensure):
            lane = self.claim()
        self.assertTrue((lane / "client.rep" / "analysis").is_file())
        self.assertFalse((lane / "unrelated.gpr").exists())
        with self.assertRaisesRegex(ValueError, "busy"):
            self.runner._claim("test", self.project, "lane")

    def test_unknown_lane_is_preserved(self):
        lane = Path(self.runner.lanes_dir) / "test-lane"
        lane.mkdir()
        note = lane / "owner-note"
        note.write_text("keep")
        with self.assertRaisesRegex(ValueError, "refusing to replace"):
            self.runner._claim("test", self.project, "lane")
        self.assertEqual(note.read_text(), "keep")
        self.assertFalse(_held(str(lane / ".rusticre.lock")))

    def test_changed_source_is_refused(self):
        lane = self.claim()
        _release(str(lane / ".rusticre.lock"))
        source = Path(self.project["dir"]) / "client.rep" / "analysis"
        source.write_bytes(b"a new analysis result")
        with self.assertRaisesRegex(ValueError, "stale lane"):
            self.runner._claim("test", self.project, "lane")
        self.assertEqual((lane / "client.rep" / "analysis").read_bytes(), b"saved analysis")

    def test_source_change_during_copy_leaves_snapshot_untrusted(self):
        import shutil
        copy = shutil.copytree

        def changing_copy(source, destination):
            result = copy(source, destination)
            (Path(source) / "new-analysis").write_text("changed")
            return result

        with patch("rusticre.ghidra.shutil.copytree", side_effect=changing_copy):
            with self.assertRaisesRegex(ValueError, "source project changed"):
                self.runner._claim("test", self.project, "lane")
        lane = Path(self.runner.lanes_dir) / "test-lane"
        self.assertFalse((lane / ".rusticre-snapshot.json").exists())

    def test_both_ghidra_lock_markers_refuse_copy(self):
        for suffix in (".lock", ".lock~"):
            with self.subTest(suffix=suffix):
                marker = Path(self.project["dir"]) / ("client" + suffix)
                marker.touch()
                self.assertTrue(ghidra_locked(self.project["dir"], "client"))
                with self.assertRaisesRegex(ValueError, "master project is open"):
                    self.runner._claim("test", self.project, "lane")
                marker.unlink()

    def test_exit_zero_script_error_raises_with_complete_diagnostics(self):
        process = Mock(returncode=0)
        process.communicate.return_value = ("ERROR Error running script: Broken.java\n", "compile diagnostic\n")
        with patch("rusticre.ghidra.headless_path", return_value=str(Path(self.project["dir"]) / "client.gpr")), patch("rusticre.ghidra.subprocess.Popen", return_value=process) as launch:
            with self.assertRaises(GhidraJobError) as raised:
                self.runner.run("test", "Broken", [])
        error = raised.exception
        self.assertEqual(error.record["state"], "failed")
        self.assertIn("compile diagnostic", Path(error.log_path).read_text())
        self.assertEqual(json.loads(Path(error.record_path).read_text())["exit_code"], 0)
        command = error.record["command"]
        self.assertIn("-noanalysis", command)
        self.assertIn("-readOnly", command)
        self.assertLess(command.index("-preScript"), command.index("-postScript"))
        self.assertEqual(command[command.index("RusticGuard.java") + 1], "0" * 64)

    @unittest.skipUnless(os.name == "nt", "Windows batch argument regression")
    def test_launcher_handles_spaces_and_semicolon_script_paths(self):
        directory = Path(self.temp.name) / "Ghidra with spaces" / "support"
        directory.mkdir(parents=True)
        (directory / "analyzeHeadless.bat").write_text(
            '@echo off\n:loop\necho [%~1]\nshift\nif not "%~1"=="" goto loop\n'
        )
        scripts = r"F:\script one;F:\script two"
        command = build_command(str(directory.parent), r"F:\project with spaces", "sample", "sample.exe",
                                scripts, "Probe.java", ["argument with spaces"], "log", 4)
        result = subprocess.run(launch_command(command), capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[F:\\project with spaces]", result.stdout)
        self.assertIn("[" + scripts + "]", result.stdout)
        self.assertIn("[argument with spaces]", result.stdout)

    def test_timeout_waits_for_owned_tree_before_releasing_lane(self):
        process = Mock(pid=123, returncode=-1)
        process.communicate.side_effect = [subprocess.TimeoutExpired("ghidra", 1), ("partial output", "stderr")]

        def terminate(proc):
            lock = str(Path(self.runner.lanes_dir) / "test-lane" / ".rusticre.lock")
            self.assertTrue(_held(lock))

        with patch("rusticre.ghidra.headless_path", return_value=str(Path(self.project["dir"]) / "client.gpr")), patch("rusticre.ghidra.subprocess.Popen", return_value=process), patch("rusticre.ghidra._terminate_owned_tree", side_effect=terminate) as kill:
            with self.assertRaises(GhidraJobError) as raised:
                self.runner.run("test", "Slow", [], timeout_s=1, lane="lane")
        kill.assert_called_once_with(process)
        self.assertEqual(raised.exception.record["state"], "timeout")
        self.assertFalse(_held(str(Path(self.runner.lanes_dir) / "test-lane" / ".rusticre.lock")))

    def test_failed_cleanup_retains_lane_lease(self):
        process = Mock(pid=123)
        process.communicate.side_effect = subprocess.TimeoutExpired("ghidra", 1)
        lock = str(Path(self.runner.lanes_dir) / "test-lane" / ".rusticre.lock")
        self.addCleanup(_release, lock)
        with patch("rusticre.ghidra.headless_path", return_value=str(Path(self.project["dir"]) / "client.gpr")), patch("rusticre.ghidra.subprocess.Popen", return_value=process), patch("rusticre.ghidra._terminate_owned_tree", side_effect=RuntimeError("not confirmed")):
            with self.assertRaises(GhidraJobError) as raised:
                self.runner.run("test", "Slow", [], timeout_s=1, lane="lane")
        self.assertEqual(raised.exception.record["state"], "cleanup_failed")
        self.assertTrue(_held(lock))

    def test_job_list_orders_timestamps_not_random_ids(self):
        for name, timestamp in (("job-zz", 1), ("job-aa", 2)):
            record = {"job_id": name, "started_at": timestamp, "duration_s": 1}
            (Path(self.runner.jobs_dir) / (name + ".json")).write_text(json.dumps(record))
        self.assertTrue(self.runner.jobs().startswith("job-aa"))

    def test_process_environment_keeps_runtime_on_configured_storage(self):
        with patch.dict(os.environ, {"JAVA_TOOL_OPTIONS": "-Duser.option=kept", "GHIDRA_HEADLESS_JAVA_OPTIONS": "-Dheadless.option=kept"}):
            environment = ghidra_environment(self.runner.settings)
            self.assertEqual(os.environ["JAVA_TOOL_OPTIONS"], "-Duser.option=kept")
            self.assertEqual(environment["GHIDRA_HEADLESS_JAVA_OPTIONS"], "-Dheadless.option=kept")
        runtime = Path(self.runner.root) / "runtime"
        self.assertEqual(environment["TEMP"], str(runtime / "tmp"))
        options = environment["JAVA_TOOL_OPTIONS"]
        self.assertIn("-Duser.option=kept", options)
        for property_name in ("application.settingsdir", "application.cachedir", "application.tempdir", "java.io.tmpdir"):
            self.assertIn("-D" + property_name + "=", options)
        self.assertTrue((runtime / "cache").is_dir())

    def test_headless_option_injection_and_missing_scripts_fail_before_claim(self):
        with patch.object(self.runner, "_claim") as claim:
            for arguments in (["-import", "new.exe"], ["-deleteProject"], ["-overwrite"]):
                with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, "headless options"):
                    self.runner.run("test", "Broken", arguments)
            for script in ("../Broken.java", "missing", "-import"):
                with self.subTest(script=script), self.assertRaises(ValueError):
                    self.runner.run("test", script, [])
            claim.assert_not_called()

    def test_missing_hash_is_refused_before_claim(self):
        self.project.pop("sha256")
        with patch.object(self.runner, "_claim") as claim:
            with self.assertRaisesRegex(ValueError, "full sha256"):
                self.runner.run("test", "Broken", [])
            claim.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows batch launcher validation")
    def test_shell_metacharacters_are_refused_before_claim(self):
        with patch.object(self.runner, "_claim") as claim:
            for argument in ("&", "|", "%PATH%", "!value!", '"', "\n"):
                with self.subTest(argument=argument), self.assertRaisesRegex(ValueError, "shell metacharacters"):
                    self.runner.run("test", "Broken", [argument])
            claim.assert_not_called()
