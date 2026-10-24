"""Exercise worker lifecycle without importing a binary or starting Ghidra."""

import hashlib
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from rusticre import query


class QueryWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        master = self.root / "master"
        master.mkdir()
        (master / "client.gpr").write_bytes(b"")
        (master / "client.rep").mkdir()
        self.analysis = master / "client.rep" / "analysis"
        self.analysis.write_bytes(b"already analysed")
        binary = self.root / "owned.exe"
        binary.write_bytes(b"a user-owned build")
        self.digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.project = {"dir": str(master), "name": "client", "program": "owned.exe", "exe": str(binary)}
        self.settings = {"root": str(self.root / "runs"), "ghidra_dir": "unused-ghidra",
                         "targets": {"test": self.project}, "query_workers": 2, "query_startup_s": 5}
        self.runner = query.QueryRunner(self.settings)
        self.alive = {}
        self.now = 0.0
        self.serial = 0
        self.processes = []
        self.requests = []
        self.launch_mode = "ready"
        self.response_mode = "ok"
        self.real_write = query._write
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("rusticre.query.launch_command", side_effect=lambda command: command))
        self.launch = self.stack.enter_context(patch("rusticre.query.subprocess.Popen", side_effect=self.launcher))
        self.stop = self.stack.enter_context(patch("rusticre.query._stop", side_effect=self.retire))
        self.stack.enter_context(patch("rusticre.query._identity", side_effect=lambda pid, started: self.alive.get((pid, started), False)))
        self.stack.enter_context(patch("rusticre.query._write", side_effect=self.mailbox))
        self.stack.enter_context(patch("rusticre.query.time.monotonic", side_effect=lambda: self.now))
        self.stack.enter_context(patch("rusticre.query.time.sleep", side_effect=self.sleep))
        self.stack.enter_context(patch("rusticre.query.uuid.uuid4", side_effect=self.uuid))
        self.snapshot = self.stack.enter_context(patch("rusticre.query.GhidraRunner.ensure_snapshot"))

    def uuid(self):
        self.serial += 1
        return SimpleNamespace(hex=("%012x" % self.serial) + "0" * 20)

    def sleep(self, seconds):
        self.now += seconds

    def retire(self, ready):
        self.alive.pop((ready.get("pid"), ready.get("started_ms")), None)

    def launcher(self, command, **kwargs):
        pid = 1000 + len(self.processes)
        started = 100000 + pid
        dead = self.launch_mode == "dead"
        process = Mock(pid=pid, returncode=7 if dead else None)
        process.poll.return_value = process.returncode
        self.processes.append(process)
        if not dead:
            session = Path(command[command.index("RusticQuery.java") + 1])
            ready = {"ok": True, "pid": pid, "started_ms": started,
                     "sha256": self.digest, "program": "owned.exe"}
            self.alive[pid, started] = True
            self.real_write(session / "ready.json", ready)
        return process

    def mailbox(self, path, value):
        self.real_write(path, value)
        if path.name != "request.json":
            return
        self.requests.append(value)
        if self.response_mode == "timeout":
            return
        if self.response_mode == "die":
            self.alive.clear()
            return
        response = {"id": value["id"], "ok": self.response_mode == "ok"}
        if not response["ok"]:
            response["error"] = "decompile refused: timed out"
        else:
            response.update(sha256=self.digest, address_kind="VA", c="void owned(void) {}")
        self.real_write(path.with_name("response.json"), response)

    def ask(self, **kwargs):
        return json.loads(self.runner.query("test", address="0x401000", **kwargs))

    def test_symbol_address_or_cursor_is_rejected_before_worker_start(self):
        for argument, value in (("address", "FUN_00401000"), ("cursor", "InitializeCommands"),
                                ("address", "0x401000; analyzeHeadless")):
            with self.subTest(argument=argument, value=value):
                args = {"address": "0x401000", argument: value}
                with self.assertRaisesRegex(ValueError, "numeric Ghidra VA"):
                    self.runner.query("test", **args)
        self.launch.assert_not_called()
        self.snapshot.assert_not_called()

    def test_binary_and_configured_hash_must_agree_before_start(self):
        self.project["sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "does not match target exe"):
            self.ask()
        self.launch.assert_not_called()

    def test_full_hash_is_required_when_no_binary_is_configured(self):
        del self.project["exe"]
        self.project["sha256"] = self.digest[:16]
        with self.assertRaisesRegex(ValueError, "full sha256"):
            self.ask()
        self.launch.assert_not_called()

    def test_repeated_queries_across_cli_runner_instances_reuse_one_worker(self):
        first = self.ask()
        self.runner = query.QueryRunner(self.settings)
        second = self.ask()
        self.assertTrue(first["cold"])
        self.assertFalse(second["cold"])
        self.assertEqual(first["session"], second["session"])
        self.assertNotEqual(self.requests[0]["id"], self.requests[1]["id"])
        self.assertEqual(self.launch.call_count, 1)
        self.assertEqual(self.snapshot.call_count, 1)
        command = self.launch.call_args.args[0]
        self.assertIn("-noanalysis", command)
        self.assertIn("-readOnly", command)
        self.assertIn("-process", command)
        self.assertNotIn("-import", command)
        self.assertIn(self.digest, command)

    def test_changed_master_retires_old_worker_before_new_snapshot(self):
        first = self.ask()
        old_pid = self.processes[0].pid
        self.analysis.write_bytes(b"changed analysis with different size")
        second = self.ask()
        self.assertTrue(second["cold"])
        self.assertNotEqual(first["session"], second["session"])
        self.assertEqual(self.stop.call_args.args[0]["pid"], old_pid)
        self.assertEqual(self.snapshot.call_count, 2)

    def test_open_master_is_refused_even_when_a_warm_worker_exists(self):
        self.ask()
        (Path(self.project["dir"]) / "client.lock~").touch()
        with self.assertRaisesRegex(ValueError, "master project is open"):
            self.ask()
        self.assertEqual(self.launch.call_count, 1)
        self.assertEqual(len(self.requests), 1)

    def test_failed_startup_does_not_poison_the_next_start(self):
        self.launch_mode = "dead"
        with self.assertRaisesRegex(RuntimeError, "exited 7 before ready"):
            self.ask()
        self.launch_mode = "ready"
        result = self.ask()
        self.assertTrue(result["cold"])
        self.assertEqual(self.launch.call_count, 2)
        self.assertEqual(len(self.requests), 1)

    def test_decompiler_refusal_retires_worker_and_next_query_starts_fresh(self):
        first = self.ask()
        self.response_mode = "refusal"
        with self.assertRaisesRegex(RuntimeError, "decompile refused"):
            self.ask()
        self.assertEqual(self.stop.call_count, 1)
        self.response_mode = "ok"
        result = self.ask()
        self.assertTrue(result["cold"])
        self.assertNotEqual(first["session"], result["session"])
        self.assertEqual(self.launch.call_count, 2)

    def test_timeout_ignores_old_response_retires_worker_and_restarts_next_call(self):
        first = self.ask()
        self.response_mode = "timeout"
        with self.assertRaisesRegex(TimeoutError, "worker retired"):
            self.ask(timeout_s=1)
        self.assertGreaterEqual(self.now, 3)
        self.assertEqual(self.stop.call_count, 1)
        self.response_mode = "ok"
        result = self.ask()
        self.assertNotEqual(first["session"], result["session"])
        self.assertTrue(result["cold"])

    def test_worker_death_during_request_allows_a_fresh_next_session(self):
        first = self.ask()
        self.response_mode = "die"
        with self.assertRaisesRegex(RuntimeError, "worker exited"):
            self.ask()
        self.response_mode = "ok"
        result = self.ask()
        self.assertNotEqual(first["session"], result["session"])
        self.assertTrue(result["cold"])

    def test_capacity_counts_live_workers_before_copy_or_launch(self):
        self.settings["query_workers"] = 1
        foreign = self.runner.root / "foreign"
        session = foreign / "session"
        session.mkdir(parents=True)
        self.real_write(foreign / "current.json", {"session": str(session)})
        self.real_write(session / "ready.json", {"ok": True, "pid": 9999, "started_ms": 1})
        self.alive[9999, 1] = True
        with self.assertRaisesRegex(ValueError, "worker limit reached"):
            self.ask()
        self.launch.assert_not_called()
        self.snapshot.assert_not_called()
        self.alive.clear()
        self.assertTrue(self.ask()["cold"])


if __name__ == "__main__":
    unittest.main()
