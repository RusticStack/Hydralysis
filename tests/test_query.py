"""Exercise worker lifecycle without importing a binary or starting Ghidra."""

import hashlib
import json
import os
import subprocess
import sys
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
        self.endpoints = []
        self.rpc_limits = []
        self.launch_mode = "ready"
        self.response_mode = "ok"
        self.real_write = query._write
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("rusticre.query.launch_command", side_effect=lambda command: command))
        self.launch = self.stack.enter_context(patch("rusticre.query.subprocess.Popen", side_effect=self.launcher))
        self.stop = self.stack.enter_context(patch("rusticre.query._stop", side_effect=self.retire))
        self.stack.enter_context(patch("rusticre.query._identity", side_effect=lambda pid, started: self.alive.get((pid, started), False)))
        self.stack.enter_context(patch("rusticre.query._process_start_ms", side_effect=lambda pid: 100000 + pid))
        self.stack.enter_context(patch("rusticre.query._write", side_effect=self.mailbox))
        self.rpc = self.stack.enter_context(patch("rusticre.query.rpc", side_effect=self.exchange))
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
                     "sha256": self.digest, "program": "owned.exe", "image_base": "0x400000",
                     "ipc": {"port": 12345, "token": "e" * 64}}
            if self.launch_mode == "no_ipc":
                ready.pop("ipc")
            self.alive[pid, started] = True
            self.real_write(session / "ready.json", ready)
        return process

    def mailbox(self, path, value):
        self.real_write(path, value)

    def exchange(self, endpoint, value, timeout_s, **limits):
        self.requests.append(value)
        self.endpoints.append(endpoint)
        self.rpc_limits.append(limits)
        if self.response_mode == "timeout":
            self.now += timeout_s
            raise TimeoutError("fixture RPC timeout")
        if self.response_mode == "die":
            self.alive.clear()
            raise ConnectionResetError("fixture worker exited")
        response = {"id": value["id"], "ok": self.response_mode == "ok"}
        if not response["ok"]:
            response["error"] = "decompile refused: timed out"
            if self.response_mode == "not_found":
                response.update(error="no analysed function contains this address", recoverable=True, error_kind="not_found")
        else:
            response.update(sha256=self.digest, address_kind="VA", c="void owned(void) {}")
        return response

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

    def test_explicit_rva_is_normalized_from_analysed_program_base(self):
        self.runner.query("test", address="rva:0x1000")
        self.assertEqual(self.requests[-1]["address"], "0x401000")
        self.runner.query("test", address="va:0x401000")
        self.assertEqual(self.requests[-1]["address"], "0x401000")
        self.assertEqual(self.launch.call_count, 1)

    def test_rpc_uses_authenticated_endpoint_and_explicit_frame_budgets(self):
        self.ask()
        self.assertEqual(self.endpoints[0], {"port": 12345, "token": "e" * 64})
        self.assertNotIn("token", self.requests[0])
        self.assertRegex(self.requests[0]["id"], r"^[0-9a-f]{32}$")
        self.assertEqual(self.rpc_limits[0], {"request_limit": 32 * 1024 * 1024, "response_limit": 16 * 1024 * 1024})

    def test_queries_do_not_read_write_or_replace_hot_json_files(self):
        first = self.ask()
        session = Path(first["session"])
        legacy = session / "request.json"
        legacy.write_bytes(b"legacy request evidence")
        response = session / "response.json"
        response.write_bytes(b"legacy response evidence")
        original_read = query._json

        def read(path):
            if path.name.startswith(("request", "response")):
                raise PermissionError("legacy hot files must not be read")
            return original_read(path)

        def write(path, value):
            if path.name.startswith(("request", "response")):
                raise PermissionError("hot file transport must not be used")
            return self.mailbox(path, value)

        with patch("rusticre.query._json", side_effect=read), patch("rusticre.query._write", side_effect=write):
            second = self.ask()
        self.assertEqual(legacy.read_bytes(), b"legacy request evidence")
        self.assertEqual(response.read_bytes(), b"legacy response evidence")
        self.assertEqual(len(self.requests), 2)
        self.assertFalse(second["cold"])

    def test_invalid_rpc_response_retires_worker_before_a_fresh_query(self):
        self.ask()
        self.rpc.side_effect = ValueError("response does not match admitted request")
        with self.assertRaisesRegex(RuntimeError, "transport failed"):
            self.ask()
        self.assertEqual(self.stop.call_count, 1)
        self.rpc.side_effect = self.exchange
        self.assertTrue(self.ask()["cold"])

    def test_endpoint_credentials_are_redacted_from_public_status(self):
        first = self.ask()
        status = self.runner.query("test", action="status")
        self.assertNotIn("e" * 64, status)
        self.assertNotIn('"ipc"', status)
        self.assertNotIn("e" * 64, json.dumps(first))
        self.assertEqual(query._json(Path(first["session"]) / "ready.json")["ipc"]["token"], "e" * 64)

    def test_missing_rpc_endpoint_is_a_failed_worker_not_a_successful_query(self):
        self.launch_mode = "no_ipc"
        with self.assertRaisesRegex(RuntimeError, "authenticated local query endpoint"):
                self.ask()
        self.stop.assert_called_once()
        self.rpc.assert_not_called()
        self.launch_mode = "ready"
        self.assertTrue(self.ask()["cold"])

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

    def fail_current_metadata(self, path, value):
        if path.name == "current.json":
            raise OSError("fixture current metadata failure")
        return self.mailbox(path, value)

    def terminate_launcher(self, process):
        process.returncode = -1
        process.poll.return_value = -1
        for identity in list(self.alive):
            if identity[0] == process.pid:
                self.alive.pop(identity)

    def test_startup_metadata_failure_stops_owned_child_before_retry(self):
        with patch("rusticre.query._write", side_effect=self.fail_current_metadata), \
             patch("rusticre.query._terminate_owned_tree", side_effect=self.terminate_launcher) as terminate:
            with self.assertRaisesRegex(OSError, "current metadata failure"):
                self.ask()
        terminate.assert_called_once_with(self.processes[0])
        self.assertFalse(list(self.runner.root.glob("*/startup-failure.json")))
        self.assertTrue(self.ask()["cold"])
        self.assertEqual(self.launch.call_count, 2)

    def test_unconfirmed_startup_cleanup_reserves_target_until_verified_stop(self):
        with patch("rusticre.query._write", side_effect=self.fail_current_metadata), \
             patch("rusticre.query._terminate_owned_tree", side_effect=RuntimeError("fixture cleanup refused")):
            with self.assertRaisesRegex(RuntimeError, "cleanup is unconfirmed"):
                self.ask()
        reservation = next(self.runner.root.glob("*/startup-failure.json"))
        self.assertEqual(json.loads(reservation.read_text())["state"], "cleanup_failed")
        with self.assertRaisesRegex(RuntimeError, "uncommitted Ghidra startup"):
            self.ask()
        self.assertEqual(self.launch.call_count, 1)
        status = json.loads(self.runner.query("test", action="status"))
        self.assertTrue(status["alive"])
        self.assertEqual(len(status["sessions"]), 1)
        self.assertEqual(status["startup_failure"]["state"], "cleanup_failed")
        stopped = json.loads(self.runner.query("test", action="stop"))
        self.assertTrue(stopped["stopped"])
        self.assertFalse(reservation.exists())
        self.assertTrue(self.ask()["cold"])
        self.assertEqual(self.launch.call_count, 2)

    def test_orphan_readiness_counts_capacity_even_without_current_metadata(self):
        self.settings["query_workers"] = 1
        session = self.runner.root / "other-target" / "orphan-session"
        session.mkdir(parents=True)
        self.real_write(session / "ready.json", {"ok": True, "pid": 9999, "started_ms": 1})
        self.alive[9999, 1] = True
        with self.assertRaisesRegex(ValueError, "worker limit reached"):
            self.ask()
        self.launch.assert_not_called()
        self.snapshot.assert_not_called()

    def test_stop_covers_live_target_orphans_but_leaves_other_targets_alone(self):
        first = self.ask()
        target = Path(first["session"]).parent
        orphan = target / "orphan-session"
        orphan.mkdir()
        self.real_write(orphan / "ready.json", {"ok": True, "pid": 9999, "started_ms": 1})
        self.alive[9999, 1] = True
        other = self.runner.root / "other-target" / "session"
        other.mkdir(parents=True)
        self.real_write(other / "ready.json", {"ok": True, "pid": 8888, "started_ms": 2})
        self.alive[8888, 2] = True
        with self.assertRaisesRegex(RuntimeError, "uncommitted Ghidra startup"):
            self.ask()
        stopped = json.loads(self.runner.query("test", action="stop"))
        self.assertEqual(len(stopped["sessions"]), 2)
        self.assertNotIn((9999, 1), self.alive)
        self.assertIn((8888, 2), self.alive)

    def test_failed_overlay_persistence_retires_unrecorded_worker_state(self):
        self.ask()
        with patch("rusticre.query.save_overlay", side_effect=OSError("fixture overlay write failure")):
            with self.assertRaisesRegex(OSError, "overlay write failure"):
                self.ask(action="type_edit", options={"kind": "comment", "source": "fixture:1", "comment": "cited"})
        self.assertEqual(self.stop.call_count, 1)
        self.assertTrue(self.ask()["cold"])

    def test_unconfirmed_retirement_never_reuses_poisoned_current_worker(self):
        self.ask()
        self.response_mode = "refusal"
        self.stop.side_effect = RuntimeError("fixture retirement refused")
        with self.assertRaisesRegex(RuntimeError, "retirement cleanup is unconfirmed"):
            self.ask()
        self.response_mode = "ok"
        with self.assertRaisesRegex(RuntimeError, "uncommitted Ghidra startup/session"):
            self.ask()
        self.assertEqual(self.launch.call_count, 1)
        self.assertEqual(len(self.requests), 2)
        self.stop.side_effect = self.retire
        self.runner.query("test", action="stop")
        self.assertTrue(self.ask()["cold"])

    def test_unconfirmed_overlay_cleanup_blocks_unpersisted_in_memory_state(self):
        self.ask()
        self.stop.side_effect = RuntimeError("fixture retirement refused")
        with patch("rusticre.query.save_overlay", side_effect=OSError("fixture overlay write failure")):
            with self.assertRaisesRegex(RuntimeError, "retirement cleanup is unconfirmed"):
                self.ask(action="type_edit", options={"kind": "comment", "source": "fixture:1", "comment": "cited"})
        with self.assertRaisesRegex(RuntimeError, "uncommitted Ghidra startup/session"):
            self.ask()
        status = json.loads(self.runner.query("test", action="status"))
        self.assertIn("overlay persistence failed", status["startup_failure"]["error"])
        self.assertEqual(len(self.requests), 2)

    def test_metadata_permission_denial_is_not_reported_as_missing(self):
        with patch("rusticre.query.local_read_text", side_effect=PermissionError("fixture denied")):
            with self.assertRaisesRegex(PermissionError, "fixture denied"):
                query._json(self.root / "ready.json")

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

    def test_explicit_lookup_miss_keeps_warm_worker(self):
        first = self.ask()
        self.response_mode = "not_found"
        with self.assertRaisesRegex(RuntimeError, "no analysed function"):
            self.ask()
        self.stop.assert_not_called()
        self.response_mode = "ok"
        result = self.ask()
        self.assertFalse(result["cold"])
        self.assertEqual(first["session"], result["session"])
        self.assertEqual(self.launch.call_count, 1)

    def test_failed_overlay_is_retired_even_if_validation_is_recoverable(self):
        self.ask()
        self.response_mode = "not_found"
        with self.assertRaises(RuntimeError):
            self.ask(action="type_edit", options={"kind": "comment", "source": "fixture:1", "comment": "cited"})
        self.assertEqual(self.stop.call_count, 1)

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


@unittest.skipUnless(os.name == "nt", "Windows retained process handles")
class WindowsProcessIdentityTests(unittest.TestCase):
    def test_exited_process_is_not_live_while_its_popen_handle_is_retained(self):
        from rusticre.preparation import process_start_ms
        with subprocess.Popen([sys.executable, "-B", "-c", "import sys; sys.stdin.buffer.read(1)"],
                              stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=subprocess.CREATE_NO_WINDOW) as process:
            started = process_start_ms(process.pid)
            self.assertGreater(started, 0)
            self.assertTrue(query._identity(process.pid, started))
            process.communicate(input=b"x", timeout=10)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(process_start_ms(process.pid), 0)
            self.assertFalse(query._identity(process.pid, started))


if __name__ == "__main__":
    unittest.main()
