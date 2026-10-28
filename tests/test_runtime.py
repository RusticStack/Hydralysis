import hashlib
import json
import socket
import struct
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hydralysis import runtime, runtime_ipc
from hydralysis.runtime_worker import CONTROL, MEMORY_HELPER, RuntimeAgent, _expect, _probe_source, _ready_record, _read

from support import workdir


class RuntimeCase(unittest.TestCase):
    def setUp(self):
        self.temp = workdir()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "owned.exe"
        self.binary.write_bytes(bytes.fromhex("55 48 89 E5 90 C3 90 90"))
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.module = {"name": self.binary.name, "path": str(self.binary), "base": "0x10000000", "size": 0x10000}
        self.device = Mock()
        self.agent = RuntimeAgent(self.root, self.device)
        self.agent.session = Mock()
        self.agent.control = Mock()
        self.agent.control.exports_sync.module.return_value = self.module
        self.agent.control.exports_sync.read.return_value = [0x55, 0x48, 0x89, 0xE5, 0x90]
        self.agent.control.exports_sync.locate.return_value = {"module": None, "range": {"base": "0x20000000", "size": 4096, "protection": "rw-"}}
        self.agent.state = "running"
        self.agent.pid = 123
        self.script = Mock()
        self.script.exports_sync.status.return_value = {"installed": True}
        self.agent.session.create_script.return_value = self.script

    def site(self, **extra):
        return {"module": self.binary.name, "rva": "0x1000", "sha256": self.digest,
                "expect": "55 48 89 E5 90", **extra}


class ProbeGuards(RuntimeCase):
    def test_live_reads_are_volatile_and_require_the_exact_requested_length(self):
        self.assertIn("address.readVolatile(size)", MEMORY_HELPER)
        self.assertIn("buffer===null||buffer.byteLength!==size", MEMORY_HELPER)
        self.assertIn("readExact(p,size)", CONTROL)
        source = _probe_source(self.module, 0x1000, _expect("55 48 89 E5 90"), "hook", 2, False)
        self.assertIn("readExact(site,p.expect.length)", source)
        self.assertLess(source.index("buffer.byteLength!==size"), source.index("Interceptor.attach"))
        self.assertNotIn("readByteArray", CONTROL + source)

    def test_live_byte_mismatch_does_not_load_any_script(self):
        self.agent.control.exports_sync.read.return_value = [0xCC] * 5
        with self.assertRaisesRegex(ValueError, "PROLOGUE MISMATCH"):
            self.agent.handle("observe", self.site())
        self.agent.session.create_script.assert_not_called()

    def test_wrong_backing_file_hash_or_wildcards_do_not_install(self):
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.agent.handle("observe", self.site(sha256="1" * 64))
        with self.assertRaisesRegex(ValueError, "expected bytes"):
            self.agent.handle("observe", self.site(expect="55 48 ?? E5 90"))
        self.agent.session.create_script.assert_not_called()

    def test_probe_verifies_again_before_interceptor_and_confirms_installation(self):
        result = self.agent.handle("observe", self.site())
        self.assertTrue(result["verified"])
        source = self.agent.session.create_script.call_args.args[0]
        self.assertLess(source.index("got.some"), source.index("Interceptor.attach"))
        self.assertIn("mapping changed", source)
        self.assertIn("context", source)
        self.assertIn("backtrace", source)
        self.assertIn("onLeave", source)
        self.assertIn("'rip','rsp','rbp'", source)
        self.assertNotIn("Object.keys(this.context)", source)
        self.script.exports_sync.status.assert_called_once()

    def test_js_load_error_is_a_failure_even_if_load_did_not_raise(self):
        def error_during_load():
            script_id = next(iter(self.agent.scripts))
            self.agent.message(script_id, {"type": "error", "description": "probe refused"})
        self.script.load.side_effect = error_during_load
        with self.assertRaisesRegex(RuntimeError, "probe refused"):
            self.agent.handle("observe", self.site())
        self.script.unload.assert_called_once()
        self.assertFalse(self.agent.scripts)

    def test_failed_install_cleanup_reports_retained_script_id(self):
        self.script.load.side_effect = ValueError("install refused")
        self.script.unload.side_effect = PermissionError("unload denied")
        with self.assertRaisesRegex(PermissionError, "install refused.*cleanup failed.*unload denied") as caught:
            self.agent.handle("observe", self.site())
        script_id = next(iter(self.agent.scripts))
        self.assertIn(script_id, str(caught.exception))
        self.assertTrue(self.agent.scripts[script_id]["cleanup_pending"])

    def test_breakpoint_waits_for_typed_continue_message(self):
        source = _probe_source(self.module, 0x1000, _expect("55 48 89 E5 90"), "hook", 2, True)
        self.assertIn("recv('continue:'+p.id", source)
        self.assertIn('"pause": true', source)
        self.agent.scripts["hook"] = {"handle": self.script}
        self.agent.pauses["hook"] = 0
        result = self.agent.handle("continue", {"hook_id": "hook"})
        self.assertEqual(result["continued"], "hook")
        self.script.post.assert_called_with({"type": "continue:hook"})
        self.assertNotIn("hook", self.agent.pauses)

    def test_out_of_module_read_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "inside selected module"):
            self.agent.handle("read", self.site(rva="0xffff", size=2))
        self.agent.control.exports_sync.read.assert_not_called()

    def test_absolute_heap_read_retains_range_and_target_identity(self):
        self.agent.control.exports_sync.info.return_value = {"pointer_size": 8}
        self.agent.target_created_ms = 77
        self.agent.target_exe = str(self.binary)
        self.agent.target_sha256 = self.digest
        result = self.agent.handle("read", {"address": "0x20000010", "size": 5})
        self.agent.control.exports_sync.read.assert_called_with("0x20000010", 5)
        self.assertIsNone(result["module"])
        self.assertIsNone(result["rva"])
        self.assertEqual(result["range"]["protection"], "rw-")
        self.assertEqual(result["target"]["created_ms"], 77)
        self.assertEqual(result["target"]["exe_sha256"], self.digest)

    def test_absolute_read_rejects_pointer_overflow_before_native_read(self):
        self.agent.control.exports_sync.info.return_value = {"pointer_size": 4}
        with self.assertRaisesRegex(ValueError, "overflows"):
            self.agent.handle("read", {"address": "0xfffffffe", "size": 8})
        self.agent.control.exports_sync.read.assert_not_called()

    def test_authored_script_cannot_bypass_the_live_hook_gate(self):
        self.assertNotIn("script", runtime.ACTION_NAMES)
        with self.assertRaisesRegex(ValueError, "arbitrary scripts are not accepted"):
            self.agent.handle("script", {"trusted": True, "source": "Interceptor.attach(ptr('0x1234'),{});"})
        self.agent.session.create_script.assert_not_called()


class LifecycleAndBounds(RuntimeCase):
    def test_capture_is_bounded_and_status_paginates_by_sequence(self):
        # Disk publication is orthogonal to the ring's loss/paging contract.
        with patch.object(self.agent, "publish"):
            for i in range(1100):
                self.agent.message("script", {"type": "send", "payload": "x" * 500})
        self.agent.publish()
        self.assertLessEqual(len(self.agent.events), 1000)
        self.assertLessEqual(self.agent.event_bytes, 262144)
        first = self.agent.handle("status", {"limit": 2})
        second = self.agent.handle("status", {"limit": 2, "after": first["next_after"]})
        self.assertTrue(first["truncated"])
        self.assertGreater(first["dropped_events"], 0)
        self.assertGreater(second["events"][0]["sequence"], first["events"][-1]["sequence"])

    def test_cleanup_releases_break_and_instrumentation_before_resuming_spawn(self):
        calls = []
        self.script.post.side_effect = lambda value: calls.append("continue")
        self.script.unload.side_effect = lambda: calls.append("unload")
        self.agent.session.detach.side_effect = lambda: calls.append("detach")
        self.device.resume.side_effect = lambda pid: calls.append("resume")
        self.agent.scripts["hook"] = {"handle": self.script}
        self.agent.pauses["hook"] = 0
        self.agent.paused_spawn = True
        self.agent.target_created_ms = 77
        with patch("hydralysis.runtime_worker._created_ms", return_value=77):
            result = self.agent.cleanup()
        self.assertEqual(calls, ["continue", "unload", "detach", "resume"])
        self.assertEqual(result["target_state"], "unknown")
        self.device.kill.assert_not_called()

    def test_failed_cleanup_retains_handles_and_does_not_resume_instrumented_spawn(self):
        self.script.unload.side_effect = RuntimeError("busy")
        self.agent.session.detach.side_effect = RuntimeError("busy")
        self.agent.scripts["hook"] = {"handle": self.script}
        self.agent.paused_spawn = True
        with self.assertRaisesRegex(RuntimeError, "cleanup incomplete"):
            self.agent.cleanup()
        self.assertIn("hook", self.agent.scripts)
        self.assertFalse(self.agent.closed)
        self.device.resume.assert_not_called()
        self.device.kill.assert_not_called()

    def test_changed_spawn_pid_is_not_resumed(self):
        self.agent.paused_spawn = True
        self.agent.target_created_ms = 77
        with patch("hydralysis.runtime_worker._created_ms", return_value=99), self.assertRaisesRegex(RuntimeError, "identity changed"):
            self.agent.cleanup()
        self.device.resume.assert_not_called()

    def test_attach_path_is_checked_before_injection(self):
        self.agent.session = None
        initial = {"exe": str(self.binary), "sha256": self.digest, "action": "attach", "pid": 123, "argv": []}
        with patch("hydralysis.runtime_worker._process_path", return_value=str(self.root / "other.exe")), self.assertRaisesRegex(ValueError, "path differs"):
            self.agent.startup(initial)
        self.device.attach.assert_not_called()

    def test_pid_reuse_during_attach_detaches_before_loading_control_or_probes(self):
        attached = Mock()
        self.device.attach.return_value = attached
        initial = {"exe": str(self.binary), "sha256": self.digest, "action": "attach", "pid": 123, "argv": []}
        with patch("hydralysis.runtime_worker._process_path", return_value=str(self.binary)), patch("hydralysis.runtime_worker._created_ms", side_effect=[77, 99]), self.assertRaisesRegex(ValueError, "identity changed during attach"):
            self.agent.startup(initial)
        attached.detach.assert_called_once()
        attached.create_script.assert_not_called()
        self.assertTrue(self.agent.detached)

    def test_attach_recheck_permission_failure_keeps_the_actual_cause(self):
        attached = Mock()
        self.device.attach.return_value = attached
        error = PermissionError(13, "cannot query target identity")
        error.winerror = 5
        initial = {"exe": str(self.binary), "sha256": self.digest, "action": "attach", "pid": 123, "argv": []}
        with patch("hydralysis.runtime_worker._process_path", return_value=str(self.binary)), patch("hydralysis.runtime_worker._created_ms", side_effect=[77, error]), self.assertRaisesRegex(RuntimeError, "errno=13 winerror=5"):
            self.agent.startup(initial)
        attached.detach.assert_called_once()
        attached.create_script.assert_not_called()

    def test_startup_resolves_selected_module_instead_of_mainmodule_shortcut(self):
        self.device.attach.return_value = self.agent.session
        self.agent.session.create_script.return_value = self.agent.control
        self.agent.control.exports_sync.info.return_value = {"pid": 123, "main": self.module}
        initial = {"exe": str(self.binary), "sha256": self.digest, "action": "attach", "pid": 123, "argv": []}
        with patch("hydralysis.runtime_worker._process_path", return_value=str(self.binary)), patch("hydralysis.runtime_worker._created_ms", return_value=77):
            observation = self.agent.startup(initial)
        self.agent.control.exports_sync.info.assert_called_with(str(self.binary))
        self.assertEqual(observation["target"]["main"]["path"], str(self.binary))

    def test_ready_metadata_retains_worker_identity_separate_from_target(self):
        ready = _ready_record({"pid": 500, "started_ms": 88}, {"pid": 123, "target": {"pid": 123}})
        self.assertEqual(ready["pid"], 500)
        self.assertEqual(ready["started_ms"], 88)
        self.assertEqual(ready["target"]["pid"], 123)


class HostRuntimeContracts(RuntimeCase):
    def test_typed_read_resolves_struct_and_enum_from_the_requested_view(self):
        runner = runtime.RuntimeRunner({"root": str(self.root)})
        query = Mock()
        query.query.side_effect = [json.dumps({"type": {"path": "/Config", "length": 4,
            "fields": [{"field": "mode", "offset": 0, "name": "Mode", "length": 4,
                        "kind": "EnumDB", "path": "/Mode"}]}}),
            json.dumps({"type": {"values": [{"value": "0x2", "name": "active"}]}})]
        args = {"type": "/Config", "target": "fixture", "view": "experiment"}
        with patch("hydralysis.query.QueryRunner", return_value=query), patch("hydralysis.backends.resolved", return_value={}):
            layout = runner._layout(args)
        self.assertEqual(query.query.call_args_list[0].kwargs["options"], {"path": "/Config", "view": "experiment"})
        self.assertEqual(query.query.call_args_list[1].kwargs["options"], {"path": "/Mode", "view": "experiment"})
        self.assertEqual(layout["layout"][0]["names"], {"2": "active"})
        self.assertNotIn("view", args)

    def test_worker_error_type_reaches_runtime_caller(self):
        session_id = "c" * 32
        runner = runtime.RuntimeRunner({"root": str(self.root)})
        directory = runner.root / session_id
        directory.mkdir()
        (directory / "ready.json").write_text(json.dumps({"pid": 500, "started_ms": 88}))
        for error_type, expected in (("PermissionError", PermissionError), ("ValueError", ValueError), ("unknown", RuntimeError)):
            with self.subTest(error_type=error_type), patch("hydralysis.runtime._identity", return_value=True), \
                 patch("hydralysis.runtime.ipc_request", return_value={"ok": False, "error": "denied", "error_type": error_type}):
                with self.assertRaisesRegex(expected, "denied"):
                    runner.call("modules", {"session": session_id})
        with patch("hydralysis.runtime._identity", return_value=True), \
             patch("hydralysis.runtime.ipc_request", side_effect=PermissionError("socket denied")):
            with self.assertRaisesRegex(PermissionError, "socket denied"):
                runner.call("modules", {"session": session_id})

    def test_host_uses_authenticated_ipc_without_publishing_hot_files(self):
        session_id = "c" * 32
        runner = runtime.RuntimeRunner({"root": str(self.root)})
        directory = runner.root / session_id
        directory.mkdir()
        endpoint = {"port": 4444, "token": "a" * 64}
        (directory / "ready.json").write_text(json.dumps({"pid": 500, "started_ms": 88, "ipc": endpoint}))
        with patch("hydralysis.runtime._identity", return_value=True), patch("hydralysis.runtime._write") as files, patch("hydralysis.runtime.ipc_request", return_value={"ok": True, "result": {"modules": []}}) as rpc:
            result = runner.call("modules", {"session": session_id})
        self.assertEqual(result, {"modules": []})
        self.assertEqual(rpc.call_args.args[0], endpoint)
        self.assertRegex(rpc.call_args.args[1], "^[0-9a-f]{32}$")
        files.assert_not_called()

    def test_public_worker_metadata_never_includes_authentication_material(self):
        ready = {"pid": 500, "started_ms": 88, "ipc": {"port": 4444, "token": "a" * 64}}
        public = runtime._public_ready(ready)
        self.assertEqual(public, {"pid": 500, "started_ms": 88})
        self.assertNotIn("a" * 64, json.dumps(public))

    def test_permission_errors_report_exact_details_instead_of_missing_mailbox(self):
        error = PermissionError(13, "access denied", str(self.root / "response.json"))
        error.winerror = 5
        with patch("hydralysis.runtime.local_read_text", side_effect=error), self.assertRaisesRegex(RuntimeError, "errno=13 winerror=5"):
            runtime._json(self.root / "response.json")
        with patch("hydralysis.runtime_worker.local_read_text", side_effect=error), self.assertRaisesRegex(RuntimeError, "errno=13 winerror=5"):
            _read(self.root / "request.json")

    def test_live_status_uses_in_memory_snapshot_not_rewritten_state_file(self):
        with patch("hydralysis.runtime_worker._read", side_effect=PermissionError("state file should not be read")):
            result = self.agent.handle("status", {})
        self.assertEqual(result["pid"], self.agent.pid)

    def test_inspect_has_no_filesystem_or_install_side_effects(self):
        settings = {"root": str(self.root / "missing-root")}
        with patch("hydralysis.runtime.proc.run") as run:
            report = runtime.inspect(settings)
        self.assertFalse(report["ready"])
        self.assertIn("backend action=install component=runtime", report["reason"])
        # A backend that was never installed is reported without starting any child.
        run.assert_not_called()
        self.assertFalse(Path(settings["root"]).exists())

    def test_missing_backend_fails_fast_for_every_action_that_needs_it(self):
        runner = runtime.RuntimeRunner({"root": str(self.root / "no-backend")})
        with patch("hydralysis.runtime.proc.run") as run, patch("hydralysis.runtime.proc.popen") as launch:
            for action, args in (("processes", {}),
                                 ("spawn", {"exe": str(self.binary), "sha256": self.digest}),
                                 ("attach", {"exe": str(self.binary), "sha256": self.digest, "pid": 4})):
                with self.subTest(action=action), self.assertRaisesRegex(RuntimeError, "not installed"):
                    runner.call(action, args)
        run.assert_not_called()
        launch.assert_not_called()

    def test_spawn_and_attach_name_the_options_they_need(self):
        runner = runtime.RuntimeRunner({"root": str(self.root / "options")})
        cases = (("spawn", {"exe": str(self.binary)}, "options.sha256"),
                 ("attach", {"exe": str(self.binary), "pid": 4}, "options.sha256"),
                 ("spawn", {"sha256": self.digest}, "options.exe"),
                 ("spawn", {"exe": str(self.binary), "sha256": self.digest, "cwd": "relative"}, "options.cwd"),
                 ("spawn", {"exe": str(self.binary), "sha256": self.digest, "env": {"A": 1}}, "options.env"),
                 ("spawn", {"exe": str(self.binary), "sha256": self.digest, "working_dir": "x"}, "unknown spawn options"),
                 ("attach", {"exe": str(self.binary), "sha256": self.digest, "cwd": str(self.root)}, "unknown attach options"))
        with patch("hydralysis.runtime.proc.popen") as launch:
            for action, args, message in cases:
                with self.subTest(args=args), self.assertRaisesRegex(ValueError, message):
                    runner.call(action, args)
        launch.assert_not_called()

    def test_spawned_target_gets_the_callers_environment_not_the_workers(self):
        from hydralysis.runtime_worker import target_environment
        restore = json.dumps({"TEMP": "C:/caller-temp", "PYTHONPATH": None})
        with patch.dict("os.environ", {"HYDRALYSIS_TARGET_ENV_RESTORE": restore, "TEMP": "worker-temp",
                                       "PYTHONPATH": "worker-site"}):
            env = target_environment({"MESA_LOADER_DRIVER_OVERRIDE": "zink"})
        self.assertEqual(env["TEMP"], "C:/caller-temp")
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("HYDRALYSIS_TARGET_ENV_RESTORE", env)
        self.assertEqual(env["MESA_LOADER_DRIVER_OVERRIDE"], "zink")

    def test_setup_passes_hashes_and_explicit_target_without_global_install(self):
        settings = {"root": str(self.root / "runtime-root")}
        site = self.root / "runtime-root" / "runtime-backend" / ("frida-" + runtime.FRIDA_VERSION)
        responses = [SimpleNamespace(returncode=0),
                     SimpleNamespace(returncode=0, stdout=json.dumps({"version": runtime.FRIDA_VERSION,
                                                                      "path": str(site / "frida" / "__init__.py")}), stderr="")]
        metadata = {"urls": [{"packagetype": "bdist_wheel", "digests": {"sha256": "a" * 64}}]}
        from io import BytesIO
        with patch("hydralysis.runtime.proc.run", side_effect=responses) as run, patch("hydralysis.runtime.urllib.request.urlopen", return_value=BytesIO(json.dumps(metadata).encode())):
            result = runtime.setup(settings)
        self.assertEqual(result["state"], "ready")
        self.assertFalse(result["reused"])
        command = run.call_args_list[0].args[0]
        self.assertIn("--require-hashes", command)
        self.assertIn("--target", command)
        self.assertIn("--isolated", command)
        self.assertIn("--no-deps", command)
        self.assertTrue(str(self.root) in command[command.index("--target") + 1])

    def test_a_frida_beside_the_dependencies_is_not_an_install(self):
        settings = {"root": str(self.root / "runtime-root2")}
        site = self.root / "runtime-root2" / "runtime-backend" / ("frida-" + runtime.FRIDA_VERSION)
        site.mkdir(parents=True)
        elsewhere = json.dumps({"version": runtime.FRIDA_VERSION, "path": str(self.root / "site-packages" / "frida" / "__init__.py")})
        with patch("hydralysis.runtime.proc.run", return_value=SimpleNamespace(returncode=0, stdout=elsewhere, stderr="")),                 self.assertRaisesRegex(RuntimeError, "incomplete"):
            runtime.setup(settings)

    def test_an_idle_ended_session_says_so_and_how_to_continue(self):
        runner = runtime.RuntimeRunner({"root": str(self.root / "ended")})
        session = "e" * 32
        directory = runner.root / session
        directory.mkdir(parents=True)
        (directory / "ready.json").write_text(json.dumps({"pid": 0, "started_ms": 0}))
        (directory / "state.json").write_text(json.dumps({"detached": True, "pid": 4242,
                                                          "ended": "idle: no request for 600 s (runtime_idle_s)"}))
        with self.assertRaisesRegex(RuntimeError, "ended .idle.*attach again with pid 4242"):
            runner.call("read", {"session": session, "address": "0x1000", "size": 4})

    def test_invalid_sessions_and_target_builds_do_not_launch_worker(self):
        runner = runtime.RuntimeRunner({"root": str(self.root / "sessions")})
        with patch("hydralysis.runtime.proc.popen") as launch:
            for action, args in (("read", {"session": "../foreign"}),
                                 ("spawn", {"exe": str(self.binary), "sha256": "1" * 64}),
                                 ("attach", {"exe": str(self.binary), "sha256": self.digest, "pid": 0})):
                with self.subTest(action=action), self.assertRaises(ValueError):
                    runner.call(action, args)
            launch.assert_not_called()


class LocalIPC(unittest.TestCase):
    def server(self, handler, count=1, raw=False):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(2)
        endpoint = {"port": listener.getsockname()[1], "token": "a" * 64}
        errors = []
        def run():
            try:
                for _ in range(count):
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(1)
                        if raw:
                            handler(connection)
                        else:
                            runtime_ipc.serve(connection, endpoint["token"], handler)
            except Exception as exc:
                errors.append(exc)
            finally:
                listener.close()
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        def finish():
            thread.join(3)
            listener.close()
            self.assertFalse(thread.is_alive(), "bounded IPC test server did not exit")
            self.assertFalse(errors, repr(errors))
        self.addCleanup(finish)
        return endpoint

    def packet(self, **extra):
        return {"id": "b" * 32, "token": "a" * 64, "action": "modules", "args": {},
                "deadline_s": 1, **extra}

    def exchange(self, endpoint, packet):
        with socket.create_connection(("127.0.0.1", endpoint["port"]), timeout=1) as connection:
            runtime_ipc.send(connection, packet)
            return runtime_ipc.receive(connection)

    def test_wrong_auth_is_refused_before_handler_and_next_connection_works(self):
        handler = Mock(return_value={"modules": []})
        endpoint = self.server(handler, count=2)
        refused = self.exchange(endpoint, self.packet(token="c" * 64))
        self.assertFalse(refused["ok"])
        self.assertIn("authentication failed", refused["error"])
        handler.assert_not_called()
        result = runtime_ipc.request(endpoint, "d" * 32, "modules", {}, 1)
        self.assertTrue(result["ok"])
        handler.assert_called_once_with("modules", {}, 1)

    def test_malformed_requests_never_reach_handler_or_echo_token(self):
        handler = Mock()
        invalid = [{"id": "short"}, {"args": []}, {"deadline_s": 0}, {"action": ""}]
        endpoint = self.server(handler, count=len(invalid) + 1)
        with socket.create_connection(("127.0.0.1", endpoint["port"]), timeout=1) as connection:
            payload = b'{"truncated":'
            connection.sendall(struct.pack("!I", len(payload)) + payload)
            self.assertFalse(runtime_ipc.receive(connection)["ok"])
        for fields in invalid:
            with self.subTest(fields=fields):
                response = self.exchange(endpoint, self.packet(**fields))
                self.assertFalse(response["ok"])
                self.assertNotIn(endpoint["token"], json.dumps(response))
        handler.assert_not_called()

    def test_frame_bounds_reject_before_handler_and_response_oversize_is_error(self):
        handler = Mock(return_value={"data": "x" * runtime_ipc.MAX_FRAME})
        endpoint = self.server(handler, count=2)
        with socket.create_connection(("127.0.0.1", endpoint["port"]), timeout=1) as connection:
            connection.sendall(struct.pack("!I", runtime_ipc.MAX_FRAME + 1))
            response = runtime_ipc.receive(connection)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error_type"], "ValueError")
        handler.assert_not_called()
        response = runtime_ipc.request(endpoint, "b" * 32, "read", {}, 1)
        self.assertFalse(response["ok"])
        self.assertIn("frame", response["error"])
        handler.assert_called_once()
        with socket.socket() as connection, self.assertRaisesRegex(ValueError, "frame"):
            runtime_ipc.send(connection, {"data": "x" * runtime_ipc.MAX_FRAME})

    def test_structured_agent_error_preserves_server_and_redacts_secret(self):
        handler = Mock(side_effect=[ValueError("bad module " + "a" * 64), {"state": "running"}])
        endpoint = self.server(handler, count=2)
        response = runtime_ipc.request(endpoint, "b" * 32, "read", {}, 1)
        self.assertFalse(response["ok"])
        self.assertIn("[redacted]", response["error"])
        self.assertEqual(response["error_type"], "ValueError")
        self.assertNotIn(endpoint["token"], json.dumps(response))
        self.assertTrue(runtime_ipc.request(endpoint, "c" * 32, "status", {}, 1)["ok"])

    def test_permission_error_type_is_preserved_over_ipc(self):
        endpoint = self.server(Mock(side_effect=PermissionError("probe denied")), count=1)
        response = runtime_ipc.request(endpoint, "b" * 32, "observe", {}, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error_type"], "PermissionError")
        self.assertEqual(response["error"], "probe denied")

    def test_absolute_deadline_stops_drip_frames_and_handler_wait(self):
        # Each byte arrives inside a per-recv timeout; only a total deadline
        # rejects a peer that keeps one frame alive by trickling bytes.
        def drip(connection):
            try:
                for value in struct.pack("!I", 20) + b'{"id":"never"}':
                    connection.sendall(bytes([value]))
                    time.sleep(0.025)
            except OSError:
                pass
        endpoint = self.server(drip, raw=True)
        with self.assertRaises(TimeoutError):
            runtime_ipc.rpc(endpoint, {"id": "b" * 32}, 0.065)
        endpoint = self.server(lambda *_: time.sleep(0.12))
        with self.assertRaises(TimeoutError):
            runtime_ipc.rpc(endpoint, self.packet(), 0.04)

    def test_request_identity_and_endpoint_are_validated_without_remote_urls(self):
        for endpoint in ({"port": 0, "token": "a" * 64}, {"port": 10, "token": "bad"}):
            with self.subTest(endpoint=endpoint), patch("hydralysis.runtime_ipc.socket.create_connection") as connect, self.assertRaises(ValueError):
                runtime_ipc.rpc(endpoint, {"id": "b" * 32}, 1)
            connect.assert_not_called()
        def wrong_id(connection):
            runtime_ipc.receive(connection)
            runtime_ipc.send(connection, {"id": "f" * 32, "ok": True, "result": {}})
        endpoint = self.server(wrong_id, raw=True)
        endpoint["host"] = "https://remote.invalid/"
        with self.assertRaisesRegex(ValueError, "does not match"):
            runtime_ipc.rpc(endpoint, {"id": "b" * 32}, 1)


if __name__ == "__main__":
    unittest.main()
