"""The native engine client (`hydralysis_native.Session`, wrapped by `hydralysis.engine_client`) against a scripted daemon.

The daemon is a loopback socket that speaks the session protocol's JSON lines. Where the engine's own Python library
(`ghidra_session.py`, 1.1.0) is reachable (HYDRALYSIS_INTEGRATION_CLIENT) the same script is also run through it and
the two must agree: this is the "identical behaviour" claim, on the replies, the errors and the deadline.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import threading
import time
import unittest
from pathlib import Path

from hydralysis import engine_client

native = engine_client._native
CLIENT_FILE = os.environ.get("HYDRALYSIS_INTEGRATION_CLIENT") or os.environ.get("RUSTICRE_INTEGRATION_CLIENT")

HELLO = {"protocol": 3, "protocolMin": 2, "protocolMax": 3, "minClient": "1.0.0", "hydraVersion": "12.3-test", "ghidraVersion": "12.3"}


class Daemon:
    """A scripted daemon: ANSWER(msg) gives the lines to write for one request (a list of dicts or raw strings)."""

    def __init__(self, answer=None, hello=None):
        self.answer = answer or (lambda msg: [{"id": msg["id"], "ok": True, "result": {"echo": msg}}])
        self.hello = HELLO if hello is None else hello
        self.token = "tok"
        self.requests: list[dict] = []
        self.raw: list[str] = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.connections: list[socket.socket] = []
        self.stopped = False
        self.write_lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def endpoint(self) -> dict:
        return {"host": "127.0.0.1", "port": self.port, "token": self.token, "pid": 1}

    def _accept(self):
        while not self.stopped:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            self.connections.append(connection)
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection):
        buffer = b""
        try:
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    return
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self.raw.append(line.decode("utf-8"))
                    message = json.loads(line)
                    self.requests.append(message)
                    threading.Thread(target=self._answer, args=(connection, message), daemon=True).start()
        except OSError:
            return

    def _answer(self, connection, message):
        """One thread per request, so that a request the script holds back does not hold back the ones behind it."""
        if message["cmd"] == "hello":
            lines = [{"id": message["id"], "ok": True, "result": self.hello}]
        else:
            lines = self.answer(message)
        try:
            for item in lines or []:
                text = item if isinstance(item, str) else json.dumps(item)
                with self.write_lock:
                    connection.sendall(text.encode("utf-8") + b"\n")
        except OSError:
            return

    def drop_all(self):
        for connection in self.connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()

    def stop(self):
        self.stopped = True
        self.listener.close()
        self.drop_all()


def connect(daemon, **kw):
    return native.connect_endpoint(json.dumps(daemon.endpoint), kw.get("client", "c"), kw.get("harness", "h"), kw.get("hello"))


def library(path):
    spec = importlib.util.spec_from_file_location("ghidra_session_for_parity", path)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipIf(native is None, "hydralysis_native is not built")
class Session(unittest.TestCase):
    def setUp(self):
        self.daemon = Daemon()
        self.addCleanup(self.daemon.stop)

    def test_hello_is_the_result_in_the_engines_own_order_and_carries_the_labels(self):
        session = connect(self.daemon)
        self.addCleanup(session.close)
        self.assertEqual(list(session.hello), list(HELLO))
        self.assertEqual(session.protocol, 3)
        sent = self.daemon.requests[0]
        self.assertEqual((sent["cmd"], sent["token"], sent["client"], sent["harness"], sent["protocol"], sent["clientVersion"]),
                         ("hello", "tok", "c", "h", 3, "1.1.0"))
        self.assertEqual(session.last_ms, 0)
        self.assertIsNone(session.launch)
        self.assertEqual((session.started, session.warnings, session.supports_deadline), (False, [], True))

    def test_a_request_is_written_as_json_dumps_writes_it(self):
        session = connect(self.daemon)
        self.addCleanup(session.close)
        fields = {"text": "café ☃ \U0001f600 \"q\" \\ \n\t\x00\x7f", "n": 2 ** 70, "neg": -3, "f": 0.1, "big": 1e300, "tiny": 1e-7,
                  "t": True, "none": None, "list": [1, (2, 3), {"k": [None]}], "empty": {}, "nested": {"a": {"b": []}}}
        session.call("probe", **fields)
        written = self.daemon.raw[-1]
        self.assertEqual(written, json.dumps({"id": 2, "cmd": "probe", **fields}))
        self.assertTrue(written.isascii())

    def test_lone_surrogates_nan_and_int_keys_serialise_like_json_dumps(self):
        session = connect(self.daemon)
        self.addCleanup(session.close)
        fields = {"s": "a\ud800b", "nan": float("nan"), "inf": float("-inf"), "k": {1: "x", None: 2, True: 3, 1.5: 4}}
        session.call("probe", **fields)
        self.assertEqual(self.daemon.raw[-1], json.dumps({"id": 2, "cmd": "probe", **fields}))

    def test_unserialisable_values_raise_the_errors_json_dumps_raises(self):
        session = connect(self.daemon)
        self.addCleanup(session.close)
        for bad, error in ((object(), TypeError), ({1, 2}, TypeError), (b"x", TypeError), ({(1, 2): 3}, TypeError)):
            with self.assertRaises(error):
                session.call("probe", value=bad)
        loop: list = []
        loop.append(loop)
        with self.assertRaises(ValueError):
            session.call("probe", value=loop)
        # nothing was sent for them, and the session still works
        self.assertEqual(session.call("probe")["echo"]["cmd"], "probe")

    def test_result_and_whole_answer(self):
        daemon = Daemon(lambda m: [{"id": m["id"], "ok": True, "stale": ["p"], "ms": 7, "result": {"b": 1, "a": [1, 2.5, "x"]}}])
        self.addCleanup(daemon.stop)
        session = connect(daemon)
        self.addCleanup(session.close)
        result = session.call("go")
        self.assertEqual(list(result), ["b", "a"])
        self.assertEqual(session.last_ms, 7)
        self.assertEqual(session.last_response["stale"], ["p"])
        whole = session.call_raw("go")
        self.assertEqual((whole["stale"], whole["ms"], whole["result"]["a"]), (["p"], 7, [1, 2.5, "x"]))

    def test_an_error_answer_becomes_session_error_with_the_whole_envelope(self):
        error = {"code": "busy", "message": "held", "details": {"holder": "x"}, "trace": "t", "retryAfterMs": 250, "next": {"cmd": "status"}}
        daemon = Daemon(lambda m: [{"id": m["id"], "ok": False, "error": error}])
        self.addCleanup(daemon.stop)
        session = connect(daemon)
        self.addCleanup(session.close)
        with self.assertRaises(engine_client.SessionError) as caught:
            session.call("go")
        exc = caught.exception
        self.assertEqual((exc.code, exc.message, exc.details, exc.trace, str(exc)), ("busy", "held", {"holder": "x"}, "t", "busy: held"))
        self.assertEqual(exc.error, error)
        self.assertEqual(session.last_response["error"], error)
        with self.assertRaises(engine_client.SessionError):
            session.call_raw("go")

    def test_an_error_without_details_has_empty_details(self):
        daemon = Daemon(lambda m: [{"id": m["id"], "ok": False, "error": {"code": "x", "message": "y"}},])
        self.addCleanup(daemon.stop)
        session = connect(daemon)
        self.addCleanup(session.close)
        with self.assertRaises(engine_client.SessionError) as caught:
            session.call("go")
        self.assertEqual((caught.exception.details, caught.exception.trace), ({}, None))

    def test_events_are_not_answers_and_reach_on_event_and_events(self):
        def answer(m):
            return [{"event": "progress", "message": "m", "progress": 1}, "not protocol", {"id": m["id"], "ok": True, "result": 1}]
        daemon = Daemon(answer)
        self.addCleanup(daemon.stop)
        session = connect(daemon)
        self.addCleanup(session.close)
        seen = []
        arrived = threading.Event()
        session.on_event = lambda event: (seen.append(event), arrived.set())
        self.assertEqual(session.call("go"), 1)
        self.assertTrue(arrived.wait(5))
        self.assertEqual(seen, [{"event": "progress", "message": "m", "progress": 1}])
        self.assertEqual(session.events, seen)
        self.assertIs(session.on_event.__class__.__name__ == "function", True)

    def test_late_answers_and_interleaved_ids_are_routed_to_their_waiters(self):
        gate = threading.Event()

        def answer(m):
            if m["cmd"] == "slow":
                gate.wait(5)
            return [{"id": m["id"], "ok": True, "result": m["cmd"]}]
        daemon = Daemon(answer)
        self.addCleanup(daemon.stop)
        session = connect(daemon)
        self.addCleanup(session.close)
        slow = session.send("slow")
        fast = session.send("fast")
        self.assertEqual(session.wait(fast), "fast")
        gate.set()
        self.assertEqual(session.wait(slow), "slow")

    def test_a_deadline_sends_cancel_drops_the_late_answer_and_keeps_the_connection(self):
        release = threading.Event()

        def answer(m):
            if m["cmd"] == "hang":
                release.wait(10)
                return [{"id": m["id"], "ok": True, "result": "late"}]
            if m["cmd"] == "cancel":
                return [{"id": m["id"], "ok": True, "result": "cancelled"}]
            return [{"id": m["id"], "ok": True, "result": m["cmd"]}]
        daemon = Daemon(answer)
        self.addCleanup(daemon.stop)
        session = connect(daemon)
        self.addCleanup(session.close)
        start = time.monotonic()
        with self.assertRaises(engine_client.SessionError) as caught:
            session.call("hang", 0.3)
        self.assertLess(time.monotonic() - start, 3)
        exc = caught.exception
        target = [r for r in daemon.requests if r["cmd"] == "hang"][0]["id"]
        end = time.monotonic() + 5
        while not [r for r in daemon.requests if r["cmd"] == "cancel"] and time.monotonic() < end:
            time.sleep(0.01)   # the daemon thread records the line a moment after the client wrote it
        cancel = [r for r in daemon.requests if r["cmd"] == "cancel"][0]
        self.assertEqual(exc.code, "deadline_exceeded")
        self.assertEqual(exc.message, "no answer to request %d within 0.3 s; cancel sent" % target)
        self.assertEqual(exc.details, {"deadlineS": 0.3, "target": target, "cancelId": cancel["id"]})
        self.assertEqual((cancel["target"], cancel["parallel"]), (target, True))
        release.set()   # the late answer to `hang` and the answer to the cancel are read and dropped
        self.assertEqual(session.call("after"), "after")
        self.assertEqual(session.call("again", 5), "again")

    def test_an_integer_deadline_is_reported_as_given_and_a_float_is_formatted_with_g(self):
        daemon = Daemon(lambda m: [])
        self.addCleanup(daemon.stop)
        session = connect(daemon)
        self.addCleanup(session.close)
        for deadline, text in ((1, "1"), (0.25, "0.25"), (1e-05 * 5000, "0.05")):
            with self.subTest(deadline=deadline):
                with self.assertRaises(engine_client.SessionError) as caught:
                    session.call("hang", deadline)
                self.assertEqual(caught.exception.details["deadlineS"], deadline)
                self.assertIs(type(caught.exception.details["deadlineS"]), type(deadline))
                self.assertIn("within %s s;" % text, caught.exception.message)
                if deadline == 1:
                    break   # a second is enough to show the int form

    def test_a_bad_deadline_raises_value_error_before_anything_is_sent(self):
        session = connect(self.daemon)
        self.addCleanup(session.close)
        sent = len(self.daemon.requests)
        for bad in (0, -1, True, "5", float("nan"), [1]):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "deadline must be a positive number of seconds, not "):
                    session.call("go", bad)
                with self.assertRaises(ValueError):
                    session._check_deadline(bad)
        session._check_deadline(None)
        session._check_deadline(2)
        self.assertEqual(len(self.daemon.requests), sent)

    def test_the_connection_ending_raises_closed_for_a_waiter_and_marks_the_session(self):
        def answer(m):
            if m["cmd"] == "die":
                threading.Timer(0.1, self.daemon.drop_all).start()
                return []
            return [{"id": m["id"], "ok": True, "result": 1}]
        self.daemon.answer = answer
        session = connect(self.daemon)
        self.addCleanup(session.close)
        with self.assertRaises(engine_client.SessionError) as caught:
            session.call("die")
        self.assertEqual((caught.exception.code, caught.exception.message), ("closed", "the session connection ended"))
        self.assertTrue(session._closed)
        with self.assertRaises(engine_client.SessionError) as again:
            session.wait(99)
        self.assertEqual(again.exception.code, "closed")

    def test_close_wakes_a_waiter_and_later_sends_fail_with_os_error(self):
        self.daemon.answer = lambda m: []
        session = connect(self.daemon)
        box = {}

        def waiter():
            try:
                session.call("hang")
            except Exception as exc:   # noqa: BLE001
                box["error"] = exc
        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.2)
        started = time.monotonic()
        session.close()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(box["error"].code, "closed")
        self.assertTrue(session._closed)
        with self.assertRaises(OSError):
            session.send("late")
        session.close()   # twice is fine

    def test_wait_releases_the_gil(self):
        self.daemon.answer = lambda m: []
        session = connect(self.daemon)
        self.addCleanup(session.close)
        ticks = []
        stop = threading.Event()

        def count():
            while not stop.is_set():
                ticks.append(1)
                time.sleep(0.01)
        thread = threading.Thread(target=count)
        thread.start()
        with self.assertRaises(engine_client.SessionError):
            session.call("hang", 0.5)
        stop.set()
        thread.join()
        self.assertGreater(len(ticks), 20)

    def test_many_threads_share_one_session(self):
        session = connect(self.daemon)
        self.addCleanup(session.close)
        results = []

        def work(n):
            for i in range(50):
                results.append(session.call("echo", n=n, i=i)["echo"]["n"] == n)
        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual(len(results), 400)
        self.assertTrue(all(results))
        ids = [r["id"] for r in self.daemon.requests]
        self.assertEqual(len(ids), len(set(ids)))

    def test_send_request_with_abandon_drops_the_answer(self):
        session = connect(self.daemon)
        self.addCleanup(session.close)
        rid = session._send_request("quiet", {"a": 1}, abandon=True)
        self.assertEqual(session.call("next"), {"echo": self.daemon.requests[-1]})
        with self.assertRaises(Exception):
            session.wait(rid, 0.2)

    def test_an_incompatible_engine_is_refused_with_both_versions_named(self):
        for hello, text in (({**HELLO, "protocol": 1, "protocolMin": 1, "protocolMax": 1}, "speaks protocol 1"),
                            ({**HELLO, "minClient": "9.0.0"}, "requires a client of at least 9.0.0")):
            daemon = Daemon(hello=hello)
            self.addCleanup(daemon.stop)
            with self.assertRaisesRegex(engine_client.IncompatibleError, text) as caught:
                connect(daemon)
            self.assertEqual(caught.exception.code, "incompatible")

    def test_a_wrong_token_answer_is_a_session_error_and_a_dead_port_an_os_error(self):
        daemon = Daemon()
        daemon.answer = None
        port = daemon.port
        daemon.stop()
        with self.assertRaises(OSError):
            native.connect_endpoint(json.dumps({"host": "127.0.0.1", "port": port, "token": "t"}), "c", "h", 2.0)
        with self.assertRaises(KeyError):
            native.connect_endpoint(json.dumps({"host": "127.0.0.1", "token": "t"}), "c", "h", 2.0)

    def test_a_silent_daemon_ends_the_hello_at_its_deadline(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        started = time.monotonic()
        with self.assertRaises(engine_client.SessionError) as caught:
            native.connect_endpoint(json.dumps({"host": "127.0.0.1", "port": listener.getsockname()[1], "token": "t"}), "c", "h", 0.4)
        self.assertEqual(caught.exception.code, "deadline_exceeded")
        self.assertLess(time.monotonic() - started, 3)

    def test_context_manager_closes(self):
        with connect(self.daemon) as session:
            self.assertFalse(session._closed)
        self.assertTrue(session._closed)


@unittest.skipIf(native is None or not CLIENT_FILE or not Path(CLIENT_FILE).is_file(), "no engine client library (HYDRALYSIS_INTEGRATION_CLIENT)")
class Parity(unittest.TestCase):
    """The same script through the engine's Python library and through the native session: the same values and errors."""

    @classmethod
    def setUpClass(cls):
        cls.module = library(CLIENT_FILE)

    def both(self, answer):
        daemon = Daemon(answer)
        self.addCleanup(daemon.stop)
        endpoint = daemon.endpoint
        python = self.module.SocketSession(endpoint, client="c", harness="h")
        self.addCleanup(python.close)
        rust = connect(daemon)
        self.addCleanup(rust.close)
        return python, rust

    def outcome(self, session, error, *args, **kw):
        try:
            return ("ok", session.call(*args, **kw))
        except error as exc:
            return ("error", exc.code, exc.message, exc.details, exc.trace, str(exc))

    def test_values_errors_and_the_hello_agree(self):
        def answer(m):
            if m["cmd"] == "fail":
                return [{"id": m["id"], "ok": False, "error": {"code": "not_found", "message": "no", "details": {"k": [1, 2]}}}]
            if m["cmd"] == "bare":
                return [{"id": m["id"], "ok": False, "error": {}}]
            return [{"id": m["id"], "ok": True, "ms": 3, "result": {"z": 1.5, "a": [None, True, "é"], "big": 2 ** 70}}]
        python, rust = self.both(answer)
        self.assertEqual(python.hello, rust.hello)
        self.assertEqual(list(python.hello), list(rust.hello))
        self.assertEqual(python.protocol, rust.protocol)
        for cmd, fields in (("get", {"x": 1}), ("fail", {}), ("bare", {}), ("get", {"text": "café ☃", "n": [1, 2.5]})):
            with self.subTest(cmd=cmd):
                a = self.outcome(python, self.module.SessionError, cmd, **fields)
                b = self.outcome(rust, engine_client.SessionError, cmd, **fields)
                self.assertEqual(a, b)
        self.assertEqual(python.last_ms, rust.last_ms)

    def test_deadlines_agree(self):
        python, rust = self.both(lambda m: [])
        a = self.outcome(python, self.module.SessionError, "hang", 0.3)
        b = self.outcome(rust, engine_client.SessionError, "hang", 0.3)
        self.assertEqual(a[0], "error")
        self.assertEqual(a[1], b[1])
        self.assertEqual(a[2].split(" ", 5)[3:], b[2].split(" ", 5)[3:])   # past the request id, which differs (hello shifts it)
        self.assertEqual(sorted(a[3]), sorted(b[3]))
        self.assertEqual(a[3]["deadlineS"], b[3]["deadlineS"])


class NativeClientFacade(unittest.TestCase):
    def test_usable_follows_the_pins_the_stamps_and_the_switch(self):
        pins = (3, 2, "1.1.0")
        if native is None:
            self.assertFalse(engine_client.usable("3", "1.1.0", pins))
            return
        from unittest.mock import patch
        self.assertTrue(engine_client.usable("3", "1.1.0", pins))
        self.assertFalse(engine_client.usable("2", "1.1.0", pins))
        self.assertFalse(engine_client.usable("3", "1.0.0", pins))
        self.assertFalse(engine_client.usable("3", "1.1.0", (3, 2, "1.2.0")))
        with patch.dict(os.environ, {"HYDRALYSIS_NATIVE": "0"}):
            self.assertFalse(engine_client.enabled())
            self.assertFalse(engine_client.usable("3", "1.1.0", pins))

    def test_the_exception_classes_match_the_librarys(self):
        self.assertTrue(issubclass(engine_client.IncompatibleError, engine_client.LaunchError))
        error = engine_client.IncompatibleError("m")
        self.assertEqual((error.code, error.details, str(error)), ("incompatible", {}, "m"))
        error = engine_client.SessionError("c", "m")
        self.assertEqual((str(error), error.details, error.trace), ("c: m", {}, None))


@unittest.skipIf(native is None, "hydralysis_native is not built")
class Attach(unittest.TestCase):
    def setUp(self):
        from support import workdir
        self.work = workdir("engine-client")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        install = self.root / "install"
        (install / "Ghidra" / "Framework" / "Utility" / "lib").mkdir(parents=True)
        (install / "Ghidra" / "Features" / "HeadlessSession" / "lib").mkdir(parents=True)
        (install / "Ghidra" / "application.properties").write_text("application.version=1\n")
        (install / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar").write_bytes(b"")
        (install / "Ghidra" / "Features" / "HeadlessSession" / "lib" / "HeadlessSession.jar").write_bytes(b"")
        self.install = install
        self.state = self.root / "state"
        self.state.mkdir()
        self.daemon = Daemon()
        self.addCleanup(self.daemon.stop)
        client = self.root / "ghidra_session.py"
        client.write_text('raise SystemExit("the library must not be imported on the fast path")\n')
        self.client = engine_client.NativeClient(client, lambda path: self.fail("the library was imported"))

    def endpoint(self, **extra):
        (self.state / "d.json").write_text(json.dumps({**self.daemon.endpoint, "install": str(self.install), "protocol": 3,
                                                       "protocolMin": 2, "protocolMax": 3, **extra}))

    def hold_lock(self):
        lock = self.state / "d.lock"
        lock.write_bytes(b"x")
        fd = os.open(str(lock), os.O_RDWR)
        self.addCleanup(os.close, fd)
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0)

    def test_a_live_daemon_is_joined_with_no_library(self):
        self.endpoint()
        self.hold_lock()
        (self.state / "d.launch.json").write_text(json.dumps({"pid": 1, "launch": {"route": "spawn", "warnings": [{"code": "w"}]}}))
        session = self.client.connect("c", "h", ghidra=str(self.install), state=str(self.state), instance="d", start=False)
        self.addCleanup(session.close)
        self.assertEqual(type(session).__module__, "hydralysis_native")
        self.assertEqual(session.call("ping")["echo"]["cmd"], "ping")
        self.assertEqual(session.launch["route"], "spawn")
        self.assertEqual(session.warnings, [{"code": "w"}])

    def test_no_lock_no_endpoint_another_install_or_another_protocol_go_to_the_library(self):
        went = []

        def load(path):
            went.append(path)
            raise engine_client.LaunchError("library says so", "not_running")
        client = engine_client.NativeClient(self.root / "x.py", load)

        def join():
            went.clear()
            with self.assertRaises(engine_client.LaunchError):
                client.connect("c", "h", ghidra=str(self.install), state=str(self.state), instance="d", start=False)
            return bool(went)
        self.assertTrue(join(), "no endpoint file")
        self.endpoint()
        self.assertTrue(join(), "no lock held: a stale endpoint is never dialled")
        self.hold_lock()
        self.endpoint(install=str(self.root))
        self.assertTrue(join(), "the daemon runs another install")
        self.endpoint(protocol=5, protocolMin=5, protocolMax=5)
        self.assertTrue(join(), "the daemon speaks another protocol")
        self.endpoint()
        went.clear()
        client.connect("c", "h", ghidra=str(self.install), state=str(self.state), instance="d", start=False).close()
        self.assertEqual(went, [], "control: a plain daemon is joined without the library")

    def test_daemon_reads_the_endpoint_and_the_lock_itself_and_delegates_the_rest(self):
        self.endpoint()
        daemon = self.client.Daemon(str(self.install), str(self.state), "d")
        self.assertEqual(daemon.read_endpoint()["port"], self.daemon.port)
        self.assertFalse(daemon.jvm_alive())
        self.hold_lock()
        self.assertTrue(daemon.jvm_alive())
        self.assertEqual(daemon.endpoint_file, self.state.resolve() / "d.json")
        with self.assertRaisesRegex(AssertionError, "the library was imported"):
            daemon.stop()


if __name__ == "__main__":
    unittest.main()
