"""MCP request handling: lanes sized from the granted CPUs, long engine tools apart from short ones, cancellation that
reaches the engine wait, arrival order inside a lane, and the runtime worker's concurrent accept (H5, H9)."""

from __future__ import annotations

import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import unittest
import uuid
from unittest.mock import patch

import fakehydra
from hydralysis import cancel, hydra, mcp, runtime_ipc
from hydralysis.mcp import ENGINE_TOOLS, LONG_TOOLS, Lane, Server, lane_sizes
from hydralysis.runtime_worker import RequestGate
from test_deadline import Base
from test_mcp_transport import IdOutput, request


def small(fast=(1, 2), engine=(2, 2), long=(1, 1)):
    return {"fast": Lane("fast", *fast), "engine": Lane("engine", *engine), "long": Lane("long", *long)}


class QueueInput:
    """A stdin the test feeds one message at a time; `close()` is EOF."""

    def __init__(self):
        self.lines: queue.Queue = queue.Queue()

    def put(self, message):
        self.lines.put(json.dumps(message).encode("utf-8") + b"\n")

    def close(self):
        self.lines.put(b"")

    def readline(self, *args):
        return self.lines.get(timeout=20)


def cancelled(ident, reason="user abort"):
    return {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": ident, "reason": reason}}


class Live(unittest.TestCase):
    def start(self, fake, lanes):
        stdin, output = QueueInput(), IdOutput()
        patcher = patch("hydralysis.mcp.call", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        server = threading.Thread(target=Server(lanes).serve, args=(stdin, output), daemon=True)
        server.start()
        self.addCleanup(lambda: (stdin.close(), server.join(10)))
        return stdin, output, server


class Sizing(unittest.TestCase):
    def test_lanes_follow_the_granted_cpus_and_never_drop_below_the_0_6_0_budget(self):
        previous = None
        for cpus in (1, 2, 4, 8, 16, 24, 32, 64, 256):
            lanes = lane_sizes(cpus)
            for lane in lanes.values():
                self.assertGreaterEqual(lane.workers, 4)
                self.assertGreaterEqual(lane.outstanding, 8)
            # Engine lanes: every accepted call has its own thread (nothing queues behind a blocked socket wait).
            self.assertEqual(lanes["engine"].workers, lanes["engine"].outstanding)
            self.assertEqual(lanes["long"].workers, lanes["long"].outstanding)
            if previous is not None:
                for name in lanes:
                    self.assertGreaterEqual(lanes[name].outstanding, previous[name].outstanding)
            previous = lanes
        self.assertEqual(lane_sizes(4)["engine"].outstanding, 8)
        self.assertEqual(lane_sizes(24)["engine"].outstanding, 24)
        self.assertEqual(lane_sizes(256)["fast"].workers, 16)

    def test_the_engine_lanes_never_admit_more_than_the_engines_parallel_limit(self):
        # hydra.4: every engine call of the process shares one connection; the engine refuses request 33 as BUSY.
        self.assertEqual(mcp.ENGINE_PARALLEL_MAX, 32)
        for cpus in range(1, 1025):
            lanes = lane_sizes(cpus)
            self.assertLessEqual(lanes["engine"].outstanding + lanes["long"].outstanding, mcp.ENGINE_PARALLEL_MAX, cpus)

    def test_the_count_is_the_processes_granted_cpus_not_the_machines(self):
        with patch("hydralysis.mcp._windows_granted_cpus", return_value=None), \
                patch("os.process_cpu_count", return_value=3), patch("os.cpu_count", return_value=64):
            self.assertEqual(mcp.granted_cpus(), 3)
            self.assertEqual(lane_sizes()["fast"].workers, 4)
        with patch("hydralysis.mcp._windows_granted_cpus", return_value=None), \
                patch("os.process_cpu_count", return_value=None), patch("os.cpu_count", return_value=None), \
                patch("os.sched_getaffinity", create=True, return_value=set()):
            self.assertEqual(mcp.granted_cpus(), 1)

    def test_python_cpu_count_wins_when_set(self):
        with patch.dict("os.environ", {"PYTHON_CPU_COUNT": "3"}), patch("os.process_cpu_count", return_value=3), \
                patch("hydralysis.mcp._windows_granted_cpus", return_value=64):
            self.assertEqual(mcp.granted_cpus(), 3)

    @unittest.skipUnless(sys.platform == "win32", "the Windows affinity mask")
    def test_a_process_limited_by_affinity_gets_its_granted_cpus_on_windows(self):
        # os.process_cpu_count() ignores the affinity mask on Windows: a child limited to 2 CPUs must still see 2.
        if (os.cpu_count() or 1) < 3:
            self.skipTest("needs at least 3 CPUs")
        child = (
            "import ctypes, os, sys\n"
            "k = ctypes.WinDLL('kernel32')\n"
            "k.GetCurrentProcess.restype = ctypes.c_void_p\n"
            "k.SetProcessAffinityMask.argtypes = (ctypes.c_void_p, ctypes.c_size_t)\n"
            "assert k.SetProcessAffinityMask(k.GetCurrentProcess(), 3)\n"
            "from hydralysis import mcp\n"
            "print(mcp.granted_cpus(), mcp.lane_sizes()['engine'].outstanding)\n")
        env = {key: value for key, value in os.environ.items() if key != "PYTHON_CPU_COUNT"}
        env["PYTHONPATH"] = os.pathsep.join(path for path in sys.path if path)
        out = subprocess.run([sys.executable, "-c", child], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.split(), ["2", "8"])

    def test_a_lane_needs_at_least_one_worker_and_no_more_workers_than_slots(self):
        with self.assertRaises(ValueError):
            Lane("x", 0, 1)
        with self.assertRaises(ValueError):
            Lane("x", 3, 2)


class Separation(Live):
    def test_saturated_long_lane_leaves_short_engine_tools_running(self):
        release = threading.Event()
        entered = []

        def fake(name, arguments):
            if name in LONG_TOOLS:
                entered.append(arguments["tag"])
                release.wait(10)
            return "%s:%s" % (name, arguments["tag"])

        stdin, output, server = self.start(fake, small(long=(2, 2)))
        self.addCleanup(release.set)
        for i in range(3):
            stdin.put(request("r%d" % i, "tools/call", {"name": "ghidra_run", "arguments": {"tag": "r%d" % i}}))
        for name in ("ghidra_query", "job", "runtime", "backend"):
            stdin.put(request(name, "tools/call", {"name": name, "arguments": {"tag": name}}))
        self.assertTrue(output.wait_for({"r2", "ghidra_query", "job", "runtime", "backend"}, 5),
                        "short engine tools waited behind long ones")
        busy = output.reply("r2")["result"]
        self.assertTrue(busy["isError"])
        self.assertEqual(busy["structuredContent"]["lane"], "long")
        self.assertEqual(busy["structuredContent"]["outstanding"], 2)
        self.assertEqual(output.ids() & {"r0", "r1"}, set())
        self.assertEqual(sorted(entered), ["r0", "r1"])
        release.set()
        self.assertTrue(output.wait_for({"r0", "r1"}, 5))
        self.assertEqual(output.text("r0"), "ghidra_run:r0")

    def test_every_accepted_engine_call_starts_at_once(self):
        release = threading.Event()
        started = threading.Semaphore(0)

        def fake(name, arguments):
            started.release()
            release.wait(10)
            return name

        stdin, output, server = self.start(fake, small(engine=(3, 3)))
        self.addCleanup(release.set)
        for i in range(3):
            stdin.put(request("q%d" % i, "tools/call", {"name": "ghidra_query", "arguments": {}}))
        for _ in range(3):
            self.assertTrue(started.acquire(timeout=5), "an accepted engine call waited in a queue")
        release.set()
        self.assertTrue(output.wait_for({"q0", "q1", "q2"}, 5))


class Cancellation(Live):
    def test_a_running_call_is_woken_gets_no_reply_and_frees_its_slot(self):
        entered = threading.Event()
        seen = []

        def fake(name, arguments):
            if arguments.get("tag") == "slow":
                token = cancel.current()
                woke = threading.Event()
                token.add(woke.set)
                entered.set()
                seen.append(woke.wait(10))
                seen.append(token.reason)
                return "late answer"
            return "%s:%s" % (name, arguments.get("tag"))

        stdin, output, server = self.start(fake, small(engine=(1, 1)))
        stdin.put(request(7, "tools/call", {"name": "ghidra_query", "arguments": {"tag": "slow"}}))
        self.assertTrue(entered.wait(5))
        stdin.put(cancelled("7"))           # another id: "7" is not 7
        stdin.put(request("p1", "ping"))
        self.assertTrue(output.wait_for({"p1"}, 5))
        self.assertEqual(seen, [], "a cancel of another id reached the call")
        stdin.put(cancelled(7))
        self.assertTrue(fakehydra_until(lambda: len(seen) == 2))
        # The lane has one slot: a call is accepted again once the cancelled call has freed it.
        accepted = None
        for attempt in range(50):
            ident = "next%d" % attempt
            stdin.put(request(ident, "tools/call", {"name": "job", "arguments": {"tag": ident}}))
            self.assertTrue(output.wait_for({ident}, 5))
            if "Server busy" not in output.text(ident):
                accepted = ident
                break
            time.sleep(0.02)
        self.assertEqual(output.text(accepted), "job:%s" % accepted)
        stdin.put(request("p2", "ping"))
        stdin.close()
        server.join(10)
        self.assertFalse(server.is_alive())
        self.assertEqual(seen, [True, "user abort"])
        self.assertNotIn(7, output.ids(), "MCP: no response for a cancelled request")
        self.assertIn("p2", output.ids())

    def test_a_queued_call_cancelled_before_it_starts_never_runs(self):
        release = threading.Event()
        calls = []

        def fake(name, arguments):
            calls.append(arguments["tag"])
            if arguments["tag"] == "f0":
                release.wait(10)
            return arguments["tag"]

        stdin, output, server = self.start(fake, small(fast=(1, 3)))
        stdin.put(request("f0", "tools/call", {"name": "disasm", "arguments": {"tag": "f0"}}))
        stdin.put(request("f1", "tools/call", {"name": "disasm", "arguments": {"tag": "f1"}}))
        stdin.put(request("f2", "tools/call", {"name": "disasm", "arguments": {"tag": "f2"}}))
        stdin.put(cancelled("f1"))
        stdin.put(request("p", "ping"))
        self.assertTrue(output.wait_for({"p"}, 5))
        release.set()
        stdin.close()
        server.join(10)
        self.assertEqual(calls, ["f0", "f2"])
        self.assertEqual(output.ids(), {"f0", "f2", "p"})

    def test_malformed_cancels_are_ignored(self):
        stdin, output, server = self.start(lambda name, arguments: "ok", small())
        stdin.put({"jsonrpc": "2.0", "method": "notifications/cancelled"})
        stdin.put({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": [1]}})
        stdin.put({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "nobody"}})
        stdin.put(request("a", "tools/call", {"name": "disasm", "arguments": {}}))
        stdin.close()
        server.join(10)
        self.assertEqual(output.ids(), {"a"})


class Ordering(Live):
    def test_calls_of_one_lane_start_in_arrival_order_and_control_replies_keep_theirs(self):
        order = []
        guard = threading.Lock()

        def fake(name, arguments):
            with guard:
                order.append(arguments["tag"])
            return arguments["tag"]

        stdin, output, server = self.start(fake, small(fast=(1, 8)))
        tags = ["f%d" % i for i in range(8)]
        for tag in tags:
            stdin.put(request(tag, "tools/call", {"name": "strings", "arguments": {"tag": tag}}))
        for i in range(3):
            stdin.put(request("ping%d" % i, "ping"))
        stdin.close()
        server.join(10)
        self.assertEqual(order, tags)
        pings = [r["id"] for r in output.replies() if str(r["id"]).startswith("ping")]
        self.assertEqual(pings, ["ping0", "ping1", "ping2"])
        self.assertEqual(output.ids(), set(tags) | set(pings))


class EngineWaits(Base):
    """A cancel reaches the engine wait: the pooled attempt (hydra.2/3), the plain call (hydra.4) and the pool wait."""

    def cancel_after(self, token, seconds):
        timer = threading.Timer(seconds, token.cancel)
        timer.start()
        self.addCleanup(timer.cancel)

    def test_a_cooperative_request_ends_on_the_clients_cancel_long_before_its_deadline(self):
        self.hold("script", cooperative=True)
        token = cancel.Token()
        started = time.monotonic()
        with self.assertRaises(hydra.EngineError) as raised, cancel.scope(token):
            with self.pool.attempt(30.0) as entry:
                entry.grace_s = 2.0
                program = self.program(entry)
                self.cancel_after(token, 0.2)
                entry.call("script", script="Other.java", program=program["key"], args=["{}"])
        self.assertEqual(raised.exception.code, "cancelled")
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertEqual(len(self.daemon.cancels), 1, "cancel is sent to the engine")
        self.assertEqual(self.registry.count("user"), 0)
        self.assertEqual(self.pool.live(), 1, "the answered request leaves the entry usable")

    def test_a_request_that_ignores_cancel_is_abandoned_after_the_grace_with_code_cancelled(self):
        event = self.hold("script")
        token = cancel.Token()
        with self.assertRaises(hydra.EngineError) as raised, cancel.scope(token):
            with self.pool.attempt(30.0) as entry:
                entry.grace_s = 0.2
                program = self.program(entry)
                self.cancel_after(token, 0.1)
                entry.call("script", script="Other.java", program=program["key"], args=["{}"])
        self.assertEqual(raised.exception.code, "cancelled")
        self.assertTrue(raised.exception.details["connection_abandoned"])
        self.assertEqual(self.registry.count("user"), 1)
        self.assertEqual(self.daemon.close_log, [])
        event.set()
        self.assertTrue(fakehydra_until(lambda: self.registry.count("user") == 0))

    def test_without_a_cancel_the_attempt_behaves_as_before(self):
        event = self.hold("script")
        with self.assertRaises(hydra.DeadlineError) as raised, cancel.scope(cancel.Token()):
            with self.pool.attempt(0.3) as entry:
                entry.grace_s = 0.1
                program = self.program(entry)
                entry.call("script", script="Other.java", program=program["key"], args=["{}"])
        self.assertEqual(raised.exception.code, "deadline_exceeded")
        event.set()

    def test_a_wait_for_a_pool_entry_ends_on_cancel(self):
        self.pool.size = 1
        held = self.pool.acquire(30.0)
        self.addCleanup(self.pool.release, held)
        token = cancel.Token()
        self.cancel_after(token, 0.2)
        started = time.monotonic()
        with self.assertRaises(hydra.EngineError) as raised, cancel.scope(token):
            self.pool.acquire(30.0)
        self.assertEqual(raised.exception.code, "cancelled")
        self.assertLess(time.monotonic() - started, 3.0)


def fakehydra_until(condition, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


class PlainSession:
    """A hydra.4-style session: call = wait(send(...)); `cancel` ends the waited request."""

    def __init__(self):
        self.sent = []
        self.ended = {}
        self.guard = threading.Lock()

    def send(self, command, **fields):
        with self.guard:
            self.sent.append((command, fields))
            rid = len(self.sent)
            if command == "cancel":
                self.ended[fields["target"]].set()
            else:
                self.ended[rid] = threading.Event()
        return rid

    def wait(self, rid, deadline=None):
        if not self.ended[rid].wait(10):
            raise AssertionError("never cancelled")
        raise RuntimeError("cancelled")

    def call(self, command, **fields):
        return self.wait(self.send(command, **fields))


def _library():
    import importlib.util
    from pathlib import Path
    for root in (Path(__file__).resolve().parents[3] / "hydra-engine", Path("D:/Projects/Hydra/hydra-engine")):
        path = root / "Ghidra/Features/HeadlessSession/support/ghidra_session.py"
        if path.exists():
            spec = importlib.util.spec_from_file_location("ghidra_session_for_test", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise unittest.SkipTest("the engine's ghidra_session library is not available")


def _ScriptedSession(module):
    """The library's _Base over an in-memory channel: a `cancel` makes the engine answer both the cancel and its
    target (with `cancelled`)."""

    class Scripted(module._Base):
        supports_deadline = True

        def __init__(self):
            super().__init__()
            self.lines = []
            self.inbox = queue.Queue()

        def _send(self, line):
            self.lines.append(line)
            message = json.loads(line)
            if message["cmd"] == "cancel":
                self.inbox.put(json.dumps({"id": message["id"], "ok": True, "result": {"cancelled": 1}}))
                self.inbox.put(json.dumps({"id": message["target"], "ok": False,
                                           "error": {"code": "cancelled", "message": "cancelled"}}))

        def _recv(self, timeout=None):
            try:
                return self.inbox.get(timeout=timeout if timeout is not None else 30)
            except queue.Empty:
                return None if timeout is not None else ""

    return Scripted()


class PlainCall(unittest.TestCase):
    def test_the_plain_call_sends_cancel_for_its_request_id(self):
        session = PlainSession()
        token = cancel.Token()
        threading.Timer(0.1, token.cancel).start()
        with cancel.scope(token), self.assertRaisesRegex(RuntimeError, "cancelled"):
            hydra._cancellable_call(session, "script", {"client": "t", "parallel": True}, {"script": "X.java", "deadline": 5})
        self.assertEqual(session.sent[0], ("script", {"client": "t", "parallel": True, "script": "X.java"}))
        # Sent the way the library's deadline sends it: parallel and with the request's labels.
        self.assertEqual(session.sent[1], ("cancel", {"target": 1, "parallel": True, "client": "t"}))

    def test_a_request_the_engine_does_not_stop_returns_after_the_grace(self):
        session = PlainSession()
        session.wait = lambda rid, deadline=None: time.sleep(30)   # the engine never answers
        token = cancel.Token()
        threading.Timer(0.1, token.cancel).start()
        started = time.monotonic()
        with cancel.scope(token), self.assertRaises(hydra.EngineError) as raised:
            hydra._cancellable_call(session, "script", {}, {}, grace_s=0.2)
        self.assertEqual(raised.exception.code, "cancelled")
        self.assertLess(time.monotonic() - started, 5.0, "the slot is held until the engine answers")

    def test_the_cancel_callback_does_no_engine_io_on_the_cancelling_thread(self):
        # The token fires on the MCP stdin reader thread; a send blocked on the socket's write lock must not block it.
        session = PlainSession()
        blocked = threading.Event()
        send = session.send

        def slow_send(command, **fields):
            if command == "cancel":
                blocked.wait(5)
            return send(command, **fields)

        session.send = slow_send
        token = cancel.Token()

        def caller():
            try:
                with cancel.scope(token):
                    hydra._cancellable_call(session, "script", {}, {})
            except Exception:   # noqa: BLE001
                pass

        thread = threading.Thread(target=caller, daemon=True)
        thread.start()
        time.sleep(0.1)
        started = time.monotonic()
        token.cancel()
        self.assertLess(time.monotonic() - started, 0.5, "cancel() waited for engine I/O")
        blocked.set()
        thread.join(10)

    def test_no_answer_is_left_in_the_sessions_pending_map(self):
        # With the engine library's own matching (_Base.wait), the cancel's answer is dropped (abandoned) and the
        # cancelled request's late answer is consumed by the waiting thread.
        module = _library()
        session = _ScriptedSession(module)
        token = cancel.Token()
        threading.Timer(0.1, token.cancel).start()
        with cancel.scope(token), self.assertRaises(module.SessionError) as raised:
            hydra._cancellable_call(session, "script", {"client": "t", "parallel": True}, {}, grace_s=2.0)
        self.assertEqual(raised.exception.code, "cancelled")
        self.assertTrue(fakehydra_until(lambda: not session._pending and not session._abandoned))
        self.assertEqual(session._pending, {})
        self.assertEqual(session._abandoned, set())
        cancel_line = [line for line in session.lines if '"cancel"' in line][0]
        self.assertEqual(json.loads(cancel_line), {"id": 2, "cmd": "cancel", "target": 1, "parallel": True, "client": "t"})


    def test_without_a_token_it_is_session_call_unchanged(self):
        calls = []

        class Stub:
            def call(self, command, **fields):
                calls.append((command, fields))
                return "value"

        self.assertEqual(hydra._cancellable_call(Stub(), "hello", {"a": 1}, {"b": 2}), "value")
        self.assertEqual(calls, [("hello", {"a": 1, "b": 2})])

    def test_an_already_cancelled_request_is_never_sent(self):
        session = PlainSession()
        token = cancel.Token()
        token.cancel()
        with cancel.scope(token), self.assertRaises(hydra.EngineError) as raised:
            hydra._cancellable_call(session, "script", {}, {})
        self.assertEqual(raised.exception.code, "cancelled")
        self.assertEqual(session.sent, [])


class RuntimeAccept(unittest.TestCase):
    """H9: the worker serves `status` beside a running request; other actions stay one at a time."""

    def serve(self, handler, connections):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(5)
        endpoint = {"port": listener.getsockname()[1], "token": "b" * 64}
        gate = RequestGate(endpoint["token"], handler)

        def loop():
            try:
                for _ in range(connections):
                    connection, _ = listener.accept()
                    gate.submit(connection)
            finally:
                listener.close()

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        self.addCleanup(lambda: (thread.join(5), gate.drain(5)))
        return endpoint, gate

    def ask(self, endpoint, action, results, budget=5):
        def run():
            try:
                results[action + str(len(results))] = runtime_ipc.request(endpoint, uuid.uuid4().hex, action, {}, budget)
            except Exception as exc:   # noqa: BLE001
                results[action + str(len(results))] = exc
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def test_status_is_answered_while_a_request_runs(self):
        release, entered = threading.Event(), threading.Event()

        def handler(action, args, budget):
            if action == "watch":
                entered.set()
                release.wait(10)
            return {"action": action}

        endpoint, gate = self.serve(handler, 2)
        results: dict = {}
        long = self.ask(endpoint, "watch", results)
        self.assertTrue(entered.wait(5))
        started = time.monotonic()
        status = runtime_ipc.request(endpoint, uuid.uuid4().hex, "status", {}, 5)
        self.assertLess(time.monotonic() - started, 2.0, "status waited for the running request")
        self.assertEqual(status["result"], {"action": "status"})
        release.set()
        long.join(5)

    def test_other_actions_stay_one_at_a_time(self):
        active, peak = [0], [0]
        guard = threading.Lock()

        def handler(action, args, budget):
            with guard:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.15)
            with guard:
                active[0] -= 1
            return {}

        endpoint, gate = self.serve(handler, 3)
        results: dict = {}
        threads = [self.ask(endpoint, action, results) for action in ("read", "write", "modules")]
        for thread in threads:
            thread.join(10)
        self.assertEqual(peak[0], 1)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(isinstance(value, dict) and value.get("ok") for value in results.values()), results)

    def test_the_client_sends_status_without_the_session_lock(self):
        from hydralysis import runtime
        self.assertIn("status", runtime.LOCK_FREE)
        self.assertFalse(set(runtime.MUTATING) & runtime.LOCK_FREE)

    def test_status_to_an_older_worker_takes_the_lock(self):
        # A worker of 0.6.0 serves one connection at a time: status to it must not skip the lock (it would wait in the
        # backlog, time out and retire the worker). Only a worker whose ready.json says concurrent_status skips it.
        import inspect
        from hydralysis import runtime, runtime_worker
        self.assertIn('ready.get("concurrent_status") is True', inspect.getsource(runtime.RuntimeRunner))
        self.assertIn('"concurrent_status": True', inspect.getsource(runtime_worker.main))

    def test_a_request_that_outlasts_the_idle_time_keeps_the_worker(self):
        release, entered = threading.Event(), threading.Event()

        def handler(action, args, budget):
            entered.set()
            release.wait(10)
            return {}

        endpoint, gate = self.serve(handler, 1)
        gate.touched = time.monotonic()
        results: dict = {}
        thread = self.ask(endpoint, "watch", results)
        self.assertTrue(entered.wait(5))
        time.sleep(0.4)
        self.assertFalse(gate.idle(0.2), "the worker counted itself idle while it served a request")
        release.set()
        thread.join(5)
        self.assertTrue(fakehydra_until(lambda: gate.active == 0))
        self.assertFalse(gate.idle(0.2), "the idle clock restarts when the request is answered")
        time.sleep(0.3)
        self.assertTrue(gate.idle(0.2))


if __name__ == "__main__":
    unittest.main()
