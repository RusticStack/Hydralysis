"""The protocol negotiation, the lane hint and the deadline mechanism on hydra.2/3 (PROTOCOL-3.md 7.5, 7.6; Y4a).

Against the fake daemon: the abandon helper (never a `close()` or a `shutdown` while a request is in flight), one deadline per
attempt, the two budgets, the pool entry with its context (I1 to I3), the leave gate, `QueryRunner.stop` over the entries.
The real hydra.3 cases (L, S, C, `replacement_context`, `wait_below_deadline`, `leave_gate_no_freeze`) are in
`test_engine_integration.py`-style tests gated on HYDRALYSIS_REAL_HYDRA3 and are not part of this file.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import hydra, query
from support import default_to_shared, workdir


def until(condition, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


class Negotiation(unittest.TestCase):
    def client(self, protocol, release=None):
        folder = tempfile.mkdtemp(dir=str(workdir("neg").name))
        path = Path(folder) / "ghidra_session.py"
        path.write_text('PROTOCOL = %s\nCLIENT_VERSION = "%s"\nHYDRA_RELEASE = "%s"\n' % (protocol, hydra.CLIENT_VERSION, release or hydra.RELEASE),
                        encoding="utf-8")
        return path

    def test_the_pin_is_protocol_3_and_negotiates_down_to_2(self):
        self.assertEqual((hydra.PROTOCOL, hydra.PROTOCOL_MIN), (3, 2))

    def test_a_pinned_client_must_speak_the_pinned_protocol(self):
        hydra.load_client(self.client(hydra.PROTOCOL))
        with self.assertRaisesRegex(ValueError, "speaks protocol 2"):
            hydra.load_client(self.client(2))

    def test_an_unpinned_client_of_the_released_protocol_2_engine_is_accepted_and_protocol_1_is_not(self):
        hydra.load_client(self.client(2, release="12.3-hydra.3"), allow_unpinned=True)
        hydra.load_client(self.client(3, release="12.3-hydra.4x"), allow_unpinned=True)
        with self.assertRaisesRegex(ValueError, "2 to 3"):
            hydra.load_client(self.client(1, release="12.3-hydra.1"), allow_unpinned=True)

    def test_protocol_and_capabilities_are_negotiated_from_hello(self):
        daemon = fakehydra.reset()
        engine = fakehydra.FakeEngine({})
        self.assertEqual(engine.hello()["protocol"], 2)
        real = hydra.Engine.__new__(hydra.Engine)
        real.hello = lambda: {"protocol": 3, "capabilities": {"laneHint": 1, "queueInfo": 1}}
        self.assertEqual(hydra.Engine.protocol(real), 3)
        self.assertTrue(hydra.supports(real, "laneHint"))
        real.hello = lambda: {"protocol": 2}
        self.assertEqual(hydra.Engine.protocol(real), 2)
        self.assertFalse(hydra.supports(real, "laneHint"))
        del daemon


class Mechanism(unittest.TestCase):
    """The abandon helper, the pool and the gate against the fake daemon."""

    def setUp(self):
        self.temp = workdir("deadline")
        self.addCleanup(self.temp.cleanup)
        self.daemon = fakehydra.reset()
        self.root = Path(self.temp.name)
        self.exe = self.root / "owned.exe"
        self.exe.write_bytes(b"MZ a small owned executable")
        self.digest = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.gpr = self.root / "analysed" / "Owned" / "Owned.gpr"
        self.daemon.add_project(self.gpr, {"/owned.exe": {"sha256": self.digest}})
        self.settings = {"root": str(self.root / "data"), "hydra_dir": "x", "hydra_client": "x",
                         "targets": {"owned": {"gpr": str(self.gpr), "program": "/owned.exe", "exe": str(self.exe)}}}
        query._keys.clear()
        self.registry = hydra.Registry()
        self.engine = fakehydra.FakePooledEngine(self.settings)
        self.pool = hydra.Pool(self.engine, registry=self.registry, on_retire=query.forget)
        self.release = []
        self.addCleanup(self.finish)

    def finish(self):
        for hold in self.daemon.holds.values():
            hold["event"].set()
        for event in self.release:
            event.set()

    def hold(self, command, cooperative=False, times=1):
        event = threading.Event()
        self.daemon.holds[command] = {"event": event, "cooperative": cooperative, "times": times, "timeout": 20}
        self.release.append(event)
        return event

    def runner(self):
        patcher = patch("hydralysis.hydra.Engine", fakehydra.FakePooledEngine)
        patcher.start()
        self.addCleanup(patcher.stop)
        runner = query.QueryRunner(self.settings, self.engine)
        default_to_shared(runner)
        return runner

    def ask(self, runner, **kwargs):
        return json.loads(runner.query("owned", "decompile", "0x140001000", **kwargs))

    def program(self, entry):
        return query.open_program(entry, str(self.gpr), "/owned.exe", self.digest)

    # --- the abandon helper ------------------------------------------------------------------------------------------

    def test_a_blocked_call_gets_cancel_then_is_abandoned_with_no_close_and_no_shutdown(self):
        event = self.hold("script")
        with self.assertRaises(hydra.DeadlineError) as raised:
            with self.pool.attempt(0.3) as entry:
                entry.grace_s = 0.2
                program = self.program(entry)
                entry.call("script", script="Other.java", program=program["key"], args=["{}"])
        self.assertEqual(raised.exception.code, "deadline_exceeded")
        self.assertTrue(raised.exception.details["connection_abandoned"])
        self.assertEqual(len(self.daemon.cancels), 1, "cancel is the only thing sent")
        self.assertEqual(self.registry.count("user"), 1)
        self.assertEqual(self.daemon.violations, [])
        self.assertEqual(self.daemon.close_log, [], "no close while the worker is alive")
        event.set()
        self.assertTrue(until(lambda: self.registry.count("user") == 0), "the count drops when the engine answers")
        self.assertTrue(until(lambda: len(self.daemon.close_log) == 1), "the worker's session is closed through the gate")
        self.assertEqual(self.daemon.violations, [])
        self.assertEqual(self.registry.snapshot()["closing"], [])

    def test_a_cooperative_request_ends_on_cancel_and_the_connection_is_kept(self):
        self.hold("script", cooperative=True)
        with self.assertRaises(hydra.EngineError) as raised:
            with self.pool.attempt(0.2) as entry:
                entry.grace_s = 2.0
                program = self.program(entry)
                entry.call("script", script="Other.java", program=program["key"], args=["{}"])
        self.assertEqual(raised.exception.code, "cancelled")
        self.assertEqual(self.registry.count("user"), 0)
        self.assertEqual(self.pool.live(), 1, "an answered request leaves the entry usable")

    def test_the_deadline_is_the_attempts_not_each_calls(self):
        slow = self.hold("open_program")
        started = time.monotonic()
        threading.Timer(0.4, slow.set).start()
        script = self.hold("script")
        with self.assertRaises(hydra.DeadlineError):
            with self.pool.attempt(0.6) as entry:
                entry.grace_s = 0.2
                program = self.program(entry)          # takes 0.4 of the 0.6 s
                entry.call("script", script="Other.java", program=program["key"], args=["{}"])   # has 0.2 s left, not 0.6
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.6 + 0.2 + 0.35, "one clock for the attempt: deadline plus grace, not one deadline per call")
        self.assertGreaterEqual(elapsed, 0.6 + 0.2 - 0.05)
        script.set()

    def test_a_second_request_on_a_checked_out_entry_raises(self):
        event = self.hold("script")
        with self.pool.attempt(5) as entry:
            program = self.program(entry)
            worker = threading.Thread(target=lambda: entry.call("script", script="Other.java", program=program["key"], args=["{}"]), daemon=True)
            worker.start()
            self.assertTrue(until(lambda: self.daemon.reads_in_flight == 1))
            with self.assertRaisesRegex(RuntimeError, "in flight"):
                entry.call("ping")
            event.set()
            worker.join(5)

    def test_the_budget_is_8_user_calls_then_abandoned_cap_before_anything_is_sent_and_a_probe_is_exempt(self):
        event = self.hold("script", times=100)
        for _ in range(hydra.USER_CAP):
            with self.assertRaises(hydra.DeadlineError):
                with self.pool.attempt(0.05) as entry:
                    entry.grace_s = 0.02
                    entry.call("script", script="Other.java", program="p1:/owned.exe", args=["{}"])
        self.assertEqual(self.registry.count("user"), 8)
        sent = len(self.daemon.calls)
        with self.assertRaises(hydra.DeadlineError) as raised:
            with self.pool.attempt(1) as entry:
                entry.call("ping")
        self.assertEqual(raised.exception.code, "abandoned_cap")
        self.assertNotEqual(raised.exception.code, "daemon_unhealthy")
        self.assertEqual(raised.exception.details["cap"], 8)
        self.assertEqual(len(raised.exception.details["abandoned"]), 8)
        self.assertEqual(raised.exception.next, {"cmd": "doctor"})
        self.assertEqual(len(self.daemon.calls), sent, "the ninth call is refused before anything is sent")
        self.assertEqual(self.pool.probe("ping", 1.0), {"pong": True}, "the probe is exempt from the user budget")
        event.set()
        self.assertTrue(until(lambda: self.registry.count("user") == 0))

    def test_probes_have_their_own_budget_of_3(self):
        self.hold("ping", times=100)
        for _ in range(hydra.PROBE_CAP):
            with self.assertRaises(hydra.DeadlineError) as raised:
                self.pool.probe("ping", 0.05)
            self.assertEqual(raised.exception.code, "deadline_exceeded")
        self.assertEqual(self.registry.count("probe"), 3)
        with self.assertRaises(hydra.DeadlineError) as raised:
            self.pool.probe("ping", 0.05)
        self.assertEqual(raised.exception.code, "abandoned_cap")
        self.assertEqual(self.registry.count("user"), 0)

    # --- the pool entry and its context (I1 to I3) --------------------------------------------------------------------

    def test_an_entrys_first_use_sends_both_opens_and_a_replacement_has_a_new_key(self):
        self.daemon.scoped = True
        runner = self.runner()
        self.ask(runner)
        opens = [call for call in self.daemon.calls if call[1] == "open_project"]
        self.assertEqual(len(opens), 1)
        self.ask(runner)
        self.assertEqual(len([call for call in self.daemon.calls if call[1] == "open_project"]), 1, "the entry's rows are cached")
        first = {key[0] for key in query._keys}
        self.assertEqual(len(first), 1)
        # retire the entry (a stalled call would): the next read takes a new entry, re-establishes the context, no no_project
        (entry,) = list(self.pool._idle) or list(runner._pool()._idle)
        runner._pool().release(entry, hydra.EngineError("no_program", "x"))
        self.ask(runner)
        second = {key[0] for key in query._keys}
        self.assertEqual(len(second), 1)
        self.assertFalse(first & second, "I1: a serial is never reused")
        self.assertEqual(len([call for call in self.daemon.calls if call[1] == "open_project"]), 2)

    def test_forget_of_an_entry_leaves_another_entrys_rows(self):
        a, b = self.pool.acquire(5), self.pool.acquire(5)
        self.program(a)
        self.program(b)
        self.assertEqual({key[0] for key in query._keys}, {a.key, b.key})
        query.forget(a)
        self.assertEqual({key[0] for key in query._keys}, {b.key})
        query.forget_role(self.engine)
        self.assertEqual(query._keys, {})

    def test_a_retry_after_closed_takes_another_entry(self):
        self.daemon.scoped = True
        runner = self.runner()
        self.daemon.fail_next["script"] = hydra.EngineError("closed", "the connection ended")
        answer = self.ask(runner)
        self.assertTrue(answer)
        scripts = [call for call in self.daemon.calls if call[1] == "script"]
        self.assertEqual(len(scripts), 2)
        self.assertEqual(len({key[0] for key in query._keys}), 1)
        self.assertEqual(self.daemon.violations, [])

    # --- lane hint and waits -----------------------------------------------------------------------------------------

    def test_the_lane_hint_and_the_patience_budget_only_with_the_capability(self):
        self.daemon.queue_info = True
        runner = self.runner()
        self.ask(runner)
        scripts = [call for call in self.daemon.calls if call[1] == "script"]
        self.assertEqual(scripts[-1][2]["lane"], "quick")
        self.assertEqual(scripts[-1][2]["wait"], 25_000, "min(25 s, remaining / 2) with the default deadline")
        opens = [call for call in self.daemon.calls if call[1] in ("open_project", "open_program")]
        self.assertTrue(all(call[2]["wait"] == 25_000 for call in opens))

    def test_wait_is_half_of_what_remains_below_the_patience_budget(self):
        with self.pool.attempt(10) as entry:
            program = self.program(entry)
            entry.call("script", script="Other.java", program=program["key"], args=["{}"], wait=hydra.PATIENCE_S * 1000)
        script = [call for call in self.daemon.calls if call[1] == "script"][-1]
        self.assertLessEqual(script[2]["wait"], 5000)
        self.assertGreater(script[2]["wait"], 4000)

    def test_no_lane_hint_without_the_capability(self):
        runner = self.runner()
        self.ask(runner)
        script = [call for call in self.daemon.calls if call[1] == "script"][-1]
        self.assertNotIn("lane", script[2])

    # --- the leave gate ------------------------------------------------------------------------------------------------

    def joined(self, *programs):
        entry = self.pool.acquire(5)
        entry.joined.update(programs)
        return entry

    def test_no_entry_is_closed_while_a_read_is_in_flight_on_a_program_it_joined_and_the_list_drains(self):
        entry = self.joined("p1:/a.exe")
        other = self.joined("p1:/b.exe")
        self.registry.read_begin("p1:/a.exe")
        self.assertEqual(self.registry.leave(entry), "deferred")
        self.assertEqual(self.registry.leave(other), "closed", "a read on another program does not hold it")
        self.assertEqual(self.registry.snapshot()["closing"], [entry.key])
        self.assertEqual(entry.session.closes, 0)
        self.registry.read_end("p1:/a.exe")
        self.assertEqual(entry.session.closes, 1)
        self.assertEqual(self.registry.snapshot()["closing"], [])

    def test_a_ninth_entry_in_the_closing_list_closes_the_oldest(self):
        self.registry.read_begin("p1:/a.exe")
        entries = []
        for _ in range(hydra.CLOSING_CAP + 1):
            entry = self.pool._new()
            entry.joined.add("p1:/a.exe")
            entries.append(entry)
            self.registry.leave(entry)
        self.assertEqual(entries[0].session.closes, 1)
        self.assertTrue(all(entry.session.closes == 0 for entry in entries[1:]))
        self.assertEqual(len(self.registry.snapshot()["closing"]), hydra.CLOSING_CAP)

    def test_an_entry_whose_connection_failed_is_dropped_without_a_close(self):
        entry = self.joined("p1:/a.exe")
        entry.broken = True
        self.assertEqual(self.registry.leave(entry), "dropped")
        self.assertEqual(entry.session.closes, 0)

    # --- QueryRunner.stop ------------------------------------------------------------------------------------------------

    def test_stop_releases_the_programs_of_the_entries_and_reports_released_failed_entries(self):
        self.daemon.scoped = True
        runner = self.runner()
        self.ask(runner)
        stopped = runner.stop(runner.target("owned"))
        self.assertTrue(stopped["ok"], stopped)
        self.assertEqual(len(stopped["released"]), 1)
        self.assertEqual(stopped["failed"], [])
        self.assertEqual(stopped["entries"], {"closed": 1, "deferred": 0})
        self.assertEqual(query._keys, {})
        self.assertEqual([call for call in self.daemon.calls if call[1] == "close_program"].__len__(), 1)

    def test_stop_defers_the_close_of_an_entry_with_a_read_in_flight_and_does_not_count_it_failed(self):
        self.daemon.scoped = True
        runner = self.runner()
        self.ask(runner)
        self.registry_busy = self.pool.registry
        entry = next(iter(runner._pool()._idle))
        program_key = next(iter(query._keys.values()))["key"]
        runner._pool().registry.read_begin(program_key)
        try:
            with patch.object(hydra, "DEADLINE_GRACE_S", 0.05):
                stopped = runner.stop(runner.target("owned"))
        finally:
            runner._pool().registry.read_end(program_key)
        self.assertEqual(stopped["failed"], [])
        self.assertEqual(stopped["released"], [])
        self.assertEqual(stopped["entries"], {"closed": 0, "deferred": 1})
        self.assertIn(program_key, entry.pending_close)


if __name__ == "__main__":
    unittest.main()
