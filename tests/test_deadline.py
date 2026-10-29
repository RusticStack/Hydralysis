"""The protocol negotiation, the lane hint and the deadline mechanism on hydra.2/3 (PROTOCOL-3.md 7.5, 7.6; Y4a).

Against the fake daemon: the abandon helper (never a `close()` or a `shutdown` while a request is in flight), one deadline per
attempt, the two budgets, the pool entry with its context (I1 to I3), the leave gate, `QueryRunner.stop` over the entries.
The real hydra.3 cases (L, S, C, `replacement_context`, `wait_below_deadline`, `leave_gate_no_freeze`) are in
`RealHydra3` at the end of this file: skipped unless HYDRALYSIS_REAL_HYDRA3 names an engine install (see there).
"""

from __future__ import annotations

import hashlib
import json
import os
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


class Base(unittest.TestCase):
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
        patcher = patch.object(hydra, "REGISTRY", self.registry)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.engine = fakehydra.FakePooledEngine(self.settings)
        # The production pool, unmodified: hydra.Engine.pool() wires the retire hook (I2) and the daemon-restart reset itself.
        self.pool = self.engine.pool()
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



class Mechanism(Base):
    """The abandon helper, the pool, the lane hint, the gate and `stop`."""

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

    def test_an_entry_whose_connection_failed_is_dropped_and_its_socket_freed(self):
        entry = self.joined("p1:/a.exe")
        entry.broken = True
        self.assertEqual(self.registry.leave(entry), "dropped")
        self.assertEqual(entry.session.closes, 1, "nothing is in flight on a failed connection: its socket is freed")

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


class ProductionWiring(Base):
    """The pool is `hydra.Engine.pool()` as production builds it: retired entries forget their rows (I2), and a daemon
    restart (`Engine.reset`) retires every idle entry (7.2, 7.6)."""

    def idle_entries(self, count):
        entries = [self.pool.acquire(5) for _ in range(count)]
        for entry in entries:
            self.program(entry)
        for entry in entries:
            self.pool.release(entry)
        return entries

    def test_the_production_pool_is_wired_to_forget_rows_without_any_test_wiring(self):
        self.assertIs(self.pool.on_retire, hydra._forget_rows)
        entry = self.pool.acquire(5)
        self.program(entry)
        self.assertEqual({key[0] for key in query._keys}, {entry.key})
        self.pool.release(entry, hydra.EngineError("no_program", "gone"))
        self.assertEqual(query._keys, {}, "I2: the retired entry's rows left with it")

    def test_an_abandoned_entry_forgets_its_rows_when_the_engine_answers(self):
        event = self.hold("script")
        with self.assertRaises(hydra.DeadlineError):
            with self.pool.attempt(0.2) as entry:
                entry.grace_s = 0.1
                program = self.program(entry)
                entry.call("script", script="Other.java", program=program["key"], args=["{}"])
        self.assertTrue(query._keys, "the rows stay while the request is still running")
        event.set()
        self.assertTrue(until(lambda: not query._keys), "I2: dropped once the abandoned request ended")

    def test_a_daemon_restart_retires_every_idle_entry_and_the_next_read_succeeds_first_time(self):
        first, second = self.idle_entries(2)
        self.assertEqual(len(query._keys), 2)
        self.engine.reset()
        self.assertEqual(query._keys, {}, "forget_role: every row of the role")
        self.assertTrue(first.finished and second.finished and first.session.closes == 1 and second.session.closes == 1,
                        "both idle entries retired and their sockets freed")
        self.assertEqual(self.pool.live(), 0)
        runner = self.runner()
        self.assertTrue(self.ask(runner))
        self.assertEqual(len([call for call in self.daemon.calls if call[1] == "script"]), 1, "no retry was needed")

    def test_a_checked_out_entry_returned_after_a_restart_is_retired_not_reused(self):
        (idle,) = self.idle_entries(1)
        out = self.pool.acquire(5)
        self.assertIs(out, idle)
        self.engine.reset()
        self.pool.release(out)
        self.assertEqual(self.pool.live(), 0)
        self.assertNotIn(out, self.pool._idle)
        self.assertTrue(out.finished)

    def test_two_idle_entries_whose_daemon_went_away_do_not_fail_the_read(self):
        first, second = self.idle_entries(2)
        for entry in (first, second):
            entry.session._closed = True    # what the library does when the connection ends
        runner = self.runner()
        self.assertTrue(self.ask(runner), "the read takes a fresh entry; no `closed` reaches the caller")
        self.assertEqual(self.daemon.refused_closed, 0, "no request was ever sent to a dead entry")

    def test_acquire_retiring_a_dead_entry_and_stop_do_not_deadlock(self):
        """Lock order: the pool lock is never held while `on_retire` takes the row guard, and `stop` reads the pool before it
        takes the row guard. Thread B acquires over a dead idle entry whose retirement is slow; thread A stops the target."""
        (dead,) = self.idle_entries(1)
        dead.session._closed = True
        runner = self.runner()
        retiring, go = threading.Event(), threading.Event()
        original = dead.on_retire

        def slow(entry):
            retiring.set()
            go.wait(10)          # the window: B is inside `retire`; before the fix it held the pool lock here
            original(entry)

        dead.on_retire = slow
        self.addCleanup(go.set)
        got, stopped = [], []
        b = threading.Thread(target=lambda: got.append(self.pool.acquire(5)), daemon=True)
        b.start()
        self.assertTrue(retiring.wait(5), "B is retiring the dead entry")
        a = threading.Thread(target=lambda: stopped.append(runner.stop(runner.target("owned"))), daemon=True)
        a.start()
        time.sleep(0.2)          # A is past the pool read and holds (or waits for) the row guard
        go.set()
        a.join(8)
        b.join(8)
        self.assertFalse(a.is_alive() or b.is_alive(), "DEADLOCK: stop and acquire wait for each other")
        self.assertEqual(len(got), 1)
        self.assertIsNot(got[0], dead)
        self.assertTrue(stopped and stopped[0]["ok"])
        self.pool.release(got[0])

    def test_acquire_retires_every_dead_idle_entry_even_when_a_live_one_follows(self):
        first, second = self.idle_entries(2)
        first.session._closed = True        # idle is [first, second]: the pop order takes `second`, then `first`
        second.session._closed = True
        third = self.pool.acquire(5)
        self.assertTrue(first.finished and second.finished, "dead entries are retired, not leaked, on every path")
        self.assertNotIn(third, (first, second))
        self.pool.release(third)

    def test_a_closed_answer_invalidates_the_other_idle_entries_before_the_retry(self):
        self.daemon.scoped = True
        runner = self.runner()
        used, spare = self.pool.acquire(5), self.pool.acquire(5)
        self.pool.release(spare)
        self.pool.release(used)          # idle is [spare, used]: the read takes `used`
        self.daemon.fail_next["script"] = hydra.EngineError("closed", "the connection ended")
        self.assertTrue(self.ask(runner))
        self.assertEqual(self.daemon.violations, [])
        self.assertTrue(spare.finished, "the idle entry that was not used was retired too")
        self.assertEqual(self.daemon.refused_closed, 0, "the retry took a fresh entry, not another dead one")


class DeadlineBranches(Base):
    """Production branches the pool tests do not reach: the native deadline (hydra.4), the patience budget, the gate on
    `stop`, and the protocol range of `Engine._connect`."""

    def native(self, queue_info=False):
        self.daemon.queue_info = queue_info
        self.engine.deadline_mode = lambda: "native"
        return self.runner()

    def test_a_hydra_4_client_library_gets_the_deadline_and_no_pool_entry_is_made(self):
        runner = self.native()
        self.ask(runner, timeout_s=30)
        script = [call for call in self.daemon.calls if call[1] == "script"][-1]
        self.assertEqual(script[2]["deadline"], 60.0, "max(60, timeout + 10) for a 30 s script")
        self.assertEqual(self.pool.live(), 0)
        self.ask(runner, timeout_s=100)
        script = [call for call in self.daemon.calls if call[1] == "script"][-1]
        self.assertEqual(script[2]["deadline"], 110.0)

    def test_the_helper_path_never_sends_a_deadline_field(self):
        runner = self.runner()
        self.ask(runner)
        script = [call for call in self.daemon.calls if call[1] == "script"][-1]
        self.assertNotIn("deadline", script[2])
        self.assertEqual(self.pool.live(), 1)

    def test_the_patience_budget_applies_off_the_pool_too(self):
        runner = self.native(queue_info=True)
        self.ask(runner)
        waits = [call[2]["wait"] for call in self.daemon.calls if call[1] in ("open_project", "open_program", "script")]
        self.assertEqual(set(waits), {25_000}, "queueInfo: the 25 s budget, not the 180 s one")
        self.daemon.queue_info = False
        query._keys.clear()
        self.daemon.calls.clear()
        self.ask(runner)
        waits = [call[2]["wait"] for call in self.daemon.calls if call[1] in ("open_project", "open_program", "script")]
        self.assertEqual(set(waits), {query.BUSY_WAIT_MS}, "no queueInfo: the old budget")

    def test_stop_waits_for_the_gate_before_it_reports(self):
        runner = self.runner()
        self.ask(runner)
        other = self.pool.acquire(5)
        other.joined.add("p9:/other.exe")
        self.registry.read_begin("p9:/other.exe")
        self.assertEqual(self.registry.leave(other), "deferred")
        threading.Timer(0.3, self.registry.read_end, ("p9:/other.exe",)).start()
        started = time.monotonic()
        runner.stop(runner.target("owned"))
        self.assertGreaterEqual(time.monotonic() - started, 0.25, "stop waited for the read to end")
        self.assertEqual(self.registry.snapshot()["closing"], [], "the closing list was drained, not left behind")
        self.assertEqual(other.session.closes, 1)

    def connect_with(self, protocol):
        class Session:
            hello = {"protocol": protocol, "hydraVersion": hydra.RELEASE}
            closed = 0

            def close(self):
                Session.closed += 1

        module = type("Module", (fakehydra.FakeClientModule,), {"connect": classmethod(lambda cls, **_: Session())})
        engine = hydra.Engine(self.settings, start=False)
        with patch.object(hydra, "load_client", lambda *_, **__: module), patch.object(hydra, "sync_scripts"), \
                patch.object(hydra, "write_daemon_config"):
            try:
                return engine._connect(), Session
            except RuntimeError as exc:
                return exc, Session

    def test_connect_refuses_a_protocol_outside_the_range_and_closes_the_session(self):
        for protocol in (hydra.PROTOCOL_MIN - 1, hydra.PROTOCOL + 1):
            outcome, session = self.connect_with(protocol)
            self.assertIsInstance(outcome, RuntimeError)
            self.assertIn("speaks protocol %d" % protocol, str(outcome))
            self.assertEqual(session.closed, 1)
        for protocol in range(hydra.PROTOCOL_MIN, hydra.PROTOCOL + 1):
            outcome, session = self.connect_with(protocol)
            self.assertNotIsInstance(outcome, RuntimeError, protocol)
            self.assertEqual(session.closed, 0)


class FakeSurface(unittest.TestCase):
    """The v3 and E2 surface of the fake that Y4d's tests run on: `format`, `backup_required`, `fork_project purpose:"backup"`
    with an engine-written manifest, `health` and `next`."""

    def setUp(self):
        self.temp = workdir("fakesurface")
        self.addCleanup(self.temp.cleanup)
        self.daemon = fakehydra.reset()
        self.root = Path(self.temp.name)
        self.gpr = self.root / "m" / "Master" / "Master.gpr"
        self.daemon.add_project(self.gpr, {"/a.exe": {"sha256": "ab" * 32}})
        self.engine = fakehydra.FakeEngine({})

    FORMAT = {"programDb": {"min": 32, "max": 32, "current": 33}, "upgradeRequired": True, "oneWay": True}

    def test_format_is_reported_by_open_project_and_info_only_when_the_engine_has_it(self):
        opened = self.engine.call("open_project", path=str(self.gpr))
        self.assertNotIn("format", opened, "a hydra.2/3 engine reports none")
        self.daemon.format_info = self.FORMAT
        opened = self.engine.call("open_project", path=str(self.gpr))
        self.assertEqual(opened["format"], self.FORMAT)
        program = self.engine.call("open_program", project=opened["id"], path="/a.exe")
        self.assertEqual(self.engine.call("info", program=program["key"])["format"], self.FORMAT)

    def gate(self, protocol):
        self.daemon.backup_required = True
        self.daemon.format_info = self.FORMAT
        self.daemon.hello_extra = {"protocol": protocol}
        opened = self.engine.call("open_project", path=str(self.gpr))
        return opened["id"]

    def test_the_upgrade_gate_refuses_a_non_disposable_project_without_a_backup(self):
        project = self.gate(3)
        with self.assertRaises(hydra.EngineError) as raised:
            self.engine.call("open_program", project=project, path="/a.exe", writable=True, upgrade=True)
        self.assertEqual(raised.exception.code, "backup_required")
        self.assertEqual(raised.exception.next["purpose"], "backup")
        self.assertEqual(raised.exception.details["suggest"], "fork_project purpose backup")
        self.assertTrue(self.engine.call("open_program", project=project, path="/a.exe", writable=True, upgrade=True, backup="b.json"))

    def test_the_gate_answers_conflict_with_a_reason_on_protocol_2_and_never_for_a_disposable_fork(self):
        project = self.gate(2)
        with self.assertRaises(hydra.EngineError) as raised:
            self.engine.call("open_program", project=project, path="/a.exe", writable=True, upgrade=True)
        self.assertEqual((raised.exception.code, raised.exception.details["reason"]), ("conflict", "backup_required"))
        fork = self.engine.call("fork_project", project=project, path=str(self.root / "fork"), purpose="fork")
        self.assertTrue(self.engine.call("open_program", project=fork["project"], path="/a.exe", writable=True, upgrade=True))
        self.daemon.backup_required = False
        self.assertTrue(self.engine.call("open_program", project=project, path="/a.exe", writable=True, upgrade=True))

    def test_fork_project_backup_writes_an_engine_manifest_that_backups_verify_accepts(self):
        from hydralysis import backups
        project = self.engine.call("open_project", path=str(self.gpr))["id"]
        folder = self.root / "backup"
        made = self.engine.call("fork_project", project=project, path=str(folder), purpose="backup", reason="pre-commit", open=False)
        manifest = json.loads((folder / "backup.json").read_text(encoding="utf-8"))
        self.assertEqual((manifest["writer"], manifest["kind"], manifest["purpose"]), ("engine", "ghidra-session-backup", "pre-commit"))
        self.assertEqual(made["manifest"]["selfSha256"], manifest["selfSha256"])
        self.assertTrue(backups.verify(folder)["ok"], backups.verify(folder))
        sidecar = json.loads((folder / "Master.fork.json").read_text(encoding="utf-8"))
        self.assertEqual((sidecar["purpose"], sidecar["disposable"], sidecar["state"]), ("backup", False, "complete"))
        again = self.engine.call("fork_project", project=project, path=str(self.root / "backup2"), purpose="backup")
        self.assertNotEqual(again["manifest"]["id"], manifest["id"])
        plain = self.engine.call("fork_project", project=project, path=str(self.root / "plain"))
        self.assertFalse((self.root / "plain" / "backup.json").exists())
        self.assertNotIn("manifest", plain)

    def test_health_exists_only_on_an_engine_with_queue_information(self):
        with self.assertRaises(hydra.EngineError) as raised:
            self.engine.call("health")
        self.assertEqual(raised.exception.details["command"], "health")
        self.daemon.queue_info = True
        self.daemon.health_extra = {"state": "suspect"}
        self.assertEqual(hydra.wedge_signal(self.engine.call("health")), "suspect")
        self.daemon.health_extra = {}
        self.assertIsNone(hydra.wedge_signal(self.engine.call("health")))

    def test_next_and_retry_after_survive_a_pool_entry(self):
        engine = fakehydra.FakePooledEngine({})
        self.daemon.replies["ping"] = fakehydra.busy_with_holder(retry_after_ms=1500)
        with self.assertRaises(hydra.EngineError) as raised:
            with engine.pool().attempt(5) as entry:
                entry.call("ping")
        self.assertEqual(raised.exception.next, {"cmd": "status"})
        self.assertEqual(raised.exception.retry_after_ms, 1500)
        self.assertEqual(raised.exception.holder_info["harness"], "codex")


class SupervisorWiring(unittest.TestCase):
    """`Supervisor.for_engine` reads real sources: the endpoint pid, the instance lock, the job records of the root."""

    def setUp(self):
        self.temp = workdir("supwiring")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = {"root": str(self.root / "data"), "hydra_dir": "x", "hydra_client": "x"}
        self.state = hydra.state_dir(self.settings)
        self.state.mkdir(parents=True, exist_ok=True)
        self.alive = True
        self.pid = 4242
        outer = self

        class Daemon:
            def __init__(self, *_):
                pass

            def read_endpoint(self):
                return {"pid": outer.pid} if outer.pid else None

            def jvm_alive(self):
                return outer.alive

            def kill(self):
                outer.alive = False

        module = type("Module", (), {"Daemon": Daemon})
        self.status_reply = {}
        self.engine = type("E", (), {"module": lambda _: module, "engine_dir": "x", "capabilities": lambda _: {},
                                     "call": lambda _, command: outer.status_reply})()

    def job(self, kind, state="running"):
        from hydralysis import overlayjobs
        from hydralysis.backends import write_json
        job_id = "overlay-" + hashlib.sha256((kind + state).encode()).hexdigest()[:12]
        path = overlayjobs.job_path(self.settings, job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json(path, {"id": job_id, "kind": kind, "state": state, "created_at": time.time(), "worker_pid": os.getpid(),
                          "worker_started_ms": overlayjobs.proc_start(os.getpid())})
        return job_id, path

    def supervisor(self, **overrides):
        return hydra.Supervisor.for_engine(self.engine, self.settings, **overrides)

    def test_pid_and_instance_lock_are_two_facts(self):
        supervisor = self.supervisor(probe=lambda: {})
        self.alive, self.pid = False, os.getpid()
        self.assertTrue(supervisor.pid_alive(), "the endpoint's pid exists")
        self.assertTrue(supervisor.lock_free(), "the lock is free: not the same answer as pid_alive")
        self.pid = None
        self.assertFalse(supervisor.pid_alive())
        self.alive = True
        self.assertFalse(supervisor.lock_free())

    def test_a_dead_pid_with_a_held_lock_is_not_restarted(self):
        supervisor = self.supervisor(probe=lambda: {}, restart=lambda force: self.fail("must not restart"))
        self.pid, self.alive = None, True
        self.assertEqual(supervisor.tick()["event"], "no_process")

    def test_an_active_publish_job_refuses_the_restart_and_other_jobs_are_marked_lost(self):
        from hydralysis.backends import read_json
        _, publish = self.job("publish")
        supervisor = self.supervisor(probe=lambda: {}, durable_journal=lambda: True)
        self.assertTrue(supervisor.publish_in_flight())
        publish.write_text(publish.read_text().replace("running", "done"), encoding="utf-8")
        self.assertFalse(supervisor.publish_in_flight())
        _, sync = self.job("sync")
        supervisor.mark_lost([{"program": "p1:/a.exe"}])
        record = read_json(sync)
        self.assertTrue(record["lost_on_restart"])
        self.assertEqual(record["lost_on_restart_programs"], ["p1:/a.exe"])

    def test_programs_under_working_are_recoverable_after_a_status(self):
        working = Path(self.settings["root"]) / "working" / "k" / "x.gpr"
        self.status_reply = {"programs": [{"key": "p1:/w.exe", "gpr": str(working), "unsavedEdits": 2},
                                          {"key": "p1:/o.exe", "gpr": str(self.root / "elsewhere.gpr"), "unsavedEdits": 1}]}
        supervisor = self.supervisor(probe=lambda: {})
        supervisor.status()
        self.assertTrue(supervisor.recoverable("p1:/w.exe"))
        self.assertFalse(supervisor.recoverable("p1:/o.exe"))

    def test_the_journal_gate_needs_a_v3_store_and_a_passing_self_test(self):
        from hydralysis import workcopy
        self.assertTrue(hydra.journal_durable(self.settings))
        with patch.object(workcopy, "STORE_VERSION", 2):
            self.assertFalse(hydra.journal_durable(self.settings))

    def test_the_supervisor_is_started_with_the_first_pool_of_a_real_engine_and_stopped_by_stop(self):
        engine = hydra.Engine(self.settings, start=False)
        log = []
        fake = type("S", (), {"start": lambda self: log.append("start"), "stop": lambda self: log.append("stop")})()
        self.addCleanup(hydra._SUPERVISORS.clear)
        with patch.object(hydra.Supervisor, "for_engine", classmethod(lambda cls, e, s, **o: fake)):
            engine.pool()
            engine.pool()
            self.assertEqual(log, ["start"], "once per root")
            stubs = []

            class StubDaemon:
                def __init__(self, *args):
                    stubs.append(args)

                def stop(self, force=False):
                    log.append("daemon.stop")
                    return True

            with patch.object(hydra.Engine, "module", lambda self: type("M", (), {"Daemon": StubDaemon})):
                self.assertEqual(engine.stop(), {"stopped": True})
            self.assertEqual(log, ["start", "stop", "daemon.stop"], "Engine.stop stops the supervisor before the daemon")
            self.assertEqual(len(stubs), 1)
            self.assertNotIn(hydra._root_key(engine), hydra._SUPERVISORS)
        hydra._SUPERVISORS.clear()
        with patch.object(hydra.Supervisor, "for_engine", side_effect=AttributeError("no Daemon")):
            self.assertIsNone(hydra.supervise(engine), "a client without Daemon leaves the engine unsupervised, no error")
        self.assertIsNone(hydra.supervise(engine, {**self.settings, "hydra_supervisor": False}))


@unittest.skipUnless(os.environ.get("HYDRALYSIS_REAL_HYDRA3"), "HYDRALYSIS_REAL_HYDRA3 (a hydra.3 install with its client) is not set")
class RealHydra3(unittest.TestCase):
    """The cases of 7.6 and 7.2 that need a real hydra.3 engine. NOT WRITTEN: the real-engine run did not happen (daemon
    spawns belong to the coordinator, with a stamped private copy of the engine install). Each case below skips with its
    name when HYDRALYSIS_REAL_HYDRA3 is set, so the gap is listed by the runner and not hidden: L, S and C,
    `replacement_context`, `wait_below_deadline`, `leave_gate_no_freeze`, the 7.2 policy and the 7.5 degrade matrix."""


def _not_written(name):
    def case(self):
        self.skipTest("%s: not written; needs a real hydra.3 engine (see the class docstring)" % name)
    return case


for _name in ("case_L", "case_S", "case_C", "replacement_context", "wait_below_deadline", "leave_gate_no_freeze",
              "supervisor_policy_suspended_daemon", "supervisor_slow_daemon_with_unsaved_edits", "degrade_matrix_7_5"):
    setattr(RealHydra3, "test_" + _name, _not_written(_name))


if __name__ == "__main__":
    unittest.main()
