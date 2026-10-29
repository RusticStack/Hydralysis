"""The protocol negotiation, the lane hint and the deadline mechanism on hydra.2/3 (PROTOCOL-3.md 7.5, 7.6; Y4a).

Against the fake daemon: the abandon helper (never a `close()` or a `shutdown` while a request is in flight), one deadline per
attempt, the two budgets, the pool entry with its context (I1 to I3), the leave gate, `QueryRunner.stop` over the entries.
The real-engine cases (L, S, C, `replacement_context`, `wait_below_deadline`, `leave_gate_no_freeze`, the 7.5 degrade
matrix) are at the end of this file: `RealHelper` (the hydra.2/3 helper of 7.6), `RealNative` (P1b's deadline on hydra.4) and
`RealDegrade`. They run only when HYDRALYSIS_INTEGRATION_ENGINE and HYDRALYSIS_INTEGRATION_CLIENT name a Hydra install, as
for tests/test_engine_integration.py (see `RealEngine` there for the variables); the 7.2 policy on the real daemon is in
tests/test_supervisor.py.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
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

    def test_the_pool_lock_and_the_row_guard_are_never_nested_in_either_order(self):
        """Lock order, stated as the invariant instead of one interleaving: no thread ever takes the query row guard
        (`query._keys_guard`) while it holds the pool's `_cond`, and none takes `_cond` while it holds the row guard. The two
        orders together were the inversion (`stop` held the guard and asked the pool, `acquire` held `_cond` and retired an entry,
        whose `on_retire` takes the guard); either one alone cannot deadlock, so this watches both on every path that touches
        both: acquire over a dead idle entry, `stop`, `invalidate`, and a release that retires."""
        violations, held = [], threading.local()

        class Guard:
            def __init__(self, inner):
                self.inner = inner

            def __enter__(self):
                if pool._cond._is_owned():
                    violations.append("row guard taken under the pool lock")
                self.inner.acquire()
                held.guard = True
                return self

            def __exit__(self, *exc):
                held.guard = False
                self.inner.release()

        class Cond(threading.Condition):
            def __enter__(self):
                if getattr(held, "guard", False):
                    violations.append("pool lock taken under the row guard")
                return super().__enter__()

        pool = self.pool
        pool._cond = Cond()
        patcher = patch.object(query, "_keys_guard", Guard(query._keys_guard))
        patcher.start()
        self.addCleanup(patcher.stop)
        runner = self.runner()
        live, dead = self.idle_entries(2)            # idle is [live, dead]: acquire pops `dead` first, then takes `live`
        dead.session._closed = True
        pool.release(pool.acquire(5))                # retires the dead idle entry, which forgets its rows
        stopped = runner.stop(runner.target("owned"))   # reads the pool, then the guard
        self.assertNotIn("error", stopped)
        taken = pool.acquire(5)
        self.program(taken)
        pool.release(taken, hydra.EngineError("no_program", "gone"))   # a retiring release forgets rows
        pool.invalidate()                            # retires the idle entries, forgets the role
        self.assertTrue(dead.finished and live.finished)
        self.assertEqual(violations, [], "the pool lock and the row guard must not be nested")

    def test_acquire_retires_every_dead_idle_entry_even_when_a_live_one_follows(self):
        live, dead1, dead2 = self.idle_entries(3)
        dead1.session._closed = True        # idle is [live, dead1, dead2]: the pop order takes dead2, then dead1, then `live`
        dead2.session._closed = True
        got = self.pool.acquire(5)
        self.assertIs(got, live, "the live entry that follows the dead ones is the one handed out")
        self.assertTrue(dead1.finished and dead2.finished, "dead entries are retired, not leaked, on the live-found path")
        self.assertEqual({key[0] for key in query._keys}, {live.key}, "the dead entries' rows are gone, the live one's stay")
        self.pool.release(got)

    def test_acquire_releases_the_chosen_entry_when_retiring_a_dead_one_raises(self):
        live, dead = self.idle_entries(2)
        dead.session._closed = True         # idle is [live, dead]: dead is popped first, then live is chosen

        def boom(entry):
            raise RuntimeError("on_retire failed")

        dead.on_retire = boom
        with self.assertRaises(RuntimeError):
            self.pool.acquire(5)
        self.assertIn(live, self.pool._idle, "the chosen entry went back to the pool, it does not hold a slot for good")
        self.assertIs(self.pool.acquire(5), live)

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


def _env(name):
    """HYDRALYSIS_<name>, else the old RUSTICRE_<name> (as tests/test_engine_integration.py)."""
    return os.environ.get("HYDRALYSIS_" + name) or os.environ.get("RUSTICRE_" + name)


# The real engine (PROTOCOL-3.md 7.6 "Tests (Y4a)"). HYDRALYSIS_INTEGRATION_ENGINE is a Hydra install and
# HYDRALYSIS_INTEGRATION_CLIENT its ghidra_session.py, as for the other integration tests (an engine that is not the pinned
# release is accepted here: these tests are about the mechanism, not the pin). The hydra.2/3 helper needs a library that does
# not time its own wait (1.0.0): the client itself when it is one (a hydra.3 install), else
# HYDRALYSIS_INTEGRATION_HELPER_CLIENT (for instance the hydra.3 client against the same daemon, which negotiates protocol 2).
REAL_ENGINE = _env("INTEGRATION_ENGINE")
REAL_CLIENT = _env("INTEGRATION_CLIENT")
REAL_BINARY = _env("INTEGRATION_BINARY") or (
    os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "System32", "whoami.exe") if os.name == "nt" else "")
HAVE_REAL = bool(REAL_ENGINE and REAL_CLIENT and REAL_BINARY and Path(REAL_BINARY).is_file())


def _library_version(path) -> tuple:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    found = re.search(r'^CLIENT_VERSION\s*=\s*"([0-9.]+)"', text, re.M)
    return tuple(int(part) for part in found.group(1).split(".")) if found else (0,)


def _helper_client():
    if not HAVE_REAL:
        return None
    return REAL_CLIENT if _library_version(REAL_CLIENT) < (1, 1, 0) else _env("INTEGRATION_HELPER_CLIENT")


def _native_client():
    return REAL_CLIENT if HAVE_REAL and _library_version(REAL_CLIENT) >= (1, 1, 0) else None


SCRIPTS = {
    "TestMakeProject": """import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
public class TestMakeProject extends GhidraScript {
    @Override protected void run() throws Exception {
        GhidraProject.createProject(getScriptArgs()[0], getScriptArgs()[1], false).close();
    }
}
""",
    # C: a cooperative script (polls its monitor).
    "TestSleep": """import ghidra.app.script.GhidraScript;
public class TestSleep extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) { monitor.checkCancelled(); Thread.sleep(20); }
        println("slept");
    }
}
""",
    # S: a script that ignores cancel and swallows interrupts; its length does not depend on a race.
    "TestNoCoop": """import ghidra.app.script.GhidraScript;
public class TestNoCoop extends GhidraScript {
    @Override protected void run() throws Exception {
        long end = System.currentTimeMillis() + Long.parseLong(getScriptArgs()[0]);
        while (System.currentTimeMillis() < end) {
            try { Thread.sleep(50); } catch (InterruptedException e) { /* ignored on purpose */ }
        }
        println("spun");
    }
}
""",
    # An unsaved edit on a writable program (the supervisor's `lost_on_restart`, tests/test_supervisor.py).
    "TestEdit": """import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
public class TestEdit extends GhidraScript {
    @Override protected void run() throws Exception {
        currentProgram.getListing().setComment(currentProgram.getImageBase(), CodeUnit.EOL_COMMENT, "y4a unsaved");
    }
}
""",
}


class RealEngine(unittest.TestCase):
    """One data root, one daemon and one unanalysed fixture project per class; the daemon is stopped at the end.

    `settings` loads the library of the class (`client()`); `base` the install's own client, which makes the fixture and is
    the observer that reads `status`. Every wait for the engine is a poll with a bound."""

    PROGRAM = "/fixture.exe"

    @classmethod
    def client(cls):
        return REAL_CLIENT

    @classmethod
    def setUpClass(cls):
        if not HAVE_REAL:
            raise unittest.SkipTest("set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
        if not cls.client():
            raise unittest.SkipTest("no client library for %s: set HYDRALYSIS_INTEGRATION_HELPER_CLIENT to a library 1.0.0 "
                                    "(the hydra.2/3 helper) or use an install whose library is 1.1.0" % cls.__name__)
        cls.work = workdir("real-" + cls.__name__.lower())
        cls.root = Path(cls.work.name)
        scripts = cls.root / "hydra" / "user-scripts"   # on the daemon's scriptPath (hydra.script_dirs)
        scripts.mkdir(parents=True, exist_ok=True)
        for name, text in SCRIPTS.items():
            (scripts / (name + ".java")).write_text(text, encoding="utf-8")
        binary = cls.root / "fixture.exe"
        shutil.copy2(REAL_BINARY, binary)
        cls.sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        cls.base = {"root": str(cls.root), "hydra_dir": REAL_ENGINE, "hydra_client": REAL_CLIENT,
                    "hydra_allow_unpinned": True, "hydra_supervisor": False, "hydra_idle_s": 600}
        if _env("INTEGRATION_JAVA"):
            cls.base["java_home"] = _env("INTEGRATION_JAVA")
        cls.settings = dict(cls.base, hydra_client=cls.client())
        cls.engines = []
        cls.observer = cls.engine("observer", cls.base)
        try:
            project = cls.root / "project"
            project.mkdir()
            cls.observer.call("script", script="TestMakeProject.java", program=None, args=[str(project), "Fixture"])
            cls.gpr = str(project / "Fixture.gpr")
            cls.observer.call("open_project", path=cls.gpr, writable=True, wait=60000)
            imported = cls.observer.call("import", file=str(binary), analyze=False, timeout=300, wait=300000)
            cls.PROGRAM = imported.get("path") or cls.PROGRAM
            cls.observer.call("close_project")
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def engine(cls, role, settings=None):
        found = hydra.Engine(settings or cls.settings, role=role)
        cls.engines.append(found)
        return found

    @classmethod
    def tearDownClass(cls):
        try:
            for engine in cls.engines:
                hydra.unsupervise(engine)
                pool = hydra.Engine._pools.pop(engine.key, None)
                if pool is not None:
                    pool.close_all(0.0)
            cls.observer.stop(force=True)
        finally:
            daemon = cls.observer.module().Daemon(str(cls.observer.engine_dir), str(hydra.state_dir(cls.base)), hydra.INSTANCE)
            if daemon.jvm_alive() or daemon.read_endpoint():
                daemon.kill()
            for engine in cls.engines:
                engine.reset()
            time.sleep(1)
            cls.work.cleanup()

    # --- what the engine says ----------------------------------------------------------------------------------------

    def status(self) -> dict:
        return self.observer.call("status")

    def clients(self) -> dict:
        return {item["id"]: item for item in self.status().get("clients", [])}

    def requests_of(self, client_id) -> list:
        return (self.clients().get(client_id) or {}).get("requests") or []

    def users(self, key) -> set:
        found = set()
        for program in self.status().get("programs", []):
            if program.get("key") == key or "%s:%s" % (program.get("project"), program.get("path")) == key:
                found.update(program.get("users") or [])
        return found

    @staticmethod
    def ident(entry) -> int:
        return (getattr(entry.session, "hello", {}) or {}).get("client")

    @staticmethod
    def ident_of_engine(engine) -> int:
        return (getattr(engine.session(), "hello", {}) or {}).get("client")

    # --- the fixture's program ---------------------------------------------------------------------------------------

    def join(self, entry, deadline_s=30.0) -> str:
        """Re-establish ENTRY's context (the two opens, as the query layer sends them) and return the daemon's program key."""
        entry.begin(deadline_s)
        opened = entry.call("open_project", path=self.gpr, wait=180000)
        return entry.call("open_program", path=self.PROGRAM, project=opened["id"], wait=180000)["key"]

    def read(self, entry, key, ms, deadline_s=30.0, script="TestSleep.java"):
        entry.begin(deadline_s)
        return entry.call("script", script=script, program=key, args=[str(int(ms))], timeout=120, wait=180000)

    def hold(self, ms):
        """Another client holds the program exclusively for MS: an owner's cooperative script on the writable program
        (case L). Returns (thread, box); the box gets the holder's reply."""
        holder = self.engine("holder-%d" % len(self.engines), self.base)
        holder.call("open_project", path=self.gpr, writable=True, wait=60000)
        key = holder.call("open_program", path=self.PROGRAM, writable=True, wait=60000)["key"]
        box = {}

        def run():
            try:
                box["reply"] = holder.call("script", script="TestSleep.java", program=key, args=[str(int(ms))], timeout=120,
                                           wait=60000)
            except Exception as exc:   # noqa: BLE001 - asserted by the test
                box["error"] = exc
            finally:
                try:
                    holder.call("close_program", program=key)
                except Exception:   # noqa: BLE001
                    pass

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        ident = self.ident_of_engine(holder)
        self.assertTrue(until(lambda: self.requests_of(ident), 10.0), "the holder's script runs")
        return thread, box


@unittest.skipUnless(HAVE_REAL and _helper_client(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT, and HYDRALYSIS_INTEGRATION_HELPER_CLIENT "
                     "to a client library 1.0.0 when the install's own is 1.1.0 (the hydra.2/3 helper)")
class RealHelper(RealEngine):
    """7.6 on a real daemon with the hydra.2/3 helper: L, S, C, `replacement_context`, `wait_below_deadline`,
    `leave_gate_no_freeze` (this module's pool, registry and leave gate, on real connections)."""

    @classmethod
    def client(cls):
        return _helper_client()

    def setUp(self):
        self.registry = hydra.Registry()
        self.reader = self.engine("reader-%d" % len(self.engines))
        self.assertEqual(self.reader.deadline_mode(), "helper", "a library 1.0.0 has no deadline of its own")
        self.pool = hydra.Pool(self.reader, registry=self.registry)
        self.addCleanup(self.pool.close_all, 0.0)

    def take(self, deadline_s=30.0, grace_s=hydra.DEADLINE_GRACE_S):
        entry = self.pool.acquire(deadline_s)
        entry.grace_s = grace_s
        return entry

    def abandon_noncoop(self, entry, key, ms, deadline_s=2.0):
        """Case S on ENTRY: a non-cooperative script, `cancel` at the deadline, nothing at all after the grace."""
        started = time.monotonic()
        with self.assertRaises(hydra.DeadlineError) as raised:
            self.read(entry, key, ms, deadline_s=deadline_s, script="TestNoCoop.java")
        self.assertEqual(raised.exception.code, "deadline_exceeded")
        self.assertTrue(raised.exception.details.get("connection_abandoned"))
        self.assertLess(time.monotonic() - started, deadline_s + entry.grace_s + 2.0, "the caller never waits for the engine")
        self.assertTrue(entry.abandoned)
        self.pool.release(entry, raised.exception)

    def engine_has_fast_leave(self) -> bool:
        """hydra.4 (E3c) makes a plain reader's leave harmless; hydra.2/3 stalls the other readers behind it (3.5)."""
        return "health" in self.observer.capabilities()

    def join_during_queued_leave(self, key, deadline_s):
        """A read R runs on one entry; another entry that joined the program is closed at once (its leave queues behind R);
        a new entry then joins and reads with `wait = remaining / 2`. Returns (refused, seconds, error)."""
        running = self.take()
        self.join(running)
        leaving = self.take()
        self.join(leaving)
        box = {}
        reader = threading.Thread(target=lambda: box.setdefault("r", self.read(running, key, 6000)), daemon=True)
        reader.start()
        self.assertTrue(until(lambda: self.requests_of(self.ident(running)), 5.0))
        leaving.close_now()   # what rule L2 forbids: a leave while a read runs
        leaving.broken = True
        self.pool.release(leaving)
        time.sleep(0.3)   # the close sends nothing back to wait for; give the engine's leave a moment to queue
        fresh = self.take(deadline_s=deadline_s)
        started = time.monotonic()
        error = None
        try:
            self.join(fresh, deadline_s)
            self.read(fresh, key, 10, deadline_s)
        except hydra.EngineError as exc:
            error = exc
        elapsed = time.monotonic() - started
        self.pool.release(fresh, error)
        reader.join(30)
        self.pool.release(running)
        self.assertIn("r", box)
        self.assertNotIsInstance(error, hydra.DeadlineError, "the join is answered, never abandoned")
        return error is not None, elapsed, error

    def test_case_C_a_cooperative_script_is_ended_by_cancel_and_nothing_is_abandoned(self):
        entry = self.take(grace_s=5.0)
        key = self.join(entry)
        ident = self.ident(entry)
        started = time.monotonic()
        with self.assertRaises(hydra.EngineError) as raised:
            self.read(entry, key, 30000, deadline_s=2.0)
        self.assertNotIsInstance(raised.exception, hydra.DeadlineError, "the engine answered within the grace")
        self.assertLess(time.monotonic() - started, 2.0 + 5.0)
        self.assertFalse(entry.abandoned)
        self.assertEqual(self.registry.count("user"), 0)
        self.assertTrue(until(lambda: not self.requests_of(ident), 1.5), "C is released within 1 s of the cancel")
        self.pool.release(entry, raised.exception)
        again = self.take()
        self.assertIs(again, entry, "a reply leaves the connection healthy: the entry goes back to the pool")
        self.assertEqual(self.read(again, key, 10)["output"].strip(), "slept")
        self.pool.release(again)

    def test_case_S_a_script_that_ignores_cancel_is_abandoned_and_closed_after_its_reply(self):
        entry = self.take(grace_s=1.0)
        key = self.join(entry)
        ident = self.ident(entry)
        self.abandon_noncoop(entry, key, 9000)
        self.assertEqual(self.registry.count("user"), 1)
        self.assertTrue(until(lambda: any(r.get("cancelled") for r in self.requests_of(ident)), 2.0),
                        "the engine shows the cancelled flag within 1 s of the cancel: %s" % self.requests_of(ident))
        self.assertIn(ident, self.users(key), "S stays registered while the script runs")
        self.assertTrue(until(lambda: self.registry.count("user") == 0, 30.0), "the abandoned worker gets the reply")
        self.assertTrue(until(lambda: entry.finished, 10.0), "no other read is in flight: the gate closes it")
        self.assertTrue(until(lambda: ident not in self.clients(), 10.0), "the engine lets the client go")
        self.assertEqual(self.registry.closing, [])

    def test_case_L_a_lock_wait_is_answered_busy_below_the_deadline(self):
        entry = self.take()
        key = self.join(entry)
        self.pool.release(entry)
        thread, box = self.hold(12000)
        entry = self.take(deadline_s=6.0)
        started = time.monotonic()
        with self.assertRaises(hydra.EngineError) as raised:
            entry.call("script", script="TestSleep.java", program=key, args=["10"], timeout=120, wait=180000)
        self.assertEqual(raised.exception.code, "busy", raised.exception)
        self.assertLess(time.monotonic() - started, 6.0, "the engine's `wait` (min(25 s, remaining / 2)) ends L, not the deadline")
        self.assertFalse(entry.abandoned)
        self.assertEqual(self.registry.count("user"), 0)
        self.pool.release(entry, raised.exception)
        thread.join(30)
        self.assertIn("reply", box, "the holder's script is untouched: %s" % box)

    def test_wait_below_deadline(self):
        entry = self.take()
        key = self.join(entry)
        self.pool.release(entry)
        thread, box = self.hold(10000)
        entry = self.take(deadline_s=6.0)
        with self.assertRaises(hydra.EngineError) as raised:
            entry.call("script", script="TestSleep.java", program=key, args=["10"], timeout=120, wait=180000)
        self.assertEqual(raised.exception.code, "busy")
        self.pool.release(entry, raised.exception)
        self.assertIs(self.take(), entry, "the entry returned to the pool")
        self.pool.release(entry)
        self.assertEqual(self.registry.snapshot()["abandoned"]["user"], 0)
        thread.join(30)
        self.assertIn("reply", box)
        # The two opens: a new entry joins while a leave is queued behind a running read (the hazard of 3.5, made real).
        refused, elapsed, error = self.join_during_queued_leave(key, deadline_s=3.0)
        if refused:
            self.assertEqual(error.code, "busy", "an open blocked by the queued leave is answered `busy` at its `wait`")
            self.assertLess(elapsed, 3.0)
        elif not self.engine_has_fast_leave():
            self.fail("hydra.2/3: the join was expected to wait behind the queued leave (exp13 A)")
        self.assertEqual(self.registry.count("user"), 0, "nothing is abandoned either way")

    def test_replacement_context(self):
        warm = self.take()
        key = self.join(warm)
        self.read(warm, key, 10)
        # (1) A fresh connection without the two opens is refused: the premise of the entry's context.
        bare = self.reader.connect_entry()
        try:
            with self.assertRaises(self.reader.module().SessionError) as refused:
                bare.call("script", script="TestSleep.java", program=key, args=["1"], parallel=True)
            self.assertIn(refused.exception.code, ("no_project", "no_program"))
        finally:
            bare.close()
        stalled = self.take(grace_s=1.0)
        self.join(stalled)
        self.pool.release(warm)
        before = self.clients()
        self.abandon_noncoop(stalled, key, 9000)
        # (2) The next read takes a new entry (the warm one is busy elsewhere), re-establishes its context and is answered.
        busy = self.take()
        self.assertIs(busy, warm)
        fresh = self.take()
        self.assertGreater(fresh.serial, stalled.serial, "a retired entry's key is never reused (I1)")
        self.assertEqual(self.join(fresh), key)
        self.assertEqual(self.read(fresh, key, 10)["output"].strip(), "slept", "answered, with no no_project")
        after = self.clients()
        self.assertEqual(set(after) - set(before), {self.ident(fresh)}, "exactly one new client, which sent the two opens")
        self.assertTrue(after[self.ident(fresh)].get("programs"))
        # (3) The other entries are unchanged: the same ids, no request added.
        self.assertIn(self.ident(warm), after)
        self.assertFalse(after[self.ident(warm)].get("requests"))
        # (4) users = the live entries + the new entry + the abandoned one, while S runs.
        users = self.users(key)
        self.assertTrue({self.ident(warm), self.ident(fresh), self.ident(stalled)} <= users, users)
        self.pool.release(busy)
        self.pool.release(fresh)
        # (5) S ends: the worker gets the reply; no read is in flight, so the gate closes it and users drops it.
        self.assertTrue(until(lambda: self.registry.count("user") == 0, 30.0))
        self.assertTrue(until(lambda: self.ident(stalled) not in self.users(key), 10.0))
        self.assertEqual(self.users(key) & {self.ident(warm), self.ident(fresh)}, {self.ident(warm), self.ident(fresh)})
        self.assertEqual(self.registry.closing, [])

    def test_leave_gate_no_freeze(self):
        warm = self.take()
        key = self.join(warm)
        stalled = self.take(grace_s=1.0)
        self.join(stalled)
        self.abandon_noncoop(stalled, key, 6000)
        # R: a cooperative 14 s read on another entry, in flight when S ends.
        box = {}
        reader = threading.Thread(target=lambda: box.setdefault("r", self.read(warm, key, 14000, deadline_s=60.0)), daemon=True)
        reader.start()
        self.assertTrue(until(lambda: self.registry.count("user") == 0, 30.0), "S ended and its worker got the reply")
        self.assertTrue(reader.is_alive(), "R is still running when S ends")
        self.assertIn(stalled, self.registry.closing, "the close is deferred while R is in flight")
        self.assertIn(self.ident(stalled), self.users(key), "users still lists the deferred entry")
        further = self.take(deadline_s=10.0)
        started = time.monotonic()
        self.join(further, 10.0)
        self.assertEqual(self.read(further, key, 10, 10.0)["output"].strip(), "slept", "a further read is answered, not busy")
        self.assertLess(time.monotonic() - started, 3.0)
        self.pool.release(further)
        reader.join(60)
        self.pool.release(warm)
        self.assertIn("r", box)
        self.assertTrue(until(lambda: not self.registry.closing and stalled.finished, 5.0), "the list drains when R ends")
        self.assertTrue(until(lambda: self.ident(stalled) not in self.users(key), 10.0))
        self.assertEqual(self.registry.snapshot()["abandoned"]["user"], 0)
        # The control: the same close done at once while a read runs. It stalls on hydra.2/3 (if it stops stalling there,
        # rule L2 is dropped, as E0's convention says); on hydra.4 E3c's fast leave makes it harmless.
        refused, _elapsed, error = self.join_during_queued_leave(key, deadline_s=3.0)
        if self.engine_has_fast_leave():
            self.assertFalse(refused, "hydra.4: a plain reader's leave takes no exclusive lock (%s)" % error)
        else:
            self.assertTrue(refused, "hydra.3: closing at once while a read runs stalls the next join (exp13 E)")
            self.assertEqual(error.code, "busy")


@unittest.skipUnless(_native_client(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT to an install with client library 1.1.0 "
                     "(hydra.4)")
class RealNative(RealEngine):
    """7.6 on hydra.4 (library 1.1.0, P1b): the library times its own wait, sends `cancel` and raises `deadline_exceeded`;
    the connection stays usable and nothing is abandoned (no entry, no registry, no gate)."""

    @classmethod
    def client(cls):
        return _native_client()

    def setUp(self):
        self.reader = self.engine("native-%d" % len(self.engines))
        self.assertEqual(self.reader.deadline_mode(), "native")
        self.program = query.open_program(self.reader, self.gpr, self.PROGRAM, self.sha256)
        self.addCleanup(query.forget, self.reader)
        self.abandoned_before = hydra.REGISTRY.count("user")

    def deadline_read(self, script, ms, deadline_s, wait=180000):
        started = time.monotonic()
        with self.assertRaises(hydra.EngineError) as raised:
            self.reader.call("script", script=script, program=self.program["key"], args=[str(ms)], timeout=120, wait=wait,
                             lane="quick", deadline=deadline_s)
        return raised.exception, time.monotonic() - started

    def assert_connection_survives(self):
        before = self.reader.session()
        self.assertEqual(self.reader.call("script", script="TestSleep.java", program=self.program["key"], args=["10"],
                                          timeout=60, wait=60000, deadline=30.0)["output"].strip(), "slept")
        self.assertIs(self.reader.session(), before, "the connection survives a deadline: nothing is abandoned")
        self.assertEqual(hydra.REGISTRY.count("user"), self.abandoned_before)

    def test_case_C(self):
        error, elapsed = self.deadline_read("TestSleep.java", 30000, 2.0)
        self.assertEqual(error.code, "deadline_exceeded")
        self.assertLess(elapsed, 4.0)
        ident = self.ident_of_engine(self.reader)
        self.assertTrue(until(lambda: not self.requests_of(ident), 1.5), "C is released within 1 s of the cancel")
        self.assert_connection_survives()

    def test_case_S(self):
        error, elapsed = self.deadline_read("TestNoCoop.java", 8000, 2.0)
        self.assertEqual(error.code, "deadline_exceeded")
        self.assertLess(elapsed, 4.0, "the caller is answered at the deadline although the script ignores cancel")
        self.assert_connection_survives()
        ident = self.ident_of_engine(self.reader)
        self.assertTrue(until(lambda: not self.requests_of(ident), 30.0), "S ends by itself and leaves no request behind")

    def test_case_L(self):
        thread, box = self.hold(10000)
        error, elapsed = self.deadline_read("TestSleep.java", 10, 3.0)
        self.assertEqual(error.code, "deadline_exceeded")
        self.assertLess(elapsed, 5.0)
        ident = self.ident_of_engine(self.reader)
        self.assertTrue(until(lambda: not self.requests_of(ident), 2.0), "hydra.4 ends a lock wait on cancel (cancelWait)")
        thread.join(30)
        self.assertIn("reply", box, "the holder is untouched: %s" % box)
        self.assert_connection_survives()

    def test_wait_below_deadline(self):
        thread, box = self.hold(10000)
        error, elapsed = self.deadline_read("TestSleep.java", 10, 30.0, wait=2000)
        self.assertEqual(error.code, "busy", "the engine's `wait` answers before the deadline")
        self.assertLess(elapsed, 6.0)
        thread.join(30)
        self.assertIn("reply", box)
        self.assert_connection_survives()


@unittest.skipUnless(HAVE_REAL, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class RealDegrade(RealEngine):
    """The 7.5 degrade matrix on a real daemon: each row with the library 1.0.0 (protocol 2, the degraded side) and with the
    install's library 1.1.0 (hydra.4, the capabilities). A side without its library is skipped with its reason."""

    def test_degrade_matrix_7_5(self):
        from hydralysis import backups, commits
        for side, client in (("degraded", _helper_client()), ("hydra4", _native_client())):
            with self.subTest(side=side):
                if not client:
                    self.skipTest("no library for the %s side (HYDRALYSIS_INTEGRATION_HELPER_CLIENT)" % side)
                settings = dict(self.base, hydra_client=client)
                engine = self.engine("degrade-" + side, settings)
                degraded = side == "degraded"
                self.assertEqual(engine.protocol() < 3, degraded)
                # lane hint, queue info, `next`: not sent; waits keep the client budgets.
                self.assertEqual(hydra.supports(engine, "laneHint"), not degraded)
                self.assertEqual(hydra.patience_ms(engine, query.BUSY_WAIT_MS),
                                 query.BUSY_WAIT_MS if degraded else int(hydra.PATIENCE_S * 1000))
                # deadlines: the 7.6 helper (and its pool) on hydra.2/3, P1b's deadline with library 1.1.0.
                self.assertEqual(engine.deadline_mode(), "helper" if degraded else "native")
                runner = query.QueryRunner(settings, engine)
                self.assertEqual(runner._pool() is not None, degraded)
                self.assertEqual(runner._native_deadline(30) is None, degraded)
                # format: unknown on hydra.2/3, so the commit always needs the one-way confirmation.
                if degraded:
                    with self.assertRaises(commits.CommitError) as raised:
                        commits._plan_confirmation({}, engine, self.gpr)
                    self.assertEqual(raised.exception.code, "confirmation_required")
                    self.assertNotIn("format", raised.exception.detail)
                else:
                    self.assertIsInstance(engine.call("open_project", path=self.gpr).get("format"), dict)
                    try:
                        commits._plan_confirmation({}, engine, self.gpr)
                    except commits.CommitError as exc:
                        self.assertIn("format", exc.detail, "a refusal on hydra.4 carries what the engine reported")
                    engine.call("close_project")
                # backup: a Python-written manifest over a plain fork, or the engine's.
                self.assertEqual(backups._engine_backup(engine), not degraded)
                # health: `ping` with a deadline on the probe's own connection; wedge detection needs the pid and the lock.
                supervisor = hydra.Supervisor.for_engine(engine, settings)
                reply = supervisor.probe()
                if degraded:
                    self.assertEqual(reply, {})
                else:
                    self.assertEqual(reply.get("state"), "ok", reply)
                self.assertIsNone(hydra.wedge_signal(reply))
                self.assertTrue(supervisor.pid_alive())
                self.assertFalse(supervisor.lock_free())
                self.assertEqual(supervisor.tick()["event"], "ok")


if __name__ == "__main__":
    unittest.main()
