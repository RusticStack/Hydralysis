"""The supervisor policy (PROTOCOL-3.md 7.2, D55; Y4a), against scripted stand-ins for the daemon, and `RealPolicy` against a
real daemon (only when HYDRALYSIS_INTEGRATION_ENGINE and HYDRALYSIS_INTEGRATION_CLIENT name a Hydra install, see
tests/test_deadline.py `RealEngine`).

Fresh state roots only; the real tests start their own daemon and touch no other process."""

from __future__ import annotations

import os
import time
import unittest
from pathlib import Path

import test_deadline
from hydralysis import hydra
from support import workdir


class World:
    """A scripted daemon: what the probe answers, whether the process is alive, and what a restart does."""

    def __init__(self):
        self.alive = True
        self.lock_free = False
        self.replies = []          # each probe pops one; an Exception instance is raised; the last one repeats
        self.status = {}
        self.restarts = []
        self.restart_error = None
        self.journal = True
        self.publish = False
        self.recoverable = set()
        self.lost = []
        self.now = 0.0

    def probe(self):
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply

    def restart(self, force):
        if self.restart_error:
            raise self.restart_error
        self.restarts.append(force)
        self.alive, self.lock_free = True, False

    def supervisor(self, path):
        return hydra.Supervisor(path, probe=self.probe, pid_alive=lambda: self.alive, lock_free=lambda: self.lock_free,
                                restart=self.restart, status=lambda: self.status, recoverable=lambda program: program in self.recoverable,
                                durable_journal=lambda: self.journal, publish_in_flight=lambda: self.publish,
                                mark_lost=self.lost.extend, clock=lambda: self.now)


HEALTHY = {"state": "ok", "tick": {"ageMs": 100}, "schedulerLockOk": True, "watchdogStallMs": 30_000}
NOANSWER = TimeoutError("no answer to ping")


class Policy(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("supervisor")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "supervisor.json"
        self.world = World()
        self.world.replies = [HEALTHY]
        self.supervisor = self.world.supervisor(self.path)

    def ticks(self, count):
        return [self.supervisor.tick() for _ in range(count)]

    def test_a_healthy_daemon_is_left_alone_and_a_long_request_is_never_a_wedge(self):
        self.world.status = {"programs": [], "jobs": [{"kind": "script", "state": "running", "id": "7"}]}
        self.assertEqual({item["event"] for item in self.ticks(10)}, {"ok"})
        self.assertEqual(self.world.restarts, [])
        self.assertEqual(self.supervisor.last_status, self.world.status)

    def test_a_wedge_needs_three_consecutive_misses_and_a_good_probe_resets_the_count(self):
        self.world.replies = [NOANSWER, NOANSWER, HEALTHY, NOANSWER, NOANSWER, NOANSWER]
        events = self.ticks(5)
        self.assertEqual([item["event"] for item in events], ["miss", "miss", "ok", "miss", "miss"])
        self.assertEqual(self.world.restarts, [])
        last = self.supervisor.tick()
        self.assertEqual((last["event"], last["why"]), ("restarted", "wedged:no_answer"))
        self.assertEqual(self.world.restarts, [False])

    def test_each_wedge_signal_counts_as_a_miss(self):
        for reply, signal in (({"state": "suspect"}, "suspect"),
                              ({"tick": {"ageMs": 31_000}, "watchdogStallMs": 30_000}, "tick_stalled"),
                              ({"schedulerLockOk": False}, "scheduler_lock")):
            self.assertEqual(hydra.wedge_signal(reply), signal)
        self.assertIsNone(hydra.wedge_signal(HEALTHY))
        self.assertEqual(hydra.wedge_signal(None), "no_answer")

    def test_a_dead_process_with_a_free_lock_is_restarted_at_once_and_recorded(self):
        self.world.alive, self.world.lock_free = False, True
        event = self.supervisor.tick()
        self.assertEqual((event["event"], event["why"]), ("restarted", "dead"))
        recorded = self.supervisor.events()
        self.assertEqual([item["event"] for item in recorded], ["restarted"])
        self.assertTrue(self.path.is_file())

    def test_a_pid_that_is_gone_but_whose_lock_is_held_is_not_restarted(self):
        self.world.alive, self.world.lock_free = False, False
        self.assertEqual(self.supervisor.tick()["event"], "no_process")
        self.assertEqual(self.world.restarts, [])

    def test_no_auto_restart_without_a_durable_journal(self):
        self.world.journal = False
        self.world.alive, self.world.lock_free = False, True
        event = self.supervisor.tick()
        self.assertEqual((event["event"], event["reason"]), ("restart_refused", "journal_not_durable"))
        self.assertEqual(self.world.restarts, [])

    def test_no_restart_while_a_publish_is_mid_flight(self):
        self.world.publish = True
        self.world.alive, self.world.lock_free = False, True
        self.assertEqual(self.supervisor.tick()["reason"], "publish_in_flight")
        self.assertEqual(self.world.restarts, [])

    def test_the_budget_is_three_restarts_per_ten_minutes_then_daemon_unhealthy_and_no_attempt(self):
        for number in range(3):
            self.world.alive, self.world.lock_free = False, True
            self.world.now = number * 60.0
            self.assertEqual(self.supervisor.tick()["event"], "restarted")
        self.world.alive, self.world.lock_free = False, True
        self.world.now = 200.0
        event = self.supervisor.tick()
        self.assertEqual(event["event"], "daemon_unhealthy")
        self.assertIn("abandoned", event["doctor"])
        self.assertEqual(len(self.world.restarts), 3)
        self.assertTrue(self.supervisor.unhealthy)
        # no further attempt, even when the window has moved on: only an operator's decision probes again
        self.world.now = 601.0
        self.world.alive, self.world.lock_free = False, True
        self.assertEqual(self.supervisor.tick()["event"], "daemon_unhealthy")
        self.assertEqual(len(self.world.restarts), 3)
        self.supervisor.reset_budget()
        self.assertEqual(self.supervisor.tick()["event"], "restarted")

    def test_lost_on_restart_lists_non_recoverable_edits_and_jobs_and_marks_them(self):
        self.world.replies = [HEALTHY, NOANSWER]
        self.world.status = {"programs": [{"key": "p1:/a.exe", "unsavedEdits": 3, "lastEditor": "alice"},
                                          {"key": "p1:/working.exe", "unsavedEdits": 5},
                                          {"key": "p1:/clean.exe", "unsavedEdits": 0}],
                             "jobs": [{"kind": "import", "state": "running", "program": "p1:/new.exe"}]}
        self.world.recoverable = {"p1:/working.exe"}
        self.supervisor.tick()
        self.ticks(2)
        event = self.supervisor.tick()
        self.assertEqual(event["event"], "restarted")
        self.assertEqual([(item["program"], item["unsavedEdits"]) for item in event["lost_on_restart"]],
                         [("p1:/a.exe", 3), ("p1:/new.exe", 0)])
        self.assertEqual(self.world.lost, event["lost_on_restart"])

    def test_a_slow_daemon_is_not_restarted_while_the_list_is_not_empty_unless_forced(self):
        slow = {"state": "suspect"}
        self.world.replies = [HEALTHY, slow]
        self.world.status = {"programs": [{"key": "p1:/a.exe", "unsavedEdits": 2}]}
        self.supervisor.tick()
        self.ticks(2)
        refused = self.supervisor.tick()
        self.assertEqual((refused["event"], refused["reason"]), ("restart_refused", "unsaved_edits"))
        self.assertEqual(refused["lost_on_restart"][0]["program"], "p1:/a.exe")
        self.assertEqual(self.world.restarts, [])
        forced = self.supervisor.tick(force=True)
        self.assertEqual(forced["event"], "restarted")
        self.assertEqual(self.world.restarts, [True])

    def test_a_failed_restart_is_recorded_and_never_raised_into_the_probe_loop(self):
        self.world.alive, self.world.lock_free = False, True
        self.world.restart_error = RuntimeError("the daemon process did not exit within 45 s")
        event = self.supervisor.tick()
        self.assertEqual(event["event"], "restart_failed")
        self.assertIn("did not exit", event["error"])

    def test_the_record_is_sealed_and_keeps_every_event(self):
        for _ in range(3):
            self.world.alive, self.world.lock_free = False, True
            self.world.now += 1
            self.supervisor.tick()
        self.assertEqual(len(self.supervisor.events()), 3)
        fresh = self.world.supervisor(self.path)
        self.assertEqual(len(fresh.events()), 3, "a second process reads the same record")


class Journal(unittest.TestCase):
    def test_the_self_test_passes_on_a_writable_state_directory_and_fails_closed_otherwise(self):
        temp = workdir("journal")
        self.addCleanup(temp.cleanup)
        settings = {"root": temp.name}
        self.assertTrue(hydra.journal_durable(settings))
        blocker = Path(temp.name) / "blocked"
        blocker.write_text("a file where the state directory should be", encoding="utf-8")
        self.assertFalse(hydra.journal_durable({"root": str(blocker)}))


def _suspend(pid: int, resume: bool = False) -> None:
    """Freeze (or thaw) process PID: a daemon that is alive and holds its lock but answers nothing."""
    import ctypes
    kernel = ctypes.windll.kernel32
    handle = kernel.OpenProcess(0x0800, False, pid)   # PROCESS_SUSPEND_RESUME
    if not handle:
        raise OSError("cannot open process %d" % pid)
    try:
        (ctypes.windll.ntdll.NtResumeProcess if resume else ctypes.windll.ntdll.NtSuspendProcess)(handle)
    finally:
        kernel.CloseHandle(handle)


@unittest.skipUnless(test_deadline.HAVE_REAL, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class RealPolicy(test_deadline.RealEngine):
    """7.2 on a real daemon: `Supervisor.for_engine` with its real pid, lock, probe, status and restart."""

    def supervisor(self, **overrides):
        self.assertTrue(hydra.journal_durable(self.base), "the journal self-test passes on a fresh root (D55)")
        engine = self.engine("supervised-%d" % len(self.engines), self.base)
        engine.session()
        return engine, hydra.Supervisor.for_engine(engine, self.base, **overrides)

    @unittest.skipUnless(os.name == "nt", "suspends the daemon process with NtSuspendProcess")
    def test_supervisor_policy_suspended_daemon(self):
        engine, supervisor = self.supervisor()
        self.assertEqual(supervisor.tick()["event"], "ok")
        self.assertIsInstance(supervisor.last_status.get("programs"), list, "the status is kept at each probe")
        pid = engine.hello()["pid"]
        _suspend(pid)
        try:
            self.assertTrue(supervisor.pid_alive())
            self.assertFalse(supervisor.lock_free())
            first = supervisor.tick()
            self.assertEqual((first["event"], first["signal"], first["misses"]), ("miss", "no_answer", 1))
            self.assertEqual(supervisor.tick()["misses"], 2, "a long silence is not a wedge until the third probe")
            self.assertLessEqual(hydra.REGISTRY.count("probe"), hydra.PROBE_CAP)
            started = time.monotonic()
            third = supervisor.tick()
        finally:
            try:
                _suspend(pid, resume=True)
            except OSError:
                pass   # the restart killed it
        self.assertEqual(third["event"], "restarted", third)
        self.assertEqual(third["why"], "wedged:no_answer")
        self.assertLess(time.monotonic() - started, 5.0 + 5.0 + hydra.EXIT_WAIT_S + 60.0)
        self.assertNotEqual(engine.hello()["pid"], pid, "a new daemon answers")
        self.assertEqual(supervisor.tick()["event"], "ok")
        self.assertIn("restarted", [item["event"] for item in supervisor.events()], "every event is in supervisor.json")
        self.assertTrue(test_deadline.until(lambda: hydra.REGISTRY.count("probe") == 0, 10.0),
                        "the abandoned probes end with the old daemon")
        type(self).observer.reset()   # the observer's connection went with the old daemon

    def test_supervisor_slow_daemon_with_unsaved_edits(self):
        holder = self.engine("editor", self.base)
        holder.call("open_project", path=self.gpr, writable=True, wait=60000)
        key = holder.call("open_program", path=self.PROGRAM, writable=True, wait=60000)["key"]
        holder.call("script", script="TestEdit.java", program=key, args=[], timeout=60, wait=60000)
        slow = {"on": False}

        def probe():
            reply = real_probe()
            return dict(reply, state="suspect") if slow["on"] else reply

        engine, supervisor = self.supervisor(probe=probe)
        real_probe = hydra.Supervisor.for_engine(engine, self.base).probe
        self.assertEqual(supervisor.tick()["event"], "ok")
        edited = [item for item in supervisor.last_status.get("programs", []) if item.get("unsavedEdits")]
        self.assertTrue(edited, supervisor.last_status.get("programs"))
        pid = engine.hello()["pid"]
        slow["on"] = True
        self.assertEqual(supervisor.tick()["signal"], "suspect")
        supervisor.tick()
        refused = supervisor.tick()
        self.assertEqual((refused["event"], refused["reason"]), ("restart_refused", "unsaved_edits"), refused)
        self.assertTrue(refused["lost_on_restart"] and refused["lost_on_restart"][0]["unsavedEdits"] >= 1, refused)
        self.assertEqual(engine.hello()["pid"], pid, "a daemon that is merely slow is not restarted")
        engine.call("ping")   # it answers
        forced = supervisor.tick(force=True)
        self.assertEqual(forced["event"], "restarted", forced)
        self.assertTrue(forced["lost_on_restart"], "the restart reports what died with the daemon")
        self.assertNotEqual(engine.hello()["pid"], pid)
        holder.reset()
        type(self).observer.reset()


if __name__ == "__main__":
    unittest.main()
