"""OS locks: the bounded wait, the typed `LockBusy` and the non-blocking `LaneLock` (PROTOCOL-3.md 4.10, D44, D61)."""

from __future__ import annotations

import json
import multiprocessing
import os
import statistics
import subprocess
import sys
import time
import unittest
from pathlib import Path

from hydralysis import locks
from hydralysis.locks import LaneLock, LockBusy, locked
from support import workdir

SRC = Path(__file__).resolve().parent.parent / "src"


class LaneLockIsNonBlocking(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("locks")
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "a.lock")

    def test_a_second_acquire_returns_false_at_once(self):
        first, second = LaneLock(self.path), LaneLock(self.path)
        self.assertTrue(first.acquire())
        started = time.monotonic()
        self.assertFalse(second.acquire())
        self.assertLess(time.monotonic() - started, 2)
        first.release()
        self.assertTrue(second.acquire())
        second.release()

    def test_acquire_is_idempotent_for_the_holder_and_held_reports_it(self):
        lease = LaneLock(self.path)
        self.assertTrue(lease.acquire())
        self.assertTrue(lease.acquire())
        self.assertTrue(locks.held(self.path))
        lease.release()
        self.assertFalse(locks.held(self.path))

    def test_the_os_releases_the_lock_when_the_holder_is_killed(self):
        code = ("import sys,time\nsys.path.insert(0,%r)\nfrom hydralysis.locks import LaneLock\n"
                "l=LaneLock(%r)\nassert l.acquire()\nprint('held',flush=True)\ntime.sleep(3600)\n" % (str(SRC), self.path))
        child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        self.addCleanup(child.stdout.close)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        self.assertEqual(child.stdout.readline().strip(), "held")
        self.assertFalse(LaneLock(self.path).acquire())
        child.kill()
        child.wait()
        deadline = time.monotonic() + 10
        survivor = LaneLock(self.path)
        while not survivor.acquire():
            self.assertLess(time.monotonic(), deadline, "the lock of a killed holder was never released")
            time.sleep(0.05)
        survivor.release()


class LockBusyIsTyped(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("locks")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "view.lock"

    def test_the_bounded_wait_raises_lockbusy_with_its_facts(self):
        holder = LaneLock(str(self.path))
        self.assertTrue(holder.acquire())
        self.addCleanup(holder.release)
        started = time.monotonic()
        with self.assertRaises(LockBusy) as raised:
            with locked(self.path, 0.3, "working copy"):
                self.fail("the lock was held by someone else")
        busy = raised.exception
        self.assertGreaterEqual(time.monotonic() - started, 0.25)
        self.assertEqual((busy.what, Path(busy.path).name), ("working copy", "view.lock"))
        self.assertGreaterEqual(busy.waited_s, 0.25)
        self.assertGreater(busy.retry_after_ms, 0)
        self.assertIsInstance(busy, ValueError)  # callers that caught the old ValueError still do
        payload = busy.payload()
        self.assertEqual(payload["error"], "busy")
        self.assertEqual(payload["retryAfterMs"], busy.retry_after_ms)
        json.dumps(payload)

    def test_a_free_lock_is_taken_and_released(self):
        with locked(self.path, 1, "working copy"):
            self.assertTrue(locks.held(str(self.path)))
        self.assertFalse(locks.held(str(self.path)))

    def test_the_lock_is_released_when_the_body_raises(self):
        with self.assertRaises(KeyError):
            with locked(self.path, 1, "working copy"):
                raise KeyError("x")
        with locked(self.path, 1, "working copy"):
            pass


def _contender(path, rounds, barrier, grants, results):
    """One of N processes taking the lock back to back (the worst case for an unfair lock: a releaser asks again
    at once). Per acquisition it records the wait and how many other grants happened while it waited."""
    waits, bypassed, holds, busy = [], [], [], []
    try:
        barrier.wait(60)
        for _ in range(rounds):
            before = grants.value
            asked = time.perf_counter()
            try:
                with locked(Path(path), 30, "fairness"):
                    got = time.perf_counter()
                    seen = grants.value
                    grants.value = seen + 1  # only ever written under the lock
                    time.sleep(0.002)        # the work of the critical section (an append's write + fsync)
                    holds.append(time.perf_counter() - got)
            except LockBusy as error:
                busy.append(error.waited_s)
                continue
            waits.append(got - asked)
            bypassed.append(seen - before)
        results.put({"waits": waits, "bypassed": bypassed, "holds": holds, "busy": busy})
    except BaseException as error:  # reported, never lost
        results.put({"error": repr(error)})


@unittest.skipUnless(os.name == "nt", "the queued wait is the Windows lock; POSIX keeps the polled wait")
class LockedIsFair(unittest.TestCase):
    """Gate 9.10: with 16 writers one append waited 8.3 s and on E: 6 writers starved into LockBusy after 30 s.
    The bounded wait now queues in the kernel, so every waiter is served in turn."""

    WRITERS, ROUNDS = 8, 15

    def setUp(self):
        self.temp = workdir("locks")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "store.lock"

    def test_n_writers_released_together_are_served_in_turn(self):
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(self.WRITERS)
        grants = context.Value("q", 0, lock=False)
        results = context.Queue()
        workers = [context.Process(target=_contender, args=(str(self.path), self.ROUNDS, barrier, grants, results))
                   for _ in range(self.WRITERS)]
        for worker in workers:
            worker.start()
        self.addCleanup(lambda: [w.kill() for w in workers if w.is_alive()])
        rows = [results.get(timeout=240) for _ in workers]
        for worker in workers:
            worker.join(60)
        self.assertEqual([r for r in rows if "error" in r], [])
        self.assertEqual([r["busy"] for r in rows if r["busy"]], [], "a writer starved into LockBusy")
        bypassed = [x for r in rows for x in r["bypassed"]]
        waits = [x for r in rows for x in r["waits"]]
        holds = [x for r in rows for x in r["holds"]]
        self.assertEqual(len(waits), self.WRITERS * self.ROUNDS, "every writer got the lock every time")
        self.assertEqual(grants.value, self.WRITERS * self.ROUNDS)
        # Fair: while one writer waits, each other writer is served about once, so at most N-1 grants overtake
        # it; allow twice that. The polled wait let one writer take the lock back for all its rounds (~N*ROUNDS).
        self.assertLessEqual(max(bypassed), 2 * (self.WRITERS - 1), "overtaken %s times" % sorted(bypassed)[-5:])
        # And in time: the longest wait is a small multiple of the fair share, (N-1) holds.
        fair_share = (self.WRITERS - 1) * statistics.mean(holds)
        self.assertLessEqual(max(waits), 3 * fair_share + 0.5,
                             "max wait %.3f s, fair share %.3f s" % (max(waits), fair_share))


def _hold_until_killed(path, ready):
    with locked(Path(path), 30, "holder"):
        ready.set()
        time.sleep(3600)


def _queue_for(path, ready, results):
    try:
        ready.set()
        asked = time.monotonic()
        with locked(Path(path), 60, "waiter"):
            results.put(("held", time.monotonic() - asked))
    except BaseException as error:
        results.put(("error", repr(error)))


class LockedSurvivesAKilledHolder(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("locks")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "store.lock"

    def test_queued_waiters_are_served_when_the_holder_is_killed(self):
        context = multiprocessing.get_context("spawn")
        held = context.Event()
        holder = context.Process(target=_hold_until_killed, args=(str(self.path), held))
        holder.start()
        self.addCleanup(lambda: holder.is_alive() and holder.kill())
        self.assertTrue(held.wait(120), "the holder never took the lock")
        results = context.Queue()
        waiters = []
        for _ in range(3):
            queued = context.Event()
            waiter = context.Process(target=_queue_for, args=(str(self.path), queued, results))
            waiter.start()
            self.addCleanup(lambda w=waiter: w.is_alive() and w.kill())
            self.assertTrue(queued.wait(120))
            waiters.append(waiter)
        # A waiter that gives up (its request is withdrawn) leaves no ghost behind it in the queue.
        with self.assertRaises(LockBusy):
            with locked(self.path, 0.2, "impatient"):
                self.fail("the lock was held by the holder")
        holder.kill()
        holder.join(30)
        outcomes = [results.get(timeout=60) for _ in waiters]
        self.assertEqual([kind for kind, _ in outcomes], ["held"] * 3, outcomes)
        for waiter in waiters:
            waiter.join(30)
            self.assertEqual(waiter.exitcode, 0)
        with locked(self.path, 5, "after"):
            pass

    def test_a_killed_waiter_does_not_block_the_queue(self):
        context = multiprocessing.get_context("spawn")
        results = context.Queue()
        with locked(self.path, 5, "holder"):
            queued = context.Event()
            doomed = context.Process(target=_queue_for, args=(str(self.path), queued, results))
            doomed.start()
            self.addCleanup(lambda: doomed.is_alive() and doomed.kill())
            self.assertTrue(queued.wait(120))
            doomed.kill()
            doomed.join(30)
        started = time.monotonic()
        with locked(self.path, 10, "next"):
            self.assertLess(time.monotonic() - started, 5)


if __name__ == "__main__":
    unittest.main()
