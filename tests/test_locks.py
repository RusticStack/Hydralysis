"""OS locks: the bounded wait, the typed `LockBusy` and the non-blocking `LaneLock` (PROTOCOL-3.md 4.10, D44, D61)."""

from __future__ import annotations

import json
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


if __name__ == "__main__":
    unittest.main()
