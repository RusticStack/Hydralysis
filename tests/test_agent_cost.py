"""Per-agent CPU of a Hydralysis process (rust/t-hy-agents): what one agent costs while it queries and while it waits.

- A query resolved the data root and its project paths about twenty times; `Path.resolve` opens each path twice on Windows.
  `paths.resolved` keeps the answer for RESOLVE_TTL_S.
- A publish worker that waits for a leader looked at the queue every POLL_S (0.1 s) and rewrote its job record each time. It
  now waits in the kernel queue of `publish.lock` (Windows) and reports progress only when it changed.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import locks, paths, targets, views


class ResolvedPaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cache = getattr(paths, "_resolved_cache", {})
        cache.clear()
        self.addCleanup(cache.clear)

    def count_resolves(self):
        real = Path.resolve
        calls = []

        def counting(path, *args, **kwargs):
            calls.append(str(path))
            return real(path, *args, **kwargs)
        return calls, patch.object(Path, "resolve", counting)

    def test_a_warm_root_path_does_not_resolve_again(self):
        settings = {"root": str(Path(self.tmp.name) / "data")}
        calls, patcher = self.count_resolves()
        with patcher:
            first = paths.root_path(settings)
            for _ in range(50):
                self.assertEqual(paths.root_path(settings), first)
        self.assertLessEqual(len(calls), 2, calls[:6])
        self.assertEqual(first, (Path(self.tmp.name) / "data").resolve())

    def test_an_old_answer_is_resolved_again(self):
        target = Path(self.tmp.name) / "p.gpr"
        calls, patcher = self.count_resolves()
        with patcher, patch.object(paths, "RESOLVE_TTL_S", 0.0):
            for _ in range(3):
                paths.resolved(target)
        self.assertEqual(len(calls), 3)

    def test_a_relative_path_is_keyed_by_the_working_directory(self):
        one, two = Path(self.tmp.name) / "one", Path(self.tmp.name) / "two"
        one.mkdir()
        two.mkdir()
        here = os.getcwd()
        self.addCleanup(os.chdir, here)
        os.chdir(one)
        first = paths.resolved("x.gpr")
        os.chdir(two)
        second = paths.resolved("x.gpr")
        self.assertEqual(first, (one / "x.gpr").resolve())
        self.assertEqual(second, (two / "x.gpr").resolve())

    def test_target_key_is_unchanged(self):
        gpr = str(Path(self.tmp.name) / "Proj" / "a.gpr")
        import hashlib
        expected = hashlib.sha256((str(Path(gpr).expanduser().resolve()).lower() + "\n" + "prog.exe").encode()).hexdigest()[:16]
        self.assertEqual(targets.target_key(gpr, "/prog.exe"), expected)

    def test_validate_project_path_still_refuses_dot_folders(self):
        with self.assertRaises(ValueError):
            paths.validate_project_path(Path(self.tmp.name) / ".hidden" / "p.gpr")


@unittest.skipUnless(os.name == "nt", "the queued wait is the Windows kernel lock queue")
class FollowerWait(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.lock_path = Path(self.tmp.name) / "publish.lock"

    def hold(self, seconds: float) -> threading.Thread:
        holder = locks.LaneLock(str(self.lock_path))
        self.assertTrue(holder.acquire())

        def later():
            time.sleep(seconds)
            holder.release()
        thread = threading.Thread(target=later)
        thread.start()
        self.addCleanup(thread.join)
        return thread

    def test_await_turn_returns_the_lock_soon_after_the_leader_lets_go(self):
        self.hold(0.4)
        with patch.object(views, "publish_lock_path", return_value=self.lock_path):
            started = time.monotonic()
            turn = views.await_turn({}, "l-1", 5.0)
            waited = time.monotonic() - started
        self.assertIsNotNone(turn)
        try:
            self.assertGreaterEqual(waited, 0.3)
            self.assertLess(waited, 2.0)
            self.assertTrue(locks.held(str(self.lock_path)), "the granted turn holds publish.lock")
        finally:
            turn.release()
        self.assertFalse(locks.held(str(self.lock_path)))

    def test_await_turn_gives_up_after_its_timeout(self):
        self.hold(1.5)
        with patch.object(views, "publish_lock_path", return_value=self.lock_path):
            started = time.monotonic()
            self.assertIsNone(views.await_turn({}, "l-1", 0.3))
            self.assertLess(time.monotonic() - started, 1.2)

    def test_a_waiting_follower_neither_polls_nor_rewrites_its_progress(self):
        """While a leader holds the lock for 1.5 s, the old loop looked at the queue ~15 times and wrote progress each time."""
        self.hold(1.5)
        looks, reports, drains = [], [], []
        decided = {"outcome": "applied", "generation": 1}

        def read_done(settings, lineage_id, csid):
            looks.append(time.monotonic())
            return decided if drains and drains[-1] == "led" else None

        def drain(settings, lineage_id, engine=None, stop_after=None, timeout_s=600, lock=None):
            if lock is None:
                probe = locks.LaneLock(str(self.lock_path))
                if not probe.acquire():
                    drains.append("busy")
                    return {"led": False, "built": [], "failure": None}
                lock = probe
            lock.release()
            drains.append("led")
            return {"led": True, "built": [1], "failure": None}

        info = {"state": "publish_pending", "csid": "c-1", "position": 2, "etaMs": None, "leader": True}
        with patch.object(views, "publish_lock_path", return_value=self.lock_path), \
                patch.object(views, "read_done", side_effect=read_done), patch.object(views, "drain", side_effect=drain), \
                patch.object(views, "pending_info", return_value=dict(info)), \
                patch.object(views, "_settle_own", return_value=True), patch.object(views, "_revision_of", return_value=1):
            result = views.run_publish_job({}, {"name": "t"}, {"csid": "c-1", "lineage": "l-1"}, engine=object(), timeout_s=60,
                                           progress=reports.append)
        self.assertEqual(result["outcome"], "applied")
        self.assertEqual(drains[-1], "led")
        self.assertLessEqual(drains.count("busy"), 3, drains)
        self.assertEqual(len(reports), 1, "progress is written when it changes, not on every look")
        self.assertFalse(locks.held(str(self.lock_path)))


if __name__ == "__main__":
    unittest.main()
