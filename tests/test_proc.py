import gc
import os
import subprocess
import sys
import time
import unittest
import threading
import warnings
from pathlib import Path
from unittest import mock

from hydralysis import proc
from support import workdir


class BackgroundProcessLifetime(unittest.TestCase):
    def test_running_child_is_retained_and_reaped_after_exit(self):
        child = proc.popen([sys.executable, "-c", "import time; time.sleep(0.3)"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with proc._children_changed:
            self.assertIn(child, proc._children)
        self.assertEqual(child.wait(timeout=10), 0)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with proc._children_changed:
                if child not in proc._children:
                    break
            time.sleep(0.05)
        else:
            self.fail("completed child remained in the reaper registry")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            del child
            gc.collect()
        self.assertFalse([warning for warning in caught if issubclass(warning.category, ResourceWarning)])

    def isolated(self):
        """A private registry and reaper, so children of other tests in this process cannot keep the thread alive."""
        self.foreign = {t for t in threading.enumerate() if t.name == "hydralysis-child-reaper"}
        for name, value in (("_children", set()), ("_children_changed", threading.Condition()), ("_reaper", None)):
            patcher = mock.patch.object(proc, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def wait_until(self, condition, what, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.02)
        self.fail(what)

    def reapers(self):
        return [t for t in threading.enumerate() if t.name == "hydralysis-child-reaper" and t not in self.foreign]

    def test_the_reaper_thread_ends_when_the_last_child_is_reaped(self):
        self.isolated()
        child = proc.popen([sys.executable, "-c", "pass"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(len(self.reapers()), 1)
        self.assertEqual(child.wait(timeout=10), 0)
        self.wait_until(lambda: not self.reapers(), "the child-reaper thread outlived its last child")
        self.assertEqual(proc._children, set())
        self.assertIsNone(proc._reaper)

    def test_a_child_started_after_the_reaper_ended_gets_a_new_reaper(self):
        self.isolated()
        for _ in range(3):
            child = proc.popen([sys.executable, "-c", "pass"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(child.wait(timeout=10), 0)
            self.wait_until(lambda: not self.reapers(), "the child-reaper thread outlived its last child")
        long = proc.popen([sys.executable, "-c", "import time; time.sleep(1.5)"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertEqual(len(self.reapers()), 1, "a running child must keep a reaper")
        self.assertEqual(long.wait(timeout=10), 0)
        self.wait_until(lambda: not self.reapers() and long not in proc._children, "the reaper did not end after the child")

    def test_a_reaper_that_is_ending_never_strands_a_new_child(self):
        # Short children started while earlier reapers are ending: every handle is registered and then reaped,
        # and no thread remains at the end.
        self.isolated()
        children = [proc.popen([sys.executable, "-c", "pass"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    for _ in range(6)]
        for child in children:
            self.assertEqual(child.wait(timeout=30), 0)
        self.wait_until(lambda: not proc._children, "children remained in the registry")
        self.wait_until(lambda: not self.reapers(), "the child-reaper thread outlived its last child")
        self.assertLessEqual(len(self.reapers()), 1)

    def test_short_lived_client_can_leave_background_child_running(self):
        with workdir("child-lifetime") as work:
            marker = Path(work) / "done.txt"
            worker = "import time, pathlib, sys; time.sleep(0.5); pathlib.Path(sys.argv[1]).write_text('done')"
            launcher = ("import gc, subprocess, sys; from hydralysis import proc; "
                        "proc.popen([sys.executable, '-c', sys.argv[1], sys.argv[2]], "
                        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); gc.collect()")
            result = subprocess.run([sys.executable, "-W", "always::ResourceWarning", "-c", launcher, worker, str(marker)],
                                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
                                    env=dict(os.environ))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("ResourceWarning", result.stderr)
            deadline = time.monotonic() + 10
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(marker.exists(), "detached child did not complete after its launcher exited")
            self.assertEqual(marker.read_text(), "done")


if __name__ == "__main__":
    unittest.main()
