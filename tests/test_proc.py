import gc
import os
import subprocess
import sys
import time
import unittest
import warnings
from pathlib import Path

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
