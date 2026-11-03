"""The Rust stack capture (crates/hy-trace/src/capture.rs + unwind.rs, bound in native/src/trace/watchdog.rs) against Python.

A target whose threads are all asleep has stacks that do not move, so the Python capture and the Rust capture of the same
process must give the same threads with the same frames, key for key.
"""

import contextlib
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hydralysis import trace_native, trace_watchdog as wd


@contextlib.contextmanager
def impl(value):
    saved = os.environ.get("HYDRALYSIS_IMPL")
    os.environ["HYDRALYSIS_IMPL"] = value
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("HYDRALYSIS_IMPL", None)
        else:
            os.environ["HYDRALYSIS_IMPL"] = saved


def have_native():
    with impl("rust"):
        module = trace_native.native()
        return module is not None and hasattr(module, "watchdog_capture_stacks")


SLEEPERS = "import threading,time\nfor _ in range(3): threading.Thread(target=time.sleep,args=(60,),daemon=True).start()\ntime.sleep(60)"


@unittest.skipUnless(os.name == "nt" and have_native(), "Windows with the trace port built")
class RustCaptureMatchesPython(unittest.TestCase):
    def setUp(self):
        self.proc = subprocess.Popen([sys.executable, "-c", SLEEPERS])
        time.sleep(1.5)

    def tearDown(self):
        self.proc.kill()
        self.proc.wait()

    def test_the_same_threads_and_frames_of_a_sleeping_target(self):
        with impl(""):
            python = wd.capture_stacks(self.proc.pid)
        with impl("rust"):
            native = wd.capture_stacks(self.proc.pid)
        self.assertEqual(python["state"], "captured")
        self.assertEqual(list(python), list(native))                       # the same keys in the same order
        self.assertEqual({k: v for k, v in python.items() if k != "threads"}, {k: v for k, v in native.items() if k != "threads"})
        by_tid = {t["tid"]: t for t in native["threads"]}
        self.assertEqual(sorted(by_tid), sorted(t["tid"] for t in python["threads"]))
        same = 0
        for expected in python["threads"]:
            got = by_tid[expected["tid"]]
            self.assertEqual(list(expected), list(got))
            if expected.get("frames") == got.get("frames"):
                same += 1
        self.assertGreaterEqual(same, len(python["threads"]) - 1, "all but at most one busy thread have identical stacks")
        self.assertIsNone(self.proc.poll())

    def test_the_native_path_is_taken_and_the_target_lives(self):
        with impl("rust"):
            result = trace_native.function("watchdog_capture_stacks")(self.proc.pid, 24, 4096)
            again = wd.capture_stacks(self.proc.pid)
        self.assertEqual(result["state"], "captured")
        self.assertEqual(again["state"], "captured")
        self.assertTrue(all(t.get("suspended_before") == 0 for t in again["threads"] if t["state"] == "captured"))
        self.assertIsNone(self.proc.poll())

    def test_a_missing_process_is_refused_in_both(self):
        with impl(""):
            python = wd.capture_stacks(0x7FFFFFF0)
        with impl("rust"):
            native = wd.capture_stacks(0x7FFFFFF0)
        self.assertEqual(python["state"], native["state"])
        self.assertEqual(list(python), list(native))
        self.assertEqual(python["reason"], native["reason"])

    def test_arguments_the_port_does_not_model_use_python(self):
        module = trace_native.native
        with impl("rust"):
            native = module()
            with self.assertRaises(native.TraceFallback):
                native.watchdog_capture_stacks(-1, 24, 4096)
            self.assertEqual(wd.capture_stacks(0x7FFFFFF0)["state"], "refused")


if __name__ == "__main__":
    unittest.main()
