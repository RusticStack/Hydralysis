"""The frame-stall watchdog and the unwind-table stack capture, against the deadlock and veh_freeze fixtures (Windows x64)."""

from __future__ import annotations

import subprocess
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fixtures"))
sys.path.insert(0, str(HERE.parent / "src"))

import trace_fixtures as tf  # noqa: E402
from support import workdir  # noqa: E402

from hydralysis import trace_watchdog as wd  # noqa: E402


def frames_of(result: dict):
    return {t["tid"]: [f["at"] or "" for f in t.get("frames", [])] for t in result["threads"] if t["state"] == "captured"}


@unittest.skipUnless(tf.msvc_available(), "MSVC build tools are not installed")
class StallWatchdog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = workdir("trace-stall")
        cls.dir = {}
        for group in ("deadlock", "veh_freeze"):
            cls.dir[group] = tf.build_group(group, Path(cls.root.name) / group, ("x64",))["x64"]["dir"]

    @classmethod
    def tearDownClass(cls):
        cls.root.cleanup()

    def run_stall(self, exe: Path, args: list[str], module: str, symbol: str, stall_s: float = 0.6):
        proc = subprocess.Popen([str(exe), *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        got = []
        try:
            dog = wd.FrameStallWatchdog(proc.pid, wd.counter_reader(proc.pid, module, symbol), stall_s, got.append,
                                        poll_s=0.02, after_s=0.0).start()
            deadline = time.monotonic() + 15
            while not got and time.monotonic() < deadline and proc.poll() is None:
                time.sleep(0.05)
            dog.stop()
            self.assertEqual(dog.errors, [])
            return got, proc
        finally:
            proc.kill()
            proc.wait()

    def test_a_deadlocked_main_loop_is_captured_with_the_blocked_frames(self):
        got, _proc = self.run_stall(self.dir["deadlock"] / "deadlock.exe", ["--mode=deadlock", "--hold=8"], "deadlock.exe", "g_frame")
        self.assertEqual(len(got), 1, "one stall is one capture")
        stall = got[0]
        self.assertGreaterEqual(stall["stalled_for_s"], 0.5)
        self.assertEqual(stall["progress"], 20)
        stacks = frames_of(stall["stacks"])
        main = [chain for chain in stacks.values() if any("deadlock.exe" in at for at in chain)]
        self.assertTrue(main, stacks)
        # the unwind tables give the real chain: the wait is inside ntdll and the fixture's lock function is a caller
        self.assertTrue(any(any(at.startswith("ntdll") for at in chain) for chain in main))
        hows = {f["how"] for t in stall["stacks"]["threads"] for f in t.get("frames", [])}
        self.assertIn("unwind", hows)
        self.assertNotIn("stack-scan", hows)

    def test_the_blocked_function_is_named_by_the_map_file(self):
        got, _proc = self.run_stall(self.dir["deadlock"] / "deadlock.exe", ["--mode=deadlock", "--hold=8"], "deadlock.exe", "g_frame")
        want = {}
        for line in (self.dir["deadlock"] / "deadlock.map").read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1].startswith("fx_main_lock_a_then_b"):
                want = int(parts[2], 16)
        base = 0x140000000
        found = False
        for thread in got[0]["stacks"]["threads"]:
            for frame in thread.get("frames", []):
                if frame["at"] and frame["at"].lower().startswith("deadlock.exe+") and base + int(frame["at"].split("+")[1], 16) - want in range(0, 0x200):
                    found = True
        self.assertTrue(found, "fx_main_lock_a_then_b is on the main thread's chain")

    def test_a_handler_that_suspends_every_thread_does_not_stop_the_capture(self):
        got, _proc = self.run_stall(self.dir["deadlock"] / "deadlock.exe", ["--mode=suspend-all", "--hold=8"], "deadlock.exe", "g_frame")
        self.assertEqual(len(got), 1)
        captured = [t for t in got[0]["stacks"]["threads"] if t["state"] == "captured"]
        self.assertGreaterEqual(len(captured), 3)            # main, faulting worker, reaper, watchdog

    def test_a_loop_that_keeps_advancing_is_never_captured(self):
        proc = subprocess.Popen([str(self.dir["deadlock"] / "deadlock.exe"), "--mode=suspend-all", "--hold=1"], stdout=subprocess.PIPE)
        got = []
        try:
            # a progress source that always moves
            tick = iter(range(10 ** 9))
            dog = wd.FrameStallWatchdog(proc.pid, lambda: next(tick), 0.3, got.append, poll_s=0.02).start()
            time.sleep(1.0)
            dog.stop()
            self.assertEqual(got, [])
        finally:
            proc.kill()
            proc.wait()

    def test_a_loop_that_never_started_is_not_a_stall(self):
        got = []
        dog = wd.FrameStallWatchdog(0, lambda: 0, 0.1, got.append, poll_s=0.02).start()
        time.sleep(0.5)
        dog.stop()
        self.assertEqual(got, [])

    def test_veh_freeze_is_captured_from_outside_without_a_fault(self):
        exe = self.dir["veh_freeze"] / "veh_freeze.exe"
        proc = subprocess.Popen([str(exe), "--mode=wait", "--seconds=4"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            time.sleep(1.0)
            result = wd.capture_stacks(proc.pid)
            self.assertEqual(result["state"], "captured")
            self.assertTrue(any("veh_freeze.exe" in at for chain in frames_of(result).values() for at in chain))
            out = proc.communicate(timeout=15)[0].decode(errors="replace")
            self.assertIn("handler_ran=0", out)
        finally:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
