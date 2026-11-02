"""ETW supervisor, watchdog, footprint diff and pairing."""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hydralysis import trace_capture as tc  # noqa: E402
from hydralysis import trace_etw, trace_footprint as fp, trace_pairing as pr  # noqa: E402

ETW = Path(os.environ.get("HYDRA_ETW", r"C:\dev-overflow\cargo-target\l-capture-etw\debug\hydra-etw.exe"))
ELEVATED = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False


class EtwSupervisor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "scope.key").write_bytes(bytes(range(32)))
        self.target = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])

    def tearDown(self):
        self.target.kill()
        self.target.wait()
        self.tmp.cleanup()

    @unittest.skipUnless(ETW.is_file(), "hydra-etw not built")
    def test_not_elevated_is_recorded_as_missing_coverage(self):
        if ELEVATED:
            self.skipTest("elevated: the refusal path cannot be exercised")
        c = trace_etw.EtwConsumer(self.dir, "s", [self.target.pid], self.dir / "scope.key", binary=ETW)
        self.assertEqual(c.start(), {"state": "refused", "limitation": "etw-not-elevated"})
        v = tc.verify_segment(self.dir / "etw.seg", c.segment_id)
        self.assertEqual(v["outcome"], "clean")
        self.assertIn("etw-not-elevated", c.coverage()["limitations"])
        self.assertFalse(c.coverage()["complete"])

    @unittest.skipUnless(ETW.is_file() and ELEVATED, "needs the built tool and an elevated token")
    def test_elevated_session_records_and_verifies(self):
        c = trace_etw.EtwConsumer(self.dir, "s", [self.target.pid], self.dir / "scope.key", binary=ETW)
        self.assertEqual(c.start()["state"], "running")
        time.sleep(1)
        self.assertEqual(c.stop()["state"], "stopped")
        self.assertEqual(tc.verify_segment(self.dir / "etw.seg", c.segment_id)["outcome"], "clean")

    def test_missing_binary_is_unavailable_not_an_error(self):
        c = trace_etw.EtwConsumer(self.dir, "s", [1], self.dir / "scope.key", binary=None)
        c.binary = None
        self.assertEqual(c.start()["state"], "unavailable")


@unittest.skipUnless(os.name == "nt", "Windows only")
class Watchdog(unittest.TestCase):
    def test_captures_every_thread_without_stopping_the_target(self):
        from hydralysis import trace_watchdog as wd
        code = "import threading,time\nfor _ in range(3): threading.Thread(target=time.sleep,args=(30,),daemon=True).start()\ntime.sleep(30)"
        p = subprocess.Popen([sys.executable, "-c", code])
        try:
            time.sleep(1.0)
            r = wd.capture_stacks(p.pid)
            self.assertEqual(r["state"], "captured")
            got = [t for t in r["threads"] if t["state"] == "captured"]
            self.assertGreaterEqual(len(got), 4)
            self.assertTrue(any(f["at"] for t in got for f in t["frames"]))
            self.assertTrue(any(f["at"] and f["at"].lower().startswith(("ntdll", "kernelbase", "python")) for t in got for f in t["frames"]))
            self.assertIsNone(p.poll())
            r2 = wd.capture_stacks(p.pid)  # threads were resumed: a second capture works and the process lives
            self.assertEqual(r2["state"], "captured")
        finally:
            p.kill()
            p.wait()

    def test_unopenable_process_is_refused_not_guessed(self):
        from hydralysis import trace_watchdog as wd
        self.assertEqual(wd.capture_stacks(0x7FFFFFF0)["state"], "refused")


class Footprint(unittest.TestCase):
    def test_diff_classify_and_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.cfg").write_text("1")
            (root / "log.txt").write_text("x")
            s0 = fp.snapshot([root])
            (root / "a.cfg").write_text("2")      # caused by the intervention
            (root / "log.txt").write_text("xy")   # ordinary: the control run changes it too
            (root / "new.dat").write_text("n")
            s1 = fp.snapshot([root])
            d_int = fp.diff(s0, s1)
            self.assertEqual(len(d_int["changed"]), 2)
            control = {"added": [], "removed": [], "changed": [os.path.normcase(str(root / "log.txt"))]}
            c = fp.classify(d_int, control)
            self.assertEqual(c["verdict"], "caused")
            self.assertEqual(sorted(Path(p).name for p in c["caused"]), ["a.cfg", "new.dat"])
            self.assertEqual(fp.classify(d_int, None)["verdict"], "unknown")
            (root / "a.cfg").write_text("1")      # revert, but forget new.dat
            r = fp.round_trip(s0, fp.snapshot([root]), ordinary={os.path.normcase(str(root / "log.txt"))})
            self.assertEqual(r["verdict"], fp.NOT_ROUND_TRIP)
            self.assertEqual([Path(p).name for p in r["paths"]], ["new.dat"])
            (root / "new.dat").unlink()
            r = fp.round_trip(s0, fp.snapshot([root]), ordinary={os.path.normcase(str(root / "log.txt"))})
            self.assertEqual(r["verdict"], "round-trips")


def ev(marker, t):
    return {"t_mono_ns": t, "payload": {"marker": marker}}


class Pairing(unittest.TestCase):
    def setUp(self):
        # replica clock = owner clock * 0.999 - 5e6 (drift and offset), markers m0..m4
        self.owner = [ev(f"m{i}", 1e9 * i + 3e9) for i in range(5)]
        self.replica = [ev(f"m{i}", (1e9 * i + 3e9 + 5e6) / 0.999 + (2000 if i == 2 else 0)) for i in range(5)]

    def test_calibration_recovers_offset_and_drift(self):
        cal = pr.pair(self.owner, self.replica)["calibration"]
        self.assertTrue(cal.ok)
        self.assertAlmostEqual(cal.drift, 0.999, places=6)
        self.assertLess(cal.uncertainty_ns, 3000)

    def test_ordering_is_three_valued(self):
        cal = pr.pair(self.owner, self.replica)["calibration"]
        t_r = (4e9 + 3e9 + 5e6) / 0.999
        self.assertEqual(pr.ordered_before(cal, 5e9, t_r), pr.TRUE)
        self.assertEqual(pr.ordered_before(cal, 9e9, t_r), pr.FALSE)
        self.assertEqual(pr.ordered_before(cal, 7e9 + 100, t_r), pr.UNKNOWN)  # inside the uncertainty
        self.assertEqual(pr.ordered_before(cal, 5e9, t_r, [pr.Outage(6e9, 8e9)]), pr.UNKNOWN)  # outage

    def test_too_few_or_ambiguous_markers_are_unknown(self):
        few = pr.pair(self.owner[:2], self.replica[:2])
        self.assertFalse(few["usable"])
        self.assertEqual(pr.ordered_before(few["calibration"], 1, 2), pr.UNKNOWN)
        dup = self.owner + [ev("m0", 9e9)]
        self.assertEqual(pr.pair(dup, self.replica)["pairs"], 4)

    def test_both_observed(self):
        self.assertEqual(pr.both_observed(True, True), pr.TRUE)
        self.assertEqual(pr.both_observed(True, None), pr.UNKNOWN)
        self.assertEqual(pr.both_observed(False, None), pr.FALSE)


if __name__ == "__main__":
    unittest.main()
