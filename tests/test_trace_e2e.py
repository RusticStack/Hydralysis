"""End to end (gate M1): the real fixtures traced with the declared profile, ingested by hydra-trace, symbolized, exported.

Spawns each fixture paused under a RuntimeAgent worker, arms the verified baseline-profile hooks through
`capture start {trace}`, resumes, stops, then imports the segment with the `hydra-trace` tool (import, rebuild, verify,
resymbolize, export). Skips without MSVC, Frida or the built tool (HYDRA_TRACE_EXE).
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time
import unittest
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fixtures"))
sys.path.insert(0, str(HERE.parent / "src"))

import trace_fixtures as tf  # noqa: E402
from support import workdir  # noqa: E402

from hydralysis import trace_capture as tc  # noqa: E402

try:
    import frida  # noqa: F401
    LIVE = os.name == "nt"
except ImportError:
    LIVE = False

TOOL = os.environ.get("HYDRA_TRACE_EXE") or r"C:\dev-overflow\cargo-target\l-capture2-trace\release\hydra-trace.exe"
ELEVATED = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False


@unittest.skipUnless(LIVE and tf.msvc_available(), "needs Windows, Frida and MSVC")
class M1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import trace_live
        cls.tl = trace_live
        cls.root = workdir("trace-e2e")
        cls.fx = None
        for group in ("trace_app", "interleave", "frameloop", "veh_freeze", "deadlock"):
            built = tf.build_group(group, Path(cls.root.name) / "fx", ("x64",))["x64"]
            cls.fx = built["dir"]
        cls.store = Path(cls.root.name) / "store"
        cls.lives = []

    @classmethod
    def tearDownClass(cls):
        for live in cls.lives:
            live.close()
        cls.root.cleanup()

    def tearDown(self):
        # Each test owns the targets it starts. Close them before the next test, so a finished fixture
        # (deadlock.exe, a detached frameloop, ...) cannot load the next measurement; class teardown is
        # only the final safety net.
        for live in self.lives:
            live.close()
        self.lives.clear()

    # ---- helpers ----------------------------------------------------------------------------------------------------
    def traced(self, exe, argv, *, hooks=None, wait=True, linger_ms=600, **trace):
        specs, _verification = self.tl.specs_for(self.fx, [exe], hooks)
        live = self.tl.Live(Path(self.root.name) / "runs", self.fx / exe, argv, linger_ms=linger_ms)
        self.lives.append(live)
        live.start(specs, **trace)
        live.resume()
        if wait:
            self.assertTrue(live.wait_exit(90))
            time.sleep(0.3)
        return live

    def wait_segment(self, live, min_bytes=8192, timeout=60.0):
        # readiness, not a fixed sleep: wait until the producer has written real batches to the segment (load-proof)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                if live.segment.stat().st_size >= min_bytes:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        self.fail("the producer wrote no batches to the segment")

    @staticmethod
    def exit_code(live):
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        handle = k32.OpenProcess(0x1000, False, live.pid)       # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return "unknown (process gone)"
        try:
            code = ctypes.c_ulong()
            k32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code))
            return "still running" if code.value == 259 else hex(code.value)
        finally:
            k32.CloseHandle(ctypes.c_void_p(handle))

    def wait_attempted(self, live, count, timeout=90.0):
        # readiness on the producer's own counters (the periodic trace_counters message), not on segment bytes: those are mostly
        # setup events, and a kill that comes before the first counters message leaves `attempted` at what the batches carried
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if live.agent.trace.health().get("producer", {}).get("attempted", 0) > count:
                return
            time.sleep(0.1)
        self.fail("the producer reported fewer than %d attempted records in %.0f s" % (count, timeout))

    def stop_quiescent(self, live):
        # `capture stop` gives the recorder trace_stop's default 3 s to prove its callbacks quiescent; on a machine loaded by parallel
        # suites that proof can lapse, the recorder then stays in pass-through (`stopped: false`) and no final counters are sent. The
        # production stop is called first with a longer bound, then the capture is closed; the result is the same as live.stop()
        reply = live.agent.trace_stop({"reason": "capture stopped", "timeout_ms": 60000})
        self.assertTrue(reply["stopped"], ({k: v for k, v in reply.items() if k != "health"}, "target exit code: %s" % self.exit_code(live), "detached: %s %r" % (live.agent.detached, live.agent.detach_reason)))
        live.stopped = live.agent.handle("capture", {"op": "stop"})
        return reply

    def events(self, live):
        return tc.read_events(live.segment, live.segment_id)

    def ingest(self, live, session, exes):
        if not Path(TOOL).is_file():
            self.skipTest("hydra-trace is not built")
        return self.tl.ingest(TOOL, self.store, session, live.segment, live.segment_id, tc, self.tl.symbol_table(self.fx, exes))

    # ---- the three M1 programs ----------------------------------------------------------------------------------------
    def test_trace_app_is_recorded_ingested_symbolized_and_exported(self):
        work = Path(self.root.name) / "w-app"
        work.mkdir()
        live = self.traced("trace_app.exe", [str(work), "A"])
        stopped = live.stop()
        health = stopped["trace"]["health"]
        events = self.events(live)
        kinds = Counter(e["kind"] for e in events)
        self.assertEqual((kinds["app.feature"], kinds["app.registry"], kinds["app.plugin"]), (1, 1, 1))
        self.assertEqual(kinds["core.resource.write"], 2)
        self.assertEqual(health["producer"]["dropped"], 0)
        self.assertEqual(health["verify"]["outcome"], "clean")
        self.assertTrue(health["claims"]["fault_free"])
        hits = [e for e in events if e["kind"].startswith(("app.", "core.resource"))]
        self.assertGreater(sum(1 for e in hits if len(e.get("callstack") or []) > 1), 4)       # real chains, not one return address
        result = self.ingest(live, "m1-app", ["trace_app.exe"])
        for verb in ("import", "rebuild", "verify", "resymbolize", "export"):
            self.assertEqual(result[verb]["exit"], 0, (verb, result[verb]))
        self.assertEqual(json.loads(result["import"]["stdout"])["rejected"], 0)
        verify = json.loads(result["verify"]["stdout"])
        self.assertTrue(verify["index_matches_segments"])
        counts = result["symbolization"]
        with_address = counts["total"] - counts["no_stack"] - counts["not_code"]
        self.assertGreaterEqual(with_address, 8)
        self.assertGreaterEqual(counts["symbolized"] / with_address, 0.95, counts)          # the M1 ratio
        self.assertEqual(counts["module_unknown"], 0)
        self.assertGreater(counts["no_stack"], 0)                                           # counted separately, not hidden in the ratio
        exported = Path(result["jsonl"]).parent / "m1-app-export"
        text = (exported / "traces" / "events.jsonl").read_text(encoding="utf-8")
        self.assertEqual(len(text.splitlines()), result["events"])
        self.assertNotIn(str(work).lower(), text.lower())                                   # no path text in an export

    def test_frameloop_every_frame_and_stage_is_recorded_without_loss(self):
        live = self.traced("frameloop.exe", ["--frames=60"])
        health = live.stop()["trace"]["health"]
        kinds = Counter(e["kind"] for e in self.events(live))
        self.assertEqual(kinds["app.frame"], 120)                                           # begin and end of 60 frames
        self.assertEqual(kinds["app.stage"], 180)
        self.assertEqual(health["producer"]["dropped"], 0)
        self.assertEqual(health["encoder"]["records"], health["producer"]["attempted"])
        result = self.ingest(live, "m1-frame", ["frameloop.exe"])
        self.assertEqual(result["verify"]["exit"], 0)
        counts = result["symbolization"]
        self.assertEqual(counts["symbolized"], health["producer"]["attempted"])

    def test_interleave_requests_are_recorded_with_their_arguments(self):
        live = self.traced("interleave.exe", [])
        health = live.stop()["trace"]["health"]
        events = self.events(live)
        requests = [e for e in events if e["kind"] == "app.request"]
        self.assertGreaterEqual(len(requests), 32)
        self.assertEqual(health["producer"]["dropped"], 0)
        self.assertTrue(len({e["thread_id"] for e in requests}) >= 2)                       # more than one thread, one ring each

    # ---- section 15.1 ----------------------------------------------------------------------------------------------
    def test_veh_freeze_is_fault_free(self):
        live = self.traced("veh_freeze.exe", ["--mode=wait", "--seconds=2"])
        stopped = live.stop()
        health = stopped["trace"]["health"]
        self.assertTrue(health["claims"]["fault_free"])
        self.assertEqual(health["errors"], [])
        self.assertGreater(health["reads_refused"], 0)               # the freed address was refused by a non-faulting read, and counted
        self.assertEqual(health["producer"]["attempted"], len([e for e in self.events(live) if e["kind"] == "core.function.enter"]))
        self.assertEqual(live.agent.pid and True, True)

    # ---- the five failure modes of section 14.1 -------------------------------------------------------------------------
    def test_failure_mode_attach_to_nothing(self):
        import frida
        from hydralysis.runtime_worker import RuntimeAgent
        import hashlib
        exe = self.fx / "frameloop.exe"
        agent = RuntimeAgent(Path(self.root.name) / "none", frida.get_local_device()) if (Path(self.root.name) / "none").mkdir() is None else None
        agent.startup({"action": "spawn", "exe": str(exe), "sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "argv": [], "env": {}})
        self.addCleanup(lambda: agent.closed or agent.cleanup())
        with self.assertRaises(Exception) as caught:
            agent.handle("capture", {"op": "start", "trace": {"session": "s", "hooks": ["ghost"], "probes": [
                {"name": "ghost", "hook": "ghost", "module": "nope.dll", "rva": "0x1000", "required": False}]}})
        self.assertIn("every probe was refused", str(caught.exception))
        self.assertIsNone(agent.open_capture)                       # nothing is left recording
        self.assertIsNone(agent.trace)

    def test_failure_modes_lose_the_producer_versus_a_clean_stop(self):
        live = self.traced("frameloop.exe", ["--frames=100000", "--spin-us=1000"], wait=False)
        self.wait_segment(live, min_bytes=65536)
        stopped_alive = self.stop_quiescent(live)["health"]
        subprocess.run(["taskkill", "/F", "/PID", str(live.pid)], capture_output=True)
        self.assertEqual(stopped_alive["producer_state"], "final")                          # the producer reported its last counters
        self.assertEqual(stopped_alive["transport"]["batches_missing"], 0)
        killed = self.traced("frameloop.exe", ["--frames=100000", "--spin-us=1000"], wait=False)
        self.wait_segment(killed)
        self.wait_attempted(killed, 100)
        subprocess.run(["taskkill", "/F", "/PID", str(killed.pid)], capture_output=True)
        time.sleep(1.0)
        health = killed.stop()["trace"]["health"]
        self.assertEqual(health["producer_state"], "ended-without-final-counters")        # the producer vanished: no final counters
        self.assertEqual(health["verify"]["outcome"], "clean")                              # what arrived is intact, and said to be incomplete
        self.assertGreater(health["producer"]["attempted"], 100)

    def test_failure_mode_overflow(self):
        # exact mode: the sampling policy would thin this loop before the ring could overflow, and this test is about overflow
        live = self.traced("frameloop.exe", ["--frames=20000"], ring_bytes=1 << 16, batch_ms=300, counter_ms=100, bp_ms=0.2, window=1,
                           sampling="exact")
        health = live.stop()["trace"]["health"]
        self.assertGreater(health["producer"]["dropped"], 0)
        gaps = [e["payload"] for e in self.events(live) if e["kind"] == "core.capture.gap"]
        self.assertTrue(gaps)
        self.assertTrue({g["reason"] for g in gaps} <= {"ring-overflow", "producer-lost"}, [g for g in gaps if g["reason"] not in ("ring-overflow", "producer-lost")][:3])
        cited = sum(g["dropped"] for g in gaps if g["reason"] in ("ring-overflow", "producer-lost"))
        self.assertGreaterEqual(cited + health["encoder"]["records"], health["producer"]["attempted"])   # every attempt is a record or cited

    def test_a_loop_over_the_rate_budget_is_thinned_and_every_skip_is_counted(self):
        # The DEFAULT policy: the bare loop offers far more than the budget, so probes are thinned; nothing is
        # silent. The budget is 1,000/s so thinning starts early and a kept event is labelled `sampled` even on a
        # loaded host; the exact budget is not the subject, the policy, the citations and the sampled label are.
        live = self.traced("frameloop.exe", ["--frames=60000"], sampling={"mode": "adaptive", "rate_budget": 1000})
        health = live.stop()["trace"]["health"]
        sampling = health["producer"]["sampling"]
        self.assertEqual(sampling["policy"], "adaptive")
        self.assertGreater(sampling["skipped"], 0)
        events = self.events(live)
        gaps = [e["payload"] for e in events if e["kind"] == "core.capture.gap" and e["payload"].get("sampled")]
        self.assertTrue(gaps)
        self.assertTrue(all(g["reason"] == "budget" for g in gaps))
        self.assertEqual(sum(g["dropped"] for g in gaps), sampling["skipped"])                 # every skipped hit is cited, exactly
        calls = [e for e in events if not e["kind"].startswith("core.capture.") and e["kind"] != "core.marker"]
        thinned = {row["probe"] for row in sampling["sites"] if row["stride"] > 1}
        thinned_calls = [e for e in calls if (e.get("payload") or {}).get("site") in thinned]
        # A site thinned only at the very end may have no kept record before the capture stops; the wire mapping
        # (F_SAMPLED -> confidence "sampled") is covered deterministically by tests.test_trace_wire. Every record
        # that does come from a thinned site must carry the label.
        self.assertTrue(all(e["confidence"] == "sampled" for e in thinned_calls),
                        [(e["kind"], e["confidence"]) for e in thinned_calls if e["confidence"] != "sampled"][:5])
        total = sum(r["hits"] for r in sampling["sites"])
        self.assertEqual(total, sampling["skipped"] + sum(r["kept"] for r in sampling["sites"]))
        self.assertEqual(health["verify"]["outcome"], "clean")

    def test_exact_mode_keeps_every_hit_and_labels_nothing_sampled(self):
        live = self.traced("frameloop.exe", ["--frames=300"], sampling="exact")
        health = live.stop()["trace"]["health"]
        self.assertEqual(health["producer"]["sampling"]["skipped"], 0)
        self.assertFalse([e for e in self.events(live) if e["confidence"] == "sampled"])

    def test_failure_mode_restart_child_is_a_new_producer_generation_and_process(self):
        first = self.traced("frameloop.exe", ["--frames=30"], producer_gen=1)
        first.stop()
        second = self.traced("frameloop.exe", ["--frames=30"], producer_gen=2)
        second.stop()
        a, b = self.events(first), self.events(second)
        self.assertEqual({e["producer_gen"] for e in a}, {1})
        self.assertEqual({e["producer_gen"] for e in b}, {2})
        self.assertNotEqual(first.segment_id, second.segment_id)
        self.assertNotEqual({e["process_id"] for e in a}, {e["process_id"] for e in b})

    def test_failure_mode_kill_writer_leaves_a_torn_tail_the_verifier_names(self):
        live = self.traced("frameloop.exe", ["--frames=30"])
        live.stop()
        data = live.segment.read_bytes()
        torn = live.segment.with_name("torn.seg")
        torn.write_bytes(data[:-25])
        self.assertEqual(tc.verify_segment(live.segment, live.segment_id)["outcome"], "clean")
        verdict = tc.verify_segment(torn, live.segment_id)
        self.assertEqual(verdict["outcome"], "torn-tail")
        self.assertGreater(verdict["records"], 10)                                          # the intact prefix is kept
        if Path(TOOL).is_file():
            done = subprocess.run([TOOL, "verify", str(torn), live.segment_id], capture_output=True, text=True)
            self.assertEqual(done.returncode, 1)                                            # the engine's verifier agrees
            self.assertIn("damage", done.stdout)

    # ---- ETW -------------------------------------------------------------------------------------------------------
    def test_etw_without_elevation_is_visible_as_missing_coverage(self):
        if ELEVATED:
            self.skipTest("elevated: the refusal path cannot be exercised")
        live = self.traced("frameloop.exe", ["--frames=20"], etw=True)
        stopped = live.stop()
        etw = stopped["trace"]["etw"]
        self.assertIn(etw["start"]["state"], ("refused", "unavailable"))
        refused = [e for e in self.events(live) if e["kind"] == "core.capture.source" and e["payload"].get("source_type") == "etw"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["payload"]["state"], "refused")
        self.assertIn(refused[0]["payload"]["limitation"], ("etw-not-elevated", "etw-binary-missing", "etw-unavailable"))
        self.assertFalse(etw["coverage"]["complete"])

    # ---- the frame-stall watchdog inside the worker ---------------------------------------------------------------------
    def test_a_deadlocked_frame_loop_is_captured_by_the_worker_watchdog(self):
        live = self.traced("deadlock.exe", ["--mode=deadlock", "--hold=8"], wait=False, linger_ms=0,
                           watchdog={"hook": "main-frame", "stall_s": 0.8})
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and live.agent.trace_info["watchdog"].captures == 0:
            time.sleep(0.1)
        stopped = live.stop()
        summary = stopped["trace"]["watchdog"]
        self.assertEqual(summary["captures"], 1)
        self.assertEqual(summary["errors"], [])
        stall = json.loads(Path(summary["last"]["file"]).read_text(encoding="utf-8"))
        self.assertEqual(stall["progress"], 20)
        names = [f["at"] or "" for t in stall["stacks"]["threads"] for f in t.get("frames", [])]
        self.assertTrue(any(n.lower().startswith("deadlock.exe+") for n in names))
        self.assertTrue(any(n.lower().startswith("ntdll") for n in names))
        subprocess.run(["taskkill", "/F", "/PID", str(live.pid)], capture_output=True)


if __name__ == "__main__":
    unittest.main()
