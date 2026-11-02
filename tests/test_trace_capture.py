"""Trace capture: the writer (counters, gaps, durability, teardown policy) and, on Windows with Frida, the real recorder.

The live tests spawn this Python as a target (a script that calls CreateFileW and DeviceIoControl through ctypes) and
inject the native recorder into that process only. They skip when Frida or Windows is missing.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from hydralysis import trace_capture as tc
from hydralysis import trace_wire as tw
from support import workdir

try:
    import frida  # type: ignore[import-not-found]
    LIVE = os.name == "nt"
except ImportError:
    frida, LIVE = None, False

SITES = {1: {"name": "CreateFileW", "kind": "open", "module": "KernelBase.dll", "va": 0x7FF800001000},
         2: {"name": "DeviceIoControl", "kind": "ioctl", "module": "KernelBase.dll", "va": 0x7FF800002000, "buf": "payload"}}
KEY = bytes(range(32))


def wide(text: str) -> bytes:
    return text.encode("utf-16le") + b"\0\0"


def rec(ring, seq, qpc, path="C:\\x", handle=7, site=1, **extra):
    base = {"site": site, "ring": ring, "ring_seq": seq, "qpc": qpc, "tid": 50 + ring, "ret_addr": 0x7FF8000099, "qpc_end": qpc + 9,
            "retval": handle, "flags": tw.F_RET | (tw.F_WIDE if site == 1 else 0), "args": [0, 1, 2, 3, 4, 5, 6, 7][:8 if site == 2 else 7],
            "buf": wide(path) if site == 1 else b"\xde\xad\xbe\xef", "buf_addr": 0x4000}
    base.update(extra)
    return base


def source(directory, **options):
    args = dict(session="s" * 32, producer_gen=1, process_id=99, sites=SITES, qpc_freq=10_000_000, key=KEY)
    args.update(options)
    return tc.TraceSource(directory, **args)


class Policy(unittest.TestCase):
    def test_tolerant_allows_anything(self):
        self.assertIsNone(tc.check_probe_policy("tolerant", {"read_mode": "direct", "pause": True}))

    def test_fatal_and_freezes_refuse_what_could_fault_or_stop(self):
        for policy in ("fatal", "freezes"):
            self.assertIsNone(tc.check_probe_policy(policy, {}))
            self.assertIn("non-faulting", tc.check_probe_policy(policy, {"read_mode": "direct"}))
            self.assertIn("pausing", tc.check_probe_policy(policy, {"pause": True}))
            self.assertIn("single validated range", tc.check_probe_policy(policy, {"deref_chain": [0, 8]}))

    def test_an_unknown_policy_is_refused_not_assumed_tolerant(self):
        self.assertIn("not one of", tc.check_probe_policy("whatever", {}))


class Sampling(unittest.TestCase):
    """The declared sampling policy: validated, and every hit it skips is cited exactly once, never silently."""

    def test_the_default_policy_is_adaptive_and_bad_options_are_refused(self):
        from hydralysis.runtime_agents import normalize_sampling
        self.assertEqual(normalize_sampling(None)["mode"], "adaptive")
        self.assertEqual(normalize_sampling("exact")["mode"], "exact")
        self.assertEqual(normalize_sampling({"mode": "fixed", "stride": 16})["stride"], 16)
        for bad in ({"mode": "random"}, {"rate_budget": 0}, {"stride": 0}, {"exact": "all"}, {"nope": 1}, 5):
            with self.assertRaises(ValueError):
                normalize_sampling(bad)

    def test_skipped_hits_become_one_budget_gap_per_report_with_exact_counts(self):
        with workdir() as root:
            t = source(root)
            t.on_ready({"context": {"debugger_present": False}, "installed": [], "qpc_freq": 10_000_000,
                        "sampling": {"policy": "adaptive", "rate_budget_per_s": 100}})
            counters = {"attempted": 0, "dropped": 0, "read_failed": 0, "no_ring": 0, "rings": []}
            first = {"policy": "adaptive", "sites": [{"site": 1, "probe": "CreateFileW", "hits": 100, "kept": 10, "skipped": 90, "stride": 8, "rate_per_s": 5000}]}
            second = {"policy": "adaptive", "sites": [{"site": 1, "probe": "CreateFileW", "hits": 150, "kept": 20, "skipped": 130, "stride": 4, "rate_per_s": 900}]}
            t.on_counters({**counters, "sampling": first})
            t.on_counters({**counters, "sampling": first})        # nothing new: no second citation
            t.on_counters({**counters, "sampling": second, "final": True})
            health = t.finalize(detach={"quiescent": True})
            events = [json.loads(line.split(" ", 1)[1]) for line in t.path.read_text(encoding="utf-8").splitlines() if line.strip()]
            gaps = [e["payload"] for e in events if e["kind"] == "core.capture.gap" and e["payload"].get("sampled")]
            self.assertEqual([g["dropped"] for g in gaps], [90, 40])
            self.assertTrue(all(g["reason"] == "budget" and g["out_of_band"] for g in gaps))
            self.assertEqual(health["producer"]["sampling"]["sites"][0]["skipped"], 130)
            self.assertEqual(t.verify()["outcome"], "clean")


class Writer(unittest.TestCase):
    def test_batches_become_a_clean_chain_and_the_counters_reconcile(self):
        with workdir() as root:
            t = source(root)
            t.on_ready({"context": {"debugger_present": False}, "installed": [], "qpc_freq": 10_000_000})
            batch = tw.build_batch(1, 0, 100, (2, 0, 0, 0), [rec(0, 0, 10), rec(0, 1, 20, path="\\\\.\\NUL")])
            self.assertTrue(t.on_batch(batch)["ok"])
            t.on_counters({"attempted": 2, "dropped": 0, "read_failed": 0, "no_ring": 0, "batches_sent": 1, "final": True,
                           "rings": [{"ring": 0, "attempted": 2, "dropped": 0}]})
            health = t.finalize(detach={"quiescent": True})
            self.assertEqual(t.verify()["outcome"], "clean")
            self.assertEqual(health["transport"]["batches_missing"], 0)
            self.assertEqual(health["claims"], {"attached": True, "observing": True, "finalized": True, "fault_free": True})
            kinds = [e["kind"] for e in tc.read_events(t.path, t.segment_id)]
            self.assertEqual(kinds[0], "core.capture.source")
            self.assertEqual(kinds[-1], "core.capture.source")
            self.assertIn("driver.device_open", kinds)
            sidecar = json.loads(Path(str(t.path) + ".head").read_text())
            self.assertEqual((sidecar["records"], sidecar["head"], sidecar["finalized"]), (t.encoder.count, t.encoder.head, True))

    def test_the_three_hops_localize_a_loss(self):
        with workdir() as root:
            t = source(root)
            t.on_ready({"context": {}, "installed": [], "qpc_freq": 10_000_000})
            t.on_batch(tw.build_batch(1, 0, 100, (1, 0, 0, 0), [rec(0, 0, 10)]))
            t.on_batch(tw.build_batch(1, 2, 200, (6, 3, 0, 0), [rec(0, 4, 90)]))      # batch 1 never arrived; 3 attempts overflowed
            t.on_counters({"attempted": 7, "dropped": 3, "batches_sent": 3, "rings": [{"ring": 0, "attempted": 7, "dropped": 3}]})
            health = t.health()
            self.assertEqual(health["transport"]["batches_missing"], 1)            # transport: counted by the batch numbers
            self.assertEqual(health["transport"]["gaps_reported"], 1)
            self.assertEqual(health["producer"]["dropped"], 3)                     # producer: its own counter
            self.assertEqual(health["writer"]["write_failed"], 0)                  # writer: fine
            events = tc.read_events(t.path, t.segment_id)
            reasons = [e["payload"]["reason"] for e in events if e["kind"] == "core.capture.gap"]
            self.assertEqual(reasons, ["producer-lost", "ring-overflow"])         # the missing batch (transport); the 3 records the drop counter explains

    def test_tail_loss_after_the_last_batch_is_found_from_the_out_of_band_counters(self):
        with workdir() as root:
            t = source(root)
            t.on_ready({"context": {}, "installed": [], "qpc_freq": 10_000_000})
            t.on_batch(tw.build_batch(1, 0, 100, (1, 0, 0, 0), [rec(0, 0, 10)]))
            t.on_counters({"attempted": 9, "dropped": 8, "no_ring": 2, "batches_sent": 1, "final": True,
                           "rings": [{"ring": 0, "attempted": 9, "dropped": 8}]})
            t.finalize(detach={"quiescent": True})
            gaps = [e["payload"] for e in tc.read_events(t.path, t.segment_id) if e["kind"] == "core.capture.gap"]
            self.assertEqual([(g["reason"], g["dropped"], g["out_of_band"]) for g in gaps], [("ring-overflow", 8, True), ("budget", 2, True)])

    def test_a_batch_that_does_not_decode_is_counted_and_never_written(self):
        with workdir() as root:
            t = source(root)
            before = t.encoder.count
            self.assertFalse(t.on_batch(b"junk" * 40)["ok"])
            self.assertEqual((t.encoder.count, t.transport["decode_failed"]), (before, 1))
            self.assertTrue(t.on_batch(tw.build_batch(1, 0, 1, (1, 0, 0, 0), [rec(0, 0, 10)]))["ok"])   # the stream goes on

    def test_the_five_segment_outcomes_stay_distinct(self):
        with workdir() as root:
            t = source(root)
            self.assertEqual(t.verify()["outcome"], "missing")
            t.path.write_bytes(b"")
            self.assertEqual(t.verify()["outcome"], "empty")
            t.on_ready({"context": {}, "installed": [], "qpc_freq": 10_000_000})
            t.on_batch(tw.build_batch(1, 0, 1, (2, 0, 0, 0), [rec(0, 0, 10), rec(0, 1, 11)]))
            t.finalize(detach={"quiescent": True})
            good = t.path.read_bytes()
            self.assertEqual(t.verify()["outcome"], "clean")
            t.path.write_bytes(good[:-5])
            self.assertEqual(t.verify()["outcome"], "torn-tail")
            lines = good.split(b"\n")
            lines[2] = lines[2][:-3] + b"xyz"
            t.path.write_bytes(b"\n".join(lines))
            self.assertEqual(t.verify()["outcome"], "corrupt")
            valid = good.split(b"\n")
            t.path.write_bytes(b"\n".join(valid[:1] + valid[2:]))     # a valid line removed: numbering and chain break
            self.assertEqual(t.verify()["outcome"], "chain-break")

    def test_a_failed_write_keeps_the_lines_and_retries_them_in_order(self):
        with workdir() as root:
            t = source(root)
            t.on_ready({"context": {}, "installed": [], "qpc_freq": 10_000_000})
            real = os.write
            calls = {"n": 0}

            def flaky(fd, data):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise OSError(28, "No space left on device")
                return real(fd, data)
            with patch("hydralysis.trace_capture.os.write", flaky):
                t.on_batch(tw.build_batch(1, 0, 1, (1, 0, 0, 0), [rec(0, 0, 10)]))
                self.assertGreater(t.health()["writer"]["pending_bytes"], 0)
                self.assertEqual(t.writer["write_failed"], 1)
                t.on_batch(tw.build_batch(1, 1, 2, (2, 0, 0, 0), [rec(0, 1, 11)]))
            t.finalize(detach={"quiescent": True})
            self.assertEqual(t.verify()["outcome"], "clean")                       # nothing lost, nothing reordered
            self.assertFalse(t.health()["claims"]["fault_free"])                   # and the failure is reported

    def test_the_size_limit_stops_recording_with_a_gap_never_silently(self):
        with workdir() as root:
            t = source(root, max_bytes=2500)      # checked before each batch: a segment may pass it by one batch
            t.on_ready({"context": {}, "installed": [], "qpc_freq": 10_000_000})
            for i in range(8):
                t.on_batch(tw.build_batch(1, i, i, (i + 1, 0, 0, 0), [rec(0, i, 10 + i)]))
            self.assertTrue(t.full)
            self.assertGreater(t.writer["refused_after_full"], 0)
            events = tc.read_events(t.path, t.segment_id)
            self.assertEqual([e["payload"].get("reason") for e in events if e["kind"] == "core.capture.gap"], ["budget"])
            self.assertEqual(t.verify()["outcome"], "clean")

    def test_payload_mode_keeps_exactly_the_range_and_export_omits_it(self):
        with workdir() as root:
            t = source(root, payload_authorized=True)
            t.on_ready({"context": {}, "installed": [], "qpc_freq": 10_000_000})
            t.on_batch(tw.build_batch(1, 0, 1, (2, 0, 0, 0), [rec(0, 0, 10, path="\\\\.\\NUL", handle=33), rec(0, 1, 11, site=2, args=[33, 4, 0, 4, 0, 0, 0, 0])]))
            digest = hashlib.sha256(b"\xde\xad\xbe\xef").hexdigest()
            self.assertEqual((t.directory / "artifacts" / digest).read_bytes(), b"\xde\xad\xbe\xef")
            lines, omitted = tc.export_jsonl(t.path, t.segment_id)
            self.assertEqual(omitted, 1)
            self.assertNotIn(digest, "\n".join(lines))
            self.assertNotIn("deadbeef", "\n".join(lines))
            with_payload, _ = tc.export_jsonl(t.path, t.segment_id, include_payload_refs=True)
            self.assertIn(digest, "\n".join(with_payload))

    def test_payload_without_authorization_is_refused_in_the_event(self):
        with workdir() as root:
            t = source(root)
            t.on_ready({"context": {}, "installed": [], "qpc_freq": 10_000_000})
            t.on_batch(tw.build_batch(1, 0, 1, (1, 0, 0, 0), [rec(0, 0, 11, site=2, args=[33, 4, 0, 4, 0, 0, 0, 0])]))
            self.assertFalse((t.directory / "artifacts").exists())
            self.assertIn("payload-not-authorized", t.path.read_text())

    def test_an_artifact_that_cannot_be_made_durable_blocks_its_reference(self):
        with workdir() as root:
            t = source(root, payload_authorized=True)
            t.on_ready({"context": {}, "installed": [], "qpc_freq": 10_000_000})
            before = t.encoder.count
            with patch("hydralysis.trace_capture.durable.atomic_write", side_effect=OSError("disk")):
                result = t.on_batch(tw.build_batch(1, 0, 1, (1, 0, 0, 0), [rec(0, 0, 11, site=2, args=[33, 4, 0, 4, 0, 0, 0, 0])]))
            self.assertFalse(result["ok"])
            self.assertEqual(t.path.read_bytes().count(b"driver.ioctl"), 0)       # nothing refers to bytes that are not there
            self.assertGreaterEqual(t.encoder.count, before)

    def test_correlation_ids_are_keyed_by_scope(self):
        with workdir() as a, workdir() as b:
            t1, t2 = source(a, key=bytes(32)), source(b, key=KEY)
            for t in (t1, t2):
                t.on_ready({"context": {}, "installed": [], "qpc_freq": 10_000_000})
                t.on_batch(tw.build_batch(1, 0, 1, (1, 0, 0, 0), [rec(0, 0, 11, path="C:\\Secret\\token.txt")]))
            ids = [next(e["payload"]["resource_id"] for e in tc.read_events(t.path, t.segment_id) if e["kind"] == "core.resource.open") for t in (t1, t2)]
            self.assertNotEqual(ids[0], ids[1])                                    # not linkable across scopes
            self.assertNotIn(b"Secret", t1.path.read_bytes() + t2.path.read_bytes())


# ---- the real recorder -----------------------------------------------------------------------------------------------------
TARGET = r'''
import ctypes, sys, time
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.CreateFileW.restype = ctypes.c_void_p
k.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
k.DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
k.CloseHandle.argtypes = [ctypes.c_void_p]
k.Sleep.argtypes = [ctypes.c_uint]
mode, n = sys.argv[1], int(sys.argv[2])
print("ready", flush=True)
sys.stdin.readline()
buf = ctypes.create_string_buffer(8)
if mode == "blocked":
    k.Sleep(60000)
if mode == "secret":
    for i in range(n):
        k.CreateFileW("C:\\Users\\x\\password=hunter2secret\\missing%d.cfg" % i, 0x80000000, 3, None, 3, 0, None)
        k.CreateFileW("C:\\Users\\x\\Authorization: Bearer abc123def456ghi789jkl\\n.cfg", 0x80000000, 3, None, 3, 0, None)
    print("done", flush=True)
    sys.stdin.readline()
    sys.exit(0)
if mode == "threads":
    import threading
    def one():
        k.CreateFileW("\\\\.\\NUL", 0xC0000000, 3, None, 3, 0, None)
    for i in range(n):
        t = threading.Thread(target=one)
        t.start()
        t.join()
        time.sleep(0.05)
    print("done", flush=True)
    sys.stdin.readline()
    sys.exit(0)
for i in range(n):
    h = k.CreateFileW("\\\\.\\NUL", 0xC0000000, 3, None, 3, 0, None)
    k.DeviceIoControl(h, 0x00220004, b"\x01\x02\x03\x04", 4, buf, 8, None, None)
    k.CreateFileW("C:\\Windows\\System32\\drivers\\etc\\hosts", 0x80000000, 3, None, 3, 0, None)
    k.CloseHandle(h)
print("done", flush=True)
sys.stdin.readline()
'''


@unittest.skipUnless(LIVE, "needs Windows and Frida; the recorder is injected only into a process this test spawns")
class Recorder(unittest.TestCase):
    def setUp(self):
        self.dirs = workdir()
        self.root = self.dirs.__enter__()
        self.addCleanup(self.dirs.__exit__, None, None, None)
        self.script = Path(self.root) / "target.py"
        self.script.write_text(TARGET)
        self.procs = []
        self.addCleanup(self.kill_all)

    def kill_all(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
            p.wait()
            for stream in (p.stdin, p.stdout):
                try:
                    stream.close()
                except OSError:
                    pass

    def target(self, mode="loop", n=100):
        p = subprocess.Popen([sys.executable, str(self.script), mode, str(n)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.procs.append(p)
        self.assertEqual(p.stdout.readline().strip(), "ready")
        return p

    def attach(self, p):
        from hydralysis.runtime_worker import RuntimeAgent, _process_path
        directory = Path(self.root) / uuid.uuid4().hex
        directory.mkdir()
        agent = RuntimeAgent(directory, frida.get_local_device())
        exe = _process_path(p.pid)
        agent.startup({"action": "attach", "exe": exe, "sha256": hashlib.sha256(Path(exe).read_bytes()).hexdigest(), "pid": p.pid, "argv": []})
        self.addCleanup(lambda: agent.closed or self.safe_cleanup(agent))
        return agent

    @staticmethod
    def safe_cleanup(agent):
        try:
            agent.cleanup()
        except Exception:
            pass

    def run_loop(self, p, wait_for="done"):
        p.stdin.write("go\n")
        p.stdin.flush()
        self.assertEqual(p.stdout.readline().strip(), wait_for)

    def test_a_loop_is_recorded_exactly_and_the_counters_reconcile(self):
        p = self.target(n=150)
        agent = self.attach(p)
        started = agent.handle("trace_start", {"builtin": ["driver-boundary"], "fault_policy": "fatal"})
        self.assertEqual({x["name"] for x in started["probes"]}, {"CreateFileW", "DeviceIoControl"})
        self.assertTrue(all(r["limitation"] == "optional-hook-refused" for r in started["refusals"]))   # setupapi/cfgmgr not loaded
        context = started["fault_context"]
        self.assertFalse(context["debugger_present"])
        self.assertTrue(any("frida" in (v.get("module") or "") for v in context["veh"]))               # our handler is in the chain, recorded
        self.run_loop(p)
        stopped = agent.handle("trace_stop", {})
        self.assertTrue(stopped["stopped"])
        self.assertTrue(stopped["detach"]["quiescent"])
        health = stopped["health"]
        self.assertEqual(health["verify"]["outcome"], "clean")
        events = tc.read_events(agent.trace.path, agent.trace.segment_id)
        calls = [e for e in events if e["kind"] in ("core.resource.open",)]
        self.assertEqual(len(calls), 300)                                                               # 2 opens x 150
        self.assertEqual(len([e for e in events if e["kind"] == "driver.ioctl"]), 150)
        self.assertEqual(len([e for e in events if e["kind"] == "driver.device_open"]), 150)
        self.assertEqual(health["producer"]["attempted"], 450)
        self.assertEqual(health["producer"]["dropped"], 0)
        self.assertEqual(health["transport"]["batches_missing"], 0)
        self.assertTrue(health["claims"]["fault_free"])
        text = agent.trace.path.read_text()
        self.assertNotIn("hosts", text)                                                                 # no path text in the segment
        ioctl = next(e for e in events if e["kind"] == "driver.ioctl")["payload"]
        self.assertEqual((ioctl["code"], ioctl["device_type"], ioctl["function"], ioctl["in_size"], ioctl["out_size"]), (0x220004, 0x22, 1, 4, 8))
        self.assertIsNotNone(ioctl["resource_id"])                                                      # joined to the device open by handle
        self.assertTrue(all(e["thread_id"] and e["callstack"] for e in calls))                          # return address captured
        p.stdin.write("x\n")

    def test_after_the_stop_the_hooks_are_gone(self):
        p = self.target(n=40)
        agent = self.attach(p)
        agent.handle("trace_start", {"builtin": ["driver-boundary"]})
        stopped = agent.handle("trace_stop", {})
        self.assertTrue(stopped["stopped"])
        self.assertEqual(agent.scripts, {})                                                             # the recorder was unloaded
        self.run_loop(p)                                                                                # the target runs on, unhooked
        self.assertEqual(p.poll(), None)
        p.stdin.write("x\n")

    def test_a_ring_that_fills_counts_and_cites_every_drop(self):
        p = self.target(n=3000)
        agent = self.attach(p)
        # The smallest ring, a drain far slower than the target and almost no patience (bp_ms): the ring must overflow.
        agent.handle("trace_start", {"builtin": ["driver-boundary"], "ring_bytes": 1 << 16, "batch_ms": 4000, "counter_ms": 100, "bp_ms": 0.2})
        self.run_loop(p)
        stopped = agent.handle("trace_stop", {})
        health = stopped["health"]
        self.assertGreater(health["producer"]["dropped"], 0)
        events = tc.read_events(agent.trace.path, agent.trace.segment_id)
        gaps = [e["payload"] for e in events if e["kind"] == "core.capture.gap"]
        self.assertTrue(gaps)
        self.assertEqual(sum(g["dropped"] for g in gaps if g["reason"] == "ring-overflow"), health["producer"]["dropped"])
        got = len([e for e in events if e["kind"] == "driver.ioctl"]) + len([e for e in events if e["kind"] == "core.resource.open"])
        self.assertGreater(got, 0)
        self.assertEqual(health["producer"]["attempted"], 9000)                                         # nothing unaccounted: kept + dropped
        kept = len([e for e in events if e["kind"] in ("core.resource.open", "driver.ioctl") and e["kind"] != "core.resource.write"])
        self.assertEqual(health["encoder"]["records"] + health["producer"]["dropped"], 9000)
        self.assertGreater(kept, 0)
        self.assertEqual(health["verify"]["outcome"], "clean")
        p.stdin.write("x\n")

    def test_a_probe_a_fatal_host_cannot_take_is_refused_before_anything_is_loaded(self):
        p = self.target()
        agent = self.attach(p)
        with self.assertRaises(Exception) as caught:
            agent.handle("trace_start", {"probes": [{"name": "CreateFileW", "module": "KernelBase.dll", "export": "CreateFileW", "nargs": 7,
                                                     "required": True, "read_mode": "direct"}], "fault_policy": "freezes"})
        self.assertIn("non-faulting", str(caught.exception))
        self.assertEqual(agent.scripts, {})
        self.assertIsNone(agent.trace)

    def test_a_wrong_prologue_refuses_the_probe(self):
        p = self.target()
        agent = self.attach(p)
        with self.assertRaises(Exception) as caught:
            agent.handle("trace_start", {"probes": [{"name": "CreateFileW", "module": "KernelBase.dll", "export": "CreateFileW", "nargs": 7,
                                                     "required": True, "expect": "90 90 90 90 90 90 90 90"}]})
        self.assertIn("PROLOGUE MISMATCH", str(caught.exception))
        self.assertEqual(agent.scripts, {})

    def test_payload_needs_its_own_authorization_and_keeps_exactly_the_range(self):
        p = self.target(n=5)
        agent = self.attach(p)
        agent.handle("trace_start", {"builtin": ["driver-boundary"], "authorize_payload": {"scope": "fixture-ioctl", "sites": ["DeviceIoControl"], "max_bytes": 64}})
        self.run_loop(p)
        stopped = agent.handle("trace_stop", {})
        self.assertTrue(stopped["stopped"])
        digest = hashlib.sha256(b"\x01\x02\x03\x04").hexdigest()
        self.assertEqual((agent.trace.directory / "artifacts" / digest).read_bytes(), b"\x01\x02\x03\x04")
        lines, omitted = tc.export_jsonl(agent.trace.path, agent.trace.segment_id)
        self.assertEqual(omitted, 5)
        self.assertNotIn(digest, "\n".join(lines))
        p.stdin.write("x\n")

    def test_close_handle_pairs_with_the_open_by_the_handle_it_closed(self):
        p = self.target(n=40)
        agent = self.attach(p)
        agent.handle("trace_start", {"builtin": ["driver-boundary", "handle-lifetime"]})
        self.run_loop(p)
        stopped = agent.handle("trace_stop", {})
        events = tc.read_events(agent.trace.path, agent.trace.segment_id)
        opens = {e["payload"]["handle"]: e["payload"]["resource_id"] for e in events if e["kind"] == "core.resource.open"}
        closes = [e["payload"] for e in events if e["kind"] == "core.resource.close"]
        self.assertEqual(len(closes), 40)
        self.assertTrue(all(c["resource_id"] for c in closes))
        self.assertTrue(all(c["resource_id"] in opens.values() for c in closes))
        self.assertEqual(stopped["health"]["producer"]["dropped"], 0)
        # 40 handles of the hosts file were opened and never closed: opens without a close, not an error
        self.assertEqual(len([e for e in events if e["kind"] == "core.resource.open"]), 80)
        p.stdin.write("x\n")

    def test_the_call_stack_is_deeper_than_one_and_every_frame_is_inside_a_module(self):
        p = self.target(n=30)
        agent = self.attach(p)
        agent.handle("trace_start", {"probes": [{"name": "CreateFileW", "module": "KernelBase.dll", "export": "CreateFileW", "nargs": 7,
                                                 "kind": "open", "with_leave": True, "required": True, "stack": 8,
                                                 "buf": {"ptr_arg": 0, "wide": True, "max": 64}}]})
        self.run_loop(p)
        agent.handle("trace_stop", {})
        events = [e for e in tc.read_events(agent.trace.path, agent.trace.segment_id) if e["kind"] == "core.resource.open"]
        self.assertEqual(len(events), 60)
        depth = sorted(len(e["callstack"]) for e in events)
        self.assertGreaterEqual(depth[len(depth) // 2], 4)              # the median call has a real chain, not one return address
        self.assertLessEqual(depth[-1], 8)                              # and it is bounded by the declared depth
        modules = {m["base"]: m for m in agent.control.exports_sync.modules(200)["modules"]} if not agent.detached else {}
        for event in events[:5]:
            for address in event["callstack"]:
                self.assertTrue(any(int(m["base"], 16) <= address < int(m["base"], 16) + m["size"] for m in modules.values()), hex(address))
        p.stdin.write("x\n")

    def test_a_preview_is_redacted_and_the_secret_is_nowhere_on_disk(self):
        p = self.target(mode="secret", n=10)
        agent = self.attach(p)
        agent.handle("trace_start", {"builtin": ["driver-boundary"], "authorize_preview": {"scope": "fixture", "sites": ["CreateFileW"], "max_bytes": 128}})
        self.run_loop(p)
        stopped = agent.handle("trace_stop", {})
        self.assertEqual(stopped["health"]["producer"]["dropped"], 0)
        events = [e for e in tc.read_events(agent.trace.path, agent.trace.segment_id) if e["kind"] == "core.resource.open"]
        previews = [e["payload"]["preview"] for e in events]
        self.assertEqual(len(previews), 20)
        self.assertTrue(all(len(x) <= 128 for x in previews))
        self.assertTrue(any("password=***" in x for x in previews), previews[:3])
        self.assertTrue(any("***" in x and "Authorization" in x for x in previews), previews[:3])
        lines, _ = tc.export_jsonl(agent.trace.path, agent.trace.segment_id)
        secrets = (b"hunter2secret", "hunter2secret".encode("utf-16le"), b"abc123def456ghi789jkl", "abc123def456ghi789jkl".encode("utf-16le"))
        blobs = [("\n".join(lines)).encode()]
        for path in Path(agent.directory).rglob("*"):
            if path.is_file():
                blobs.append(path.read_bytes())
        for blob in blobs:
            for secret in secrets:
                self.assertNotIn(secret, blob)
        p.stdin.write("x\n")

    def test_a_preview_without_authorization_records_no_text_and_one_for_a_site_without_a_buffer_is_refused(self):
        p = self.target(mode="secret", n=3)
        agent = self.attach(p)
        started = agent.handle("trace_start", {"builtin": ["driver-boundary"], "authorize_preview": {"scope": "fixture", "sites": ["DeviceIoControl"], "max_bytes": 64}})
        self.assertIn("preview-not-possible", [r["limitation"] for r in started["refusals"]])
        self.run_loop(p)
        agent.handle("trace_stop", {})
        text = agent.trace.path.read_text()
        self.assertNotIn('"preview"', text.replace('"preview":null', ""))
        p.stdin.write("x\n")
        with self.assertRaises(ValueError):
            agent2 = self.attach(self.target(mode="secret", n=1))
            agent2.handle("trace_start", {"builtin": ["driver-boundary"], "authorize_preview": {"scope": "x", "sites": ["CreateFileW"], "max_bytes": 4096}})

    def test_a_ring_is_reused_after_its_thread_exits(self):
        p = self.target(mode="threads", n=40)
        agent = self.attach(p)
        agent.handle("trace_start", {"builtin": ["driver-boundary"], "rings": 3, "batch_ms": 5})
        self.run_loop(p)
        time.sleep(0.3)
        stopped = agent.handle("trace_stop", {})
        producer = stopped["health"]["producer"]
        self.assertGreaterEqual(producer["attempted"], 40)                                             # the 40 threads (and the interpreter's own opens)
        self.assertEqual((producer["dropped"], producer["no_ring"]), (0, 0))                          # 40 threads through 3 rings, none starved
        self.assertGreater(producer["ring_reuses"], 20)
        self.assertEqual(stopped["health"]["encoder"]["records"], producer["attempted"])
        p.stdin.write("x\n")

    def test_a_recorder_that_cannot_prove_quiescence_stays_in_pass_through_and_says_so(self):
        p = self.target(mode="blocked")
        agent = self.attach(p)
        agent.handle("trace_start", {"probes": [{"name": "Sleep", "module": "KernelBase.dll", "export": "Sleep", "nargs": 1,
                                                 "with_leave": True, "required": True}]})
        p.stdin.write("go\n")
        p.stdin.flush()
        time.sleep(0.6)                                                                                  # the target is now inside Sleep
        stopped = agent.handle("trace_stop", {"timeout_ms": 400})
        self.assertFalse(stopped["stopped"])
        self.assertFalse(stopped["detach"]["quiescent"])
        self.assertIn("pass-through", stopped["safe_state"])
        self.assertTrue(agent.scripts)                                                                   # not unloaded: not freed
        self.assertTrue(agent.trace_info["detach_failed"])
        with self.assertRaises(RuntimeError) as caught:
            agent.cleanup()                                                                              # and the session is not detached under it
        self.assertIn("not quiescent", str(caught.exception))
        self.assertFalse(agent.detached)
        self.assertIn(agent.trace.verify()["outcome"], ("clean",))
        p.kill()


if __name__ == "__main__":
    unittest.main()
