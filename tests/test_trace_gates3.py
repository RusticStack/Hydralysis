"""Acceptance gates M3 (concurrency, recovery, bundles, pairing), M4, S and I of the semantic trace: real fixtures, real engine.

Same conventions as test_trace_gates.py (engine-gated, real Frida capture of built MSVC fixtures, the `trace` tool)."""

from __future__ import annotations

import json
import subprocess
import sys
import time
import unittest
from pathlib import Path

from hydralysis import trace_pairing as pairing
import trace_gate_support as g
from test_trace_gates import FRAMELOOP, Gate, LIVE, hooks

HERE = Path(__file__).resolve().parent


def live_capture(gate, exe, args, specs, session, *, pump_to=None, **trace):
    """Start EXE paused, return (live, pump) with the pump tailing its segment into SESSION; the caller resumes and stops."""
    import trace_live
    from hydralysis import trace_pump
    live = trace_live.Live(gate.root / "runs", gate.fx / exe, args, linger_ms=300)
    live.start(specs, **trace)
    pump = trace_pump.Pump(gate.engine.client(), session, gate.engine.caps[session], live.segment, live.segment_id,
                           skip_ingested=False).start()
    return live, pump


@unittest.skipUnless(LIVE, "needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
class M3Concurrency(Gate):
    def spawn_agent(self, session, tag, stop_file):
        spec = {"settings": self.engine.settings, "session": session, "stop_file": str(stop_file),
                "out": str(self.root / ("agent-%s.json" % tag)), "full_every": 2}
        path = self.root / ("agent-%s-spec.json" % tag)
        path.write_text(json.dumps(spec), encoding="utf-8")
        proc = subprocess.Popen([sys.executable, "-I", str(HERE / "trace_agent_proc.py"), str(path)], stderr=subprocess.PIPE)
        return proc, Path(spec["out"])

    def test_two_agents_query_the_same_trace_during_a_live_capture_without_waiting_or_partial_rows(self):
        profile = g.GateProfile(self.fx, "gate-m3/1", ["frameloop.exe"], FRAMELOOP)
        session = g.unique("m3_live")
        self.engine.open(session)
        stop = self.root / "agents.stop"
        stop.unlink(missing_ok=True)
        agents = [self.spawn_agent(session, tag, stop) for tag in ("a", "b")]
        time.sleep(1.5)     # both agents are connected and reading
        live, pump = live_capture(self, "frameloop.exe", ["--frames=4000", "--sleep-ms=1"], profile.specs(self.root), session)
        try:
            live.resume()
            self.assertTrue(live.wait_exit(90))
            time.sleep(0.3)
            live.stop()
            report = pump.stop()
        finally:
            live.close()
        time.sleep(0.5)
        stop.write_text("stop")
        results = []
        for proc, out in agents:
            proc.wait(120)
            self.assertEqual(proc.returncode, 0, proc.stderr.read().decode()[-2000:])
            results.append(json.loads(out.read_text(encoding="utf-8")))
        self.assertIsNone(report["error"], report)
        self.assertEqual(report["rejected"], 0)
        total = self.engine.client().info(session)["events"]
        self.assertEqual(total, report["appended"])
        self.assertGreater(total, 8000)
        for r in results:
            self.assertEqual(r["problems"], [], r["problems"][:3])
            self.assertGreaterEqual(r["full_reads"], 3)
            # the reads happened while the trace grew: several distinct committed revisions, each whole
            self.assertGreaterEqual(len(set(r["revisions"])), 3, r["revisions"])
            self.assertEqual(r["counts"], sorted(r["counts"]))
            self.assertEqual(r["final_rows"], total)
            # measure requests waiting: nothing queued, nobody waited on a lock, over the whole run
            self.assertEqual(r["waits_after"]["ever_queued"] - r["waits_before"]["ever_queued"], 0, r)
            self.assertEqual(r["peak_queued_now"], 0, r)
            self.assertEqual(r["waits_after"]["contended"] - r["waits_before"]["contended"], 0, r)
            self.assertEqual(r["waits_after"]["foreign_blocked"] - r["waits_before"]["foreign_blocked"], 0, r)
        print("M3 live: %d events, agents read %s / %s full snapshots, slowest %.0f ms" % (
            total, results[0]["full_reads"], results[1]["full_reads"], max(r["slowest_ms"] for r in results)))
        self.assertEqual(results[0]["final_revision"], results[1]["final_revision"])
        shared = set(results[0]["digests"]) & set(results[1]["digests"])
        for rev in shared:
            self.assertEqual(results[0]["digests"][rev], results[1]["digests"][rev], "same revision, same bytes for both agents")


    def start_pump_process(self, session, cap, live, stop_file, resume=True):
        spec = {"settings": self.engine.settings, "session": session, "cap": cap, "segment": str(live.segment),
                "segment_id": live.segment_id, "stop_file": str(stop_file), "resume": resume}
        proc = subprocess.Popen([sys.executable, "-m", "hydralysis.trace_pump"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={**__import__("os").environ, "PYTHONPATH": str(HERE.parent / "src")})
        proc.stdin.write(json.dumps(spec).encode())
        proc.stdin.close()
        started = json.loads(proc.stdout.readline())
        self.assertEqual(started["pump"], "started")
        self.pump_started = started
        return proc

    def test_writer_kill_and_lease_takeover_recover_from_the_raw_segment_and_evidence_stays_readable(self):
        import trace_live  # noqa: F401
        profile = g.GateProfile(self.fx, "gate-m3k/1", ["frameloop.exe"], FRAMELOOP)
        session = g.unique("m3_kill")
        import trace_live
        live = trace_live.Live(self.root / "runs", self.fx / "frameloop.exe", ["--frames=3000", "--sleep-ms=2"], linger_ms=300)
        stop = self.root / "pump.stop"
        stop.unlink(missing_ok=True)
        try:
            live.start(profile.specs(self.root))
            writer = self.start_pump_process(session, None, live, stop)
            old_cap = self.pump_started["cap"]
            self.assertEqual(self.pump_started["lease"]["producerGen"], 1)
            live.resume()
            client = self.engine.client()
            deadline = time.time() + 60
            while client.info(session)["events"] < 1500 and time.time() < deadline:
                time.sleep(0.05)
            before = client.info(session)
            self.assertGreaterEqual(before["events"], 1500)
            writer.kill()                                   # the writer dies; the capture keeps writing its raw segment
            writer.wait(30)
            self.assertTrue(live.wait_exit(90))
            time.sleep(0.3)
            live.stop()
            # evidence stays readable while nobody holds the writer
            frozen = client.info(session)
            rows = self.engine.rows(session)
            self.assertEqual(len(rows), frozen["events"])
            self.assertLess(frozen["events"], len(live_events(live)), "the dead writer left events only in the raw segment")
            self.assertEqual(client.query(session, limit=5)["rows"][0]["seq"], 1)
            # the old writer is gone: its lease is an orphan, and a stale capability is refused
            from hydralysis.trace import TraceError
            with self.assertRaises(TraceError) as refused:
                client.append(session, [], cap="cap_" + "0" * 32)
            self.assertRegex(str(refused.exception.code) + str(refused.exception), "owner|cap|lease", refused.exception)
            took = client.begin(session=session, mode="write", takeover=True)
            self.assertEqual(took["lease"]["producerGen"], 2, took["lease"])
            self.assertTrue(took["lease"]["tookOver"])
            new_cap = took["lease"]["cap"]
            self.assertNotEqual(new_cap, old_cap)
            with self.assertRaises(TraceError):
                client.append(session, [], cap=old_cap)     # the old capability is worthless now
            # the new writer replays the raw segment from where the engine stopped: nothing twice, nothing lost
            from hydralysis import trace_pump
            pump = trace_pump.Pump(client, session, new_cap, live.segment, live.segment_id)
            self.assertEqual(pump.skipped, frozen["events"])
            pump.drain()
            self.assertEqual(pump.rejected, 0)
            final = client.info(session)
            self.assertEqual(final["events"], len(live_events(live)))
            self.assertEqual(final["rejects"], 0)
            again = trace_pump.Pump(client, session, new_cap, live.segment, live.segment_id)
            again.drain()
            self.assertEqual(client.info(session)["events"], final["events"], "a second recovery adds nothing")
            # the rows the first writer committed are byte-identical after recovery
            after = self.engine.rows(session)
            self.assertEqual([json.dumps(r, sort_keys=True) for r in after[:len(rows)]],
                             [json.dumps(r, sort_keys=True) for r in rows])
            self.assertEqual(pump.tail.damage, None)
        finally:
            live.close()

    def test_evidence_bundles_are_pinned_to_revisions_and_list_what_cannot_be_reproduced(self):
        import hashlib
        from hydralysis import evidence, evidence_bundle, trace
        cap = self.captured("frames30", "frameloop.exe", FRAMELOOP, ["--frames=30"])
        session = g.unique("m3_bundle")
        self.engine.load(session, cap.lines())
        client = self.engine.client()
        info = client.info(session)
        revision, upto = info["revision"], info["events"]
        frames = [r for r in self.engine.rows(session, kinds=["app.frame"])][:3]
        ids = [r["event_id"] for r in frames]

        def digest(limit):
            rows = [r for r in paged(self.engine, session, limit)]
            return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
        pinned_digest = digest(upto)
        folder = Path(self.root) / "bundle-work"
        folder.mkdir(exist_ok=True)
        db = folder / "e.db"
        evidence.add_claim(db, game="fx", build="b1", kind="behavior", name="frames-seen", note="three frame ends",
                           source="trace %s" % session, from_trace=trace.citation(session, ids, revision))
        pins = folder / "pins"
        pins.mkdir(exist_ok=True)
        # an event's payload bytes were not authorized for export: the pin lists them as what cannot be reproduced
        pin = trace.pin_for(session, revision, ids, unauthorized=[{"id": "payload:" + ids[0], "range": [0, 64]}],
                            coverage={"revision": revision, "gaps": info["gaps"], "up_to": upto, "rows_sha256": pinned_digest})
        (pins / (session + ".json")).write_text(json.dumps(pin), "utf-8")
        result = evidence_bundle.export_bundle(db, folder / "b1", game="fx", traces_dir=pins)
        self.assertEqual(result["unreproducible_traces"], [session])
        member = json.loads((folder / "b1" / "traces" / (session + ".json")).read_text("utf-8"))
        self.assertEqual(member["revision"], revision)
        self.assertEqual(member["cannot_reproduce"][0]["reason"], "payload-not-authorized")
        self.assertTrue(evidence_bundle.verify_bundle(folder / "b1")["ok"])
        # the trace grows after the bundle was made; the pinned revision still reads exactly what it read
        for n in range(5):
            self.engine.tool("mark", session, label="after-%d" % n, cap=self.engine.caps[session])
        grown = client.info(session)
        self.assertGreater(grown["revision"], revision)
        self.assertGreater(grown["events"], upto)
        self.assertEqual(digest(upto), pinned_digest, "the pinned read is the same bytes after the trace grew")
        for event_id in ids:
            self.assertIn(event_id, [r["event_id"] for r in paged(self.engine, session, upto)])
        again = evidence_bundle.export_bundle(db, folder / "b2", game="fx", traces_dir=pins)
        self.assertEqual(again["bundle_id"], result["bundle_id"], "a pin makes the bundle independent of later revisions")
        # a pin with every range authorized is reproducible; a cited session with no pin says it cannot be reproduced
        good = trace.pin_for(session, revision, ids, coverage={"revision": revision, "gaps": [], "up_to": upto})
        (pins / (session + ".json")).write_text(json.dumps(good), "utf-8")
        self.assertEqual(evidence_bundle.export_bundle(db, folder / "b3", game="fx", traces_dir=pins)["unreproducible_traces"], [])
        stub = evidence_bundle.export_bundle(db, folder / "b4", game="fx")
        self.assertEqual(stub["unreproducible_traces"], [session])

    def test_only_the_owner_arms_probes_changes_scope_and_stops(self):
        import trace_live
        from hydralysis.trace import TraceError
        profile = g.GateProfile(self.fx, "gate-m3o/1", ["frameloop.exe"], FRAMELOOP)
        session = g.unique("m3_owner")
        self.engine.open(session)
        owner = self.engine.caps[session]
        client = self.engine.client()
        # the engine: a live holder is never taken over, and a stranger's capability writes nothing
        with self.assertRaises(TraceError):
            client.begin(session=session, mode="write", takeover=True)
        for call in (lambda: client.close(session, cap="cap_" + "1" * 32), lambda: client.mark(session, "x", cap="cap_" + "1" * 32),
                     lambda: client.append(session, [], cap="cap_" + "1" * 32), lambda: client.close(session)):
            with self.assertRaises(TraceError) as refused:
                call()
            self.assertRegex(str(refused.exception.code) + str(refused.exception), "owner|cap", refused.exception)
        self.assertTrue(client.info(session)["writer_open"], "still open after every refused stop")
        # the capture: probes, scope and stop need the owner's capability
        live = trace_live.Live(self.root / "runs", self.fx / "frameloop.exe", ["--frames=2000", "--sleep-ms=2"], linger_ms=200)
        try:
            specs = profile.specs(self.root)
            live.start(specs, owner=owner)
            with self.assertRaises(PermissionError):
                live.agent.handle("capture", {"op": "start", "name": "second", "trace": {"session": session, "hooks": [], "probes": []}})
            with self.assertRaises(PermissionError):
                live.agent.handle("capture", {"op": "scope", "scope": {"add": ["child.exe"]}})
            with self.assertRaises(PermissionError):
                live.agent.handle("capture", {"op": "scope", "scope": {"add": ["child.exe"]}, "owner": "cap_" + "2" * 32})
            with self.assertRaises(PermissionError):
                live.agent.handle("capture", {"op": "stop"})
            self.assertFalse(live.agent.trace.finalized, "the refused stop left the capture running")
            widened = live.agent.handle("capture", {"op": "scope", "scope": {"add": ["child.exe"]}, "owner": owner})
            self.assertEqual(widened["scope"]["added"], ["child.exe"])
            live.resume()
            self.assertTrue(live.wait_exit(90))
            time.sleep(0.3)
            stopped = live.agent.handle("capture", {"op": "stop", "owner": owner})
            self.assertTrue(stopped["trace"]["health"])
        finally:
            live.close()
        # the trace tool: widening the scope of a session needs the owner token
        refused = self.engine.tool("start", g.unique("m3_scope"), scope={"add": ["x.exe"]})
        self.assertEqual(refused["error"], "scope_expansion_needs_owner")


REPLICA_A = hooks("replica_a.exe", [
    dict(id="truth", event="app.truth", symbol="fx_truth_publish", nargs=3, capture=["obj:u32@0", "seq:u32@1", "value:u32@2"]),
    dict(id="create", event="app.create", symbol="fx_truth_create", nargs=2, capture=["obj:u32@0", "seq:u32@1"]),
    dict(id="sync", event="app.sync", symbol="fx_send_sync", nargs=1, capture=["n:u32@0"]),
])
REPLICA_B = hooks("replica_b.exe", [
    dict(id="mirror", event="app.mirror", symbol="fx_mirror_apply", nargs=3, capture=["obj:u32@0", "seq:u32@1", "value:u32@2"]),
    dict(id="extrapolate", event="app.extrapolated", symbol="fx_mirror_extrapolate", nargs=3,
         capture=["obj:u32@0", "seq:u32@1", "value:u32@2"]),
    dict(id="sync", event="app.sync_recv", symbol="fx_receive_sync", nargs=2, capture=["n:u32@0"]),
])
CLOCK_OFFSET_NS = 250_000_000     # the replica's clock reads 250 ms ahead (the fixture's own log offset)


@unittest.skipUnless(LIVE, "needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
class M3Pairing(Gate):
    """Section 15.5 live: owner and replica captured at the same time, paired through the trace tool."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import trace_live
        from hydralysis import trace_capture as tc
        a = g.GateProfile(cls.fx, "gate-rep-a/1", ["replica_a.exe"], REPLICA_A)
        b = g.GateProfile(cls.fx, "gate-rep-b/1", ["replica_b.exe"], REPLICA_B)
        tag = g.unique("pair")
        work = cls.root / "pair-work"
        work.mkdir()
        owner = trace_live.Live(cls.root / "runs", cls.fx / "replica_a.exe", [tag, str(work / "owner.jsonl")], linger_ms=300)
        replica = trace_live.Live(cls.root / "runs", cls.fx / "replica_b.exe", [tag, str(work / "replica.jsonl"), "250"], linger_ms=300)
        try:
            owner.start(a.specs(cls.root))
            replica.start(b.specs(cls.root))
            owner.resume()
            time.sleep(0.4)
            replica.resume()
            assert owner.wait_exit(90) and replica.wait_exit(90)
            time.sleep(0.4)
            owner.stop()
            replica.stop()
            cls.owner_events = [json.loads(x) for x in tc.export_jsonl(owner.segment, owner.segment_id, for_import=True)[0]]
            cls.replica_events = [json.loads(x) for x in tc.export_jsonl(replica.segment, replica.segment_id, for_import=True)[0]]
        finally:
            owner.close()
            replica.close()
        for e in cls.replica_events:       # a different machine's clock: the replica reads 250 ms ahead
            e["t_mono_ns"] += CLOCK_OFFSET_NS

    def load(self):
        owner, replica = g.unique("pair_owner"), g.unique("pair_replica")
        self.engine.load(owner, self.owner_events)
        self.engine.load(replica, self.replica_events)
        return owner, replica

    def test_the_delay_is_recovered_within_the_stated_uncertainty_the_outage_is_unknown_and_the_owner_only_object_is_flagged(self):
        owner, replica = self.load()
        reply = self.engine.tool("diff", owner, mode="pair", against=replica)
        self.assertNotIn("error", reply, reply)
        cal = reply["calibration"]
        self.assertTrue(cal["ok"])
        self.assertEqual(cal["markers"], 3)
        self.assertFalse(cal["drift_estimated"], "three markers 10 ms apart cannot say anything about drift")
        self.assertLessEqual(abs(cal["offset_ns"] + CLOCK_OFFSET_NS), cal["uncertainty_ns"], cal)    # the stated uncertainty bounds the error
        # the contract is not an absolute figure (scheduler jitter under load widens the marker spread, honestly): the stated
        # bound is the measured spread plus the declared transport allowance, and it must still resolve the 250 ms skew
        allowance = cal["uncertainty_ns"] - cal["spread_ns"]
        self.assertEqual(allowance, pairing.DEFAULT_SPEC["latency_allowance_ns"], cal)
        self.assertLess(cal["uncertainty_ns"], CLOCK_OFFSET_NS, cal)
        one = reply["objects"]["1"]
        self.assertEqual(one["status"], "paired")
        delay, uncertainty = one["delay_estimate_ns"], one["delay_uncertainty_ns"]
        self.assertLessEqual(abs(delay - 100_000_000), uncertainty, (delay, uncertainty))
        self.assertGreaterEqual(one["lag_ns"]["p50"], delay, "the median lag carries the host's scheduling slop; the floor is the delay")
        self.assertEqual(uncertainty, cal["uncertainty_ns"], "one calibration, one stated bound")
        # every owner value gets one of three answers; the 2 s outage is unknown, never agreement
        self.assertEqual(one["answers"], {"reflected": 100, "not_reflected": 0, "unknown": 100})
        self.assertEqual(len(one["outages"]), 1)
        outage = one["outages"][0]
        self.assertEqual(outage["answer"], "unknown")
        self.assertGreater(outage["silent_ns"], 1_900_000_000)
        self.assertLess(outage["silent_ns"], 2_400_000_000)
        self.assertEqual(one["unknown_total"], 100)
        # the object that exists only on the owner is flagged, and the replica's extrapolated ticks are reported
        self.assertEqual(reply["objects"]["2"]["status"], "owner_only")
        self.assertEqual(reply["owner_only"], ["2"])
        self.assertEqual(reply["replica_only"], [])
        self.assertGreater(reply["extrapolated"]["count"], 0)
        # value error over time is reported and the report cites events
        self.assertIn("value_error", one)
        self.assertTrue(reply["citations"])
        again = self.engine.tool("diff", owner, mode="pair", against=replica)
        self.assertEqual(json.dumps(reply, sort_keys=True), json.dumps(again, sort_keys=True))

    def test_without_shared_markers_nothing_is_compared(self):
        owner, replica = self.load()
        reply = self.engine.tool("diff", owner, mode="pair", against=replica, pair={"replica_sync": "app.never"})
        self.assertFalse(reply["usable"])
        self.assertFalse(reply["calibration"]["ok"])
        self.assertEqual(reply["objects"], {})


def paged(engine, session, up_to, **options):
    """Every row with seq <= UP_TO (a pinned read)."""
    out, after = [], None
    while True:
        reply = engine.client().query(session, limit=1000, after=after, up_to=up_to, **options)
        out.extend(reply.get("rows") or [])
        after = reply.get("next")
        if not after:
            return out


def live_events(live):
    from hydralysis import trace_capture as tc
    return tc.read_events(live.segment, live.segment_id)


if __name__ == "__main__":
    unittest.main()
