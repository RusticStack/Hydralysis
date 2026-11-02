"""Acceptance gates M4 (checks, field-writer, discovery), S (hash names, script natives, build invalidation) and I (persist
footprint, hang dumps) of the semantic trace: real fixtures, real engine. Same conventions as test_trace_gates.py."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import test_trace_gates as t2
import trace_gate_support as g
from test_trace_gates import Gate, LIVE, hooks

FRAME_HOOKS = hooks("frameloop.exe", [
    dict(id="ours", event="app.ours", symbol="fx_ours_write", nargs=1, capture=["frame:u64@0"]),
    dict(id="consume", event="app.consume", symbol="fx_consume", nargs=1, capture=["frame:u64@0"]),
    dict(id="frame-end", event="app.frame_end", symbol="fx_frame_end", nargs=1, capture=["frame:u64@0"]),
])
SURVIVAL_HOOKS = hooks("frameloop.exe", [
    dict(id="frame-begin", event="core.marker", symbol="fx_frame_begin", nargs=1, capture=["frame:u64@0"]),
    dict(id="frame-end", event="app.frame", symbol="fx_frame_end", nargs=1, capture=["frame:u64@0"]),
    dict(id="stage-begin", event="app.stage", symbol="fx_phase_begin", nargs=1, capture=["stage:u32@0"]),
    dict(id="pool-thread", event="app.pool", symbol="fx_pool_thread", nargs=1),
    dict(id="ours-write", event="core.state.write", symbol="fx_ours_write", nargs=1, capture=["frame:u64@0", "value:u32@0"],
         const={"object": 1, "key": "entity.value", "ours": True}),
    dict(id="host-overwrite", event="core.state.write", symbol="fx_host_overwrite", nargs=1, capture=["frame:u64@0"],
         const={"object": 1, "key": "entity.value"}),
    dict(id="consume", event="core.state.read", symbol="fx_consume", nargs=1, capture=["frame:u64@0"],
         const={"object": 1, "key": "entity.value"}),
])


@unittest.skipUnless(LIVE, "needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
class M4Checks(Gate):
    """Section 14.8: findings turned into regression checks, three-valued, with saved assertion revisions."""

    ORDER = {"type": "ordered_transitions", "name": "ours-before-consume", "kinds": ["app.ours", "app.consume"], "key_field": "frame"}

    def run_check(self, key, args, assertions=None, **trace):
        profile = g.GateProfile(self.fx, "gate-chk-%s/1" % key, ["frameloop.exe"], FRAME_HOOKS)
        cap = g.capture(self.root / "runs", "frameloop.exe", args, profile.specs(self.root), **trace)
        session = g.unique("m4_" + key)
        self.engine.load(session, cap.lines())
        reply = self.engine.tool("check", session, assertions=assertions or [self.ORDER], cap=self.engine.caps[session])
        return session, cap, reply["results"]

    def test_a_correct_run_passes_a_changed_transition_gives_a_cited_counterexample(self):
        _session, _cap, results = self.run_check("pass", ["--frames=40"])
        self.assertEqual(results[0]["verdict"], "pass", results[0])
        self.assertEqual(results[0]["checked"], 40)
        self.assertTrue(results[0]["assertion"].startswith("ours-before-consume/"))
        session, _c, failed = self.run_check("fail", ["--frames=40", "--ours-stage=render"])
        self.assertEqual(failed[0]["verdict"], "fail", failed[0])
        cited = failed[0]["counterexamples"]
        self.assertTrue(cited and all(c.startswith("ev_") for c in cited), cited)
        rows = self.engine.rows(session)
        self.assertTrue(set(cited) <= {r["event_id"] for r in rows}, "every citation resolves to an event of the failing run")

    def test_an_observation_gap_gives_unknown_while_the_valid_portions_stay_usable(self):
        lossy = dict(ring_bytes=1 << 16, batch_ms=300, counter_ms=100, bp_ms=0.2, window=1)
        session, cap, results = self.run_check("gap", ["--frames=20000"], **lossy)
        self.assertGreater(cap.health["producer"]["dropped"], 0)
        verdict = results[0]
        self.assertEqual(verdict["verdict"], "unknown", verdict)
        self.assertEqual(verdict["counterexamples"], [], "a gap is never reported as a violation")
        self.assertGreater(verdict["checked"], 0, "the portions without a gap were still evaluated")
        self.assertTrue(verdict.get("reason") or verdict.get("coverage"), verdict)
        info = self.engine.client().info(session)
        self.assertTrue(info["gaps"])
        rows = self.engine.rows(session, kinds=["app.consume"])
        self.assertGreater(len(rows), 100, "the events around the gap are still served")
        _s, _c, failed = self.run_check("gapfail", ["--frames=20000", "--ours-stage=render"], **lossy)
        if failed[0]["verdict"] == "fail":
            self.assertTrue(failed[0]["counterexamples"])
        else:
            self.assertEqual((failed[0]["verdict"], failed[0]["counterexamples"]), ("unknown", []))

    def test_saved_assertions_keep_every_revision_and_their_verdicts(self):
        profile = g.GateProfile(self.fx, "gate-chk-rev/1", ["frameloop.exe"], FRAME_HOOKS)
        cap = g.capture(self.root / "runs", "frameloop.exe", ["--frames=30", "--ours-stage=render"], profile.specs(self.root))
        session = g.unique("m4_rev")
        self.engine.load(session, cap.lines())
        token = self.engine.caps[session]
        first = {**self.ORDER, "rev": 1}
        second = {"type": "cardinality", "name": "ours-before-consume", "rev": 2, "kind": "app.ours", "min": 30, "max": 30}
        r1 = self.engine.tool("check", session, assertions=[first], cap=token)
        r2 = self.engine.tool("check", session, assertions=[second], cap=token)
        self.assertTrue(r1["persisted"] and r2["persisted"])
        self.assertEqual(r1["results"][0]["assertion"], "ours-before-consume/1")
        self.assertEqual(r2["results"][0]["assertion"], "ours-before-consume/2")
        self.assertEqual((r1["results"][0]["verdict"], r2["results"][0]["verdict"]), ("fail", "pass"))
        exported = self.engine.tool("export", session, name="checks", overwrite=True)
        self.assertNotIn("error", exported, exported)
        found = list(Path(self.engine.settings["root"]).rglob("checks.json"))
        self.assertTrue(found, "the export carries the saved assertions")
        document = json.loads(found[0].read_text(encoding="utf-8"))
        self.assertEqual([(a["name"], a["rev"]) for a in document["assertions"]], [("ours-before-consume", 1), ("ours-before-consume", 2)])
        self.assertEqual([(r["assertion"], r["verdict"]) for r in document["results"]],
                         [("ours-before-consume/1", "fail"), ("ours-before-consume/2", "pass")])


@unittest.skipUnless(LIVE, "needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
class M4Survival(Gate):
    """Section 15.3 over LIVE trace data on the frame loop, through the trace tool."""

    def report(self, *args):
        from hydralysis import trace_keys
        profile = g.GateProfile(self.fx, "gate-surv/1", ["frameloop.exe"], SURVIVAL_HOOKS, extra=t2.ROLES_PHASES)
        cap = g.capture(self.root / "runs", "frameloop.exe", list(args), profile.specs(self.root))
        events, _report = trace_keys.annotate(cap.lines(), profile.load(self.root))
        session = g.unique("m4_surv")
        self.engine.load(session, events)
        reply = self.engine.tool("query", session, report="survival", kinds=["core.state.write", "core.state.read"], limit=200,
                                 params={"field": "entity.value", "consumer": "consume", "phases": ["input", "update", "render"]})
        self.assertNotIn("error", reply, reply)
        return reply

    def test_a_later_stage_overwrites_on_most_frames_and_the_report_names_the_site_and_the_ratio(self):
        reply = self.report("--frames=60")
        result = reply["result"]
        self.assertEqual(result["frames"], 60)
        self.assertEqual(result["verdicts"], {"survived": 6, "overwritten": 54, "consumer read before write": 0, "unknown": 0})
        self.assertEqual(result["overwriters"], [{"site": "host-overwrite", "frames": 54}])
        self.assertEqual(result["summary"], "54 of 60 frames overwritten by one site")
        self.assertEqual(result["ratios_ppm"]["overwritten"], 900000)
        self.assertEqual(result["representatives"]["survived"], [9, 19, 29])
        self.assertEqual([f["frame"] for f in result["per_frame"] if f["verdict"] == "survived"], [9, 19, 29, 39, 49, 59])
        self.assertEqual(result["claim"], "all_frames_decided")
        frame0 = result["per_frame"][0]
        self.assertEqual([w["site"] for w in frame0["writes"]], ["ours-write", "host-overwrite"])
        self.assertEqual(frame0["overwritten_by"], "host-overwrite")
        self.assertTrue(frame0["produced_by"].startswith("ev_"))
        self.assertTrue(reply["citations"])

    def test_removing_the_overwrite_turns_every_frame_to_survived(self):
        result = self.report("--frames=60", "--no-overwrite")["result"]
        self.assertEqual(result["verdicts"], {"survived": 60, "overwritten": 0, "consumer read before write": 0, "unknown": 0})
        self.assertIsNone(result["summary"])
        self.assertEqual(result["overwriters"], [])


if __name__ == "__main__":
    unittest.main()
