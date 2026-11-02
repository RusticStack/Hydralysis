"""Acceptance gates M2 / M3 / M4 / S / I of the semantic trace (12.3-hydra.6): real fixtures, the real engine.

Every test captures a built MSVC fixture with the real Frida recorder (or runs the real static builders on its image),
loads the events into a real Hydra daemon through the same entry point as the MCP tool (`api.call("trace", ...)`), and
asserts the fixture's known answer (tests/fixtures/expected/*.json). Runs only with HYDRALYSIS_INTEGRATION_ENGINE/CLIENT
(an install that advertises `trace`), HYDRA_TRACE_EXE, Frida and MSVC; HYDRA_TRACE_FX may name a persistent fixture build.
"""

from __future__ import annotations

import json
import shutil
import unittest
from collections import Counter
from pathlib import Path

import trace_gate_support as g
from support import workdir

LIVE = g.HAVE_ENGINE and g.HAVE_LIVE


def hooks(module: str, rows: list[dict]) -> list[dict]:
    return [{"module": module, "stack": 4, **row} for row in rows]


INTERLEAVE = hooks("interleave.exe", [
    dict(id="submit", event="app.request", symbol="fx_submit", nargs=2, capture=["pool:u32@0", "corr:u32@1", "handoff:u32@1"]),
    dict(id="dropped", event="app.request", symbol="fx_submit_dropped", nargs=2, capture=["pool:u32@0", "corr:u32@1"]),
    dict(id="handle", event="app.handle", symbol="fx_handle_request", nargs=3,
         capture=["pool:u32@0", "corr:u32@1", "handoff:u32@1"], const={"stage": "handle"}),
    dict(id="store", event="app.result", symbol="fx_store_result", nargs=2, capture=["corr:u32@0", "value:u32@1"],
         const={"stage": "store"}),
    dict(id="complete", event="app.complete", symbol="fx_complete", nargs=1, capture=["corr:u32@0"]),
    dict(id="alloc", event="core.object.create", module="KERNELBASE.dll", symbol="VirtualAlloc", nargs=4,
         capture=["object:u64@ret", "size:u64@1", "protect:u32@3"]),
    dict(id="free", event="core.object.destroy", module="KERNELBASE.dll", symbol="VirtualFree", nargs=3,
         capture=["object:u64@0", "freetype:u32@2"]),
])


TRACE_APP = hooks("trace_app.exe", [
    dict(id="file-write", event="core.resource.write", symbol="fx_write_file", nargs=3, capture=["key:key@0", "size:u32@2"],
         buf={"arg": 0, "max": 128, "cstr": True}),
    dict(id="file-read", event="core.resource.read", symbol="fx_read_file", nargs=3, with_leave=True,
         capture=["key:key@0", "size:u32@2", "got:u32@ret"], buf={"arg": 0, "max": 128, "cstr": True}),
    dict(id="config", event="core.state.read", symbol="fx_read_config", nargs=3, with_leave=True, buf={"arg": 0, "fixed": 2, "max": 2},
         capture=["value:key@0", "enabled:bool@ret"], const={"object": "config", "key": "active"}),
    dict(id="registry", event="core.state.write", symbol="fx_registry_roundtrip", nargs=3, buf={"arg": 0, "fixed": 2, "max": 2},
         capture=["value:key@0"], const={"object": "registry", "key": "Mode"}),
    dict(id="plugin", event="app.plugin", symbol="fx_load_plugin", nargs=3, buf={"arg": 0, "fixed": 8, "max": 8},
         capture=["winner:key@0"]),
])
FRAMELOOP = hooks("frameloop.exe", [
    dict(id="frame-begin", event="app.frame", symbol="fx_frame_begin", nargs=1, capture=["frame:u64@0"], const={"edge": "begin"}),
    dict(id="frame-end", event="app.frame", symbol="fx_frame_end", nargs=1, capture=["frame:u64@0"], const={"edge": "end"}),
    dict(id="stage-begin", event="app.stage", symbol="fx_phase_begin", nargs=1, capture=["stage:u32@0"]),
])
SHARED_SCOPE = {"scope": "gates-shared", "scope_key": "5a" * 32}


class Gate(unittest.TestCase):
    """Shared engine and capture cache for one class."""

    @classmethod
    def setUpClass(cls):
        if not LIVE:
            raise unittest.SkipTest("needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
        cls.work = workdir("trace-gates")
        cls.root = Path(cls.work.name)
        cls.fx = g.fixtures_dir()
        cls.engine = g.Engine("gates")
        cls._captures = {}

    @classmethod
    def tearDownClass(cls):
        try:
            cls.engine.close()
        finally:
            cls.work.cleanup()

    def captured(self, key: str, exe: str, hook_rows: list[dict], args=None, **trace):
        """Capture EXE once per class and keep the result."""
        if key not in self._captures:
            profile = g.GateProfile(self.fx, "gate-%s/1" % key, [exe], hook_rows)
            self._captures[key] = g.capture(self.root / "runs", exe, args or [], profile.specs(self.root), **trace)
        return self._captures[key]

    def only(self, rows, **match):
        return [r for r in rows if all((r.get("payload") or {}).get(k, r.get(k)) == v for k, v in match.items())]


class M2Interleave(Gate):
    def loaded(self, name: str = "inter", transform=None) -> tuple[str, list]:
        cap = self.captured("interleave", "interleave.exe", INTERLEAVE)
        self.assertEqual(cap.health["producer"]["dropped"], 0)
        events = cap.lines()
        if transform:
            events = transform(events)
        session = g.unique("m2_" + name)
        self.engine.load(session, events)
        return session, self.engine.rows(session)

    @staticmethod
    def by_corr(rows):
        found = {}
        for row in rows:
            corr = row.get("p", {}).get("corr")
            if corr is not None:
                found.setdefault(str(corr), []).append(row)
        return found

    def test_explanation_follows_correlation_ids_and_reports_missing_links(self):
        session, rows = self.loaded()
        by_corr = self.by_corr(rows)
        client = self.engine.client()
        # every submitted operation has its own chain; the pools interleave in time but never in the explanation
        for op in (1003, 2005):
            chain = by_corr[str(op)]
            self.assertEqual(sorted(r["kind"] for r in chain), ["app.complete", "app.handle", "app.request", "app.result"], op)
            done = next(r for r in chain if r["kind"] == "app.complete")
            up = client.explain(session, done["event_id"], direction="upstream", max_depth=8)
            names = {n["event_id"]: n for n in up["nodes"]}
            self.assertEqual(set(names), {r["event_id"] for r in chain}, "the explanation is exactly the verified chain of %d" % op)
            corrs = {json.loads(n["payload"])["corr"] for n in up["nodes"]}
            self.assertEqual(corrs, {op}, "no event of another operation (the other pool's) is connected")
            self.assertEqual(up["boundaries"], [])
            self.assertTrue(all(e["status"] == "supported" and e["relation"] in ("request-completion", "async-handoff")
                                for e in up["edges"]))
            self.assertTrue(all("temporal-only" != e["relation"] for e in up["edges"]))
            hops = {(n["kind"]) for n in up["nodes"]}
            self.assertEqual(hops, {"app.complete", "app.request", "app.handle", "app.result"})
        # the dropped request has no handler: a cited unresolved boundary, not the closest handler by time
        dropped = by_corr["9999"]
        self.assertEqual([r["kind"] for r in dropped], ["app.request"])
        down = client.explain(session, dropped[0]["event_id"], direction="downstream", max_depth=8)
        self.assertEqual([n["event_id"] for n in down["nodes"]], [dropped[0]["event_id"]])
        self.assertEqual(down["edges"], [])
        self.assertEqual(down["boundaries"], [{"event_id": dropped[0]["event_id"], "reason": "missing-completion",
                                               "relation": "request-completion"}])
        info = client.info(session)
        print(json.dumps(info["relations"]))

    def test_reuse_rebase_and_delay_never_merge_identities_or_infer_order_from_arrival(self):
        session, rows = self.loaded("reuse")
        client = self.engine.client()
        objects = client.query(session, lifetimes="objects")["rows"]
        modules = client.query(session, lifetimes="modules")["rows"]
        # an address reused after a free is a new lifetime: two objects, never one
        by_addr = {}
        for o in objects:
            by_addr.setdefault(o["addr"], []).append(o)
        reused = [v for v in by_addr.values() if len(v) == 2]
        self.assertEqual(len(reused), 1, objects)
        first, second = sorted(reused[0], key=lambda o: o["gen"])
        self.assertEqual((first["gen"], second["gen"]), (1, 2))
        self.assertLess(first["destroy_seq"], second["create_seq"])
        self.assertTrue(first["resolved"] and second["resolved"])
        # the module reloaded at another base is a second instance, with its own lifetime
        mod = [m for m in modules if m["name"] == "interleave_mod.dll"]
        self.assertEqual(len(mod), 2, mod)
        self.assertNotEqual(mod[0]["base"], mod[1]["base"])
        self.assertNotEqual(mod[0]["inst"], mod[1]["inst"])
        self.assertTrue(all(m["unload_seq"] is not None for m in mod))
        self.assertLess(mod[0]["unload_seq"], mod[1]["load_seq"])
        # a state key carries the lifetime generation: the same address in two lifetimes is two keys
        # (checked in M4); here the identities in the event stream are distinct as well
        creates = [r for r in rows if r["kind"] == "core.object.create" and r["p"]["object"] == first["addr"]]
        self.assertEqual(len(creates), 2)

    def test_delayed_producers_do_not_change_what_is_connected(self):
        """The pool producer's batches reach the collector before the main producer's: arrival is the reverse of execution."""
        def two_producers(events):
            pool_kinds = {"app.handle", "app.result", "app.complete"}
            main, pool, rest = [], [], []
            for e in events:
                if e["kind"] in pool_kinds:
                    pool.append(e)
                elif e["kind"].startswith("core.capture") or e["kind"] == "core.process.start":
                    rest.append(e)
                else:
                    main.append(e)
            out = []
            for source, group in (("agent-pool", pool), ("agent", rest), ("agent-main", main)):
                for index, e in enumerate(group, 1):
                    out.append({**e, "source_id": source, "source_seq": index})
            return out
        ordered, ordered_rows = self.loaded("ordered")
        delayed, delayed_rows = self.loaded("delayed", two_producers)
        client = self.engine.client()
        chain_o = self.by_corr(ordered_rows)["1003"]
        chain_d = self.by_corr(delayed_rows)["1003"]
        request = next(r for r in chain_d if r["kind"] == "app.request")
        done = next(r for r in chain_d if r["kind"] == "app.complete")
        self.assertLess(done["seq"], request["seq"], "arrival order is reversed in the delayed session")
        self.assertLess(request["t_mono_ns"], done["t_mono_ns"], "while the producers' clocks say the request came first")

        def shape(session, rows):
            done = next(r for r in self.by_corr(rows)["1003"] if r["kind"] == "app.complete")
            up = client.explain(session, done["event_id"], direction="upstream", max_depth=8)
            kinds = {n["event_id"]: n["kind"] for n in up["nodes"]}
            return (sorted(kinds.values()), sorted((kinds[e["from"]], kinds[e["to"]], e["relation"], e["status"]) for e in up["edges"]),
                    up["boundaries"])
        self.assertEqual(shape(ordered, ordered_rows), shape(delayed, delayed_rows))
        # the relations are not temporal: nothing was ordered because it arrived first
        self.assertTrue(all(e["relation"] != "temporal-only" for e in client.explain(
            delayed, done["event_id"], direction="upstream", max_depth=8)["edges"]))


class M2Diff(Gate):
    """Section 14.7: two configurations of trace_app, aligned before they are compared."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.work_dir = cls.root / "app-work"
        cls.runs = {}
        profile = g.GateProfile(cls.fx, "gate-app/1", ["trace_app.exe"], TRACE_APP)
        specs = profile.specs(cls.root)
        for config in ("A", "B"):
            shutil.rmtree(cls.work_dir, ignore_errors=True)
            cls.work_dir.mkdir()
            cls.runs[config] = g.capture(cls.root / "runs", "trace_app.exe", [str(cls.work_dir), config], specs, **SHARED_SCOPE)

    def test_two_configurations_differ_in_resources_state_and_functions_not_in_addresses_or_timing(self):
        engine = self.engine
        a, b = g.unique("m2_a"), g.unique("m2_b")
        engine.load(a, self.runs["A"].lines())
        engine.load(b, self.runs["B"].lines())
        client = engine.client()
        d = client.diff(a, b, align={"keys": ["kind", "resource", "state", "payload:value", "payload:winner"],
                                     "kinds": ["core.resource.write", "core.resource.read", "core.state.read", "core.state.write", "app.plugin"]})
        aligned = d["aligned"]
        entries = {e["key"]: e for e in aligned["entries"]}
        by_class = Counter(e["class"] for e in aligned["entries"])
        # the real differences, and only those: B's extra file (read and write), the config and registry values, the plugin winner
        self.assertEqual(by_class, {"same": 4, "only_a": 3, "only_b": 5})
        self.assertEqual(aligned["unmatched_a"], 3)
        self.assertEqual(aligned["unmatched_b"], 5)
        extra = [e for e in aligned["entries"] if e["class"] == "only_b" and e["key"].startswith("core.resource.")]
        self.assertEqual(sorted(e["key"].split("|")[0] for e in extra), ["core.resource.read", "core.resource.write"])
        for state in ("core.state.read|-|config:active", "core.state.write|-|registry:Mode"):
            sides = {e["class"] for k, e in entries.items() if k.startswith(state)}
            self.assertEqual(sides, {"only_a", "only_b"}, state)
        winners = {e["class"] for k, e in entries.items() if k.startswith("app.plugin")}
        self.assertEqual(winners, {"only_a", "only_b"})
        # addresses, pids, threads and timing differ between the runs and none of them is a key
        rows_a, rows_b = engine.rows(a), engine.rows(b)
        self.assertNotEqual({r["process_id"] for r in rows_a}, {r["process_id"] for r in rows_b})
        self.assertNotEqual([r["t_mono_ns"] for r in rows_a], [r["t_mono_ns"] for r in rows_b])
        self.assertIn("event ids, sequence numbers, timestamps, pids, tids and addresses are never keys", aligned["normalizations"])
        self.assertEqual((aligned["gaps_a"], aligned["gaps_b"], aligned["ambiguous"]), (0, 0, 0))
        # the same diff twice is byte-identical
        again = client.diff(a, b, align={"keys": ["kind", "resource", "state", "payload:value", "payload:winner"],
                                         "kinds": ["core.resource.write", "core.resource.read", "core.state.read", "core.state.write", "app.plugin"]})
        self.assertEqual(json.dumps(d, sort_keys=True), json.dumps(again, sort_keys=True))

    def test_symbolization_against_the_real_program_in_the_live_daemon_and_a_function_diff(self):
        engine = self.engine
        prepared = engine.prepare(self.fx / "trace_app.exe", "trace-app-gates")
        self.assertEqual(prepared["state"], "done", prepared)
        program, project = prepared["project"]["program"], prepared["project"]["gpr"]
        sessions = {}
        for config in ("A", "B"):
            name = g.unique("m2_sym_" + config.lower())
            opened = engine.load(name, self.runs[config].lines(), program=program, project=project)
            sessions[config] = name
            self.assertGreater(opened["opened"]["symbols"]["functions"], 100, opened)
        info = engine.client().info(sessions["A"])
        counts = info["symbolization"]
        # every event with a mapped code address is symbolized by the engine's own program, not a test-side table
        with_address = counts["total"] - counts["no_stack"] - counts["not_code"]
        self.assertGreaterEqual(counts["symbolized"] / with_address, 0.95, counts)
        d = engine.client().diff(sessions["A"], sessions["B"], align={
            "keys": ["kind", "function"], "kinds": ["core.resource.write", "core.resource.read"]})["aligned"]
        self.assertTrue(all(e["class"] == "different_under_matched_coverage" for e in d["entries"]), d["entries"])
        self.assertEqual(sorted(e["key"].split("|")[0] for e in d["entries"]), ["core.resource.read", "core.resource.write"])
        self.assertTrue(all((e["count_a"], e["count_b"]) == (2, 3) for e in d["entries"]))
        self.assertTrue(all(e["key"].split("|")[1].startswith("FUN_") for e in d["entries"]))
        # a re-symbolization through the live daemon is a new interpretation revision and leaves the old one readable
        before = engine.client().info(sessions["A"])
        again = engine.tool("resymbolize", sessions["A"], program=program, project=project, cap=engine.caps[sessions["A"]])
        self.assertNotIn("error", again, again)
        after = engine.client().info(sessions["A"])
        self.assertGreater(after["interpretations"], before["interpretations"])
        self.assertEqual(after["symbolization"]["symbolized"], before["symbolization"]["symbolized"])
        pinned = engine.client().query(sessions["A"], kinds=["core.resource.write"], with_symbols=True, interp=before["symbolization"]["interp"])
        latest = engine.client().query(sessions["A"], kinds=["core.resource.write"], with_symbols=True)
        self.assertEqual(pinned["symbols"]["interp"], before["symbolization"]["interp"])
        self.assertGreater(latest["symbols"]["interp"], pinned["symbols"]["interp"])
        self.assertEqual([r["function"] for r in pinned["symbols"]["rows"]], [r["function"] for r in latest["symbols"]["rows"]])

    def test_an_overlapping_capture_gap_makes_the_comparison_unknown_and_keeps_the_rest(self):
        """B overflowed its ring (a real loss, cited by core.capture.gap): what it lacks is unknown, not absent."""
        profile = g.GateProfile(self.fx, "gate-frame/1", ["frameloop.exe"], FRAMELOOP)
        specs = profile.specs(self.root)
        clean = g.capture(self.root / "runs", "frameloop.exe", ["--frames=60"], specs, **SHARED_SCOPE)
        lossy = g.capture(self.root / "runs", "frameloop.exe", ["--frames=20000"], specs, ring_bytes=1 << 16, batch_ms=300,
                          counter_ms=100, bp_ms=0.2, window=1, **SHARED_SCOPE)
        self.assertGreater(lossy.health["producer"]["dropped"], 0)
        a, b = g.unique("m2_clean"), g.unique("m2_lossy")
        self.engine.load(a, clean.lines())
        self.engine.load(b, lossy.lines())
        d = self.engine.client().diff(a, b, align={"keys": ["kind", "payload:stage"], "kinds": ["app.frame", "app.stage"]})["aligned"]
        self.assertEqual(d["gaps_a"], 0)
        self.assertGreater(d["gaps_b"], 0)
        classes = Counter(e["class"] for e in d["entries"])
        self.assertTrue(classes["not_comparable"] > 0, classes)
        self.assertNotIn("only_a", classes)             # absence in a lossy run is never reported as absence
        self.assertNotIn("different_under_matched_coverage", classes)


ROLES_PHASES = """
[[roles]]
id = "main"
resolve = "function"
value = "frame-begin"

[[roles]]
id = "worker"
resolve = "function"
value = "pool-thread"

[[phases]]
id = "frame"
kind = "frame"
open = "frame-begin"
close = "frame-end"

[[phases]]
id = "input"
kind = "stage"
parent = "frame"
open = "stage-begin"
close = "frame-end"

[[phases]]
id = "update"
kind = "stage"
parent = "frame"
open = "stage-begin"
close = "frame-end"

[[phases]]
id = "render"
kind = "stage"
parent = "frame"
open = "stage-begin"
close = "frame-end"
"""
FRAMELOOP_KEYS = hooks("frameloop.exe", [
    dict(id="frame-begin", event="core.marker", symbol="fx_frame_begin", nargs=1, capture=["frame:u64@0"]),
    dict(id="frame-end", event="app.frame", symbol="fx_frame_end", nargs=1, capture=["frame:u64@0"]),
    dict(id="stage-begin", event="app.stage", symbol="fx_phase_begin", nargs=1, capture=["stage:u32@0"]),
    dict(id="job-callback", event="app.callback", symbol="fx_job_callback", nargs=1, capture=["frame:u64@0"]),
    dict(id="pool-thread", event="app.pool", symbol="fx_pool_thread", nargs=1),
    dict(id="job-physics", event="app.physics", symbol="fx_job_physics", nargs=1, capture=["frame:u64@0"]),
    dict(id="ours-write", event="core.state.write", symbol="fx_ours_write", nargs=1, capture=["frame:u64@0"], const={"object": 1, "key": "entity.value"}),
    dict(id="consume", event="core.state.read", symbol="fx_consume", nargs=1, capture=["frame:u64@0"], const={"object": 1, "key": "entity.value"}),
])


class M2Roles(Gate):
    """Section 15.2: roles and phases on the frame loop are first-class keys, and the checks read them."""

    def run_frameloop(self, *args):
        from hydralysis import trace_keys
        profile = g.GateProfile(self.fx, "gate-keys/1", ["frameloop.exe"], FRAMELOOP_KEYS, extra=ROLES_PHASES)
        specs = profile.specs(self.root)
        cap = g.capture(self.root / "runs", "frameloop.exe", list(args), specs)
        loaded = profile.load(self.root)
        events, report = trace_keys.annotate(cap.lines(), loaded)
        return events, report

    def verdicts(self, *args):
        events, report = self.run_frameloop(*args)
        session = g.unique("m2_roles")
        self.engine.load(session, events)
        reply = self.engine.client().check(session, assertions=[
            {"type": "only_on_role", "name": "callback-on-main", "kind": "app.callback", "role": "main"},
            {"type": "write_precedes_read_in_frame", "name": "write-before-read"},
            {"type": "only_on_role", "name": "callback-in-update", "kind": "app.callback", "role": "update", "role_field": "phase"},
        ])
        results = {r["assertion"].split("/")[0]: r for r in reply["results"]}
        return results, report, events

    def test_the_defaults_pass_and_roles_and_phases_are_stamped(self):
        results, report, events = self.verdicts("--frames=20")
        for name in ("callback-on-main", "write-before-read", "callback-in-update"):
            self.assertEqual(results[name]["verdict"], "pass", results[name])
        self.assertEqual(results["callback-on-main"]["checked"], 20)
        roles = {tuple(v) for v in report["roles"].values()}
        self.assertEqual(roles, {("main",), ("worker",)})
        stamped = [e for e in events if e["kind"] == "app.stage"]
        self.assertEqual(sorted({e["payload"]["phase"] for e in stamped}), ["input", "render", "update"])

    def test_a_callback_on_a_worker_fails_only_on_main_with_a_cited_event(self):
        results, _report, _events = self.verdicts("--frames=20", "--callback-on=worker")
        failed = results["callback-on-main"]
        self.assertEqual(failed["verdict"], "fail")
        self.assertTrue(failed["counterexamples"] and failed["counterexamples"][0].startswith("ev_"), failed)

    def test_a_write_one_stage_late_fails_the_ordering_check(self):
        results, _report, _events = self.verdicts("--frames=20", "--ours-stage=render")
        self.assertEqual(results["write-before-read"]["verdict"], "fail")
        self.assertTrue(results["write-before-read"]["counterexamples"])

    def test_a_missing_phase_marker_makes_the_phase_check_unknown_not_pass(self):
        results, report, events = self.verdicts("--frames=20", "--skip-marker=update")
        self.assertEqual(results["callback-in-update"]["verdict"], "unknown", results["callback-in-update"])
        callbacks = [e for e in events if e["kind"] == "app.callback" and e["payload"].get("role") == "main"]
        self.assertTrue(callbacks)
        self.assertTrue(all("missing-marker:update" in e["payload"]["unresolved"]["phase"] for e in callbacks))
