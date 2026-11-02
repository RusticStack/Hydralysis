"""Acceptance gates M2 / M3 / M4 / S / I of the semantic trace (12.3-hydra.6): real fixtures, the real engine.

Every test captures a built MSVC fixture with the real Frida recorder (or runs the real static builders on its image),
loads the events into a real Hydra daemon through the same entry point as the MCP tool (`api.call("trace", ...)`), and
asserts the fixture's known answer (tests/fixtures/expected/*.json). Runs only with HYDRALYSIS_INTEGRATION_ENGINE/CLIENT
(an install that advertises `trace`), HYDRA_TRACE_EXE, Frida and MSVC; HYDRA_TRACE_FX may name a persistent fixture build.
"""

from __future__ import annotations

import json
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
