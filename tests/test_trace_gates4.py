"""Acceptance gates M4 (checks, field-writer, discovery), S (hash names, script natives, build invalidation) and I (persist
footprint, hang dumps) of the semantic trace: real fixtures, real engine. Same conventions as test_trace_gates.py."""

from __future__ import annotations

import json
import re
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

    def test_the_discovery_report_lists_the_observation_gaps_of_a_lossy_capture_apart_from_everything_else(self):
        lossy = dict(ring_bytes=1 << 16, batch_ms=300, counter_ms=100, bp_ms=0.2, window=1)
        session, cap, _results = self.run_check("discgap", ["--frames=20000"], **lossy)
        self.assertGreater(cap.health["producer"]["dropped"], 0)
        reply = self.engine.tool("query", session, report="discovery", kinds=["app.consume"], limit=200,
                                 params={"candidates": [{"key": "consume"}, {"key": "never_hooked_candidate"}]})
        result = reply["result"]
        self.assertGreater(result["observation_gaps"]["count"], 0)
        self.assertEqual(result["observation_gaps"]["count"], len(self.engine.client().info(session)["gaps"]))
        self.assertEqual([i["key"] for i in result["unobserved_candidates"]["items"]], ["never_hooked_candidate"])
        self.assertEqual([i["key"] for i in result["exercised_behavior"]["items"]], ["consume"])

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


def writer_hooks(*, alias_write: bool = False):
    rows = [
        dict(id="fx_set_level", event="core.state.write", symbol="fx_set_level", nargs=2, capture=["object:u64@0", "value:u32@1"],
             const={"offset": 4, "size": 4}),
        dict(id="fx_reset_thing", event="core.state.write", symbol="fx_reset_thing", nargs=2, capture=["object:u64@0"],
             const={"offset": 0, "size": 12}),
        dict(id="fx_bump_level", event="core.state.write", symbol="fx_bump_level", nargs=1, capture=["object:u64@0"],
             const={"offset": 4, "size": 4}),
        dict(id="fx_use_alias", event="app.escape", symbol="fx_use_alias", nargs=2, capture=["object:u64@0"],
             const={"offset": 4, "callee": "fx_alias_write"}),
    ]
    if alias_write:
        rows.append(dict(id="fx_alias_write", event="core.state.write", symbol="fx_alias_write", nargs=2, capture=["object:u64@0"],
                         const={"offset": 0, "size": 4}))
    return hooks("field_writers.exe", rows)


@unittest.skipUnless(LIVE, "needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
class M4FieldWriters(Gate):
    """Section 14.4: who writes one field of one object, as three answers that are never merged, over a REAL static scan
    (the engine's `writes` query on the built program) and LIVE trace data."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import build_fixtures
        from hydralysis import query
        exe = cls.fx / "field_writers.exe"
        cls.functions, cls.data = build_fixtures.symbols(exe.with_suffix(".map"))
        cls.names = {address: name for name, address in cls.functions.items()}
        status = cls.engine.prepare(exe, "fw_gate")
        assert status["state"] not in ("failed",), status
        scan = json.loads(query.QueryRunner(cls.engine.settings).query("fw_gate", "writes", "", limit=64, options={"offset": "0x4"}))
        ours = set(cls.names)
        cls.static_sites = [r for r in scan["writes"] if r["function"] in ours]

    def writers(self, key, args=(), alias_write=False):
        profile = g.GateProfile(self.fx, "gate-fw-%s/1" % key, ["field_writers.exe"], writer_hooks(alias_write=alias_write))
        cap = g.capture(self.root / "runs", "field_writers.exe", ["--frames=20", *args], profile.specs(self.root))
        session = g.unique("m4_fw_" + key)
        self.engine.load(session, cap.lines())
        sets = self.engine.rows(session, kinds=["core.state.write"])
        first = next(r["p"] for r in sets if r["p"].get("site") == "fx_set_level")
        obj = first["object"]
        self.assertEqual(obj & 0xffff, int(self.data["g_thing"], 16) & 0xffff, "the traced object is g_thing")
        reply = self.engine.tool("query", session, report="writers", kinds=["core.state.write", "app.escape"], limit=200,
                                 params={"object": obj, "offset": 4, "size": 4, "static_sites": self.static_sites,
                                         "names": self.names})
        self.assertNotIn("error", reply, reply)
        return reply["result"]

    def test_the_static_scan_lists_exactly_the_stores_at_the_field_offset(self):
        self.assertEqual(sorted({self.names[r["function"]] for r in self.static_sites}),
                         ["fx_bump_level", "fx_reset_thing", "fx_set_level"])

    def test_a_static_candidate_that_never_ran_is_may_access_not_a_writer(self):
        result = self.writers("plain")
        self.assertEqual([w["site"] for w in result["observed"]], ["fx_reset_thing", "fx_set_level"])
        self.assertTrue(all(w["static_candidate"] and w["on_selected_object"] for w in result["observed"]))
        self.assertEqual({w["site"]: w["count"] for w in result["observed"]}, {"fx_reset_thing": 4, "fx_set_level": 20})
        self.assertEqual([m["site"] for m in result["may_access"]], ["fx_bump_level"])
        self.assertEqual(result["may_access"][0]["status"], "may access")
        self.assertFalse(result["static_inventory_complete"])

    def test_an_uninstrumented_alias_stays_unresolved_and_is_not_attributed(self):
        result = self.writers("alias")
        self.assertEqual([(u["site"], u["callee"], u["count"]) for u in result["unresolved"]], [("fx_use_alias", "fx_alias_write", 5)])
        self.assertIn("neither observed nor excluded", result["unresolved"][0]["stopped_by"])
        self.assertNotIn("fx_use_alias", [w["site"] for w in result["observed"]], "an escape is not a confirmed write")
        self.assertNotIn("fx_use_alias", [m["site"] for m in result["may_access"]])

    def test_a_writer_the_scan_did_not_list_is_observed_and_flagged(self):
        result = self.writers("hooked", alias_write=True)
        row = next(w for w in result["observed"] if w["site"] == "fx_alias_write")
        self.assertFalse(row["static_candidate"])
        self.assertIn("no scan of this field would have listed it", row["note"])
        self.assertEqual(row["count"], 5)

    def test_the_discovery_report_keeps_exercised_unobserved_and_gaps_apart(self):
        profile = g.GateProfile(self.fx, "gate-fw-disc/1", ["field_writers.exe"], writer_hooks())
        cap = g.capture(self.root / "runs", "field_writers.exe", ["--frames=20"], profile.specs(self.root))
        session = g.unique("m4_disc")
        self.engine.load(session, cap.lines())
        candidates = [{"key": name, "static_sites": [r["site"] for r in self.static_sites if self.names[r["function"]] == name]}
                      for name in sorted({self.names[r["function"]] for r in self.static_sites})]
        reply = self.engine.tool("query", session, report="discovery", kinds=["core.state.write", "app.escape"], limit=200,
                                 params={"candidates": candidates})
        self.assertNotIn("error", reply, reply)
        result = reply["result"]
        exercised = {i["key"]: i["count"] for i in result["exercised_behavior"]["items"] if i["kind"] == "core.state.write"}
        self.assertEqual(exercised, {"fx_reset_thing": 4, "fx_set_level": 20})
        self.assertEqual([i["key"] for i in result["unobserved_candidates"]["items"]], ["fx_bump_level"])
        self.assertEqual(result["observation_gaps"]["count"], 0, "this capture lost nothing")
        self.assertIn("proves nothing", result["observation_gaps"]["meaning"])

    def test_running_the_candidate_moves_it_from_may_access_to_observed(self):
        result = self.writers("bump", args=("--bump",))
        self.assertIn("fx_bump_level", [w["site"] for w in result["observed"]])
        self.assertEqual(result["may_access"], [])


BYPASS_HOOKS_ROWS = [
    dict(id="fx_put_slot", event="core.function.enter", symbol="fx_put_slot", nargs=2, capture=["receiver:u64@0"]),
    dict(id="put_int", event="core.state.write", symbol="?put@Counter@@QEAAXH@Z", nargs=2, const={"key": "Store.value"}),
    dict(id="put_ll", event="core.state.write", symbol="?put@Counter@@UEAAX_J@Z", nargs=2, const={"key": "Store.value"}),
]
BYPASS_HOOKS = hooks("vcall_fixture.exe", BYPASS_HOOKS_ROWS)


@unittest.skipUnless(LIVE, "needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
class M4Bypass(Gate):
    """Section 15.4: a hook on the first overload of Counter::put does not see the write of the second, which is reached
    through the base pointer's vtable. Receiver classes come from the vtable pointer in the image; static virtual-call
    candidates that were never observed stay `may call`."""

    FRAMES = 30

    def setUp(self):
        import build_fixtures
        from hydralysis import query
        from hydralysis.pe import Image
        cls = type(self)
        if not hasattr(cls, "image"):
            exe = self.fx / "vcall_fixture.exe"
            cls.functions, cls.data = build_fixtures.symbols(exe.with_suffix(".map"))
            cls.image = Image(exe)
            self.assertNotEqual(self.engine.prepare(exe, "vc_gate")["state"], "failed")
            scan = json.loads(query.QueryRunner(self.engine.settings).query("vc_gate", "vcalls", "", limit=20, options={"offset": "0x8"}))
            cls.static_callers = {c["function"] for c in scan["callers"]}

    def vtable_slot_targets(self):
        """Every class's slot-1 (offset 8) entry, read from the vftables in the image: the static candidates of a call [vptr + 8]."""
        by_address = {int(a, 16): n for n, a in self.functions.items() if "::" in n and not n.endswith("!direct")}
        out = []
        for name, address in sorted(self.data.items()):
            if not name.endswith("::vftable") or name.startswith("type_info"):
                continue
            entry = int.from_bytes(self.image.read_rva(int(address, 16) - self.image.base + 8, 8), "little")
            out.append(by_address.get(entry, "%#x" % entry))
        return sorted(set(out))

    def run_report(self):
        profile = g.GateProfile(self.fx, "gate-bypass/1", ["vcall_fixture.exe"], BYPASS_HOOKS)
        cap = g.capture(self.root / "runs", "vcall_fixture.exe", [str(self.root / "no-stop-file"), str(self.FRAMES)],
                        profile.specs(self.root), linger_ms=800)
        session = g.unique("m4_byp")
        self.engine.load(session, cap.lines())
        writes = self.engine.rows(session, kinds=["core.state.write"])
        enters = self.engine.rows(session, kinds=["core.function.enter"])
        base = next(r["p"]["base"] for r in self.engine.rows(session, kinds=["core.module.load"])
                    if r["p"]["name"].lower() == "vcall_fixture.exe")
        counter_rva = int(self.data["g_counter"], 16) - self.image.base
        # the receiver's class is the class that defines the method the dispatch reached (the hooked Counter::put override):
        # the image constructs g_counter in a dynamic initializer, so its vtable pointer is not in the file
        target_symbol = next(h["symbol"] for h in BYPASS_HOOKS_ROWS if h["id"] == "put_ll")
        owner = re.fullmatch(r"\?\w+@(\w+)@@.*", target_symbol).group(1)
        receivers = {base + counter_rva: owner}
        self.assertIn(base + counter_rva, {r["p"]["receiver"] for r in enters}, "fx_put_slot was reached with g_counter")
        candidates = self.vtable_slot_targets()
        # hook ids stand for the hooked functions: Counter::put is the hook put_ll
        wanted = {"Counter::put": "put_ll"}
        reply = self.engine.tool("query", session, report="bypass", kinds=["core.state.write", "core.function.enter"], limit=200,
                                 params={"hook": "put_int", "field": "Store.value", "dispatch_sites": {"fx_put_slot": {"slot": 8}},
                                         "receivers": receivers,
                                         "static_candidates": {"fx_put_slot": [wanted.get(c, c) for c in candidates]}})
        self.assertNotIn("error", reply, reply)
        return reply["result"], writes, candidates

    def test_the_second_overload_is_reported_as_a_bypass_with_the_observed_path_and_receiver_class(self):
        result, writes, _c = self.run_report()
        frames = len(writes) // 2          # the frames the capture saw: both overloads write once per frame
        self.assertEqual(len(writes), 2 * frames)
        self.assertGreaterEqual(frames, self.FRAMES - 2)
        self.assertEqual((result["writes_observed"], result["through_hook"], result["bypassed"]), (2 * frames, frames, frames))
        self.assertEqual(result["verdict"], "hook_bypassed")
        self.assertEqual(result["by_class"], {"different-slot": frames})
        first = result["bypasses"][0]
        self.assertEqual((first["class"], first["site"] if "site" in first else None), ("different-slot", first["site"]))
        self.assertEqual(first["receiver_class"], "Counter")
        self.assertEqual(first["via"], "fx_put_slot")
        self.assertEqual(first["path"], ["put_ll"])
        self.assertIn("indirect call at fx_put_slot (slot 8)", first["reached_through"])
        self.assertTrue(first["event_id"].startswith("ev_"))

    def test_the_observed_edge_is_cited_and_unobserved_slots_stay_may_call(self):
        result, _w, candidates = self.run_report()
        edges = result["edges"]
        self.assertEqual([(e["site"], e["target"], e["receiver_class"], e["count"]) for e in edges["observed"]],
                         [("fx_put_slot", "put_ll", "Counter", edges["observed"][0]["count"])])
        self.assertGreaterEqual(edges["observed"][0]["count"], self.FRAMES - 2)
        self.assertEqual(edges["observed"][0]["relation"], "observed-call")
        self.assertTrue(edges["observed"][0]["events"])
        self.assertIn("Counter::put", candidates)
        self.assertGreater(len(candidates), 3, "other classes' slot-1 methods are static candidates of the same call")
        self.assertEqual({u["status"] for u in edges["unobserved_candidates"]}, {"may call"})
        self.assertEqual(sorted(u["target"] for u in edges["unobserved_candidates"]), sorted(c for c in candidates if c != "Counter::put"))
        self.assertIn("never `does not call`", edges["note"])
        self.assertNotIn("does not call", json.dumps(edges["unobserved_candidates"]))

    def test_the_static_scan_names_the_dispatch_site(self):
        self.run_report()
        self.assertIn(self.functions["fx_put_slot"], self.static_callers)


NAMES_HOOKS = hooks("fnv_names.exe", [
    dict(id="dispatch", event="app.record", symbol="fx_dispatch_record", nargs=1, capture=["hash:u64@0", "id:u32@ret"]),
])
COLLISION = ("rec_L9qap7cOoK1", "rec_EQI_EyPfCio")


@unittest.skipUnless(LIVE, "needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
class SHashedNames(Gate):
    """Section 15.6: hashed names. The dictionary comes from the program's own strings; constants are annotated, a name
    search finds code, the colliding pair is ambiguous, and trace payload hashes are resolved at query time."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import build_fixtures
        from hydralysis import trace_hashes
        from hydralysis.pe import Image
        cls.exe = cls.fx / "fnv_names.exe"
        cls.image = Image(cls.exe)
        cls.functions, cls.data = build_fixtures.symbols(cls.exe.with_suffix(".map"))
        found = set(re.findall(rb"[a-z]+\.[a-z]+|rec_[A-Za-z0-9_]{11}", cls.image.data))
        cls.strings = sorted(f.decode() for f in found)
        cls.expected = json.loads((Path(__file__).parent / "fixtures" / "expected" / "fnv_names.json").read_text())["answers"]
        cls.dictionary = trace_hashes.Dictionary(algorithms=["fnv1a64"])
        cls.dictionary.add_lines("\n".join(cls.strings), "fnv_names.exe strings")
        cls.registry = cls.dictionary.registry
        cls.hashes = {r["name"]: int(r["hash"], 16) for r in cls.expected["records"]}
        from hydralysis import query
        assert cls.engine.prepare(cls.exe, "fnv_gate")["state"] != "failed"
        runner, cursor, functions = query.QueryRunner(cls.engine.settings), None, []
        while True:
            listed = json.loads(runner.query("fnv_gate", "functions", "", limit=200, **({"cursor": cursor} if cursor else {}), options={}))
            functions.extend(listed["functions"])
            cursor = listed.get("next_cursor") if listed.get("truncated") else None
            if not cursor:
                break
        cls.bodies = []
        for f in functions:
            for part in f["body"]:
                lo, hi = (int(x, 16) for x in part.strip("[]").split(","))
                cls.bodies.append((lo - cls.image.base, hi - cls.image.base + 1))

    def test_the_dictionary_built_from_the_image_strings_hashes_like_the_program(self):
        self.assertTrue(set(self.hashes) <= set(self.strings), "all 64 record names are strings of the image")
        for name, value in self.hashes.items():
            self.assertEqual(self.registry.compute("fnv1a64", name), value, name)

    def test_hash_constants_in_the_dispatch_code_are_annotated_with_name_and_source(self):
        from hydralysis import trace_hashes
        hits = trace_hashes.scan_constants(self.image, [(v, 64) for v in self.hashes.values()], limit=500, functions=self.bodies)
        code = [h for h in hits if h["context"] == "code-immediate"]
        entry = int(self.functions["fx_dispatch_record"], 16) - self.image.base
        self.assertGreaterEqual(len({h["value"] for h in code}), 60)
        self.assertEqual({h["function"] for h in code if "function" in h}, {"rva:%#x" % entry})
        notes = trace_hashes.annotate_constants(self.dictionary, [{"value": h["value"], "where": h["rva"]} for h in code], ["fnv1a64"])
        by_value = {n["value"]: n for n in notes}
        health = by_value["0xc5c4191b5a4187c0"]
        self.assertEqual((health["status"], health["answers"][0]["names"][0]["name"]), ("resolved", "player.health"))
        self.assertEqual(health["answers"][0]["names"][0]["sources"], ["fnv_names.exe strings"])
        self.assertEqual({n["status"] for n in notes} - {"resolved", "ambiguous"}, set())

    def test_a_name_search_finds_the_function_that_carries_the_constant(self):
        from hydralysis import trace_hashes
        entry = int(self.functions["fx_dispatch_record"], 16) - self.image.base
        found = trace_hashes.find_name_users(self.dictionary, "player.health", self.image, algorithms=["fnv1a64"], functions=self.bodies)
        self.assertEqual(found["algorithms"][0]["hash"], "0xc5c4191b5a4187c0")
        self.assertIn(("code-immediate", "rva:%#x" % entry), [(h["context"], h.get("function")) for h in found["hits"]])
        self.assertEqual(found["algorithms"][0]["status"], "resolved")

    def test_the_colliding_pair_is_ambiguous_in_every_view_and_never_silently_resolved(self):
        from hydralysis import trace_hashes
        value = self.expected["collision"]["hash"]
        for name in COLLISION:
            found = trace_hashes.find_name_users(self.dictionary, name, self.image, algorithms=["fnv1a64"])
            self.assertEqual(found["algorithms"][0]["status"], "ambiguous", name)
            self.assertEqual(found["algorithms"][0]["hash"], value)
            self.assertTrue(found["hits"], "the constant is in the image either way")
        note = trace_hashes.annotate_constants(self.dictionary, [{"value": value}], ["fnv1a64"])[0]
        self.assertEqual(note["status"], "ambiguous")
        self.assertEqual(sorted(n["name"] for n in note["answers"][0]["names"]), sorted(COLLISION))

    def capture_events(self):
        if not hasattr(type(self), "session"):
            profile = g.GateProfile(self.fx, "gate-names/1", ["fnv_names.exe"], NAMES_HOOKS)
            cap = g.capture(self.root / "runs", "fnv_names.exe", [], profile.specs(self.root))
            type(self).session = g.unique("s_names")
            self.engine.load(self.session, cap.lines())
        return self.session

    def names_report(self, session, names, parent=None):
        reply = self.engine.tool("query", session, report="names", kinds=["app.record"], limit=200,
                                 params={"algorithm": "fnv1a64", "fields": ["hash"], "parent": parent,
                                         "dictionary": {"fnv_names.exe strings": names}})
        self.assertNotIn("error", reply, reply)
        return reply["result"]

    def test_hashed_ids_in_the_trace_are_resolved_at_query_time_as_interpretation_revisions(self):
        session = self.capture_events()
        rows = self.engine.rows(session, kinds=["app.record"])
        self.assertEqual(len(rows), 65)
        raw = {r["event_id"]: r["p"]["hash"] for r in rows}
        first = self.names_report(session, [n for n in self.strings if n.startswith("player.")])
        self.assertEqual(first["interpretation"]["counts"], {"resolved": 16, "ambiguous": 0, "unknown": 49})
        second = self.names_report(session, self.strings, parent=first["interpretation"]["revision"])
        self.assertEqual(second["interpretation"]["counts"], {"resolved": 64, "ambiguous": 1, "unknown": 0})
        self.assertNotEqual(first["interpretation"]["revision"], second["interpretation"]["revision"])
        self.assertEqual(second["interpretation"]["parent"], first["interpretation"]["revision"])
        self.assertTrue(second["interpretation"]["raw_preserved"])
        again = self.names_report(session, self.strings, parent=first["interpretation"]["revision"])
        self.assertEqual(again["interpretation"]["revision"], second["interpretation"]["revision"], "same inputs, same revision")
        notes = {n["event_id"]: n for n in second["annotations"]}
        self.assertEqual(set(notes), set(raw), "every hashed id of the trace was read")
        for event_id, note in notes.items():
            self.assertEqual(int(note["raw"], 16), int(raw[event_id], 0) if isinstance(raw[event_id], str) else raw[event_id])
        health = next(n for n in notes.values() if n["raw"] == "0xc5c4191b5a4187c0")
        self.assertEqual((health["status"], health["names"][0]["name"]), ("resolved", "player.health"))
        ambiguous = [n for n in notes.values() if n["status"] == "ambiguous"]
        self.assertEqual(sorted(x["name"] for x in ambiguous[0]["names"]), sorted(COLLISION))
        after = {r["event_id"]: r["p"]["hash"] for r in self.engine.rows(session, kinds=["app.record"])}
        self.assertEqual(after, raw, "the trace itself still holds the raw values")


NATIVES = ["add", "sub", "mul", "neg", "min", "max", "clamp", "abs", "sq", "avg3", "dist2", "select"]
PARAMS = {"add": 2, "sub": 2, "mul": 2, "neg": 1, "min": 2, "max": 2, "clamp": 3, "abs": 1, "sq": 1, "avg3": 3, "dist2": 4, "select": 3}
VM_TABLE = {"id": "minivm-table", "kind": "table", "table_rva": None, "stride": 24, "name_offset": 0, "fn_offset": 8,
            "argc_offset": 16, "argc_size": 4, "count": 10}
VM_CALLS = {"id": "minivm-register", "kind": "call", "register": "fx_vm_register", "name_arg": 0, "fn_arg": 1, "argc_arg": 2}


@unittest.skipUnless(LIVE, "needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
class SScriptNatives(Gate):
    """Section 15.7: the script VM's natives from the table and from registration calls, and a traced script call linked
    to the native event it invoked."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import build_fixtures
        from hydralysis import query, trace_bindings
        from hydralysis.pe import Image
        cls.exe = cls.fx / "minivm.exe"
        cls.image = Image(cls.exe)
        cls.functions, cls.data = build_fixtures.symbols(cls.exe.with_suffix(".map"))
        assert cls.engine.prepare(cls.exe, "vm_gate")["state"] != "failed"
        register = int(cls.functions["fx_vm_register"], 16)
        refs = json.loads(query.QueryRunner(cls.engine.settings).query("vm_gate", "xrefs", hex(register), limit=50, options={}))
        cls.call_sites = sorted(int(r["from"], 16) for r in refs["references"] if "CALL" in str(r.get("type", "")).upper())
        VM = dict(VM_TABLE, table_rva=int(cls.data["g_native_table"], 16) - cls.image.base)
        sites = [trace_bindings.x64_call_site_args(cls.image, va) for va in cls.call_sites]
        cls.table = trace_bindings.collect(cls.image, [VM, VM_CALLS], {"minivm-register": sites})

    def test_the_registration_calls_are_found_by_the_engine_and_the_loader_loop_is_one_of_them(self):
        loader = int(self.functions["fx_vm_load_table"], 16)
        self.assertEqual(len(self.call_sites), 3, [hex(v) for v in self.call_sites])
        self.assertEqual(sum(1 for v in self.call_sites if loader <= v < loader + 0x40), 1)

    def test_twelve_natives_have_names_addresses_and_parameter_counts(self):
        resolved = {r["script_name"]: r for r in self.table["rows"] if r["status"] == "resolved"}
        self.assertEqual(sorted(resolved), sorted(NATIVES))
        for name, row in resolved.items():
            self.assertEqual(row["argc"], PARAMS[name], name)
            self.assertEqual(row["native_va"], "va:%#x" % int(self.functions["fx_nat_" + name], 16), name)
        self.assertEqual(sorted(r["binding"] for r in resolved.values()).count("minivm-table"), 10)
        self.assertEqual(sorted(name for name, r in resolved.items() if r["binding"] == "minivm-register"), ["dist2", "select"])
        loop = [r for r in self.table["rows"] if r["status"] != "resolved"]
        self.assertEqual(len(loop), 1, "the loop in the table loader passes values it loads from memory")
        self.assertIn("argument 0 (name) was not a constant", loop[0]["unresolved"])
        self.assertEqual(self.table["counts"], {"rows": 13, "resolved": 12, "unresolved": 1})

    def test_the_binding_table_becomes_a_cited_corpus(self):
        from hydralysis import trace_bindings
        records, body = trace_bindings.to_corpus(self.table, build_sha256=self.image.fingerprint() if hasattr(self.image, "fingerprint")
                                                 else "00" * 32, source="fixture minivm")
        self.assertEqual(sorted(r["name"] for r in records), sorted("vm_native_" + n for n in NATIVES))
        sq = next(r for r in records if r["name"] == "vm_native_sq")
        self.assertIn("1 parameter(s)", sq["comment"])
        self.assertIn("table minivm-table", sq["comment"])
        self.assertEqual(body["counts"]["resolved"], 12)

    def run_links(self, skip=None, key="vm"):
        rows = [dict(id="line", event="app.script", symbol="fx_vm_run_line", nargs=1, capture=["script:string@0"], buf={"arg": 0, "cstr": True, "max": 64})]
        for name in NATIVES:
            if name != skip:
                rows.append(dict(id="nat_" + name, event="core.function.enter", symbol="fx_nat_" + name, nargs=1,
                                 capture=["result:u32@ret"], const={"rva": int(self.functions["fx_nat_" + name], 16) - self.image.base}))
        profile = g.GateProfile(self.fx, "gate-vm-%s/1" % key, ["minivm.exe"], hooks("minivm.exe", rows))
        cap = g.capture(self.root / "runs", "minivm.exe", [], profile.specs(self.root),
                        authorize_preview={"scope": "minivm-gate", "sites": ["line"], "max_bytes": 64})
        session = g.unique("s_vm_" + key)
        self.engine.load(session, cap.lines())
        slim = {"rows": [{k: v for k, v in r.items() if k in ("binding", "script_name", "argc", "native_rva", "implementation_rva",
                                                               "status")} for r in self.table["rows"]]}
        reply = self.engine.tool("query", session, report="links", kinds=["app.script", "core.function.enter"], limit=200,
                                 params={"table": slim, "script_field": "script.preview", "window": 8})
        self.assertNotIn("error", reply, reply)
        return session, reply["result"]

    def test_each_traced_script_call_links_to_the_native_event_it_invoked(self):
        session, result = self.run_links()
        self.assertEqual(len(result["links"]), 12)
        self.assertEqual(result["unlinked"], [])
        rows = {r["event_id"]: r for r in self.engine.rows(session)}
        sq = next(l for l in result["links"] if l["script_function"] == "sq")
        self.assertEqual(rows[sq["from"]]["p"]["script"]["preview"], "sq 12")
        self.assertEqual((rows[sq["to"]]["p"]["site"], rows[sq["to"]]["p"]["result"]), ("nat_sq", 144))
        self.assertEqual(sq["relation"], "observed-call")
        self.assertIn("binding-table", sq["basis"])
        for link in result["links"]:
            self.assertEqual(rows[link["to"]]["p"]["site"], "nat_" + link["script_function"])

    def test_a_script_call_whose_native_was_not_instrumented_is_unlinked_not_dropped(self):
        _session, result = self.run_links(skip="sq", key="skip")
        self.assertEqual(len(result["links"]), 11)
        self.assertEqual([u["script_function"] for u in result["unlinked"]], ["sq"])
        self.assertIn("not observed, or not instrumented", result["unlinked"][0]["reason"])


SAME_CODE = ["df_parse", "df_checksum", "df_format", "df_scale", "df_lookup", "df_walk"]


@unittest.skipUnless(LIVE, "needs a trace engine (HYDRALYSIS_INTEGRATION_*, HYDRA_TRACE_EXE), Frida and MSVC")
class SBuildInvalidation(Gate):
    """Section 15.10 over two real builds of one program (diff1.exe, diff2.exe -DV2): the layout the codec depends on
    moved, a hook row on a moved function is a candidate, a removed function is unplaced, the rest is carried."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import re
        import subprocess
        import build_fixtures
        from hydralysis import trace_corpus_diff
        from hydralysis.pe import Image
        cls.images, cls.functions, cls.layout, cls.sizes = {}, {}, {}, {}
        for build, name in (("A", "diff1"), ("B", "diff2")):
            exe = cls.fx / (name + ".exe")
            cls.images[build] = Image(exe)
            cls.functions[build] = {k: int(v, 16) - cls.images[build].base
                                    for k, v in build_fixtures.symbols(exe.with_suffix(".map"))[0].items() if k.startswith("df_")}
            # a function's extent: up to the next symbol of the linker map (the padding between functions is identical in both builds)
            starts = sorted({int(m.group(1), 16) - cls.images[build].base for m in re.finditer(
                r"^\s*0001:[0-9a-f]+\s+\S+\s+([0-9a-f]{16}) f", exe.with_suffix(".map").read_text(errors="replace"), re.M)})
            cls.sizes[build] = {k: min((s for s in starts if s > v), default=v + 16) - v for k, v in cls.functions[build].items()}
            out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30, cwd=str(cls.fx)).stdout
            found = re.search(r"FX amount=(\d+) offset=(\d+) size=(\d+)", out)
            assert found, out
            cls.layout[build] = {"amount": int(found.group(1)), "offset": int(found.group(2)), "size": int(found.group(3))}

        def corpus(build):
            fields = [{"name": "id", "offset": 0, "type": "int32"}, {"name": "version", "offset": 4, "type": "int32"}]
            if cls.layout[build]["size"] == 16:
                fields.append({"name": "inserted", "offset": 8, "type": "int32"})
            fields.append({"name": "amount", "offset": cls.layout[build]["offset"], "type": "int32"})
            records = [{"kind": "struct", "name": "Record", "size": cls.layout[build]["size"], "fields": fields}]
            records += [{"kind": "function", "name": k, "address": "rva:%#x" % v, "size": cls.sizes[build][k]} for k, v in cls.functions[build].items()]
            return trace_corpus_diff.load_corpus(records)
        cls.a, cls.b = corpus("A"), corpus("B")

    def readers(self):
        from hydralysis import trace_corpus_diff
        return (trace_corpus_diff.position_independent_reader(self.images["A"]),
                trace_corpus_diff.position_independent_reader(self.images["B"]))

    def report(self):
        from hydralysis import trace_corpus_diff
        base = self.images["A"].base
        dependents = [
            {"id": "codec:record-amount", "kind": "codec", "refs": [{"type": "Record", "field": "amount"}]},
            {"id": "codec:record-id", "kind": "codec", "refs": [{"type": "Record", "field": "id"}]},
            {"id": "hook:df_render", "kind": "hook", "refs": [{"function": "df_render", "rva": "%#x" % self.functions["A"]["df_render"]}]},
            {"id": "claim:df_removed", "kind": "evidence", "refs": [{"function": "df_removed"}]},
            {"id": "claim:df_decode_amount", "kind": "evidence", "refs": [{"function": "df_decode_amount"}]},
        ] + [{"id": "claim:" + name, "kind": "evidence", "refs": [{"function": name}]} for name in SAME_CODE]
        self.assertGreater(base, 0)
        return trace_corpus_diff.invalidation_report(self.a, self.b, dependents, readers=self.readers(), build_a="diff1.exe", build_b="diff2.exe")

    def test_the_programs_report_the_layouts_the_corpora_are_built_from(self):
        self.assertEqual({k: (v["offset"], v["size"]) for k, v in self.layout.items()}, {"A": (8, 12), "B": (12, 16)})
        self.assertEqual(self.layout["A"]["amount"], self.layout["B"]["amount"], "the codec follows the layout: the decoded value is the same")

    def test_the_corpus_diff_names_the_inserted_field_and_the_moved_one(self):
        from hydralysis import trace_corpus_diff
        diff = trace_corpus_diff.diff_corpora(self.a, self.b)
        self.assertEqual({(c["field"], c["change"]) for c in diff["fields"]}, {("inserted", "added"), ("amount", "moved")})
        self.assertEqual(diff["types"]["resized"], [{"type": "Record", "change": "resized", "a": 12, "b": 16}])
        self.assertEqual(diff["functions"]["added"], ["df_added"])
        self.assertEqual(diff["functions"]["removed"], ["df_removed"])

    def test_the_layout_codec_is_moved_the_hook_row_a_candidate_the_removed_function_unplaced_and_the_rest_carried(self):
        report = self.report()
        status = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(status["codec:record-amount"], "moved")
        self.assertEqual(status["codec:record-id"], "carried", "the unmoved field keeps its codec")
        self.assertEqual(status["hook:df_render"], "candidate")
        self.assertEqual(status["claim:df_removed"], "unplaced")
        self.assertEqual(status["claim:df_decode_amount"], "candidate", "the codec function changed bytes")
        self.assertEqual({n: status["claim:" + n] for n in SAME_CODE}, {n: "carried" for n in SAME_CODE})
        self.assertEqual(report["counts"], {"carried": 7, "candidate": 2, "moved": 1, "unplaced": 1})
        self.assertEqual(report["promoted"], 0)
        self.assertIn("Nothing is promoted", report["policy"])
        self.assertEqual([m["dependents"] for m in report["moved_layouts"]], [["codec:record-amount"]])


if __name__ == "__main__":
    unittest.main()
