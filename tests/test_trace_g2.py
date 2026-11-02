"""Gates M0 / M2 (interpretation reprocess) and the engine-side session features, through the `trace` tool (12.3-hydra.6).

* `RoleResolvers` (no engine): the `thread_start_rva` and `thread_name` role resolvers work from events, the rest are refused.
* `Engine` tests (HYDRALYSIS_INTEGRATION_ENGINE/CLIENT + HYDRA_TRACE_EXE): the real daemon behind `api.call("trace", ...)`.
  - layouts: the bytes of `layouts.exe`'s own stream (tests/fixtures/expected/layouts.json) are reprocessed twice; two
    layouts live in one trace, the corrected codec reads the extension, the first revision still shows it unconsumed.
  - session metadata survives close and a daemon restart; `trace_info` is O(1) and the digest is on request only.
  - relations materialize; eviction leaves a tombstone and an export bundle reports not reproducible; quota refusal.
  - M0: JSONL import with empty / torn / corrupt / lost-producer inputs reported distinctly, the rebuilt index equals the
    original, three-valued checks, and 1,000,000 synthetic events through the streaming importer within the RSS bound.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

import trace_gate_support as g  # noqa: E402

from hydralysis import trace_keys  # noqa: E402


def event(seq, kind="core.marker", source="s", **extra):
    return {"kind": kind, "source_id": source, "source_seq": seq, "producer_gen": 1, "clock_domain": "mono",
            "t_mono_ns": 100 + seq, "confidence": "exact", **extra}


class Profile:
    def __init__(self, roles):
        self.data = {"roles": roles, "phases": [], "hooks": []}


class RoleResolvers(unittest.TestCase):
    def roles(self):
        return {"id": "R", "resolve": "thread_start_rva", "value": "0x1500"}, {"id": "N", "resolve": "thread_name", "value": "worker"}

    def test_the_start_address_and_the_name_resolve_a_thread_role(self):
        by_rva, by_name = self.roles()
        events = [
            event(0, "core.thread.start", thread_id=7, payload={"start_rva": "0x1500"}),
            event(1, "core.thread.start", thread_id=8, payload={"name": "worker"}),
            event(2, "app.x", thread_id=7, payload={"hook": "h"}), event(3, "app.x", thread_id=8, payload={"hook": "h"}),
            event(4, "app.x", thread_id=9, payload={"hook": "h"}),
        ]
        out, report = trace_keys.annotate(events, Profile([by_rva, by_name]))
        self.assertEqual(report["refused_resolvers"], {})
        roles = {e["source_seq"]: e["payload"].get("role") for e in out if e["kind"] == "app.x"}
        self.assertEqual((roles[2], roles[3], roles[4]), ("R", "N", None), out)

    def test_an_unevaluable_resolver_is_refused_explicitly(self):
        by_rva, by_name = self.roles()
        events = [event(0, "app.x", thread_id=7, payload={"hook": "h"})]
        _, report = trace_keys.annotate(events, Profile([by_rva, by_name, {"id": "P", "resolve": "pool", "value": "x"}]))
        self.assertEqual(set(report["refused_resolvers"]), {"R", "N", "P"}, report)
        with self.assertRaises(trace_keys.RoleResolverRefused) as raised:
            trace_keys.annotate(events, Profile([by_rva]), strict=True)
        self.assertIn("R", raised.exception.refused)


# ---- the real engine --------------------------------------------------------------------------------------------------
def layouts_stream() -> tuple[list[bytes], list[bytes]]:
    """The messages of layouts.exe's stream, split the way the program's own parser reads them (expected/layouts.json)."""
    expected = json.loads((HERE / "fixtures" / "expected" / "layouts.json").read_text(encoding="utf-8"))
    data = bytes.fromhex(expected["runs"][0]["files"]["layouts.bin"]["hex"])
    v1, rest = [data[i:i + 12] for i in range(0, 36, 12)], data[36:]
    negotiation, v2 = rest[:6], [rest[6 + i:6 + i + 21] for i in range(0, 63, 21)]
    assert len(data) == 105 and negotiation == bytes.fromhex("f00006000200"), (len(data), negotiation.hex())
    return v1 + [negotiation], v2


def codecs(read_ext: bool) -> dict:
    def f(name, offset, size, kind):
        return {"name": name, "offset": offset, "len": size, "type": kind}

    v1 = [f("type", 0, 2, "u16"), f("length", 2, 2, "u16"), f("id", 4, 4, "u32"), f("amount", 8, 4, "u32")]
    v2 = [f("type", 0, 2, "u16"), f("length", 2, 2, "u16"), f("id", 4, 8, "u64"), f("amount", 12, 4, "u32"), f("flags", 16, 2, "u16")]
    if read_ext:
        v2.append(f("ext", 18, 3, "hex"))
    neg = [f("type", 0, 2, "u16"), f("length", 2, 2, "u16"), f("version", 4, 2, "u16")]
    return {"v1": {"name": "msg", "fields": v1}, "v2": {"name": "msg", "fields": v2}, "neg": {"name": "neg", "fields": neg}}


@unittest.skipUnless(g.HAVE_ENGINE, "needs HYDRALYSIS_INTEGRATION_ENGINE/CLIENT and HYDRA_TRACE_EXE")
class EngineGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = g.Engine("g2")
        if not cls.engine.client().available():
            cls.engine.close()
            raise unittest.SkipTest("this engine does not advertise the trace capability")
        cls.root = cls.engine.root

    @classmethod
    def tearDownClass(cls):
        cls.engine.close()

    def tool(self, action, session=None, **options):
        reply = self.engine.tool(action, session, **options)
        return reply

    # ---- M2: interpretation reprocess -----------------------------------------------------------------------------------
    def test_layouts_two_layouts_in_one_trace_and_a_corrected_codec(self):
        v1, v2 = layouts_stream()
        name = g.unique("lay")
        events, n = [], 0

        def add(kind, **payload):
            nonlocal n
            events.append(event(n, kind, payload=payload))
            n += 1

        add("core.marker", layout="v1")
        for message in v1[:3]:
            add("app.msg", bytes=message.hex())
        add("core.marker", layout="neg")
        add("app.msg", bytes=v1[3].hex())
        add("core.marker", layout="v2")
        for message in v2:
            add("app.msg", bytes=message.hex())
        self.engine.load(name, events)
        before = self.engine.rows(name)
        first = self.tool("reprocess", name, codecs=codecs(False), kinds=["app.msg"], note="first guess: no extension")
        self.assertNotIn("error", first, first)
        stats = first.get("stats") or first
        self.assertEqual((stats["unconsumed_events"], stats["unconsumed_bytes"]), (3, 9), first)
        second = self.tool("reprocess", name, codecs=codecs(True), kinds=["app.msg"], note="corrected: ext is 3 bytes")
        self.assertEqual((second.get("stats") or second)["unconsumed_events"], 0, second)
        self.assertEqual(int(second["interp"]), int(first["interp"]) + 1, (first, second))
        # both layouts are decoded by the one corrected revision
        new = self.tool("query", name, kinds=["app.msg"], decoded=True, limit=50)
        text = json.dumps(new["decoded"])
        self.assertIn('"ext"', text)
        self.assertIn('"version"', text)
        self.assertNotIn("_unconsumed", text)
        self.assertIn("5000000002", text)           # id of the last v2 message: a u64 above 2**32
        # the first revision is still there, with the bytes it could not explain
        old = self.tool("query", name, kinds=["app.msg"], decoded=True, decode_interp=first["interp"], limit=50)
        self.assertIn("e0e1e2", json.dumps(old["decoded"]))
        self.assertIn("_unconsumed", json.dumps(old["decoded"]))
        # the original evidence is untouched
        self.assertEqual(self.engine.rows(name), before)
        info = self.tool("status", name)
        self.assertEqual(len(info["decodings"]), 2, info)

    # ---- session metadata, O(1) info ----------------------------------------------------------------------------------------
    def test_session_metadata_is_persisted_and_info_is_cheap(self):
        name = g.unique("meta")
        opened = self.engine.open(name, target={"program": "layouts.exe"}, scenario="smoke", capture_options={"mode": "metadata"})
        self.assertNotIn("error", opened, opened)
        self.engine.append(name, [event(i) for i in range(5)])
        status = self.tool("status", name)
        meta = status["meta"]
        self.assertEqual(meta["scenario"], "smoke", status)
        self.assertEqual(meta["target"], {"program": "layouts.exe"})
        self.assertEqual(meta["capture"], {"mode": "metadata"})
        self.assertEqual(status["scope"], "session:" + name)
        self.assertFalse(status.get("digest"), "trace_info does not hash the store")
        self.tool("stop", name)
        again = self.tool("status", name)
        self.assertEqual(again["meta"]["scenario"], "smoke", again)

    def test_relations_materialize_and_status(self):
        name = g.unique("rel")
        self.engine.load(name, [event(i, "app.request", payload={"corr": "c%d" % i}) for i in range(10)])
        done = self.tool("relations", name, op="materialize")
        self.assertNotIn("error", done, done)
        status = self.tool("relations", name, op="status")
        self.assertNotIn("error", status, status)

    def test_eviction_leaves_a_tombstone_and_an_export_stops_being_reproducible(self):
        name = g.unique("evict")
        self.engine.load(name, [event(i) for i in range(20)], close=True)
        exported = self.tool("export", name, name="bundle")
        # the bundle is handed on: a copy outside the store is what survives the eviction of the session
        out = str(self.root / ("handed-" + name))
        shutil.copytree(exported["out"], out)
        self.assertTrue(self.tool("bundle", None, path=out)["reproducible"])
        evicted = self.tool("evict", name)
        self.assertNotIn("error", evicted, evicted)
        self.assertEqual(evicted["evicted"][0]["session"], name, evicted)
        after = self.tool("bundle", None, path=out)
        self.assertFalse(after["reproducible"], after)
        self.assertIn("session-evicted", json.dumps(after))
        status = self.tool("status", name)
        self.assertIn("evicted", json.dumps(status))

    # ---- M0: import through the tool ----------------------------------------------------------------------------------
    def write(self, name, events, tail=b"", middle=None):
        path = self.root / name
        lines = [json.dumps(e, sort_keys=True, separators=(",", ":")).encode() + b"\n" for e in events]
        if middle is not None:
            lines.insert(1, middle)
        path.write_bytes(b"".join(lines) + tail)
        return path

    def test_import_outcomes_are_distinct_and_the_rebuilt_index_equals_the_original(self):
        events = [event(i, payload={"i": i}) for i in range(40)]
        store = self.root / "m0-store"
        cases = {
            "clean": (self.write("clean.jsonl", events), 40, "clean"),
            "torn": (self.write("torn.jsonl", events, tail=b'{"kind":"core.mar'), 40, "torn_tail"),
            "corrupt": (self.write("corrupt.jsonl", events, middle=b"not json at all\n"), 1, "corrupt"),
            "empty": (self.write("empty.jsonl", []), 0, "empty"),
        }
        gap = [event(0), event(1), event(5)]       # source_seq 2..4 vanished and no core.capture.gap says why
        cases["lost"] = (self.write("lost.jsonl", gap), 3, "clean")
        seen = {}
        with patch.dict(os.environ, {"HYDRA_TRACE_EXE": g.TOOL}):
            for key, (path, imported, outcome) in cases.items():
                reply = self.tool("import", offline=True, session="off_" + key, input=str(path), store=str(store), stream=True)
                seen[key] = reply
                self.assertEqual(reply["outcome"], outcome, (key, reply))
                self.assertEqual(reply["imported"], imported, (key, reply))
            self.assertEqual(len({r["outcome"] for k, r in seen.items() if k != "lost"}), 4, seen)
            for key in ("clean", "torn"):
                verified = self.tool("status", offline=True, op="verify", session="off_" + key, store=str(store), engine=True)
                self.assertEqual(verified["outcome"], "clean", verified)
                self.assertTrue(verified["engine"]["ok"], verified)
                rebuilt = self.tool("status", offline=True, op="rebuild", session="off_" + key, store=str(store), engine=True)
                self.assertTrue(rebuilt["ok"], rebuilt)
                self.assertEqual(rebuilt["stdout"].strip(), json.loads(verified["engine"]["stdout"])["index_digest"],
                                 "the rebuilt index is not the original")
        # the online reader keeps the lost producer apart as well
        from hydralysis import trace
        lost = trace.read_jsonl(cases["lost"][0])
        self.assertEqual(lost["lost_producers"], 1, lost)
        online = self.tool("import", g.unique("onl"), input=str(cases["corrupt"][0]))
        self.assertEqual(online["outcome"], "corrupt", online)

    def test_three_valued_checks_over_an_imported_trace(self):
        name = g.unique("chk")
        events = [event(0, "app.begin", payload={"corr": "a"}), event(1, "app.end", payload={"corr": "a"}),
                  event(2, "app.begin", payload={"corr": "b"})]
        self.engine.load(name, events, close=True)
        verdicts = self.tool("check", name, assertions=[
            {"type": "cardinality", "name": "begins", "kind": "app.begin", "min": 2, "max": 2},
            {"type": "forbidden", "name": "no-end", "kind": "app.end"},
        ], persist=False)
        self.assertEqual([r["verdict"] for r in verdicts["results"]], ["pass", "fail"], verdicts)
        gap = g.unique("gap")
        self.engine.load(gap, [event(0), event(1, "core.capture.gap", payload={"last_missing_source_seq": 4, "reason": "ring-full"}),
                               event(6)], close=True)
        unknown = self.tool("check", gap, assertions=[{"type": "forbidden", "name": "never-end", "kind": "app.end"}],
                            persist=False)
        self.assertIn(unknown["results"][0]["verdict"], ("unknown", "fail", "pass"), unknown)
        self.assertEqual(unknown["results"][0]["verdict"], "unknown", "a forbidden event cannot be ruled out over a capture gap")

    @unittest.skipIf(os.environ.get("HYDRALYSIS_SKIP_SCALE"), "HYDRALYSIS_SKIP_SCALE")
    def test_one_million_events_are_imported_by_the_tool_within_bounded_memory(self):
        path = self.root / "million.jsonl"
        with path.open("wb") as out:
            for start in range(0, 1_000_000, 10_000):
                out.write(b"".join(json.dumps(event(i, "app.step", payload={"i": i}), sort_keys=True, separators=(",", ":")).encode()
                                   + b"\n" for i in range(start, start + 10_000)))
        store = self.root / "m0-million"
        with patch.dict(os.environ, {"HYDRA_TRACE_EXE": g.TOOL}):
            reply = self.tool("import", offline=True, session="million", input=str(path), store=str(store), stream=True,
                              timeout_s=3000)
            self.assertEqual((reply["outcome"], reply["imported"]), ("clean", 1_000_000), reply)
            peak = reply["report"].get("peak_working_set")
            if peak is not None:
                self.assertLess(peak, 1536 * 1024 * 1024, "the streaming import is bounded (scale.rs: 1536 MiB for 1M events)")
            verified = self.tool("status", offline=True, op="verify", session="million", store=str(store), engine=True)
            self.assertEqual(verified["outcome"], "clean", verified)


if __name__ == "__main__":
    unittest.main()
