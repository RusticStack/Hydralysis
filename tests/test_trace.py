"""The `trace` tool: routing, bounded replies, start/stop, import, offline mode and evidence from a trace."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import workdir
from test_pe import image as make_image

from hydralysis import api, evidence, evidence_bundle, hydra, mcp, profiles, trace, trace_canon
from hydralysis.trace import TraceClient, TraceError


class FakeEngine:
    """Answers trace_* commands from a table and records every call."""

    def __init__(self, replies=None, capabilities=True):
        self.calls = []
        self.replies = replies or {}
        self._capabilities = {"trace": 1} if capabilities else {}

    def capabilities(self):
        return self._capabilities

    def call(self, command, raw=False, **fields):
        self.calls.append((command, fields))
        reply = self.replies.get(command, {})
        return reply(fields) if callable(reply) else dict(reply)

    def commands(self):
        return [command for command, _ in self.calls]


def run(action, session=None, options=None, engine=None, settings=None):
    engine = engine or FakeEngine()
    result = trace.handle_action(action, session, dict(options or {}), settings or {}, TraceClient(engine))
    return result, engine


def event(seq, kind="core.marker", source="s", **extra):
    return {"kind": kind, "source_id": source, "source_seq": seq, "producer_gen": 1, "clock_domain": "qpc",
            "t_mono_ns": 100 + seq, "confidence": "exact", **extra}


class Catalog(unittest.TestCase):
    def test_trace_is_the_21st_tool_with_a_small_schema(self):
        self.assertEqual(len(api.TOOL_NAMES), 21)
        table = {tool["name"]: tool for tool in api.tool_table()}
        schema = table["trace"]["inputSchema"]
        self.assertEqual(schema["required"], ["action"])
        self.assertEqual(tuple(schema["properties"]["action"]["enum"]), trace.ACTIONS)
        self.assertLess(len(json.dumps(schema)), 900)
        self.assertIn("from_trace", table["evidence_add"]["inputSchema"]["properties"])

    def test_lanes_the_long_actions_ride_the_long_lane(self):
        self.assertEqual(mcp.lane_of("trace", {"action": "query"}), "engine")
        self.assertEqual(mcp.lane_of("trace", {}), "engine")
        self.assertEqual(mcp.lane_of("trace", None), "engine")
        for action in ("export", "import", "resymbolize"):
            self.assertEqual(mcp.lane_of("trace", {"action": action}), "long")
        self.assertEqual(frozenset(mcp.LONG_TRACE_ACTIONS), trace.LONG_ACTIONS)
        self.assertEqual(mcp.lane_of("ghidra_run", {}), "long")
        self.assertEqual(mcp.lane_of("inspect", {}), "fast")

    def test_trace_reads_may_be_sent_again_after_a_lost_reply_and_writes_may_not(self):
        for command in trace.IDEMPOTENT_COMMANDS:
            self.assertTrue(hydra.idempotent(command), command)
        for command in ("trace_open", "trace_append", "trace_mark", "trace_export", "trace_close", "trace_resymbolize", "trace_reprocess",
                        "trace_relations", "trace_artifact", "trace_evict"):
            self.assertFalse(hydra.idempotent(command), command)

    def test_the_tool_rejects_a_missing_or_unknown_action(self):
        with self.assertRaises(ValueError):
            trace.call({}, {})
        with self.assertRaises(ValueError):
            trace.handle_action("explode", None, {}, {}, TraceClient(FakeEngine()))
        with self.assertRaises(ValueError):
            trace.call({"action": "status", "options": [1]}, {})

    def test_limitation_codes_are_shared_with_evidence(self):
        self.assertEqual(len(trace.LIMITATIONS), 16)
        for code in trace.LIMITATIONS:
            self.assertIn(trace.to_evidence_code(code), evidence.LIMITATIONS)
            evidence.check_limitation_code(trace.to_evidence_code(code))
        self.assertEqual(trace.to_evidence_code("producer-lost"), "producer_lost")
        with self.assertRaises(ValueError):
            trace.to_evidence_code("nonsense")


class Routing(unittest.TestCase):
    def test_not_available_without_the_capability(self):
        result, engine = run("query", "s1", engine=FakeEngine(capabilities=False))
        self.assertEqual(result["not_available"], "trace")
        self.assertEqual(engine.calls, [])

    def test_each_action_sends_its_command(self):
        cases = [
            ("query", "s1", {"kinds": ["core.resource.open"], "group_by": ["resource.key"], "limit": 5}, "trace_query"),
            ("diff", "s1", {"against": "s2", "group_by": ["kind"]}, "trace_diff"),
            ("explain", "s1", {"event_id": "ev_s1_7", "depth": 3}, "trace_explain"),
            ("mark", "s1", {"label": "after-login", "note": "n"}, "trace_mark"),
            ("export", "s1", {"out": "C:/x/out.jsonl"}, "trace_export"),
            ("check", "s1", {"assertions": [{"id": "a1"}]}, "trace_check"),
            ("resymbolize", "s1", {"program": "p"}, "trace_resymbolize"),
            ("status", "s1", {}, "trace_info"),
            ("status", None, {}, "trace_list"),
        ]
        for action, session, options, command in cases:
            _, engine = run(action, session, options)
            self.assertEqual(engine.commands(), [command], action)

    def test_fields_reach_the_engine_and_empty_ones_do_not(self):
        _, engine = run("query", "s1", {"kinds": ["core.state.write"], "up_to": 9, "limit": 7})
        command, fields = engine.calls[0]
        self.assertEqual(fields, {"session": "s1", "kinds": ["core.state.write"], "up_to": 9, "limit": 7})
        _, engine = run("diff", "s1", {"against": "s2", "align": {"keys": ["phase"]}})
        self.assertEqual((engine.calls[0][1]["a"], engine.calls[0][1]["b"]), ("s1", "s2"))
        self.assertEqual(engine.calls[0][1]["align"], {"keys": ["phase"]})

    def test_bad_arguments_are_refused_before_the_engine_is_asked(self):
        bad = [("query", None, {}), ("query", "bad id!", {}), ("query", "s1", {"limit": 0}), ("query", "s1", {"limit": 999}),
               ("query", "s1", {"kinds": "core.marker"}), ("explain", "s1", {}), ("explain", "s1", {"event_id": "x y"}),
               ("explain", "s1", {"event_id": "ev_1", "depth": 99}), ("mark", "s1", {}), ("mark", "s1", {"label": " "}),
               ("diff", "s1", {}), ("check", "s1", {"assertions": "all"})]
        for action, session, options in bad:
            engine = FakeEngine()
            with self.assertRaises(ValueError, msg=(action, options)):
                run(action, session, options, engine=engine)
            self.assertEqual(engine.calls, [], (action, options))

    def test_an_engine_refusal_is_answered_as_data(self):
        class Refusing(FakeEngine):
            def call(self, command, raw=False, **fields):
                raise hydra.EngineError("not_owner", "only the owner may mark", {"owner": "x"}, command)

        engine = Refusing()
        with patch.object(trace, "_engine", return_value=engine):
            text = trace.call({"action": "mark", "session": "s1", "options": {"label": "a"}}, {})
        answer = json.loads(text)
        self.assertEqual(answer["error"], "not_owner")
        self.assertEqual(answer["command"], "trace_mark")

    def test_the_mark_carries_the_owner_the_session_was_opened_with(self):
        engine = FakeEngine({"trace_open": {"session": "s9", "lease": {"cap": "tok"}}})
        run("start", "s9", {}, engine=engine)
        engine.calls.clear()
        run("mark", "s9", {"label": "x"}, engine=engine)
        self.assertEqual(engine.calls[0][1]["cap"], "tok")
        trace._TOKENS.pop("s9", None)


class Bounds(unittest.TestCase):
    def test_lists_are_cut_counted_and_cited(self):
        groups = [{"key": "k%d" % i, "count": i, "representative": "ev_s1_%d" % i} for i in range(80)]
        engine = FakeEngine({"trace_query": {"groups": groups, "revision": 12, "total_events": 5000,
                                             "coverage": {"revision": 12, "gaps": [{"reason": "ring-overflow", "dropped": 3}]}}})
        result, _ = run("query", "s1", {"limit": 10}, engine=engine)
        self.assertEqual(len(result["groups"]), 10)
        self.assertEqual(result["bounds"]["truncated"]["groups"], 70)
        self.assertFalse(result["bounds"]["complete"])
        self.assertEqual(result["revision"], 12)
        self.assertEqual(result["total_events"], 5000)
        self.assertEqual(result["coverage"]["revision"], 12)
        self.assertEqual(result["coverage"]["gaps"][0]["reason"], "ring-overflow")
        self.assertTrue(result["coverage"]["reported"])
        self.assertEqual([c["event_id"] for c in result["citations"]], ["ev_s1_%d" % i for i in range(10)])
        self.assertEqual(result["citations"][0], {"session": "s1", "event_id": "ev_s1_0", "revision": 12})

    def test_a_reply_without_coverage_says_so(self):
        result, _ = run("query", "s1", engine=FakeEngine({"trace_query": {"groups": [], "revision": 3}}))
        self.assertFalse(result["coverage"]["reported"])
        self.assertIn("absence of events", result["coverage"]["note"])

    def test_a_huge_reply_is_halved_until_it_fits(self):
        events = [{"event_id": "ev_s1_%d" % i, "text": "x" * 900} for i in range(200)]
        result, _ = run("query", "s1", {"limit": 200}, engine=FakeEngine({"trace_query": {"events": events, "revision": 1}}))
        self.assertLessEqual(len(json.dumps(result, separators=(",", ":"))), trace.MAX_REPLY_BYTES + 2048)
        self.assertGreater(result["bounds"]["truncated"]["events"], 0)
        self.assertGreaterEqual(len(result["events"]), 1)

    def test_citations_are_capped(self):
        events = [{"event_id": "ev_s1_%d" % i} for i in range(200)]
        result, _ = run("query", "s1", {"limit": 200}, engine=FakeEngine({"trace_query": {"events": events, "revision": 1}}))
        self.assertEqual(len(result["citations"]), trace.MAX_CITATIONS)
        self.assertEqual(result["bounds"]["truncated"]["citations"], 200 - trace.MAX_CITATIONS)

    def test_the_reply_is_deterministic(self):
        reply = {"groups": [{"key": "a", "event_id": "ev_s1_1"}], "revision": 4, "coverage": {"revision": 4, "gaps": []}}
        first, _ = run("query", "s1", engine=FakeEngine({"trace_query": reply}))
        second, _ = run("query", "s1", engine=FakeEngine({"trace_query": reply}))
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))


class StartAndStop(unittest.TestCase):
    def setUp(self):
        self.addCleanup(trace._LINKS.clear)
        self.addCleanup(trace._TOKENS.clear)

    def images(self, exports=None, text=b"\x55\x8b\xec\x83\xec\x10" + b"\x90" * 26):
        img = make_image(text)
        img.export_rva = lambda symbol: (exports or {}).get(symbol)
        return img

    def profile_file(self, folder, sha, prologue="55 8B EC 83 EC 10", required=True):
        path = Path(folder) / "p.toml"
        path.write_text(f"""
[profile]
id = "t/1"
[target]
bitness = 32
modules = ["main.exe"]
[[target.builds]]
module = "main.exe"
image_sha256 = "{sha}"
[[hooks]]
id = "gate"
event = "core.marker"
symbol = "Gate"
required = {"true" if required else "false"}
prologue = "{prologue}"
""", "utf-8")
        return path

    def test_a_tampered_required_hook_refuses_the_session_before_anything_opens(self):
        img = self.images({"Gate": 0x1000})
        with workdir("trace-start") as folder:
            path = self.profile_file(folder, img.fingerprint()["sha256"], prologue="55 8B EC 83 EC 11")
            engine = FakeEngine()
            with patch("hydralysis.pe.Image", return_value=img):
                with patch.object(trace, "_engine", return_value=engine):
                    answer = json.loads(trace.call({"action": "start", "options": {"profile": str(path), "images": {"main.exe": "x.exe"}}}, {}))
        self.assertEqual(answer["error"], "required_hook_refused")
        self.assertEqual(answer["refusals"][0]["hook"], "gate")
        self.assertEqual(engine.calls, [])

    def test_an_optional_refusal_opens_the_session_with_the_limitation_recorded(self):
        img = self.images({"Gate": 0x1000})
        with workdir("trace-start") as folder:
            path = self.profile_file(folder, img.fingerprint()["sha256"], prologue="55 8B EC 83 EC 11", required=False)
            engine = FakeEngine({"trace_open": {"session": "s1", "lease": {"cap": "t"}}})
            with patch("hydralysis.pe.Image", return_value=img):
                result, _ = run("start", "s1", {"profile": str(path), "images": {"main.exe": "x.exe"}}, engine=engine)
        command, fields = engine.calls[0]
        self.assertEqual(command, "trace_open")
        self.assertEqual((fields["create"], fields["mode"]), (True, "write"))
        self.assertNotIn("profile", fields)
        self.assertEqual(result["limitations"][0]["code"], "optional-hook-refused")
        self.assertEqual(result["profile"]["enabled"], [])
        self.assertEqual(result["profile"]["profile"], "t/1")
        self.assertEqual(len(result["profile"]["profile_sha256"]), 64)
        self.assertEqual(result["profile"]["counts"]["refused_optional"], 1)

    def test_a_build_bound_profile_needs_its_images(self):
        with workdir("trace-start") as folder:
            path = self.profile_file(folder, "0" * 64)
            answer = json.loads(self.call_tool({"action": "start", "options": {"profile": str(path)}}, FakeEngine()))
        self.assertEqual(answer["error"], "images_required")

    def call_tool(self, args, engine):
        with patch.object(trace, "_engine", return_value=engine):
            return trace.call(args, {})

    def test_scope_expansion_needs_the_owner_token(self):
        answer = json.loads(self.call_tool({"action": "start", "options": {"scope": {"add": ["svc"]}}}, FakeEngine()))
        self.assertEqual(answer["error"], "scope_expansion_needs_owner")

    def test_start_delegates_the_target_to_runtime_and_stop_undoes_it(self):
        calls = []

        class Runner:
            def __init__(self, settings):
                pass

            def call(self, action, args=None):
                calls.append((action, dict(args or {})))
                return {"session": "r" * 32} if action in ("spawn", "attach") else {"ok": True, "action": action}

        engine = FakeEngine({"trace_open": {"session": "s1", "lease": {"cap": "tok"}}, "trace_close": {"closed": True, "revision": 77}})
        with patch("hydralysis.runtime.RuntimeRunner", Runner):
            started, _ = run("start", "s1", {"launch": {"action": "spawn", "path": "C:/x/app.exe"}}, engine=engine)
            self.assertEqual(started["runtime"]["session"], "r" * 32)
            self.assertEqual([c[0] for c in calls], ["spawn", "capture"])
            self.assertEqual(calls[0][1], {"path": "C:/x/app.exe"})
            self.assertEqual(calls[1][1]["op"], "start")
            self.assertEqual(calls[1][1]["trace"]["session"], "s1")
            self.assertEqual(calls[1][1]["trace"]["owner"], "tok")
            stopped, _ = run("stop", "s1", {}, engine=engine)
        self.assertEqual([c[0] for c in calls], ["spawn", "capture", "capture", "detach"])
        self.assertEqual(calls[2][1], {"op": "stop", "session": "r" * 32, "owner": "tok"})
        self.assertEqual(engine.commands(), ["trace_open", "trace_close"])
        self.assertEqual(engine.calls[1][1]["cap"], "tok")
        self.assertEqual(stopped["closed"]["revision"], 77)
        self.assertNotIn("s1", trace._LINKS)

    def test_a_failed_launch_closes_the_session_it_opened(self):
        class Runner:
            def __init__(self, settings):
                pass

            def call(self, action, args=None):
                raise RuntimeError("no such file")

        engine = FakeEngine({"trace_open": {"session": "s1", "lease": {"cap": "tok"}}})
        with patch("hydralysis.runtime.RuntimeRunner", Runner):
            with self.assertRaises(RuntimeError):
                run("start", "s1", {"launch": {"path": "nope"}}, engine=engine)
        self.assertEqual(engine.commands(), ["trace_open", "trace_close"])
        self.assertEqual(engine.calls[1][1]["cap"], "tok")

    def test_status_includes_the_runtime_session_it_is_linked_to(self):
        trace._LINKS["s1"] = "r" * 32

        class Runner:
            def __init__(self, settings):
                pass

            def call(self, action, args=None):
                return {"state": "running", "args": args}

        with patch("hydralysis.runtime.RuntimeRunner", Runner):
            result, _ = run("status", "s1", engine=FakeEngine({"trace_info": {"revision": 5, "events": 10}}))
        self.assertEqual(result["runtime"]["state"], "running")
        self.assertEqual(result["events"], 10)


class Importing(unittest.TestCase):
    def write(self, folder, events, tail=b"", name="in.jsonl"):
        path = Path(folder) / name
        path.write_bytes(b"".join(json.dumps(e).encode() + b"\n" for e in events) + tail)
        return path

    def test_the_outcomes_of_a_file_stay_distinct(self):
        with workdir("trace-in") as folder:
            events = [event(i) for i in range(3)]
            self.assertEqual(trace.read_jsonl(self.write(folder, events))["outcome"], "clean")
            empty = Path(folder) / "empty.jsonl"
            empty.write_bytes(b"\n  \n")
            self.assertEqual(trace.read_jsonl(empty)["outcome"], "empty")
            self.assertEqual(trace.read_jsonl(Path(folder) / "nope.jsonl")["outcome"], "missing")
            torn = trace.read_jsonl(self.write(folder, events, tail=b'{"kind":"core.mar', name="torn.jsonl"))
            self.assertEqual((torn["outcome"], len(torn["events"]), torn["damage"]["line"]), ("torn_tail", 3, 4))
            middle = self.write(folder, events[:1] + [{"kind": "bogus"}] + events[1:], name="mid.jsonl")
            corrupt = trace.read_jsonl(middle)
            self.assertEqual((corrupt["outcome"], len(corrupt["events"]), corrupt["damage"]["line"]), ("corrupt", 1, 2))
            garbage = Path(folder) / "g.jsonl"
            garbage.write_bytes(b"not json\n" + json.dumps(events[0]).encode() + b"\n")
            self.assertEqual(trace.read_jsonl(garbage)["outcome"], "corrupt")
            floaty = self.write(folder, [{**events[0], "payload": {"ratio": 0.5}}], name="f.jsonl")
            self.assertEqual(trace.read_jsonl(floaty)["outcome"], "corrupt")

    def test_a_missing_producer_range_is_counted_unless_a_gap_explains_it(self):
        with workdir("trace-in") as folder:
            lost = [event(0), event(1), event(5)]
            self.assertEqual(trace.read_jsonl(self.write(folder, lost))["lost_producers"], 1)
            explained = [event(0), event(1), event(2, "core.capture.gap", payload={"reason": "ring-overflow", "dropped": 2,
                         "first_missing_source_seq": 3, "last_missing_source_seq": 4}), event(5)]
            self.assertEqual(trace.read_jsonl(self.write(folder, explained, name="e.jsonl"))["lost_producers"], 0)

    def test_online_import_opens_appends_in_batches_and_closes(self):
        with workdir("trace-in") as folder:
            path = self.write(folder, [event(i) for i in range(1200)])
            engine = FakeEngine({"trace_open": {"session": "imp1", "lease": {"cap": "o"}}, "trace_append": {"appended": 500}})
            result, _ = run("import", None, {"input": str(path)}, engine=engine)
        self.assertEqual(engine.commands(), ["trace_open"] + ["trace_append"] * 3 + ["trace_close"])
        self.assertEqual([len(f["events"]) for c, f in engine.calls if c == "trace_append"], [500, 500, 200])
        self.assertEqual(result["imported"], 1200)
        self.assertEqual((engine.calls[0][1]["create"], engine.calls[0][1]["mode"]), (True, "write"))
        self.assertTrue(all(f["cap"] == "o" for c, f in engine.calls if c != "trace_open"))

    def test_a_damaged_file_imports_its_valid_prefix_and_says_where_it_stopped(self):
        with workdir("trace-in") as folder:
            path = self.write(folder, [event(0), event(1)], tail=b"{broken", name="d.jsonl")
            engine = FakeEngine({"trace_open": {"session": "imp1"}})
            result, _ = run("import", None, {"input": str(path)}, engine=engine)
        self.assertEqual(result["imported"], 2)
        self.assertEqual(result["outcome"], "torn_tail")

    def test_an_empty_file_opens_no_session(self):
        with workdir("trace-in") as folder:
            path = Path(folder) / "e.jsonl"
            path.write_bytes(b"")
            result, engine = run("import", None, {"input": str(path)})
        self.assertEqual((result["imported"], result["outcome"], engine.calls), (0, "empty", []))


class Offline(unittest.TestCase):
    def test_import_hands_the_valid_prefix_to_the_tool_and_needs_it(self):
        calls = []

        class Done:
            returncode = 0
            stdout = b'{"accepted":4,"dropped_budget":0,"recovered_batches":0,"rejected":0}\n'
            stderr = b""

        def fake(command, **kw):
            calls.append((command, Path(command[4]).read_bytes()))
            return Done()

        with workdir("trace-off") as folder:
            source = Path(folder) / "in.jsonl"
            source.write_bytes(b"".join(json.dumps(event(i)).encode() + b"\n" for i in range(4)) + b"{torn")
            exe = Path(folder) / "hydra-trace.exe"
            exe.write_bytes(b"")
            options = {"offline": True, "session": "off1", "input": str(source), "store": str(Path(folder) / "store")}
            with patch.dict("os.environ", {"HYDRA_TRACE_EXE": ""}):
                with self.assertRaises(TraceError) as caught:
                    run("import", None, options)
            self.assertEqual(caught.exception.code, "tool_missing")
            with patch.dict("os.environ", {"HYDRA_TRACE_EXE": str(exe)}):
                with patch("hydralysis.proc.run", side_effect=fake):
                    result, engine = run("import", None, options)
        self.assertEqual(engine.calls, [])
        self.assertEqual((calls[0][0][1], calls[0][0][3]), ("import", "off1"))
        self.assertEqual(len(calls[0][1].splitlines()), 4)
        self.assertEqual((result["imported"], result["outcome"], result["report"]["accepted"]), (4, "torn_tail", 4))

    def test_verify_keeps_torn_corrupt_and_chain_break_apart(self):
        with workdir("trace-off") as folder:
            session = Path(folder) / "store" / "v1" / "segments"
            session.mkdir(parents=True)
            def segment(name):
                chain = trace_canon.Chain(name)
                return b"".join(chain.push(event(i)) for i in range(3))

            good = segment("good")
            (session / "good.trace").write_bytes(good)
            (session / "torn.trace").write_bytes(segment("torn") + b"abcd")
            flipped = bytearray(segment("bad"))
            flipped[20] ^= 1
            (session / "bad.trace").write_bytes(bytes(flipped))
            (session / "wrong.trace").write_bytes(good)  # its genesis was derived from another id
            outcomes = {row["segment"]: row["outcome"] for row in trace.offline_verify(session)["segments"]}
        self.assertEqual(outcomes, {"bad": "corrupt", "good": "clean", "torn": "torn_tail", "wrong": "chain_break"})

    def test_the_tool_verbs_need_the_engine_install(self):
        with patch.dict("os.environ", {"HYDRA_TRACE_EXE": ""}):
            with self.assertRaises(TraceError) as caught:
                run("export", "s1", {"offline": True, "op": "export", "session": "s1", "output": "o.jsonl"})
        self.assertEqual(caught.exception.code, "tool_missing")

    def test_a_tool_found_is_run_with_the_documented_arguments(self):
        calls = []

        class Done:
            returncode = 0
            stdout = b"ok"
            stderr = b""

        with workdir("trace-off") as folder:
            exe = Path(folder) / "hydra-trace.exe"
            exe.write_bytes(b"")
            with patch.dict("os.environ", {"HYDRA_TRACE_EXE": str(exe)}):
                with patch("hydralysis.proc.run", side_effect=lambda cmd, **kw: calls.append(cmd) or Done()):
                    result, _ = run("export", "s1", {"offline": True, "op": "export", "session": "s1", "output": "o.jsonl", "store": "S"})
        self.assertEqual(calls[0][1:], ["export", "S", "s1", "o.jsonl"])
        self.assertTrue(result["ok"])


class EvidenceFromTrace(unittest.TestCase):
    def add(self, path, **extra):
        return evidence.add_claim(path, game="fx", build="b1", kind="behavior", name="opens-config", note="seen",
                                  source="trace s1 events", **extra)

    def test_a_trace_claim_cites_session_events_and_revision(self):
        with workdir("trace-ev") as folder:
            db = Path(folder) / "e.db"
            cite = trace.citation("s1", ["ev_s1_9", "ev_s1_3", "ev_s1_3"], 42, 2)
            self.assertEqual(cite, {"session": "s1", "events": ["ev_s1_3", "ev_s1_9"], "revision": 42, "interpretation": 2})
            plain = self.add(db)
            traced = self.add(db, from_trace=cite)
            rows = evidence.query(db, "fx", limit=10)
            by_trace = {bool(r["from_trace"]): r for r in rows}
            self.assertNotEqual(by_trace[True]["evidence_id"], by_trace[False]["evidence_id"])
            self.assertEqual(by_trace[True]["from_trace"], cite)
            self.assertIsNone(by_trace[False]["from_trace"])
            self.assertIn("evidence_id=", traced)
            self.assertEqual(evidence.verify_ledger(db), {"checked": 2, "failed": []})
            # restating the same citation is a no-op; a different revision is a different claim
            self.assertIn("already stored", self.add(db, from_trace=cite))
            self.assertNotIn("already stored", self.add(db, from_trace={**cite, "revision": 43}))
            self.assertIn("already stored", self.add(db))

    def test_a_claim_without_a_trace_keeps_the_id_it_always_had(self):
        content = evidence.build_content(game="fx", build="b1", kind="k", name="n", note="n", source="s")
        self.assertNotIn("from_trace", content)
        self.assertEqual(set(content), set(evidence.CONTENT_KEYS))

    def test_bad_citations_are_refused(self):
        for bad in ({}, {"session": "s1"}, {"session": "s1", "events": [], "revision": 1}, {"session": "s 1", "events": ["a"], "revision": 1},
                    {"session": "s1", "events": ["a"], "revision": -1}, {"session": "s1", "events": ["a"], "revision": True},
                    {"session": "s1", "events": ["a" * 200], "revision": 1}, {"session": "s1", "events": ["a"] * 65 + ["b"], "revision": 1},
                    {"session": "s1", "events": ["a"], "revision": 1, "extra": 1}):
            with self.assertRaises(ValueError, msg=bad):
                evidence.check_from_trace(bad)

    def test_the_tool_stores_a_claim_with_from_trace(self):
        with workdir("trace-ev") as folder:
            db = str(Path(folder) / "e.db")
            text = api.call("evidence_add", {"target": "fx", "build": "b1", "kind": "behavior", "name": "n", "note": "n",
                                             "source": "trace s1", "db": db, "from_trace": {"session": "s1", "events": ["ev_1"], "revision": 3}})
            self.assertIn("stored", text)
            listed = evidence.query(Path(db), "fx")
            self.assertEqual(listed[0]["from_trace"]["revision"], 3)


class BundleWithTraces(unittest.TestCase):
    def ledger(self, folder):
        db = Path(folder) / "e.db"
        evidence.add_claim(db, game="fx", build="b1", kind="behavior", name="opens", note="n", source="trace s1",
                           from_trace=trace.citation("s1", ["ev_1", "ev_2"], 5))
        evidence.add_claim(db, game="fx", build="b1", kind="behavior", name="plain", note="n", source="static")
        return db

    def test_a_cited_session_without_a_pin_lists_what_cannot_be_reproduced(self):
        with workdir("trace-bundle") as folder:
            db, out = self.ledger(folder), Path(folder) / "b"
            result = evidence_bundle.export_bundle(db, out, game="fx")
            self.assertEqual(result["unreproducible_traces"], ["s1"])
            pin = json.loads((out / "traces" / "s1.json").read_text("utf-8"))
            self.assertFalse(pin["reproducible"])
            self.assertEqual(pin["cannot_reproduce"][0]["reason"], "pin-not-supplied")
            verdict = evidence_bundle.verify_bundle(out)
            self.assertTrue(verdict["ok"], verdict)
            self.assertEqual(verdict["unreproducible_traces"], ["s1"])
            replay = json.loads((out / "replay.json").read_text("utf-8"))
            self.assertIn("s1", replay["unreproducible_traces"])

    def test_a_pin_makes_it_reproducible_and_changes_the_bundle_id(self):
        with workdir("trace-bundle") as folder:
            db = self.ledger(folder)
            stub = evidence_bundle.export_bundle(db, Path(folder) / "b1", game="fx")
            pins = Path(folder) / "pins"
            pins.mkdir()
            pin = trace.pin_for("s1", 5, ["ev_1", "ev_2", "ev_3"], artifacts=[{"id": "a1", "sha256": "ab" * 32, "range": [0, 64]}])
            (pins / "s1.json").write_text(json.dumps(pin), "utf-8")
            pinned = evidence_bundle.export_bundle(db, Path(folder) / "b2", game="fx", traces_dir=pins)
            self.assertNotEqual(stub["bundle_id"], pinned["bundle_id"])
            self.assertEqual(pinned["unreproducible_traces"], [])
            verdict = evidence_bundle.verify_bundle(Path(folder) / "b2")
            self.assertTrue(verdict["ok"], verdict)
            again = evidence_bundle.export_bundle(db, Path(folder) / "b3", game="fx", traces_dir=pins)
            self.assertEqual(again["bundle_id"], pinned["bundle_id"])
            compared = evidence_bundle.compare_bundles(Path(folder) / "b1", Path(folder) / "b2")
            self.assertTrue(any(c["entity"] == "trace" and c["key"] == "s1" for c in compared["changes"]))

    def test_unauthorized_artifacts_are_never_pinned(self):
        pin = trace.pin_for("s1", 5, ["ev_1"], unauthorized=[{"id": "a9", "range": [0, 8]}])
        self.assertFalse(pin["reproducible"])
        self.assertEqual(pin["artifacts"], [])
        self.assertEqual(pin["cannot_reproduce"][0]["reason"], "payload-not-authorized")
        bad = {**pin, "artifacts": [{"id": "a", "sha256": "0" * 64, "range": [0, 1], "authorized": False}]}
        with self.assertRaises(evidence_bundle.BundleError):
            evidence_bundle.check_pin(bad, "s1")
        with self.assertRaises(evidence_bundle.BundleError):
            evidence_bundle.check_pin({**pin, "artifacts": [{"id": "a", "sha256": "0" * 64, "range": [0, 1], "authorized": True, "data": "AA"}]}, "s1")

    def test_tampering_with_a_trace_member_or_its_pin_is_refused(self):
        with workdir("trace-bundle") as folder:
            db, out = self.ledger(folder), Path(folder) / "b"
            pins = Path(folder) / "pins"
            pins.mkdir()
            (pins / "s1.json").write_text(json.dumps(trace.pin_for("s1", 5, ["ev_1", "ev_2"])), "utf-8")
            evidence_bundle.export_bundle(db, out, game="fx", traces_dir=pins)
            member = out / "traces" / "s1.json"
            original = member.read_bytes()
            member.write_bytes(original.replace(b'"revision":5', b'"revision":9'))
            self.assertEqual(evidence_bundle.verify_bundle(out)["error"], "bundle_file_changed")
            member.write_bytes(original)
            self.assertTrue(evidence_bundle.verify_bundle(out)["ok"])
            member.unlink()
            self.assertNotEqual(evidence_bundle.verify_bundle(out).get("ok"), True)

    def test_a_pin_that_does_not_cover_the_cited_events_is_refused_at_export_or_verify(self):
        with workdir("trace-bundle") as folder:
            db, out = self.ledger(folder), Path(folder) / "b"
            pins = Path(folder) / "pins"
            pins.mkdir()
            (pins / "s1.json").write_text(json.dumps(trace.pin_for("s1", 5, ["ev_1"])), "utf-8")  # ev_2 is missing
            evidence_bundle.export_bundle(db, out, game="fx", traces_dir=pins)
            self.assertEqual(evidence_bundle.verify_bundle(out)["error"], "trace_pin_invalid")

    def test_a_bundle_without_trace_claims_is_byte_identical_in_shape(self):
        with workdir("trace-bundle") as folder:
            db = Path(folder) / "e.db"
            evidence.add_claim(db, game="fx", build="b1", kind="k", name="n", note="n", source="s")
            result = evidence_bundle.export_bundle(db, Path(folder) / "b", game="fx")
            self.assertNotIn("traces", result)
            self.assertFalse((Path(folder) / "b" / "traces").exists())
            self.assertNotIn("unreproducible_traces", json.loads((Path(folder) / "b" / "replay.json").read_text("utf-8")))


if __name__ == "__main__":
    unittest.main()
