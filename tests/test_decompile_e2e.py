"""Decompile through Hydralysis against the engine's real reply shapes (PROTOCOL-3 8.21): the fallback, the job, paging, budgets.

Fake engine replies only; the shapes are the ones in the engine document and the real-target runs.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from hydralysis import analysis, cli, decompile_job, decompile_result as dr, query
from hydralysis.backends import read_json, write_json

NO_PCODE = "No pcode could be generated at 0x143020480"
BUDGET_AUTO = {"mode": "auto", "bytes": 268435456, "mb": 256, "in_flight": 1, "free_physical_mb": 20480, "free_heap_mb": 3072,
               "floor_physical_mb": 4096}
OVERFLOW = {"name": "f", "entry": "0x140076fe0", "completed": False,
            "error": "Exception while decompiling 140076fe0: Response buffer size exceeded",
            "timedOut": False, "truncated": True, "bytes_emitted": 268435456, "reason": "response_buffer", "max_result_mb": 256,
            "max_result_bytes": 268435456, "budget": BUDGET_AUTO, "partial": True, "c": "int f(void)\n{\n  int a;", "chars": 120,
            "signature": "int f(void);",
            "cut": {"kind": "response_buffer", "response_bytes_read": 268435456, "c_recovered": True, "c_chars": 120, "c_lines": 3,
                    "c_tokens": 30, "c_returned_chars": 21, "what": "everything after the text is missing"}}
CEILING = {**OVERFLOW, "budget": {"mode": "ceiling", "bytes": 1024, "mb": 1, "in_flight": 1}}
PIECES = {"name": "FUN_141f6f9b0", "entry": "0x141f6f9b0", "completed": True,
          "signature": "undefined8 FUN_141f6f9b0(longlong *param_1);",
          "chars": 240815, "truncated": False, "partial": True, "reason": "non_contiguous_body", "c": "/* fragment */\nvoid f(){}",
          "fragments": [{"start": "0x141f6f9b0", "end": "0x141f702c5", "class": "code", "decompiled": True, "chars": 900},
                        {"start": "0x143020450", "end": "0x14302047f", "class": "data", "decompiled": False}]}
PAGE = {"name": "f", "entry": "0x1", "completed": True, "c": "page", "offset": 0, "chars": 9000, "next_offset": 4, "truncated": False}
REQUEST = {"action": "decompile", "address": "0x141f6f9b0", "options": {"max_characters": 1000}}
FAILED = {"ok": False, "error": NO_PCODE}


class Engine:
    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.calls = reply, error, []

    def call(self, command, **fields):
        self.calls.append((command, fields))
        if self.error:
            raise self.error
        return self.reply


class Options(unittest.TestCase):
    def test_ranges_match_the_engine(self):
        for good in ({"max_result_mb": 1}, {"max_result_mb": 1024}, {"max_result_kb": 1}, {"max_result_kb": 1048576},
                     {"offset": 0}, {"offset": 5000}):
            self.assertEqual(analysis.validate_options("decompile", good)[next(iter(good))], next(iter(good.values())))
        for bad in ({"max_result_mb": 0}, {"max_result_mb": 1025}, {"max_result_kb": 0}, {"max_result_kb": 1048577},
                    {"offset": -1}, {"offset": "3"}, {"max_result_kb": True}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                analysis.validate_options("decompile", bad)
        self.assertEqual(analysis.validate_options("decompile", {}), {"max_characters": 32000})   # omitted = the engine's auto budget

    def test_cli_passes_kb_and_offset(self):
        with patch("hydralysis.cli.call", return_value="{}") as dispatch, redirect_stdout(io.StringIO()):
            cli.main(["ghidra-query", "--target", "t", "0x1", "--max-result-kb", "64", "--offset", "100"])
        self.assertEqual(dispatch.call_args.args[1]["options"], {"max_result_kb": 64, "offset": 100})


class Replies(unittest.TestCase):
    def test_overflow_with_the_front_of_the_text_is_a_partial_result(self):
        reply = query.accepted("decompile", dr.merge({"id": "x", "ok": True, "c": "script text"}, OVERFLOW))
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["c"], OVERFLOW["c"])
        self.assertEqual(reply["decompile"]["cut"]["c_chars"], 120)
        self.assertEqual(reply["decompile"]["budget"]["mode"], "auto")
        self.assertEqual(reply["budget"], BUDGET_AUTO)

    def test_budget_limited_is_told_apart_from_truncated(self):
        auto = query.accepted("decompile", dr.merge({"id": "x", "ok": False, "error": "e"}, OVERFLOW))
        ceiling = query.accepted("decompile", dr.merge({"id": "x", "ok": False, "error": "e"}, CEILING))
        self.assertEqual(dr.coverage(auto), {"status": "partial", "limitations": [dr.LIMIT_BUDGET]})
        self.assertEqual(dr.coverage(ceiling), {"status": "partial", "limitations": [dr.LIMIT_TRUNCATED]})

    def test_a_page_carries_offset_and_next_offset(self):
        merged = dr.merge({"id": "x", "ok": True, "c": "whole clipped", "truncated": True}, PAGE)
        self.assertEqual((merged["c"], merged["offset"], merged["next_offset"], merged["total_characters"]), ("page", 0, 4, 9000))
        self.assertFalse(merged["truncated"])
        reply = query.accepted("decompile", merged)
        self.assertEqual(reply["decompile"]["next_offset"], 4)
        self.assertEqual(dr.coverage(reply), {"status": "partial", "limitations": [dr.LIMIT_PAGED]})
        last = dr.merge({"id": "x", "ok": True, "c": "a"}, {k: v for k, v in PAGE.items() if k != "next_offset"} | {"offset": 4})
        self.assertNotIn("next_offset", dr.summarize(last))


class Fallback(unittest.TestCase):
    def test_a_script_failure_is_deferred_to_a_job_unless_inline(self):
        engine = Engine(PIECES)
        with self.assertRaises(query.DeferDecompile) as caught:
            query.engine_decompile(engine, {"key": "k"}, REQUEST, 30, dict(FAILED))
        self.assertIn("No pcode", caught.exception.reason)
        self.assertEqual(engine.calls, [])

    def test_inline_the_engine_command_runs_with_a_long_timeout_and_is_labelled(self):
        engine = Engine(PIECES)
        merged = query.engine_decompile(engine, {"key": "k"}, REQUEST, 30, dict(FAILED), inline=True)
        command, fields = engine.calls[0]
        self.assertEqual((command, fields["timeout"], fields["maxChars"]), ("decompile", query.FALLBACK_TIMEOUT_S, 1000))
        self.assertNotIn("maxResultMb", fields)   # omitted: the engine's adaptive budget
        self.assertTrue(merged["ok"])
        self.assertEqual(merged["fallback"]["via"], "engine_decompile")
        self.assertIn("No pcode", merged["fallback"]["reason"])
        self.assertEqual(merged["reason"], "non_contiguous_body")
        self.assertEqual(len(merged["fragments"]), 2)

    def test_explicit_options_reach_the_engine_and_a_slow_answer_defers(self):
        request = {**REQUEST, "options": {"max_characters": 10, "max_result_kb": 7, "max_result_mb": 3, "offset": 20}}
        engine = Engine(PAGE)
        query.engine_decompile(engine, {"key": "k"}, request, 30, {"ok": True, "c": "t"})
        fields = engine.calls[0][1]
        self.assertEqual((fields["maxResultKb"], fields["maxResultMb"], fields["offset"], fields["timeout"]), (7, 3, 20, 35))
        slow = Engine(error=query.hydra.EngineError("timeout", "decompile timed out"))
        with self.assertRaises(query.DeferDecompile):
            query.engine_decompile(slow, {"key": "k"}, request, 30, {"ok": True, "c": "t"})
        kept = query.engine_decompile(slow, {"key": "k"}, request, 30, {"ok": True, "c": "t"}, inline=True)
        self.assertEqual(kept, {"ok": True, "c": "t"})

    def test_scripted_turns_a_script_exception_into_the_fallback(self):
        runner = query.QueryRunner.__new__(query.QueryRunner)
        runner.requests, runner.inline = None, False
        with patch.object(query, "run_script", side_effect=RuntimeError("RusticQuery returned no complete answer (truncated=True)")):
            with self.assertRaises(query.DeferDecompile):
                runner._scripted(Engine(PIECES), {"key": "k"}, REQUEST, 30)
            runner.inline = True
            answer, raw = runner._scripted(Engine(PIECES), {"key": "k"}, REQUEST, 30)
        self.assertEqual((answer["fallback"]["via"], raw), ("engine_decompile", {}))
        # a non-decompile query keeps the script's own error
        with patch.object(query, "run_script", side_effect=RuntimeError("boom")), self.assertRaises(RuntimeError):
            runner._scripted(Engine(PIECES), {"key": "k"}, {"action": "xrefs", "address": "0x1"}, 30)

    def test_inline_with_no_engine_answer_raises_the_script_error(self):
        runner = query.QueryRunner.__new__(query.QueryRunner)
        runner.requests, runner.inline = None, True
        with patch.object(query, "run_script", side_effect=RuntimeError("script died")):
            with self.assertRaises(RuntimeError) as caught:
                runner._scripted(Engine({"completed": False, "truncated": False}), {"key": "k"}, REQUEST, 30)
        self.assertIn("script died", str(caught.exception))


class Job(unittest.TestCase):
    def record(self, root: Path) -> Path:
        path = decompile_job.job_path({"root": str(root)}, "decompile-0123456789ab")
        path.parent.mkdir(parents=True)
        write_json(path, {"id": "decompile-0123456789ab", "kind": "decompile", "state": "queued", "target": "t",
                          "created_at": 1e12, "updated_at": 1e12,
                          "call": {"target": "t", "action": "decompile", "address": "0x1", "options": {}},
                          "call_key": {}, "fallback_reason": NO_PCODE, "settings": {"root": str(root)},
                          "result_path": str(path.parent / "result.json"), "log_path": str(path.parent / "worker.log")})
        return path

    def test_the_worker_runs_the_query_inline_and_stores_the_labelled_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.record(Path(tmp))
            seen = {}

            class Runner:
                def __init__(self, settings):
                    seen["settings"] = settings

                def query(self, **call):
                    seen["inline"], seen["call"] = self.inline, call
                    return json.dumps({"ok": True, "c": "x", "fallback": {"via": "engine_decompile", "reason": NO_PCODE}})

            with patch("hydralysis.query.QueryRunner", Runner):
                self.assertEqual(decompile_job.run(path), 0)
            self.assertTrue(seen["inline"])
            self.assertEqual(seen["call"]["address"], "0x1")
            done = decompile_job.status({"root": tmp}, "decompile-0123456789ab")
            self.assertEqual((done["state"], done["result"]["fallback"]["job"]), ("done", "decompile-0123456789ab"))

    def test_a_worker_failure_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.record(Path(tmp))

            class Runner:
                def __init__(self, settings):
                    pass

                def query(self, **call):
                    raise RuntimeError(NO_PCODE)

            with patch("hydralysis.query.QueryRunner", Runner):
                self.assertEqual(decompile_job.run(path), 1)
            self.assertIn("No pcode", read_json(path)["error"])

    def test_the_cli_follows_a_job_to_its_result(self):
        states = [{"id": "decompile-0123456789ab", "state": "running", "stage": "engine decompile running (5 s)"},
                  {"id": "decompile-0123456789ab", "state": "done",
                   "result": {"ok": True, "c": "text", "fallback": {"via": "engine_decompile"}}}]
        first = json.dumps({"id": "decompile-0123456789ab", "state": "queued", "stage": "starting"})
        with patch("hydralysis.cli.call", side_effect=[json.dumps(item) for item in states]), patch("time.sleep"):
            out = cli._await_decompile_job(first, 60)
        self.assertEqual(json.loads(out)["c"], "text")
        self.assertEqual(cli._await_decompile_job('{"ok": true}', 60), '{"ok": true}')


if __name__ == "__main__":
    unittest.main()
