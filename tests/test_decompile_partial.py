"""Partial decompile results (issue-lane): max_result_mb, and the engine fields fragments/truncated/bytes_emitted/reason.

Fake engine replies only. The real engine's field names are the ones in hydralysis.decompile_result.
"""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from hydralysis import analysis, api, cli, decompile_result as dr, evidence, query

FRAGMENTS = [{"start": "0x401000", "end": "0x401040", "class": "code"},
             {"start": "0x401040", "end": "0x401060", "class": "data"},
             {"start": "0x401060", "end": "0x401070", "class": "unknown"}]
PARTIAL = {"ok": True, "c": "int f(void) {", "truncated": True, "bytes_emitted": 1048576, "reason": "max_result_mb",
           "fragments": FRAGMENTS}


class Options(unittest.TestCase):
    def test_max_result_mb_is_a_decompile_option_with_bounds(self):
        self.assertEqual(analysis.validate_options("decompile", {"max_result_mb": 4})["max_result_mb"], 4)
        self.assertNotIn("max_result_mb", analysis.validate_options("decompile", {}))
        for bad in (0, -1, analysis.MAX_RESULT_MB + 1, "4", 1.5, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                analysis.validate_options("decompile", {"max_result_mb": bad})
        with self.assertRaises(ValueError):
            analysis.validate_options("xrefs", {"max_result_mb": 4})

    def test_top_level_limits_fold_into_options_once(self):
        self.assertEqual(analysis.with_decompile_limits({"x": 1}, max_result_mb=2), {"x": 1, "max_result_mb": 2})
        self.assertEqual(analysis.with_decompile_limits(None, max_result_mb=None), None)
        self.assertEqual(analysis.with_decompile_limits({"max_result_mb": 2}, max_result_mb=2), {"max_result_mb": 2})
        with self.assertRaises(ValueError):
            analysis.with_decompile_limits({"max_result_mb": 2}, max_result_mb=3)

    def test_mcp_and_cli_carry_max_result_mb_to_the_query(self):
        props = {t["name"]: t["inputSchema"]["properties"] for t in api.tool_table()}["ghidra_query"]
        self.assertEqual(props["max_result_mb"]["type"], "integer")
        out = io.StringIO()
        with patch("hydralysis.cli.call", return_value="ok") as dispatch, redirect_stdout(out):
            code = cli.main(["ghidra-query", "--target", "t", "0x401000", "--max-result-mb", "8", "--max-characters", "500"])
        self.assertEqual(code, 0)
        self.assertEqual(dispatch.call_args.args[1]["options"], {"max_characters": 500, "max_result_mb": 8})
        with patch("hydralysis.cli.call", return_value="ok") as dispatch, redirect_stdout(out):
            cli.main(["ghidra-query", "--target", "t", "0x401000"])
        self.assertEqual(dispatch.call_args.args[1]["options"], {})

    def test_help_explains_the_difference(self):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["ghidra-query", "--help"])
        text = " ".join(out.getvalue().split())
        self.assertIn("--max-result-mb", text)
        self.assertIn("WHOLE reply", text)
        self.assertIn("clip", text)


class Fields(unittest.TestCase):
    def test_summary_counts_fragment_bytes_by_class(self):
        summary = dr.summarize(PARTIAL)
        self.assertEqual(summary["partial"], True)
        self.assertEqual((summary["reason"], summary["bytes_emitted"]), ("max_result_mb", 1048576))
        self.assertEqual(summary["fragment_bytes"], {"code": 0x40, "data": 0x20, "unknown": 0x10})
        self.assertEqual(dr.limitations(PARTIAL), ["decompile_truncated", "non_code_fragments"])

    def test_an_old_engine_reply_is_untouched(self):
        old = {"ok": True, "c": "x", "truncated": False}
        self.assertEqual(dr.summarize({"ok": True, "c": "x"}), {})
        self.assertEqual(dr.coverage({"ok": True, "c": "x"})["status"], "unknown")
        self.assertEqual(dr.annotate(dict(old)), old)
        self.assertEqual(dr.annotate({"truncated": True})["decompile"], {"partial": True})

    def test_malformed_fragments_are_dropped_and_reported(self):
        bad = [{"start": "0x2", "end": "0x1", "class": "code"}, {"start": "0x1", "end": "0x2", "class": "text"}, "x",
               {"start": "0x1", "end": "0x5", "class": "code"}]
        summary = dr.summarize({"fragments": bad, "truncated": False})
        self.assertEqual(summary["fragment_count"], 1)
        self.assertIn("3 malformed", summary["fragments_note"])
        self.assertEqual(dr.summarize({"fragments": "nope"})["fragments_note"], "fragments is not a list")

    def test_coverage_is_valid_evidence_coverage(self):
        partial = evidence.normalize_coverage(dr.coverage(PARTIAL))
        self.assertEqual(partial, {"status": "partial", "limitations": ["decompile_truncated"]})
        self.assertEqual(evidence.merge_limitations(partial, dr.limitations(PARTIAL)), ["decompile_truncated", "non_code_fragments"])
        complete = dr.coverage({"truncated": False, "fragments": FRAGMENTS[:1]})
        self.assertEqual(evidence.normalize_coverage(complete)["status"], "complete")
        with self.assertRaises(ValueError):    # a truncated decompile can never be recorded as complete
            evidence.merge_limitations({"status": "complete"}, ["decompile_truncated"])


class Accepted(unittest.TestCase):
    def test_an_ok_reply_keeps_every_field_and_gains_a_summary(self):
        reply = query.accepted("decompile", dict(PARTIAL))
        for name in ("c", "fragments", "truncated", "bytes_emitted", "reason"):
            self.assertEqual(reply[name], PARTIAL[name])
        self.assertTrue(reply["decompile"]["partial"])

    def test_a_refusal_that_is_a_partial_result_is_not_a_failure(self):
        reply = query.accepted("decompile", {**PARTIAL, "ok": False})
        self.assertTrue(reply["ok"])
        self.assertFalse(reply["engine_ok"])
        self.assertTrue(reply["decompile"]["partial"])

    def test_real_failures_and_other_actions_still_raise(self):
        with self.assertRaises(RuntimeError):
            query.accepted("decompile", {"ok": False, "error": "decompile refused: x"})
        with self.assertRaises(RuntimeError):
            query.accepted("decompile", {"ok": False, "truncated": True})          # nothing emitted: a failure
        with self.assertRaises(RuntimeError):
            query.accepted("xrefs", {**PARTIAL, "ok": False})
        self.assertNotIn("decompile", query.accepted("xrefs", {"ok": True, "truncated": True}))


class EngineCommand(unittest.TestCase):
    """The engine's own `decompile` answer folded into RusticQuery's (real-engine behaviour of the issues-eng fixture)."""
    FAILED = {"id": "x", "program": "p", "sha256": "ab", "ok": False, "error": "decompile refused: Bad instruction count exceeded"}
    PIECES = {"completed": True, "name": "entry", "entry": "0x140001000", "signature": "int entry(void);", "chars": 5, "c": "int x;",
              "truncated": False, "partial": True, "reason": "non_contiguous_body",
              "fragments": [{"start": "0x140001000", "end": "0x140001038", "class": "code", "decompiled": True},
                            {"start": "0x140001200", "end": "0x14000121f", "class": "data", "decompiled": False}]}
    CAPPED = {"completed": False, "truncated": True, "bytes_emitted": 1024, "reason": "response_buffer",
              "error": "Response buffer size exceeded for: x"}

    def test_a_body_in_pieces_is_partial_with_the_non_code_limitation(self):
        reply = query.accepted("decompile", dr.merge(self.FAILED, self.PIECES))
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["c"], "int x;")
        self.assertTrue(reply["decompile"]["partial"])
        self.assertEqual(reply["decompile"]["reason"], "non_contiguous_body")
        self.assertEqual(dr.coverage(reply), {"status": "partial", "limitations": [dr.LIMIT_NON_CODE]})
        self.assertEqual(dr.limitations(reply), [dr.LIMIT_NON_CODE])
        self.assertIs(reply["fragments"][1]["decompiled"], False)

    def test_a_reply_cut_at_the_bound_is_partial_with_the_truncated_limitation(self):
        ok = {"id": "x", "ok": True, "c": "text", "truncated": False, "function": {"address": "0x1"}}
        reply = query.accepted("decompile", dr.merge(ok, self.CAPPED))
        self.assertTrue(reply["ok"])
        self.assertFalse(reply["engine_ok"])
        self.assertEqual((reply["reason"], reply["bytes_emitted"]), ("response_buffer", 1024))
        self.assertEqual(dr.limitations(reply), [dr.LIMIT_TRUNCATED])
        self.assertEqual(dr.coverage(reply), {"status": "partial", "limitations": [dr.LIMIT_TRUNCATED]})

    def test_a_complete_contiguous_reply_is_unchanged(self):
        ok = {"id": "x", "ok": True, "c": "text", "truncated": False}
        self.assertEqual(dr.merge(ok, {"completed": True, "c": "text", "truncated": False, "chars": 4}), ok)

    def test_the_command_is_asked_only_when_needed_and_a_refusal_keeps_the_script_answer(self):
        calls = []

        class Engine:
            def call(self, command, **fields):
                calls.append((command, fields))
                if self.refuse:
                    raise query.hydra.EngineError("bad_request", "no")
                return TestReply

        TestReply = self.PIECES
        eng, program = Engine(), {"key": "k"}
        eng.refuse = False
        good = {"ok": True, "c": "t"}
        self.assertIs(query.engine_decompile(eng, program, {"action": "decompile", "address": "0x1", "options": {}}, 5, good), good)
        self.assertIs(query.engine_decompile(eng, program, {"action": "xrefs", "address": "0x1", "options": {"max_result_mb": 1}}, 5, good), good)
        self.assertEqual(calls, [])
        merged = query.engine_decompile(eng, program, {"action": "decompile", "address": "0x1", "options": {"max_result_mb": 2}}, 5, good)
        self.assertEqual(calls[0][1]["maxResultMb"], 2)
        self.assertEqual(merged["reason"], "non_contiguous_body")
        eng.refuse = True
        self.assertIs(query.engine_decompile(eng, program, {"action": "decompile", "address": "0x1", "options": {"max_result_mb": 2}}, 5, good), good)


if __name__ == "__main__":
    unittest.main()
