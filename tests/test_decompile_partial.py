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


if __name__ == "__main__":
    unittest.main()
