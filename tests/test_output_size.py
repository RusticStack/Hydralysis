"""Output-size budgets and the harness's own engine-free logic (Z2; the harness tests live here because tests/test_bench_harness.py has no 8.1 row).

Output-size budgets (row C1-15): bytes of an answer per action and function size, on the public fixture.

Two parts. The first needs no engine: the transport cap (`mcp.MAX_OUTPUT_BYTES`) and the decompiler's character cap
hold. The second runs on a real engine (HYDRALYSIS_INTEGRATION_ENGINE and HYDRALYSIS_INTEGRATION_CLIENT, as the other
integration tests) against the fixture program, picks a small, a medium and the largest function, and asserts each
answer is within a byte budget. Budgets are bytes, not tokens (docs/verification-complete-workflow.md), with 1.3 to
3 times the measured size as headroom (the largest answers have the least), because the 0.5.0 options fix changes decompiled C for about one function in
six. KotOR numbers stay local evidence: nothing from a game is read or stored here.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

from hydralysis import analysis, mcp
from support import workdir
from test_engine_integration import BINARY, CLIENT, ENGINE, _prepare, _release

BENCH = Path(__file__).resolve().parent.parent / "benchmarks"
sys.path.insert(0, str(BENCH))

import mcp_latency as common  # noqa: E402
import named_view_cost  # noqa: E402

# action -> byte budget of the whole JSON answer for a function of up to 4 KB (fixture scale).
# Measured on the fixture (whoami.exe, functions of 3, 105 and 2,916 bytes) on 2026-10-28: function 603, decompile 17,065,
# dossier 38,245, blocks 11,143, pcode 72,230, variables 8,246, trace 2,825 bytes at most.
BUDGET_BYTES = {"function": 2 * 1024, "decompile": 32 * 1024, "dossier": 64 * 1024, "blocks": 24 * 1024,
                "pcode": 110 * 1024, "variables": 16 * 1024, "trace": 8 * 1024}


class TransportCap(unittest.TestCase):
    def test_a_reply_over_the_cap_is_cut_and_marked(self):
        text = "x" * (mcp.MAX_OUTPUT_BYTES * 2)
        reply = mcp._tool_result(1, text)["result"]
        body = reply["content"][0]["text"].encode("utf-8")
        self.assertLessEqual(len(body), mcp.MAX_OUTPUT_BYTES)
        self.assertIn("OUTPUT TRUNCATED", reply["content"][0]["text"])
        self.assertTrue(reply["isError"])

    def test_a_reply_under_the_cap_is_unchanged(self):
        text = "y" * (mcp.MAX_OUTPUT_BYTES - 1)
        reply = mcp._tool_result(1, text)["result"]
        self.assertEqual(reply["content"][0]["text"], text)
        self.assertFalse(reply["isError"])

    def test_the_decompiler_character_cap_defaults_to_32000(self):
        self.assertEqual(analysis.validate_options("decompile", {})["max_characters"], 32000)


@unittest.skipUnless(ENGINE and CLIENT and BINARY and Path(BINARY).is_file(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class AnswerSizes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _prepare(cls, BINARY, "outsize", "fixture")
        listed = json.loads(cls.runner.query("fixture", "functions", limit=200))["functions"]

        def size(item):
            total = 0
            for part in item.get("body") or []:
                low, _, high = part.strip("[]").partition(",")
                total += int(high.strip(), 16) - int(low.strip(), 16) + 1
            return total
        ordered = sorted(listed, key=size)
        cls.picks = {"small": ordered[0], "medium": ordered[len(ordered) // 2], "large": ordered[-1]}
        cls.sizes = {label: size(item) for label, item in cls.picks.items()}

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def test_each_answer_is_within_its_byte_budget(self):
        measured = {}
        for label, item in self.picks.items():
            self.assertLess(self.sizes[label], 4096, "the fixture function is larger than the budget table covers")
            for action, budget in BUDGET_BYTES.items():
                with self.subTest(size=label, action=action):
                    try:
                        text = self.runner.query("fixture", action, item["address"], timeout_s=120,
                                                 options={"brief": True, "depth": 4} if action == "trace" else None)
                    except RuntimeError as refused:
                        # Only the engine's refusal of a trace seed is "does not apply"; any other failure is a failure.
                        if action == "trace" and "trace seed not found" in str(refused):
                            self.skipTest("trace refused: %s" % str(refused)[:800])
                        raise
                    used = len(text.encode("utf-8"))
                    measured["%s/%s" % (label, action)] = used
                    self.assertLessEqual(used, budget, "%s of a %s function (%d bytes of code)" % (action, label, self.sizes[label]))
                    self.assertLessEqual(used, mcp.MAX_OUTPUT_BYTES)
        self.assertTrue(measured)
        print("\nmeasured bytes:%s; function sizes: %s" % (json.dumps(measured, sort_keys=True), json.dumps(self.sizes)))

    def test_a_large_listing_page_is_bounded(self):
        text = self.runner.query("fixture", "functions", limit=200)
        self.assertLessEqual(len(text.encode("utf-8")), mcp.MAX_OUTPUT_BYTES)


class Statistics(unittest.TestCase):
    def test_median_p95_and_maximum(self):
        stats = common.summarize([float(i) for i in range(1, 101)])
        self.assertEqual((stats["n"], stats["median"], stats["p95"], stats["max"], stats["min"]), (100, 50.5, 95.0, 100.0, 1.0))

    def test_an_empty_sample_has_no_figures(self):
        self.assertIsNone(common.summarize([])["median"])

    def test_listing_size_is_the_sum_of_the_body_ranges(self):
        self.assertEqual(common.body_size({"body": ["[140001010, 14000101b]", "[140001030, 140001030]"]}), 12 + 1)
        self.assertEqual(common.body_size({}), 0)


class Budgets(unittest.TestCase):
    def test_a_budget_is_three_times_the_recorded_median_and_never_raises(self):
        budgets = {"factor": 3, "entries": {"a": {"median": 10.0}, "b": {"median": 10.0, "budget": 50.0}}}
        self.assertEqual(common.judge("a", 29.0, budgets)["status"], "within")
        self.assertIn("over-budget", common.judge("a", 31.0, budgets)["status"])
        self.assertEqual(common.judge("b", 49.0, budgets)["status"], "within")
        self.assertEqual(common.judge("missing", 1.0, budgets)["status"], "unrecorded")
        self.assertEqual(common.judge("a", None, budgets)["status"], "no-value")

    def test_the_committed_budgets_are_three_times_their_medians(self):
        data = json.loads(common.BUDGETS.read_text(encoding="utf-8"))
        self.assertEqual(data["factor"], 3)
        for key, entry in data["entries"].items():
            with self.subTest(key=key):
                self.assertAlmostEqual(entry["budget"], entry["median"] * 3, places=2)


class Guards(unittest.TestCase):
    def test_the_original_kotor_folder_is_refused(self):
        with self.assertRaises(SystemExit):
            common.refuse_original("F:/dev-cache/hydra-projects/kotor/swkotor.exe")
        with self.assertRaises(SystemExit):
            common.default_binary("F:\\dev-cache\\hydra-projects\\kotor\\x.exe")
        common.refuse_original("D:/Projects/Hydra/_logs/Z2/copy/swkotor.exe")

    def test_a_report_is_written_under_the_output_folder(self):
        with workdir("bench") as folder:
            out = common.output_dir(str(Path(folder) / "nested" / "logs"))
            path = common.write_report(out, "x", {"a": 1})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"a": 1})
            self.assertEqual(path.parent, out)

    def test_the_foreign_load_names_its_own_process(self):
        load = common.foreign_load()
        self.assertIn("processes", load)
        self.assertIn("own_pid", load)


class Aggregation(unittest.TestCase):
    def test_phases_are_aggregated_over_every_view_of_every_run(self):
        def view(total, base):
            return {"phases_ms": {"total": total, "fork": 10, "base_upgrade": base, "open": 1, "replay": 2, "copy": 3, "master_open": 4}}
        runs = [{"wall_s": 1.0, "errors": [], "per_view": [view(100, 0), view(300, 50)]},
                {"wall_s": 2.0, "errors": ["boom"], "per_view": [view(200, 0)]}]
        cell = named_view_cost.aggregate(runs)
        self.assertEqual(cell["total"]["median"], 200.0)
        self.assertEqual(cell["total"]["n"], 3)
        self.assertEqual(cell["views_that_rebuilt_the_base"], 1)
        self.assertEqual(cell["errors"], ["boom"])
        self.assertEqual(cell["wall_s"]["median"], 1.5)

    def test_the_keep_warm_placeholder_and_the_threshold_are_the_spec_values(self):
        self.assertEqual(named_view_cost.PER_CALL_THRESHOLD_S, 5.0)
        self.assertEqual(named_view_cost.KEEP_WARM_RECORDS_PLACEHOLDER, 1000)


if __name__ == "__main__":
    unittest.main()
