"""Output-size budgets (row C1-15): bytes of an answer per action and function size, on the public fixture.

Two parts. The first needs no engine: the transport cap (`mcp.MAX_OUTPUT_BYTES`) and the decompiler's character cap
hold. The second runs on a real engine (HYDRALYSIS_INTEGRATION_ENGINE and HYDRALYSIS_INTEGRATION_CLIENT, as the other
integration tests) against the fixture program, picks a small, a medium and the largest function, and asserts each
answer is within a byte budget. Budgets are bytes, not tokens (docs/verification-complete-workflow.md), with 1.3 to
3 times the measured size as headroom (the largest answers have the least), because the 0.5.0 options fix changes decompiled C for about one function in
six. KotOR numbers stay local evidence: nothing from a game is read or stored here.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from hydralysis import analysis, mcp
from test_engine_integration import BINARY, CLIENT, ENGINE, _prepare, _release

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
                        # An action that does not apply to this function (for example trace without calls) is not a size.
                        self.skipTest("%s refused: %s" % (action, str(refused)[:800]))
                    used = len(text.encode("utf-8"))
                    measured["%s/%s" % (label, action)] = used
                    self.assertLessEqual(used, budget, "%s of a %s function (%d bytes of code)" % (action, label, self.sizes[label]))
                    self.assertLessEqual(used, mcp.MAX_OUTPUT_BYTES)
        self.assertTrue(measured)
        print("\nmeasured bytes:%s; function sizes: %s" % (json.dumps(measured, sort_keys=True), json.dumps(self.sizes)))

    def test_a_large_listing_page_is_bounded(self):
        text = self.runner.query("fixture", "functions", limit=200)
        self.assertLessEqual(len(text.encode("utf-8")), mcp.MAX_OUTPUT_BYTES)


if __name__ == "__main__":
    unittest.main()
