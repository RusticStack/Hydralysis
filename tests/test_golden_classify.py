"""tools/golden_classify.py on small synthetic captures (invented C text, no engine, no game data)."""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import golden  # noqa: E402
import golden_classify as gc  # noqa: E402

from support import workdir  # noqa: E402

BASE = """int demo(int param_1)

{
  int iVar1;

  iVar1 = FUN_00401000(param_1);
  if (iVar1 == 0) {
    return 1;
  }
  return iVar1 + 1;
}
"""
BADDATA = BASE.replace("return iVar1 + 1;", "halt_baddata();")
SWITCH = BASE.replace("return iVar1 + 1;", "switch (iVar1) {\n  case 1:\n    return 2;\n  }\n  return 3;")
WARN = "/* WARNING: Removing unreachable block (ram,0x00401010) */\n" + BASE
LOOP = BASE.replace("if (iVar1 == 0)", "while (iVar1 == 0)")
CONV = BASE.replace("int demo", "int __thiscall demo")
CAST = BASE.replace("FUN_00401000(param_1)", "(int)FUN_00401000((char *)param_1)")
CONST = BASE.replace("iVar1 + 1", "iVar1 + 2")
REORDER = BASE.replace("if (iVar1 == 0) {\n    return 1;\n  }\n  return iVar1 + 1;",
                       "if (iVar1 != 0) {\n    return iVar1 + 1;\n  }\n  return 1;")
LOCALS = BASE.replace("  int iVar1;", "  uint iVar1;")
SECRET = "SECRET_GAME_IDENT_QQ"
SECRET_C = BASE.replace("param_1", SECRET)


def capture(root: Path, name: str, rows: dict, **header) -> Path:
    writer = golden.CaptureWriter(root / name, {"label": name, "path": "explicit", "program_sha256": "ab" * 32,
                                                "engine": {"ghidra_version": "12.3"}, **header})
    for entry, (status, c) in rows.items():
        writer.add(entry, "FUN_" + entry[2:].zfill(8), 10, status, 1.0, c if status == "ok" else None,
                   None if status == "ok" else "refused")
    writer.close()
    return root / name


class Causes(unittest.TestCase):
    def test_each_cause_is_recognised(self):
        cases = {BADDATA: "bad-data-limit", SWITCH: "switch-jump-table", LOOP: "control-flow", CONV: "calling-convention",
                 CAST: "types-casts", CONST: "constants-data",
                 REORDER: "condition-inversion", LOCALS: "local-types"}
        for changed, cause in cases.items():
            self.assertEqual(gc.primary(gc.signals(BASE, changed)), cause, cause)

    def test_warning_only_and_naming_only(self):
        self.assertEqual(gc.signals(BASE, WARN), ["warning-comment"])
        self.assertEqual(gc.primary(gc.signals(BASE, BASE.replace("param_1", "param_2"))), "variable-names")

    def test_unmatched_is_other_and_the_list_is_never_empty(self):
        self.assertEqual(gc.signals(BASE, BASE + "\nextra;"), ["other"])

    def test_every_cause_has_a_policy_entry(self):
        for name, _ in gc.CAUSES:
            self.assertIn(gc.POLICY[name][0], ("accepted", "open"))


STORE5 = BASE.replace("  iVar1 = FUN", "  *(int *)param_1 = 5;\n  iVar1 = FUN")
STORE6 = STORE5.replace("= 5;", "= 6;")
TWO = BASE.replace("  iVar1 = FUN_00401000(param_1);",
                   "  iVar1 = FUN_00401000(param_1);\n  param_1 = iVar1 << 2;\n  iVar1 = iVar1 + param_1;")
TWO_SWAPPED = TWO.replace("  param_1 = iVar1 << 2;\n  iVar1 = iVar1 + param_1;",
                          "  iVar1 = iVar1 + param_1;\n  param_1 = iVar1 << 2;")
BLOCKCOMMENT = "/* WARNING: first line\n * second line of the note\n */\n" + BASE
BLOCKCOMMENT2 = BLOCKCOMMENT.replace("second line", "other words")
STACKED = BASE.replace("  int iVar1;", "  int iVar1;\n  int uStack_8;").replace("  iVar1 = FUN", "  uStack_8 = 0;\n  iVar1 = FUN")
UNIMPL = BASE.replace("return iVar1 + 1;", "halt_unimplemented();")


class Rules(unittest.TestCase):
    """Each classifier rule against a case that must match it and a case that must not."""

    def test_pointer_store_is_code_not_a_comment(self):
        found = gc.signals(STORE5, STORE6)
        self.assertNotIn("warning-comment", found)
        self.assertEqual(gc.primary(found), "constants-data")
        self.assertFalse(gc.is_accepted(found))

    def test_comment_continuation_lines_are_comment_only_inside_an_open_block(self):
        self.assertEqual(gc.signals(BLOCKCOMMENT, BLOCKCOMMENT2), ["warning-comment"])
        self.assertTrue(gc.is_accepted(gc.signals(BLOCKCOMMENT, BLOCKCOMMENT2)))
        self.assertEqual(gc.signals(WARN, WARN.replace("Removing unreachable block", "Control flow encountered")), ["warning-comment"])

    def test_comment_change_next_to_a_code_change_is_not_comment_only(self):
        found = gc.signals(WARN, WARN.replace("Removing unreachable block", "Control flow encountered").replace("iVar1 + 1", "iVar1 + 2"))
        self.assertNotIn("warning-comment", found)
        self.assertEqual(gc.primary(found), "constants-data")

    def test_flipped_condition_with_a_store_change_is_not_accepted(self):
        both = STORE6.replace("iVar1 == 0", "iVar1 != 0")
        found = gc.signals(STORE5, both)
        self.assertNotIn("condition-inversion", found)
        self.assertFalse(gc.is_accepted(found))
        self.assertEqual(gc.primary(found), "constants-data")

    def test_flipped_condition_with_constants_in_the_body_is_not_accepted(self):
        found = gc.signals(BASE, REORDER.replace("iVar1 + 1", "iVar1 + 2"))
        self.assertNotIn("condition-inversion", found)
        self.assertFalse(gc.is_accepted(found))

    def test_pure_flip_is_accepted(self):
        found = gc.signals(BASE, REORDER)
        self.assertEqual(gc.primary(found), "condition-inversion")
        self.assertTrue(gc.is_accepted(found))

    def test_operator_is_compared_not_only_the_operands(self):
        self.assertNotIn("condition-inversion", gc.signals(BASE, BASE.replace("iVar1 == 0", "iVar1 < 0")))
        lt = BASE.replace("iVar1 == 0", "iVar1 < 0")
        for other in ("iVar1 >= 0", "0 > iVar1"):
            self.assertIn("condition-inversion", gc.signals(lt, lt.replace("iVar1 < 0", other)), other)
        self.assertNotIn("condition-inversion", gc.signals(lt, lt.replace("iVar1 < 0", "iVar1 > 0")))
        self.assertNotIn("condition-inversion", gc.signals(lt, lt.replace("iVar1 < 0", "0 < iVar1")))

    def test_operand_swap_alone_is_not_a_constants_change(self):
        found = gc.signals(BASE, BASE.replace("iVar1 == 0", "0 == iVar1"))
        self.assertNotIn("constants-data", found)
        self.assertTrue(gc.is_accepted(found))

    def test_block_reorder(self):
        found = gc.signals(TWO, TWO_SWAPPED)
        self.assertEqual(gc.primary(found), "block-reorder")
        self.assertTrue(gc.is_accepted(found))
        self.assertNotEqual(gc.primary(gc.signals(TWO, TWO_SWAPPED.replace("<< 2", "<< 3"))), "block-reorder")

    def test_stack_layout(self):
        self.assertIn("stack-layout", gc.signals(BASE, STACKED))
        self.assertNotIn("stack-layout", gc.signals(BASE, CONST))

    def test_unimplemented_instruction(self):
        self.assertEqual(gc.primary(gc.signals(BASE, UNIMPL)), "unimplemented-instruction")
        self.assertNotIn("unimplemented-instruction", gc.signals(BASE, BADDATA))

    def test_accepted_count_excludes_a_function_with_another_signal(self):
        with workdir("accepted-split") as work:
            tmp = Path(work)
            a = capture(tmp, "a", {"0x401000": ("ok", STORE5), "0x401010": ("ok", BASE)})
            b = capture(tmp, "b", {"0x401000": ("ok", STORE6.replace("iVar1 == 0", "iVar1 != 0")),
                                   "0x401010": ("ok", REORDER)})
            report = gc.compare(a, b)
        self.assertEqual(report["changed"], 2)
        self.assertEqual(report["accepted_functions"], 1)
        self.assertEqual(report["open_functions"], 1)
        self.assertEqual(report["accepted_by_cause"]["condition-inversion"], 1)


class Reports(unittest.TestCase):
    def setUp(self):
        self.work = workdir("classify")
        self.tmp = Path(self.work.name)
        self.addCleanup(self.work.cleanup)

    def pair(self):
        a = capture(self.tmp, "a", {"0x401000": ("ok", BASE), "0x401010": ("ok", BASE), "0x401020": ("ok", BASE),
                                    "0x401030": ("ok", BASE), "0x401040": ("ok", BASE)}, options={"x": "1"})
        b = capture(self.tmp, "b", {"0x401000": ("ok", BASE), "0x401010": ("ok", BADDATA), "0x401020": ("ok", SWITCH),
                                    "0x401030": ("ok", WARN), "0x401040": ("ok", SECRET_C)},
                    options={"x": "1", "maxBadData": "1000000"})
        return a, b

    def test_counts_by_cause_and_policy(self):
        a, b = self.pair()
        report = gc.compare(a, b)
        self.assertEqual(report["functions_compared"], 5)
        self.assertEqual(report["identical_or_normalised"], 1)
        self.assertEqual(report["changed"], 4)
        self.assertEqual(report["match_pct"], 20.0)
        self.assertEqual(sum(report["by_primary_cause"].values()), 4)
        self.assertEqual(report["by_primary_cause"]["bad-data-limit"], 1)
        self.assertEqual(report["by_primary_cause"]["switch-jump-table"], 1)
        self.assertEqual(report["accepted_functions"] + report["open_functions"], 4)
        self.assertTrue(report["reported_not_gated"])

    def test_pinned_option_is_not_counted_as_an_options_difference(self):
        a, b = self.pair()
        options = gc.compare(a, b)["options"]
        self.assertTrue(options["equal_apart_from_pinned"])
        self.assertEqual(options["pinned_in_B"], "1000000")
        self.assertIsNone(options["pinned_in_A"])

    def test_other_option_difference_is_named(self):
        a = capture(self.tmp, "a", {"0x401000": ("ok", BASE)}, options={"x": "1"})
        b = capture(self.tmp, "b", {"0x401000": ("ok", BASE)}, options={"x": "2"})
        options = gc.compare(a, b)["options"]
        self.assertFalse(options["equal_apart_from_pinned"])
        self.assertEqual(options["differing_other_than_pinned"], ["x"])

    def test_unpinned_effect(self):
        a, b = self.pair()
        # unpinned: the bad-data function is cut short, the pinned capture is not
        u = capture(self.tmp, "u", {"0x401000": ("ok", BASE), "0x401010": ("ok", BADDATA), "0x401020": ("ok", SWITCH),
                                    "0x401030": ("ok", WARN), "0x401040": ("ok", BASE)},
                    options={"x": "1", "maxBadData": "4"})
        effect = gc.compare(a, b, u)["maxBadData_effect"]
        self.assertEqual(effect["functions_with_bad_data_text_unpinned"], 1)
        self.assertEqual(gc.compare(a, b, u)["functions_with_bad_data_text"], {"A": 0, "B": 1})
        self.assertEqual(effect["changed_in_both"], 3)
        self.assertEqual(effect["changed_only_when_pinned"], 1)
        self.assertEqual(effect["changed_only_when_unpinned"], 0)
        self.assertEqual(effect["functions_where_pinned_and_unpinned_B_differ"], 1)

    def test_report_holds_no_c_text_name_or_address(self):
        a, b = self.pair()
        report = gc.compare(a, b)
        text = json.dumps(report) + gc.render_markdown(report)
        self.assertFalse(report["contains_c_text"])
        for forbidden in (SECRET, "iVar1", "FUN_0", "0x4010", "halt_baddata"):
            self.assertNotIn(forbidden, text)

    def test_different_program_or_path_is_refused(self):
        a = capture(self.tmp, "a", {"0x401000": ("ok", BASE)})
        b = capture(self.tmp, "b", {"0x401000": ("ok", BASE)}, program_sha256="cd" * 32)
        with self.assertRaises(ValueError):
            gc.compare(a, b)
        c = capture(self.tmp, "c", {"0x401000": ("ok", BASE)}, path="production")
        with self.assertRaises(ValueError):
            gc.compare(a, c)

    def test_failed_functions_are_counted_not_classified(self):
        a = capture(self.tmp, "a", {"0x401000": ("ok", BASE), "0x401010": ("ok", BASE)})
        b = capture(self.tmp, "b", {"0x401000": ("ok", BASE), "0x401010": ("failed", None)})
        report = gc.compare(a, b)
        self.assertEqual(report["counts"]["failed_only_in_B"], 1)
        self.assertEqual(report["changed"], 0)

    def test_exit_status_is_zero_whatever_the_match_and_two_on_a_bad_path(self):
        a, b = self.pair()
        out = self.tmp / "r.json"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(gc.main(["classify", str(a), str(b), "--json", str(out),
                                      "--markdown", str(self.tmp / "r.md")]), 0)
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["match_pct"], 20.0)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(gc.main(["classify", str(self.tmp / "nope"), str(b)]), 2)

    def test_fixtures_command(self):
        for root in ("ra", "rb"):
            for fx in ("f1", "f2"):
                changed = root == "rb" and fx == "f2"
                rows = {"0x401000": ("ok", BASE), "0x401010": ("ok", CONST if changed else BASE)}
                capture(self.tmp / root / fx, "explicit", rows)
        report = gc.compare_fixtures(self.tmp / "ra", self.tmp / "rb")
        self.assertEqual(sorted(report["fixtures"]), ["f1", "f2"])
        self.assertEqual(report["totals"], {"compared": 4, "identical": 3, "changed": 1})


if __name__ == "__main__":
    unittest.main()
