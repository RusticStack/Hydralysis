"""Structure guards on RusticQuery.java. The behaviour itself is checked on the real engine
(tests/test_engine_integration.py, ProductionDecompileOptions); these only keep a new decompile entry
point from being added that bypasses the shared options setup."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "src" / "hydralysis" / "scripts" / "RusticQuery.java"


class DecompileOptionsSetup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SCRIPT.read_text(encoding="utf-8")

    def test_one_decompiler_factory_and_it_sets_options_before_opening_the_program(self):
        self.assertEqual(len(re.findall(r"new DecompInterface\(", self.text)), 1)
        factory = self.text[self.text.index("new DecompInterface("):]
        self.assertLess(factory.index("applyProgramOptions("), factory.index(".openProgram("))

    def test_options_come_from_the_program(self):
        helper = self.text[self.text.index("void applyProgramOptions("):]
        helper = helper[:helper.index("\n    }")]
        self.assertIn("grabFromProgram(program)", helper)
        self.assertIn("setOptions(", helper)

    def test_every_decompile_goes_through_a_borrowed_decompiler(self):
        calls = [m.start() for m in re.finditer(r"\.decompileFunction\(", self.text)]
        self.assertTrue(calls)
        for position in calls:
            window = self.text[max(0, position - 400):position]
            self.assertIn("borrow(currentProgram)", window)

    def test_a_reused_decompiler_gets_the_options_again_when_the_program_changed(self):
        stale = self.text[self.text.index("seen != program.getModificationNumber()"):]
        stale = stale[:stale.index("return found;")]
        self.assertIn("applyProgramOptions(found, program)", stale)


class SubjectRecordOutputs(unittest.TestCase):
    """The new outputs (effects, annotation_probe, verify_before, state:null) must not touch the decompile path.
    Their behaviour is checked on the real engine (tests/test_engine_integration.py, SubjectRecord)."""

    @classmethod
    def setUpClass(cls):
        cls.text = SCRIPT.read_text(encoding="utf-8")

    @staticmethod
    def body(text, signature):
        start = text.index(signature)
        return text[start:text.index("\n    }\n", start)]

    def test_an_effect_is_reported_only_from_typeEdit_and_only_through_effect(self):
        edit = self.body(self.text, "private void typeEdit(")
        for field in ("definition", "existence", "body", "name", "label:", '"type"', "comment:plate", "signature", "variable:"):
            self.assertIn(field, edit)
        self.assertEqual(len(re.findall(r"currentEffects\.add\(", self.text)), 1)  # effect() is the one writer
        # The decompile action never starts a transaction or reports effects.
        decompile = self.text[self.text.index('action.equals("decompile")'):]
        decompile = decompile[:decompile.index('out.addProperty("total_characters"')]
        self.assertNotIn("effect", decompile)
        self.assertNotIn("startTransaction", decompile)

    def test_the_probe_is_read_only(self):
        for signature in ("private String probe(", "private void annotationProbe("):
            body = self.body(self.text, signature)
            for write in ("startTransaction", ".setName(", ".setComment(", ".createLabel(", "createData(", "setBody("):
                self.assertNotIn(write, body, signature)

    def test_verify_before_runs_before_the_edit_and_fails_the_whole_transaction(self):
        apply = self.body(self.text, "private void applyOverlays(")
        self.assertLess(apply.index("verifyBefore(edit, deadline)"), apply.index("typeEdit(text(edit"))
        self.assertIn("endTransaction(transaction, success)", apply)
        self.assertIn("class VerifyMismatch extends IllegalArgumentException", self.text)

    def test_a_null_state_clears_the_overlay_marker(self):
        apply = self.body(self.text, "private void applyOverlays(")
        self.assertIn("removeOption(STATE_OPTION)", apply)

    def test_apply_overlays_and_the_probe_are_dispatched_by_name(self):
        for action in ("apply_overlays", "annotation_probe", "overlay_state"):
            self.assertIn('action.equals("%s")' % action, self.text)


if __name__ == "__main__":
    unittest.main()
