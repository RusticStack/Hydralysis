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


if __name__ == "__main__":
    unittest.main()
