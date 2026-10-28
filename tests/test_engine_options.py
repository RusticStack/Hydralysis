"""The production decompile path (RusticQuery) runs on the program's own decompiler options.

Runs on the real engine only, like tests/test_engine_integration.py, and needs the public MSVC fixtures
built by tests/fixtures/build_fixtures.py: HYDRALYSIS_INTEGRATION_FIXTURES names the build directory
(the one holding x86/diff1.exe, x86/diff1.map, x86/vcall_fixture.exe and x86/vcall_fixture.map).
The fixtures are built from source in this repository, so nothing here is derived from a game.
"""

from __future__ import annotations

import json
import os
import re
import unittest
from pathlib import Path

from test_engine_integration import CLIENT, ENGINE, _env, _prepare, _release

FIXTURES = _env("INTEGRATION_FIXTURES")


def _symbol(build: Path, stem: str, name: str) -> str:
    """The address the linker map gives NAME (a decorated symbol), as 0x...."""
    pattern = re.compile(r"^\s*\d+:[0-9a-f]+\s+%s\s+([0-9a-f]{8})\s+f" % re.escape(name), re.M)
    found = pattern.search((build / "x86" / (stem + ".map")).read_text(encoding="utf-8", errors="replace"))
    if not found:
        raise AssertionError("%s is not in %s.map" % (name, stem))
    return "0x" + found.group(1)


def _have(*parts: str) -> bool:
    return bool(ENGINE and CLIENT and FIXTURES and all((Path(FIXTURES) / "x86" / part).is_file() for part in parts))


class _Fixture(unittest.TestCase):
    STEM = ""
    TARGET = ""

    @classmethod
    def setUpClass(cls):
        _prepare(cls, Path(FIXTURES) / "x86" / (cls.STEM + ".exe"), "engine-options-" + cls.STEM, cls.TARGET)

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def decompile(self, name):
        address = _symbol(Path(FIXTURES), self.STEM, name)
        answer = json.loads(self.runner.query(self.TARGET, "decompile", address))
        self.assertTrue(answer["ok"], answer)
        return answer["c"]


@unittest.skipUnless(_have("diff1.exe", "diff1.map"), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT/FIXTURES")
class ProductionDecompileOptions(_Fixture):
    STEM, TARGET = "diff1", "diffone"

    def test_constants_in_read_only_data_are_folded_as_the_ghidra_window_does(self):
        # df_scale: `value * 1.5f - 0.25f` with both constants in .rdata. The native defaults
        # (a DecompInterface nobody called setOptions on) keep them as DAT_ names; the program's
        # own options (respect read-only on) print the values.
        c = self.decompile("_df_scale")
        self.assertIn("1.5", c)
        self.assertIn("0.25", c)
        self.assertNotRegex(c, r"DAT_[0-9a-f]{8}")


@unittest.skipUnless(_have("vcall_fixture.exe", "vcall_fixture.map"), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT/FIXTURES")
class ProductionKeepsCallingConventions(_Fixture):
    STEM, TARGET = "vcall_fixture", "vcallx86"

    def test_a_thiscall_method_keeps_its_convention_and_its_this_parameter(self):
        # Square::area reads this->side; MSVC passes `this` in ECX. The signature names the
        # convention and `this` is a parameter, not an `in_ECX` local.
        c = self.decompile("?area@Square@@UAEHXZ")
        self.assertRegex(c.strip().split("\n")[0], r"__(thiscall|fastcall)")
        self.assertNotIn("in_ECX", c)


if __name__ == "__main__":
    unittest.main()
