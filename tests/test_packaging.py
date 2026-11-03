"""A release carries the product, not its tests: MANIFEST.in keeps tests/ and the other working directories out of the
sdist, and the wheel is built from src/ only."""

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ReleaseContents(unittest.TestCase):
    def test_the_sdist_manifest_prunes_the_tests_and_working_directories(self):
        lines = {line.strip() for line in (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()}
        for directory in ("tests", "test-work", "benchmarks", "tools", "native", "rust"):
            self.assertIn("prune " + directory, lines)

    def test_the_wheel_is_built_from_src_only_and_names_no_test_data(self):
        config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]
        self.assertEqual(config["packages"]["find"]["where"], ["src"])
        for patterns in config["package-data"].values():
            for pattern in patterns:
                self.assertIsNone(re.search(r"test|fixture", pattern, re.I), pattern)

    def test_no_package_module_lives_in_a_tests_directory(self):
        offenders = [str(p.relative_to(ROOT)) for p in (ROOT / "src").rglob("*") if "tests" in p.relative_to(ROOT / "src").parts]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
