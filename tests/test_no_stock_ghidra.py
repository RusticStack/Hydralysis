"""Hydralysis never uses a stock Ghidra: the shipped source and skills do not even name its hooks.

The only place allowed to name the old stock-Ghidra settings is the notice that tells a user they
are ignored (`backends._ignored`). Everything else under src/ and skills/ must stay free of them.
"""

import ast
import re
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
FORBIDDEN = re.compile(r"GHIDRA_INSTALL_DIR|analyzeHeadless|ghidra_dir", re.IGNORECASE)
SHIPPED = (REPOSITORY / "src" / "hydralysis", REPOSITORY / "skills")
TEXT_SUFFIXES = {".py", ".java", ".md", ".json", ".txt", ".toml", ".cfg", ".ps1", ".sh"}
NOTICE_FILE = REPOSITORY / "src" / "hydralysis" / "backends.py"
NOTICE_FUNCTION = "_ignored"


def notice_lines() -> range:
    tree = ast.parse(NOTICE_FILE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == NOTICE_FUNCTION:
            return range(node.lineno, node.end_lineno + 1)
    raise AssertionError("%s no longer defines %s" % (NOTICE_FILE.name, NOTICE_FUNCTION))


class StockGhidraSourceScan(unittest.TestCase):
    def shipped_files(self):
        for root in SHIPPED:
            for path in sorted(root.rglob("*")):
                if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES and "__pycache__" not in path.parts:
                    yield path

    def test_no_stock_ghidra_hook_is_named_outside_the_ignored_notice(self):
        allowed = notice_lines()
        found, scanned = [], 0
        for path in self.shipped_files():
            scanned += 1
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if FORBIDDEN.search(line) and not (path == NOTICE_FILE and number in allowed):
                    found.append("%s:%d: %s" % (path.relative_to(REPOSITORY).as_posix(), number, line.strip()[:120]))
        self.assertGreater(scanned, 20, "the scan found no shipped files; the roots moved")
        self.assertEqual(found, [], "stock Ghidra hooks must not appear outside backends._ignored")

    def test_the_notice_is_the_only_place_and_it_does_exist(self):
        text = "\n".join(NOTICE_FILE.read_text(encoding="utf-8").splitlines()[n - 1] for n in notice_lines())
        self.assertIn("GHIDRA_INSTALL_DIR", text)
        self.assertIn("ghidra_dir", text)


if __name__ == "__main__":
    unittest.main()
