"""Hydralysis never uses a stock Ghidra: the shipped source and skills do not even name its hooks.

The only place in the shipped source allowed to name the old stock-Ghidra settings is the notice
that tells a user they are ignored (`backends._ignored`). Everything else under src/ and skills/
must stay free of them. The same names are also kept out of the documentation (README.md,
THIRD_PARTY.md, docs/) and the tools/ scripts, except for the explicit allow-list below, where
each entry says why it may name them.
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


TEXT_ROOTS = (REPOSITORY / "README.md", REPOSITORY / "THIRD_PARTY.md", REPOSITORY / "docs", REPOSITORY / "tools")
IGNORED_NOTICE = re.compile(r"\bignored\b", re.IGNORECASE)
# Whole files that may name the old hooks, and why. Everything else under README.md, THIRD_PARTY.md,
# docs/ and tools/ is scanned. Do not grow this list to make a failing scan pass: remove the
# reference, or add a file only when it is a deliberate record or tool and say so here.
ALLOWED_FILES = {
    "docs/golden-harness.md": "documents the explicit, opt-in stock-Ghidra capture used only to compare an old baseline",
    "tools/golden.py": "the golden harness can run a stock install by explicit path, only to record a comparison baseline",
    "tools/golden/GoldenExport.java": "the harness's export script, which runs under stock analyzeHeadless for that baseline",
    "docs/prompts/review.md": "historical review prompt, kept as written (it describes agents typing analyzeHeadless by hand)",
}
# Files that may name them only on the line that says they are ignored: the upgrade notices.
ALLOWED_NOTICE_FILES = ("README.md", "THIRD_PARTY.md")


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

    def text_files(self):
        for root in TEXT_ROOTS:
            candidates = [root] if root.is_file() else sorted(root.rglob("*"))
            for path in candidates:
                if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES | {".java"} and "__pycache__" not in path.parts:
                    yield path

    def hits(self, path):
        text = path.read_text(encoding="utf-8", errors="replace")
        return [(number, line) for number, line in enumerate(text.splitlines(), 1) if FORBIDDEN.search(line)]

    def test_docs_and_tools_do_not_name_stock_ghidra_hooks_outside_the_allow_list(self):
        found, scanned = [], 0
        for path in self.text_files():
            relative = path.relative_to(REPOSITORY).as_posix()
            scanned += 1
            if relative in ALLOWED_FILES:
                continue
            for number, line in self.hits(path):
                if relative in ALLOWED_NOTICE_FILES and IGNORED_NOTICE.search(line):
                    continue
                found.append("%s:%d: %s" % (relative, number, line.strip()[:120]))
        self.assertGreater(scanned, 15, "the scan found too few documents; the roots moved")
        self.assertEqual(found, [], "stock Ghidra hooks must not appear in docs/tools; "
                                    "see ALLOWED_FILES for the few deliberate exceptions")

    def test_the_allow_list_has_no_stale_entries(self):
        for relative, reason in ALLOWED_FILES.items():
            path = REPOSITORY / relative
            self.assertTrue(path.is_file(), "%s is allow-listed but no longer exists" % relative)
            self.assertTrue(reason)
            self.assertTrue(self.hits(path), "%s no longer names a stock hook; remove it from ALLOWED_FILES" % relative)
        for relative in ALLOWED_NOTICE_FILES:
            noticed = [line for _, line in self.hits(REPOSITORY / relative) if IGNORED_NOTICE.search(line)]
            self.assertTrue(noticed, "%s no longer carries its 'ignored' notice; remove it from ALLOWED_NOTICE_FILES" % relative)

    def test_the_notice_is_the_only_place_and_it_does_exist(self):
        text = "\n".join(NOTICE_FILE.read_text(encoding="utf-8").splitlines()[n - 1] for n in notice_lines())
        self.assertIn("GHIDRA_INSTALL_DIR", text)
        self.assertIn("ghidra_dir", text)


if __name__ == "__main__":
    unittest.main()
