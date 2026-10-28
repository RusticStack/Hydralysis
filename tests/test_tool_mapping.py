"""The tool-mapping page, the surface counts and the numbers the documents quote (Z13b).

 - the Hydralysis table of docs/tool-mapping.md equals api.TOOL_NAMES, name for name,
 - docs/data/tool-surfaces.json holds the three counts and tools/count_surfaces.py writes them,
 - once the page is declared complete no row says "to verify" (and while it is a skeleton it says so),
 - every "N tools" sentence of the governed documents and the catalog size come from tool_table(),
 - the 8-outstanding-per-lane MCP cap is documented and equals the constant in mcp.py,
 - the dated table of third-party figures labels every row "not reproduced".

The checks are plain functions of text, so the last class plants violations and shows each can fail.
"""

from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

from hydralysis import mcp
from hydralysis.api import TOOL_NAMES, tool_table

REPOSITORY = Path(__file__).resolve().parent.parent
MAPPING = REPOSITORY / "docs" / "tool-mapping.md"
SURFACES = REPOSITORY / "docs" / "data" / "tool-surfaces.json"
VERIFICATION = REPOSITORY / "docs" / "verification.md"
README = REPOSITORY / "README.md"
DOCUMENTS = ("README.md", "THIRD_PARTY.md", "docs/tool-mapping.md")
THIRD_PARTY_HEADING = "## Owner-reported third-party figures"


def load_script():
    spec = importlib.util.spec_from_file_location("count_surfaces", REPOSITORY / "tools" / "count_surfaces.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def section(text: str, heading: str) -> str:
    """The body of the section whose heading line starts with `heading`, up to the next '## '."""
    lines, body, inside = text.splitlines(), [], False
    for line in lines:
        if line.startswith("## "):
            if inside:
                break
            inside = line.startswith(heading)
            continue
        if inside:
            body.append(line)
    return "\n".join(body)


def table_tool_names(text: str) -> list[str]:
    """The tool names in the first column of the '## Hydralysis tools' table, in order."""
    names = []
    for line in section(text, "## Hydralysis tools").splitlines():
        if line.startswith("|") and not line.startswith("| Tool") and not line.startswith("| ---"):
            first = line.split("|")[1]
            names.extend(re.findall(r"`([a-z_]+)`", first))
    return names


def heading_count(text: str) -> int:
    match = re.search(r"^## Hydralysis tools \((\d+)\)", text, re.MULTILINE)
    if not match:
        raise LookupError("no '## Hydralysis tools (N)' heading")
    return int(match.group(1))


def to_verify_rows(text: str) -> list[str]:
    return [line for line in text.splitlines() if re.search(r"to verify", line, re.IGNORECASE)]


def check_completeness(status: str, text: str) -> list[str]:
    rows = to_verify_rows(text)
    if status == "complete" and rows:
        return ["declared complete but %d line(s) still say 'to verify'" % len(rows)]
    if status == "skeleton" and not rows:
        return ["declared a skeleton but no line says 'to verify': declare it complete"]
    if status not in ("skeleton", "complete"):
        return ["unknown status %r" % status]
    return []


def check_tool_counts(text: str, live: int) -> list[str]:
    """Every sentence that gives the size of Hydralysis' own catalog ('registers N tools', 'The N tools',
    'catalog has N tools', 'N tools in about') names the live count."""
    own = re.compile(r"(?:registers|catalog has|[Tt]he) (\d+) tools|(\d+) tools in about")
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        for match in own.finditer(line):
            value = int(match.group(1) or match.group(2))
            if value != live:
                problems.append("line %d: %d tools, the catalog has %d" % (number, value, live))
    return problems


def check_cap_documented(readme: str, outstanding: int, workers: int) -> list[str]:
    flat = " ".join(readme.split())
    wanted = "%d engine workers and accepts %d outstanding calls per lane" % (workers, outstanding)
    problems = [] if wanted in flat else ["README does not say %r" % wanted]
    if "Server busy" not in flat or "retryAfterMs" not in flat:
        problems.append("README does not describe the busy refusal and its retry hint")
    return problems


def check_not_reproduced(text: str) -> list[str]:
    body = section(text, THIRD_PARTY_HEADING)
    if not body:
        return ["no dated third-party section"]
    heading = next(line for line in text.splitlines() if line.startswith(THIRD_PARTY_HEADING))
    problems = [] if re.search(r"\d{4}-\d{2}-\d{2}", heading) else ["the section heading carries no date"]
    rows = [line for line in body.splitlines() if line.startswith("|") and not line.startswith("| ---") and not line.startswith("| Figure")]
    if not rows:
        problems.append("the table has no rows")
    for row in rows:
        if not row.rstrip().rstrip("|").rstrip().endswith("not reproduced"):
            problems.append("row without the label 'not reproduced': %s" % row[:60])
    return problems


class ToolMapping(unittest.TestCase):
    text = ""

    @classmethod
    def setUpClass(cls):
        cls.text = MAPPING.read_text(encoding="utf-8")
        cls.surfaces = json.loads(SURFACES.read_text(encoding="utf-8"))

    def test_the_doc_table_equals_api_tool_names(self):
        names = table_tool_names(self.text)
        self.assertEqual(len(names), len(set(names)), "a tool is listed twice")
        self.assertEqual(sorted(names), sorted(TOOL_NAMES))
        self.assertEqual(heading_count(self.text), len(TOOL_NAMES))
        self.assertEqual([tool["name"] for tool in tool_table()], list(TOOL_NAMES))

    def test_the_surface_counts_equal_their_sources(self):
        counts = {surface["id"]: surface["count"] for surface in self.surfaces["surfaces"]}
        self.assertEqual(set(counts), {"hydralysis", "ghidramcp", "rea"})
        self.assertEqual(counts["hydralysis"], len(tool_table()))
        reproduced = {surface["id"]: surface["reproduced"] for surface in self.surfaces["surfaces"]}
        self.assertEqual(reproduced, {"hydralysis": True, "ghidramcp": False, "rea": False})
        # The page's counts table says the same numbers.
        counts_table = section(self.text, "## Counts, and where each comes from")
        for surface, pattern in (("hydralysis", r"MCP tools \| (\d+) \|"), ("ghidramcp", r"GhidraMCP bridge \| (\d+) "), ("rea", r"\(`reverse-engineer-anything`\) \| (\d+) \|")):
            match = re.search(pattern, counts_table)
            self.assertIsNotNone(match, surface)
            self.assertEqual(int(match.group(1)), counts[surface], surface)

    def test_the_script_writes_the_three_counts_and_check_agrees(self):
        script = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "tool-surfaces.json"
            self.assertEqual(script.main(["--output", str(out)]), 0)
            written = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual([(s["id"], s["count"]) for s in written["surfaces"]],
                             [(s["id"], s["count"]) for s in self.surfaces["surfaces"]])
            self.assertEqual(script.main(["--check", "--output", str(out)]), 0)
            out.write_text(out.read_text(encoding="utf-8").replace('"count": 20', '"count": 21'), encoding="utf-8")
            self.assertEqual(script.main(["--check", "--output", str(out)]), 1)
        self.assertEqual(script.main(["--check"]), 0, "docs/data/tool-surfaces.json is out of date: run tools/count_surfaces.py")

    def test_the_script_recounts_the_bridge_and_the_skill_metadata_when_given_them(self):
        script = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            server = Path(tmp) / "server.py"
            server.write_text("@mcp.tool()\ndef a(): pass\n\n@mcp.tool()\ndef b(): pass\n# @mcp.tool() in a comment\n", encoding="utf-8")
            meta = Path(tmp) / "meta.json"
            meta.write_text(json.dumps({"tool_count": 11}), encoding="utf-8")
            result = script.compute(self.surfaces, server, meta)
            counts = {s["id"]: s["count"] for s in result["surfaces"]}
            self.assertEqual(counts, {"hydralysis": len(TOOL_NAMES), "ghidramcp": 2, "rea": 11})

    def test_no_row_says_to_verify_once_declared_complete(self):
        self.assertEqual(check_completeness(self.surfaces["status"], self.text), [])

    def test_the_catalog_size_and_tool_count_in_the_documents_come_from_tool_table(self):
        live = len(tool_table())
        for relative in DOCUMENTS:
            text = (REPOSITORY / relative).read_text(encoding="utf-8")
            self.assertEqual(check_tool_counts(text, live), [], relative)
        size = len(json.dumps(tool_table()).encode("utf-8"))
        flat = " ".join(README.read_text(encoding="utf-8").split())
        self.assertIn("{:,} bytes as the catalog test counts them".format(size), flat)

    def test_the_mcp_cap_is_documented_and_is_the_code_constant(self):
        self.assertEqual(check_cap_documented(README.read_text(encoding="utf-8"), mcp.MAX_OUTSTANDING, mcp.TOOL_WORKERS), [])
        self.assertEqual(mcp.RETRY_AFTER_MS, 2000)
        self.assertIn("retryAfterMs=%d" % mcp.RETRY_AFTER_MS, README.read_text(encoding="utf-8"))

    def test_third_party_figures_are_dated_and_labelled_not_reproduced(self):
        self.assertEqual(check_not_reproduced(VERIFICATION.read_text(encoding="utf-8")), [])
        # Every non-reproduced surface appears in that table with the count the data file holds.
        body = section(VERIFICATION.read_text(encoding="utf-8"), THIRD_PARTY_HEADING)
        owner = {s["id"]: s for s in self.surfaces["surfaces"]}
        self.assertIn("%d GhidraMCP tools" % owner["ghidramcp"]["owner_reported"], body)
        self.assertIn("%d tools in `reverse-engineer-anything`" % owner["rea"]["count"], body)


class TheChecksCanFail(unittest.TestCase):
    def test_a_missing_extra_or_duplicate_tool_in_the_table_is_seen(self):
        text = chr(10).join(MAPPING.read_text(encoding="utf-8").splitlines())
        self.assertEqual(sorted(table_tool_names(text)), sorted(TOOL_NAMES))
        removed = text.replace("| `runtime` | Controlled local runtime sessions |\n", "")
        self.assertNotEqual(sorted(table_tool_names(removed)), sorted(TOOL_NAMES))
        extra = text.replace("| `runtime` |", "| `runtime`, `frida_attach` |")
        self.assertNotEqual(sorted(table_tool_names(extra)), sorted(TOOL_NAMES))
        doubled = text.replace("| `runtime` |", "| `runtime`, `job` |")
        names = table_tool_names(doubled)
        self.assertNotEqual(len(names), len(set(names)))

    def test_to_verify_after_complete_and_a_stale_skeleton_are_seen(self):
        self.assertTrue(check_completeness("complete", "| a | Covered |\n| b | Gap; to verify |\n"))
        self.assertEqual(check_completeness("complete", "| a | Covered |\n"), [])
        self.assertTrue(check_completeness("skeleton", "| a | Covered |\n"))
        self.assertTrue(check_completeness("done", "x"))

    def test_a_wrong_tool_count_is_seen(self):
        self.assertTrue(check_tool_counts("Hydralysis registers 19 tools.", 20))
        self.assertTrue(check_tool_counts("20 tools in about 8 KB of schema; the catalog has 21 tools", 20))
        self.assertEqual(check_tool_counts("Hydralysis registers 20 tools. REA has 207 tools.", 20), [])

    def test_a_missing_or_changed_cap_sentence_is_seen(self):
        good = "4 engine workers and accepts 8 outstanding calls per lane. Server busy retryAfterMs=2000"
        self.assertEqual(check_cap_documented(good, 8, 4), [])
        self.assertTrue(check_cap_documented(good.replace("8 outstanding", "16 outstanding"), 8, 4))
        self.assertTrue(check_cap_documented("nothing", 8, 4))
        self.assertTrue(check_cap_documented(good.replace("Server busy", "busy"), 8, 4))

    def test_an_unlabelled_or_undated_third_party_row_is_seen(self):
        good = "## Owner-reported third-party figures, 2026-10-28\n\n| Figure | By | Here | Status |\n| --- | --- | --- | --- |\n| 28 tools | owner | 30 | not reproduced |\n"
        self.assertEqual(check_not_reproduced(good), [])
        self.assertTrue(check_not_reproduced(good.replace("not reproduced", "confirmed")))
        self.assertTrue(check_not_reproduced(good.replace(", 2026-10-28", "")))
        self.assertTrue(check_not_reproduced("## Other\n"))
        self.assertTrue(check_not_reproduced(good.split("| 28")[0]))


if __name__ == "__main__":
    unittest.main()
