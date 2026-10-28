"""Surface parity against the linker-map ground truth of the MSVC fixtures (x86 and x64): PR 6 row C1-44.

The GhidraMCP rows of docs/tool-mapping.md move from "to verify" to tested, or to an explicit documented gap.
Each row names the Hydralysis operation that answers it and the check that proves the answer against ground
truth the tool under test did not produce: the linker map (function and import addresses), the C sources (call
edges, string literals), and the PE headers parsed with struct.

Always run: the row table (every GhidraMCP tool of the mapping has a verdict and a check that exists) and the
helpers that read the ground truth.

Run only with the fixtures prepared (docs/verification-fixtures.md): HYDRALYSIS_FIXTURES names the build output
directory holding manifest.json (tests/fixtures/build_fixtures.py), and HYDRALYSIS_CONFIG the data root in which
tests/fixtures/prepare_fixtures.py made the fx-<arch>-<name>-<sha8> targets. The same checks run as
    python tests/fixtures/verify_fixtures.py <dir> listing callgraph namemap
and exit 0 when every one passes.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import sys
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY / "tests" / "fixtures"))

FIXTURES = os.environ.get("HYDRALYSIS_FIXTURES", "")

# GhidraMCP tool -> (verdict, the verify_fixtures check that proves it, or the reason for the gap).
# Verdicts: tested (equal to ground truth), partial (tested; the equivalent answers a narrower question),
# gap (no equivalent; the absence is tested), gui (needs a GUI, out of scope for a headless server),
# unchecked (outside C1-44: edit semantics; no parity claim is made here).
PARITY = {
    "get_program_info": ("partial", "listing/metadata: identity (sha256, image base, bits) equals the build; no memory-block or language summary"),
    "list_functions": ("tested", "listing/functions: paged listing equals the 200-row paging; the linker map's functions are listed"),
    "list_methods": ("partial", "listing/bounds: class methods are functions with exact bounds; names stay FUN_<address> (no PDB)"),
    "search_functions_by_name": ("partial", "listing/search: contains matches the analysis name; a map name finds nothing until read through name:<name>"),
    "list_classes": ("gap", "documented_gaps: no class action; vtables and RTTI labels are read per address (listing/data)"),
    "list_namespaces": ("gap", "documented_gaps: no namespace action"),
    "list_segments": ("partial", "listing/segments: PE sections equal the header; Ghidra memory blocks are not listed"),
    "list_imports": ("tested", "listing/imports: equals the linker map's __imp_ rows"),
    "list_exports": ("partial", "listing/exports: empty export table of the fixtures (a non-empty table is not covered by a fixture)"),
    "list_data_items": ("partial", "listing/data: per address only (no enumeration); RTTI vftable labels equal the map names"),
    "list_strings": ("tested", "listing/strings: the source literals, at their bytes"),
    "get_function_by_address": ("tested", "callgraph/function_by_address: an address inside a body answers the entry"),
    "get_current_address": ("gui", "no equivalent: GUI-only"),
    "get_current_function": ("gui", "no equivalent: GUI-only"),
    "decompile_function": ("partial", "namemap/decompile_by_name: through a cited address map, name:<name> decompiles the function of the address form"),
    "decompile_function_by_address": ("tested", "namemap/decompile_by_name: the address form is the reference of the by-name check"),
    "disassemble_function": ("partial", "namemap: instruction bytes of the analysis equal the file bytes (scan); disasm itself is unit-tested elsewhere"),
    "get_xrefs_to": ("tested", "callgraph/xrefs_to: callers equal the call sites; other references are not calls"),
    "get_xrefs_from": ("tested", "callgraph/callees: the callee edges of the dossier, with sites inside the body"),
    "get_function_xrefs": ("tested", "callgraph/xrefs_to and callgraph/callees"),
    "get_function_calls": ("tested", "callgraph/callees: the edges of the C sources, plus pe_callgraph for the PE-only tools"),
    "read_memory": ("partial", "namemap: bytes equal the file bytes at the mapped address; the analysis' instruction bytes agree; documented_gaps: Ghidra memory has no read action"),
    "rename_function_by_address": ("unchecked", "type_edit rename: different semantics (cited overlay); outside C1-44"),
    "rename_function": ("unchecked", "type_edit rename: different semantics; outside C1-44"),
    "rename_data": ("unchecked", "type_edit label: different semantics; outside C1-44"),
    "rename_variable": ("unchecked", "type_edit variable: outside C1-44"),
    "set_function_prototype": ("unchecked", "type_edit signature: outside C1-44"),
    "set_local_variable_type": ("unchecked", "type_edit variable: outside C1-44"),
    "set_decompiler_comment": ("unchecked", "type_edit comment: outside C1-44"),
    "set_disassembly_comment": ("unchecked", "type_edit comment: outside C1-44"),
}
VERDICTS = {"tested", "partial", "gap", "gui", "unchecked"}


class ParityTable(unittest.TestCase):
    def test_thirty_ghidramcp_tools_each_have_a_verdict(self):
        self.assertEqual(len(PARITY), 30)
        for tool, (verdict, evidence) in PARITY.items():
            self.assertIn(verdict, VERDICTS, tool)
            self.assertTrue(evidence.strip(), tool)

    def test_the_mapping_document_names_every_row(self):
        text = (REPOSITORY / "docs" / "tool-mapping.md").read_text(encoding="utf-8")
        for tool in PARITY:
            self.assertIn("`%s`" % tool, text, tool)

    def test_every_check_a_row_cites_exists_in_the_harness(self):
        import verify_fixtures
        for group in ("listing", "callgraph", "namemap"):
            self.assertIn(group, verify_fixtures.CHECKS)
        source = Path(verify_fixtures.__file__).read_text(encoding="utf-8")
        labels = set(re.findall(r'_check\("([a-z_]+)', source))
        for tool, (_, evidence) in PARITY.items():
            for group, label in re.findall(r"(listing|callgraph|namemap|documented_gaps)/([a-z_]+)", evidence):
                self.assertIn(group, verify_fixtures.CHECKS, tool)
                self.assertIn(label, labels, "%s cites %s/%s, which the harness never prints" % (tool, group, label))

    def test_documented_gaps_are_the_rows_the_mapping_calls_gaps(self):
        self.assertEqual({tool for tool, (verdict, _) in PARITY.items() if verdict == "gap"}, {"list_classes", "list_namespaces"})


class GroundTruthHelpers(unittest.TestCase):
    """The ground-truth readers, on a file whose answers are known without Hydralysis."""

    def test_section_table_and_file_bytes_of_a_system_executable(self):
        import verify_fixtures
        path = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "whoami.exe"
        if not path.is_file():
            self.skipTest("no whoami.exe")
        sections = verify_fixtures._sections(str(path))
        self.assertIn(".text", [s["name"] for s in sections])
        data = path.read_bytes()
        text = next(s for s in sections if s["name"] == ".text")
        self.assertEqual(verify_fixtures._file_bytes(str(path), text["rva"], 8), data[text["raw_ptr"]: text["raw_ptr"] + 8])
        past = verify_fixtures._file_bytes(str(path), text["rva"] + text["raw_size"] - 1, 4) if text["vsize"] > text["raw_size"] else None
        if past is not None:
            self.assertEqual(past[1:], b"\0\0\0")

    def test_ground_truth_tables_agree_with_the_fixture_sources(self):
        import verify_fixtures
        sources = {name: (REPOSITORY / "tests" / "fixtures" / name).read_text(encoding="utf-8")
                   for name in ("flow_fixture.c", "diff_fixture.c", "vcall_fixture.cpp")}
        for caller, callees in verify_fixtures.EDGES["flow_fixture.exe"].items():
            for callee in callees:
                self.assertRegex(sources["flow_fixture.c"], r"\b%s\b" % callee)
        for caller, callees in verify_fixtures.EDGES["diff2.exe"].items():
            for callee in callees:
                self.assertRegex(sources["diff_fixture.c"], r"\b%s\(" % callee)
        for literal in verify_fixtures.LITERALS["diff1.exe"] + verify_fixtures.LITERALS["diff2.exe"]:
            self.assertIn(literal, sources["diff_fixture.c"])


@unittest.skipUnless(FIXTURES and (Path(FIXTURES) / "manifest.json").is_file(),
                     "HYDRALYSIS_FIXTURES (built fixtures; docs/verification-fixtures.md) is not set")
class FixtureParity(unittest.TestCase):
    """PR 6 C1-44 against the engine: one test per harness group, each exit 0 with every line PASS."""

    @classmethod
    def setUpClass(cls):
        import verify_fixtures
        cls.harness = verify_fixtures
        cls.manifest = verify_fixtures.load(FIXTURES)

    def run_group(self, group):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            failures = self.harness.CHECKS[group](self.manifest)
        report = buffer.getvalue()
        self.assertEqual(failures, [], report)
        self.assertGreaterEqual(report.count("PASS "), 8, report)
        return report

    def test_listing_group(self):
        report = self.run_group("listing")
        for label in ("metadata", "functions", "bounds", "search", "segments", "imports", "exports", "strings", "data"):
            self.assertIn("PASS %s x64" % label, report)
            self.assertIn("PASS %s x86" % label, report)

    def test_callgraph_group(self):
        report = self.run_group("callgraph")
        for label in ("callees", "xrefs_to", "pe_callgraph", "function_by_address"):
            self.assertIn("PASS %s x64" % label, report)
            self.assertIn("PASS %s x86" % label, report)

    def test_namemap_group(self):
        report = self.run_group("namemap")
        for label in ("namemap", "decompile_by_name", "namemap_refusals", "documented_gaps"):
            self.assertIn("PASS %s x64" % label, report)
            self.assertIn("PASS %s x86" % label, report)


if __name__ == "__main__":
    unittest.main()
