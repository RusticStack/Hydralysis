"""Matching two builds from their fingerprints."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from rusticre import crossbuild
from support import workdir


def row(rva, *, bytes_="b", shape="s", size=64, instructions=20, strings=(), imports=(), constants=(), callees=(),
        name=None, source="DEFAULT", prologue="48 89 5C 24 08"):
    return {"rva": rva, "name": name or "FUN_" + rva[2:], "source": source, "size": size, "instructions": instructions,
            "bytes": bytes_, "shape": shape, "strings": list(strings), "imports": list(imports),
            "constants": list(constants), "callees": list(callees), "prologue": prologue}


class Matching(unittest.TestCase):
    def build(self):
        source = {r["rva"]: r for r in (
            row("0x1000", bytes_="same", shape="s1", name="Init", source="USER_DEFINED", callees=("0x3000",)),
            row("0x2000", bytes_="b2", shape="s2", strings=("hello",), name="Load", source="USER_DEFINED"),
            row("0x3000", bytes_="b3", shape="s3", size=40),
            row("0x4000", bytes_="gone", shape="gone"),
        )}
        destination = {r["rva"]: r for r in (
            row("0x9000", bytes_="same", shape="s1", callees=("0xb000",)),
            row("0xa000", bytes_="b2-new", shape="s2-new", strings=("hello",), size=70),
            row("0xb000", bytes_="b3-new", shape="s3-new", size=44),
            row("0xc000", bytes_="new", shape="new"),
        )}
        return source, destination

    def test_phases_place_moved_changed_and_callgraph_matches(self):
        source, destination = self.build()
        pairs = crossbuild.match(source, destination)
        self.assertEqual(pairs["0x1000"], ("0x9000", "exact"))
        self.assertEqual(pairs["0x2000"], ("0xa000", "anchors"))
        self.assertEqual(pairs["0x3000"], ("0xb000", "callgraph"))
        self.assertNotIn("0x4000", pairs)

    def test_ambiguous_candidates_are_never_paired(self):
        source = {r["rva"]: r for r in (row("0x1", bytes_="x"), row("0x2", bytes_="x"))}
        destination = {r["rva"]: r for r in (row("0x9", bytes_="x"),)}
        self.assertEqual(crossbuild.match(source, destination), {})

    def test_report_names_and_prologue_table(self):
        with workdir("cross") as folder:
            folder = Path(folder)
            source, destination = self.build()
            checks = folder / "checks.json"
            checks.write_text(json.dumps([{"name": "Load", "address": "rva:0x2000", "expect": "48"},
                                          {"name": "Gone", "address": "rva:0x4000", "expect": "48"}]))
            pairs = crossbuild.match(source, destination)
            result = crossbuild.transfer_checks(str(checks), pairs, destination, folder / "out.json")
            self.assertEqual((result["placed"], result["unplaced"]), (1, 1))
            placed = json.loads((folder / "out.json").read_text())["checks"][0]
            self.assertEqual(placed["address"], "rva:0xa000")
            self.assertEqual(placed["expect"], "48 89 5C 24 08")
            self.assertTrue(crossbuild._named(source["0x1000"]))
            self.assertFalse(crossbuild._named(destination["0x9000"]))


if __name__ == "__main__":
    unittest.main()
