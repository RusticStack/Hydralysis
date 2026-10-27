"""Matching two builds from their fingerprints."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from rusticre.cli import _checks_file

from rusticre import crossbuild
from support import workdir


def row(rva, *, bytes_="b", shape="s", size=64, instructions=20, strings=(), imports=(), constants=(), callees=(),
        name=None, source="DEFAULT", prologue="48 89 5C 24 08", heads=()):
    return {"rva": rva, "name": name or "FUN_" + rva[2:], "source": source, "size": size, "instructions": instructions,
            "bytes": bytes_, "shape": shape, "strings": list(strings), "imports": list(imports),
            "constants": list(constants), "callees": list(callees), "prologue": prologue, "heads": list(heads)}


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

    def test_three_collisions_remain_ambiguous_and_exclusions_can_leave_one(self):
        source = {r["rva"]: r for r in (row("0x1", bytes_="x"), row("0x2", bytes_="x"), row("0x3", bytes_="x"))}
        destination = {r["rva"]: r for r in (row("0x9", bytes_="x"),)}
        self.assertEqual(crossbuild.match(source, destination), {})
        self.assertEqual(crossbuild._unique(source, lambda item: item["bytes"], {"0x1", "0x2"}), {"x": "0x3"})

    def test_code_that_only_moved_is_identical(self):
        before = row("0x1", bytes_="call+0x10", shape="s", strings=("x",))
        self.assertTrue(crossbuild.identical_code(before, row("0x9", bytes_="call+0x40", shape="s", strings=("x",))))
        self.assertFalse(crossbuild.identical_code(before, row("0x9", bytes_="call+0x40", shape="s", strings=("y",))))
        self.assertFalse(crossbuild.identical_code(before, row("0x9", bytes_="other", shape="t", strings=("x",))))

    def test_a_changed_function_keeps_its_string_head_and_a_removed_one_takes_no_place(self):
        main_a = row("0x100", bytes_="main", shape="main", callees=("0x1", "0x2"), size=200, instructions=60)
        main_b = row("0x900", bytes_="main", shape="main", callees=("0x9",), size=200, instructions=60)
        banner_a = row("0x1", bytes_="b1", shape="t1", size=8, instructions=2, strings=("h1",), heads=("diff fixture",))
        removed = row("0x2", bytes_="r", shape="r", size=31, instructions=9)
        banner_b = row("0x9", bytes_="b2", shape="t2", size=41, instructions=9, strings=("h2",), heads=("diff fixture",))
        pairs = crossbuild.match({r["rva"]: r for r in (main_a, banner_a, removed)},
                                 {r["rva"]: r for r in (main_b, banner_b)})
        self.assertEqual(pairs["0x1"], ("0x9", "strings"))
        self.assertNotIn("0x2", pairs)

    def test_a_destination_claimed_by_two_callers_candidates_is_nobodys(self):
        main_a = row("0x100", bytes_="main", shape="main", callees=("0x1", "0x2"), size=200, instructions=60)
        main_b = row("0x900", bytes_="main", shape="main", callees=("0x9",), size=200, instructions=60)
        one, two = row("0x1", bytes_="p", shape="p", size=30), row("0x2", bytes_="q", shape="q", size=32)
        only = row("0x9", bytes_="z", shape="z", size=31)
        pairs = crossbuild.match({r["rva"]: r for r in (main_a, one, two)}, {r["rva"]: r for r in (main_b, only)})
        self.assertNotIn("0x1", pairs)
        self.assertNotIn("0x2", pairs)

    def test_transfer_checks_are_review_candidates_not_hook_tables(self):
        with workdir("cross") as folder:
            folder = Path(folder)
            source, destination = self.build()
            image = FakeImage()
            checks = folder / "checks.json"
            checks.write_text(json.dumps({"build_sha256": image.digest, "image_base": hex(image.base), "hooks": [
                {"offset": "0x2000", "names": ["Load", "Alias"], "prologue": "4889"},
                {"offset": "0x4000", "names": ["Gone"], "prologue": "4889"}]}))
            prepared = crossbuild._prepare_checks(str(checks), image)
            result = crossbuild.transfer_checks(prepared, crossbuild.match(source, destination), source, destination,
                                               image, image, folder / "out.json")
            self.assertEqual((result["candidates"], result["unplaced"]), (1, 1))
            document = json.loads((folder / "out.json").read_text())
            candidate = document["candidates"][0]
            self.assertEqual(candidate["address"], "rva:0xa000")
            self.assertEqual(candidate["names"], ["Load", "Alias"])
            self.assertEqual(candidate["observed_destination_prologue"], "48 89 " + "90 " * 21 + "90")
            self.assertTrue(candidate["review_required"])
            self.assertNotIn("expect", candidate)
            self.assertNotIn("checks", document)
            with self.assertRaisesRegex(ValueError, "checks file"):
                _checks_file(str(folder / "out.json"), None)
            self.assertTrue(crossbuild._named(source["0x1000"]))
            self.assertFalse(crossbuild._named(destination["0x9000"]))

    def test_va_offsets_and_canonical_addresses_resolve_using_source_base(self):
        with workdir("cross") as folder:
            path = Path(folder) / "checks.json"
            image = FakeImage()
            path.write_text(json.dumps({"image_base": hex(image.base), "hooks": [
                {"offset": "va:0x402000", "names": ["va"], "prologue": "48 89"},
                {"address": "rva:0x2000", "name": "rva", "expect": "48 89"}]}))
            rows = crossbuild._prepare_checks(str(path), image)
            self.assertEqual([item["rva"] for item in rows], ["0x2000", "0x2000"])

    def test_wrong_build_base_or_bytes_fail_before_candidates(self):
        with workdir("cross") as folder:
            path = Path(folder) / "checks.json"
            image = FakeImage()
            table = {"build_sha256": image.digest, "image_base": hex(image.base),
                     "checks": [{"address": "rva:0x2000", "expect": "48 89"}]}
            for key, bad, error in (("build_sha256", "a" * 64, "hash"), ("image_base", "0x1234", "image_base")):
                invalid = dict(table, **{key: bad})
                path.write_text(json.dumps(invalid))
                with self.assertRaisesRegex(ValueError, error):
                    crossbuild._prepare_checks(str(path), image)
            table["checks"][0]["expect"] = "CC"
            path.write_text(json.dumps(table))
            with self.assertRaisesRegex(ValueError, "prologue mismatch"):
                crossbuild._prepare_checks(str(path), image)

    def test_ambiguous_unqualified_address_is_rejected(self):
        image = FakeImage(base=0x1000, mapped={0x2000, 0x3000})
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            crossbuild._source_rva("0x3000", image, None)
        self.assertEqual(crossbuild._source_rva("va:0x3000", image, None), 0x2000)
        self.assertEqual(crossbuild._source_rva("rva:0x3000", image, None), 0x3000)

    def test_job_refuses_invalid_source_before_fingerprinting(self):
        with workdir("cross") as folder:
            path = Path(folder) / "checks.json"
            path.write_text(json.dumps({"hooks": [{"offset": "rva:0x2000", "prologue": "CC"}]}))
            target = {"name": "fixture", "sha256": "e" * 64, "exe": "fixture.exe"}
            record = {"target": "destination", "options": {"against": "source", "checks": str(path)}}
            with patch("rusticre.crossbuild.targets.resolve", return_value=target), \
                 patch("rusticre.crossbuild._target_image", return_value=FakeImage()), \
                 patch("rusticre.crossbuild.fingerprints") as fingerprints:
                with self.assertRaisesRegex(ValueError, "prologue mismatch"):
                    crossbuild.run({}, record, Path(folder) / "output")
                fingerprints.assert_not_called()

    def test_unbacked_destination_is_unplaced(self):
        with workdir("cross") as folder:
            path = Path(folder) / "checks.json"
            image = FakeImage()
            path.write_text(json.dumps([{"address": "rva:0x2000", "expect": "48"}]))
            prepared = crossbuild._prepare_checks(str(path), image)
            source, destination = self.build()
            destination_image = FakeImage(mapped={0x9000})
            result = crossbuild.transfer_checks(prepared, crossbuild.match(source, destination), source, destination,
                                               image, destination_image, Path(folder) / "out.json")
            self.assertEqual((result["candidates"], result["unplaced"]), (0, 1))
            row = json.loads((Path(folder) / "out.json").read_text())["unplaced"][0]
            self.assertIn("file-backed", row["reason"])

    def test_overlay_export_preserves_citations_and_requires_review(self):
        with workdir("cross") as folder:
            source, destination = self.build()
            source_target = {"name": "old", "sha256": "a" * 64}
            dest_target = {"sha256": "b" * 64}
            record = {"id": "f" * 32, "address": "0x402000", "by": "agent", "at": 123,
                      "options": {"kind": "signature", "prototype": "int load(int x)", "source": "trace log 12"}}
            store = {"revision": 3, "edits": [record], "reverted": [{"ids": ["c" * 32]}]}
            with patch("rusticre.workcopy.load_store", return_value=store):
                result = crossbuild._export_overlay_candidates({}, source_target, dest_target,
                          crossbuild.match(source, destination), source, FakeImage(), Path(folder))
            report = json.loads(Path(result["file"]).read_text())
            self.assertEqual(report["edits"][0]["source_record"], record)
            self.assertEqual(report["edits"][0]["candidate"]["destination_address"], "rva:0xa000")
            self.assertEqual(report["reverted"], store["reverted"])
            self.assertTrue(report["review_required"])

    def test_fingerprint_cache_tracks_overlay_revision_and_identity(self):
        with workdir("cross") as folder:
            target = {"name": "fixture", "sha256": "a" * 64, "key": "target"}
            store = {"revision": 1, "edits": [{"id": "1" * 32}]}
            class Runner:
                def __init__(self, settings, engine):
                    self.engine = engine
                def program_for(self, selected):
                    return "program"
            def run_script(engine, program, request, timeout):
                Path(request["options"]["artifact"]).write_text("{}\n")
                return {"ok": True}, ""
            with patch("rusticre.crossbuild.targets.resolve", return_value=target), \
                 patch("rusticre.crossbuild.root_path", return_value=Path(folder)), \
                 patch("rusticre.crossbuild.fingerprint_code", return_value="code"), \
                 patch("rusticre.workcopy.load_store", side_effect=lambda *args: store), \
                 patch("rusticre.query.QueryRunner", Runner), \
                 patch("rusticre.query.run_script", side_effect=run_script):
                first = crossbuild.fingerprints({}, "fixture", engine=object())
                other_view = crossbuild.fingerprints({}, "fixture", engine=object(), view="alice")
                store["revision"] = 2
                store["edits"] = [{"id": "2" * 32}]
                second = crossbuild.fingerprints({}, "fixture", engine=object())
            self.assertNotEqual(first, second)
            self.assertNotEqual(first, other_view)
            self.assertTrue(first.is_file() and second.is_file())

    def test_diff_uses_and_reports_each_selected_view(self):
        with workdir("cross") as folder:
            folder = Path(folder)
            source, destination = self.build()
            for name, rows in (("source", source), ("destination", destination)):
                (folder / (name + ".jsonl")).write_text("".join(json.dumps(row) + "\n" for row in rows.values()), encoding="utf-8")
            targets = {"source": {"name": "source", "sha256": "a" * 64, "key": "source-key"},
                       "destination": {"name": "destination", "sha256": "b" * 64, "key": "destination-key"}}
            seen = []
            def store(settings, target):
                seen.append((target["name"], target["view"]))
                return {"revision": 0, "edits": [], "reverted": []}
            record = {"target": "destination", "view": "alice", "options": {"against": "source", "against_view": "bob"}}
            with patch("rusticre.crossbuild.targets.resolve", side_effect=lambda settings, name: targets[name]), \
                 patch("rusticre.crossbuild.fingerprints", side_effect=lambda settings, name, view="": folder / (name + ".jsonl")) as fingerprints, \
                 patch("rusticre.workcopy.load_store", side_effect=store):
                summary = crossbuild.run({}, record, folder / "output")
            self.assertEqual((summary["source_view"], summary["destination_view"]), ("bob", "alice"))
            self.assertIn(("source", "bob"), seen)
            self.assertIn(("destination", "alice"), seen)
            self.assertEqual([call.kwargs["view"] for call in fingerprints.call_args_list], ["bob", "alice"])

    def test_target_image_checks_registered_hash_and_requires_executable(self):
        with self.assertRaisesRegex(ValueError, "registered executable"):
            crossbuild._target_image({"name": "source", "sha256": "f" * 64})
        with patch("rusticre.crossbuild.Image", return_value=FakeImage()):
            with self.assertRaisesRegex(ValueError, "registered build hash"):
                crossbuild._target_image({"name": "source", "exe": "fake.exe", "sha256": "f" * 64})


class FakeImage:
    def __init__(self, base=0x400000, mapped=None):
        self.base = base
        self.digest = "e" * 64
        self.mapped = mapped if mapped is not None else {0x1000, 0x2000, 0x3000, 0x4000, 0x9000, 0xa000, 0xb000, 0xc000}

    def fingerprint(self):
        return {"sha256": self.digest, "image_base": hex(self.base)}

    def rva_to_offset(self, rva):
        return rva if rva in self.mapped else None

    def _available(self, rva):
        if self.rva_to_offset(rva) is None:
            raise ValueError("outside file-backed sections")
        return 24

    def read_rva(self, rva, size):
        if size > self._available(rva):
            raise ValueError("outside file-backed sections")
        return (b"\x48\x89" + b"\x90" * 22)[:size]


if __name__ == "__main__":
    unittest.main()
