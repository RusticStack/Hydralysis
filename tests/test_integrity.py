"""Header-magic check and quarantine of Hydralysis-owned forks (PROTOCOL-3.md D42, D44, K2, GR2 on hydra.2/3)."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import integrity, query, workcopy
from support import workdir

MAGIC = integrity.GBF_MAGIC


def make_project(folder: Path, name: str = "p", versions=(1,), bad=(), databases=1) -> Path:
    """A project folder shaped like Ghidra's: <name>.gpr, <name>.rep/idata/00/~0000000N.db/db.<N>.gbf."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / (name + ".gpr")).write_text("gpr", encoding="utf-8")
    for index in range(databases):
        database = folder / (name + ".rep") / "idata" / "00" / ("~%08x.db" % index)
        database.mkdir(parents=True, exist_ok=True)
        for number in versions:
            body = (b"\x00" * 8 if number in bad else MAGIC) + bytes([number]) * 64
            (database / ("db.%d.gbf" % number)).write_bytes(body)
    return folder / (name + ".gpr")


def tree(folder: Path) -> dict:
    return {str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(folder.rglob("*")) if path.is_file()}


class Scan(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("integrity")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_a_clean_project_has_no_findings_and_the_scan_writes_nothing(self):
        gpr = make_project(self.root / "clean", versions=(1, 2), databases=3)
        before = tree(self.root / "clean")
        report = integrity.scan(gpr)
        self.assertTrue(report["ok"])
        self.assertEqual((report["databases"], report["versions"]), (3, 6))
        self.assertEqual(tree(self.root / "clean"), before)

    def test_the_magic_is_the_one_valid_files_begin_with(self):
        self.assertEqual(MAGIC.hex(), "2f30312c34292c2a")
        self.assertEqual(MAGIC, b"/01,4),*")

    def test_a_zero_header_newest_version_is_found_with_its_fallback(self):
        gpr = make_project(self.root / "torn", versions=(1, 2), bad=(2,))
        report = integrity.scan(gpr)
        self.assertFalse(report["ok"])
        (found,) = report["newest_invalid"]
        self.assertEqual((found["file"], found["version"], found["previous_valid"]), ("db.2.gbf", 2, "db.1.gbf"))
        self.assertTrue(report["usable"])

    def test_an_invalid_older_version_is_not_a_finding_only_the_newest_matters(self):
        gpr = make_project(self.root / "old", versions=(1, 2), bad=(1,))
        self.assertTrue(integrity.scan(gpr)["ok"])

    def test_a_file_shorter_than_the_magic_is_invalid(self):
        gpr = make_project(self.root / "short", versions=(1, 2))
        (self.root / "short" / "p.rep" / "idata" / "00" / "~00000000.db" / "db.2.gbf").write_bytes(b"/01")
        self.assertFalse(integrity.scan(gpr)["ok"])

    def test_a_database_with_no_version_is_empty_not_damaged(self):
        gpr = make_project(self.root / "new", versions=())
        report = integrity.scan(gpr)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["empty"]), 1)

    def test_only_the_newest_version_of_each_database_counts(self):
        gpr = make_project(self.root / "many", versions=(1, 2, 10), bad=(10,), databases=2)
        report = integrity.scan(gpr)
        self.assertEqual([item["version"] for item in report["newest_invalid"]], [10, 10])  # numeric order, not text


class Quarantine(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("integrity")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_a_disposable_fork_is_repaired_by_moving_the_damaged_version_aside(self):
        gpr = make_project(self.root / "fork", versions=(1, 2), bad=(2,))
        damaged = (self.root / "fork" / "p.rep" / "idata" / "00" / "~00000000.db" / "db.2.gbf").read_bytes()
        result = integrity.quarantine(gpr, disposable=True)
        self.assertEqual(len(result["moved"]), 1)
        self.assertTrue(result["after"]["ok"])
        self.assertFalse((self.root / "fork" / "p.rep" / "idata" / "00" / "~00000000.db" / "db.2.gbf").exists())
        moved = Path(result["moved"][0]["to"])
        self.assertEqual(moved.read_bytes(), damaged)  # moved, never deleted
        self.assertEqual(moved.parent.parent.name, "fork.quarantine")
        self.assertTrue(list((self.root / "fork" / "fork.quarantine").glob("quarantine-*.json")))
        self.assertTrue(integrity.scan(gpr)["ok"])

    def test_the_repair_is_idempotent(self):
        gpr = make_project(self.root / "fork", versions=(1, 2), bad=(2,))
        integrity.quarantine(gpr, disposable=True)
        again = integrity.quarantine(gpr, disposable=True)
        self.assertEqual(again["moved"], [])

    def test_a_project_not_declared_disposable_is_never_written(self):
        gpr = make_project(self.root / "master", versions=(1, 2), bad=(2,))
        before = tree(self.root / "master")
        with self.assertRaises(integrity.CorruptNewest) as raised:
            integrity.quarantine(gpr)
        self.assertEqual(tree(self.root / "master"), before)
        self.assertEqual(raised.exception.payload()["error"], "corrupt_newest")

    def test_a_sealed_project_is_never_written_even_when_declared_disposable(self):
        for marker in ("marker", "sidecar"):
            with self.subTest(seal=marker):
                folder = self.root / ("sealed-" + marker)
                gpr = make_project(folder, versions=(1, 2), bad=(2,))
                if marker == "marker":
                    (folder / "SEALED.json").write_text("{}", encoding="utf-8")
                else:
                    (folder / "p.fork.json").write_text(json.dumps({"purpose": "generation", "state": "complete"}), encoding="utf-8")
                before = tree(folder)
                self.assertTrue(integrity.is_sealed(folder))
                with self.assertRaises(integrity.CorruptNewest):
                    integrity.quarantine(gpr, disposable=True)
                self.assertEqual(tree(folder), before)

    def test_a_candidate_sidecar_is_not_a_seal(self):
        folder = self.root / "candidate"
        make_project(folder, versions=(1,))
        (folder / "p.fork.json").write_text(json.dumps({"purpose": "generation", "state": "candidate"}), encoding="utf-8")
        self.assertFalse(integrity.is_sealed(folder))

    def test_a_database_with_no_valid_version_moves_nothing(self):
        gpr = make_project(self.root / "dead", versions=(1, 2), bad=(1, 2))
        before = tree(self.root / "dead")
        with self.assertRaises(integrity.CorruptNewest):
            integrity.quarantine(gpr, disposable=True)
        self.assertEqual(tree(self.root / "dead"), before)

    def test_check_fork_is_a_noop_on_a_clean_fork(self):
        gpr = make_project(self.root / "ok", versions=(1,))
        before = tree(self.root / "ok")
        self.assertEqual(integrity.check_fork(gpr), {"ok": True, "moved": []})
        self.assertEqual(tree(self.root / "ok"), before)


class BeforeTheEngineOpensIt(unittest.TestCase):
    """The sync checks a view's fork before it asks the engine to open it, and reuses the repaired fork."""

    def setUp(self):
        self.temp = workdir("integrity")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "owned.exe"
        self.exe.write_bytes(b"MZ a small owned executable")
        digest = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.daemon = fakehydra.reset()
        self.gpr = self.root / "analysed" / "Owned" / "Owned.gpr"
        self.daemon.add_project(self.gpr, {"/owned.exe": {"sha256": digest}})
        self.settings = {"root": str(self.root / "data"), "hydra_dir": "x", "hydra_client": "x",
                         "targets": {"owned": {"gpr": str(self.gpr), "program": "/owned.exe", "exe": str(self.exe)}}}
        patcher = patch("hydralysis.hydra.Engine", fakehydra.FakeEngine)
        patcher.start()
        self.addCleanup(patcher.stop)
        query._keys.clear()
        self.runner = query.QueryRunner(self.settings, fakehydra.FakeEngine(self.settings))

    def edit(self, name, expect):
        return json.loads(self.runner.query("owned", "type_edit", "0x140001000", options={
            "kind": "rename", "name": name, "source": "cited test evidence", "expect_revision": expect}))

    def give_the_fork_a_gbf(self, versions, bad):
        state = workcopy._state(self.settings, self.runner.target("owned"))
        folder = Path(state["fork_gpr"]).parent
        make_project(folder, name=Path(state["fork_gpr"]).stem, versions=versions, bad=bad)
        return folder

    def test_a_damaged_newest_version_is_moved_aside_before_the_sync_opens_the_fork(self):
        self.edit("One", 0)
        folder = self.give_the_fork_a_gbf((1, 2), (2,))
        reply = self.edit("Two", 1)
        self.assertEqual(len(reply["sync"]["integrity"]["moved"]), 1)
        self.assertTrue(integrity.scan(folder)["ok"])
        self.assertTrue((folder / (folder.name + ".quarantine")).is_dir())
        self.assertFalse(reply["sync"]["rebuilt"])  # the repaired fork was reused

    def test_a_fork_with_nothing_usable_is_dropped_and_rebuilt_from_the_base_and_the_store(self):
        self.edit("One", 0)
        folder = self.give_the_fork_a_gbf((1,), (1,))
        before = workcopy._state(self.settings, self.runner.target("owned"))["fork_gpr"]
        reply = self.edit("Two", 1)
        self.assertTrue(reply["sync"]["rebuilt"])
        self.assertEqual(reply["sync"]["integrity"]["ok"], False)
        self.assertNotEqual(workcopy._state(self.settings, self.runner.target("owned"))["fork_gpr"], before)
        self.assertEqual(json.loads(self.runner.query("owned", "decompile", "0x140001000"))["function"]["name"], "Two")

    def test_a_damaged_shared_base_is_not_repaired_and_is_rebuilt(self):
        self.edit("One", 0)
        record = workcopy._base_ready(next(path for path in workcopy.bases_root(self.settings).iterdir() if path.is_dir()))
        folder = Path(record["gpr"]).parent
        make_project(folder, name=Path(record["gpr"]).stem, versions=(1, 2), bad=(2,))
        before = tree(folder)
        self.assertIsNone(workcopy._base_ready(folder.parent))  # a base with a damaged newest version is not offered
        self.assertEqual(tree(folder), before)  # and nothing in it was written


if __name__ == "__main__":
    unittest.main()
