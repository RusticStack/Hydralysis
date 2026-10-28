"""Evidence bundles: export, verify, compare, import, and the limits that keep game payloads out (Z9)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from hydralysis import api, evidence, evidence_bundle
from hydralysis.evidence_bundle import BundleError
from support import REPOSITORY, workdir

POPULATE = """
import sys
from pathlib import Path
from hydralysis.evidence import add_claim
db = Path(sys.argv[1])
extra = sys.argv[2:]
add_claim(db, game="cp", build="2.31", kind="function", name="ForceMoveTo", address="rva:0x1a5f14",
          note="moves the vehicle", source="decompile line 12", subsystem="vehicles")
add_claim(db, game="cp", build="2.5", kind="function", name="ForceMoveTo", address="rva:0x2e3270",
          note="moves the vehicle", source="decompile line 40", subsystem="vehicles", supersedes=1,
          coverage={"status": "partial", "limitations": ["static_only", "indirect_calls_unresolved"]})
add_claim(db, game="cp", build="2.5", kind="probe", name="hit count", address="rva:0x2e3270",
          note="three hits in the fixture", source="runtime observe", subsystem="vehicles",
          authority="controlled-replay", confidence="observed", from_capture="cap_one",
          coverage={"status": "complete"}, parameters={"script_sha256": "ab" * 32}, limitations=["fixture_only"])
for index, item in enumerate(extra):
    add_claim(db, game="cp", build="2.5", kind="field", name="extra-%s" % item, note="n", source="s", subsystem="vehicles")
"""
MANY = """
import sys
from pathlib import Path
from hydralysis.evidence import add_claim
for index in range(int(sys.argv[2])):
    add_claim(Path(sys.argv[1]), game="cp", build="2.5", kind="field", name="busy-%d" % index, note="n", source="s",
              subsystem="vehicles")
"""
CAPTURE = {"capture_id": "cap_one", "events": [{"seq": 1, "rva": "0x2e3270", "args_hex": "00ff10"}], "dropped_events": 0}


def populate(db: Path, *extra: str, harness="writer"):
    env = dict(os.environ, PYTHONPATH=str(REPOSITORY / "src"), HYDRALYSIS_HARNESS=harness)
    done = subprocess.run([sys.executable, "-c", POPULATE, str(db), *extra], env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr[-3000:]


class Bundles(unittest.TestCase):
    def setUp(self):
        self.work = workdir("evbundle")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.db = self.root / "a.db"
        self.captures = self.root / "captures-in"
        self.captures.mkdir()
        (self.captures / "cap_one.json").write_text(json.dumps(CAPTURE), encoding="utf-8")

    def export(self, name="bundle", db=None, **options):
        return evidence_bundle.export_bundle(db or self.db, self.root / name, captures_dir=self.captures, **options)

    def mutate(self, folder: Path, name: str, change):
        file = folder / name
        file.write_bytes(change(file.read_bytes()))


class ExportAndVerify(Bundles):
    def test_a_bundle_exports_and_verifies(self):
        populate(self.db)
        result = self.export()
        self.assertEqual((result["records"], result["captures"], result["missing_captures"]), (3, 1, []))
        folder = self.root / "bundle"
        names = sorted(str(path.relative_to(folder)).replace("\\", "/") for path in folder.rglob("*") if path.is_file())
        self.assertEqual(names, ["captures/cap_one.json", "environment.json", "evidence.jsonl", "limitations.md",
                                 "manifest.json", "replay.json", "subjects.json"])
        verdict = evidence_bundle.verify_bundle(folder)
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(verdict["bundle_id"], result["bundle_id"])
        self.assertRegex(result["bundle_id"], r"^eb_[0-9a-f]{64}$")
        self.assertEqual(verdict["limitations"], ["coverage_unknown", "fixture_only", "indirect_calls_unresolved", "static_only"])
        manifest = json.loads((folder / "manifest.json").read_text())
        self.assertEqual(manifest["format"], evidence_bundle.FORMAT)
        self.assertEqual(set(manifest["files"]), {name for name in names if name != "manifest.json"})
        text = (folder / "limitations.md").read_text()
        self.assertIn("`static_only`", text)
        self.assertIn("(bounds coverage)", text)
        replay = json.loads((folder / "replay.json").read_text())
        self.assertEqual([item["name"] for item in replay["scenarios"]], ["hit count"])

    def test_the_selection_filters_and_an_empty_selection_is_refused(self):
        populate(self.db, "x")
        self.assertEqual(self.export("only-25", build="2.5")["records"], 3)
        with self.assertRaises(BundleError) as caught:
            self.export("none", game="no-such-game")
        self.assertEqual(caught.exception.code, "empty_selection")
        self.assertFalse((self.root / "none").exists())

    def test_a_citation_without_its_capture_is_named_not_hidden(self):
        populate(self.db)
        empty = self.root / "no-captures"
        empty.mkdir()
        result = evidence_bundle.export_bundle(self.db, self.root / "b", captures_dir=empty)
        self.assertEqual(result["missing_captures"], ["cap_one"])
        self.assertEqual(evidence_bundle.verify_bundle(self.root / "b")["missing_captures"], ["cap_one"])

    def test_export_replaces_a_bundle_only_when_told_to_and_never_a_foreign_folder(self):
        populate(self.db)
        self.export()
        with self.assertRaises(BundleError) as caught:
            self.export()
        self.assertEqual(caught.exception.code, "bundle_exists")
        self.assertEqual(self.export(overwrite=True)["records"], 3)
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "mine.txt").write_text("keep")
        with self.assertRaises(BundleError) as caught:
            evidence_bundle.export_bundle(self.db, foreign, overwrite=True)
        self.assertEqual(caught.exception.code, "not_a_bundle")
        self.assertEqual((foreign / "mine.txt").read_text(), "keep")
        self.assertEqual([path.name for path in self.root.iterdir() if path.name.endswith((".staging", ".old"))], [])

    def test_an_export_beside_a_busy_writer_is_a_consistent_snapshot(self):
        populate(self.db)
        env = dict(os.environ, PYTHONPATH=str(REPOSITORY / "src"))
        writer = subprocess.Popen([sys.executable, "-c", MANY, str(self.db), "150"],
                                  env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            for index in range(3):
                self.export("snap%d" % index, overwrite=True)
                self.assertTrue(evidence_bundle.verify_bundle(self.root / ("snap%d" % index))["ok"])
        finally:
            _, error = writer.communicate(timeout=120)
        self.assertEqual(writer.returncode, 0, error.decode()[-3000:])


class Tampering(Bundles):
    def setUp(self):
        super().setUp()
        populate(self.db)
        self.export()
        self.folder = self.root / "bundle"

    def code(self):
        return evidence_bundle.verify_bundle(self.folder)

    def test_a_flipped_byte_in_any_file_is_caught(self):
        for name in ("evidence.jsonl", "subjects.json", "replay.json", "limitations.md", "environment.json",
                     "captures/cap_one.json"):
            pristine = (self.folder / name).read_bytes()
            self.mutate(self.folder, name, lambda data: data[:20] + bytes([data[20] ^ 1]) + data[21:])
            verdict = self.code()
            self.assertFalse(verdict["ok"], name)
            self.assertEqual(verdict["error"], "bundle_file_changed", name)
            (self.folder / name).write_bytes(pristine)
        self.assertTrue(self.code()["ok"])

    def test_a_record_changed_with_the_manifest_repaired_still_fails_its_evidence_id(self):
        path = self.folder / "evidence.jsonl"
        lines = path.read_text().splitlines()
        record = json.loads(lines[0])
        record["content"]["note"] = record["content"]["note"] + "!"
        lines[0] = evidence.canonical_json(record)
        data = ("\n".join(lines) + "\n").encode()
        path.write_bytes(data)
        manifest = json.loads((self.folder / "manifest.json").read_text())
        import hashlib
        manifest["files"]["evidence.jsonl"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        (self.folder / "manifest.json").write_text(json.dumps(manifest))
        verdict = self.code()
        self.assertEqual((verdict["ok"], verdict["error"]), (False, "evidence_mismatch"))

    def test_a_wrong_bundle_id_an_extra_file_a_missing_file_and_a_foreign_path_are_refused(self):
        manifest_path = self.folder / "manifest.json"
        pristine = manifest_path.read_text()
        manifest = json.loads(pristine)
        manifest["bundle_id"] = "eb_" + "0" * 64
        manifest_path.write_text(json.dumps(manifest))
        self.assertEqual(self.code()["error"], "bundle_id_mismatch")
        manifest_path.write_text(pristine)
        (self.folder / "stray.txt").write_text("x")
        self.assertEqual(self.code()["error"], "bundle_unlisted_file")
        (self.folder / "stray.txt").unlink()
        (self.folder / "replay.json").unlink()
        self.assertEqual(self.code()["error"], "bundle_file_missing")
        shutil.copy(self.root / "bundle" / "limitations.md", self.root / "bundle" / "replay.json")
        manifest = json.loads(pristine)
        manifest["files"]["../outside.json"] = {"bytes": 1, "sha256": "0" * 64}
        manifest_path.write_text(json.dumps(manifest))
        self.assertEqual(self.code()["error"], "bundle_path_refused")
        manifest_path.write_text("{")
        self.assertEqual(self.code()["error"], "bundle_manifest_invalid")
        self.assertEqual(evidence_bundle.verify_bundle(self.root / "nowhere")["error"], "bundle_missing")

    def test_a_derived_file_that_says_something_else_is_refused(self):
        replay = self.folder / "replay.json"
        replay.write_bytes(b'{"missing_captures":[],"scenarios":[]}\n')
        manifest = json.loads((self.folder / "manifest.json").read_text())
        import hashlib
        manifest["files"]["replay.json"] = {"bytes": replay.stat().st_size, "sha256": hashlib.sha256(replay.read_bytes()).hexdigest()}
        (self.folder / "manifest.json").write_text(json.dumps(manifest))
        self.assertEqual(self.code()["error"], "bundle_derived_mismatch")


def forge_bundle(folder: Path, records: list[dict]) -> None:
    """Write a bundle whose every hash, derived file and bundle_id is consistent with `records` as given."""
    import hashlib
    records = sorted(records, key=lambda record: record["evidence_id"])
    subjects = evidence_bundle._subjects(records)
    replay = evidence_bundle._replay(records, set())
    limitations = evidence_bundle._limitations(records)
    files = {"evidence.jsonl": evidence_bundle._jsonl(records), "subjects.json": evidence_bundle._json_bytes(subjects),
             "replay.json": evidence_bundle._json_bytes(replay), "environment.json": evidence_bundle._json_bytes({}),
             "limitations.md": evidence_bundle._limitations_md(limitations)}
    manifest = {"format": evidence_bundle.FORMAT,
                "bundle_id": evidence_bundle.bundle_id_of(records, subjects, {}, replay, limitations),
                "records": len(records), "filter": {"game": "", "subsystem": "", "build": ""},
                "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                          for name, data in sorted(files.items())},
                "volatile": {"exported_at": "2026-01-01T00:00:00Z", "files": []}}
    files["manifest.json"] = evidence_bundle._json_bytes(manifest)
    for name, data in files.items():
        (folder / name).parent.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(data)


def hash_valid_record(**changes) -> dict:
    """A record whose evidence_id is the true hash of its (possibly invalid) content."""
    base = dict(game="cp", build="2.5", kind="field", name="forged", note="n", source="s", address="rva:0x10")
    content = evidence.build_content(**base)
    content.update(changes)
    return {"evidence_id": evidence.compute_evidence_id(content), "content": content, "meta": {}}


class ForgedRecords(Bundles):
    """A bundle can be hash-consistent and still break the evidence model; none of it may reach a ledger."""

    CASES = {
        "complete coverage beside a bounding limitation":
            dict(coverage={"status": "complete"}, limitations=["event_ring_overflow"]),
        "an unknown confidence": dict(confidence="bogus"),
        "an integer address": dict(address=5),
        "an unknown authority": dict(authority="trust-me"),
        "an unsorted limitation list": dict(coverage={"status": "unknown", "reason": "r"},
                                            limitations=["coverage_unknown", "coverage_unknown"]),
        "a parameters value that is not an object": dict(parameters=["x"]),
        "a link that is not an evidence id": dict(evidence_links=["not-an-id"]),
        "an empty note": dict(note=""),
        "a boolean where a string belongs": dict(name=True),
    }

    def test_each_hash_valid_but_invalid_record_fails_verify_and_import_and_leaves_the_ledger_empty(self):
        for label, changes in self.CASES.items():
            with self.subTest(label):
                record = hash_valid_record(**changes)
                folder = self.root / "forged"
                shutil.rmtree(folder, ignore_errors=True)
                folder.mkdir()
                forge_bundle(folder, [record])
                verdict = evidence_bundle.verify_bundle(folder)
                self.assertFalse(verdict["ok"], verdict)
                self.assertEqual(verdict["error"], "evidence_content_invalid", verdict)
                target = self.root / "forged.db"
                if target.exists():
                    target.unlink()
                with self.assertRaises(BundleError):
                    evidence_bundle.import_bundle(folder, target)
                with self.assertRaises(evidence.EvidenceIntegrityError):  # the library is guarded on its own too
                    evidence.import_records(target, [record])
                self.assertEqual(evidence.query(target), [])
                self.assertEqual(evidence.verify_ledger(target)["failed"], [])

    def test_the_forged_bundle_of_the_review_is_refused_and_a_valid_one_still_imports(self):
        good = hash_valid_record()
        folder = self.root / "mixed"
        folder.mkdir()
        forge_bundle(folder, [good])
        self.assertTrue(evidence_bundle.verify_bundle(folder)["ok"])
        target = self.root / "mixed.db"
        self.assertEqual(evidence_bundle.import_bundle(folder, target)["added"], 1)
        bad = hash_valid_record(name="forged-two", address=5, confidence="bogus",
                                coverage={"status": "complete"}, limitations=["event_ring_overflow"])
        folder2 = self.root / "mixed2"
        folder2.mkdir()
        forge_bundle(folder2, [good, bad])
        with self.assertRaises(BundleError):
            evidence_bundle.import_bundle(folder2, target)
        self.assertEqual(len(evidence.query(target)), 1)  # the ledger is as it was, and still readable

    def test_meta_that_is_not_an_object_is_a_bundle_error_with_a_code(self):
        for meta in ("text", {"provenance": "x"}, {"created": 5}, {"harness": ["x"]}):
            with self.subTest(meta=meta):
                record = hash_valid_record()
                record["meta"] = meta
                folder = self.root / "meta"
                shutil.rmtree(folder, ignore_errors=True)
                folder.mkdir()
                forge_bundle(folder, [record])
                verdict = evidence_bundle.verify_bundle(folder)
                self.assertEqual((verdict["ok"], verdict["error"]), (False, "bundle_meta_invalid"), verdict)
                with self.assertRaises(evidence.EvidenceIntegrityError):
                    evidence.import_records(self.root / "meta.db", [record])


class Compare(Bundles):
    def test_two_independent_exports_compare_equal_modulo_volatile_fields(self):
        first, second = self.root / "one.db", self.root / "two.db"
        populate(first, harness="client-alpha")
        populate(second, harness="client-beta")
        self.export("one", db=first)
        self.export("two", db=second)
        result = evidence_bundle.compare_bundles(self.root / "one", self.root / "two")
        self.assertEqual(result["status"], "equal", result)
        self.assertEqual(result["left_bundle_id"], result["right_bundle_id"])
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["summary"]["records_unchanged"], 3)
        # the volatile part did differ (the writer's name is in evidence.jsonl), and the comparison says so
        self.assertIn("evidence.jsonl", result["volatile_ignored"]["files_differing"])
        self.assertNotEqual((self.root / "one" / "evidence.jsonl").read_bytes(), (self.root / "two" / "evidence.jsonl").read_bytes())

    def test_a_different_bundle_is_classified(self):
        first, second = self.root / "one.db", self.root / "two.db"
        populate(first)
        populate(second, "more")
        evidence.add_claim(second, game="cp", build="2.6", kind="function", name="ForceMoveTo", address="rva:0x3",
                           note="moved again", source="s", subsystem="vehicles")
        self.export("one", db=first)
        self.export("two", db=second)
        result = evidence_bundle.compare_bundles(self.root / "one", self.root / "two")
        self.assertEqual(result["status"], "different")
        by_key = {item["key"]: item for item in result["changes"] if item["entity"] == "evidence"}
        self.assertEqual({item["classification"] for item in by_key.values()}, {"added"})
        self.assertEqual(result["summary"]["records_added"], 2)
        reverse = evidence_bundle.compare_bundles(self.root / "two", self.root / "one")
        self.assertEqual(reverse["summary"]["records_removed"], 2)

    def test_a_changed_claim_and_a_changed_capture_are_named(self):
        first, second = self.root / "one.db", self.root / "two.db"
        populate(first)
        populate(second)
        # the same claim with a different statement of coverage: same logical key, new id
        evidence.add_claim(first, game="cp", build="2.5", kind="probe", name="hit count", address="rva:0x2e3270",
                           note="four hits", source="runtime observe", subsystem="vehicles")
        evidence.add_claim(second, game="cp", build="2.5", kind="probe", name="hit count", address="rva:0x2e3270",
                           note="five hits", source="runtime observe", subsystem="vehicles")
        self.export("one", db=first)
        other = self.root / "captures-two"
        other.mkdir()
        (other / "cap_one.json").write_text(json.dumps(dict(CAPTURE, dropped_events=3)), encoding="utf-8")
        evidence_bundle.export_bundle(second, self.root / "two", captures_dir=other)
        result = evidence_bundle.compare_bundles(self.root / "one", self.root / "two")
        kinds = {(item["entity"], item["classification"]) for item in result["changes"]}
        self.assertIn(("evidence", "changed"), kinds)
        self.assertIn(("capture", "changed"), kinds)
        self.assertEqual(result["status"], "different")

    def test_compare_refuses_a_bundle_that_does_not_verify(self):
        populate(self.db)
        self.export("one")
        self.export("two")
        self.mutate(self.root / "two", "subjects.json", lambda data: data + b" ")
        with self.assertRaises(BundleError):
            evidence_bundle.compare_bundles(self.root / "one", self.root / "two")


class Import(Bundles):
    def test_a_bundle_imports_into_another_ledger_with_its_history(self):
        populate(self.db)
        self.export()
        target = self.root / "c.db"
        summary = evidence_bundle.import_bundle(self.root / "bundle", target)
        self.assertEqual((summary["added"], summary["already_present"], summary["dangling_links"]), (3, 0, 0))
        rows = evidence.query(target, include_superseded=True)
        self.assertEqual({row["evidence_id"] for row in rows}, {r["evidence_id"] for r in evidence.records_for_bundle(self.db)})
        current = evidence.query(target, "cp")
        self.assertEqual(sorted(row["name"] for row in current), ["ForceMoveTo", "hit count"])
        self.assertEqual(evidence.verify_ledger(target), {"checked": 3, "failed": []})
        old = [row for row in rows if row["build"] == "2.31"][0]
        self.assertIsNotNone(old["superseded_by"])
        self.assertEqual(old["client"], [r for r in evidence.query(self.db, include_superseded=True) if r["build"] == "2.31"][0]["client"])
        # and the exported ledger exports to an equal bundle
        evidence_bundle.export_bundle(target, self.root / "again", captures_dir=self.captures)
        self.assertEqual(evidence_bundle.compare_bundles(self.root / "bundle", self.root / "again")["status"], "equal")

    def test_a_second_import_adds_nothing(self):
        populate(self.db)
        self.export()
        target = self.root / "c.db"
        evidence_bundle.import_bundle(self.root / "bundle", target)
        again = evidence_bundle.import_bundle(self.root / "bundle", target)
        self.assertEqual((again["added"], again["already_present"]), (0, 3))
        self.assertEqual(len(evidence.query(target, include_superseded=True)), 3)

    def test_a_tampered_bundle_imports_nothing(self):
        populate(self.db)
        self.export()
        self.mutate(self.root / "bundle", "evidence.jsonl", lambda data: data.replace(b"moves", b"moveZ", 1))
        target = self.root / "c.db"
        with self.assertRaises(BundleError):
            evidence_bundle.import_bundle(self.root / "bundle", target)
        self.assertFalse(target.exists())

    def test_a_history_that_diverged_is_reported_not_overwritten(self):
        populate(self.db)
        self.export()
        target = self.root / "c.db"
        evidence.add_claim(target, game="cp", build="2.31", kind="function", name="ForceMoveTo", address="rva:0x1a5f14",
                           note="moves the vehicle", source="decompile line 12", subsystem="vehicles")
        evidence.add_claim(target, game="cp", build="9.9", kind="function", name="ForceMoveTo", address="rva:0x99",
                           note="local successor", source="s", subsystem="vehicles", supersedes=1)
        summary = evidence_bundle.import_bundle(self.root / "bundle", target)
        self.assertEqual(summary["history_diverged"], 1)
        self.assertEqual(evidence.query(target, include_superseded=True, limit=10)[-1]["superseded_by"], 2)


class Payloads(Bundles):
    def test_no_game_payload_bytes_in_a_claim(self):
        for bad in ({"note": "x " * 9000}, {"parameters": {"dump": "ab" * 5000}}, {"parameters": {"blob": "QUJD" * 3000}}):
            db = self.root / ("p%d.db" % len(str(bad)))
            evidence.add_claim(db, game="cp", build="1", kind="k", name="n", source="s",
                               **({"note": "n"} | bad))
            with self.assertRaises(BundleError) as caught:
                evidence_bundle.export_bundle(db, self.root / ("out%d" % len(str(bad))))
            self.assertEqual(caught.exception.code, "payload_refused", bad)

    def test_bounded_captured_hex_is_allowed_and_a_big_capture_is_not(self):
        populate(self.db)
        bounded = dict(CAPTURE, events=[{"bytes_hex": "ab" * 4000}])  # 8000 characters, under the bound
        (self.captures / "cap_one.json").write_text(json.dumps(bounded), encoding="utf-8")
        self.assertEqual(self.export()["captures"], 1)
        (self.captures / "cap_one.json").write_text(json.dumps(dict(CAPTURE, events=[{"bytes_hex": "ab" * 5000}])))
        with self.assertRaises(BundleError) as caught:
            self.export("big-hex")
        self.assertEqual(caught.exception.code, "payload_refused")
        (self.captures / "cap_one.json").write_text(json.dumps(dict(CAPTURE, events=[{"n": i} for i in range(200000)])))
        with self.assertRaises(BundleError) as caught:
            self.export("big-file")
        self.assertEqual(caught.exception.code, "payload_refused")
        (self.captures / "cap_one.json").write_text(json.dumps(dict(CAPTURE, capture_id="someone-else")))
        with self.assertRaises(BundleError) as caught:
            self.export("wrong-id")
        self.assertEqual(caught.exception.code, "capture_invalid")

    def test_a_bundle_that_carries_a_payload_does_not_verify(self):
        populate(self.db)
        self.export()
        folder = self.root / "bundle"
        record_path = folder / "evidence.jsonl"
        lines = record_path.read_text().splitlines()
        record = json.loads(lines[0])
        record["content"]["parameters"] = {"blob": "ab" * 6000}
        record["evidence_id"] = evidence.compute_evidence_id(record["content"])
        lines[0] = evidence.canonical_json(record)
        data = ("\n".join(sorted(lines)) + "\n").encode()
        record_path.write_bytes(data)
        import hashlib
        manifest = json.loads((folder / "manifest.json").read_text())
        manifest["files"]["evidence.jsonl"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        (folder / "manifest.json").write_text(json.dumps(manifest))
        self.assertIn(evidence_bundle.verify_bundle(folder)["error"], ("payload_refused", "bundle_not_canonical"))

    def test_the_bundle_of_this_suite_holds_only_fixture_text(self):
        populate(self.db)
        self.export()
        text = "".join(path.read_text(encoding="utf-8") for path in (self.root / "bundle").rglob("*") if path.is_file())
        self.assertNotIn(str(self.root), text.replace(str(self.root / "bundle"), ""))  # no local path leaks into a bundle


class Surface(Bundles):
    def cli(self, *args):
        env = dict(os.environ, PYTHONPATH=str(REPOSITORY / "src"))
        return subprocess.run([sys.executable, "-m", "hydralysis.evidence_bundle", *map(str, args)], env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)

    def test_the_command_line_round_trip(self):
        populate(self.db)
        done = self.cli("export", self.root / "cli-bundle", "--db", self.db, "--captures", self.captures)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["records"], 3)
        self.assertEqual(self.cli("verify", self.root / "cli-bundle").returncode, 0)
        self.mutate(self.root / "cli-bundle", "subjects.json", lambda data: data + b" ")
        bad = self.cli("verify", self.root / "cli-bundle")
        self.assertEqual((bad.returncode, json.loads(bad.stdout)["error"]), (1, "bundle_file_changed"))
        self.export("good")
        same = self.cli("compare", self.root / "good", self.root / "good")
        self.assertEqual((same.returncode, json.loads(same.stdout)["status"]), (0, "equal"))
        target = self.root / "cli.db"
        imported = self.cli("import", self.root / "good", "--db", target)
        self.assertEqual((imported.returncode, json.loads(imported.stdout)["added"]), (0, 3))
        refused = self.cli("export", self.root / "good", "--db", self.db)
        self.assertEqual((refused.returncode, json.loads(refused.stdout)["error"]), (1, "bundle_exists"))

    def test_the_capability_is_registered_and_answers(self):
        populate(self.db)
        self.export()
        module = api.handler("evidenceBundle")
        self.assertIs(module, evidence_bundle)
        reply = json.loads(module.handle("evidenceBundle", {"options": {"op": "verify", "bundle": str(self.root / "bundle")}}))
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["op"], "verify")
        relative = json.loads(module.handle("evidenceBundle", {"options": {"op": "verify", "bundle": "bundle"}}))
        self.assertEqual(relative["error"], "path_not_absolute")
        unknown = json.loads(module.handle("evidenceBundle", {"options": {"op": "burn"}}))
        self.assertEqual(unknown["error"], "unknown_op")
        compared = json.loads(module.handle("evidenceBundle", {"options": {"op": "compare", "left": str(self.root / "bundle"),
                                                                           "right": str(self.root / "bundle")}}))
        self.assertEqual(compared["status"], "equal")


if __name__ == "__main__":
    unittest.main()
