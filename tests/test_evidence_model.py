"""Evidence v2: content-addressed ids, coverage, limitations, legacy backfill (PROTOCOL-3.md Z9)."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path

from hydralysis import evidence
from support import REPOSITORY, workdir

ADD = """
import sys
from pathlib import Path
from hydralysis.evidence import add_claim
print(add_claim(Path(sys.argv[1]), game="cp", build="2.5", kind="function", name="ForceMoveTo", address="rva:0x2e3270",
                note="moves the vehicle", source="decompile line 12", subsystem="vehicles",
                parameters={"z": 1, "a": {"y": [1, 2], "b": "x"}}, coverage={"status": "partial", "limitations": ["static_only"]}))
"""
OPEN = """
import sys
from pathlib import Path
from hydralysis import evidence
db = evidence.connect(Path(sys.argv[1]))
print(db.execute("SELECT count(*) FROM claims WHERE evidence_id IS NULL OR evidence_id = ''").fetchone()[0])
"""

# Pinned: the id of this exact claim must never change (a change would orphan every stored and exported id).
PINNED_CONTENT = dict(game="cp", build="2.5", kind="function", name="ForceMoveTo", address="rva:0x2e3270",
                      note="moves the vehicle", source="decompile line 12", subsystem="vehicles")
PINNED_ID = "ev_429247fbd78b7252e2ccd84c4e669781dbe9d812f958e3865d48b43f6ed467ed"


def run(code: str, *args, harness="writer", hashseed="0"):
    env = dict(os.environ, PYTHONPATH=str(REPOSITORY / "src"), HYDRALYSIS_HARNESS=harness, PYTHONHASHSEED=hashseed)
    return subprocess.run([sys.executable, "-c", code, *map(str, args)], env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=120)


class Ledger(unittest.TestCase):
    def setUp(self):
        self.work = workdir("evmodel")
        self.addCleanup(self.work.cleanup)
        self.db = Path(self.work.name) / "evidence.db"

    def add(self, **fields):
        values = {"game": "cp", "build": "2.31", "kind": "field", "name": "speed", "note": "n", "source": "s"} | fields
        return evidence.add_claim(self.db, **values)

    def raw(self, sql, *args):
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(sql, args)
            connection.commit()
        finally:
            connection.close()


class ContentAddressedId(Ledger):
    def test_the_id_is_stable_across_key_order(self):
        base = evidence.build_content(**PINNED_CONTENT, parameters={"a": 1, "b": {"x": [1, 2], "y": "z"}})
        shuffled = evidence.build_content(**PINNED_CONTENT, parameters={"b": {"y": "z", "x": [1, 2]}, "a": 1})
        self.assertEqual(evidence.compute_evidence_id(base), evidence.compute_evidence_id(shuffled))
        reordered = dict(reversed(list(base.items())))
        self.assertEqual(evidence.compute_evidence_id(base), evidence.compute_evidence_id(reordered))
        self.assertRegex(evidence.compute_evidence_id(base), r"^ev_[0-9a-f]{64}$")

    def test_the_id_is_pinned_so_that_stored_ids_never_orphan(self):
        content = evidence.build_content(**PINNED_CONTENT)
        self.assertEqual(evidence.compute_evidence_id(content), PINNED_ID)

    def test_the_id_is_stable_across_sessions(self):
        first = run(ADD, self.work.name + "/one.db", hashseed="1")
        second = run(ADD, self.work.name + "/two.db", hashseed="2", harness="another-client")
        self.assertEqual((first.returncode, second.returncode), (0, 0), first.stderr + second.stderr)
        ids = [line.split("evidence_id=")[1].strip() for line in (first.stdout, second.stdout)]
        self.assertEqual(ids[0], ids[1])
        self.assertTrue(evidence.is_evidence_id(ids[0]))
        stored = evidence.query(Path(self.work.name) / "one.db")[0]
        self.assertEqual(stored["evidence_id"], ids[0])
        self.assertEqual(stored["parameters"], {"z": 1, "a": {"y": [1, 2], "b": "x"}})

    def test_the_id_commits_the_content_and_not_the_writer(self):
        self.add()
        other = self.add(note="different")
        rows = evidence.query(self.db, "cp", include_superseded=True)
        self.assertEqual(len({row["evidence_id"] for row in rows}), 2)
        self.assertIn("stored", other)
        # a different client or time does not change it: the same claim from a second writer is the first claim
        again = run(ADD, self.db)
        again_two = run(ADD, self.db, harness="second")
        self.assertIn("already stored", again_two.stdout)

    def test_the_key_order_of_utf16_not_of_code_points(self):
        # U+FFEE is above U+10000 by code point but below it in UTF-16 units; RFC 8785 and the reference use UTF-16.
        self.assertEqual(evidence.canonical_json({"\U00010000": 1, "￮": 2}), '{"\U00010000":1,"￮":2}')

    def test_floats_big_integers_and_lone_surrogates_are_refused(self):
        with self.assertRaisesRegex(ValueError, "float"):
            evidence.build_content(**PINNED_CONTENT, parameters={"x": 1.5})
        with self.assertRaisesRegex(ValueError, "2\\*\\*53"):
            evidence.build_content(**PINNED_CONTENT, parameters={"x": 2 ** 60})
        with self.assertRaisesRegex(ValueError, "surrogate"):
            evidence.build_content(**{**PINNED_CONTENT, "note": "bad \ud800 text"})
        self.assertFalse(self.db.exists())

    def test_a_flipped_byte_is_rejected_on_read(self):
        self.add(name="alpha", note="the original note")
        self.assertEqual(len(evidence.query(self.db, "cp")), 1)
        # the content changes by one byte, the stored id does not
        self.raw("UPDATE claims SET note = ? WHERE name = 'alpha'", "the originbl note")
        with self.assertRaises(evidence.EvidenceIntegrityError) as caught:
            evidence.query(self.db, "cp")
        self.assertEqual(caught.exception.code, "evidence_mismatch")
        self.assertEqual(caught.exception.row_id, 1)
        listing = evidence.list_claims(self.db, "cp")
        self.assertIn("INTEGRITY FAILED", listing)
        report = evidence.verify_ledger(self.db)
        self.assertEqual((report["checked"], [item["id"] for item in report["failed"]]), (1, [1]))
        with self.assertRaises(evidence.EvidenceIntegrityError):
            evidence.export(self.db, Path(self.work.name) / "out.md", "cp")

    def test_a_flipped_id_and_a_flipped_coverage_are_rejected_too(self):
        self.add(name="alpha")
        self.add(name="beta", coverage={"status": "complete"})
        stored = evidence.query(self.db, "cp")[0]["evidence_id"]
        flipped = stored[:-1] + ("0" if stored[-1] != "0" else "1")
        self.raw("UPDATE claims SET evidence_id = ? WHERE evidence_id = ?", flipped, stored)
        with self.assertRaises(evidence.EvidenceIntegrityError):
            evidence.query(self.db, "cp")
        self.raw("UPDATE claims SET evidence_id = ? WHERE evidence_id = ?", stored, flipped)
        self.assertEqual(len(evidence.query(self.db, "cp", include_superseded=True)), 2)
        self.raw("UPDATE claims SET coverage = ? WHERE name = 'beta'", '{"status": "partial", "limitations": ["static_only"]}')
        with self.assertRaises(evidence.EvidenceIntegrityError):
            evidence.query(self.db, "cp")
        self.raw("UPDATE claims SET coverage = ? WHERE name = 'beta'", "{broken")
        with self.assertRaises(evidence.EvidenceIntegrityError) as caught:
            evidence.query(self.db, "cp")
        self.assertEqual(caught.exception.code, "evidence_unreadable")

    def test_restating_a_superseding_claim_is_idempotent_even_after_its_predecessor_is_superseded(self):
        self.add()
        first = self.add(note="second", supersedes=1)
        self.assertIn("stored", first)
        again = self.add(note="second", supersedes=1)  # claim 1 is already superseded by claim 2
        self.assertIn("already stored", again)
        self.assertEqual(len(evidence.query(self.db, "cp", include_superseded=True)), 2)
        with self.assertRaises(ValueError) as caught:  # a different successor of claim 1 is still refused
            self.add(note="third", supersedes=1)
        self.assertIn("already superseded", str(caught.exception))
        self.assertEqual(len(evidence.query(self.db, "cp", include_superseded=True)), 2)

    def test_a_claim_stated_twice_is_one_row(self):
        self.add()
        message = self.add()
        self.assertIn("already stored", message)
        self.assertEqual(len(evidence.query(self.db, "cp", include_superseded=True)), 1)
        self.add(coverage={"status": "complete"})  # coverage is part of what is claimed
        self.assertEqual(len(evidence.query(self.db, "cp", include_superseded=True)), 2)

    def test_concurrent_writers_of_one_claim_leave_one_row(self):
        env = dict(os.environ, PYTHONPATH=str(REPOSITORY / "src"))
        writers = [subprocess.Popen([sys.executable, "-c", ADD, str(self.db)], env=dict(env, HYDRALYSIS_HARNESS="w%d" % index),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                   for index in range(6)]
        for writer in writers:
            _, error = writer.communicate(timeout=120)
            self.assertEqual(writer.returncode, 0, error.decode()[-3000:])
        self.assertEqual(len(evidence.query(self.db, "cp", include_superseded=True)), 1)

    def test_supersession_is_an_evidence_link(self):
        self.add(name="old", address="rva:0x1")
        old = evidence.query(self.db, "cp")[0]
        self.add(name="old", build="2.5", address="rva:0x2", supersedes=old["id"])
        new = evidence.query(self.db, "cp")[0]
        self.assertEqual(new["evidence_links"], [old["evidence_id"]])
        self.assertEqual(evidence.get_claim(self.db, old["evidence_id"])["superseded_by"], new["id"])
        self.assertIsNone(evidence.get_claim(self.db, "ev_" + "0" * 64))

    def test_the_parameters_carry_the_probe_hash(self):
        digest = "ab" * 32
        self.add(parameters={"script_sha256": digest}, authority="controlled-replay", confidence="observed",
                 from_capture="cap_1", subject_sha256="cd" * 32)
        row = evidence.query(self.db, "cp")[0]
        self.assertEqual((row["parameters"], row["authority"], row["confidence"], row["from_capture"], row["subject_sha256"]),
                         ({"script_sha256": digest}, "controlled-replay", "observed", "cap_1", "cd" * 32))
        for bad in ({"from_capture": "../x"}, {"subject_sha256": "xyz"}, {"authority": "trust-me"}, {"confidence": "sure"},
                    {"parameters": [1]}):
            with self.assertRaises(ValueError, msg=str(bad)):
                self.add(name="bad", **bad)


class CoverageAndLimitations(Ledger):
    def test_a_claim_that_does_not_say_is_unknown(self):
        self.add()
        row = evidence.query(self.db, "cp")[0]
        self.assertEqual(row["coverage"], {"status": "unknown", "reason": "coverage_not_reported"})
        self.assertEqual(row["limitations"], ["coverage_unknown"])

    def test_the_coverage_and_the_catalog_are_stored_with_the_row(self):
        self.add(name="a", coverage={"status": "partial", "limitations": ["event_ring_overflow", "hit_limit_reached"]},
                 limitations=["single_run", "fixture_only"])
        self.add(name="b", coverage={"status": "complete"}, limitations=["static_only"])
        rows = {row["name"]: row for row in evidence.query(self.db, "cp")}
        self.assertEqual(rows["a"]["coverage"]["status"], "partial")
        self.assertEqual(rows["a"]["limitations"], ["event_ring_overflow", "fixture_only", "hit_limit_reached", "single_run"])
        self.assertEqual(rows["b"]["limitations"], ["static_only"])
        for code in rows["a"]["limitations"] + rows["b"]["limitations"]:
            self.assertIn(code, evidence.LIMITATIONS)
        listing = evidence.list_claims(self.db, "cp")
        self.assertIn("coverage=partial", listing)
        self.assertIn("limitations=event_ring_overflow", listing)

    def test_a_capped_capture_never_presents_as_complete(self):
        for code in ("event_ring_overflow", "hit_limit_reached", "payload_clipped", "sampled"):
            with self.assertRaisesRegex(ValueError, "complete"):
                self.add(coverage={"status": "complete"}, limitations=[code])
        with self.assertRaisesRegex(ValueError, "complete"):
            self.add(coverage="complete", limitations=["z9test:capped"])  # a code of one's own is assumed to bound
        self.assertFalse(self.db.exists())

    def test_the_coverage_object_is_strict(self):
        for bad in ({"status": "mostly"}, {"status": "partial"}, {"status": "partial", "limitations": []},
                    {"status": "unknown", "reason": " "}, {"status": "complete", "reason": "x"},
                    {"status": "complete", "colour": "red"}, {"status": "partial", "limitations": ["no_such_code"]}):
            with self.assertRaises(ValueError, msg=str(bad)):
                evidence.normalize_coverage(bad)
        self.assertEqual(evidence.normalize_coverage("complete"), {"status": "complete"})
        self.assertEqual(evidence.merge_limitations(evidence.normalize_coverage(
            {"status": "partial", "limitations": ["sampled"]}), ["z9:custom"]), ["sampled", "z9:custom"])

    def test_the_states_are_those_of_the_reference(self):
        self.assertEqual(set(evidence.COVERAGE_STATES), {"complete", "partial", "unknown"})


class LegacyLedger(Ledger):
    def legacy(self):
        """A ledger of the release before evidence v2: the columns of FIELDS up to superseded_by only."""
        connection = sqlite3.connect(self.db)
        connection.executescript(evidence.SCHEMA)
        for column in ("subsystem", "client", "harness", "supersedes", "superseded_by"):
            connection.execute("ALTER TABLE claims ADD COLUMN %s %s" % (column, evidence.COLUMNS[column]))
        insert = ("INSERT INTO claims (game, build, kind, name, address, prologue, note, source, created, subsystem, "
                  "client, harness, supersedes, superseded_by) VALUES ('cp', ?, 'function', ?, ?, '', 'note', 'src', "
                  "'2026-01-01T00:00:00Z', 'veh', 'old-client:1', 'cli', ?, ?)")
        connection.execute(insert, ("2.31", "ForceMoveTo", "rva:0x1a5f14", None, 2))
        connection.execute(insert, ("2.5", "ForceMoveTo", "rva:0x2e3270", 1, None))
        connection.execute(insert, ("2.5", "Other", "rva:0x10", None, None))
        connection.commit()
        connection.close()

    def test_legacy_rows_are_backfilled_and_verify(self):
        self.legacy()
        rows = evidence.query(self.db, "cp", include_superseded=True)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(evidence.is_evidence_id(row["evidence_id"]) for row in rows))
        by_name = {(row["name"], row["build"]): row for row in rows}
        old, new = by_name[("ForceMoveTo", "2.31")], by_name[("ForceMoveTo", "2.5")]
        self.assertEqual(new["evidence_links"], [old["evidence_id"]])
        self.assertEqual(old["coverage"]["status"], "unknown")
        self.assertEqual(old["authority"], evidence.DEFAULT_AUTHORITY)
        self.assertEqual(evidence.verify_ledger(self.db), {"checked": 3, "failed": []})
        self.assertEqual(old["client"], "old-client:1")  # attribution survives

    def test_a_backfilled_row_has_the_id_of_the_same_claim_stated_today(self):
        self.legacy()
        legacy_other = [row for row in evidence.query(self.db, "cp") if row["name"] == "Other"][0]
        fresh = Path(self.work.name) / "fresh.db"
        evidence.add_claim(fresh, game="cp", build="2.5", kind="function", name="Other", address="rva:0x10",
                           note="note", source="src", subsystem="veh")
        self.assertEqual(evidence.query(fresh)[0]["evidence_id"], legacy_other["evidence_id"])

    def test_the_backfill_is_not_repeated_and_new_rows_land_beside_it(self):
        self.legacy()
        evidence.query(self.db, "cp")
        before = [row["evidence_id"] for row in evidence.query(self.db, "cp", include_superseded=True)]
        self.add(name="after")
        after = [row["evidence_id"] for row in evidence.query(self.db, "cp", include_superseded=True, limit=100)]
        self.assertEqual(len(after), 4)
        self.assertTrue(set(before) <= set(after))

    def test_a_row_written_by_an_old_client_after_the_migration_is_backfilled_on_the_next_open(self):
        self.add()
        self.raw("INSERT INTO claims (game, build, kind, name, note, source, created) VALUES ('cp','1','k','n','note','src','t')")
        rows = evidence.query(self.db, "cp", include_superseded=True)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(evidence.is_evidence_id(row["evidence_id"]) for row in rows))

    def test_four_processes_opening_an_old_ledger_at_once_agree(self):
        self.legacy()
        env = dict(os.environ, PYTHONPATH=str(REPOSITORY / "src"))
        openers = [subprocess.Popen([sys.executable, "-c", OPEN, str(self.db)], env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
        for opener in openers:
            out, error = opener.communicate(timeout=120)
            self.assertEqual(opener.returncode, 0, error.decode()[-3000:])
            self.assertEqual(out.decode().strip(), "0")
        self.assertEqual(evidence.verify_ledger(self.db), {"checked": 3, "failed": []})


if __name__ == "__main__":
    unittest.main()
