"""The evidence ledger under several writers, with subsystems and supersession."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path

from rusticre import evidence
from support import REPOSITORY, workdir

WRITER = """
import sys
from pathlib import Path
from rusticre.evidence import add_claim
for index in range(int(sys.argv[3])):
    add_claim(Path(sys.argv[1]), game="cp", build="2.5", kind="function", name="%s-%d" % (sys.argv[2], index),
              note="written concurrently", source="test", subsystem="vehicles")
"""


class Ledger(unittest.TestCase):
    def setUp(self):
        self.work = workdir("evidence")
        self.addCleanup(self.work.cleanup)
        self.db = Path(self.work.name) / "evidence.db"

    def add(self, **fields):
        values = {"game": "cp", "build": "2.31", "kind": "field", "name": "speed", "note": "n", "source": "s"} | fields
        return evidence.add_claim(self.db, **values)

    def test_concurrent_writers_all_land(self):
        env = dict(os.environ, PYTHONPATH=str(REPOSITORY / "src"), RUSTICRE_HARNESS="writer")
        writers = [subprocess.Popen([sys.executable, "-c", WRITER, str(self.db), "w%d" % index, "40"], env=env,
                                    stdin=subprocess.DEVNULL, stderr=subprocess.PIPE) for index in range(4)]
        for writer in writers:
            _, error = writer.communicate(timeout=120)
            self.assertEqual(writer.returncode, 0, error.decode()[-4000:])
        rows = evidence.query(self.db, "cp", "vehicles", limit=1000)
        self.assertEqual(len(rows), 160)
        self.assertEqual({row["harness"] for row in rows}, {"writer"})
        check = sqlite3.connect(self.db)
        mode = check.execute("PRAGMA journal_mode").fetchone()[0]
        check.close()
        self.assertEqual(mode.lower(), "wal")

    def test_supersession_keeps_the_old_claim_and_filters_it(self):
        self.add(address="rva:0x6ab990", subsystem="animation")
        old_id = evidence.query(self.db, "cp")[0]["id"]
        self.add(build="2.5", address="rva:0x7c1234", subsystem="animation", supersedes=old_id)
        current = evidence.query(self.db, "cp", "animation")
        self.assertEqual([row["build"] for row in current], ["2.5"])
        both = evidence.query(self.db, "cp", "animation", include_superseded=True)
        self.assertEqual(len(both), 2)
        self.assertEqual(next(row for row in both if row["id"] == old_id)["superseded_by"], current[0]["id"])
        with self.assertRaisesRegex(ValueError, "already superseded"):
            self.add(build="2.5", supersedes=old_id)
        self.assertEqual(len(evidence.query(self.db, "cp", address="rva:0x7c1234")), 1)
        self.assertEqual(len(evidence.query(self.db, "cp", build="2.31")), 0)

    def test_export_lists_current_claims_and_superseded_ones(self):
        self.add(subsystem="vehicles", name="ForceMoveTo", address="rva:0x1a5f14")
        old_id = evidence.query(self.db, "cp")[0]["id"]
        self.add(subsystem="vehicles", name="ForceMoveTo", build="2.5", address="rva:0x2e3270", supersedes=old_id)
        result = evidence.export(self.db, Path(self.work.name) / "vehicles.md", "cp", "vehicles")
        self.assertEqual((result["current"], result["superseded"]), (1, 1))
        text = Path(result["markdown"]).read_text(encoding="utf-8")
        self.assertIn("rva:0x2e3270", text)
        self.assertIn("## Superseded", text)
        self.assertEqual(len(Path(result["jsonl"]).read_text().splitlines()), 2)

    def test_a_first_release_ledger_is_upgraded_in_place(self):
        legacy = sqlite3.connect(self.db)
        legacy.executescript(evidence.SCHEMA)
        legacy.execute("INSERT INTO claims (game, build, kind, name, note, source, created) VALUES ('cp','2.31','k','n','note','src','t')")
        legacy.commit()
        legacy.close()
        self.add(subsystem="new")
        rows = evidence.query(self.db, "cp", include_superseded=True)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[-1]["subsystem"], "")


if __name__ == "__main__":
    unittest.main()
