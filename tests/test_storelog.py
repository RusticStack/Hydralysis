"""The overlay store as snapshot plus append log (storelog, H16): one framed row per mutation, fsynced before return;
recovery from snapshot (or `.bak`) plus log; compaction; identical load results to the whole-store writer."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import durable, revisions, storelog, workcopy
from support import workdir

SRC = Path(__file__).resolve().parent.parent / "src"
TARGET = {"key": "s" * 16, "sha256": "b" * 64, "name": "t", "view": "shared"}


def record(number: int, kind: str = "rename") -> dict:
    return {"id": "%032x" % number, "address": "0x%x" % (0x401000 + number),
            "options": {"kind": kind, "name": "F%d" % number, "source": "test"}, "by": {"client": "c"}, "at": float(number),
            "seq": number, "effects": [{"subject": "address:0x%x" % (0x401000 + number), "field": "name",
                                        "before": None, "after": "F%d" % number}]}


def run_child(code: str, root: Path, fault: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    env.pop("HYDRALYSIS_TEST_FAULT", None)
    env.pop("HYDRALYSIS_TEST_MODE", None)
    if fault:
        env.update(HYDRALYSIS_TEST_MODE="1", HYDRALYSIS_TEST_FAULT=fault)
    prelude = ("import json, sys; from hydralysis import workcopy; settings = {'root': sys.argv[1]}; target = json.loads(sys.argv[2])\n"
               "store = workcopy.load_store(settings, target)\n")
    return subprocess.run([sys.executable, "-c", prelude + code, str(root), json.dumps(TARGET)], env=env,
                          capture_output=True, text=True, timeout=120)


class Base(unittest.TestCase):
    def setUp(self):
        self.work = workdir("storelog")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.settings = {"root": str(self.root)}
        durable._VERIFIED.clear()
        storelog._CACHE.clear()
        self.addCleanup(storelog._CACHE.clear)

    def path(self) -> Path:
        return workcopy._store_path(self.settings, TARGET)

    def log(self) -> Path:
        return storelog.log_path(self.path())

    def load(self) -> dict:
        return workcopy.load_store(self.settings, TARGET)

    def edit(self, store: dict, number: int) -> dict:
        """What workcopy.edit does to the store: revision, one record, one journal entry (three fields, one mutation)."""
        store["revision"] += 1
        store["edits"].append(record(number))
        store["journal"] = revisions.append(store["journal"], revisions.journal_entry(
            store["revision"], "edit", ["address:0x%x" % (0x401000 + number)], {"client": "c"}, float(number)))
        workcopy._save_store(self.settings, TARGET, store)
        return store

    def rows(self) -> list[dict]:
        return durable.scan_file(self.log()).records if self.log().is_file() else []


class Appending(Base):
    def test_a_mutation_is_one_framed_row_and_the_snapshot_is_not_rewritten(self):
        store = self.edit(self.load(), 1)  # first write: the snapshot (and its .bak)
        snapshot = self.path().read_bytes()
        self.assertTrue(durable.backup_path(self.path()).is_file())
        store = self.edit(store, 2)
        self.assertEqual(self.path().read_bytes(), snapshot)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        # revision, edits and journal changed together: one row, the list fields as appends
        self.assertEqual(rows[0]["set"], {"revision": 2})
        self.assertEqual(sorted(rows[0]["lists"]), ["edits", "journal"])
        self.assertEqual(rows[0]["lists"]["edits"], {"drop": 0, "push": [record(2)]})
        self.assertEqual(self.load(), workcopy.load_store(self.settings, TARGET))
        self.assertEqual([item["id"] for item in self.load()["edits"]], [record(1)["id"], record(2)["id"]])

    def test_the_row_is_fsynced_before_save_returns(self):
        store = self.edit(self.load(), 1)
        synced = []
        real = os.fsync
        with patch("hydralysis.durable.os.fsync", side_effect=lambda fd: (synced.append(fd), real(fd))[1]):
            self.edit(store, 2)
        self.assertEqual(len(synced), 1)  # one fsync per mutation (the whole-store writer made two or three)

    def test_an_unchanged_store_writes_nothing(self):
        store = self.edit(self.load(), 1)
        before = self.log().stat().st_size if self.log().exists() else 0
        workcopy._save_store(self.settings, TARGET, self.load())
        self.assertEqual(self.log().stat().st_size if self.log().exists() else 0, before)
        self.assertEqual(self.load()["revision"], store["revision"])

    def test_the_budget_is_refused_before_anything_is_written(self):
        store = self.edit(self.load(), 1)
        self.edit(store, 2)
        size = self.log().stat().st_size
        store = self.load()
        store["edits"].append({**record(3), "options": {"kind": "rename", "name": "F3", "source": "x" * 4096}})
        store["revision"] += 1
        with patch.object(workcopy, "MAX_HISTORY_BYTES", 4000), self.assertRaises(ValueError):
            workcopy._save_store(self.settings, TARGET, store)
        self.assertEqual(self.log().stat().st_size, size)
        self.assertEqual(self.load()["revision"], 2)


class Equivalence(Base):
    """Any sequence of mutations loads exactly as the whole-store writer's file does (HYDRALYSIS_STORE_LOG=0)."""

    def mutate(self, rng: random.Random, store: dict, counter: list) -> None:
        choice = rng.randrange(7)
        store["revision"] += 1
        if choice <= 2:
            counter[0] += 1
            store["edits"].append(record(counter[0]))
            store["journal"] = revisions.append(store["journal"], revisions.journal_entry(
                store["revision"], "edit", ["*"], {"client": "c"}, 1.0))
        elif choice == 3 and store["edits"]:  # a revert or a rebase: records leave from anywhere
            gone = rng.choice(store["edits"])["id"]
            store["edits"] = [item for item in store["edits"] if item["id"] != gone]
            store["reverted"] = store["reverted"] + [{"ids": [gone], "by": {"client": "c"}, "at": 2.0}]
        elif choice == 4:
            store["base"] = {"lineage": "L", "generation": rng.randrange(5)}
            store["stale"] = rng.choice([None, "behind"])
        elif choice == 5:
            store["published_through"] = {"v%d" % rng.randrange(3): rng.randrange(100)}
            store["changesets"] = (store["changesets"] + [{"csid": "c%d" % store["revision"]}])[-3:]
        else:
            store["journal"] = store["journal"][rng.randrange(len(store["journal"]) + 1):]

    def test_random_mutation_sequences_load_identically_with_compaction(self):
        legacy = {**TARGET, "key": "l" * 16}
        rng = random.Random(1234)
        with patch.object(storelog, "SNAPSHOT_EVERY", 5), patch.object(revisions, "MAX_JOURNAL", 7):
            mine, theirs, counter = self.load(), workcopy.load_store(self.settings, legacy), [0]
            for step in range(120):
                self.mutate(rng, mine, counter)
                theirs = json.loads(json.dumps(mine))
                workcopy._save_store(self.settings, TARGET, mine)
                with patch.dict(os.environ, {"HYDRALYSIS_STORE_LOG": "0"}):
                    workcopy._save_store(self.settings, legacy, theirs)
                if step % 7 == 0:
                    storelog._CACHE.clear()  # as another process would: the writer re-reads the chain
                self.assertEqual(self.load(), workcopy.load_store(self.settings, legacy), "step %d" % step)
                mine = self.load()
        # compaction kept the log short: only the rows since the `.bak` snapshot remain
        self.assertLessEqual(len(self.rows()), 2 * 5)


class CleanOnce(Base):
    """_v3 takes a record equal to the stored (clean) one as it is: the result must be what cleaning it gives."""

    def test_cleaning_a_clean_record_gives_it_back(self):
        raw = [record(1), {**record(2), "batch": "b1"}, {**record(3), "effects": None},
               {k: v for k, v in record(4).items() if k not in ("seq", "effects")},
               {**record(5), "imported_from": {"view": "x"}, "before_unknown": True}]
        previous = 0
        for position, item in enumerate(raw):
            once = workcopy._clean_record(item, position, previous)
            self.assertEqual(workcopy._clean_record(json.loads(json.dumps(once)), position, previous), once)
            previous = once["seq"]

    def test_the_fast_path_writes_what_the_full_clean_writes(self):
        store = self.load()
        for number in range(1, 30):
            store = self.edit(store, number)
        known = storelog.known_edits(self.path())
        self.assertIsNotNone(known)
        store = self.load()
        store["edits"].append({**record(31), "seq": 31})
        store["edits"][3] = {**store["edits"][3], "options": {**store["edits"][3]["options"], "name": "Changed"}}
        self.assertEqual(workcopy._v3(store, TARGET, known), workcopy._v3(store, TARGET))
        with patch.object(workcopy, "_clean_record", wraps=workcopy._clean_record) as cleaned:
            workcopy._v3(store, TARGET, known)
        self.assertEqual(cleaned.call_count, 2)  # the changed record and the new one, not all 30


class LoadCache(Base):
    def setUp(self):
        super().setUp()
        workcopy._LOADED.clear()
        self.addCleanup(workcopy._LOADED.clear)

    def test_a_warm_load_does_not_clean_the_records_again_and_gives_a_private_copy(self):
        store = self.load()
        for number in range(1, 6):
            store = self.edit(store, number)
        first = self.load()
        with patch.object(workcopy, "_clean_record", wraps=workcopy._clean_record) as cleaned:
            second = self.load()
        self.assertEqual(cleaned.call_count, 0)
        self.assertEqual(first, second)
        second["edits"].append(record(99))
        second["edits"][0]["options"]["name"] = "Mutated"
        self.assertEqual(self.load(), first)

    def test_every_write_and_an_in_place_rewrite_of_the_same_size_are_seen(self):
        store = self.edit(self.load(), 1)
        self.assertEqual(self.load()["revision"], 1)
        self.edit(store, 2)
        self.assertEqual(self.load()["revision"], 2)
        with patch.dict(os.environ, {"HYDRALYSIS_STORE_LOG": "0"}):  # the whole-store writer: main and .bak replaced
            workcopy._save_store(self.settings, TARGET, {**self.load(), "revision": 3})
        self.assertEqual(self.load()["revision"], 3)
        good = self.path().read_bytes()
        self.path().write_bytes(good.replace(b'"revision": 3', b'"revision": 4'))  # same size, mis-sealed
        self.assertEqual(self.load()["revision"], 2)  # the .bak (and its log), never the cached 3 nor the forged 4


class Recovery(Base):
    def build(self, count: int) -> dict:
        store = self.load()
        for number in range(1, count + 1):
            store = self.edit(store, number)
        return store

    def test_a_damaged_main_file_reads_the_newest_state_from_the_backup_and_the_log(self):
        with patch.object(storelog, "SNAPSHOT_EVERY", 4):
            for count in (3, 6, 9):  # before the first compaction, after one, after two
                with self.subTest(count=count):
                    self.setUp()
                    newest = self.build(count)
                    self.path().write_bytes(self.path().read_bytes()[:50])
                    self.assertEqual(self.load()["revision"], newest["revision"])
                    self.path().unlink()
                    self.assertEqual(self.load(), {**newest, "version": 3})

    def test_a_torn_log_tail_is_ignored_and_repaired_by_the_next_append(self):
        store = self.build(3)
        with self.log().open("ab") as handle:
            handle.write(b"0123abcd {\"a\":")
        self.assertEqual(self.load()["revision"], 3)
        self.edit(store, 4)
        self.assertEqual(self.load()["revision"], 4)
        self.assertEqual(len(list(self.log().parent.glob(self.log().name + ".torn-*"))), 1)

    def test_corruption_inside_the_log_is_store_corrupt(self):
        self.build(4)
        raw = bytearray(self.log().read_bytes())
        raw[12] ^= 0x01
        self.log().write_bytes(bytes(raw))
        with self.assertRaises(durable.StoreCorrupt):
            self.load()

    def test_a_snapshot_without_an_anchor_never_takes_a_stale_log(self):
        self.build(3)
        with patch.dict(os.environ, {"HYDRALYSIS_STORE_LOG": "0"}):
            workcopy._save_store(self.settings, TARGET, {**workcopy._empty_store(TARGET["sha256"]), "revision": 9})
        self.assertTrue(self.log().is_file())
        self.assertEqual((self.load()["revision"], self.load()["edits"]), (9, []))
        # and the log writer starts a new anchored snapshot from there
        store = self.edit(self.load(), 10)
        storelog._CACHE.clear()
        self.assertEqual(self.load(), {**store, "version": 3})

    def test_another_writer_between_two_of_mine_is_seen(self):
        store = self.build(2)
        result = run_child("store['revision'] += 1; store['stale'] = 'other'; workcopy._save_store(settings, target, store)", self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        store["revision"] += 1  # this process' copy is stale on purpose: what it saves is what must be on disk
        store["base"] = {"lineage": "L", "generation": 1}
        workcopy._save_store(self.settings, TARGET, store)
        storelog._CACHE.clear()
        self.assertEqual((self.load()["stale"], self.load()["base"]), (None, {"lineage": "L", "generation": 1}))


class Crashes(Base):
    """A process killed at each point leaves the old state or the new one, and an acknowledged write is never lost (O2)."""

    EDIT = ("store['revision'] += 1; store['edits'].append(%r); workcopy._save_store(settings, target, store); print('acked')")

    def crash(self, fault: str, number: int) -> subprocess.CompletedProcess:
        return run_child(self.EDIT % record(number), self.root, fault)

    def test_kill_points_of_an_append(self):
        cases = [("log.before_write:exit", 2), ("log.torn_append:torn:7", 2), ("log.torn_append:torn:30", 2),
                 ("store.after_append:exit", 3), ("log.after_append:exit", 3)]
        for fault, revision in cases:
            with self.subTest(fault=fault):
                self.setUp()
                store = self.edit(self.edit(self.load(), 1), 2)
                result = self.crash(fault, 3)
                self.assertEqual(result.returncode, 137, result.stderr)
                self.assertNotIn("acked", result.stdout)
                self.assertEqual(self.load()["revision"], revision)
                # the next writer repairs any torn tail and goes on
                store = self.load()
                store = self.edit(store, 4)
                self.assertEqual(self.load()["revision"], revision + 1)

    def test_kill_points_of_a_compaction(self):
        # SNAPSHOT_EVERY=4 in both processes: the parent writes the snapshot and 3 rows (and, for the trim case, 4 more:
        # one compaction already made, so the child's compaction also trims the rows of the first snapshot).
        every = 4
        for fault, before in (("atomic.before_replace:exit", 4), ("atomic.after_replace:exit", 4),
                              ("store.after_snapshot:exit", 4), ("store.trim.before_replace:exit", 8),
                              ("store.trim.after_replace:exit", 8)):
            with self.subTest(fault=fault):
                self.setUp()
                store = self.load()
                with patch.object(storelog, "SNAPSHOT_EVERY", every):
                    for number in range(1, before + 1):
                        store["revision"] += 1
                        store["edits"].append(record(number))
                        workcopy._save_store(self.settings, TARGET, store)
                code = "from hydralysis import storelog; storelog.SNAPSHOT_EVERY = %d; " % every + self.EDIT % record(before + 1)
                result = run_child(code, self.root, fault)  # this row is the one that compacts
                self.assertEqual(result.returncode, 137, result.stderr)
                self.assertNotIn("acked", result.stdout)
                self.assertEqual(self.load()["revision"], before + 1)  # the row was durable before the snapshot
                self.path().unlink(missing_ok=True)  # and the .bak plus the log still reach it
                self.assertEqual(self.load()["revision"], before + 1)

if __name__ == "__main__":
    unittest.main()
