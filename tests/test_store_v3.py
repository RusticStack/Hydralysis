"""Store v3 (PROTOCOL-3.md 4.2): the subject record, the committed-id set, migration, sealing, revert with dependents.

Against the fake daemon of tests/fakehydra.py. The fake's `apply_overlays` reports no effects (it models an engine whose
script predates them); `EffectsEngine` below adds the effects a real RusticQuery reports for renames.
"""

from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import durable, hydra, query, revisions, workcopy
from support import default_to_shared, workdir

ADDRESS_A, ADDRESS_B = "0x140001000", "0x140002000"
SOURCE = "cited test evidence"


class EffectsEngine(fakehydra.FakeEngine):
    """The fake engine plus the `effects` output of the new RusticQuery, for rename and comment edits."""

    def _script(self, script, program=None, args=(), **fields):
        result = super()._script(script, program=program, args=args, **fields)
        body = args[0]
        if body.startswith("@"):
            body = Path(body[1:]).read_text(encoding="utf-8")
        request = json.loads(body)
        if request.get("action") == "annotation_probe":
            return self._probe(program, request, result)
        if request.get("action") != "apply_overlays":
            return result
        out = json.loads(result["output"])
        if not out.get("ok"):
            return result
        batch = json.loads(Path(request["edits_file"]).read_text(encoding="utf-8"))
        entry = self._program(program)
        names = dict(self._view(entry)["names"])
        # The program now holds the new names; recompute each record's before from the names of the records before it.
        before_names = self.daemon.pre_apply_names.get(program, {})
        rows = []
        for record in batch["edits"]:
            options = record["options"]
            if options.get("kind") != "rename":
                continue
            address = record["address"]
            before = before_names.get(address, "FUN_" + address.removeprefix("0x"))
            rows.append({"id": record["id"], "effects": [{
                "subject": "address:" + hex(int(address, 16)), "field": "name", "before": before, "after": options["name"]}]})
            before_names[address] = options["name"]
        out["effects"] = rows
        self.daemon.pre_apply_names[program] = before_names
        return {**result, "output": json.dumps(out) + "\n"}


    def _probe(self, program, request, result):
        """annotation_probe for the names of the fake program (everything else is absent)."""
        names = self._view(self._program(program))["names"]
        values = []
        for item in request["options"]["probes"]:
            row = {"subject": item["subject"], "field": item["field"]}
            if item["subject"] == "*":
                pass
            elif item["field"] == "name":
                address = item["subject"].removeprefix("address:")
                row["value"] = names.get(address, "FUN_" + address.removeprefix("0x"))
            else:
                row["value"] = "absent"
            values.append(row)
        out = {**json.loads(result["output"]), "values": values}
        return {**result, "output": json.dumps(out) + "\n"}


class Case(unittest.TestCase):
    engine_class = EffectsEngine

    def setUp(self):
        self.temp = workdir("storev3")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "owned.exe"
        self.exe.write_bytes(b"MZ a small owned executable")
        self.digest = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.daemon = fakehydra.reset()
        self.daemon.pre_apply_names = {}
        self.gpr = self.root / "analysed" / "Owned" / "Owned.gpr"
        self.daemon.add_project(self.gpr, {"/owned.exe": {"sha256": self.digest}})
        self.settings = {"root": str(self.root / "data"), "hydra_dir": "x", "hydra_client": "x",
                         "targets": {"owned": {"gpr": str(self.gpr), "program": "/owned.exe", "exe": str(self.exe)}}}
        for item in (patch("hydralysis.hydra.Engine", self.engine_class),):
            item.start()
            self.addCleanup(item.stop)
        query._keys.clear()
        self.runner = query.QueryRunner(self.settings, self.engine_class(self.settings))
        self.target = workcopy.with_view(self.runner.target("owned"))
        default_to_shared(self.runner)  # these tests exercise the shared view; a bare call has a view of its own now (Y5)

    def store(self, view=""):
        return workcopy.load_store(self.settings, workcopy.with_view(self.runner.target("owned"), view))

    def rename(self, name, address=ADDRESS_A, view="", **extra):
        revision = self.store(view)["revision"]
        return json.loads(self.runner.query("owned", "type_edit", address, options={
            "kind": "rename", "name": name, "source": SOURCE, "expect_revision": revision, **({"view": view} if view else {}), **extra}))

    def revert(self, ids, view="", **extra):
        revision = self.store(view)["revision"]
        return json.loads(self.runner.query("owned", "type_edit", options={
            "kind": "revert", "ids": ids, "expect_revision": revision, **({"view": view} if view else {}), **extra}))

    def path(self):
        return workcopy._store_path(self.settings, self.target)

    def v2_file(self, edits, revision=None, sealed=False):
        record = {"version": 2, "sha256": self.digest, "revision": len(edits) if revision is None else revision,
                  "edits": [{**edit, "by": {"client": "old", "harness": "h"}, "at": 100.0 + index}
                            for index, edit in enumerate(edits)],
                  "reverted": [{"ids": ["f" * 32], "by": {"client": "old"}, "at": 9.0}],
                  "journal": [revisions.journal_entry(number, "edit", ["address:0x401000"], {"client": "old"}, 100.0 + number)
                              for number in range(1, len(edits) + 1)]}
        self.path().parent.mkdir(parents=True, exist_ok=True)
        if sealed:
            durable.write_sealed(self.path(), record)
        else:
            self.path().write_text(json.dumps(record, indent=2), encoding="utf-8")
        return record


def rename_record(number, address="0x401000", name=None):
    return {"id": "%032x" % number, "address": address,
            "options": {"kind": "rename", "name": name or "N%d" % number, "source": SOURCE}}


class Migration(Case):
    def test_a_v2_store_loads_upgrades_and_is_kept_once_as_v2_bak(self):
        edits = [rename_record(1), rename_record(2, "0x401010")]
        original = self.v2_file(edits)
        raw = self.path().read_bytes()
        loaded = self.store()
        self.assertEqual(loaded["version"], 2)  # what was read; the first write makes it 3
        self.assertEqual([edit["id"] for edit in loaded["edits"]], [edit["id"] for edit in edits])
        for position, edit in enumerate(loaded["edits"]):
            self.assertEqual((edit["seq"], edit["effects"], edit["before_unknown"]), (position + 1, None, True))
            self.assertEqual(edit["by"], {"client": "old", "harness": "h"})
        self.assertEqual((loaded["commits"], loaded["archived"], loaded["stale"], loaded["base"]),
                         ([], [], None, {"lineage": "", "generation": 0}))
        self.assertEqual(self.path().read_bytes(), raw)  # a read writes nothing
        self.assertEqual(list(self.path().parent.glob("*.bak")), [])

        workcopy._save_store(self.settings, self.target, {**loaded, "revision": loaded["revision"] + 1})
        written = json.loads(self.path().read_text(encoding="utf-8"))
        self.assertEqual((written["version"], written["revision"], sorted(written["seal"])), (3, 3, ["algo", "value"]))
        self.assertEqual(self.path().with_name(self.path().name + ".v2.bak").read_bytes(), raw)
        # Lossless: every v2 key is still there, unchanged.
        self.assertEqual(written["reverted"], original["reverted"])
        self.assertEqual(written["journal"], original["journal"])
        self.assertEqual([{key: edit[key] for key in ("id", "address", "options", "by", "at")} for edit in written["edits"]],
                         original["edits"])
        # The .v2.bak is written once: a second write leaves it as the original file.
        workcopy._save_store(self.settings, self.target, {**self.store(), "revision": 9})
        self.assertEqual(self.path().with_name(self.path().name + ".v2.bak").read_bytes(), raw)
        self.assertEqual(self.store()["version"], 3)

    def test_a_sealed_v2_store_migrates_the_same_way(self):
        self.v2_file([rename_record(1)], sealed=True)
        raw = self.path().read_bytes()
        workcopy._save_store(self.settings, self.target, self.store())
        self.assertEqual(self.path().with_name(self.path().name + ".v2.bak").read_bytes(), raw)

    def test_a_v1_store_is_kept_as_v1_bak(self):
        self.path().parent.mkdir(parents=True)
        self.path().write_text(json.dumps({"version": 1, "sha256": self.digest, "edits": [rename_record(1)]}), encoding="utf-8")
        raw = self.path().read_bytes()
        loaded = self.store()
        self.assertEqual((loaded["revision"], len(loaded["edits"])), (1, 1))
        workcopy._save_store(self.settings, self.target, loaded)
        self.assertEqual(self.path().with_name(self.path().name + ".v1.bak").read_bytes(), raw)

    def test_a_v2_reader_refuses_the_v3_file_so_it_is_preserved(self):
        workcopy._save_store(self.settings, self.target, self.store())
        record = json.loads(self.path().read_text(encoding="utf-8"))
        # What the v2 reader did (workcopy.py:57 at 589432e): refuse any version but 1 and 2.
        self.assertNotIn(record["version"], (1, 2))

    def test_a_v2_store_never_silently_empties(self):
        edits = [rename_record(number) for number in range(1, 6)]
        self.v2_file(edits)
        for _ in range(2):  # loading twice, and after a failed save
            self.assertEqual(len(self.store()["edits"]), 5)
        with patch("hydralysis.durable.atomic_write", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                workcopy._save_store(self.settings, self.target, self.store())
        self.assertEqual(len(self.store()["edits"]), 5)


# The whole-store writer (HYDRALYSIS_STORE_LOG=0): every save is a sealed snapshot and the previous one is the `.bak`.
# The log writer's own fallback rules (damaged main, `.bak` plus the log) are covered in test_storelog.py.
@patch.dict(os.environ, {"HYDRALYSIS_STORE_LOG": "0"})
class Sealing(Case):
    def test_a_hand_stripped_seal_on_a_v3_store_is_store_corrupt(self):
        workcopy._save_store(self.settings, self.target, self.store())
        record = json.loads(self.path().read_text(encoding="utf-8"))
        record.pop("seal")
        self.path().write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(durable.StoreCorrupt) as raised:
            self.store()
        self.assertIn("no seal", str(raised.exception))

    def test_a_stripped_seal_is_not_answered_from_an_older_sealed_copy(self):
        first = self.v3_with(1)
        workcopy._save_store(self.settings, self.target, self.v3_with(2))
        self.assertTrue(durable.backup_path(self.path()).is_file())
        record = json.loads(self.path().read_text(encoding="utf-8"))
        record.pop("seal")
        self.path().write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(durable.StoreCorrupt):
            self.store()
        self.assertEqual(first["revision"], 1)

    def v3_with(self, count):
        store = self.store()
        store["edits"] = [workcopy._clean_record(rename_record(number), number - 1, number - 1) for number in range(1, count + 1)]
        store["revision"] = count
        if count == 1:
            workcopy._save_store(self.settings, self.target, store)
        return store

    def test_a_torn_v3_store_falls_back_to_its_backup(self):
        workcopy._save_store(self.settings, self.target, self.v3_with(1))
        workcopy._save_store(self.settings, self.target, self.v3_with(2))
        good = self.path().read_bytes()
        self.path().write_bytes(good[:len(good) // 2])
        self.assertEqual(self.store()["revision"], 1)

    def test_a_pre_seal_v2_store_still_loads_once(self):
        self.v2_file([rename_record(1)])
        self.assertEqual(len(self.store()["edits"]), 1)

    def test_has_overlays_and_expected_state_see_the_overlays_when_only_the_backup_is_left(self):
        store = self.store()
        store["edits"] = [workcopy._clean_record(rename_record(1), 0, 0)]
        store["revision"] = 1
        workcopy._save_store(self.settings, self.target, store)
        workcopy._save_store(self.settings, self.target, {**store, "revision": 2})
        self.path().unlink()
        self.assertFalse(self.path().exists())
        self.assertTrue(workcopy.has_overlays(self.settings, self.target))
        self.assertEqual(workcopy.expected_state(self.settings, self.target),
                         workcopy.state_text(workcopy.state_of({**store, "revision": 1})))
        # And with neither file there is nothing.
        durable.backup_path(self.path()).unlink()
        self.assertFalse(workcopy.has_overlays(self.settings, self.target))
        self.assertIsNone(workcopy.expected_state(self.settings, self.target))


class CommittedSet(Case):
    """D32: committed iff the record's id is in the ids of a live commit entry; pending otherwise."""

    def records(self, count=5):
        return [workcopy._clean_record(rename_record(number, "0x4010%02x" % number), number - 1, number - 1)
                for number in range(1, count + 1)]

    def commit(self, ids, cid="c-1", reverted=False, **extra):
        return {"cid": cid, "generation": 1, "snapshot": 5, "ids": list(ids), "skipped": [], "at": 1.0, "reverted": reverted, **extra}

    def test_a_subset_commit_with_a_skipped_record_below_a_committed_one_replays_the_skipped_one(self):
        records = self.records(5)
        committed = [records[0]["id"], records[2]["id"], records[4]["id"]]
        store = {**self.store(), "revision": 5, "edits": records,
                 "commits": [self.commit(committed, skipped=[{"id": records[1]["id"], "reason": "drift"}])]}
        pending = workcopy.pending_of(store)
        self.assertEqual([edit["id"] for edit in pending], [records[1]["id"], records[3]["id"]])  # seq order
        self.assertEqual(workcopy.committed_ids(store), set(committed))
        # A watermark would have said "seq > 5 is pending" and taken record 2 (seq 2, below 3 and 5) for committed.
        self.assertTrue(records[1]["seq"] < records[2]["seq"])

    def test_the_marker_of_a_program_built_before_the_commit_no_longer_matches(self):
        records = self.records(3)
        before = {**self.store(), "revision": 3, "edits": records}
        marker = workcopy.state_of(before)
        self.assertEqual(workcopy._prefix_matches(workcopy.pending_of(before), marker, workcopy.state_of(before)), 3)
        after = {**before, "commits": [self.commit([records[0]["id"], records[1]["id"]])]}
        wanted = workcopy.state_of(after)
        self.assertEqual(wanted["edits"], 1)
        # The program built before the commit holds records 1 and 2 on the old base: replaying onto it would apply twice.
        self.assertIsNone(workcopy._prefix_matches(workcopy.pending_of(after), marker, wanted))
        # A program built after it (same committed set, same base) matches its pending prefix.
        built = workcopy.state_of({**after, "revision": 3})
        self.assertEqual(workcopy._prefix_matches(workcopy.pending_of(after), built, wanted), 1)
        # Another generation or lineage never matches, whatever the ids say.
        moved = {**after, "base": {"lineage": "L-1", "generation": 2}}
        self.assertIsNone(workcopy._prefix_matches(workcopy.pending_of(moved), built, workcopy.state_of(moved)))

    def test_a_v2_style_marker_matches_only_generation_zero_with_an_empty_committed_set(self):
        records = self.records(2)
        store = {**self.store(), "revision": 2, "edits": records}
        v2 = {key: workcopy.state_of(store)[key] for key in ("revision", "edits", "ids_sha256")}
        self.assertEqual(workcopy._prefix_matches(records, v2, workcopy.state_of(store)), 2)
        committed = {**store, "commits": [self.commit([records[0]["id"]])]}
        self.assertIsNone(workcopy._prefix_matches(workcopy.pending_of(committed), v2, workcopy.state_of(committed)))
        later_base = {**store, "base": {"lineage": "L-1", "generation": 1}}
        self.assertIsNone(workcopy._prefix_matches(records, v2, workcopy.state_of(later_base)))

    def test_a_reverted_commit_makes_its_records_pending_again(self):
        records = self.records(2)
        store = {**self.store(), "revision": 2, "edits": records, "commits": [self.commit([records[0]["id"]], reverted=True)]}
        self.assertEqual(len(workcopy.pending_of(store)), 2)
        self.assertEqual(workcopy.committed_ids(store), set())
        self.assertEqual(workcopy.state_of(store)["committed_sha256"], hashlib.sha256(b"").hexdigest())

    def test_the_commit_entry_is_validated_on_load(self):
        records = self.records(2)
        base = {**self.store(), "revision": 2, "edits": records}
        for bad, message in (([self.commit([records[0]["id"]]), self.commit([records[1]["id"]])], "repeat cid"),
                             ([self.commit([records[0]["id"]], ids_sha256="0" * 64)], "ids_sha256"),
                             ([{"cid": "c", "ids": "nope"}], "needs a cid")):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                workcopy._save_store(self.settings, self.target, {**base, "commits": bad})
        workcopy._save_store(self.settings, self.target, {**base, "commits": [self.commit([records[1]["id"], records[0]["id"]])]})
        entry = self.store()["commits"][0]
        self.assertEqual(entry["ids_sha256"], hashlib.sha256("\n".join(sorted([records[0]["id"], records[1]["id"]])).encode()).hexdigest())

    def test_the_working_copy_replays_only_the_pending_records(self):
        first = self.rename("One", ADDRESS_A)
        second = self.rename("Two", ADDRESS_B)
        third = self.rename("Three", "0x140003000")
        store = self.store()
        store["commits"] = [self.commit([first["overlay_id"], third["overlay_id"]])]
        workcopy._save_store(self.settings, self.target, store)
        workcopy.repair(self.settings, fakehydra.FakeEngine(self.settings), self.target)
        marker = json.loads(workcopy.expected_state(self.settings, self.target))
        self.assertEqual((marker["edits"], marker["committed_sha256"] != hashlib.sha256(b"").hexdigest()), (1, True))
        fork = self.daemon.projects[self.daemon._norm(workcopy._state(self.settings, self.target)["fork_gpr"])]
        names = dict(fork["programs"]["/owned.exe"]["live"]["names"])
        self.assertEqual(names.get(ADDRESS_B), "Two")
        self.assertNotIn("One", names.values())
        self.assertNotIn("Three", names.values())
        self.assertEqual(second["revision"], 2)


class Effects(Case):
    def test_an_edit_records_its_effects_seq_and_attribution(self):
        answer = self.rename("Known", ADDRESS_A)
        self.assertEqual(answer["effects"], [{"subject": "address:0x140001000", "field": "name",
                                              "before": "FUN_140001000", "after": "Known"}])
        record = self.store()["edits"][0]
        self.assertEqual((record["seq"], record["effects"], "before_unknown" in record), (1, answer["effects"], False))
        self.assertIn("by", record)
        again = self.rename("Better", ADDRESS_A)
        self.assertEqual(again["effects"][0]["before"], "Known")  # the chain: before is the earlier record's after
        self.assertEqual(self.store()["edits"][1]["seq"], 2)

    def test_a_script_that_reports_no_effects_leaves_the_record_before_unknown(self):
        with patch("hydralysis.hydra.Engine", fakehydra.FakeEngine):
            runner = query.QueryRunner(self.settings, fakehydra.FakeEngine(self.settings))
            answer = json.loads(runner.query("owned", "type_edit", ADDRESS_A, options={
                "kind": "rename", "name": "Quiet", "source": SOURCE, "expect_revision": 0, "view": "shared"}))
        self.assertTrue(answer["before_unknown"])
        record = self.store()["edits"][0]
        self.assertEqual((record["effects"], record["before_unknown"]), (None, True))

    def test_effects_are_validated(self):
        good = [{"subject": "address:0x1", "field": "comment:plate", "before": "absent", "after": "x"}]
        self.assertEqual(revisions.clean_effects(good), good)
        self.assertIsNone(revisions.clean_effects(None))
        for bad in ("x", [{"subject": "address:0x1"}], [{**good[0], "field": "mood"}], [{**good[0], "before": 3}],
                    [{**good[0], "extra": 1}], [{**good[0], "subject": ""}]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                revisions.clean_effects(bad)

    def test_the_field_vocabulary_derives_from_the_options_alone(self):
        self.assertEqual(revisions.fields_of("0x401000", {"kind": "rename", "name": "A"}), [("address:0x401000", "name")])
        self.assertEqual(revisions.fields_of("0x401000", {"kind": "struct", "path": "/A/B"}), [("type:/A/B", "definition")])
        self.assertEqual(revisions.fields_of("", {"kind": "import_types"}), [("*", "report")])
        batch = {"kind": "batch", "edits": [{"address": "0x401000", "options": {"kind": "comment"}},
                                            {"address": "0x401000", "options": {"kind": "variable", "variable": "v"}}]}
        self.assertEqual(revisions.fields_of("", batch), [("address:0x401000", "comment:plate"), ("address:0x401000", "variable:v")])
        self.assertEqual(revisions.fields_of("0x401000", {"kind": "label", "name": "g"}), [("address:0x401000", "label:g")])


class Revert(Case):
    def test_the_earlier_record_of_a_chain_is_refused_with_its_dependents_named(self):
        one = self.rename("One", ADDRESS_A)
        two = self.rename("Two", ADDRESS_A)
        other = self.rename("Other", ADDRESS_B)
        three = self.rename("Three", ADDRESS_A)
        with self.assertRaises(RuntimeError) as raised:
            self.revert([one["overlay_id"]])
        body = json.loads(str(raised.exception))
        self.assertEqual((body["error"], body["ids"]), ("has_dependents", [two["overlay_id"], three["overlay_id"]]))
        self.assertEqual(len(self.store()["edits"]), 4)  # nothing changed
        self.assertEqual(self.store()["revision"], 4)
        self.assertNotIn(other["overlay_id"], body["ids"])

    def test_cascade_removes_the_chain_and_leaves_other_subjects(self):
        one = self.rename("One", ADDRESS_A)
        two = self.rename("Two", ADDRESS_A)
        other = self.rename("Other", ADDRESS_B)
        done = self.revert([one["overlay_id"]], cascade=True)
        self.assertEqual((done["reverted"], done["cascaded"]), (2, [two["overlay_id"]]))
        self.assertEqual([edit["id"] for edit in self.store()["edits"]], [other["overlay_id"]])
        self.assertEqual(self.store()["reverted"][-1]["ids"], [one["overlay_id"], two["overlay_id"]])

    def test_the_last_record_of_a_chain_reverts_freely(self):
        one = self.rename("One", ADDRESS_A)
        two = self.rename("Two", ADDRESS_A)
        self.assertEqual(self.revert([two["overlay_id"]])["reverted"], 1)
        self.assertEqual(self.revert([one["overlay_id"]])["reverted"], 1)  # no later record rests on it now

    def test_a_legacy_record_without_effects_is_a_chain_by_its_options(self):
        self.v2_file([rename_record(1, ADDRESS_A, "Old1"), rename_record(2, ADDRESS_A, "Old2")])
        with self.assertRaises(RuntimeError) as raised:
            self.revert(["%032x" % 1])
        self.assertEqual(json.loads(str(raised.exception))["ids"], ["%032x" % 2])

    def test_reverting_by_batch_id_removes_the_whole_batch(self):
        records = [{**rename_record(number, "0x4010%02x" % number), "batch": "b" * 32} for number in (1, 2, 3)]
        store = self.store()
        store["edits"] = [workcopy._clean_record(record, index, index) for index, record in enumerate(records)]
        store["edits"] += [workcopy._clean_record(rename_record(9, "0x409000"), 3, 3)]
        store["revision"] = 4
        workcopy._save_store(self.settings, self.target, store)
        done = self.revert(["b" * 32])
        self.assertEqual(done["reverted"], 3)
        self.assertEqual([edit["id"] for edit in self.store()["edits"]], ["%032x" % 9])

    def test_a_committed_record_is_refused_with_already_committed(self):
        one = self.rename("One", ADDRESS_A)
        store = self.store()
        store["commits"] = [{"cid": "c-1", "generation": 1, "snapshot": 1, "ids": [one["overlay_id"]], "skipped": [], "at": 1.0,
                             "reverted": False}]
        workcopy._save_store(self.settings, self.target, store)
        with self.assertRaises(RuntimeError) as raised:
            self.revert([one["overlay_id"]])
        self.assertEqual(json.loads(str(raised.exception))["error"], "already_committed")
        # A reverted commit releases its records.
        store["commits"][0]["reverted"] = True
        workcopy._save_store(self.settings, self.target, store)
        self.assertEqual(self.revert([one["overlay_id"]])["reverted"], 1)

    def test_cascade_must_be_a_boolean(self):
        from hydralysis.analysis import validate_options
        self.assertEqual(validate_options("type_edit", {"kind": "revert", "ids": ["a" * 32], "cascade": True})["cascade"], True)
        with self.assertRaises(ValueError):
            validate_options("type_edit", {"kind": "revert", "ids": ["a" * 32], "cascade": "yes"})


class Changes(Case):
    def test_status_show_changes_lists_records_with_effects_and_commit_state(self):
        one = self.rename("One", ADDRESS_A)
        two = self.rename("Two", ADDRESS_B)
        store = self.store()
        store["commits"] = [{"cid": "c-1", "generation": 1, "snapshot": 1, "ids": [one["overlay_id"]], "skipped": [], "at": 1.0,
                             "reverted": False}]
        workcopy._save_store(self.settings, self.target, store)
        everything = json.loads(self.runner.query("owned", "status", options={"show": "changes"}))
        self.assertEqual([(row["seq"], row["state"]) for row in everything["changes"]], [(1, "committed"), (2, "pending")])
        self.assertEqual(everything["changes"][1]["effects"][0]["after"], "Two")
        self.assertEqual((everything["view_revision"], everything["truncated"]), (2, False))
        pending = json.loads(self.runner.query("owned", "status", options={"show": "changes", "state": "pending"}))
        self.assertEqual([row["id"] for row in pending["changes"]], [two["overlay_id"]])
        later = json.loads(self.runner.query("owned", "status", options={"show": "changes", "since": 1}))
        self.assertEqual([row["seq"] for row in later["changes"]], [2])
        paged = json.loads(self.runner.query("owned", "status", limit=1, options={"show": "changes"}))
        self.assertEqual((len(paged["changes"]), paged["truncated"], paged["next_since"]), (1, True, 1))
        plain = json.loads(self.runner.query("owned", "status"))
        self.assertEqual((plain["overlays"]["pending"], plain["overlays"]["committed"]), (1, 1))

    def test_status_options_are_validated(self):
        for options in ({"show": "all"}, {"since": 1}, {"show": "changes", "since": -1}, {"show": "changes", "state": "x"}, {"unknown": 1}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.runner.query("owned", "status", options=options)


class CrashWindow(Case):
    def test_a_kill_between_the_engine_apply_and_the_store_write_is_healed_by_the_marker(self):
        self.rename("One", ADDRESS_A)
        with patch.object(workcopy, "_save_store", side_effect=RuntimeError("killed before the store write")):
            with self.assertRaises(RuntimeError):
                self.rename("Lost", ADDRESS_B)
        store = self.store()
        self.assertEqual((store["revision"], len(store["edits"])), (1, 1))
        # The working copy claims two records; the store has one: the marker no longer matches, the next sync rebuilds.
        state = workcopy._state(self.settings, self.target)
        self.assertEqual(json.loads(state["state"])["edits"], 2)
        self.assertEqual(json.loads(workcopy.expected_state(self.settings, self.target))["edits"], 1)
        answer = json.loads(self.runner.query("owned", "decompile", ADDRESS_B))
        self.assertEqual(answer["function"]["name"], "FUN_140002000")  # the lost edit is not answered
        self.assertEqual(json.loads(self.runner.query("owned", "decompile", ADDRESS_A))["function"]["name"], "One")


if __name__ == "__main__":
    unittest.main()
