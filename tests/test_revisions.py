"""The subject-aware revision decision, without any engine."""

from __future__ import annotations

import unittest

from hydralysis import revisions
from hydralysis.revisions import WILDCARD, journal_entry, reconcile, subjects_of

ALICE = {"client": "alice", "harness": "h"}
BOB = {"client": "bob", "harness": "h"}


def history(*rows):
    """rows: (subjects, by); revision numbers follow from 1."""
    return [journal_entry(number, "edit", list(subjects), by, 100.0 + number) for number, (subjects, by) in enumerate(rows, 1)]


class Subjects(unittest.TestCase):
    def test_addresses_are_normalized_and_structs_are_named_by_path(self):
        self.assertEqual(subjects_of("140001000", {"kind": "rename"}), ["address:0x140001000"])
        self.assertEqual(subjects_of("0x140001000", {"kind": "rename"}), subjects_of("0X140001000".lower(), {"kind": "comment"}))
        self.assertEqual(subjects_of("", {"kind": "struct", "path": "/game/Thing"}), ["type:/game/Thing"])

    def test_batches_union_their_children_and_bulk_imports_touch_everything(self):
        batch = {"kind": "batch", "edits": [{"address": "0x10", "options": {"kind": "rename"}},
                                            {"address": "", "options": {"kind": "struct", "path": "/a/B"}}]}
        self.assertEqual(subjects_of("", batch), ["address:0x10", "type:/a/B"])
        for kind in ("import_types", "import_archive"):
            self.assertEqual(subjects_of("", {"kind": kind}), [WILDCARD])

    def test_function_structure_edits_always_overlap_each_other(self):
        create = subjects_of("0x10", {"kind": "function_create"})
        delete = subjects_of("0x9000", {"kind": "function_delete"})
        self.assertTrue(revisions.overlaps(create, delete) == {"structure:functions"})

    def test_an_edit_with_no_known_subject_is_a_wildcard(self):
        self.assertEqual(subjects_of("", {"kind": "comment"}), [WILDCARD])


class Reconcile(unittest.TestCase):
    def test_current_revision_is_accepted_without_a_rebase(self):
        decision = reconcile(2, 2, history((["address:0x1"], ALICE), (["address:0x2"], BOB)), ["address:0x1"])
        self.assertEqual((decision["outcome"], decision["current_revision"]), ("current", 2))
        self.assertEqual(decision["latest_editor"]["by"], BOB)

    def test_untouched_subjects_rebase_and_report_what_changed(self):
        journal = history((["address:0x1"], ALICE), (["address:0x2"], BOB))
        decision = reconcile(0, 2, journal, ["address:0x3"])
        self.assertEqual(decision["outcome"], "rebased")
        self.assertEqual(decision["subjects_changed_since"], ["address:0x1", "address:0x2"])
        self.assertEqual(decision["latest_editor"], {"by": BOB, "at": 102.0})

    def test_only_edits_after_the_expected_revision_count(self):
        journal = history((["address:0x1"], ALICE), (["address:0x2"], BOB))
        self.assertEqual(reconcile(1, 2, journal, ["address:0x1"])["outcome"], "rebased")
        decision = reconcile(1, 2, journal, ["address:0x2"])
        self.assertEqual((decision["outcome"], decision["overlapping"]), ("conflict", ["address:0x2"]))
        self.assertEqual(decision["latest_editor"]["by"], BOB)

    def test_a_wildcard_on_either_side_conflicts(self):
        journal = history((["address:0x1"], ALICE))
        self.assertEqual(reconcile(0, 1, journal, [WILDCARD])["outcome"], "conflict")
        journal = history(([WILDCARD], ALICE))
        decision = reconcile(0, 1, journal, ["address:0x9"])
        self.assertEqual((decision["outcome"], decision["overlapping"]), ("conflict", ["address:0x9"]))

    def test_a_gap_in_the_journal_is_never_rebased(self):
        journal = [entry for entry in history((["a:1"], ALICE), (["a:2"], BOB), (["a:3"], ALICE)) if entry["revision"] != 2]
        decision = reconcile(0, 3, journal, ["address:0x9"])
        self.assertEqual((decision["outcome"], decision["history_complete"]), ("conflict", False))
        self.assertEqual(reconcile(2, 3, journal, ["address:0x9"])["outcome"], "rebased")

    def test_an_empty_journal_cannot_prove_a_stale_edit_independent(self):
        decision = reconcile(0, 4, [], ["address:0x9"])
        self.assertEqual((decision["outcome"], decision["history_complete"]), ("conflict", False))
        self.assertEqual(reconcile(0, 0, [], ["address:0x9"])["outcome"], "current")

    def test_a_revision_from_the_future_or_a_missing_one_conflicts(self):
        self.assertEqual(reconcile(5, 2, history(([WILDCARD], ALICE), ([WILDCARD], BOB)), ["address:0x9"])["outcome"], "conflict")
        self.assertEqual(reconcile(None, 2, [], ["address:0x9"])["outcome"], "conflict")


class Payloads(unittest.TestCase):
    def test_conflict_payload_names_editor_subjects_and_the_retry_revision(self):
        journal = history((["address:0x1"], ALICE))
        decision = reconcile(0, 1, journal, ["address:0x1"])
        body = revisions.conflict_payload(0, decision, ["address:0x1"])
        self.assertEqual((body["conflict"], body["expected_revision"], body["current_revision"]), ("overlay revision changed", 0, 1))
        self.assertEqual(body["latest_editor"]["by"], ALICE)
        self.assertEqual(body["subjects_changed_since"], ["address:0x1"])
        self.assertIn("expect_revision=1", body["suggest"])

    def test_missing_payload_carries_the_current_revision(self):
        body = revisions.missing_payload(7, "shared", "type_edit")
        self.assertEqual((body["error"], body["current_revision"], body["view_revision"]), ("expect_revision_required", 7, 7))
        self.assertIn("expect_revision=7", body["suggest"])


class Journal(unittest.TestCase):
    def test_it_is_bounded_and_malformed_entries_are_dropped(self):
        journal = []
        for number in range(1, revisions.MAX_JOURNAL + 5):
            journal = revisions.append(journal, journal_entry(number, "edit", ["a:1"], ALICE, 1.0))
        self.assertEqual(len(journal), revisions.MAX_JOURNAL)
        self.assertEqual(journal[0]["revision"], 5)
        cleaned = revisions.clean_journal([{"revision": 1, "subjects": ["a"]}, {"revision": "2", "subjects": []},
                                           {"revision": True, "subjects": []}, "junk", {"revision": 3, "subjects": [1]}])
        self.assertEqual([entry["revision"] for entry in cleaned], [1])
        self.assertEqual(revisions.clean_journal(None), [])

    def test_an_oversized_subject_list_becomes_a_wildcard(self):
        many = ["address:%#x" % number for number in range(revisions.MAX_SUBJECTS + 1)]
        self.assertEqual(journal_entry(1, "revert", many, ALICE, 1.0)["subjects"], [WILDCARD])


class SubjectRecord(unittest.TestCase):
    """The effect and field vocabulary of store v3, and which records rest on which (revert with dependents)."""

    @staticmethod
    def record(ident, seq, address, kind="rename", effects=None, **options):
        return {"id": ident, "seq": seq, "address": address, "options": {"kind": kind, "source": "s", **options},
                "effects": effects}

    def test_every_field_kind_of_the_vocabulary_is_accepted_and_nothing_else(self):
        for field in ("name", "label:g", "comment:plate", "signature", "type", "variable:local_8", "definition", "body",
                      "existence", "report"):
            with self.subTest(field=field):
                self.assertEqual(len(revisions.clean_effects([{"subject": "address:0x1", "field": field, "before": None,
                                                              "after": "x"}])), 1)
        for field in ("", "names", "comments:plate", "Name"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                revisions.clean_effects([{"subject": "address:0x1", "field": field, "before": "a", "after": "b"}])

    def test_a_chain_is_the_later_pending_records_of_the_same_subject_and_field(self):
        records = [self.record("a", 1, "0x10", name="A"), self.record("b", 2, "0x10", name="B"),
                   self.record("c", 3, "0x20", name="C"), self.record("d", 4, "0x10", kind="comment", comment="x"),
                   self.record("e", 5, "0x10", name="E")]
        self.assertEqual(revisions.dependents(records, {"a"}), ["b", "e"])  # the comment is another field
        self.assertEqual(revisions.dependents(records, {"e"}), [])
        self.assertEqual(revisions.dependents(records, {"c"}), [])
        self.assertEqual(revisions.dependents(records, {"b"}), ["e"])

    def test_the_closure_follows_a_batch_that_touches_two_subjects(self):
        batch = self.record("b2", 2, "", kind="batch",
                            edits=[{"address": "0x10", "options": {"kind": "rename", "name": "X"}},
                                   {"address": "0x20", "options": {"kind": "rename", "name": "Y"}}])
        records = [self.record("a", 1, "0x10", name="A"), batch, self.record("c", 3, "0x20", name="C")]
        self.assertEqual(revisions.dependents(records, {"a"}), ["b2", "c"])

    def test_committed_records_are_not_dependents_and_reports_are_not_a_chain(self):
        records = [self.record("a", 1, "0x10", name="A"), self.record("b", 2, "0x10", name="B")]
        self.assertEqual(revisions.dependents(records, {"a"}, committed={"b"}), [])
        imports = [self.record("i1", 1, "", kind="import_types"), self.record("i2", 2, "", kind="import_types")]
        self.assertEqual(revisions.dependents(imports, {"i1"}), [])

    def test_effects_win_over_options_when_a_record_has_them(self):
        effects = [{"subject": "address:0x10", "field": "name", "before": "FUN_10", "after": "A"}]
        record = self.record("a", 1, "0x10", name="A", effects=effects)
        self.assertEqual(revisions.touches(record), {("address:0x10", "name")})
        self.assertEqual(revisions.touches({**record, "effects": None}), {("address:0x10", "name")})


if __name__ == "__main__":
    unittest.main()
