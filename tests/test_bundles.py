"""Annotation bundles (PROTOCOL-3.md 4.9): export is read-only, import is a dry run unless `apply`.

Against the fake daemon (tests/fakehydra.py) with the effects-reporting engine of tests/test_store_v3.py.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from hydralysis import annotations, durable, query, revisions, workcopy
from test_store_v3 import ADDRESS_A, ADDRESS_B, Case as StoreCase, rename_record


class Bundles(StoreCase):
    def export(self, **options):
        return annotations.export_bundle(self.settings, "owned", **options)

    def two_renames(self):
        one = self.rename("One", ADDRESS_A)
        two = self.rename("Two", ADDRESS_B)
        return one, two

    def import_dry(self, bundle, view="alice", **options):
        return annotations.import_bundle(self.settings, "owned", bundle, view=view, **options)

    def import_apply(self, bundle, view="alice", expect=None, **options):
        revision = self.store(view)["revision"] if expect is None else expect
        return annotations.import_bundle(self.settings, "owned", bundle, view=view, apply=True, expect_revision=revision, **options)


class Export(Bundles):
    def test_a_bundle_binds_program_base_store_and_records_by_hash(self):
        one, two = self.two_renames()
        bundle = self.export()["bundle"]
        self.assertEqual(bundle["format"], annotations.FORMAT)
        self.assertEqual(bundle["program"]["sha256"], self.digest)
        self.assertEqual((bundle["program"]["name"], bundle["program"]["image_base"]), ("/owned.exe", "0x140000000"))
        self.assertEqual({key: bundle["base"][key] for key in ("lineage", "generation")}, {"lineage": "", "generation": 0})
        self.assertEqual(bundle["base"]["engine"], {"hydraVersion": "12.3-hydra.2", "ghidraVersion": "12.3"})
        self.assertEqual((bundle["store"]["view"], bundle["store"]["revision"]), ("shared", 2))
        self.assertEqual(bundle["store"]["ids_sha256"], workcopy._digest_of([one["overlay_id"], two["overlay_id"]]))
        first = bundle["records"][0]
        self.assertEqual((first["id"], first["address"], first["va"], first["rva"], first["kind"], first["committed"]),
                         (one["overlay_id"], ADDRESS_A, 0x140001000, 0x1000, "rename", False))
        self.assertEqual(first["effects"], one["effects"])
        self.assertEqual(first["source"], "cited test evidence")
        self.assertEqual(set(first["by"]), {"client", "harness"})
        self.assertEqual(bundle["bundle_sha256"], annotations.bundle_hash(bundle))
        self.assertEqual(annotations.bundle_hash({**bundle, "bundle_sha256": "x"}), bundle["bundle_sha256"])
        changed = json.loads(json.dumps(bundle))
        changed["records"][0]["options"]["name"] = "Tampered"
        self.assertNotEqual(annotations.bundle_hash(changed), bundle["bundle_sha256"])

    def test_the_hash_is_over_the_canonical_form_so_key_order_does_not_matter(self):
        self.two_renames()
        bundle = self.export()["bundle"]
        reordered = {key: bundle[key] for key in reversed(list(bundle))}
        self.assertEqual(annotations.bundle_hash(reordered), bundle["bundle_sha256"])

    def test_no_path_no_personal_data_no_game_bytes(self):
        self.two_renames()
        store = self.store()
        store["edits"].append(workcopy._clean_record({
            "id": "c" * 32, "address": "", "by": {"client": "C:\\Users\\someone\\x", "harness": "codex", "user": "alice"},
            "at": 1.0, "options": {"kind": "import_types", "source": "corpus", "corpus_sha256": "a" * 64, "corpus_bytes": 9,
                                   "corpus_input": "D:\\Games\\KOTOR\\types.jsonl"}}, 2, 2))
        store["edits"].append(workcopy._clean_record({
            "id": "d" * 32, "address": "", "at": 2.0, "options": {
                "kind": "batch", "source": "b", "input_file": "C:\\Users\\someone\\batch.json", "input_file_sha256": "b" * 64,
                "input_file_bytes": 5, "edits": [{"address": "0x401000", "options": {"kind": "rename", "name": "N", "source": "b"}}]}}, 3, 3))
        store["revision"] = 4
        workcopy._save_store(self.settings, self.target, store)
        text = json.dumps(self.export()["bundle"])
        for forbidden in ("C:\\\\", "D:\\\\", "someone", "alice", "KOTOR", str(self.root).replace("\\", "\\\\")):
            self.assertNotIn(forbidden, text)
        bundle = json.loads(text)
        bulk = next(record for record in bundle["records"] if record["kind"] == "import_types")
        self.assertEqual(bulk["options"]["corpus_sha256"], "a" * 64)  # the hash of the input, never the input
        self.assertNotIn("corpus_input", bulk["options"])
        self.assertIsNone(bulk["by"] and bulk["by"].get("user"))
        self.assertEqual(bulk["by"], {"harness": "codex"})  # the client looked like a path

    def test_filters_by_id_author_revision_range_and_state(self):
        one, two = self.two_renames()
        store = self.store()
        store["commits"] = [{"cid": "c-1", "generation": 1, "snapshot": 1, "ids": [one["overlay_id"]], "skipped": [], "at": 1.0,
                             "reverted": False}]
        workcopy._save_store(self.settings, self.target, store)
        ids = lambda **options: [record["id"] for record in self.export(**options)["bundle"]["records"]]  # noqa: E731
        self.assertEqual(ids(), [one["overlay_id"], two["overlay_id"]])
        self.assertEqual(ids(state="pending"), [two["overlay_id"]])
        self.assertEqual(ids(state="committed"), [one["overlay_id"]])
        self.assertEqual(ids(ids=[two["overlay_id"]]), [two["overlay_id"]])
        self.assertEqual(ids(since=1), [two["overlay_id"]])
        self.assertEqual(ids(until=1), [one["overlay_id"]])
        harness = self.export()["bundle"]["records"][0]["by"]["harness"]
        self.assertEqual(ids(authors=[harness]), [one["overlay_id"], two["overlay_id"]])
        self.assertEqual(ids(authors=["somebody else"]), [])
        committed = {record["id"]: record["committed"] for record in self.export()["bundle"]["records"]}
        self.assertEqual(committed, {one["overlay_id"]: True, two["overlay_id"]: False})  # information only
        with self.assertRaises(ValueError):
            self.export(state="maybe")

    def test_export_is_read_only_and_writes_one_file(self):
        self.two_renames()
        before = {item: item.read_bytes() for item in (self.root / "data").rglob("*") if item.is_file()}
        out = self.root / "out"
        result = self.export(path=out / "alpha")
        written = Path(result["path"])
        self.assertEqual(written.name, "alpha" + annotations.SUFFIX)
        self.assertTrue(written.is_file())
        self.assertEqual(annotations.bundle_hash(json.loads(written.read_text(encoding="utf-8"))), result["bundle_sha256"])
        self.assertNotIn("bundle", result)
        after = {item: item.read_bytes() for item in (self.root / "data").rglob("*") if item.is_file()}
        self.assertEqual({key: value for key, value in after.items() if key in before}, before)  # nothing changed
        self.assertEqual(set(after) - set(before), set())  # and nothing new under the data root
        self.assertEqual([item.name for item in out.iterdir()], [written.name])

    def test_archived_records_are_read_on_demand_and_a_bad_archive_refuses(self):
        one, _ = self.two_renames()
        store = self.store()
        old = workcopy._clean_record(rename_record(7, "0x140009000", "Archived"), 0, 0)
        old["seq"] = 0 + 1
        entry = {"cid": "c-old", "generation": 1, "count": 1, "ids_sha256": workcopy._digest_of([old["id"]]), "archive": "x"}
        store["archived"] = [entry]
        workcopy._save_store(self.settings, self.target, store)
        archive = annotations._archive_path(self.settings, self.target, "c-old")
        with self.assertRaisesRegex(ValueError, "archive_unreadable"):  # the entry names an archive that is not there yet
            self.export(state="committed")
        archive.parent.mkdir(parents=True, exist_ok=True)
        durable.write_sealed(archive, {"records": [old]})
        bundle = self.export(state="committed")["bundle"]
        self.assertEqual([(record["id"], record["committed"]) for record in bundle["records"]], [(old["id"], True)])
        everything = self.export()["bundle"]["records"]
        self.assertEqual([record["id"] for record in everything], [old["id"], one["overlay_id"], everything[2]["id"]])
        durable.write_sealed(archive, {"records": [{**old, "id": "e" * 32}]})
        with self.assertRaisesRegex(ValueError, "archive_unreadable"):
            self.export()
        durable.backup_path(archive).unlink()  # with a valid previous version the sealed read would fall back to it
        archive.write_bytes(b"torn")
        with self.assertRaisesRegex(ValueError, "archive_unreadable"):
            self.export()
        archive.unlink()
        with self.assertRaisesRegex(ValueError, "archive_unreadable"):
            self.export()


class ImportDryRun(Bundles):
    def test_a_fresh_target_view_reports_hash_sha256_and_no_drift(self):
        self.two_renames()
        bundle = self.export()["bundle"]
        report = self.import_dry(bundle)
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["dry_run"])
        self.assertEqual((report["bundle"]["hash_ok"], report["bundle"]["program_sha256_ok"], report["base_drift"]),
                         (True, True, []))
        self.assertEqual(report["would_add"], [record["id"] for record in bundle["records"]])
        self.assertEqual(self.store("alice")["edits"], [])  # a dry run adds nothing
        self.assertTrue(report["base"]["same_master"])
        self.assertEqual(report["unverified"], [])

    def test_a_changed_bundle_a_wrong_build_and_a_wrong_format_are_refused_with_the_reason(self):
        self.two_renames()
        bundle = self.export()["bundle"]
        tampered = json.loads(json.dumps(bundle))
        tampered["records"][0]["options"]["name"] = "Tampered"
        report = self.import_dry(tampered)
        self.assertEqual((report["ok"], report["bundle"]["hash_ok"], report["would_add"]), (False, False, [report["would_add"][0], report["would_add"][1]]))
        self.assertTrue(any("bundle_sha256" in problem for problem in report["problems"]), report["problems"])
        other = {**bundle, "program": {**bundle["program"], "sha256": "0" * 64}}
        other["bundle_sha256"] = annotations.bundle_hash(other)
        report = self.import_dry(other)
        self.assertEqual((report["ok"], report["bundle"]["hash_ok"], report["bundle"]["program_sha256_ok"]), (False, True, False))
        self.assertEqual(report["base_drift"], [])  # nothing is probed against the wrong build
        foreign = {**bundle, "format": "something/9"}
        foreign["bundle_sha256"] = annotations.bundle_hash(foreign)
        self.assertFalse(self.import_dry(foreign)["ok"])
        language = {**bundle, "program": {**bundle["program"], "language": "x86:LE:32:default", "compiler": "gcc"}}
        language["bundle_sha256"] = annotations.bundle_hash(language)
        self.assertTrue(self.import_dry(language)["ok"])  # the fake engine reports none: nothing to compare

    def test_base_drift_names_the_record_subject_field_and_both_values(self):
        one, two = self.two_renames()
        bundle = self.export()["bundle"]
        self.rename("Elsewhere", ADDRESS_A, view="alice")  # the target moved: its name at A is no longer FUN_...
        report = self.import_dry(bundle)
        self.assertTrue(report["ok"], report)  # drift is reported, it is not a refusal of the dry run
        self.assertEqual(report["base_drift"], [{"id": one["overlay_id"], "subject": "address:0x140001000", "field": "name",
                                                 "expected": "FUN_140001000", "found": "Elsewhere"}])

    def test_only_the_first_effect_of_a_chain_is_compared_with_the_target(self):
        one = self.rename("One", ADDRESS_A)
        again = self.rename("Better", ADDRESS_A)
        report = self.import_dry(self.export()["bundle"])
        self.assertEqual(report["base_drift"], [])
        self.assertEqual(report["chain_breaks"], [])
        bundle = self.export(ids=[again["overlay_id"]])["bundle"]  # the record before it is missing
        report = self.import_dry(bundle)
        self.assertEqual([(item["id"], item["expected"], item["found"]) for item in report["base_drift"]],
                         [(again["overlay_id"], "One", "FUN_140001000")])
        full = self.export()["bundle"]
        gap = {**full, "records": [full["records"][1], full["records"][0]]}  # out of order: a break inside the bundle
        gap["bundle_sha256"] = annotations.bundle_hash(gap)
        self.assertEqual([item["id"] for item in self.import_dry(gap)["chain_breaks"]], [one["overlay_id"]])

    def test_a_bulk_record_needs_its_input_in_this_root(self):
        self.two_renames()
        store = self.store()
        store["edits"].append(workcopy._clean_record({
            "id": "c" * 32, "address": "", "at": 1.0, "options": {"kind": "import_types", "source": "corpus",
                                                                   "corpus_sha256": "a" * 64, "corpus_bytes": 9}}, 2, 2))
        store["revision"] = 3
        workcopy._save_store(self.settings, self.target, store)
        report = self.import_dry(self.export()["bundle"])
        self.assertFalse(report["ok"])
        self.assertEqual(report["missing_inputs"], [{"id": "c" * 32, "needs": "corpus sha256 " + "a" * 64}])
        corpus = workcopy.corpus_path(self.settings, "a" * 64)
        corpus.parent.mkdir(parents=True)
        corpus.write_bytes(b"{}\n")
        self.assertTrue(self.import_dry(self.export()["bundle"])["ok"])

    def test_a_bundle_is_read_from_a_path_and_a_huge_one_is_refused(self):
        self.two_renames()
        path = Path(self.export(path=self.root / "b")["path"])
        self.assertTrue(self.import_dry(str(path))["ok"])
        from unittest.mock import patch
        with patch.object(annotations, "MAX_BUNDLE_BYTES", 10), self.assertRaisesRegex(ValueError, "exceeds"):
            self.import_dry(str(path))


class ImportApply(Bundles):
    def test_apply_adds_proposals_with_new_ids_imported_from_and_this_views_effects(self):
        one, two = self.two_renames()
        bundle = self.export()["bundle"]
        report = self.import_apply(bundle)
        self.assertTrue(report["applied"], report)
        self.assertEqual(len(report["added"]), 2)
        records = self.store("alice")["edits"]
        self.assertEqual([record["id"] for record in records], report["added"])
        self.assertTrue(all(record["id"] not in (one["overlay_id"], two["overlay_id"]) for record in records))
        self.assertEqual([record["seq"] for record in records], [1, 2])
        self.assertEqual(self.store("alice")["revision"], 2)
        first = records[0]
        self.assertEqual({key: first["imported_from"][key] for key in ("bundle_sha256", "id", "view")},
                         {"bundle_sha256": bundle["bundle_sha256"], "id": one["overlay_id"], "view": "shared"})
        self.assertEqual(first["options"]["name"], "One")
        self.assertEqual(first["effects"], one["effects"])  # the target's own before and after (same here)
        self.assertEqual(self.ask("decompile", ADDRESS_A, "alice")["function"]["name"], "One")  # the working copy replays them
        # They are proposals: the shared view and any generation are untouched.
        self.assertEqual(len(self.store()["edits"]), 2)
        self.assertEqual(self.store("alice")["commits"], [])
        self.assertEqual(self.store("alice")["base"], {"lineage": "", "generation": 0})

    def ask(self, action, address, view):
        return json.loads(self.runner.query("owned", action, address, options={"view": view}))

    def test_importing_the_same_bundle_twice_adds_nothing_the_second_time(self):
        self.two_renames()
        bundle = self.export()["bundle"]
        self.import_apply(bundle)
        again = self.import_dry(bundle)
        self.assertEqual((again["would_add"], len(again["already_present"])), ([], 2))
        done = self.import_apply(bundle)
        self.assertEqual((done["applied"], done["added"]), (False, []))
        self.assertEqual(len(self.store("alice")["edits"]), 2)

    def test_apply_needs_a_named_view_and_the_mandatory_revision(self):
        self.two_renames()
        bundle = self.export()["bundle"]
        with self.assertRaisesRegex(ValueError, "named view"):
            annotations.import_bundle(self.settings, "owned", bundle, view="", apply=True, expect_revision=2)
        with self.assertRaisesRegex(ValueError, "named view"):
            annotations.import_bundle(self.settings, "owned", bundle, view="shared", apply=True, expect_revision=2)
        with self.assertRaises(RuntimeError) as raised:
            annotations.import_bundle(self.settings, "owned", bundle, view="alice", apply=True)
        self.assertEqual(json.loads(str(raised.exception))["error"], "expect_revision_required")
        self.assertEqual(self.store("alice")["edits"], [])

    def test_a_stale_revision_that_overlaps_conflicts_and_one_that_does_not_is_rebased(self):
        self.two_renames()
        bundle = self.export()["bundle"]
        self.rename("Clash", ADDRESS_A, view="alice")  # revision 1 of alice touches address A
        with self.assertRaisesRegex(RuntimeError, "overlay revision changed"):
            self.import_apply(bundle, expect=0)
        self.assertEqual(len(self.store("alice")["edits"]), 1)
        rebased = self.import_apply(self.export(ids=[bundle["records"][1]["id"]])["bundle"], expect=0)
        self.assertTrue(rebased["rebased"], rebased)  # address B was untouched since revision 0

    def test_a_refused_bundle_changes_nothing(self):
        self.two_renames()
        bundle = self.export()["bundle"]
        tampered = json.loads(json.dumps(bundle))
        tampered["records"][0]["options"]["name"] = "Tampered"
        with self.assertRaisesRegex(ValueError, "bundle refused"):
            self.import_apply(tampered)
        other = {**bundle, "program": {**bundle["program"], "sha256": "0" * 64}}
        other["bundle_sha256"] = annotations.bundle_hash(other)
        with self.assertRaisesRegex(ValueError, "bundle refused"):
            self.import_apply(other)
        self.assertEqual((self.store("alice")["edits"], self.store("alice")["revision"]), ([], 0))

    def test_records_without_effects_need_allow_unverified_before(self):
        self.v2_file([rename_record(1, "0x140001000", "Legacy")])
        bundle = self.export()["bundle"]
        self.assertEqual(bundle["records"][0]["effects"], None)
        self.assertTrue(bundle["records"][0]["before_unknown"])
        report = self.import_dry(bundle)
        self.assertEqual(report["unverified"], [bundle["records"][0]["id"]])
        with self.assertRaisesRegex(ValueError, "allow_unverified_before"):
            self.import_apply(bundle)
        done = self.import_apply(bundle, allow_unverified_before=True)
        self.assertTrue(done["applied"])
        # The engine measured them here, so the imported copy is no longer before-unknown.
        self.assertIsNotNone(self.store("alice")["edits"][0]["effects"])

    def test_an_invalid_record_is_listed_and_refuses_the_apply(self):
        self.two_renames()
        bundle = self.export()["bundle"]
        broken = json.loads(json.dumps(bundle))
        broken["records"][0]["options"] = {"kind": "rename", "name": "X"}  # no source
        broken["bundle_sha256"] = annotations.bundle_hash(broken)
        report = self.import_dry(broken)
        self.assertEqual([item["id"] for item in report["invalid"]], [bundle["records"][0]["id"]])
        self.assertFalse(report["ok"])
        with self.assertRaisesRegex(ValueError, "bundle refused"):
            self.import_apply(broken)

    def test_the_replay_set_of_the_importing_view_contains_the_proposals(self):
        self.two_renames()
        self.import_apply(self.export()["bundle"])
        store = self.store("alice")
        self.assertEqual(len(workcopy.pending_of(store)), 2)
        self.assertEqual(json.loads(workcopy.expected_state(self.settings, workcopy.with_view(self.runner.target("owned"), "alice")))["edits"], 2)
        self.assertEqual(revisions.fields_of(store["edits"][0]["address"], store["edits"][0]["options"]),
                         [("address:0x140001000", "name")])


if __name__ == "__main__":
    unittest.main()
