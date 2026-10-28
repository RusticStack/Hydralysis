import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import durable, workcopy
from hydralysis.analysis import _edit, validate_options

from support import workdir


class AdvancedBudgets(unittest.TestCase):
    def test_trace_limits_are_bounded_and_reject_boolean_or_unknown_knobs(self):
        value = validate_options("trace", {})
        self.assertEqual(value, {"seed": "", "direction": "backward", "depth": 5, "nodes": 80, "functions": 1, "callers": 0})
        self.assertEqual(validate_options("trace", {"argument": 1, "brief": True, "callers": 2})["argument"], 1)
        for options in ({"nodes": 201}, {"nodes": True}, {"functions": 9}, {"depth": 33}, {"callers": 5},
                        {"argument": 16}, {"brief": "yes"}, {"direction": "both"}, {"unlimited": True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                validate_options("trace", options)
        self.assertEqual(validate_options("decompile", {"max_characters": 2097152}), {"max_characters": 2097152})
        self.assertEqual(validate_options("data", {"table": True}), {"table": True})
        self.assertEqual(validate_options("scan", {"end": "0x401100", "mnemonic": "call", "operand": "rax"})["mnemonic"], "call")
        for action, options in (("decompile", {"max_characters": 2097153}), ("data", {"table": "true"}),
                                ("scan", {"end": "rva:0x1000"}), ("scan", {"regex": "("}), ("scan", {"regex": "x" * 257})):
            with self.subTest(action=action, options=options), self.assertRaises(ValueError):
                validate_options(action, options)

    def test_orphans_take_only_a_boolean_filter(self):
        self.assertEqual(validate_options("orphans", {"referenced_only": True}), {"referenced_only": True})
        for bad in ({"referenced_only": "yes"}, {"offset": "0x10"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_options("orphans", bad)

    def test_type_edits_require_a_source_and_matching_kind_fields(self):
        for options in ({"kind": "rename", "name": "KnownName"},
                        {"kind": "rename", "name": "KnownName", "source": " "},
                        {"kind": "rename", "name": "KnownName", "source": "map row 7", "prototype": "void x()"},
                        {"kind": "apply", "source": "map row 7"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                validate_options("type_edit", options)

    def test_data_label_requires_a_name_and_a_cited_source(self):
        label = {"kind": "label", "name": "global_fixture", "source": "fixture map:17"}
        self.assertEqual(validate_options("type_edit", label), label)
        for bad in ({"kind": "label", "name": "global_fixture"},
                    {"kind": "label", "source": "fixture map:17"},
                    {**label, "prototype": "void f()"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_options("type_edit", bad)

    def test_structure_layout_and_nested_aliases_are_validated(self):
        options = {"kind": "struct", "source": "fixture header:3", "path": "/RusticRE/Header", "size": 8,
                   "fields": [{"offset": 0, "type": "int", "name": "count", "length": 4}]}
        clean = validate_options("type_edit", options)
        options["fields"][0]["offset"] = 7
        self.assertEqual(clean["fields"][0]["offset"], 0)
        with self.assertRaises(ValueError):
            validate_options("type_edit", options)
        options["fields"][0]["offset"] = 0
        options["fields"].append(dict(options["fields"][0]))
        with self.assertRaisesRegex(ValueError, "unique"):
            validate_options("type_edit", options)

    def test_function_edits_require_exact_bytes_and_explicit_nonoverlapping_ranges(self):
        edit = {"kind": "function_create", "source": "fixture disassembly:12", "expect": "55 8b ec",
                "ranges": [{"start": "0x401000", "end": "0x40100f"}, {"start": "0x401020", "end": "0x40102f"}],
                "name": "known_fixture"}
        clean = validate_options("type_edit", edit)
        self.assertEqual(clean["expect"], "55 8B EC")
        self.assertEqual(len(clean["ranges"]), 2)
        for change in ({"expect": "?? ?? ??"}, {"expect": ""}, {"ranges": []},
                       {"ranges": [{"start": "0x40100f", "end": "0x401000"}]},
                       {"ranges": [{"start": "0x401000", "end": "0x40100f"}, {"start": "0x401008", "end": "0x401020"}]},
                       {"ranges": [{"start": "rva:0x1000", "end": "0x40100f"}]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_options("type_edit", {**edit, **change})

    def test_function_deletion_does_not_accept_a_body_and_requires_cited_bytes(self):
        edit = {"kind": "function_delete", "source": "fixture false entry audit:9", "expect": "90"}
        self.assertEqual(validate_options("type_edit", edit), edit)
        with self.assertRaises(ValueError):
            validate_options("type_edit", {**edit, "ranges": [{"start": "0x401000", "end": "0x40100f"}]})
        with self.assertRaises(ValueError):
            validate_options("type_edit", {**edit, "expect": "90 " * 65})

    def test_batch_validates_all_children_inherits_sources_and_refuses_nesting(self):
        children = [{"address": "0x401000", "options": {"kind": "rename", "name": "Known"}},
                    {"address": "0x401020", "options": {"kind": "comment", "comment": "observed", "source": "specific.c:9"}}]
        clean = validate_options("type_edit", {"kind": "batch", "source": "audit:4", "edits": children})
        self.assertEqual(clean["edits"][0]["options"]["source"], "audit:4")
        self.assertEqual(clean["edits"][1]["options"]["source"], "specific.c:9")
        children[0]["options"]["name"] = "Changed"
        self.assertEqual(clean["edits"][0]["options"]["name"], "Known")
        for bad in ([], children * 101, [{"address": "0x401000", "options": {"kind": "batch", "edits": children}}],
                    [children[0], {"address": "0x401000", "options": {"kind": "rename"}}]):
            with self.subTest(bad=bad[:2]), self.assertRaises(ValueError):
                validate_options("type_edit", {"kind": "batch", "source": "audit:4", "edits": bad})


class DurableOverlays(unittest.TestCase):
    """The overlay store's rules, asserted where production enforces them.

    The legacy v1 writer `analysis.save_overlay` and its reader are gone (8.2). Each rule moved to the function
    that has it: `workcopy._save_store` (byte cap, durable write), `workcopy.load_store` (count cap, other build,
    duplicate ids), `workcopy.edit` (count cap on append), `analysis._overlay_path` and `analysis._edit` (target
    key, missing address). Dropped, on purpose (no production path has them: `edit()` mints a new id every time):
    appending the same id twice is one record, and a changed edit under an existing id is refused.
    """

    def setUp(self):
        self.temp = workdir()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sha = "a" * 64
        self.settings = {"root": str(self.root)}
        self.target = {"key": "target1", "sha256": self.sha}
        self.edit = {"id": "b" * 32, "address": "0x401000",
                     "options": {"kind": "signature", "prototype": "int known(int x)", "source": "fixture.c:4"}}

    def store(self, edits, revision=None):
        return {"version": 3, "sha256": self.sha, "revision": len(edits) if revision is None else revision, "edits": edits,
                "reverted": [], "journal": []}

    def save(self, edits, key="target1", revision=None):
        target = {**self.target, "key": key}
        workcopy._save_store(self.settings, target, self.store(edits, revision))
        return target

    def path(self, key="target1"):
        return self.root / "overlays" / (key + ".json")

    @staticmethod
    def plain(edits):
        return [{key: edit[key] for key in ("id", "address", "options")} for edit in edits]

    def test_successful_edit_survives_new_reader(self):
        target = self.save([self.edit])
        self.assertEqual(self.plain(workcopy.load_store(self.settings, target)["edits"]), [self.edit])
        self.assertEqual(self.plain(workcopy.load_store(self.settings, target)["edits"]), [self.edit])
        self.assertFalse((self.root / "overlays" / "target1.tmp").exists())
        self.assertEqual([item.name for item in (self.root / "overlays").iterdir() if item.suffix == ".tmp"], [])

    def test_changed_build_cannot_replay_another_builds_types(self):
        target = self.save([self.edit])
        before = self.path().read_bytes()
        with self.assertRaisesRegex(ValueError, "another build"):
            workcopy.load_store(self.settings, {**target, "sha256": "c" * 64})
        self.assertEqual(self.path().read_bytes(), before)

    def test_read_missing_history_has_no_filesystem_side_effect(self):
        self.assertEqual(workcopy.load_store(self.settings, {**self.target, "key": "new"})["edits"], [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_corrupt_or_duplicate_history_is_refused_and_preserved(self):
        target = self.save([self.edit])
        record = json.loads(self.path().read_text())
        record.pop("seal")
        record["edits"].append(record["edits"][0])
        durable.write_sealed(self.path(), record)
        before = self.path().read_bytes()
        with self.assertRaisesRegex(ValueError, "duplicate|out of order"):
            workcopy.load_store(self.settings, target)
        self.assertEqual(self.path().read_bytes(), before)
        # The same duplicate with distinct sequence numbers: the identity rule itself.
        record["edits"][1] = {**record["edits"][1], "seq": record["edits"][0]["seq"] + 1}
        durable.write_sealed(self.path(), record)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            workcopy.load_store(self.settings, target)

    def test_target_paths_and_nonstruct_missing_address_are_refused(self):
        for key in ("../other", "a/b", "a\\b", "", "."):
            with self.subTest(key=key), self.assertRaises(ValueError):
                workcopy._store_path(self.settings, {**self.target, "key": key})
        with self.assertRaisesRegex(ValueError, "requires a Ghidra VA"):
            _edit({**self.edit, "address": ""})

    def test_ordered_function_corrections_survive_replay_history(self):
        delete = {"id": "1" * 32, "address": "0x401000",
                  "options": {"kind": "function_delete", "source": "fixture audit:1", "expect": "55 8B EC"}}
        create = {"id": "2" * 32, "address": "0x401000",
                  "options": {"kind": "function_create", "source": "fixture audit:2", "expect": "55 8B EC",
                              "ranges": [{"start": "0x401000", "end": "0x40100f"}]}}
        target = self.save([delete, create])
        loaded = workcopy.load_store(self.settings, target)["edits"]
        self.assertEqual([edit["id"] for edit in loaded], [delete["id"], create["id"]])
        self.assertEqual([edit["seq"] for edit in loaded], [1, 2])

    def test_batch_file_is_snapshotted_with_digest_and_never_reread_for_replay(self):
        path = self.root / "edits.json"
        content = json.dumps([{"address": "0x401000", "options": {"kind": "rename", "name": "Known"}}]).encode()
        path.write_bytes(content)
        normalized = validate_options("type_edit", {"kind": "batch", "source": "audit.csv:3", "file": str(path)})
        self.assertNotIn("file", normalized)
        self.assertEqual(normalized["input_file_sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(normalized["input_file_bytes"], len(content))
        path.write_text("now invalid JSON: replay must not read it")
        record = {"id": "3" * 32, "address": "", "options": normalized}
        target = self.save([record], key="batch1")
        saved = workcopy.load_store(self.settings, target)["edits"]
        self.assertEqual(self.plain(saved), [record])
        self.assertEqual(saved[0]["options"]["edits"][0]["options"]["name"], "Known")

    def test_batch_input_caps_cover_files_and_inline_arrays(self):
        path = self.root / "too-large.json"
        path.write_bytes(b" " * (256 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "256 KiB"):
            validate_options("type_edit", {"kind": "batch", "source": "audit:1", "file": str(path)})
        large = [{"address": "0x401000", "options": {"kind": "comment", "comment": "x" * 8192}}] * 50
        with self.assertRaisesRegex(ValueError, "256 KiB"):
            validate_options("type_edit", {"kind": "batch", "source": "audit:1", "edits": large})

    def test_history_supports_4096_records_and_refuses_the_4097th_on_load_and_on_edit(self):
        def record(number):
            return {"id": "%032x" % number, "address": "0x401000",
                    "options": {"kind": "comment", "comment": "observed", "source": "audit:1"}}
        full = self.save([record(number) for number in range(4096)], key="scale")
        self.assertEqual(len(workcopy.load_store(self.settings, full)["edits"]), 4096)
        before = self.path("scale").read_bytes()
        engine = fakehydra.FakeEngine(self.settings)
        with self.assertRaisesRegex(ValueError, "history limit"):
            workcopy.edit(self.settings, engine, full, "0x401020",
                          {"kind": "comment", "comment": "other", "source": "audit:2", "expect_revision": 4096}, 5)
        self.assertEqual(self.path("scale").read_bytes(), before)
        # A history written with 4097 records is refused when it is read.
        over = self.save([record(number) for number in range(4097)], key="over")
        with self.assertRaisesRegex(ValueError, "at most 4096"):
            workcopy.load_store(self.settings, over)

    def test_the_byte_cap_preserves_the_existing_history_and_leaves_no_temporary_file(self):
        target = self.save([self.edit], key="small")
        small = self.path("small")
        before = small.read_bytes()
        new = {"id": "4" * 32, "address": "0x401020",
               "options": {"kind": "comment", "comment": "other", "source": "audit:2"}}
        with patch("hydralysis.workcopy.MAX_HISTORY_BYTES", len(before) + 32):
            with self.assertRaisesRegex(ValueError, "20 MiB"):
                workcopy._save_store(self.settings, target, self.store([self.edit, new]))
        self.assertEqual(small.read_bytes(), before)
        self.assertEqual([item.name for item in small.parent.iterdir() if item.suffix == ".tmp" or ".tmp" in item.name], [])


if __name__ == "__main__":
    unittest.main()
