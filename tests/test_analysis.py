import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from rusticre.analysis import load_overlays, save_overlay, validate_options

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
    def setUp(self):
        self.temp = workdir()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sha = "a" * 64
        self.edit = {"id": "b" * 32, "address": "0x401000",
                     "options": {"kind": "signature", "prototype": "int known(int x)", "source": "fixture.c:4"}}

    def test_successful_edit_survives_new_reader_and_is_idempotent(self):
        saved = save_overlay(self.root, "target1", self.sha, self.edit)
        self.assertEqual(saved, self.edit)
        self.assertEqual(load_overlays(self.root, "target1", self.sha), [self.edit])
        save_overlay(self.root, "target1", self.sha, self.edit)
        self.assertEqual(load_overlays(self.root, "target1", self.sha), [self.edit])
        self.assertFalse((self.root / "overlays" / "target1.tmp").exists())

    def test_changed_build_cannot_replay_or_overwrite_another_builds_types(self):
        save_overlay(self.root, "target1", self.sha, self.edit)
        path = self.root / "overlays" / "target1.json"
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "another build"):
            load_overlays(self.root, "target1", "c" * 64)
        with self.assertRaisesRegex(ValueError, "another build"):
            save_overlay(self.root, "target1", "c" * 64, self.edit)
        self.assertEqual(path.read_bytes(), before)

    def test_overlay_identity_cannot_silently_change_an_existing_assertion(self):
        save_overlay(self.root, "target1", self.sha, self.edit)
        self.edit["options"]["prototype"] = "void changed(void)"
        with self.assertRaisesRegex(ValueError, "different edit"):
            save_overlay(self.root, "target1", self.sha, self.edit)

    def test_read_missing_history_has_no_filesystem_side_effect(self):
        self.assertEqual(load_overlays(self.root, "new", self.sha), [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_corrupt_or_duplicate_history_is_refused_and_preserved(self):
        save_overlay(self.root, "target1", self.sha, self.edit)
        path = self.root / "overlays" / "target1.json"
        record = json.loads(path.read_text())
        record["edits"].append(record["edits"][0])
        path.write_text(json.dumps(record))
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            load_overlays(self.root, "target1", self.sha)
        self.assertEqual(path.read_bytes(), before)

    def test_target_paths_and_nonstruct_missing_address_are_refused(self):
        for key in ("../other", "a/b", "a\\b", "", "."):
            with self.subTest(key=key), self.assertRaises(ValueError):
                save_overlay(self.root, key, self.sha, self.edit)
        self.edit["address"] = ""
        with self.assertRaisesRegex(ValueError, "requires a Ghidra VA"):
            save_overlay(self.root, "target1", self.sha, self.edit)

    def test_ordered_function_corrections_survive_replay_history(self):
        delete = {"address": "0x401000", "options": {"kind": "function_delete", "source": "fixture audit:1", "expect": "55 8B EC"}}
        create = {"address": "0x401000", "options": {"kind": "function_create", "source": "fixture audit:2", "expect": "55 8B EC",
                  "ranges": [{"start": "0x401000", "end": "0x40100f"}]}}
        first = save_overlay(self.root, "target1", self.sha, delete)
        second = save_overlay(self.root, "target1", self.sha, create)
        self.assertEqual([edit["id"] for edit in load_overlays(self.root, "target1", self.sha)], [first["id"], second["id"]])

    def test_batch_file_is_snapshotted_with_digest_and_never_reread_for_replay(self):
        path = self.root / "edits.json"
        content = json.dumps([{"address": "0x401000", "options": {"kind": "rename", "name": "Known"}}]).encode()
        path.write_bytes(content)
        normalized = validate_options("type_edit", {"kind": "batch", "source": "audit.csv:3", "file": str(path)})
        self.assertNotIn("file", normalized)
        self.assertEqual(normalized["input_file_sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(normalized["input_file_bytes"], len(content))
        path.write_text("now invalid JSON: replay must not read it")
        saved = save_overlay(self.root, "batch1", self.sha, {"address": "", "options": normalized})
        self.assertEqual(load_overlays(self.root, "batch1", self.sha), [saved])
        self.assertEqual(saved["options"]["edits"][0]["options"]["name"], "Known")

    def test_batch_input_caps_cover_files_and_inline_arrays(self):
        path = self.root / "too-large.json"
        path.write_bytes(b" " * (256 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "256 KiB"):
            validate_options("type_edit", {"kind": "batch", "source": "audit:1", "file": str(path)})
        large = [{"address": "0x401000", "options": {"kind": "comment", "comment": "x" * 8192}}] * 50
        with self.assertRaisesRegex(ValueError, "256 KiB"):
            validate_options("type_edit", {"kind": "batch", "source": "audit:1", "edits": large})

    def test_history_supports_4096_records_and_preserves_data_at_count_or_byte_cap(self):
        path = self.root / "overlays" / "scale.json"
        path.parent.mkdir()
        edits = [{"id": "%032x" % i, "address": "0x401000", "options": {"kind": "comment", "comment": "observed", "source": "audit:1"}} for i in range(4096)]
        path.write_text(json.dumps({"version": 1, "sha256": self.sha, "edits": edits}))
        self.assertEqual(len(load_overlays(self.root, "scale", self.sha)), 4096)
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "history limit"):
            save_overlay(self.root, "scale", self.sha, self.edit)
        self.assertEqual(path.read_bytes(), before)

        save_overlay(self.root, "small", self.sha, self.edit)
        small = self.root / "overlays" / "small.json"
        before = small.read_bytes()
        new = {"address": "0x401020", "options": {"kind": "comment", "comment": "other", "source": "audit:2"}}
        with patch("rusticre.analysis.MAX_HISTORY_BYTES", len(before) + 32):
            with self.assertRaisesRegex(ValueError, "20 MiB"):
                save_overlay(self.root, "small", self.sha, new)
        self.assertEqual(small.read_bytes(), before)
        self.assertFalse(small.with_suffix(".tmp").exists())


if __name__ == "__main__":
    unittest.main()
