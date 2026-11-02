"""Differential test of the pure-logic ports: decompile_result.py and analysis.validate_options (Python vs hy-query).

Hand-written cases for the documented behaviours plus seeded random mutation of them. The comparison is the parsed
value, or the exception type and message. Skipped when hydralysis_native lacks the functions.
"""

import copy
import os
import random
import unittest
from unittest.mock import patch

from hydralysis import analysis, decompile_result as dr

try:
    import hydralysis_native
    HAVE_NATIVE = hasattr(hydralysis_native, "validate_options_rs")
except ImportError:
    HAVE_NATIVE = False


def outcome(function, *args, impl):
    with patch.dict(os.environ, {"HYDRALYSIS_IMPL": impl}):
        try:
            return ("ok", function(*copy.deepcopy(args)))
        except Exception as error:  # noqa: BLE001
            return (type(error).__name__, str(error))


REPLIES = [
    {}, {"ok": True, "c": "x"}, {"truncated": False}, {"truncated": True},
    {"truncated": True, "bytes_emitted": 1048576, "reason": "max_result_mb",
     "fragments": [{"start": "0x140001000", "end": "0x140001040", "class": "code"},
                   {"start": "0x140001040", "end": "0x140001060", "class": "data", "decompiled": False},
                   {"start": 5, "end": 3, "class": "code"}, {"start": "zz", "end": 1, "class": "code"},
                   {"start": 1, "end": 2, "class": "weird"}, "nope", {"start": True, "end": 2, "class": "code"},
                   {"start": "0b11", "end": "0o10", "class": "unknown"}, {"start": "1_0", "end": " 20 ", "class": "code"}]},
    {"partial": True, "fragments": "not a list"}, {"fragments": None}, {"fragments": []},
    {"next_offset": 100, "offset": 0, "c": "abc"}, {"next_offset": -1}, {"next_offset": True},
    {"cut": {"kind": "k", "c_chars": 3, "other": 1}, "budget": {"mode": "auto", "mb": 4, "x": 1}, "truncated": True},
    {"budget": {"mode": "fixed"}, "truncated": True, "reason": "r" * 300},
    {"fragments": [{"start": 0, "end": 10, "class": "data"}], "partial": True},
    {"fragments": [{"start": 0, "end": 10, "class": "unknown"}] * 5000},
    {"bytes_emitted": 5.0}, {"bytes_emitted": -3}, {"reason": ""},
]
RESPONSES = [
    {"ok": True, "c": "a" * 5, "truncated": True, "id": "i", "function": {"name": "f"}},
    {"ok": False, "id": "i", "program": "p", "error": "boom", "engine": {"v": 1}},
    {"ok": True, "c": "short", "truncated": False}, {"id": 1},
]
ENGINE_REPLIES = [
    {"completed": True, "c": "int main(){}", "entry": "0x1", "name": "main", "signature": "int main()", "chars": 12},
    {"completed": True, "c": "page", "offset": 4, "chars": 99, "next_offset": 8, "truncated": True},
    {"completed": False, "truncated": True, "c": "part", "error": "stop", "bytes_emitted": 9, "fragments": []},
    {"completed": False, "truncated": True}, {"completed": True, "c": 5}, {"completed": False},
    {"completed": True, "c": "é€𐍈"},
]


def mutations(rng, value):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            roll = rng.random()
            if roll < 0.08:
                continue
            out[key] = mutations(rng, item) if roll > 0.2 else rng.choice([None, True, False, 0, -1, 7, "x", "0x10", [], {}, 2.5, "", "auto"])
        if rng.random() < 0.15:
            out[rng.choice(["truncated", "partial", "reason", "fragments", "next_offset", "offset", "completed", "ok", "c", "chars"])] = rng.choice(
                [True, False, 3, "s", None, [], {}])
        return out
    if isinstance(value, list):
        return [mutations(rng, item) for item in value[:20]]
    return value


class DecompileResultParity(unittest.TestCase):
    @unittest.skipUnless(HAVE_NATIVE, "native module not built")
    def test_summaries_limitations_coverage_fragments_from_error(self):
        rng = random.Random(7)
        pool = list(REPLIES) + [mutations(rng, rng.choice(REPLIES)) for _ in range(400)]
        for reply in pool:
            for function in (dr.summarize, dr.limitations, dr.coverage):
                self.assertEqual(outcome(function, reply, impl="python"), outcome(function, reply, impl="rust"), (function.__name__, reply))
            self.assertEqual(outcome(dr.fragments, reply.get("fragments"), impl="python"),
                             outcome(dr.fragments, reply.get("fragments"), impl="rust"), reply)
            import json
            self.assertEqual(outcome(dr.from_error, json.dumps(reply), impl="python"), outcome(dr.from_error, json.dumps(reply), impl="rust"))
        self.assertEqual(outcome(dr.from_error, "not json", impl="python"), outcome(dr.from_error, "not json", impl="rust"))

    @unittest.skipUnless(HAVE_NATIVE, "native module not built")
    def test_merge_and_annotate(self):
        rng = random.Random(11)
        replies = list(ENGINE_REPLIES) + [mutations(rng, rng.choice(ENGINE_REPLIES)) for _ in range(300)]
        responses = list(RESPONSES) + [mutations(rng, rng.choice(RESPONSES)) for _ in range(30)]
        for response in responses:
            for reply in replies:
                self.assertEqual(outcome(dr.merge, response, reply, impl="python"), outcome(dr.merge, response, reply, impl="rust"), (response, reply))
        for reply in REPLIES:
            self.assertEqual(outcome(dr.annotate, reply, impl="python"), outcome(dr.annotate, reply, impl="rust"), reply)


OPTION_CASES = [
    ("decompile", None), ("decompile", {}), ("decompile", {"max_characters": 5, "max_result_mb": 1024, "max_result_kb": 9, "offset": 3}),
    ("decompile", {"max_characters": 0}), ("decompile", {"max_characters": True}), ("decompile", {"max_result_mb": 1025}),
    ("decompile", {"offset": -1}), ("decompile", {"bogus": 1, "alpha": 2}), ("function", {"x": 1}), ("function", None),
    ("data", {"table": True}), ("data", {"table": 1}), ("orphans", {"referenced_only": "yes"}),
    ("scan", {"end": "0x10", "mnemonic": "call", "operand": "rax"}), ("scan", {"end": "xyz"}), ("scan", {"end": " "}),
    ("scan", {"regex": "call.*"}), ("scan", {"regex": "("}), ("scan", {"mnemonic": 5}),
    ("vcalls", {"offset": "0xc0"}), ("vcalls", {"offset": "12"}), ("vcalls", {"offset": "1234567"}), ("vcalls", {"offset": "12345678"}),
    ("vcalls", {"offset": "0x1234567"}), ("vcalls", {}), ("vcalls", {"offset": "0x10", "receiver_from": "rva:0x10", "vtable": "va:zz"}),
    ("vcalls", {"offset": "0x10", "receiver_global": 5, "receiver_type": "T"}), ("vcalls", {"offset": "0x10", "receiver_global": True}),
    ("writes", {"offset": "8", "receiver_type": " "}), ("type", {"path": "/a/b"}), ("type", {"path": ""}),
    ("pcode", {"nodes": 5}), ("pcode", {"nodes": 201}), ("trace", {}), ("trace", {"seed": "x", "direction": "forward", "depth": 3, "argument": 2, "brief": True}),
    ("trace", {"direction": "sideways"}), ("trace", {"brief": 1}), ("trace", {"argument": 16}), ("trace", {"callers": 5}),
    ("status", {"show": "changes", "since": 5, "state": "all"}), ("status", {"since": 5}), ("status", {"show": "x"}),
    ("status", {"show": "changes", "state": "nope"}), ("status", {"show": "changes", "since": -1}),
    ("diff", {"against": "other"}), ("diff", {}), ("types", {"a": 1}), ("types", None),
    ("type_edit", {}), ("type_edit", {"kind": "nope", "source": "s"}),
    ("type_edit", {"kind": "revert", "ids": ["a" * 32]}), ("type_edit", {"kind": "revert", "ids": ["A" * 32]}),
    ("type_edit", {"kind": "revert", "ids": [], "cascade": True}), ("type_edit", {"kind": "revert", "ids": ["a" * 32], "name": "x"}),
    ("type_edit", {"kind": "rename", "source": "doc", "name": "n"}), ("type_edit", {"kind": "rename", "source": "doc"}),
    ("type_edit", {"kind": "rename", "source": " ", "name": "n"}), ("type_edit", {"kind": "rename", "source": "d", "name": "n", "type": "t"}),
    ("type_edit", {"kind": "signature", "source": "d", "prototype": "int f(void)"}), ("type_edit", {"kind": "comment", "source": "d", "comment": "c" * 8192}),
    ("type_edit", {"kind": "comment", "source": "d", "comment": "c" * 8193}), ("type_edit", {"kind": "variable", "source": "d", "variable": "v", "type": "int"}),
    ("type_edit", {"kind": "variable", "source": "d", "variable": "v", "type": "int", "name": "w", "expect_revision": 3}),
    ("type_edit", {"kind": "struct", "source": "d", "path": "/x/T", "size": 16, "fields": [
        {"offset": 0, "type": "int", "name": "a"}, {"offset": 4, "type": "int", "name": "b", "length": 12}]}),
    ("type_edit", {"kind": "struct", "source": "d", "path": "x/T", "size": 16}),
    ("type_edit", {"kind": "struct", "source": "d", "path": "/x/T", "size": 16, "fields": [
        {"offset": 0, "type": "int", "name": "a"}, {"offset": 4, "type": "int", "name": "a"}]}),
    ("type_edit", {"kind": "struct", "source": "d", "path": "/x/T", "size": 4, "fields": [{"offset": 4, "type": "int", "name": "a"}]}),
    ("type_edit", {"kind": "struct", "source": "d", "path": "/x/T", "size": 4, "fields": [{"offset": 0, "type": "int", "name": "a", "x": 1}]}),
    ("type_edit", {"kind": "struct", "source": "d", "path": "/x/T", "size": 4, "fields": [{"offset": 1, "type": "int", "name": "a", "length": 4}]}),
    ("type_edit", {"kind": "struct", "source": "d", "path": "/x/T"}),
    ("type_edit", {"kind": "function_delete", "source": "d", "expect": "55 8b ec"}), ("type_edit", {"kind": "function_delete", "source": "d", "expect": "55 ??"}),
    ("type_edit", {"kind": "function_create", "source": "d", "expect": "55", "ranges": [{"start": "0x10", "end": "0x20"}, {"start": "30", "end": "40"}], "name": "f"}),
    ("type_edit", {"kind": "function_create", "source": "d", "expect": "55", "ranges": [{"start": "0x10", "end": "0x20"}, {"start": "0x20", "end": "0x30"}]}),
    ("type_edit", {"kind": "function_body", "source": "d", "expect": "55", "ranges": [{"start": "0x20", "end": "0x10"}]}),
    ("type_edit", {"kind": "function_body", "source": "d", "expect": "55", "ranges": [{"start": "0x20"}]}),
    ("type_edit", {"kind": "function_body", "source": "d", "expect": "55", "ranges": []}),
    ("type_edit", {"kind": "function_body", "source": "d", "expect": "55", "ranges": [{"start": "0xZZ", "end": "0x1"}]}),
    ("type_edit", {"kind": "batch", "source": "d", "edits": [{"address": "0x10", "options": {"kind": "rename", "name": "n"}},
                                                            {"address": "", "options": {"kind": "struct", "path": "/a/B", "size": 4}}]}),
    ("type_edit", {"kind": "batch", "source": "d", "edits": [{"address": "", "options": {"kind": "rename", "name": "n"}}]}),
    ("type_edit", {"kind": "batch", "source": "d", "edits": [{"address": "0x1", "options": {"kind": "batch", "edits": []}}]}),
    ("type_edit", {"kind": "batch", "source": "d", "edits": []}), ("type_edit", {"kind": "batch", "source": "d"}),
    ("type_edit", {"kind": "batch", "source": "d", "edits": [{"options": {"kind": "rename", "name": "n"}}], "file": "x"}),
    ("type_edit", {"kind": "batch", "source": "d", "edits": [{"address": "0x1"}]}),
    ("type_edit", {"kind": "batch", "source": "d", "edits": [{"address": "0x1", "options": {"kind": "rename", "name": "n"}}], "input_file": "f"}),
    ("type_edit", {"kind": "batch", "source": "d", "edits": [{"address": "0x1", "options": {"kind": "rename", "name": "é" * 300000}}]}),
    ("type_edit", {"kind": "import_types", "source": "d", "corpus": "C:/nowhere.jsonl"}),
    ("type_edit", {"kind": "import_archive", "source": "d", "archive": "C:/nowhere.gdt"}),
]


class ValidateOptionsParity(unittest.TestCase):
    @unittest.skipUnless(HAVE_NATIVE, "native module not built")
    def test_cases(self):
        for action, options in OPTION_CASES:
            for record in (False, True):
                python = outcome(lambda a, o: analysis.validate_options(a, o, _record=record), action, options, impl="python")
                rust = outcome(lambda a, o: analysis.validate_options(a, o, _record=record), action, options, impl="rust")
                self.assertEqual(python, rust, (action, options, record))

    @unittest.skipUnless(HAVE_NATIVE, "native module not built")
    def test_random_mutations(self):
        rng = random.Random(3)
        for _ in range(1500):
            action, options = rng.choice(OPTION_CASES)
            if isinstance(options, dict):
                options = mutations(rng, options)
            python = outcome(analysis.validate_options, action, options, impl="python")
            rust = outcome(analysis.validate_options, action, options, impl="rust")
            self.assertEqual(python, rust, (action, options))


if __name__ == "__main__":
    unittest.main()
