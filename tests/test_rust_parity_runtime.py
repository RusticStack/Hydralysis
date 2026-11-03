"""Differential test of the runtime_decode and runtime_snapshot ports: the Python functions (the specification) against
hy-runtime `decode` and `snapshot`.

Seeded random capture specs (valid, near-valid and mutated), random buffers (short, long, odd, with NULs, with invalid
UTF-8 and lone surrogates) and a table of edge cases. The comparison is the JSON text with insertion order kept (so key
order, int-versus-float and float digits all count), or the exception type and message. A case the port does not model must
raise `Unmodelled` (the Python then answers); it must never answer differently, or answer where the Python raises. The
shapes the producers emit must not fall back: that is asserted separately, so a port that always declined would fail.
Skipped when hydralysis_rt lacks the functions.
"""

from __future__ import annotations

import copy
import json
import random
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from hydralysis import runtime_decode as py  # noqa: E402
from hydralysis import runtime_snapshot as snap  # noqa: E402

try:
    from hydralysis import rust_frida
    RT = rust_frida._load_rt()
    HAVE = hasattr(RT, "decode_event") and hasattr(RT, "snapshot_compare")
except Exception:  # noqa: BLE001
    RT, HAVE = None, False

TYPES = ["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "pointer", "bool", "int", "uint", "float",
         "double", "dword", "qword", "Thing *", " u32 ", "char", "undefined4", "short", "ulong"]
KINDS = TYPES + ["utf8", "utf16", "hex", "struct"]


def outcome(function, *args):
    """(kind, text): `ok` with the JSON text, or the exception name and message."""
    args = copy.deepcopy(args)
    try:
        return ("ok", json.dumps(function(*args)))
    except RT.Unmodelled:
        return ("unmodelled", "")
    except Exception as error:  # noqa: BLE001 - the type and text are the comparison
        return (type(error).__name__, str(error))


def python_outcome(function, *args):
    args = copy.deepcopy(args)
    try:
        return ("ok", json.dumps(function(*args)))
    except Exception as error:  # noqa: BLE001
        return (type(error).__name__, str(error))


def random_capture(rng):
    item = {}
    if rng.random() < 0.2:
        item["reg"] = rng.choice(["ecx", "rdx", "xmm2", "r8", "rax"])
    else:
        item["arg"] = rng.randint(0, 7)
    if rng.random() < 0.5:
        item["deref"] = [rng.randint(0, 0x2000) for _ in range(rng.randint(0, 4))]
    kind = rng.choice(KINDS)
    item["as"] = kind
    if kind == "struct":
        item["fields"] = [{"name": rng.choice("abcdef") + str(i), "offset": rng.choice([0, 4, 8, 12, 16]),
                           "type": rng.choice(TYPES)} for i in range(rng.randint(1, 4))]
    if rng.random() < 0.4:
        item["size"] = rng.choice([1, 2, 4, 8, 16, 32, 256, 4096, 5000, 0])
    if rng.random() < 0.3:
        item["names"] = {rng.choice(["0x1", "2", "-3", "0b11", "0o7", "0X2A"]): rng.choice(["one", "two", "three", ""])
                         for _ in range(rng.randint(0, 3))}
    if rng.random() < 0.3:
        item["label"] = "label-" + "x" * rng.randint(0, 80)
    return item


def random_buffer(rng):
    shape = rng.random()
    if shape < 0.25:
        return bytes(rng.randrange(256) for _ in range(rng.randint(0, 9)))
    if shape < 0.5:
        return bytes(rng.randrange(256) for _ in range(rng.choice([4, 8, 16, 24, 32])))
    if shape < 0.7:
        return rng.choice(["héllo", "日本語", "a\u0000b", "", "\ud800x"]).encode("utf-16-le", "surrogatepass") + b"\0\0" * rng.randint(0, 2)
    if shape < 0.85:
        return rng.choice(["héllo", "日本語", "x"]).encode() + b"\0" * rng.randint(0, 3) + bytes(rng.randrange(256) for _ in range(rng.randint(0, 6)))
    return struct.pack("<fIQd", rng.uniform(-1e6, 1e6), rng.randrange(1 << 32), rng.randrange(1 << 64), rng.uniform(-1e9, 1e9))


def captured_for(rng, specs):
    rows = []
    for _ in specs:
        roll = rng.random()
        if roll < 0.08:
            rows.append({"error": "unreadable pointer at 0x10"})
        elif roll < 0.12:
            rows.append(None)
        elif roll < 0.15:
            rows.append({"pointer": "0x1", "hex": "zz"})
        else:
            rows.append({"pointer": hex(rng.randrange(1 << 48)), "hex": random_buffer(rng).hex()})
    return rows


@unittest.skipUnless(HAVE, "hydralysis_rt lacks the runtime_decode functions (cargo build --release in rust/)")
class DecodeParity(unittest.TestCase):
    def same(self, rust, python, *args):
        want = python_outcome(python, *args)
        got = outcome(rust, *args)
        if got[0] == "unmodelled":
            return got
        self.assertEqual(got, want, "input %r" % (args,))
        return got

    def test_normalize_on_random_and_mutated_specs(self):
        rng = random.Random(7)
        modelled = refused = 0
        for _ in range(3000):
            captures = [random_capture(rng) for _ in range(rng.randint(0, 5))]
            if rng.random() < 0.3 and captures:
                item = rng.choice(captures)
                key = rng.choice(["arg", "deref", "size", "as", "names", "label", "reg", "fields", "extra"])
                item[key] = rng.choice([None, True, 1.5, "7", -1, 2 ** 70, [], {}, "0x10", [1, "a"], {"1": 2}, 3])
            got = self.same(RT.decode_normalize, py._normalize_py, captures)
            modelled += got[0] == "ok"
            refused += got[0] == "ValueError"
        self.assertGreater(modelled, 600, "the producers' shapes must be answered by Rust")
        self.assertGreater(refused, 300, "and the refusals must be reached")

    def test_normalize_edge_cases(self):
        for captures in (None, [], {}, "x", 3, [1], [{}], [{"arg": 0, "as": "int", "size": 3}], [{"arg": True}], [{"arg": 0, "deref": [1 << 20]}],
                         [{"arg": 0, "deref": [-1]}], [{"arg": 0, "as": "struct", "fields": [{"name": "a", "offset": 4, "type": "u8"}]}],
                         [{"arg": 0, "as": "struct", "fields": [{"name": "a", "offset": -4, "type": "u32"}], "size": 8}],
                         [{"arg": 0, "as": "struct", "fields": []}], [{"arg": 0, "as": "struct", "fields": [{"name": 1, "type": "u8"}]}],
                         [{"arg": 0, "as": "struct", "fields": [{"name": "a", "type": "nope"}]}], [{"reg": "AX"}], [{"reg": "a"}],
                         [{"reg": "abcdef"}], [{"reg": "r15", "as": "pointer"}], [{"arg": 0, "names": {"1": "x", "0x1": "y"}}],
                         [{"arg": 0, "names": {"zz": "x"}}], [{"arg": 0, "names": []}], [{"arg": 0, "names": {"1": 5, "2": None, "3": True}}],
                         [{"arg": 0, "label": 5}], [{"arg": 0, "label": "é" * 70}], [{"arg": 0, "as": " u8"}], [{"arg": 0, "as": "U8"}],
                         [{"arg": 0, "as": "u64*"}], [{"arg": 0, "as": "bool"}], [{"arg": 0, "as": "utf8", "size": 4096}],
                         [{"arg": 0, "as": "utf8", "size": 0}], [{"arg": 0, "unknown": 1}]):
            with self.subTest(captures=captures):
                self.same(RT.decode_normalize, py._normalize_py, captures)

    def test_decode_event_on_random_buffers(self):
        rng = random.Random(11)
        answered = 0
        for _ in range(4000):
            while True:
                try:
                    specs = py._normalize_py([random_capture(rng) for _ in range(rng.randint(1, 4))])
                    break
                except ValueError:
                    continue
            captured = captured_for(rng, specs)
            got = self.same(RT.decode_event, py._decode_event_py, specs, captured)
            answered += got[0] == "ok"
        self.assertGreater(answered, 3000, "random valid specs and buffers are answered by Rust")

    def test_decode_on_every_decoder_and_buffer_length(self):
        rng = random.Random(3)
        for kind in KINDS:
            spec = {"arg": 0, "as": kind}
            if kind == "struct":
                spec["fields"] = [{"name": "a", "offset": 0, "type": "u32"}, {"name": "b", "offset": 4, "type": "f64"},
                                  {"name": "a", "offset": 12, "type": "i8"}]
            for names in (None, {"1": "one", "-1": "minus", "0": "zero"}):
                if names:
                    spec["names"] = names
                [clean] = py._normalize_py([spec])
                for length in range(0, 20):
                    data = bytes(rng.randrange(256) for _ in range(length))
                    got = self.same(RT.decode_value, py._decode_py, clean, data)
                    if length >= 16 and kind != "f32":
                        self.assertNotEqual(got[0], "unmodelled", (kind, length))

    def test_decode_text_decoders_agree_on_invalid_sequences(self):
        [text8], [text16] = py._normalize_py([{"arg": 0, "as": "utf8"}]), py._normalize_py([{"arg": 0, "as": "utf16"}])
        for data in (b"", b"\0", b"abc\0def", b"\xff\xfe", b"\xed\xa0\x80", b"\xf0\x9f", b"\xe3\x81", b"\xc0\xaf", b"ok\xf0\x9f\x98",
                     b"\xf4\x90\x80\x80", "é日\U0001F600".encode()):
            with self.subTest(data=data):
                self.assertEqual(self.same(RT.decode_value, py._decode_py, text8, data)[0], "ok")
        for data in (b"", b"\0\0", b"a\0b\0", b"a\0\0", b"\x00\xd8", b"\x00\xd8a\0", b"\x00\xdc\x00\xd8", "😀x".encode("utf-16-le"),
                     b"a\0\0\0b\0", b"a"):
            with self.subTest(data=data):
                self.assertEqual(self.same(RT.decode_value, py._decode_py, text16, data)[0], "ok")

    def test_nonfinite_floats_and_negative_offsets_fall_back(self):
        [f32] = py._normalize_py([{"arg": 0, "as": "f32"}])
        self.assertEqual(outcome(RT.decode_value, f32, struct.pack("<f", float("inf")))[0], "unmodelled")
        [nan] = py._normalize_py([{"arg": 0, "as": "f64"}])
        self.assertEqual(outcome(RT.decode_value, nan, struct.pack("<d", float("nan")))[0], "unmodelled")
        negative = {"arg": 0, "as": "struct", "fields": [{"name": "a", "offset": -4, "type": "u32"}], "names": {}, "label": ""}
        self.assertEqual(outcome(RT.decode_value, negative, b"\1\2\3\4\5\6\7\x08")[0], "unmodelled")

    def test_decode_event_edge_cases(self):
        [u32] = py._normalize_py([{"arg": 0, "as": "u32", "label": "n"}])
        for captures in (None, [], [None], [{}], [{"hex": "01000000"}], [{"hex": ""}], [{"hex": "0100000"}], [{"hex": " 01 00 00 00 "}],
                         [{"hex": "01 00 0 0 00"}], [{"hex": "ZZ"}], [{"hex": 5}], [{"hex": None}], [{"error": ""}], [{"error": "", "hex": "01000000"}],
                         [{"error": 0, "pointer": "p", "hex": "01000000"}], [{"error": ["x"]}], [0], [""], [[]], [[1]], [5], [True],
                         [{"pointer": 1, "hex": "01000000"}], {}, {"a": 1}, "ab", [{"hex": "ÿ"}], [{"hex": "0١"}], [{"hex": "FFFFFFFF"}]):
            with self.subTest(captures=captures):
                self.same(RT.decode_event, py._decode_event_py, [u32], captures)

    def test_layout_values(self):
        rng = random.Random(5)
        names = {"0": "zero", "1": "one", "-3": "minus three"}
        for _ in range(1500):
            fields = []
            for i in range(rng.randint(0, 5)):
                field = {"name": "f%d" % i, "offset": rng.choice([0, 1, 4, 8, 12, 30, 100]), "type": rng.choice(TYPES + ["Blob", "", "SomeStruct"])}
                if rng.random() < 0.3:
                    field["size"] = rng.choice([0, 1, 3, 4, 16, 100])
                if rng.random() < 0.3:
                    field["names"] = names
                if rng.random() < 0.2:
                    field["enum"] = "EKind"
                fields.append(field)
            data = random_buffer(rng) + bytes(rng.randrange(256) for _ in range(rng.choice([0, 8, 32])))
            self.same(RT.decode_layout_values, py._layout_values_py, fields, data)
        for fields in ([{"offset": 0}], [{"name": "x"}], [{"name": "x", "offset": "4", "type": "u8"}], [{"name": "x", "offset": 1.5, "type": "u8"}],
                       [{"name": "x", "offset": -1, "type": "u8"}], [{"name": "x", "offset": 0, "type": None}], [{"name": "x", "offset": 0, "type": 5}],
                       [{"name": "x", "offset": 0, "type": "f32", "names": {"1": "x"}}], [{"name": "x", "offset": 0, "type": "bool", "names": {}}],
                       [{"name": "x", "offset": 0, "type": "u8", "size": -2}], [1], "x", None, [{"name": "x", "offset": 0, "type": "u8", "size": "2"}]):
            with self.subTest(fields=fields):
                self.same(RT.decode_layout_values, py._layout_values_py, fields, bytes(range(40)))

    def test_the_module_routes_to_rust_only_when_both_variables_are_set_and_not_for_a_patched_seam(self):
        import os
        import subprocess
        code = ("import os, sys; sys.path.insert(0, %r)\n"
                "from unittest import mock\n"
                "from hydralysis import runtime_decode as d\n"
                "print(hasattr(d.normalize, 'rust_function'))\n"
                "if hasattr(d.normalize, 'rust_function'):\n"
                "    calls = []\n"
                "    real = d._unpack\n"
                "    with mock.patch.object(d, '_unpack', lambda *a: calls.append(a) or real(*a)):\n"
                "        d.decode({'as': 'u32', 'names': {}}, b'\\1\\0\\0\\0')\n"
                "    print(len(calls))\n") % str(HERE.parent / "src")
        for impl, held, expected in (("rust", "1", ["True", "1"]), ("rust", "", ["False"]), ("", "1", ["False"])):
            env = {**os.environ, "HYDRALYSIS_IMPL": impl, "HYDRALYSIS_RUNTIME_HELD": held, "PYTHONPATH": str(HERE.parent / "src")}
            done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120)
            self.assertEqual(done.stdout.split(), expected, done.stderr)


def snapshot_record(rng, scale=1):
    text = lambda: rng.choice(["a", "Game.EXE", "kernel32.dll", "é日", "x/y", "q" * 120, "line\nbreak", "", "a#2", "A\u0000b"])  # noqa: E731
    scalar = lambda: rng.choice([0, 1, -7, 2 ** 40, 2 ** 63 + 5, 1.0, 0.5, 1e-7, 1e22, -0.0, True, False, None, text(), text()])  # noqa: E731
    record = {"snapshot": "snap_" + "0" * 64, "session": "s", "taken_at_ms": rng.randrange(10 ** 9), "sequence": rng.randrange(100),
              "log_head": text(), "counters": {"messages": rng.randrange(50), "dropped": 0},
              "target": {"pid": rng.randrange(10 ** 5), "created_ms": rng.randrange(10 ** 9), "exe": text()},
              "threads": {"count": rng.randrange(1, 9)}}
    record["modules"] = [{"name": rng.choice(["Game.EXE", "kernel32.dll", "KERNEL32.DLL", "ntdll.dll", "x/y"]),
                          "base": hex(rng.randrange(1 << 40)), "size": rng.randrange(1 << 20), "path": text(),
                          "sha256": rng.choice(["ab", None, "cd"])} for _ in range(rng.randint(0, 6 * scale))]
    record["hooks"] = [{"module": rng.choice(["a.exe", None, "b"]), **({"rva": rng.choice(["0x10", 16, 0, None])} if rng.random() < 0.7 else {}),
                        **({"export": rng.choice(["Foo", "", None])} if rng.random() < 0.3 else {}), "kind": rng.choice(["observe", "break"]),
                        "hook_id": text(), "address": hex(rng.randrange(1 << 40)), "limit": scalar()} for _ in range(rng.randint(0, 5 * scale))]
    record["regions"] = {rng.choice(["config", "player", "a/b", "é"]) + str(i): {
        "address": hex(rng.randrange(1 << 40)), "range": {"base": hex(rng.randrange(1 << 40)), "size": 64},
        "bytes": "".join(rng.choice("0123456789ABCDEF ") for _ in range(rng.choice([8, 90, 300]))),
        "fields": [{"name": rng.choice(["x", "y", "x", "limit"]), "value": scalar(), "type": "u32"} for _ in range(rng.randint(0, 4))]}
        for i in range(rng.randint(0, 5 * scale))}
    record["other"] = [scalar() for _ in range(rng.randint(0, 4))] + [{"k": scalar()} for _ in range(rng.randint(0, 3))] + [[scalar()], {}]
    return record


def mutate(rng, record):
    other = copy.deepcopy(record)
    for _ in range(rng.randint(0, 6)):
        regions = other.get("regions")
        target = rng.choice([other, other.get("counters"), other.get("target"), regions.get("config0") if isinstance(regions, dict) else None, other])
        if isinstance(target, dict):
            action = rng.random()
            key = rng.choice(list(target) or ["z"])
            if action < 0.4:
                target[key] = rng.choice([1, 1.0, True, "1", None, 2 ** 40, 0.5, "x" * 200, [1, 2], {"n": 1}])
            elif action < 0.6:
                target.pop(key, None)
            else:
                target["new" + str(rng.randrange(5))] = rng.choice([7, "v", 7.0])
    return other


@unittest.skipUnless(HAVE, "hydralysis_rt lacks the runtime_snapshot functions (cargo build --release in rust/)")
class SnapshotParity(unittest.TestCase):
    def same(self, rust, python, *args, **kwargs):
        def run(function):
            call_args = copy.deepcopy(args)
            try:
                return ("ok", json.dumps(function(*call_args, **kwargs)))
            except RT.Unmodelled:
                return ("unmodelled", "")
            except Exception as error:  # noqa: BLE001
                return (type(error).__name__, str(error))
        want, got = run(python), run(rust)
        if got[0] != "unmodelled":
            self.assertEqual(got, want, "input %r %r" % (args, kwargs))
        return got

    def rust_compare(self, a, b, mask=(), predicates=(), use_default_mask=True, limit=200):
        mask = snap.check_mask(list(mask) if isinstance(mask, tuple) else mask)
        predicates = snap.check_predicates(list(predicates) if isinstance(predicates, tuple) else predicates)
        if type(limit) is not int or limit < 0:
            raise RT.Unmodelled("limit")
        patterns = (snap.DEFAULT_VOLATILE if use_default_mask else ()) + tuple(mask)
        return RT.snapshot_compare(a, b, list(patterns), list(snap.DEFAULT_VOLATILE + tuple(mask)), predicates, limit)

    def test_stable_hash_on_random_snapshots(self):
        rng = random.Random(21)
        modelled = 0
        for _ in range(500):
            record = snapshot_record(rng)
            mask = rng.choice([(), ("regions/*/bytes",), ("other/*", "modules/?/size"), ("*",)])
            modelled += self.same(lambda r, m: RT.snapshot_stable_sha256(r, list(snap.DEFAULT_VOLATILE + tuple(m))), snap._stable_sha256_py,
                                  record, mask)[0] == "ok"
        self.assertGreater(modelled, 350, "most snapshots are answered by Rust")

    def test_compare_on_random_pairs_masks_and_predicates(self):
        rng = random.Random(23)
        predicates = [[], [{"path": "counters/messages", "op": "increased"}], [{"path": "regions/config0/range/size", "op": "eq", "value": 64}],
                      [{"path": "target/exe", "op": "changed"}, {"path": "nope", "op": "absent"}, {"path": "nope", "op": "present"}],
                      [{"path": "regions/config0/fields/x/value", "op": "between", "value": [0, 1.5]},
                       {"path": "modules/game.exe/size", "op": "lt", "value": 5.5}, {"path": "other/0", "op": "ge", "value": 0}],
                      [{"path": "other/0", "op": "ne", "value": True}, {"path": "other/1", "op": "unchanged"},
                       {"path": "counters/dropped", "op": "decreased"}, {"path": "snapshot", "op": "eq", "value": None}]]
        answered = differing = 0
        for _ in range(600):
            a = snapshot_record(rng)
            b = mutate(rng, a) if rng.random() < 0.8 else snapshot_record(rng)
            mask = rng.choice([(), ["regions/*/bytes"], ("other/*", "modules/?/size")])
            kwargs = {"mask": mask, "predicates": rng.choice(predicates), "use_default_mask": rng.random() < 0.8,
                      "limit": rng.choice([200, 3, 0, 1000])}
            got = self.same(self.rust_compare, snap._compare_py, a, b, **kwargs)
            answered += got[0] == "ok"
            differing += got[0] == "ok" and '"difference_count": 0' not in got[1]
        self.assertGreater(answered, 400)
        self.assertGreater(differing, 200, "the pairs must differ for the comparison to be tested")

    def test_compare_edge_cases(self):
        a = {"counters": {"n": 1}, "x": "long" * 40, "y": 1}
        b = {"counters": {"n": 2}, "x": "long" * 41, "y": True, "z": 0}
        for kwargs in ({}, {"mask": ["x"]}, {"mask": "x"}, {"mask": ["bad[ch"]}, {"mask": ["x" * 201]}, {"predicates": [{"path": "y", "op": "nope"}]},
                       {"predicates": [{"path": "y", "op": "eq", "value": 1}, {"path": "q", "op": "unchanged"}, {"path": "x", "op": "increased"},
                                       {"path": "x", "op": "gt", "value": 1}]},
                       {"limit": -1}, {"limit": True}, {"limit": 2.0}, {"use_default_mask": 0}, {"predicates": ({"path": "y", "op": "present"},)}):
            with self.subTest(kwargs=kwargs):
                self.same(self.rust_compare, snap._compare_py, a, b, **kwargs)
        for bad in (None, [], "x", 3):
            with self.subTest(bad=bad):
                self.same(self.rust_compare, snap._compare_py, bad, b)
                self.same(self.rust_compare, snap._compare_py, a, bad)

    def test_unmodelled_snapshots_fall_back(self):
        deep = cur = {}
        for _ in range(300):
            cur["k"] = {}
            cur = cur["k"]
        for record in ({"a": 2 ** 70}, {"a": float("nan")}, {"a": float("inf")}, {"a": "\ud800"}, {"a": (1, 2)}, {1: 2}, deep,
                       {"hooks": [{"module": "m", "rva": 1.5, "kind": "k"}]}, {"modules": [{"name": 1.5}]}):
            with self.subTest(record=repr(record)[:60]):
                self.same(lambda r: RT.snapshot_stable_sha256(r, []), lambda r: snap._stable_sha256_py(r, ()), record)
        for record in ({"a": 2 ** 70}, {"a": float("nan")}, deep, {"a": (1, 2)}, {"a": "\ud800"}):
            self.assertEqual(outcome(RT.snapshot_stable_sha256, record, [])[0], "unmodelled", repr(record)[:40])
        self.assertEqual(outcome(RT.snapshot_stable_sha256, {"a": 1}, ["a[bc]"])[0], "unmodelled")

    def test_the_module_routes_snapshot_functions_only_under_the_variable(self):
        import os
        import subprocess
        code = ("import sys; sys.path.insert(0, %r)\n"
                "from hydralysis import runtime_snapshot as s\n"
                "print(hasattr(s.compare, 'rust_function'), s.compare({'a': 1}, {'a': 2})['difference_count'])\n") % str(HERE.parent / "src")
        for impl, expected in (("rust", ["True", "1"]), ("", ["False", "1"])):
            env = {**os.environ, "HYDRALYSIS_IMPL": impl, "PYTHONPATH": str(HERE.parent / "src")}
            done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120)
            self.assertEqual(done.stdout.split(), expected, done.stderr)


if __name__ == "__main__":
    unittest.main()
