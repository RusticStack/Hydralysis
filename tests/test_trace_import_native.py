"""The Rust port of the trace tool's import and reply logic (crates/hy-trace: schema.rs, jsonl.rs, shape.rs, canon.rs; bound in
native/src/trace/importer.rs) against Python.

Generated and mutated events, JSONL files in every state `read_jsonl` tells apart, and generated engine replies go through both
implementations; the answers must be equal, down to dict key order (compared as JSON text without sorting).
"""

import contextlib
import json
import os
import random
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hydralysis import trace, trace_native, trace_schema


@contextlib.contextmanager
def impl(value):
    saved = os.environ.get("HYDRALYSIS_IMPL")
    os.environ["HYDRALYSIS_IMPL"] = value
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("HYDRALYSIS_IMPL", None)
        else:
            os.environ["HYDRALYSIS_IMPL"] = saved


def have_native():
    with impl("rust"):
        module = trace_native.native()
        return module is not None and hasattr(module, "trace_shape")


def both(function):
    with impl(""):
        python = function()
    with impl("rust"):
        native = function()
    return python, native


def text(value):
    return json.dumps(value, default=repr)       # no sort_keys: key order is part of the answer


KINDS = ["core.state.write", "core.function.enter", "app.tick", "my_app.thing", "core.unknown", "Core.x", "a", "a.b.c", "core.session.start\n", ""]


def event(rng, seq):
    value = {"kind": rng.choice(KINDS[:4]), "source_id": "src%d" % rng.randrange(3), "source_seq": seq, "producer_gen": rng.randrange(3),
             "clock_domain": "mono", "t_mono_ns": rng.randrange(10 ** 12), "confidence": rng.choice(["exact", "inferred", "sampled"])}
    if rng.random() < .5:
        value["payload"] = {"k": rng.choice(["v", "\u00e9\u20ac", "\U0001f600", 3, None, [1, 2], {"z": True}]), "a": rng.randrange(100)}
    if rng.random() < .3:
        value["callstack"] = [rng.randrange(2 ** 40) for _ in range(rng.randrange(4))]
    for key in ("t_wall_ns", "process_id", "thread_id", "va", "n"):
        if rng.random() < .2:
            value[key] = rng.randrange(2 ** 63)
    if rng.random() < .1:
        value["prev"] = "".join(rng.choice("0123456789abcdef") for _ in range(64))
    return value


def mutate(rng, value):
    value = json.loads(json.dumps(value))
    kind = rng.randrange(14)
    if kind == 0:
        value["kind"] = rng.choice(KINDS)
    elif kind == 1:
        value.pop(rng.choice(["kind", "source_id", "source_seq", "producer_gen", "clock_domain", "t_mono_ns", "confidence"]), None)
    elif kind == 2:
        value["source_seq"] = rng.choice([-1, 1.5, True, "1", None, 2 ** 64, 2 ** 70, 1.0])
    elif kind == 3:
        value["confidence"] = rng.choice(["guess", 1, None, True, ["exact"]])
    elif kind == 4:
        value["extra"] = 1
    elif kind == 5:
        value["payload"] = rng.choice([[], "x", 1, None, {"f": 1.5}])
    elif kind == 6:
        value["callstack"] = rng.choice([[-1], [1.5], "no", [True], [[]], [2 ** 64]])
    elif kind == 7:
        value["source_id"] = rng.choice(["", " ", 5, None])
    elif kind == 8:
        value["hash"] = rng.choice(["xyz", "a" * 64, "A" * 64, "a" * 64 + "\n", "a" * 65, 7])
    elif kind == 9:
        value["t_mono_ns"] = rng.choice([0, -0.0, 10 ** 30, 18446744073709551615, 18446744073709551616])
    elif kind == 10:
        value["module"] = rng.choice(["m", 3, None])
    return value


@unittest.skipUnless(have_native(), "hydralysis_native with the trace port is not built")
class RustMatchesPython(unittest.TestCase):
    def test_schema_acceptance_agrees_on_generated_and_mutated_events(self):
        rng = random.Random(11)
        accepted = refused = 0
        for seq in range(1500):
            candidate = event(rng, seq)
            for _ in range(rng.randrange(3)):
                candidate = mutate(rng, candidate)
            python, native = both(lambda: trace_schema.validate_event(candidate))
            self.assertEqual(python, native, candidate)
            accepted += not python
            refused += bool(python)
        self.assertGreater(accepted, 300)
        self.assertGreater(refused, 300)

    def test_the_event_schema_is_really_compiled_in_rust(self):
        with impl("rust"):
            self.assertIsNotNone(trace_schema.native_event_schema())
        with impl(""):
            self.assertIsNone(trace_schema.native_event_schema())

    def test_kind_pattern_edges(self):
        base = event(random.Random(1), 0)
        for kind in KINDS + ["core.state.write\n\n", "core.error", "core.errors", "x_y.z_9", "x-y.z", "core.", ".core", "\u00e9.b", "core.capture.gap\n"]:
            candidate = dict(base, kind=kind)
            python, native = both(lambda: trace_schema.validate_event(candidate))
            self.assertEqual(python, native, repr(kind))

    def write(self, directory, data, name="events.jsonl"):
        path = Path(directory) / name
        path.write_bytes(data)
        return path

    def lines(self, rng, count, start=0):
        return [json.dumps(event(rng, start + n), ensure_ascii=rng.random() < .5) for n in range(count)]

    def test_read_jsonl_agrees_on_clean_and_damaged_files(self):
        rng = random.Random(5)
        good = self.lines(rng, 40)
        bad_kind = json.dumps(dict(event(rng, 99), kind="Bad"))
        floaty = json.dumps(dict(event(rng, 99), t_mono_ns=1.5))
        big = '{"kind":"a.b","source_id":"s","source_seq":1,"producer_gen":0,"clock_domain":"m","t_mono_ns":18446744073709551616,"confidence":"exact"}'
        cases = {
            "clean": "\n".join(good) + "\n", "no final newline": "\n".join(good), "crlf": "\r\n".join(good) + "\r\n",
            "blank lines": "\n\n".join(good[:5]) + "\n  \n\t\n", "only blanks": "\n \n\n", "empty": "",
            "torn tail": "\n".join(good) + '\n{"kind": "a.b", "sou', "corrupt middle": "\n".join(good[:5] + ["{broken"] + good[5:]) + "\n",
            "bad kind last": "\n".join(good + [bad_kind]) + "\n", "bad kind unterminated": "\n".join(good + [bad_kind]),
            "float": "\n".join(good[:3] + [floaty] + good[3:]) + "\n", "big int": "\n".join(good[:3] + [big]) + "\n",
            "array line": "\n".join(good[:3] + ["[1,2]"]) + "\n", "null line": "\n".join(good[:3] + ["null"]) + "\n",
            "nan": "\n".join(good[:3] + ['{"kind": NaN}']) + "\n", "duplicate keys": '{"kind":"a.b","kind":"a.c","source_id":"s","source_seq":1,"producer_gen":0,"clock_domain":"m","t_mono_ns":1,"confidence":"exact"}\n',
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, content in cases.items():
                path = self.write(directory, content.encode("utf-8"))
                for max_events in (100_000, 7, 1):
                    python, native = both(lambda: trace.read_jsonl(path, max_events=max_events))
                    self.assertEqual(text(python), text(native), (name, max_events))
            raw = {"bom": b"\xef\xbb\xbf" + good[0].encode() + b"\n", "invalid utf8": good[0].encode() + b"\n\xff\xfe\n",
                   "surrogate escape": b'{"kind":"a.b","source_id":"\\ud800","source_seq":1,"producer_gen":0,"clock_domain":"m","t_mono_ns":1,"confidence":"exact"}\n',
                   "vertical tab": good[0].encode() + b"\n\x0b\n"}
            for name, content in raw.items():
                path = self.write(directory, content)
                python, native = both(lambda: trace.read_jsonl(path))
                self.assertEqual(text(python), text(native), name)

    def test_a_clean_file_really_takes_the_native_path(self):
        rng = random.Random(8)
        data = ("\n".join(self.lines(rng, 20)) + "\n").encode()
        with impl("rust"):
            found = trace._read_clean_native(data, 100_000)
        self.assertIsNotNone(found)
        self.assertEqual(len(found[0]), 20)
        self.assertEqual(found[1], 20)
        with impl("rust"):
            self.assertIsNone(trace._read_clean_native(data + b"{broken\n", 100_000))

    def test_events_come_back_with_python_key_order_and_types(self):
        rng = random.Random(2)
        data = ("\n".join(self.lines(rng, 30)) + "\n").encode()
        with impl("rust"):
            events, _ = trace._read_clean_native(data, 100)
        for expected, got in zip((json.loads(line) for line in data.decode().splitlines()), events):
            self.assertEqual(text(expected), text(got))

    def reply(self, rng, big=False):
        def rows(count):
            return [{"event_id": rng.choice(["e%d" % rng.randrange(40), "e1\n", "bad id", None, 5, "x" * rng.choice([5, 130])]),
                     "text": rng.choice(["", "ab", "\u00e9\u20ac", "\U0001f600" * 3, "x" * (400 if big else 5)]),
                     "value": rng.choice([1, -5, 2 ** 40, 1.5, 1e20, 1e-7, 0.1, 123456789.123456789, None, True, [1, 2.5]])}
                    for _ in range(count)]
        reply = {}
        for key in rng.sample(["rows", "groups", "nodes", "edges", "events", "results", "entries", "paths", "reasons"], rng.randrange(1, 5)):
            reply[key] = rows(rng.randrange(0, 260 if big else 60))
        if rng.random() < .4:
            reply["diff"] = {"entries": rows(rng.randrange(40)), "only_a": rows(rng.randrange(40)),
                             "gaps_a": rng.choice([[], [{"x": 1}], None]), "gaps_b": [], "revision_a": 3}
        if rng.random() < .2:
            reply["aligned"] = {"rows": rows(30)}
        if rng.random() < .5:
            reply["coverage"] = rng.choice([{}, {"revision": 4, "gaps": rows(9), "extra": 1}, {"gaps": None}, {"reported": False, "note": "n"}])
        if rng.random() < .3:
            reply["gaps"] = rng.choice([rows(30), None, "no"])
        if rng.random() < .3:
            reply["coverage_revision"] = 1
        if rng.random() < .5:
            reply["revision"] = rng.choice([5, None, "r", 2 ** 33])
        for key in ("root", "representative", "from_event", "first_a"):
            if rng.random() < .3:
                reply[key] = rng.choice(["a1", "a2", 7, "bad id"])
        if rng.random() < .3:
            reply["event_ids"] = [rng.choice(["i1", "i2", 3, {"event_id": "i9"}]) for _ in range(5)]
        order = list(reply)
        rng.shuffle(order)
        return {key: reply[key] for key in order}

    def test_shape_agrees_on_generated_replies(self):
        rng = random.Random(21)
        for number in range(400):
            reply = self.reply(rng, big=number % 4 == 0)
            for session in ("s1", None):
                for limit in (25, 3, 200, 0):
                    python, native = both(lambda: trace.shape(reply, session=session, command="trace_query", limit=limit,
                                                              requested_revision=rng.choice([None]) if number % 3 else 7))
                    self.assertEqual(text(python), text(native), (number, session, limit))

    def test_shape_agrees_on_non_object_and_oversized_replies(self):
        for reply in ([1, 2], "x", 5, None, {"blob": "x" * 60_000, "revision": 4}, {"blob": "\u00e9" * 20_000}, {"rows": ["y" * 60_000]},
                      {"rows": [{"n": i, "s": "z" * 30} for i in range(2000)]}):
            python, native = both(lambda: trace.shape(reply, session="s", command="trace_diff", limit=200))
            self.assertEqual(text(python), text(native))

    def test_shape_takes_the_native_path_and_falls_back_on_shapes_it_does_not_model(self):
        with impl("rust"):
            module = trace_native.native()
            module.trace_shape({"rows": [1]}, "s", "c", 5, None)
            for odd in ({"big": 2 ** 70}, {"k": float("inf")}, {1: "non-text key"}, {"s": object()}, {"u": "\ud800"}):
                with self.assertRaises((module.TraceFallback, OverflowError)):
                    module.trace_shape(odd, "s", "c", 5, None)
        for odd in ({"big": 2 ** 70, "rows": [1, 2, 3]}, {"u": "\ud800"}, {"t": (1, 2), "rows": [1, 2, 3]}):
            python, native = both(lambda: trace.shape(odd, session="s", command="c", limit=2))
            self.assertEqual(repr(python), repr(native))


if __name__ == "__main__":
    unittest.main()
