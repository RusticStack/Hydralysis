"""Differential test of the engine-facing core of query.py (accepted, _public, reader_lanes, engine_decompile) and
decompile_job.job_path: Python vs hy-query (`hydralysis_native`). The comparison is the value, or the exception type and
message. Skipped when hydralysis_native lacks the functions."""

import copy
import json
import os
import random
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import decompile_job, hydra, query

try:
    import hydralysis_native
    HAVE_NATIVE = hasattr(hydralysis_native, "session_engine_decompile_rs")
except ImportError:
    HAVE_NATIVE = False


def outcome(function, *args, impl):
    with patch.dict(os.environ, {"HYDRALYSIS_IMPL": impl}):
        try:
            return ("ok", function(*copy.deepcopy(args)))
        except Exception as error:  # noqa: BLE001
            return (type(error).__name__, str(error))


class Engine:
    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.calls = reply, error, []

    def call(self, command, **fields):
        self.calls.append((command, fields))
        if self.error:
            raise self.error
        return copy.deepcopy(self.reply)


PIECES = {"name": "f", "entry": "0x1", "completed": True, "signature": "int f(void);", "chars": 5, "c": "int x;",
          "truncated": False, "partial": True, "reason": "non_contiguous_body",
          "fragments": [{"start": "0x1", "end": "0x38", "class": "code", "decompiled": True},
                        {"start": "0x200", "end": "0x21f", "class": "data", "decompiled": False}]}
PAGE = {"name": "f", "entry": "0x1", "completed": True, "c": "page", "offset": 0, "chars": 9000, "next_offset": 4,
        "truncated": False}
OVERFLOW = {"completed": False, "truncated": True, "bytes_emitted": 1024, "reason": "response_buffer",
            "error": "Response buffer size exceeded", "partial": True, "c": "int f(void)\n{", "chars": 13,
            "budget": {"mode": "auto", "mb": 256}}

RESPONSES = [
    {"ok": True, "c": "x"}, {"ok": False, "error": "No pcode could be generated"}, {"ok": False, "message": "m" * 700},
    {"ok": False, "error": ""}, {"ok": False}, {"ok": None, "c": "t"}, {"ok": 0}, {"ok": 1, "c": "t"}, {},
    {"ok": False, "error": "e", "token": "T", "ipc": {"x": 1}, "list": [{"secret": 1, "keep": 2}]},
    {"ok": True, "c": "text", "truncated": True, "id": "i", "function": {"name": "f"}},
    {"ok": False, "id": "i", "program": "p", "error": "boom", "engine": {"v": 1}},
    {"ok": True, "c": "ünï", "truncated": False}, {"ok": False, "error": "ünï \u2603 \n tab\t"},
    {"ok": False, "error": json.dumps({**OVERFLOW})},
]
REQUESTS = [
    {"action": "decompile", "address": "0x1", "options": {}},
    {"action": "decompile", "address": "0x1", "options": {"max_characters": 1000}},
    {"action": "decompile", "address": "0x1", "options": {"max_result_mb": 2}},
    {"action": "decompile", "address": "0x1", "options": {"max_result_kb": 7, "offset": 0}},
    {"action": "decompile", "address": "0x1", "options": {"max_result_mb": 1, "max_result_kb": None}},
    {"action": "decompile", "address": "0x1"}, {"action": "decompile", "address": "0x1", "options": None},
    {"action": "xrefs", "address": "0x1", "options": {"max_result_mb": 1}},
    {"action": "decompile", "address": "0x1", "options": {"max_characters": 10, "max_result_kb": 7, "max_result_mb": 3, "offset": 20}},
    {"action": "decompile", "address": "0x1", "options": {"max_characters": 1.5, "offset": 1}},
]
ENGINES = [
    lambda: Engine(PIECES), lambda: Engine(PAGE), lambda: Engine(OVERFLOW), lambda: Engine({}),
    lambda: Engine(error=hydra.EngineError("timeout", "decompile timed out")),
    lambda: Engine(error=hydra.EngineError("bad_request", "no")),
    lambda: Engine(error=hydra.EngineError("failed", "x", {"reason": "Timeout in the decompiler"})),
    lambda: Engine(error=hydra.EngineError("failed", "x", {"reason": 5})),
    lambda: Engine(error=hydra.EngineError("x", "the call TIMED OUT")),
    lambda: Engine(error=hydra.EngineError("deadline", "d")),
]


def run_decompile(make, request, timeout, response, inline):
    engine = make()
    try:
        return ("ok", query.engine_decompile(engine, {"key": "k"}, request, timeout, response, inline), engine.calls)
    except query.DeferDecompile as error:
        return ("defer", str(error), engine.calls)
    except (TypeError, ValueError) as error:
        return ("raised", type(error).__name__, str(error), engine.calls)


def normalise(result):
    """Drop the measured seconds of the fallback label."""
    result = copy.deepcopy(result)
    if result[0] == "ok" and isinstance(result[1], dict) and isinstance(result[1].get("fallback"), dict):
        result[1]["fallback"].pop("engine_s", None)
    return result


@unittest.skipUnless(HAVE_NATIVE, "hydralysis_native with the session functions is not built")
class SessionParity(unittest.TestCase):
    def test_accepted_and_public(self):
        for action in ("decompile", "xrefs", "function"):
            for response in RESPONSES:
                with self.subTest(action=action, response=response):
                    self.assertEqual(outcome(query.accepted, action, response, impl="python"),
                                     outcome(query.accepted, action, response, impl="rust"))
        for response in RESPONSES:
            self.assertEqual(outcome(query._public, response, impl="python"), outcome(query._public, response, impl="rust"))

    def test_accepted_with_the_decompile_merge_shapes(self):
        from hydralysis import decompile_result as dr
        for base in ({"id": "x", "ok": True, "c": "script"}, {"id": "x", "ok": False, "error": "e"}):
            for reply in (PIECES, PAGE, OVERFLOW):
                merged = dr.merge(base, reply)
                with self.subTest(base=base, reply=reply["name"] if "name" in reply else "overflow"):
                    self.assertEqual(outcome(query.accepted, "decompile", merged, impl="python"),
                                     outcome(query.accepted, "decompile", merged, impl="rust"))

    def test_reader_lanes(self):
        for value in (None, 0, 1, 2, 64, 65, -1, True, False, 3.0, "4", [], {}, 2 ** 70):
            for name in ("readerLanes", "reader_lanes"):
                settings = {} if value is None else {name: value}
                self.assertEqual(outcome(query.reader_lanes, settings, impl="python"),
                                 outcome(query.reader_lanes, settings, impl="rust"), settings)
        both = {"readerLanes": 5, "reader_lanes": 6}
        self.assertEqual(outcome(query.reader_lanes, both, impl="python"), outcome(query.reader_lanes, both, impl="rust"))
        self.assertEqual(outcome(query.reader_lanes, {"readerLanes": None, "reader_lanes": 6}, impl="python"),
                         outcome(query.reader_lanes, {"readerLanes": None, "reader_lanes": 6}, impl="rust"))

    def test_engine_decompile_grid(self):
        for make in ENGINES:
            for request in REQUESTS:
                for response in RESPONSES[:9]:
                    for inline in (False, True):
                        with patch.dict(os.environ, {"HYDRALYSIS_IMPL": "python"}):
                            expected = normalise(run_decompile(make, request, 30, response, inline))
                        with patch.dict(os.environ, {"HYDRALYSIS_IMPL": "rust"}):
                            actual = normalise(run_decompile(make, request, 30, response, inline))
                        self.assertEqual(actual, expected, (request, response, inline))

    def test_a_python_exception_from_the_engine_propagates(self):
        for impl in ("python", "rust"):
            with patch.dict(os.environ, {"HYDRALYSIS_IMPL": impl}):
                engine = Engine(error=KeyError("boom"))
                with self.assertRaises(KeyError):
                    query.engine_decompile(engine, {"key": "k"}, REQUESTS[2], 30, {"ok": True, "c": "t"})

    def test_an_unchanged_answer_is_the_same_object(self):
        good = {"ok": True, "c": "t"}
        with patch.dict(os.environ, {"HYDRALYSIS_IMPL": "rust"}):
            self.assertIs(query.engine_decompile(Engine(PIECES), {"key": "k"}, REQUESTS[0], 5, good), good)

    def test_random_option_mutations(self):
        rng = random.Random(7)
        values = [None, 0, 1, 2, 7, 20, 1.5, True, "3", [], {}, 10 ** 12]
        for _ in range(300):
            options = {name: rng.choice(values) for name in rng.sample(
                ["max_characters", "max_result_mb", "max_result_kb", "offset", "other"], rng.randint(0, 5))}
            request = {"action": rng.choice(["decompile", "xrefs"]), "address": rng.choice(["0x1", 5, None]),
                       "options": options}
            response = rng.choice(RESPONSES[:9])
            make = rng.choice(ENGINES)
            inline = rng.random() < 0.5
            with patch.dict(os.environ, {"HYDRALYSIS_IMPL": "python"}):
                expected = normalise(run_decompile(make, request, 30, response, inline))
            with patch.dict(os.environ, {"HYDRALYSIS_IMPL": "rust"}):
                actual = normalise(run_decompile(make, request, 30, response, inline))
            self.assertEqual(actual, expected, (request, response, inline))

    def test_job_path(self):
        for job_id in ("decompile-0123456789ab", "decompile-0123456789AB", "decompile-0123456789a", "decompile-0123456789abc",
                       "x", "", "decompile-0123456789ab\n", "../decompile-0123456789ab", "decompile-０１２３４５６７８９ab"):
            settings = {"root": "D:/x/root"}
            expected = outcome(decompile_job.job_path, settings, job_id, impl="python")
            actual = outcome(decompile_job.job_path, settings, job_id, impl="rust")
            self.assertEqual((actual[0], Path(str(actual[1])) if actual[0] == "ok" else actual[1]),
                             (expected[0], Path(str(expected[1])) if expected[0] == "ok" else expected[1]), job_id)

    def test_windows_path_spelling_of_the_cache_key(self):
        for text in ("C:/views/a/a.gpr", "C:\\views\\a\\.\\a.gpr", "c:/a//b/", "", ".", "rel/x", "//srv/share/x", "\\\\srv\\share",
                     "C:", "C:x", "C:/", "/rooted/x", "a/../b", "D:/x/./y/..", "//srv/share", "//srv/share/", "//./pipe/x", "//?/C:/x", "/", "a/../.."):
            self.assertEqual(hydralysis_native.session_windows_path_rs(text), str(__import__("pathlib").PureWindowsPath(text)), text)


if __name__ == "__main__":
    unittest.main()
