"""The vendored TRACE-1 schemas equal the engine's, and the stdlib validator checks events against them."""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import REPOSITORY

from hydralysis import trace_canon, trace_schema

RELATIVE = Path("Ghidra") / "Features" / "HeadlessSession" / "trace-schema"


def engine_schema_dir():
    """The engine's schema folder: HYDRA_TRACE_SCHEMA_DIR, or a sibling engine checkout of this repository."""
    explicit = os.environ.get("HYDRA_TRACE_SCHEMA_DIR")
    candidates = [Path(explicit)] if explicit else []
    for root in (REPOSITORY.parent, REPOSITORY.parent.parent, REPOSITORY.parent.parent.parent / "wt"):
        for engine in ("hydra-engine", "trace-engine", "engine"):
            candidates.append(root / engine / RELATIVE)
    return next((path for path in candidates if path.is_dir()), None)


GOOD = {"kind": "core.marker", "source_id": "s", "source_seq": 0, "producer_gen": 1, "clock_domain": "qpc",
        "t_mono_ns": 5, "confidence": "exact", "payload": {"label": "x"}}


class VendoredSchemas(unittest.TestCase):
    def test_copies_are_identical_to_the_engines(self):
        source = engine_schema_dir()
        if source is None:
            self.skipTest("no engine checkout found; set HYDRA_TRACE_SCHEMA_DIR to its trace-schema folder")
        theirs = sorted(path.name for path in source.glob("*.json"))
        self.assertEqual(trace_schema.names(), theirs, "vendored schema set differs from the engine's")
        for name in theirs:
            self.assertEqual((trace_schema.DIRECTORY / name).read_bytes(), (source / name).read_bytes(), name)

    def test_every_schema_is_json_with_an_id_and_a_digest(self):
        self.assertIn("event.schema.json", trace_schema.names())
        for name in trace_schema.names():
            schema = trace_schema.load(name)
            self.assertTrue(schema["$id"].startswith("hydra.trace."), name)
            self.assertRegex(trace_schema.digest(name), r"^[0-9a-f]{64}$")


class Validator(unittest.TestCase):
    def test_a_good_event_and_a_chained_event_pass(self):
        self.assertEqual(trace_schema.validate_event(GOOD), [])
        chain = trace_canon.Chain("s1")
        chained = json.loads(chain.push(GOOD)[9:])
        self.assertEqual(trace_schema.validate_event(chained), [])

    def test_bad_events_say_why(self):
        cases = [
            ({**GOOD, "kind": "core.nonsense"}, "kind"),
            ({**GOOD, "kind": "app.feature"}, None),
            ({k: v for k, v in GOOD.items() if k != "clock_domain"}, "clock_domain"),
            ({**GOOD, "confidence": "certain"}, "confidence"),
            ({**GOOD, "t_mono_ns": -1}, "t_mono_ns"),
            ({**GOOD, "va": True}, "va"),
            ({**GOOD, "callstack": [1, "x"]}, "callstack[1]"),
            ({**GOOD, "surprise": 1}, "surprise"),
        ]
        for event, word in cases:
            problems = trace_schema.validate_event(event)
            if word is None:
                self.assertEqual(problems, [], event)
            else:
                self.assertTrue(any(word in problem for problem in problems), (word, problems))

    def test_an_unsupported_keyword_is_refused_not_ignored(self):
        with self.assertRaises(ValueError):
            trace_schema.errors({}, {"type": "object", "patternProperties": {}})


if __name__ == "__main__":
    unittest.main()
