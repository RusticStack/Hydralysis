"""Differential test of the link_events port: hydralysis.trace_bindings (Python) vs hy-trace `bindings` (Rust).

Seeded synthetic traces (several thread generations, interleaved script calls and native entries, calls with no native,
unknown script functions, a table with thunks) plus shape mutations. The comparison is the JSON text with insertion order
kept. A shape the port does not model must raise `TraceFallback`; it must never answer differently, nor answer where the
Python raises. Skipped when hydralysis_native lacks the function.
"""

import copy
import json
import os
import random
import unittest
from unittest.mock import patch

from hydralysis import trace_bindings

try:
    import hydralysis_native
    HAVE_NATIVE = hasattr(hydralysis_native, "bindings_link_events")
except ImportError:
    HAVE_NATIVE = False

NAMES = ["get_health", "rand", "spawn", "print", "mystery", ""]


def table(rng):
    rows = []
    for index, name in enumerate(NAMES[:4]):
        base = 0x1000 + index * 0x100
        status = rng.choice(["resolved", "resolved", "resolved", "unresolved"])
        thunk = rng.random() < 0.5
        rows.append({"script_name": name, "status": status, "native_rva": "rva:%#x" % base,
                     "implementation_rva": ("rva:%#x" % (base + 0x40)) if thunk else None, "thunk": thunk, "argc": index})
    return {"rows": rows}


def trace(rng, count):
    events = []
    for number in range(count):
        thread = rng.choice([1, 2, 3, "t4", None])
        if rng.random() < 0.35:
            events.append({"event_id": "ev_%d" % number, "seq": number, "thread_gen": thread, "kind": "app.script.call",
                           "payload": {"script_function": rng.choice(NAMES)}})
        else:
            events.append({"event_id": "ev_%d" % number, "seq": rng.choice([number, number, None]), "thread_gen": thread,
                           "kind": rng.choice(["core.function.enter", "core.function.enter", "core.function.leave"]),
                           "rva": rng.choice([0x1000, 0x1040, 0x1100, 0x1140, 0x1200, 0x9999, None])})
    rng.shuffle(events)
    return events


def outcome(events, tab, window, *, rust):
    events = copy.deepcopy(events)
    try:
        if rust:
            return ("ok", json.dumps(hydralysis_native.bindings_link_events(events, copy.deepcopy(tab), window)))
        return ("ok", json.dumps(trace_bindings._link_events_py(events, copy.deepcopy(tab), window=window)))
    except hydralysis_native.TraceFallback:
        return ("fallback", "")
    except Exception as error:  # noqa: BLE001
        return (type(error).__name__, str(error))


@unittest.skipUnless(HAVE_NATIVE, "hydralysis_native lacks bindings_link_events")
class LinkEventsParity(unittest.TestCase):
    def compare(self, events, tab, window=8):
        want = outcome(events, tab, window, rust=False)
        got = outcome(events, tab, window, rust=True)
        if got[0] != "fallback":
            self.assertEqual(got, want)
        return got

    def test_synthetic_traces_match_byte_for_byte(self):
        answered = 0
        for seed in range(150):
            rng = random.Random(seed)
            answered += self.compare(trace(rng, rng.randint(0, 80)), table(rng), rng.choice([0, 1, 3, 8, 50]))[0] == "ok"
        self.assertGreater(answered, 120, "the port must model the shapes the producers emit")

    def test_shapes_outside_the_port_never_answer_differently(self):
        rng = random.Random(5)
        events, tab = trace(rng, 40), table(rng)
        cases = []
        for change in ({"thread_gen": [1, 2]}, {"thread_gen": 1.5}, {"rva": 4096.0}, {"rva": True}, {"seq": "3"}, {"seq": 2.5},
                       {"event_id": ("a", 1)}, {"payload": [1]}, {"payload": {"script_function": ["x"]}},
                       {"payload": {"script_function": 7}}, {"kind": None}):
            broken = copy.deepcopy(events)
            for event in broken[::4]:
                event.update(change)
            cases.append((broken, tab))
        for key, value in (("status", None), ("script_name", ["x"]), ("native_rva", "rva:zz"), ("native_rva", "r"), ("native_rva", 5)):
            broken = copy.deepcopy(tab)
            broken["rows"][0][key] = value
            cases.append((events, broken))
        cases.append((events, {"rows": "no"}))
        cases.append((events, {}))
        cases.append(([1, 2], tab))
        for events_, tab_ in cases:
            self.compare(events_, tab_)

    def test_an_rva_with_python_int_syntax_is_read_like_int(self):
        rng = random.Random(9)
        events = trace(rng, 30)
        for text in ("rva:0X10_00", "rva: 0x1000 ", "rva:+0x1000", "rva:1000", "rva:-0x1"):
            tab = {"rows": [{"script_name": "get_health", "status": "resolved", "native_rva": text}]}
            self.compare(events, tab)

    def test_routing_in_link_events(self):
        rng = random.Random(2)
        events, tab = trace(rng, 60), table(rng)
        want = json.dumps(trace_bindings._link_events_py(copy.deepcopy(events), tab))
        with patch.dict(os.environ, {"HYDRALYSIS_IMPL": "rust", "HYDRALYSIS_TRACE_HELD": "1"}):   # held back by default: see trace_native
            self.assertEqual(json.dumps(trace_bindings.link_events(copy.deepcopy(events), tab)), want)
            events[0]["thread_gen"] = [1, 2]
            self.assertEqual(json.dumps(trace_bindings.link_events(copy.deepcopy(events), tab)),
                             json.dumps(trace_bindings._link_events_py(copy.deepcopy(events), tab)))


if __name__ == "__main__":
    unittest.main()
