"""Differential test of the pair_report port: hydralysis.trace_pairing (Python) vs hy-trace `pairing` (Rust).

Seeded synthetic owner/replica sessions (drift, outages, dropped mirrors, extrapolated ticks, owner-only and replica-only
objects, float and integer values) plus mutations that leave the shapes the port models. The comparison is the JSON text
with insertion order kept, so key order, int-versus-float and float digits all count. A case the port does not model must
raise `TraceFallback` (the Python then answers); it must never answer differently, or answer where the Python raises.
Skipped when hydralysis_native lacks the function.
"""

import copy
import json
import os
import random
import unittest
from unittest.mock import patch

from hydralysis import trace_pairing

try:
    import hydralysis_native
    HAVE_NATIVE = hasattr(hydralysis_native, "pairing_pair_report")
except ImportError:
    HAVE_NATIVE = False


def session(rng, *, objects=4, per_object=12, drift=1.0, offset=250_000_000, markers=5, dropped=0.2, ints=True, gap=False):
    owner, replica = [], []
    counter = iter(range(1, 10 ** 9))
    for n in range(markers):
        t = 1_000_000_000 + n * rng.choice([5_000_000, 700_000_000, 1_500_000_000])
        owner.append({"event_id": next(counter), "kind": "app.sync", "t_mono_ns": t, "payload": {"n": n}})
        replica.append({"event_id": next(counter), "kind": "app.sync_recv",
                        "t_mono_ns": int((t - offset) / drift) + rng.randint(-20_000, 20_000), "payload": {"n": n}})
    for obj in range(objects):
        kind_owner = rng.random()
        if kind_owner < 0.2:
            owner.append({"event_id": next(counter), "kind": "app.create", "t_mono_ns": 2_000_000_000, "payload": {"obj": obj}})
            continue
        if kind_owner < 0.3:
            replica.append({"event_id": next(counter), "kind": "app.mirror", "t_mono_ns": 2_000_000_000, "payload": {"obj": obj, "seq": 1}})
            continue
        value = rng.randint(0, 100)
        for seq in range(per_object):
            t = 2_000_000_000 + seq * 16_000_000 + rng.randint(0, 3_000_000)
            value += rng.randint(-5, 9)
            owner.append({"event_id": next(counter), "kind": "app.truth", "t_mono_ns": t,
                          "payload": {"obj": obj, "seq": seq, "value": value if ints else value + 0.25}})
            if rng.random() > dropped and not (gap and 4 <= seq <= 7):
                lag = rng.randint(10_000_000, 40_000_000)
                shown = value + rng.randint(-3, 3)
                replica.append({"event_id": next(counter), "kind": "app.mirror", "t_mono_ns": int((t + lag - offset) / drift),
                                "payload": {"obj": obj, "seq": seq, "value": shown if ints or rng.random() < 0.5 else shown + 0.5}})
        replica.append({"event_id": next(counter), "kind": "app.extrapolated", "t_mono_ns": 3_000_000_000, "payload": {"obj": obj}})
    rng.shuffle(owner)
    rng.shuffle(replica)
    return owner, replica


def outcome(owner, replica, spec, *, rust):
    owner, replica = copy.deepcopy(owner), copy.deepcopy(replica)
    try:
        if rust:
            merged = {**trace_pairing.DEFAULT_SPEC, **(spec or {})}
            return ("ok", json.dumps(hydralysis_native.pairing_pair_report(owner, replica, merged)))
        return ("ok", json.dumps(trace_pairing._pair_report_py(owner, replica, spec)))
    except hydralysis_native.TraceFallback:
        return ("fallback", "")
    except Exception as error:  # noqa: BLE001
        return (type(error).__name__, str(error))


@unittest.skipUnless(HAVE_NATIVE, "hydralysis_native lacks pairing_pair_report")
class PairReportParity(unittest.TestCase):
    def compare(self, owner, replica, spec=None):
        want = outcome(owner, replica, spec, rust=False)
        got = outcome(owner, replica, spec, rust=True)
        if got[0] == "fallback":
            return got
        self.assertEqual(got, want)
        return got

    def test_synthetic_sessions_match_byte_for_byte(self):
        specs = [None, {"max_error": 4}, {"max_error": 2.5, "gap_factor": 3.5}, {"min_gap_ns": 50_000_000, "latency_allowance_ns": 1.9e7}]
        answered = 0
        for seed in range(120):
            rng = random.Random(seed)
            owner, replica = session(rng, objects=rng.randint(1, 6), per_object=rng.randint(1, 30), drift=rng.choice([1.0, 1.0, 1.0001, 0.9997]),
                                     offset=rng.choice([0, 250_000_000, -40_000_000]), markers=rng.choice([0, 2, 3, 5, 8]),
                                     dropped=rng.choice([0.0, 0.2, 0.7]), ints=rng.random() < 0.6, gap=rng.random() < 0.5)
            answered += self.compare(owner, replica, rng.choice(specs))[0] == "ok"
        self.assertGreater(answered, 100, "the port must model the shapes the producers emit")

    def test_uncalibrated_and_empty_sessions(self):
        self.assertEqual(self.compare([], [])[0], "ok")
        rng = random.Random(1)
        owner, replica = session(rng, markers=2)
        self.assertEqual(self.compare(owner, replica)[0], "ok")

    def test_a_missing_field_is_a_fallback_never_a_different_answer(self):
        rng = random.Random(7)
        owner, replica = session(rng, objects=3)
        for index in range(0, len(owner), 5):
            broken = copy.deepcopy(owner)
            del broken[index]["event_id"]
            self.compare(broken, replica)
        broken = copy.deepcopy(replica)
        broken[0]["t_mono_ns"] = "12"
        self.assertEqual(self.compare(owner, broken)[0], "fallback")

    def test_exotic_values_never_answer_differently(self):
        rng = random.Random(11)
        owner, replica = session(rng, objects=2)
        for mutate in (lambda p: p.update(value=True), lambda p: p.update(value="3"), lambda p: p.update(value=None),
                       lambda p: p.update(seq=1.5), lambda p: p.update(seq=None), lambda p: p.update(obj=2.5), lambda p: p.update(obj=None),
                       lambda p: p.update(obj="aé"), lambda p: p.update(value=10 ** 12), lambda p: p.update(value=[1])):
            for side in (owner, replica):
                broken = copy.deepcopy(side)
                for event in broken[::3]:
                    if event["kind"] in ("app.truth", "app.mirror"):
                        mutate(event["payload"])
                self.compare(*(broken, replica) if side is owner else (owner, broken))

    def test_routing_in_pair_report_uses_the_port_and_falls_back(self):
        rng = random.Random(3)
        owner, replica = session(rng)
        want = json.dumps(trace_pairing._pair_report_py(owner, replica, None))
        with patch.dict(os.environ, {"HYDRALYSIS_IMPL": "rust"}):
            self.assertEqual(json.dumps(trace_pairing.pair_report(owner, replica, None)), want)
            next(e for e in replica if e["kind"] == "app.sync_recv")["t_mono_ns"] = "7"   # float("7") works in Python: a fallback
            self.assertEqual(json.dumps(trace_pairing.pair_report(owner, replica, None)),
                             json.dumps(trace_pairing._pair_report_py(owner, replica, None)))


if __name__ == "__main__":
    unittest.main()
