"""The native `annotate` (native/src/trace/keys.rs) gives exactly what `trace_keys.annotate_python` gives: the same
events, the same report, the same refusals, on hand-made cases and on randomized streams."""

from __future__ import annotations

import copy
import os
import random
import unittest

from hydralysis import trace_keys

try:
    import hydralysis_native as native  # type: ignore[import-not-found]
    HAVE = hasattr(native, "annotate_events") and os.environ.get("HYDRALYSIS_NATIVE", "1") != "0"
except ImportError:
    native, HAVE = None, False


class Profile:
    def __init__(self, roles=(), phases=()):
        self.data = {"roles": list(roles), "phases": list(phases)}


FRAME = {"id": "frame", "kind": "frame", "open": "fb", "close": "fe"}
STAGES = [{"id": "input", "kind": "stage", "open": "s1"}, {"id": "update", "kind": "stage", "open": "s2"},
          {"id": "render", "kind": "stage", "open": "s3"}]
ROLES = [{"id": "main", "resolve": "function", "value": "fb"}, {"id": "render-thread", "resolve": "function", "value": "s3"},
         {"id": "worker", "resolve": "thread_start_rva", "value": "0x1500"}, {"id": "named", "resolve": "thread_name", "value": "audio"},
         {"id": "pool", "resolve": "pool", "value": "x"}]


def event(seq, kind="app.x", pid=1, tid=1, thread_id=None, **payload):
    return {"kind": kind, "process_id": pid, "thread_id": tid if thread_id is None else thread_id, "source_seq": seq,
            "t_mono_ns": seq * 10, "payload": payload}


def both(events, profile, strict=False):
    before = copy.deepcopy(events)
    python = trace_keys.annotate_python(events, profile, strict=strict)
    assert events == before, "the Python annotate changed its input"
    native_out = native.annotate_events(events, list(profile.data["roles"]), list(profile.data["phases"]), strict, trace_keys._norm_rva)
    assert events == before, "the native annotate changed its input"
    return python, native_out


@unittest.skipUnless(HAVE, "hydralysis_native.annotate_events is not built")
class Same(unittest.TestCase):
    def check(self, events, profile):
        (py_out, py_report), (rs_out, rs_report) = both(events, profile)
        self.assertEqual(rs_out, py_out)
        self.assertEqual(rs_report, py_report)
        self.assertEqual(list(rs_report["roles"]), list(py_report["roles"]))
        for a, b in zip(rs_out, py_out):          # key order too: the stamped payload serialises the same way
            self.assertEqual(list(a), list(b))
            self.assertEqual(list(a.get("payload") or {}), list(b.get("payload") or {}))
            self.assertEqual(list((a.get("payload") or {}).get("unresolved", {})), list((b.get("payload") or {}).get("unresolved", {})))

    def test_a_frame_with_all_its_stages(self):
        events = [event(i, thread_id=7, hook=h, **extra) for i, (h, extra) in enumerate(
            [("fb", {"frame": 4}), ("s1", {}), ("x", {}), ("s2", {}), ("x", {}), ("s3", {}), ("fe", {})])]
        self.check(events, Profile(ROLES, [FRAME, *STAGES]))

    def test_a_missing_stage_marker_and_events_outside_a_frame(self):
        events = [event(0, thread_id=7, hook="x"), event(1, thread_id=7, hook="fb", frame=1), event(2, thread_id=7, hook="x"),
                  event(3, thread_id=7, hook="s3"), event(4, thread_id=7, hook="x"), event(5, thread_id=7, hook="fe"),
                  event(6, thread_id=7, hook="x"), event(7, "core.marker", thread_id=7)]
        self.check(events, Profile(ROLES, [FRAME, *STAGES]))

    def test_resolvers_by_start_address_and_by_name(self):
        events = [event(0, "core.thread.start", tid=7, start_rva="0x1500"), event(1, "core.thread.start", tid=8, name="audio"),
                  event(2, "core.marker", tid=9, name="audio", thread_name=True), event(3, "core.marker", tid=10, name="audio"),
                  *[event(4 + i, tid=7 + i, hook="h") for i in range(5)]]
        self.check(events, Profile(ROLES[2:4], [FRAME]))

    def test_refused_resolvers_and_strict(self):
        events = [event(0, thread_id=7, hook="fb", frame=1)]
        profile = Profile(ROLES, [FRAME, *STAGES])
        (py_out, py_report), (rs_out, rs_report) = both(events, profile)
        self.assertEqual((rs_out, rs_report), (py_out, py_report))
        self.assertTrue(rs_report["refused_resolvers"])
        out, report = native.annotate_events(events, list(ROLES), [FRAME], True, trace_keys._norm_rva)
        self.assertIsNone(out)
        self.assertEqual(report["refused_resolvers"], py_report["refused_resolvers"])
        with self.assertRaises(trace_keys.RoleResolverRefused):
            trace_keys.annotate(events, profile, strict=True)

    def test_no_phases_and_no_roles(self):
        events = [event(0, hook="a"), event(1, tid=2, hook="b", frame=3), event(2, "core.module.load")]
        self.check(events, Profile())
        self.check(events, Profile(ROLES[:1], [STAGES[0]]))

    def test_the_hooks_own_frame_argument_wins_and_a_bool_is_an_int(self):
        events = [event(0, hook="fb", frame=9), event(1, hook="x", frame=True), event(2, hook="x", frame="7"), event(3, hook="fe")]
        self.check(events, Profile(ROLES, [FRAME, *STAGES]))

    def test_the_stage_number_must_match_the_stage_position(self):
        events = [event(0, hook="fb", frame=1), event(1, hook="s2", stage=2), event(2, hook="s1", stage=2), event(3, hook="s3", stage=3),
                  event(4, hook="fe")]
        self.check(events, Profile(ROLES, [FRAME, *STAGES]))

    def test_randomized_streams(self):
        rng = random.Random(20260211)
        hooks = ["fb", "fe", "s1", "s2", "s3", "x", "y"]
        for _round in range(300):
            events = []
            for seq in range(rng.randint(0, 80)):
                pid, tid = rng.choice([1, 2]), rng.randint(1, 4)
                roll = rng.random()
                if roll < 0.08:
                    payload = rng.choice([{"start_rva": rng.choice(["0x1500", "5376", 0x1500, "zz", "0X1500", "1_500"])},
                                          {"name": rng.choice(["audio", "main"])},
                                          {"name": "audio", "thread_name": rng.choice([True, False, ""])}, {}])
                    events.append(event(seq, rng.choice(["core.thread.start", "core.marker"]), pid, tid, **payload))
                elif roll < 0.12:
                    events.append({"kind": "core.module.load", "process_id": pid, "thread_id": tid, "source_seq": seq})
                else:
                    payload = {"hook": rng.choice(hooks)}
                    if rng.random() < 0.3:
                        payload["frame"] = rng.choice([1, 2, 3, None, True, "9"])
                    if rng.random() < 0.2:
                        payload["stage"] = rng.randint(1, 4)
                    events.append(event(seq, "app.x", pid, tid, **payload))
            roles = rng.sample(ROLES, rng.randint(0, len(ROLES)))
            phases = [FRAME, *STAGES][:rng.randint(0, 4)] if rng.random() < 0.9 else []
            if rng.random() < 0.3:
                phases = [p for p in phases if p["kind"] != "frame"]
            self.check(events, Profile(roles, phases))

    def test_the_wrapper_falls_back_to_python_for_shapes_the_port_does_not_take(self):
        events = [event(0, hook="fb", frame=1)]
        events[0]["payload"] = "not a mapping"
        with self.assertRaises(Exception) as native_raised:
            trace_keys.annotate(events, Profile(ROLES, [FRAME]))
        with self.assertRaises(Exception) as python_raised:
            trace_keys.annotate_python(events, Profile(ROLES, [FRAME]))
        self.assertIs(type(native_raised.exception), type(python_raised.exception))


if __name__ == "__main__":
    unittest.main()
