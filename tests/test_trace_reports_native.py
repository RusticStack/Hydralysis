"""The Rust port of trace_reports (crates/hy-trace/src/reports.rs, bound in native/src/trace/reports.rs) against Python.

Generated event pages with the shapes the producers emit (and a few they do not: those must reach the Python
implementation and so give the Python answer) go through both implementations; the answers must be equal, down to dict key
order (compared as JSON text without sorting).
"""

import contextlib
import json
import os
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hydralysis import trace_native, trace_reports as tr


@contextlib.contextmanager
def impl(value):
    """HYDRALYSIS_IMPL=VALUE, with the held-back functions (reports, shape) routed so that the Rust code is what runs."""
    saved = {key: os.environ.get(key) for key in ("HYDRALYSIS_IMPL", "HYDRALYSIS_TRACE_HELD")}
    os.environ["HYDRALYSIS_IMPL"] = value
    os.environ["HYDRALYSIS_TRACE_HELD"] = "1"
    try:
        yield
    finally:
        for key, was in saved.items():
            if was is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = was


def have_native():
    with impl("rust"):
        return trace_native.native() is not None


def both(function):
    with impl(""):
        python = function()
    with impl("rust"):
        native = function()
    return python, native


def text(value):
    return json.dumps(value, default=repr)       # no sort_keys: key order is part of the answer


PHASES = ["input", "update", "late", "render"]
SITES = ["OurHook", "HostAnimator::Tick", "Other::Thread", "Wrapper", "Actor::SetHp(int)", "Actor::SetHp(float)", None]


def generated(seed, count=300, frames=25, weird=False):
    rng = random.Random(seed)
    events = []
    for number in range(count):
        kind = rng.choice(["core.state.write", "core.state.write", "core.state.read", "app.escape", "core.function.enter", "other"])
        frame = rng.choice([rng.randrange(frames)] * 5 + [None, "f%d" % rng.randrange(3)])
        function = rng.choice(SITES) if kind != "core.state.read" or rng.random() < .3 else "Render"
        payload = {"state_key": rng.choice(["Actor.speed", "Actor.speed", "Actor.hp", None]), "value": rng.randrange(5)}
        if rng.random() < .2:
            payload.pop("state_key")
            payload["key"] = "Actor.speed"
        if rng.random() < .5:
            payload.update(object=rng.choice([0x5000, 0x5000, 0x9000]), offset=rng.choice([0, 4, 8]), size=rng.choice([4, 8]))
        if rng.random() < .3:
            payload.update(site="rva:0x500", target=rng.choice(["Actor::SetHp(float)", "Actor::SetHp(double)", "Target"]),
                           receiver_class=rng.choice([None, "Hero", "Villain"]), slot=rng.choice([None, 3, 4]))
        if kind == "app.escape":
            payload["callee"] = rng.choice(["memcpy", None, ""])
        payload["receiver"] = rng.choice([0x40, 0x48, None])
        event = {"event_id": "e%d" % number if rng.random() < .97 else None, "kind": kind, "seq": rng.choice([number, number, None]),
                 "frame": frame, "phase": rng.choice(PHASES + ["unlisted", None]), "role": rng.choice(["main", None, "render"]),
                 "thread_gen": rng.choice([1, 1, 2, None, (3, 4)]), "function": function,
                 "stack": rng.choice([[], ["Caller"], ["Actor::SetHp(int)", "Caller"], None]),
                 "va": rng.choice([None, 0x1000, 0x77]), "ours": rng.random() < .4, "payload": payload}
        if rng.random() < .1:
            event["static"] = {"function": "FromStatic", "stack": ["StaticCaller"]}
            event.pop("function")
            event.pop("stack")
        if rng.random() < .1:
            event.pop("ours")
            event["payload"]["ours"] = True
        if rng.random() < .05:
            event["thread_role"] = "t"
            event.pop("role")
        if weird and rng.random() < .1:
            event["frame"] = rng.choice([1.5, True, (1, 2)])
        events.append(event)
    return events


@unittest.skipUnless(have_native(), "hydralysis_native with the trace port is not built")
class RustMatchesPython(unittest.TestCase):
    def test_generated_pages_really_take_the_native_path(self):
        import hydralysis_native as native
        events = generated(3)
        calls = [("reports_write_survival", (events, "Actor.speed", "Render", PHASES, [{"frame": 3}], 3)),
                 ("reports_observed_edges", (events, {"a": ["b"]}, 5)), ("reports_hook_bypass", (events, "h", "Actor.hp", None, None, 5)),
                 ("reports_field_writers", ([], events, 0x5000, 8, 4, None, "app.escape", ("core.state.write",), 3)),
                 ("reports_edges_from_dispatch", (events, {"Wrapper": {"slot": 1}}, None, (), None))]
        for name, args in calls:
            getattr(native, name)(*args)        # raises TraceFallback if the page were not modelled

    def test_write_survival_agrees_on_generated_pages(self):
        for seed in range(30):
            events = generated(seed)
            gaps = [[{"frame": 3}, {"first_frame": 5, "last_frame": 7}, {"first_frame": 9}, {"other": 1}], None, []][seed % 3]
            for phases in (PHASES, None, ["render", "update"]):
                python, native = both(lambda: tr.write_survival(events, field="Actor.speed", consumer="Render", phases=phases, gaps=gaps,
                                                                 representatives=seed % 4))
                self.assertEqual(text(python), text(native), (seed, phases))

    def test_the_engine_rows_to_survival_chain_agrees(self):
        rows = []
        for event in generated(5):
            payload = dict(event["payload"], frame=event["frame"], phase=event["phase"], role=event.get("role"), ours=event.get("ours", False))
            rows.append({"event_id": event["event_id"], "kind": event["kind"], "seq": event["seq"],
                         "payload": json.dumps(payload) if event["seq"] and event["seq"] % 2 else payload,
                         "process_gen": 1, "thread_gen": event["thread_gen"] if not isinstance(event["thread_gen"], tuple) else 7,
                         "va": event["va"]})
        symbols = {row["seq"]: {"function": "FUN_2000" if row["seq"] % 3 == 0 else "Named", "stack": ["FUN_20", "", "Plain", "FUN_zz"]}
                   for row in rows if row["seq"] is not None}
        names = {"0x2000": "Actor_Update", 32: "Small"}
        python, native = both(lambda: tr.from_engine_rows(rows, names=names, symbols=symbols))
        self.assertEqual(repr(python), repr(native))
        with impl("rust"):
            self.assertIsInstance(native[0]["thread_gen"], tuple)
            events = native
            for call in (lambda: tr.write_survival(events, field="Actor.speed", consumer="Named", phases=PHASES),
                         lambda: tr.hook_bypass(events, hook="Named", field="Actor.hp")):
                python_answer, native_answer = both(call)
                self.assertEqual(text(python_answer), text(native_answer))

    def test_engine_rows_with_bad_payloads_reach_python(self):
        for payload in ("{not json}", "[1, 2]", '{"a": NaN}', '{"rva": "0x10", "frame": 2}', '{"rva": "zz"}', '{"big": 123456789012345678901234567890}'):
            rows = [{"event_id": "e", "kind": "k", "seq": 1, "payload": payload, "thread_gen": 1}]

            def run():
                try:
                    return repr(tr.from_engine_rows(rows))
                except Exception as error:      # noqa: BLE001 - the same exception must come out
                    return type(error).__name__
            python, native = both(run)
            self.assertEqual(python, native, payload)

    def test_edges_and_bypass_agree(self):
        candidates = {"rva:0x500": ["Actor::SetHp(float)", "Actor::SetHp(double)", "Unseen"], "rva:0x600": ["Z", "A"]}
        for seed in range(20):
            events = generated(seed, weird=False)
            python, native = both(lambda: tr.observed_edges(events, static_candidates=candidates, frames_per_edge=seed % 6))
            self.assertEqual(text(python), text(native), seed)
            observed = python["observed"]
            for siblings in (None, ["Actor::SetHp(float)"], []):
                python, native = both(lambda: tr.hook_bypass(events, hook="Actor::SetHp(int)", field="Actor.hp", siblings=siblings,
                                                             observed=observed, per_class=seed % 4))
                self.assertEqual(text(python), text(native), (seed, siblings))
            python, native = both(lambda: tr.hook_bypass(events, hook="x", field="Actor.speed"))
            self.assertEqual(text(python), text(native))

    def test_dispatch_edges_agree(self):
        sites = {"Wrapper": {"slot": 2}, "Other::Thread": {"slot": None}, "FromStatic": {}}
        receivers = {0x40: "Hero", 0x48: "Villain"}
        for seed in range(20):
            events = generated(seed)
            for candidates in (None, {"Wrapper": ["Actor::SetHp(int)", "Render"], "Other::Thread": []}):
                for ignore in ((), ("Render",), ["OurHook", "Caller"]):
                    for callback in (None, lambda address: receivers.get(address)):
                        python, native = both(lambda: tr.edges_from_dispatch(events, sites, receiver_class=callback, ignore=ignore,
                                                                              candidates=candidates))
                        self.assertEqual(text(python), text(native), (seed, candidates, ignore))

    def test_field_writers_agree(self):
        static = [{"function": "0x2000", "site": "0x2010", "instruction": "mov [rcx+8], eax"},
                  {"function": 0x2100, "site": 0x2110}, {"function": "0x2200", "function_name": "Named", "site": "s"},
                  {"function": "zz", "site": "bad"}, {"site": "none"}, {"function": "0x2000", "site": "again"}]
        names = {"0x2000": "Actor_Update", 0x2100: "Actor_Hit", "weird": "Lost"}
        for seed in range(20):
            events = generated(seed)
            for kwargs in ({}, {"per_site": 1}, {"escape_kind": "other", "write_kinds": ("core.state.write", "core.function.enter")}):
                python, native = both(lambda: tr.field_writers(static, events, object_addr=0x5000, offset=8, size=4, names=names, **kwargs))
                self.assertEqual(text(python), text(native), (seed, kwargs))
        python, native = both(lambda: tr.field_writers([], [], object_addr=0x5000, offset=-8, size=4))
        self.assertEqual(text(python), text(native))

    def test_the_discovery_report_agrees(self):
        exercised = [{"key": "a", "kind": "k", "count": 2}, {"key": "b"}, {"key": 3}]
        candidates = [{"key": "b"}, {"key": "c"}, {"key": 3}, {"key": None}, {}]
        gaps = [{"interval": [1, 2], "reason": "observer-inactive"}]
        python, native = both(lambda: tr.discovery_report(exercised=exercised, candidates=candidates, observation_gaps=gaps))
        self.assertEqual(text(python), text(native))

    def test_shapes_the_port_does_not_model_give_the_python_answer(self):
        events = generated(1, weird=True)
        for call in (lambda: tr.write_survival(events, field="Actor.speed", consumer="Render", phases=PHASES),
                     lambda: tr.observed_edges(events), lambda: tr.hook_bypass(events, hook="h", field="Actor.hp")):
            def run():
                try:
                    return text(call())
                except Exception as error:      # noqa: BLE001
                    return type(error).__name__ + str(error)
            python, native = both(run)
            self.assertEqual(python, native)
        # a payload that is not a mapping, a float sequence number, an unhashable frame
        for event in ({"payload": [1]}, {"seq": 1.5, "frame": 1, "payload": {"state_key": "f"}, "kind": "core.state.write"},
                      {"frame": [1], "kind": "core.state.write", "payload": {"state_key": "f"}}):
            def run():
                try:
                    return text(tr.write_survival([event], field="f", consumer="c"))
                except Exception as error:      # noqa: BLE001
                    return type(error).__name__
            python, native = both(run)
            self.assertEqual(python, native, event)


if __name__ == "__main__":
    unittest.main()
