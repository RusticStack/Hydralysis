"""Which views stay open, and which are let go (PROTOCOL-3.md 3.11, 4.10, D43, D61): LRU, `max_views`, idle time, the keep-warm rule,
the atomic pin-or-evict step, the rebuild after an eviction (K8), the capacity answer, and the deletion of idle folders.

The governor is tested on its own with a fake clock and a recording release callback; the runner is tested above it on the fake
daemon of tests/fakehydra.py. Real-engine rows are not here.
"""

from __future__ import annotations

import json
import random
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import durable, hydra, lineage, query, viewgov, views, workcopy
from test_commit import A, B, C
from test_views import AgentWorld


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def view(name):
    return {"key": "key-" + name, "view": name, "name": "owned", "program": "/owned.exe", "sha256": "0" * 64, "gpr": "x"}


class Released(list):
    """A release callback that records what it was asked to close and checks the one rule that matters: not under a request."""

    def __init__(self, test):
        super().__init__()
        self.test = test

    def __call__(self, entry):
        self.test.assertEqual(entry.running, 0, "view %s was closed under a running request" % entry.name)
        self.append(entry.name)


class Limits(unittest.TestCase):
    def test_defaults_and_both_spellings(self):
        self.assertEqual({key: viewgov.limits({})[key] for key in ("max_views", "idle_evict_s", "keep_warm_records", "idle_delete_s")},
                         {"max_views": 24, "idle_evict_s": 600.0, "keep_warm_records": 1000, "idle_delete_s": 86400.0})
        self.assertEqual(viewgov.limits({"maxViews": 3, "viewIdleEvictS": 5, "viewKeepWarmRecords": 7, "viewIdleDeleteS": 9})["max_views"], 3)
        found = viewgov.limits({"max_views": 4, "view_idle_evict_s": 6})
        self.assertEqual((found["max_views"], found["idle_evict_s"]), (4, 6))

    def test_an_invalid_value_falls_back_to_the_default(self):
        found = viewgov.limits({"maxViews": 0, "viewIdleEvictS": "soon", "viewKeepWarmRecords": True, "viewIdleDeleteS": -1})
        self.assertEqual(found, viewgov.DEFAULTS)


class Governor(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.governor = viewgov.Governor(self.clock)
        self.released = Released(self)

    def use(self, name, settings=None, pending=None):
        with self.governor.hold(view(name), settings, self.released, pending) as pin:
            return pin.rebuilt

    def test_the_least_recently_used_idle_view_is_closed_when_a_new_one_would_pass_max_views(self):
        settings = {"maxViews": 2}
        for name in ("a", "b"):
            self.use(name, settings)
            self.clock.advance(1)
        self.use("a", settings)  # a is now more recent than b
        self.clock.advance(1)
        self.use("c", settings)
        self.assertEqual(self.released, ["b"])
        self.assertEqual({row["view"]: row["state"] for row in self.governor.snapshot()}, {"a": "open", "b": "evicted", "c": "open"})

    def test_an_evicted_view_is_rebuilt_once_when_it_is_used_again(self):
        settings = {"maxViews": 1}
        self.use("a", settings)
        self.use("b", settings)
        self.assertEqual(self.released, ["a"])
        self.assertTrue(self.use("a", settings), "the first use after the close says it was rebuilt")
        self.assertFalse(self.use("a", settings), "and says so once")
        self.assertEqual(self.released, ["a", "b"])

    def test_a_view_idle_past_the_limit_is_closed_and_one_that_is_not_idle_enough_is_not(self):
        settings = {"viewIdleEvictS": 600}
        self.use("a", settings)
        self.clock.advance(300)
        self.use("b", settings)
        self.clock.advance(299)
        self.assertEqual(self.governor.sweep(settings, self.released), [])
        self.clock.advance(2)  # a: 601 s idle, b: 301 s
        self.assertEqual(self.governor.sweep(settings, self.released), ["a"])
        self.clock.advance(400)
        self.assertEqual(self.governor.sweep(settings, self.released), ["b"])
        self.assertEqual(self.governor.sweep(settings, self.released), [], "a closed view is not closed twice")

    def test_a_keep_warm_view_is_not_closed_by_idle_time_only_by_pressure(self):
        """D61: a view with at least `viewKeepWarmRecords` pending records costs more to replay than to keep open."""
        settings = {"viewIdleEvictS": 10, "viewKeepWarmRecords": 5, "maxViews": 2}
        self.use("heavy", settings, pending=5)
        self.use("light", settings, pending=4)
        self.clock.advance(11)
        self.assertEqual(self.governor.sweep(settings, self.released), ["light"])
        self.clock.advance(10_000)
        self.assertEqual(self.governor.sweep(settings, self.released), [], "idle time never closes the keep-warm view")
        self.use("other", settings)
        self.use("another", settings)  # past max_views: pressure closes the least recently used, keep-warm or not
        self.assertEqual(self.released, ["light", "heavy"])

    def test_a_view_with_a_running_request_is_never_closed_and_a_full_house_answers_capacity(self):
        settings = {"maxViews": 2, "viewIdleEvictS": 0}
        first = self.governor.pin(view("a"), settings, self.released)
        second = self.governor.pin(view("b"), settings, self.released)
        self.clock.advance(5000)
        self.assertEqual(self.governor.sweep(settings, self.released), [], "idle time does not close a view that is running")
        self.assertFalse(self.governor.evict("key-a", self.released))
        with self.assertRaises(viewgov.Capacity) as raised:
            self.governor.pin(view("c"), settings, self.released)
        self.assertGreater(raised.exception.retry_after_ms, 0)
        self.assertEqual(self.released, [])
        self.assertEqual([row["view"] for row in self.governor.snapshot()], ["a", "b"], "the refused view left no trace")
        self.governor.unpin(first)
        third = self.governor.pin(view("c"), settings, self.released)  # a is idle now: it makes room
        self.assertEqual(self.released, ["a"])
        self.governor.unpin(second)
        self.governor.unpin(third)

    def test_a_failed_close_leaves_the_view_open_and_does_not_fail_the_request(self):
        def broken(entry):
            raise OSError("engine away")
        self.use("a", {"maxViews": 1})
        with self.governor.hold(view("b"), {"maxViews": 1}, broken):
            pass
        states = {row["view"]: row for row in self.governor.snapshot()}
        self.assertEqual(states["a"]["state"], "open")
        self.assertIn("engine away", states["a"]["error"])

    def test_pin_or_evict_is_one_step_so_no_view_is_closed_under_a_request(self):
        """The race of 3.11: eviction tests 'no running request' and marks the view closing in one step, and a request that
        arrives meanwhile waits for the close and then reopens it. 8 threads pin and sweep 400 times; `Released` fails the test
        if a close ever happens while a request holds the view."""
        settings = {"maxViews": 3, "viewIdleEvictS": 0}
        violations, errors = [], []

        def release(entry):
            time.sleep(random.random() * 0.002)  # a close takes time: that is when a new request would slip in
            if entry.running:
                violations.append(entry.name)

        def work(seed):
            rng = random.Random(seed)
            try:
                for _ in range(400):
                    name = "v%d" % rng.randrange(5)
                    try:
                        with self.governor.hold(view(name), settings, release):
                            time.sleep(rng.random() * 0.001)
                            self.governor.snapshot()
                    except viewgov.Capacity:
                        pass
                    if rng.random() < 0.3:
                        self.governor.sweep(settings, release)
            except Exception as error:  # noqa: BLE001
                errors.append(repr(error))

        threads = [threading.Thread(target=work, args=(seed,)) for seed in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(120)
        self.assertEqual(errors, [])
        self.assertEqual(violations, [], "a view was closed while a request held it")
        self.assertTrue(all(row["running"] == 0 for row in self.governor.snapshot()), "a pin leaked")

    def test_the_engine_saying_capacity_closes_the_least_recently_used_idle_view(self):
        self.use("a")
        self.clock.advance(1)
        self.use("b")
        self.assertEqual(self.governor.evict_lru(self.released), "a")
        pin = self.governor.pin(view("b"), None, self.released)
        self.assertIsNone(self.governor.evict_lru(self.released), "b is running: nothing can be closed")
        self.governor.unpin(pin)


class RunnerWorld(AgentWorld):
    def key_of(self, agent):
        return self.target(self.view_of(agent))["key"]

    def release_of(self, agent):
        return self.runner._release(type("E", (), {"target": self.target(self.view_of(agent))})())

    def evict(self, agent):
        return viewgov.GOVERNOR.evict(self.key_of(agent), self.runner._release)


class Eviction(RunnerWorld, unittest.TestCase):
    def test_an_evicted_view_is_rebuilt_from_the_store_and_answers_the_same(self):
        """K8: closing a view loses nothing, because every record is in the store; the next use replays it and says so once."""
        self.rename("agent-1", "One", A)
        self.rename("agent-1", "Two", B)
        before = [self.seen("agent-1", A), self.seen("agent-1", B)]
        folder = workcopy._directory(self.settings, self.target(self.view_of("agent-1")))
        self.assertTrue(self.evict("agent-1"))
        self.assertTrue(folder.is_dir(), "closing a view keeps its folder")
        self.assertEqual(len(self.pending_ids(self.view_of("agent-1"))), 2, "and its records")
        query._keys.clear()
        again = self.ask("agent-1", "decompile", A)
        self.assertEqual(again["function"]["name"], "One")
        self.assertEqual(again["view_rebuilt"]["replayed"], 2)
        self.assertIn("ms", again["view_rebuilt"])
        self.assertEqual([self.seen("agent-1", A), self.seen("agent-1", B)], before)
        self.assertNotIn("view_rebuilt", self.ask("agent-1", "decompile", A), "a rebuild is announced once")
        # an edit after the rebuild lands on the same view
        self.assertEqual(self.rename("agent-1", "Three", C)["revision"], 3)
        self.assertEqual(self.seen("agent-1", C), "Three")

    def test_an_eviction_loses_nothing_the_daemon_held_unsaved(self):
        """The fake daemon drops a closed project's unsaved changes (close with discard), like the real one."""
        self.rename("agent-1", "Gone-from-the-daemon", A)
        self.assertTrue(self.evict("agent-1"))
        state = workcopy._state(self.settings, self.target(self.view_of("agent-1")))
        project = self.daemon.projects[self.daemon._norm(state["fork_gpr"])]
        self.assertTrue(all(program["live"] is None for program in project["programs"].values()), "the daemon kept the changes")
        self.assertEqual(self.seen("agent-1", A), "Gone-from-the-daemon")

    def test_eviction_never_closes_a_view_with_a_running_request(self):
        self.rename("agent-1", "One", A)
        entered, leave = threading.Event(), threading.Event()
        original = query.QueryRunner._ask

        def slow(runner, *args, **kwargs):
            entered.set()
            leave.wait(30)
            return original(runner, *args, **kwargs)

        answers = []
        with patch.object(query.QueryRunner, "_ask", slow):
            thread = threading.Thread(target=lambda: answers.append(self.ask("agent-1", "decompile", A)))
            thread.start()
            self.assertTrue(entered.wait(30))
            self.assertFalse(self.evict("agent-1"), "a view with a running request is not closed")
            with patch.dict(self.runner.settings, {"viewIdleEvictS": 0}):
                self.assertEqual(viewgov.GOVERNOR.sweep(self.runner.settings, self.runner._release), [])
            leave.set()
            thread.join(60)
        self.assertEqual(answers[0]["function"]["name"], "One")
        self.assertNotIn("view_rebuilt", answers[0])
        self.assertTrue(self.evict("agent-1"), "idle again, it can be closed")

    def test_max_views_closes_the_least_recently_used_view_and_every_agent_still_reads_its_own_edit(self):
        self.runner.settings["maxViews"] = 2
        for index, agent in enumerate(("a1", "a2", "a3")):
            self.rename(agent, "Tag" + agent, address(index))
        rows = {row["view"]: row["state"] for row in viewgov.GOVERNOR.snapshot()}
        self.assertEqual(sorted(state for state in rows.values()), ["evicted", "open", "open"])
        self.assertEqual(rows["a1"], "evicted", "the least recently used view went")
        for index, agent in enumerate(("a1", "a2", "a3")):
            self.assertEqual(self.seen(agent, address(index)), "Tag" + agent)
        self.assertEqual(sum(row["state"] == "open" for row in viewgov.GOVERNOR.snapshot()), 2)

    def test_the_idle_sweep_before_a_call_closes_an_idle_view_but_not_a_keep_warm_one(self):
        self.runner.settings.update(viewIdleEvictS=600, viewKeepWarmRecords=2)
        self.rename("light", "L", A)
        self.rename("heavy", "H1", A)
        self.rename("heavy", "H2", B)
        clock = Clock()
        clock.now = time.monotonic() + 1000
        with patch.object(viewgov.GOVERNOR, "clock", clock):
            self.ask("other", "decompile", A)  # any call sweeps first
        rows = {row["view"]: row["state"] for row in viewgov.GOVERNOR.snapshot()}
        self.assertEqual((rows["light"], rows["heavy"]), ("evicted", "open"))
        self.assertEqual((self.seen("light", A), self.seen("heavy", B)), ("L", "H2"))


class Capacity(RunnerWorld, unittest.TestCase):
    def refuse(self, always=False, reason="capacity"):
        """An engine whose first (or every) open of a view's fork says `busy{capacity}`; the master and the base open normally."""
        calls = {"n": 0}
        original = fakehydra.FakeEngine.call

        def call(engine, command, **fields):
            if command == "open_project" and "working" in str(fields.get("path", "")).replace("\\", "/") and (always or not calls["n"]):
                calls["n"] += 1
                raise hydra.EngineError("busy", "the engine is at capacity", {"reason": reason}, command=command, retry_after_ms=1500)
            return original(engine, command, **fields)
        return call

    def test_a_view_the_engine_refuses_for_capacity_is_retried_after_an_idle_one_is_closed(self):
        self.rename("idle", "Idle", A)
        with patch.object(fakehydra.FakeEngine, "call", self.refuse()):
            self.assertEqual(self.rename("new-agent", "New", B)["view"], "new-agent")
        self.assertEqual(viewgov.GOVERNOR.snapshot()[0]["state"], "evicted", "the idle view was closed to make room")
        self.assertEqual((self.seen("idle", A), self.seen("new-agent", B)), ("Idle", "New"))

    def test_when_the_engine_keeps_refusing_the_caller_gets_the_structured_busy_with_a_ready_next_call(self):
        with patch.object(fakehydra.FakeEngine, "call", self.refuse(always=True)), self.assertRaises(RuntimeError) as raised:
            self.rename("first-agent", "Never", A)
        refusal = json.loads(str(raised.exception))
        self.assertEqual((refusal["error"], refusal["reason"], refusal["retryAfterMs"]), ("busy", "capacity", 1500))
        self.assertEqual(refusal["next"]["tool"], "ghidra_query")
        self.assertEqual(refusal["next"]["after_ms"], 1500)
        self.assertEqual(refusal["next"]["arguments"]["options"]["as"], "first-agent")
        self.assertEqual(self.pending_ids(self.view_of("first-agent")), [])

    def test_sealed_and_corrupt_newest_map_to_a_ready_next_call(self):
        for code, tool in (("sealed", "ghidra_query"), ("corrupt_newest", "backend")):
            def raising(engine, command, __code=code, **fields):
                raise hydra.EngineError(__code, "refused", {"reason": __code}, command=command)
            with patch.object(fakehydra.FakeEngine, "call", raising), self.assertRaises(RuntimeError) as raised:
                self.ask("reader", "decompile", A, scope="master")
            payload = json.loads(str(raised.exception))
            self.assertEqual((payload["error"], payload["next"]["tool"]), (code, tool))
        # an error that has no ready answer keeps its form
        def other(engine, command, **fields):
            raise hydra.EngineError("failed", "boom", command=command)
        with patch.object(fakehydra.FakeEngine, "call", other), self.assertRaises(hydra.EngineError):
            self.ask("reader", "decompile", A, scope="master")

    def test_a_full_house_of_running_requests_answers_capacity_without_waiting(self):
        self.runner.settings["maxViews"] = 1
        self.rename("a1", "One", A)
        hold = viewgov.GOVERNOR.pin(self.target(self.view_of("a1")), self.runner.settings, self.runner._release)
        try:
            started = time.monotonic()
            with self.assertRaises(RuntimeError) as raised:
                self.rename("a2", "Two", B)
            self.assertLess(time.monotonic() - started, 10)
            payload = json.loads(str(raised.exception))
            self.assertEqual((payload["error"], payload["reason"]), ("busy", "capacity"))
            self.assertIn("next", payload)
        finally:
            viewgov.GOVERNOR.unpin(hold)
        self.assertEqual(self.pending_ids(self.view_of("a2")), [], "the refused edit left no record")


class IdleFolders(RunnerWorld, unittest.TestCase):
    def test_the_folder_of_a_view_nobody_holds_is_deleted_after_the_idle_time_and_a_later_call_rebuilds_it(self):
        lid = self.rename("gone", "Kept-in-the-store", A)["base"]["lineage"]
        name = self.view_of("gone")
        record = views.read_record(self.settings, lid, name)
        durable.write_sealed(views.record_path(self.settings, lid, name),
                             {**record, "holders": {}, "lease_until": 0, "last_seen": time.time() - 90_000})
        folder = workcopy._directory(self.settings, self.target(name))
        self.assertTrue(folder.is_dir())
        self.assertTrue(self.evict("gone"))
        for project in self.daemon.projects.values():  # the fake lists a project forever; a real engine stops listing a closed one
            project.pop("id", None)
        removed = viewgov.delete_idle_folders(self.settings, self.runner.target("owned"), lid, self.runner.engine)
        self.assertEqual(removed, [name])
        self.assertFalse(folder.exists(), "the fork folder was deleted")
        self.assertEqual(views.read_record(self.settings, lid, name)["state"], "deleted")
        self.assertEqual(len(self.pending_ids(name)), 1, "the store still holds the record")
        self.assertEqual(self.seen("gone", A), "Kept-in-the-store", "and the view is rebuilt from the base and the store")

    def test_a_view_with_a_live_holder_or_a_recent_use_keeps_its_folder(self):
        lid = self.rename("live", "Live", A)["base"]["lineage"]
        self.rename("recent", "Recent", B)
        name = self.view_of("recent")
        record = views.read_record(self.settings, lid, name)
        durable.write_sealed(views.record_path(self.settings, lid, name), {**record, "holders": {}, "lease_until": 0})
        old = time.time() + 90_000  # a clock a day and an hour ahead
        removed = viewgov.delete_idle_folders(self.settings, self.runner.target("owned"), lid, self.runner.engine, now=old - 3000)
        self.assertEqual(removed, [], "the live holder's folder and the recently used folder stay")
        self.assertTrue(workcopy._directory(self.settings, self.target(name)).is_dir())

    def test_nothing_the_deletion_does_touches_a_store_a_generation_or_the_master(self):
        lid = self.rename("gone", "X", A)["base"]["lineage"]
        name = self.view_of("gone")
        record = views.read_record(self.settings, lid, name)
        durable.write_sealed(views.record_path(self.settings, lid, name), {**record, "holders": {}, "lease_until": 0, "last_seen": 1})
        self.evict("gone")
        store = workcopy._store_path(self.settings, self.target(name))
        before = store.read_bytes()
        viewgov.delete_idle_folders(self.settings, self.runner.target("owned"), lid, self.runner.engine)
        self.assertEqual(store.read_bytes(), before)
        self.assertEqual(lineage.tree_hash(self.gpr.parent), self.master_tree)
        self.assertEqual([row["gen"] for row in self.rows()], [0])


def address(index: int) -> str:
    return hex(0x140010000 + index * 0x100)


if __name__ == "__main__":
    unittest.main()
