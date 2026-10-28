"""Runtime snapshots and their comparison with volatile masks and closed-grammar predicates (Z10).

Runs on the fake frida binding (tests/fakefrida): the worker code is real, the process and Frida are not. The
real-process side is tests/fixtures/verify_fixtures.py `snapshot` (MSVC and the pinned Frida; not CI).
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fakefrida.harness import attached_agent
from hydralysis import durable, runtime
from hydralysis import runtime_capture as capture
from hydralysis import runtime_snapshot as snap
from support import workdir

SESSION, OTHER = "d" * 32, "e" * 32


def sample(**changes):
    record = {"version": 1, "name": "s", "session": SESSION, "taken_at_ms": 1000, "sequence": 7, "log_head": "ab" * 32,
              "target": {"pid": 11, "created_ms": 5, "exe": "C:/g/game.exe", "exe_sha256": "cd" * 32, "arch": "x64", "pointer_size": 8},
              "modules": [{"name": "game.exe", "path": "C:/g/game.exe", "base": "0x140000000", "size": 4096, "file_sha256": "cd" * 32},
                          {"name": "Kernel32.dll", "path": "C:/w/k.dll", "base": "0x7ff000000000", "size": 8192}],
              "threads": {"count": 3},
              "regions": [{"name": "config", "ok": True, "address": "0x2000", "size": 12, "sha256": "ef" * 32, "bytes": "02000000",
                           "range": {"base": "0x2000", "protection": "rw-"},
                           "fields": [{"name": "mode", "offset": "0x0", "type": "int32", "value": 2},
                                      {"name": "limit", "offset": "0x4", "type": "int32", "value": 40}]}],
              "hooks": [{"hook_id": "h1", "kind": "observe", "module": "game.exe", "rva": "0x1000", "export": None}],
              "counters": {"messages": 4}}
    record.update(changes)
    record["snapshot"] = snap.snapshot_id(record)
    return record


class Flattening(unittest.TestCase):
    def test_rows_are_keyed_by_name_not_by_position(self):
        a = sample()
        b = sample(modules=list(reversed(a["modules"])))
        self.assertEqual(snap.flatten(a)["modules/game.exe/size"], 4096)
        self.assertEqual(snap.flatten(a)["modules/kernel32.dll/size"], 8192)
        self.assertTrue(snap.compare(a, b)["equal"])
        self.assertEqual(snap.flatten(a)["regions/config/fields/limit/value"], 40)
        self.assertEqual(snap.flatten(a)["hooks/game.exe:0x1000:observe/rva"], "0x1000")

    def test_the_id_commits_the_content(self):
        record = sample()
        self.assertRegex(record["snapshot"], r"^snap_[0-9a-f]{64}$")
        changed = copy.deepcopy(record)
        changed["threads"]["count"] = 4
        self.assertNotEqual(snap.snapshot_id(changed), record["snapshot"])

    def test_two_runs_that_differ_only_in_volatile_fields_have_one_stable_hash(self):
        a = sample()
        b = sample(session=OTHER, taken_at_ms=99, sequence=1234, log_head="00" * 32, counters={"messages": 400})
        b["target"] = {**b["target"], "pid": 999, "created_ms": 77}
        b["modules"] = [{**m, "base": "0x1" + m["base"][3:]} for m in b["modules"]]
        b["regions"][0]["address"] = "0x9999"
        b["hooks"][0]["hook_id"] = "zz"
        self.assertNotEqual(a["snapshot"], snap.snapshot_id(b))
        self.assertEqual(snap.stable_sha256(a), snap.stable_sha256(b))
        self.assertTrue(snap.compare(a, b)["equal"])


class Comparing(unittest.TestCase):
    def pair(self):
        b = sample(taken_at_ms=2000)
        b["regions"] = copy.deepcopy(b["regions"])
        b["regions"][0]["fields"][1]["value"] = 41
        b["regions"][0]["bytes"] = "02000000"[:-2] + "ff"
        return sample(), b

    def test_a_changed_value_is_reported_with_both_sides(self):
        a, b = self.pair()
        result = snap.compare(a, b)
        self.assertFalse(result["equal"])
        self.assertFalse(result["ok"])
        paths = {row["path"]: row for row in result["differences"]}
        self.assertEqual((paths["regions/config/fields/limit/value"]["a"], paths["regions/config/fields/limit/value"]["b"]), (40, 41))
        self.assertIn("regions/config/bytes", paths)
        self.assertGreater(result["masked_differences"], 0)       # taken_at_ms differs and the default mask hid it

    def test_a_mask_hides_a_difference_and_says_how_many(self):
        a, b = self.pair()
        plain = snap.compare(a, b)
        masked = snap.compare(a, b, mask=["regions/config/fields/limit/*", "regions/config/bytes"])
        self.assertTrue(masked["equal"])
        self.assertEqual(masked["masked_differences"], plain["masked_differences"] + 2)
        self.assertIn("regions/config/bytes", masked["mask"])

    def test_the_default_masks_can_be_turned_off(self):
        a, b = self.pair()
        result = snap.compare(a, b, mask=["regions/*"], use_default_mask=False)
        self.assertIn("taken_at_ms", {row["path"] for row in result["differences"]})

    def test_a_row_in_only_one_snapshot_is_a_difference(self):
        a, b = sample(), sample()
        b["regions"] = []
        result = snap.compare(a, b)
        self.assertFalse(result["equal"])
        self.assertTrue(result["only_in_a"])
        self.assertEqual(result["only_in_b"], [])

    def test_predicates_use_a_closed_grammar_and_decide_ok(self):
        a, b = self.pair()
        path = "regions/config/fields/limit/value"
        checks = [{"path": path, "op": "changed"}, {"path": path, "op": "increased"}, {"path": path, "op": "eq", "value": 41},
                  {"path": path, "op": "between", "value": [0, 100]}, {"path": path, "op": "ge", "value": 41},
                  {"path": "regions/config/fields/mode/value", "op": "unchanged"}, {"path": "nothing/here", "op": "absent"},
                  {"path": path, "op": "present"}]
        result = snap.compare(a, b, predicates=checks)
        self.assertTrue(result["ok"], result["predicates"])
        self.assertFalse(result["equal"])                 # ok and equal are different questions
        failing = snap.compare(a, b, predicates=[{"path": path, "op": "lt", "value": 41}, {"path": path, "op": "unchanged"}])
        self.assertFalse(failing["ok"])
        self.assertEqual([row["ok"] for row in failing["predicates"]], [False, False])
        missing = snap.compare(a, b, predicates=[{"path": "nope", "op": "changed"}])
        self.assertFalse(missing["ok"])
        self.assertIn("not in both", missing["predicates"][0]["reason"])
        text = snap.compare(a, b, predicates=[{"path": "regions/config/bytes", "op": "increased"}])
        self.assertEqual(text["predicates"][0]["reason"], "not numbers")

    def test_anything_outside_the_grammar_is_refused_not_evaluated(self):
        a, b = sample(), sample()
        for predicate, message in (({"path": "x", "op": "exec"}, "op must be one of"), ({"path": "x", "op": "eq"}, "scalar value"),
                                   ({"path": "x", "op": "eq", "value": [1]}, "scalar value"),
                                   ({"path": "x", "op": "lt", "value": "a"}, "needs a number"),
                                   ({"path": "x", "op": "between", "value": [3, 1]}, "low, high"),
                                   ({"path": "x", "op": "changed", "value": 1}, "takes no value"),
                                   ({"path": "x", "op": "eq", "value": 1, "code": "1+1"}, "and nothing else"),
                                   ({"op": "eq", "value": 1}, "snapshot path"), ("x", "and nothing else")):
            with self.subTest(predicate=predicate), self.assertRaisesRegex(ValueError, message):
                snap.compare(a, b, predicates=[predicate])
        for mask in (["a" * 201], ["bad[pattern]"], [3], "all", ["x"] * 65):
            with self.subTest(mask=mask), self.assertRaisesRegex(ValueError, "mask is a list"):
                snap.compare(a, b, mask=mask)

    def test_long_values_are_shown_clipped_with_their_hash(self):
        a, b = sample(), sample()
        a["regions"][0]["bytes"] = "00" * 400
        result = snap.compare(a, b)
        shown = next(row["a"] for row in result["differences"] if row["path"] == "regions/config/bytes")
        self.assertIn("800 chars, sha256", shown)
        self.assertLess(len(shown), 200)


class Taking(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("snapshot")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "runtime-sessions" / SESSION
        self.agent, self.exe, self.digest, self.head = attached_agent(self.directory)
        self.addCleanup(self.close)
        self.name = Path(self.exe).name

    def close(self):
        if not self.agent.closed:
            try:
                self.agent.cleanup()
            except Exception:
                self.agent.log.close()

    def take(self, **options):
        return self.agent.handle("snapshot", options)

    def region(self, name="head", **extra):
        return {"name": name, "module": self.name, "rva": "0x0", "size": 16, **extra}

    def test_a_snapshot_records_modules_regions_and_counters_and_is_stored_by_its_id(self):
        record = self.take(name="first", regions=[self.region()])
        self.assertRegex(record["snapshot"], r"^snap_[0-9a-f]{64}$")
        main = record["modules"][0]
        self.assertEqual((main["name"], main["file_sha256"]), (self.name, self.digest))
        self.assertTrue(record["modules_complete"] and record["regions_complete"])
        region = record["regions"][0]
        self.assertEqual(region["bytes"][:4], "4d5a")                      # the module's own file, MZ
        self.assertEqual(region["sha256"], hashlib.sha256(bytes.fromhex(region["bytes"])).hexdigest())
        self.assertEqual(record["target"]["exe_sha256"], self.digest)
        self.assertEqual(record["threads"], {"count": 1})
        stored = capture.load_snapshot(self.directory, record["snapshot"])
        self.assertEqual(snap.snapshot_id(stored), record["snapshot"])
        self.assertEqual(capture.list_snapshots(self.directory)["snapshots"][0]["snapshot"], record["snapshot"])

    def test_two_snapshots_of_an_unchanged_target_compare_equal_whatever_happened_between(self):
        first = self.take(regions=[self.region()])
        self.agent.message("x", {"type": "log", "payload": "noise"})            # moves sequence, counters and the log head
        second = self.take(regions=[self.region()])
        self.assertNotEqual(first["snapshot"], second["snapshot"])
        self.assertEqual(first["stable_sha256"], second["stable_sha256"])
        result = capture.compare_snapshots(self.root / "runtime-sessions", SESSION, {"a": first["snapshot"], "b": second["snapshot"]})
        self.assertTrue(result["equal"], result["differences"])
        self.assertGreater(result["masked_differences"], 0)

    def test_a_live_change_shows_as_a_difference_a_predicate_can_check(self):
        first = self.take(regions=[self.region()])
        with patch.dict(os.environ, {"HYDRALYSIS_FAKE_PATCH": "0x2=FF"}):
            second = self.take(regions=[self.region()])
        sessions = self.root / "runtime-sessions"
        result = capture.compare_snapshots(sessions, SESSION, {"a": first["snapshot"], "b": second["snapshot"],
                                                               "predicates": [{"path": "regions/head/sha256", "op": "changed"},
                                                                              {"path": "modules/%s/size" % self.name.lower(), "op": "unchanged"}]})
        self.assertFalse(result["equal"])
        self.assertTrue(result["ok"], result["predicates"])
        self.assertEqual([row["path"] for row in result["differences"]], ["regions/head/bytes", "regions/head/sha256"])
        hidden = capture.compare_snapshots(sessions, SESSION, {"a": first["snapshot"], "b": second["snapshot"],
                                                               "mask": ["regions/head/*"]})
        self.assertTrue(hidden["equal"])
        self.assertEqual(hidden["masked_differences"], result["masked_differences"] + 2)

    def test_a_typed_region_carries_its_field_values_and_the_view_it_came_from(self):
        layout = [{"name": "magic", "offset": 0, "type": "u16"}, {"name": "next", "offset": 2, "type": "u16"}]
        source = {"target": "fixture", "view": "shared", "revision": 7}
        record = self.take(regions=[self.region(layout=layout, type_name="/Header", layout_source=source)])
        region = record["regions"][0]
        self.assertEqual([f["name"] for f in region["fields"]], ["magic", "next"])
        self.assertEqual(region["fields"][0]["value"], 0x5A4D)
        self.assertEqual(region["layout_source"], source)
        result = snap.compare(record, record, predicates=[{"path": "regions/head/fields/magic/value", "op": "eq", "value": 0x5A4D}])
        self.assertTrue(result["ok"])

    def test_an_unreadable_region_is_recorded_not_hidden(self):
        record = self.take(regions=[self.region("head"), {"name": "far", "module": self.name, "rva": "0x7fffffff", "size": 8}])
        self.assertFalse(record["regions_complete"])
        far = record["regions"][1]
        self.assertFalse(far["ok"])
        self.assertIn("ValueError", far["error"])

    def test_bytes_can_be_left_out_and_only_hashed(self):
        record = self.take(regions=[self.region()], keep_bytes=False)
        self.assertNotIn("bytes", record["regions"][0])
        self.assertEqual(len(record["regions"][0]["sha256"]), 64)

    def test_options_are_checked(self):
        for options, message in (({"colour": 1}, "unknown snapshot options"), ({"name": "a b"}, "name is"),
                                 ({"regions": [self.region("a"), self.region("a")]}, "used twice"),
                                 ({"regions": [{"module": self.name, "rva": "0x0"}]}, "needs a name"),
                                 ({"regions": [self.region(size=5000)]}, "1..4096"),
                                 ({"regions": [{**self.region(), "colour": 1}]}, "unknown region fields"),
                                 ({"regions": [self.region(str(i)) for i in range(33)]}, "at most 32"),
                                 ({"op": "delete"}, "snapshot op"), ({"hash_modules": "x"}, "list of module names"),
                                 ({"modules_limit": 0}, "1..200")):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, message):
                self.take(**options)

    def test_other_modules_are_hashed_only_when_asked(self):
        record = self.take(hash_modules=[self.name])
        self.assertEqual([m for m in record["modules"] if "file_sha256" in m][0]["name"], self.name)
        self.assertEqual(len([m for m in record["modules"] if "file_sha256" in m]), 1)

    def test_a_snapshot_file_that_was_edited_is_refused(self):
        record = self.take()
        path = self.directory / capture.SNAPSHOTS / (record["snapshot"] + ".json")
        edited = json.loads(path.read_text())
        edited.pop("seal")
        edited["threads"] = {"count": 99}
        durable.write_sealed(path, edited, indent=None)              # a careful editor re-seals it
        with self.assertRaisesRegex(ValueError, "does not match its own id"):
            capture.load_snapshot(self.directory, record["snapshot"])
        with self.assertRaisesRegex(ValueError, "id, snap_ and 64 hex"):
            capture.load_snapshot(self.directory, "../x")
        with self.assertRaisesRegex(ValueError, "no snapshot"):
            capture.load_snapshot(self.directory, "snap_" + "0" * 64)

    def test_snapshots_of_two_sessions_compare_and_survive_the_worker(self):
        first = self.take(regions=[self.region()])
        other_dir = self.root / "runtime-sessions" / OTHER
        other, *_ = attached_agent(other_dir)
        self.addCleanup(lambda: other.cleanup() if not other.closed else None)
        second = other.handle("snapshot", {"regions": [self.region()]})
        other.cleanup()
        self.agent.cleanup()
        runner = runtime.RuntimeRunner({"root": str(self.root)})
        result = runner.call("compare", {"session": SESSION, "other_session": OTHER, "a": first["snapshot"], "b": second["snapshot"]})
        self.assertTrue(result["equal"], result["differences"])
        with self.assertRaisesRegex(ValueError, "unknown compare options"):
            runner.call("compare", {"session": SESSION, "a": first["snapshot"], "b": first["snapshot"], "colour": 1})
        with self.assertRaisesRegex(ValueError, "other_session"):
            runner.call("compare", {"session": SESSION, "other_session": "x", "a": first["snapshot"], "b": first["snapshot"]})
        self.assertEqual(runner.call("snapshot", {"session": SESSION, "op": "list"})["snapshots"][0]["snapshot"], first["snapshot"])


class TypedReadRevision(unittest.TestCase):
    """A typed read names the view and revision its layout came from (C2-21)."""

    def setUp(self):
        self.temp = workdir("rev")
        self.addCleanup(self.temp.cleanup)
        self.runner = runtime.RuntimeRunner({"root": self.temp.name})

    def answer(self):
        return json.dumps({"type": {"path": "/Config", "length": 4, "fields": [{"field": "mode", "offset": 0, "name": "int", "length": 4}]}})

    def test_the_layout_carries_the_views_revision(self):
        query = Mock()
        query.query.return_value = self.answer()
        query.target.return_value = {"name": "fixture", "key": "k", "sha256": "0" * 64}
        args = {"type": "/Config", "target": "fixture", "view": "experiment"}
        with patch("hydralysis.query.QueryRunner", return_value=query), patch("hydralysis.backends.resolved", return_value={}),              patch("hydralysis.workcopy.load_store", return_value={"revision": 7}) as store:
            layout = self.runner._layout(args)
        self.assertEqual(layout["layout_source"], {"target": "fixture", "view": "experiment", "revision": 7})
        self.assertEqual(store.call_args.args[1]["view"], "experiment")

    def test_a_revision_that_could_not_be_read_is_said_not_dropped(self):
        query = Mock()
        query.query.return_value = self.answer()
        query.target.side_effect = ValueError("no such target")
        with patch("hydralysis.query.QueryRunner", return_value=query), patch("hydralysis.backends.resolved", return_value={}):
            layout = self.runner._layout({"type": "/Config", "target": "fixture"})
        source = layout["layout_source"]
        self.assertIsNone(source["revision"])
        self.assertIn("no such target", source["revision_error"])
        self.assertEqual(source["view"], "shared")

    def test_the_worker_hands_the_source_back_with_the_read(self):
        agent, exe, digest, head = attached_agent(Path(self.temp.name) / SESSION)
        try:
            source = {"target": "fixture", "view": "shared", "revision": 3}
            result = agent.handle("read", {"module": Path(exe).name, "rva": "0x0", "size": 4, "layout_source": source,
                                           "layout": [{"name": "magic", "offset": 0, "type": "u16"}], "type_name": "/H"})
        finally:
            agent.cleanup()
        self.assertEqual(result["layout_source"], source)
        self.assertEqual(result["fields"][0]["value"], 0x5A4D)

    def test_snapshot_regions_may_name_a_type(self):
        with patch.object(self.runner, "_layout", return_value={"layout": [{"name": "m", "offset": 0, "type": "u16"}], "size": 4,
                                                                "type_name": "/H", "layout_source": {"revision": 2}}) as layout:
            args = self.runner._snapshot_layouts({"regions": [{"name": "a", "type": "/H", "target": "t", "address": "0x10"}]})
        row = args["regions"][0]
        self.assertEqual((row["type_name"], row["size"], row["layout_source"]), ("/H", 4, {"revision": 2}))
        self.assertEqual(row["layout"][0]["name"], "m")
        self.assertEqual(layout.call_count, 1)


if __name__ == "__main__":
    unittest.main()
