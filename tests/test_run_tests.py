"""The parallel runner's planning: a class is one task, a slow class is split, and the long tasks go first."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import run_tests  # noqa: E402


def ids(cls, n):
    return ["test_mod.%s.test_%02d" % (cls, i) for i in range(n)]


class Plan(unittest.TestCase):
    def test_a_cheap_class_is_one_task_that_names_the_class(self):
        tasks = run_tests.plan(ids("Small", 5), {})
        self.assertEqual([(t["name"], t["args"]) for t in tasks], [("test_mod.Small", ["test_mod.Small"])])

    def test_a_class_over_the_limit_gets_a_task_per_slow_test_and_chunks_for_the_rest(self):
        members = ids("Big", 100)
        timings = {members[3]: 200.0, members[7]: 100.0}
        tasks = run_tests.plan(members, timings)
        self.assertEqual([t["args"] for t in tasks[:2]], [[members[3]], [members[7]]])
        rest = [a for t in tasks[2:] for a in t["args"]]
        self.assertEqual(sorted(rest), sorted(set(members) - {members[3], members[7]}))
        self.assertTrue(all(len(t["args"]) <= run_tests.CHUNK for t in tasks))

    def test_the_longest_task_starts_first_and_every_test_is_planned_once(self):
        members = ids("A", 3) + ids("B", 3)
        tasks = run_tests.plan(members, {members[4]: 30.0})
        self.assertEqual(tasks[0]["name"], "test_mod.B")
        self.assertEqual(sorted(a for t in tasks for a in t["args"]), ["test_mod.A", "test_mod.B"])

    def test_an_import_failure_stays_a_task_named_after_its_module(self):
        tasks = run_tests.plan(["test_broken"], {})
        self.assertEqual(tasks[0]["args"], ["test_broken"])


if __name__ == "__main__":
    unittest.main()
