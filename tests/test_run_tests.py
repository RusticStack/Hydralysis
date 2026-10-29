"""The parallel runner: how it plans tasks, when it trusts a task process, and that it only deletes its own directory."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import run_tests  # noqa: E402


def ids(cls, n):
    return ["test_mod.%s.test_%02d" % (cls, i) for i in range(n)]


class Plan(unittest.TestCase):
    def test_a_cheap_class_is_one_task_that_names_the_class(self):
        tasks = run_tests.plan(ids("Small", 5), {})
        self.assertEqual([(t["name"], t["args"], t["ids"]) for t in tasks], [("test_mod.Small", ["test_mod.Small"], ids("Small", 5))])

    def test_a_class_over_the_limit_gets_a_task_per_slow_test_and_chunks_for_the_rest(self):
        members = ids("Big", 100)
        timings = {members[3]: 200.0, members[7]: 100.0}
        tasks = run_tests.plan(members, timings)
        self.assertEqual([t["args"] for t in tasks[:2]], [[members[3]], [members[7]]])
        rest = [a for t in tasks[2:] for a in t["args"]]
        self.assertEqual(sorted(rest), sorted(set(members) - {members[3], members[7]}))
        self.assertTrue(all(len(t["args"]) <= run_tests.CHUNK for t in tasks))
        self.assertEqual(sorted(i for t in tasks for i in t["ids"]), sorted(members))

    def test_the_longest_task_starts_first_and_every_test_is_planned_once(self):
        members = ids("A", 3) + ids("B", 3)
        tasks = run_tests.plan(members, {members[4]: 30.0})
        self.assertEqual(tasks[0]["name"], "test_mod.B")
        self.assertEqual(sorted(i for t in tasks for i in t["ids"]), sorted(members))

    def test_a_selection_names_its_tests_never_the_whole_class(self):
        members = ids("Small", 5)[:2]
        tasks = run_tests.plan(members, {}, whole_classes=False)
        self.assertEqual([(t["args"], t["ids"]) for t in tasks], [(members, members)])

    def test_an_import_failure_stays_a_task_named_after_its_module(self):
        tasks = run_tests.plan(["test_broken"], {})
        self.assertEqual(tasks[0]["args"], ["test_broken"])
        self.assertEqual(run_tests.test_id("unittest.loader._FailedTest.test_broken"), "test_broken")


class Judge(unittest.TestCase):
    task = {"name": "t", "args": ["t"], "ids": ["m.C.a", "m.C.b"], "cost": 1.0}

    def test_a_clean_task_is_ok(self):
        v = run_tests.judge(self.task, 0, "..\n\nRan 2 tests in 0.1s\n\nOK\n")
        self.assertEqual((v["ok"], v["ran"], v["failed"], v["problem"]), (True, 2, [], ""))

    def test_a_failure_names_the_failed_test(self):
        text = "FAIL: a (m.C.a)\n----\nRan 2 tests in 0.1s\n\nFAILED (failures=1)\n"
        v = run_tests.judge(self.task, 1, text)
        self.assertEqual((v["ok"], v["failed"], v["problem"]), (False, ["m.C.a"], ""))

    def test_an_import_failure_is_named_by_its_module(self):
        text = "ERROR: broken (unittest.loader._FailedTest.broken)\nRan 1 test in 0.0s\nFAILED (errors=1)\n"
        self.assertEqual(run_tests.judge(self.task, 1, text)["failed"], ["broken"])

    def test_a_process_that_exits_0_without_a_summary_is_not_a_pass(self):
        v = run_tests.judge(self.task, 0, "")
        self.assertFalse(v["ok"])
        self.assertIn("Ran N tests", v["problem"])

    def test_a_task_that_ran_fewer_tests_than_planned_is_not_a_pass(self):
        v = run_tests.judge(self.task, 0, "Ran 1 test in 0.1s\n\nOK\n")
        self.assertFalse(v["ok"])
        self.assertIn("1 tests, 2 were planned", v["problem"])

    def test_a_nonzero_exit_without_a_failure_header_and_a_timeout_are_problems(self):
        self.assertIn("exited 3", run_tests.judge(self.task, 3, "Traceback\n")["problem"])
        self.assertEqual(run_tests.judge(self.task, None, "partial")["problem"], "timed out")


class Root(unittest.TestCase):
    def test_the_runner_deletes_only_its_own_work_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            keep = Path(parent) / "precious.txt"
            keep.write_text("keep", encoding="utf-8")
            done = subprocess.run([sys.executable, str(TOOLS / "run_tests.py"), "--root", parent, "-j", "2",
                                   "-k", "test_run_tests.Judge.test_a_clean_task_is_ok"], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertIn("Ran 1 of 1 tests", done.stdout)
            self.assertEqual([p.name for p in Path(parent).iterdir()], ["precious.txt"])


if __name__ == "__main__":
    unittest.main()
