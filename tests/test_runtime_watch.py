"""Runtime watchpoints (Z12): the state machine to verified-clear, the tainted session, the conformance stamp, and the
x86/x64 teardown matrix with a debug-register readback, on an in-memory target (tests/fakememory.py).

The real-process matrix (debug registers read back from a live fixture, the 100-iteration race loop, exit code 0 and
never 0x80000004) is tools/watch_conformance.py; the unit tests below cannot prove it, only that the worker asks for it.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from fakefrida.harness import attached_agent
from fakememory import CODE, DATA, Target, wire
from hydralysis import runtime_memory as memory
from hydralysis.runtime_events import LOG_NAME, iter_records, verify_log
from support import workdir

SESSION = "b" * 32
ARCHES = ("x64", "x86")


class Case(unittest.TestCase):
    arch = "x64"

    def setUp(self):
        self.temp = workdir("zwatch")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "runtime-sessions" / SESSION
        self.agent, *_ = attached_agent(self.directory)
        self.addCleanup(lambda: None if self.agent.closed else self.agent.log.close())
        self.target = Target(self.arch)
        self.script = wire(self.agent, self.target)
        marked = patch("hydralysis.runtime_memory.fixture_marked", return_value=True)
        marked.start()
        self.addCleanup(marked.stop)

    def stamp(self, **changes):
        return {"version": 1, "result": "pass", "arch": self.arch, "fixture_sha256": self.agent.target_sha256,
                "frida": "17.24.3", "iterations": 100, **changes}

    def gate(self, stamp=True, **changes):
        return {"fixture_sha256": self.agent.target_sha256, "frida": "17.24.3",
                "stamps": {self.arch: self.stamp()} if stamp is True else ({self.arch: stamp} if stamp else {}), **changes}

    def watch(self, op="arm", gate=None, **options):
        args = {"_gate": gate or self.gate(), "op": op, **options}
        if op == "arm":
            args = {"address": hex(DATA), "size": 4, "reason": "watch the fixture limit", **args}
        return self.agent.handle("watch", args)

    def arm(self, **options):
        return self.watch(**options)["watch"]

    def detach(self, **options):
        return self.agent.handle("detach", options)


class Stamp(Case):
    def test_a_watch_needs_a_passing_stamp_for_this_arch_build_and_frida(self):
        bad = [False, self.stamp(result="fail"), self.stamp(arch="x86" if self.arch == "x64" else "x64"),
               self.stamp(fixture_sha256="0" * 64), self.stamp(frida="1.0.0"), self.stamp(iterations=99)]
        for stamp in bad:
            with self.assertRaises(PermissionError, msg=str(stamp)) as raised:
                self.watch(gate=self.gate(stamp=stamp))
            self.assertIn("conformance stamp", str(raised.exception))
        self.assertEqual(self.agent.watches, {})
        self.assertEqual(self.script.calls, [])

    def test_the_gate_applies_to_a_watch_as_to_a_write(self):
        with self.assertRaises(PermissionError):
            self.agent.handle("watch", {"op": "list"})
        with self.assertRaises(PermissionError):
            self.watch(gate={"fixture_sha256": "", "stamps": {}})


class StateMachine(Case):
    def test_arm_then_disarm_ends_verified_clear(self):
        watch = self.arm()
        self.assertEqual(watch["state"], "armed")
        self.assertEqual(watch["threads"], [1, 2, 3])
        self.assertTrue(all(watch["slot"] in s for s in self.target.slots.values()))
        done = self.watch("disarm", watch=watch["id"])
        self.assertEqual(done["state"], "clear")
        self.assertEqual(done["watch"]["verified"]["still_enabled"], [])
        self.assertEqual(done["watch"]["verified"]["threads_read"], 3)
        self.assertTrue(all(not s for s in self.target.slots.values()))
        self.assertEqual(self.agent.tainted, "")

    def test_only_the_listed_edges_exist(self):
        watch = {"id": "w", "state": "armed"}
        with self.assertRaises(RuntimeError):
            self.agent._move(watch, "clear")      # armed cannot jump to clear: only a readback gets there
        self.agent._move(watch, "disarming")
        self.agent._move(watch, "tainted")
        with self.assertRaises(RuntimeError):
            self.agent._move(watch, "clear")      # a tainted watch must be retried through disarming
        self.agent._move(watch, "disarming")
        self.agent._move(watch, "clear")
        with self.assertRaises(RuntimeError):
            self.agent._move(watch, "armed")

    def test_the_log_and_the_state_file_record_each_step(self):
        watch = self.arm()
        self.watch("disarm", watch=watch["id"])
        self.agent.log.sync()
        self.assertTrue(verify_log(self.directory, SESSION)["ok"])
        kinds = [record["type"] for record, _ in iter_records(self.directory / LOG_NAME)]
        self.assertEqual([k for k in kinds if k.startswith("watch")], ["watch_armed", "watch_clear"])
        saved = json.loads((self.directory / "memory.json").read_text())
        self.assertEqual(saved["watches"][watch["id"]]["state"], "clear")
        self.assertEqual(saved["tainted"], "")

    def test_slots_are_four_and_a_cleared_slot_is_reused(self):
        armed = [self.arm(address=hex(DATA + 8 * i)) for i in range(4)]
        self.assertEqual(sorted(w["slot"] for w in armed), [0, 1, 2, 3])
        with self.assertRaises(ValueError) as raised:
            self.watch(address=hex(DATA + 0x40))
        self.assertIn("slots", str(raised.exception))
        self.watch("disarm", watch=armed[2]["id"])
        self.assertEqual(self.arm(address=hex(DATA + 0x40))["slot"], armed[2]["slot"])

    def test_arguments_are_checked(self):
        for options in ({"size": 3}, {"access": "exec"}, {"limit": 0}, {"address": hex(DATA + 2), "size": 4},
                        {"address": hex(CODE)}, {"reason": "x"}):
            with self.assertRaises(ValueError, msg=str(options)):
                self.watch(**options)
        self.assertEqual(self.agent.watches, {})

    def test_list_reports_counters_and_hits(self):
        watch = self.arm()
        self.script.watches[watch["id"]]["seen"] = 7
        self.agent._memory_message({"type": "send", "payload": {"event": "watch_hit", "watch": watch["id"]}})
        listed = self.watch("list")
        self.assertEqual(listed["watches"][0]["seen"], 7)
        self.assertEqual(listed["watches"][0]["hits"], 1)
        self.assertEqual(self.agent.snapshot()["watches"][watch["id"]]["hits"], 1)

    def test_rearm_covers_a_thread_born_after_the_watch(self):
        watch = self.arm()
        self.target.slots[9] = set()
        result = self.watch("rearm", watch=watch["id"])
        self.assertEqual(result["added"], [9])
        self.assertIn(9, result["watch"]["threads"])
        self.assertIn("arm time", watch["coverage"])


class Tainted(Case):
    def taint(self):
        watch = self.arm()
        self.target.fail_unset = {2}
        answer = self.watch("disarm", watch=watch["id"])
        return watch, answer

    def test_a_failed_unset_taints_the_session(self):
        watch, answer = self.taint()
        self.assertEqual(answer["state"], "tainted")
        self.assertIn("thread(s) [2]", answer["error"])
        self.assertTrue(self.agent.tainted)
        self.assertEqual(self.agent.snapshot()["tainted"], self.agent.tainted)

    def test_a_register_restored_by_a_thread_leaving_the_handler_is_cleared_by_a_retry(self):
        watch = self.arm()
        self.target.reenable_after_unset = 2
        answer = self.watch("disarm", watch=watch["id"])
        self.assertEqual(answer["state"], "clear")
        self.assertEqual(answer["watch"]["verified"]["attempts"], 3)
        self.assertTrue(all(not s for s in self.target.slots.values()))

    def test_a_register_that_keeps_coming_back_taints_after_the_attempts(self):
        watch = self.arm()
        self.target.reenable_after_unset = 99
        answer = self.watch("disarm", watch=watch["id"])
        self.assertEqual(answer["state"], "tainted")
        self.assertEqual(answer["watch"]["verified"]["attempts"], memory.DISARM_ATTEMPTS)

    def test_a_readback_that_cannot_be_read_is_not_clear(self):
        watch = self.arm()
        self.target.readback_unavailable = True
        self.assertEqual(self.watch("disarm", watch=watch["id"])["state"], "tainted")

    def test_an_unreadable_thread_is_not_clear(self):
        watch = self.arm()
        self.target.unreadable = [2]
        answer = self.watch("disarm", watch=watch["id"])
        self.assertEqual(answer["state"], "tainted")
        self.assertEqual(answer["watch"]["verified"]["unreadable"], [2])

    def test_a_thread_born_during_the_disarm_is_cleared_by_the_retry(self):
        watch = self.arm()
        self.target.new_thread_on_disarm = 1
        answer = self.watch("disarm", watch=watch["id"])
        self.assertEqual(answer["state"], "clear")
        self.assertEqual(answer["watch"]["verified"]["attempts"], 2)

    def test_a_tainted_session_takes_no_new_watch_and_refuses_to_detach(self):
        self.taint()
        with self.assertRaises(RuntimeError) as raised:
            self.watch(address=hex(DATA + 8))
        self.assertIn("tainted", str(raised.exception))
        with self.assertRaises(RuntimeError) as raised:
            self.detach()
        self.assertIn("0x80000004", str(raised.exception))
        self.assertFalse(self.agent.detached)
        self.assertFalse(self.script.unloaded)

    def test_a_retry_that_reads_clear_lifts_the_taint_and_detach_then_works(self):
        watch, _ = self.taint()
        self.target.fail_unset = set()
        again = self.watch("disarm", watch=watch["id"])
        self.assertEqual(again["state"], "clear")
        self.assertEqual(self.agent.tainted, "")
        self.assertEqual(self.detach()["state"], "detached")
        self.assertTrue(self.script.unloaded)

    def test_force_detach_goes_through_and_says_what_it_risks(self):
        self.taint()
        result = self.detach(force_tainted=True)
        self.assertEqual(result["state"], "detached")
        self.assertIn("0x80000004", result["target_state"])
        self.assertTrue(result["tainted"])

    def test_a_dead_target_is_not_an_armed_hazard(self):
        watch = self.arm()
        self.target.readback_unavailable = True      # a gone session: nothing can be created or called on it
        self.target.fail_unset = {1, 2, 3}
        self.agent.detached = True
        calls = len(self.script.calls)
        result = self.detach()
        self.assertEqual(result["state"], "detached")
        self.assertEqual(self.agent.tainted, "")
        self.assertEqual(self.agent.watches[watch["id"]]["state"], "clear")
        self.assertEqual(self.agent.watches[watch["id"]]["verified"]["evidence"], "target gone")
        self.assertEqual(len(self.script.calls), calls)     # no disarm was attempted

    def test_a_dead_target_clears_an_already_tainted_watch_too(self):
        self.taint()
        self.agent.detached = True
        self.assertEqual(self.detach()["state"], "detached")
        self.assertEqual(self.agent.tainted, "")

    def test_a_failed_script_creation_rolls_the_arm_back_and_frees_the_slot(self):
        def broken():
            raise RuntimeError("session is gone")
        self.agent._memory = broken
        for _ in range(memory.SLOTS + 1):
            with self.assertRaises(RuntimeError) as raised:
                self.watch()
            self.assertIn("arming failed", str(raised.exception))
        self.assertFalse([w for w in self.agent.watches.values() if w["state"] == "arming"])

    def test_an_address_beyond_the_pointer_width_is_refused(self):
        arch_limit = 1 << (32 if self.arch == "x86" else 64)
        for address in (hex(arch_limit), hex(arch_limit - 2)):
            with self.assertRaises(ValueError, msg=address) as raised:
                self.watch(address=address)
            self.assertIn("pointer width", str(raised.exception))
        with self.assertRaises(ValueError):
            self.watch(address="0x0")

    def test_the_worker_does_not_idle_out_while_tainted(self):
        import inspect

        from hydralysis import runtime_worker
        self.assertIn("agent.tainted or", inspect.getsource(runtime_worker.main))


class Matrix(Case):
    """Both architectures against every teardown path; each ends with the readback saying no slot is left."""
    arch = "x64"

    def teardown(self, name, prepare, ends):
        with self.subTest(arch=self.arch, scenario=name):
            self.setUp()
            try:
                watches = [self.arm(address=hex(DATA + 8 * i)) for i in range(2)]
                prepare(watches)
                ends(watches)
            finally:
                self.tearDown() if hasattr(self, "tearDown") else None
                self.doCleanups()

    def test_the_matrix(self):
        for arch in ARCHES:
            self.arch = arch
            ctx = self

            def clear(_):
                self.assertTrue(all(not s for s in self.target.slots.values()), self.target.slots)

            def disarm_each(watches):
                for w in watches:
                    self.assertEqual(self.watch("disarm", watch=w["id"])["state"], "clear")
                clear(watches)

            def detach_while_armed(_):
                result = self.detach()
                self.assertEqual(result["state"], "detached")
                self.assertNotIn("tainted", result)
                clear(_)
                self.assertTrue(self.script.unloaded)

            def detach_blocked(_):
                with self.assertRaises(RuntimeError):
                    self.detach()
                self.assertTrue(self.agent.tainted)

            def hits_while_disarming(watches):
                for w in watches:
                    self.script.watches[w["id"]]["seen"] = 99
                    self.agent._memory_message({"type": "send", "payload": {"event": "watch_hit", "watch": w["id"]}})
                disarm_each(watches)

            self.teardown("disarm each", lambda w: None, disarm_each)
            self.teardown("detach while armed disarms first", lambda w: None, detach_while_armed)
            self.teardown("hits while disarming", lambda w: None, hits_while_disarming)
            self.teardown("unset fails on a thread", lambda w: self.target.fail_unset.add(2), detach_blocked)
            self.teardown("readback unavailable", lambda w: setattr(self.target, "readback_unavailable", True), detach_blocked)
            self.teardown("thread born mid-disarm is retried clear", lambda w: setattr(self.target, "new_thread_on_disarm", 1), detach_while_armed)
            self.teardown("register restored until the attempts run out", lambda w: setattr(self.target, "reenable_after_unset", 99), detach_blocked)
            self.assertEqual(ctx.arch, arch)

    def test_the_matrix_covers_both_architectures_with_the_right_stamp(self):
        for arch in ARCHES:
            self.arch = arch
            self.setUp()
            try:
                self.assertEqual(self.arm()["state"], "armed")
                other = "x86" if arch == "x64" else "x64"
                with self.assertRaises(PermissionError):
                    self.watch(gate={"fixture_sha256": self.agent.target_sha256, "frida": "17.24.3",
                                     "stamps": {other: self.stamp(arch=other)}}, address=hex(DATA + 8))
            finally:
                self.doCleanups()


class ConformanceRun(Case):
    def test_the_conformance_run_arms_without_a_stamp_and_nothing_else_does(self):
        watch = self.arm(gate=self.gate(stamp=False, conformance=True))
        self.assertEqual(watch["state"], "armed")
        with self.assertRaises(PermissionError):
            self.watch(gate=self.gate(stamp=False), address=hex(DATA + 8))

    def test_the_client_sets_the_flag_only_from_its_own_settings(self):
        from hydralysis import runtime
        directory = Path(self.temp.name) / "client"
        directory.mkdir()
        (directory / "start.json").write_text(json.dumps({"sha256": "ab" * 32}))
        plain = runtime.RuntimeRunner({"root": self.temp.name})
        self.assertFalse(plain._memory_gate(directory, {"_gate": {"conformance": True}})["_gate"]["conformance"])
        marked = runtime.RuntimeRunner({"root": self.temp.name, "runtime_watch_conformance_run": True})
        self.assertTrue(marked._memory_gate(directory, {})["_gate"]["conformance"])

    def test_the_client_hands_over_the_stamps_it_holds(self):
        from hydralysis import runtime
        directory = Path(self.temp.name) / "client2"
        directory.mkdir()
        (directory / "start.json").write_text(json.dumps({"sha256": "ab" * 32}))
        runner = runtime.RuntimeRunner({"root": self.temp.name})
        stamps = runtime._root(runner.settings) / "watch-stamps"
        stamps.mkdir(parents=True)
        runtime._write(stamps / "x64.json", self.stamp())
        gate = runner._memory_gate(directory, {})["_gate"]
        self.assertEqual(list(gate["stamps"]), ["x64"])
        self.assertEqual(gate["stamps"]["x64"]["result"], "pass")


class Conformance(unittest.TestCase):
    """The tool's own logic, without a process: the stamp it writes is exactly the one the worker accepts."""

    def test_the_stamp_a_passing_run_writes_is_accepted(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
        import watch_conformance as tool
        stamp = tool.make_stamp("x64", "ab" * 32, "17.24.3", 100, [])
        self.assertEqual((stamp["result"], stamp["arch"], stamp["iterations"]), ("pass", "x64", 100))
        failing = tool.make_stamp("x64", "ab" * 32, "17.24.3", 100, ["iteration 7: exit 0x80000004"])
        self.assertEqual(failing["result"], "fail")
        self.assertEqual(tool.exit_status({"x64": stamp, "x86": stamp}), 0)
        self.assertNotEqual(tool.exit_status({"x64": stamp, "x86": failing}), 0)
        self.assertNotEqual(tool.exit_status({"x64": stamp}), 0)
        self.assertEqual(tool.exit_code_verdict(0), "")
        self.assertIn("0x80000004", tool.exit_code_verdict(0x80000004))
        self.assertIn("exit 3", tool.exit_code_verdict(3))
        short = tool.make_stamp("x64", "ab" * 32, "17.24.3", 5, [])
        self.assertEqual(short["result"], "fail")


if __name__ == "__main__":
    unittest.main()
