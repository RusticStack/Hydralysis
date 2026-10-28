"""Runtime memory write (Z12): fixture-only gate, compare-and-swap, reason, executable-range guard, undo log, DIVERGED.

Runs on the fake frida binding with an in-memory target (tests/fakememory.py). The real-process side is
tools/watch_conformance.py and tests/fixtures/verify_fixtures.py `write`.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from fakefrida.harness import attached_agent
from fakememory import CODE, DATA, Target, wire
from hydralysis import runtime
from hydralysis.runtime_events import verify_log
from hydralysis.runtime_memory import FIXTURE_MARKER, fixture_marked
from support import workdir

SESSION = "a" * 32


class Case(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("zwrite")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "runtime-sessions" / SESSION
        self.agent, *_ = attached_agent(self.directory)
        self.addCleanup(lambda: None if self.agent.closed else self.agent.log.close())
        self.target = Target()
        self.script = wire(self.agent, self.target)
        marked = patch("hydralysis.runtime_memory.fixture_marked", return_value=True)
        marked.start()
        self.addCleanup(marked.stop)

    def gate(self, **changes):
        return {"fixture_sha256": self.agent.target_sha256, "frida": "17.24.3", "stamps": {}, **changes}

    def write(self, **options):
        args = {"_gate": self.gate(), "address": hex(DATA), "expect": "00 00 00 00", "bytes": "2A 00 00 00",
                "reason": "set the fixture limit", **options}
        return self.agent.handle("write", {k: v for k, v in args.items() if v is not None})

    def undo(self, **options):
        return self.agent.handle("write", {"_gate": self.gate(), "op": "undo", **options})

    def memory(self, size=4, at=DATA):
        return [self.target.memory[at + i] for i in range(size)]


class Gate(Case):
    def test_an_unlisted_build_is_refused(self):
        with self.assertRaises(PermissionError) as raised:
            self.agent.handle("write", {"address": hex(DATA), "expect": "00", "bytes": "01", "reason": "no gate present"})
        self.assertIn("runtime_fixture_sha256", str(raised.exception))
        self.assertEqual(self.memory(), [0, 0, 0, 0])

    def test_another_builds_hash_is_refused(self):
        with self.assertRaises(PermissionError):
            self.write(_gate=self.gate(fixture_sha256="0" * 64))

    def test_the_fixture_marker_is_required_in_the_file(self):
        folder = Path(self.temp.name)
        marked, plain = folder / "a.exe", folder / "b.exe"
        marked.write_bytes(b"MZ" + FIXTURE_MARKER + b"\x00")
        plain.write_bytes(b"MZ" + b"game" * 100)
        self.assertTrue(fixture_marked(str(marked)))
        self.assertFalse(fixture_marked(str(plain)))
        self.assertFalse(fixture_marked(str(folder / "missing.exe")))

    def test_a_listed_build_without_the_marker_is_refused(self):
        with patch("hydralysis.runtime_memory.fixture_marked", return_value=False):
            with self.assertRaises(PermissionError) as raised:
                self.write()
        self.assertIn("marker", str(raised.exception))
        self.assertEqual(self.memory(), [0, 0, 0, 0])

    def test_the_client_adds_the_gate_and_drops_one_the_caller_sent(self):
        directory = Path(self.temp.name) / "client"
        directory.mkdir()
        (directory / "start.json").write_text(json.dumps({"sha256": "ab" * 32}))
        runner = runtime.RuntimeRunner({"root": self.temp.name})
        forged = {"address": "0x1", "_gate": {"fixture_sha256": "ab" * 32}}
        self.assertEqual(runner._memory_gate(directory, dict(forged))["_gate"]["fixture_sha256"], "")
        listed = runtime.RuntimeRunner({"root": self.temp.name, "runtime_fixture_sha256": ["ab" * 32]})
        self.assertEqual(listed._memory_gate(directory, dict(forged))["_gate"]["fixture_sha256"], "ab" * 32)
        self.assertEqual(listed._memory_gate(directory, {})["_gate"]["frida"], runtime.FRIDA_VERSION)

    def test_both_actions_are_owner_only(self):
        for action in ("write", "watch"):
            self.assertIn(action, runtime.MUTATING)
            self.assertIn(action, runtime.ACTION_NAMES)


class Write(Case):
    def test_a_compare_and_swap_writes_and_logs(self):
        result = self.write()
        self.assertTrue(result["written"])
        self.assertEqual(self.memory(), [0x2A, 0, 0, 0])
        entry = result["entry"]
        self.assertEqual((entry["before"], entry["after"], entry["status"]), ("00 00 00 00", "2A 00 00 00", "applied"))
        saved = json.loads((self.directory / "memory.json").read_text())
        self.assertEqual(saved["writes"][0]["id"], entry["id"])
        self.agent.log.sync()
        self.assertTrue(verify_log(self.directory, SESSION)["ok"])
        self.assertEqual(self.agent.snapshot()["writes"], 1)

    def test_a_stale_expectation_writes_nothing(self):
        self.target.put(DATA, [7, 0, 0, 0])
        with self.assertRaises(ValueError) as raised:
            self.write()
        self.assertIn("CAS MISMATCH", str(raised.exception))
        self.assertIn("07 00 00 00", str(raised.exception))
        self.assertEqual(self.memory(), [7, 0, 0, 0])
        self.assertEqual(self.agent.writes, [])

    def test_a_reason_is_required(self):
        for reason in (None, "", "short"):
            with self.assertRaises(ValueError, msg=repr(reason)) as raised:
                self.write(reason=reason)
            self.assertIn("reason", str(raised.exception))
        self.assertEqual(self.script.calls, [])

    def test_an_executable_range_is_refused_before_the_script_is_asked(self):
        with self.assertRaises(ValueError) as raised:
            self.write(address=hex(CODE))
        self.assertIn("EXECUTABLE RANGE", str(raised.exception))
        self.assertEqual(self.script.calls, [])
        self.assertEqual(self.agent.writes, [])

    def test_the_script_refuses_an_executable_range_on_its_own(self):
        with self.assertRaises(RuntimeError):
            self.script.writeCas(hex(CODE), [0], [1])

    def test_unmapped_and_range_crossing_spans_are_refused(self):
        with self.assertRaises(ValueError):
            self.write(address="0x50")
        with self.assertRaises(ValueError) as raised:
            self.write(address=hex(DATA + 0xFE), expect="00 00 00 00")
        self.assertIn("crosses", str(raised.exception))

    def test_malformed_bytes_and_length_mismatch_are_refused(self):
        for options in ({"expect": "0"}, {"bytes": "ZZ 00 00 00"}, {"bytes": "01"},
                        {"expect": " ".join(["00"] * 65), "bytes": " ".join(["01"] * 65)}):
            with self.assertRaises(ValueError, msg=str(options)):
                self.write(**options)
        self.assertEqual(self.script.calls, [])

    def test_a_detached_session_refuses(self):
        self.agent.detached = True
        with self.assertRaises(RuntimeError):
            self.write()


class Undo(Case):
    def test_undo_restores_the_before_bytes(self):
        entry = self.write()["entry"]
        result = self.undo()
        self.assertTrue(result["undone"])
        self.assertEqual(self.memory(), [0, 0, 0, 0])
        self.assertEqual(self.agent.writes[0]["status"], "undone")
        self.assertEqual(self.agent.handle("write", {"_gate": self.gate(), "op": "log"})["count"], 1)
        self.assertEqual(entry["id"], self.agent.writes[0]["id"])

    def test_undo_reports_diverged_and_writes_nothing_when_the_memory_changed(self):
        self.write()
        self.target.put(DATA, [9, 9, 9, 9])          # the target moved on
        result = self.undo()
        self.assertFalse(result["undone"])
        self.assertEqual(result["status"], "DIVERGED")
        self.assertEqual((result["expected"], result["found"]), ("2A 00 00 00", "09 09 09 09"))
        self.assertEqual(self.memory(), [9, 9, 9, 9])
        self.assertEqual(self.agent.writes[0]["status"], "diverged")
        with self.assertRaises(ValueError):
            self.undo()                               # a diverged entry is not retried silently

    def test_undo_takes_the_latest_unless_an_id_is_named(self):
        first = self.write()["entry"]
        self.write(address=hex(DATA + 8), expect="00 00 00 00", bytes="05 00 00 00")
        self.undo(id=first["id"])
        self.assertEqual(self.memory(), [0, 0, 0, 0])
        self.assertEqual(self.memory(at=DATA + 8), [5, 0, 0, 0])
        self.undo()
        self.assertEqual(self.memory(at=DATA + 8), [0, 0, 0, 0])

    def test_nothing_to_undo_is_an_error(self):
        with self.assertRaises(ValueError):
            self.undo()
        with self.assertRaises(ValueError):
            self.undo(id="nope")

    def test_undo_refuses_when_the_range_became_executable(self):
        self.write()
        self.target.ranges[DATA] = ("rwx", 0x100)
        with self.assertRaises(ValueError):
            self.undo()
        self.assertEqual(self.memory(), [0x2A, 0, 0, 0])


if __name__ == "__main__":
    unittest.main()
