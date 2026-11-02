"""Owner-authorized runtime memory mode (issue #7), on fixtures and the in-memory target only: never a real game.

The fixture-only default is covered by test_runtime_write.py and test_runtime_watch.py and is unchanged.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fakefrida.harness import attached_agent
from fakememory import CODE, DATA, Target, wire
from hydralysis import runtime, runtime_authorize as authz
from hydralysis.runtime_authorize import AuthorizationRefused
from support import workdir

SESSION = "c" * 32


def entry(sha, **changes):
    return {"sha256": sha, "actions": ["write", "watch"], "max_size": 8,
            "ranges": [{"va_start": hex(DATA), "va_end": hex(DATA + 0x80)}], **changes}


class Case(unittest.TestCase):
    arch = "x64"

    def setUp(self):
        self.temp = workdir("zauth")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "runtime-sessions" / SESSION
        self.agent, *_ = attached_agent(self.directory)
        self.addCleanup(lambda: None if self.agent.closed else self.agent.log.close())
        self.target = Target(self.arch)
        self.script = wire(self.agent, self.target)
        self.sha = self.agent.target_sha256
        # the target file carries no fixture marker: this is the owner-authorized path
        marked = patch("hydralysis.runtime_memory.fixture_marked", return_value=False)
        marked.start()
        self.addCleanup(marked.stop)

    def stamp(self, **changes):
        return {"version": 1, "result": "pass", "arch": self.arch, "target_sha256": self.sha, "frida": "17.24.3",
                "iterations": 100, **changes}

    def gate(self, auth=True, stamp=True, **changes):
        out = {"fixture_sha256": "", "frida": "17.24.3", "stamps": {}}
        if auth:
            out["authorized"] = authz.normalize(entry(self.sha)) if auth is True else auth
        if stamp:
            out["authorized_stamp"] = self.stamp() if stamp is True else stamp
        return {**out, **changes}

    def write(self, gate=None, **options):
        args = {"_gate": gate or self.gate(), "address": hex(DATA), "expect": "00 00 00 00", "bytes": "2A 00 00 00",
                "reason": "owner-authorized limit change", **options}
        return self.agent.handle("write", args)

    def watch(self, gate=None, op="arm", **options):
        args = {"_gate": gate or self.gate(), "op": op, **options}
        if op == "arm":
            args = {"address": hex(DATA), "size": 4, "reason": "owner-authorized watch", **args}
        return self.agent.handle("watch", args)

    def memory(self, at=DATA):
        return [self.target.memory[at + i] for i in range(4)]


class Refusals(Case):
    def test_no_authorization_is_a_coded_refusal_naming_both_settings(self):
        for call in (lambda: self.write(gate=self.gate(auth=False)), lambda: self.watch(gate=self.gate(auth=False))):
            with self.assertRaises(AuthorizationRefused) as raised:
                call()
            self.assertEqual(raised.exception.code, "not_authorized")
            self.assertIn("[not_authorized]", str(raised.exception))
            self.assertIn("runtime_authorized_targets", str(raised.exception))
            self.assertIn("runtime_fixture_sha256", str(raised.exception))
        self.assertEqual(self.script.calls, [])

    def test_an_entry_for_another_build_does_not_apply(self):
        other = authz.normalize(entry("0" * 64))
        with self.assertRaises(AuthorizationRefused):
            self.write(gate=self.gate(auth=other))

    def test_an_address_outside_the_declared_range_is_refused(self):
        with self.assertRaises(AuthorizationRefused) as raised:
            self.write(address=hex(DATA + 0x80), expect="00 00 00 00")
        self.assertEqual(raised.exception.code, "outside_authorized_range")
        with self.assertRaises(AuthorizationRefused):          # straddles the end of the range
            self.write(address=hex(DATA + 0x7E), expect="00 00 00 00")
        self.assertEqual(self.script.calls, [])

    def test_a_size_over_the_authorization_is_refused(self):
        small = authz.normalize(entry(self.sha, max_size=2))
        with self.assertRaises(AuthorizationRefused) as raised:
            self.write(gate=self.gate(auth=small))
        self.assertEqual(raised.exception.code, "size_exceeds_authorization")
        with self.assertRaises(AuthorizationRefused):
            self.watch(gate=self.gate(auth=small))

    def test_an_action_not_listed_is_refused(self):
        only_write = authz.normalize(entry(self.sha, actions=["write"]))
        with self.assertRaises(AuthorizationRefused) as raised:
            self.watch(gate=self.gate(auth=only_write))
        self.assertEqual(raised.exception.code, "action_not_authorized")
        self.assertTrue(self.write(gate=self.gate(auth=only_write))["written"])

    def test_executable_ranges_are_refused_even_when_declared(self):
        code = authz.normalize(entry(self.sha, ranges=[{"va_start": hex(CODE), "va_end": hex(CODE + 0x10)}]))
        with self.assertRaises(ValueError) as raised:
            self.write(gate=self.gate(auth=code), address=hex(CODE), expect="00", bytes="01")
        self.assertIn("EXECUTABLE RANGE", str(raised.exception))
        with self.assertRaises(ValueError) as raised:
            self.watch(gate=self.gate(auth=code), address=hex(CODE))
        self.assertIn("EXECUTABLE RANGE", str(raised.exception))
        self.assertEqual(self.agent.watches, {})
        self.assertEqual(self.script.calls, [])

    def test_the_fixture_conformance_flag_cannot_stand_in_for_the_stamp(self):
        with self.assertRaises(AuthorizationRefused) as raised:
            self.watch(gate=self.gate(stamp=False, conformance=True))
        self.assertEqual(raised.exception.code, "conformance_stamp_missing")

    def test_a_watch_needs_a_stamp_for_this_exact_build_arch_and_frida(self):
        bad = [False, self.stamp(result="fail"), self.stamp(target_sha256="0" * 64), self.stamp(arch="x86"),
               self.stamp(frida="1.0.0"), self.stamp(iterations=99)]
        for stamp in bad:
            with self.assertRaises(AuthorizationRefused, msg=str(stamp)) as raised:
                self.watch(gate=self.gate(stamp=stamp))
            self.assertEqual(raised.exception.code, "conformance_stamp_missing")
        self.assertEqual(self.agent.watches, {})
        self.assertEqual(self.script.calls, [])


class Allowed(Case):
    def test_write_undo_and_diverged_inside_the_range(self):
        result = self.write()
        self.assertTrue(result["written"])
        self.assertEqual(result["entry"]["mode"], "authorized")
        self.assertEqual(self.memory(), [0x2A, 0, 0, 0])
        undone = self.agent.handle("write", {"_gate": self.gate(), "op": "undo"})
        self.assertTrue(undone["undone"])
        self.assertEqual(self.memory(), [0, 0, 0, 0])
        self.write()
        self.target.put(DATA, [9, 9, 9, 9])
        diverged = self.agent.handle("write", {"_gate": self.gate(), "op": "undo"})
        self.assertEqual(diverged["status"], "DIVERGED")

    def test_undo_is_refused_when_the_authorization_no_longer_covers_the_entry(self):
        self.write()
        narrowed = authz.normalize(entry(self.sha, ranges=[{"va_start": hex(DATA + 0x40), "va_end": hex(DATA + 0x80)}]))
        with self.assertRaises(AuthorizationRefused):
            self.agent.handle("write", {"_gate": self.gate(auth=narrowed), "op": "undo"})
        self.assertEqual(self.memory(), [0x2A, 0, 0, 0])

    def test_a_watch_arms_and_disarms_to_verified_clear(self):
        armed = self.watch()["watch"]
        self.assertEqual((armed["state"], armed["mode"]), ("armed", "authorized"))
        cleared = self.watch(op="disarm", watch=armed["id"])
        self.assertEqual(cleared["watch"]["state"], "clear")
        self.assertEqual(self.target.slots, {tid: set() for tid in self.target.slots})

    def test_module_relative_ranges_follow_the_module_base(self):
        base = DATA - 0x1000
        auth = authz.normalize(entry(self.sha, ranges=[{"module": "Game.EXE", "rva_start": "0x1000", "rva_end": "0x1080"}]))
        real = self.agent.control.exports_sync.locate

        def locate(address):
            found = real(address)
            return {**found, "module": {"name": "game.exe", "base": hex(base)}}

        with patch.object(self.agent.control.exports_sync, "locate", locate):
            self.assertTrue(self.write(gate=self.gate(auth=auth))["written"])
            with self.assertRaises(AuthorizationRefused):
                self.write(gate=self.gate(auth=auth), address=hex(DATA + 0x80), expect="00 00 00 00")
            wrong = authz.normalize(entry(self.sha, ranges=[{"module": "other.exe", "rva_start": "0x1000",
                                                              "rva_end": "0x1080"}]))
            with self.assertRaises(AuthorizationRefused):
                self.write(gate=self.gate(auth=wrong), address=hex(DATA + 8), expect="00 00 00 00")


class Settings(unittest.TestCase):
    def test_normalize_accepts_and_rejects(self):
        good = authz.normalize(entry("AB" * 32))
        self.assertEqual(good["sha256"], "ab" * 32)
        self.assertEqual(good["ranges"][0]["end"] - good["ranges"][0]["start"], 0x80)
        sha = "ab" * 32
        bad = [{}, entry("zz"), entry(sha, actions=[]), entry(sha, actions=["exec"]),
               entry(sha, max_size=0), entry(sha, max_size=65), entry(sha, ranges=[]),
               entry(sha, ranges=[{"va_start": "0x10", "va_end": "0x10"}]),
               entry(sha, ranges=[{"va_start": "0", "va_end": hex(authz.MAX_RANGE + 1)}]),
               entry(sha, ranges=[{"module": "", "rva_start": "0", "rva_end": "8"}]),
               entry(sha, ranges=[{"va_start": "x", "va_end": "8"}])]
        for item in bad:
            with self.assertRaises(ValueError, msg=str(item)):
                authz.normalize(item)

    def test_the_client_builds_the_gate_from_its_own_settings_only(self):
        temp = workdir("zauthgate")
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name) / "client"
        directory.mkdir()
        sha = "ab" * 32
        (directory / "start.json").write_text(json.dumps({"sha256": sha}))
        stamps = Path(temp.name) / "watch-stamps" / "authorized"
        stamps.mkdir(parents=True)
        forged = {"_gate": {"authorized": entry(sha)}}
        plain = runtime.RuntimeRunner({"root": temp.name})
        self.assertNotIn("authorized", plain._memory_gate(directory, dict(forged))["_gate"])
        listed = runtime.RuntimeRunner({"root": temp.name, "runtime_authorized_targets": [entry(sha)]})
        gate = listed._memory_gate(directory, dict(forged))["_gate"]
        self.assertEqual(gate["authorized"]["sha256"], sha)
        self.assertNotIn("authorized_stamp", gate)
        (stamps / (sha + ".json")).write_text(json.dumps({"result": "pass", "target_sha256": sha}))
        self.assertEqual(listed._memory_gate(directory, {})["_gate"]["authorized_stamp"]["target_sha256"], sha)
        broken = runtime.RuntimeRunner({"root": temp.name, "runtime_authorized_targets": [entry(sha, max_size=0)]})
        gate = broken._memory_gate(directory, {})["_gate"]
        self.assertNotIn("authorized", gate)
        self.assertIn("max_size", gate["authorization_error"])

    def test_pe_arch_and_bind_stamp(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
        import watch_conformance as tool
        temp = workdir("zauthpe")
        self.addCleanup(temp.cleanup)
        exe = Path(temp.name) / "a.exe"
        head = bytearray(0x100)
        head[:2] = b"MZ"
        head[0x3C:0x40] = (0x80).to_bytes(4, "little")
        head[0x80:0x84] = b"PE\0\0"
        head[0x84:0x86] = (0x8664).to_bytes(2, "little")
        exe.write_bytes(bytes(head))
        self.assertEqual(authz.pe_arch(str(exe)), "x64")
        self.assertEqual(authz.pe_arch(str(Path(temp.name) / "missing.exe")), "")
        stamp = tool.make_stamp("x64", "cd" * 32, "17.24.3", 100, [])
        bound = tool.bind_stamp(stamp, "ab" * 32, "x64")
        self.assertTrue(authz.valid_stamp(bound, "ab" * 32, "x64", "17.24.3", 100))
        self.assertFalse(authz.valid_stamp(bound, "ab" * 32, "x86", "17.24.3", 100))
        self.assertEqual(tool.bind_stamp(stamp, "ab" * 32, "x86")["result"], "fail")


if __name__ == "__main__":
    unittest.main()
