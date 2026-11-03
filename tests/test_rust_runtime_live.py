"""The Rust runtime device on the scenarios only the Frida stand-in covered before.

`test_mcp_runtime.PatchedFunctionOverMCP`, `TwoHarnessesOneGame` and the cwd/env lifecycle run on the fake binding even under
`HYDRALYSIS_IMPL=rust` (a configured stand-in wins), and `test_runtime_decode` never reaches a probe. These tests run the same
claims against `hy-fixture.exe` on the Rust device, in a real worker (`MCP`) or a `RuntimeAgent` (`Agent`):

* a live detour another tool wrote: reported with the file bytes and its patcher, refused by `observe`, probed past with
  `accept_patch` and the original prologue (and the probe really fires through the detour);
* captured arguments decoded in the worker (`decoded` rows: values, names, registers, unreadable pointers) and the `sample`
  window of a numeric capture;
* the cwd and the environment of a spawned session, with the worker-only variables restored;
* the second harness may read a driven session but not drive, detach or attach it.

Skipped, with the reason, unless the Rust pieces are built (`cargo build --release --workspace` in rust/).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

from support import workdir  # noqa: E402
from test_rust_runtime import HY_FIXTURE, READY, WHY, rust_frida  # noqa: E402

FIXTURE = HY_FIXTURE.is_file()
SKIP = "needs the Rust runtime and hy-fixture.exe (cargo build --release --workspace in rust/): %s" % (WHY or "fixture missing")
GATE_FROM = "17.24.3"


def fixture_info() -> dict:
    out = subprocess.run([str(HY_FIXTURE), "info"], capture_output=True, text=True, timeout=60).stdout
    return dict(word.split("=", 1) for word in out.split())


def spaced(hex_text: str, count: int) -> str:
    return " ".join(hex_text[i:i + 2].upper() for i in range(0, count * 2, 2))


def wait_until(what, test, timeout=30.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = test()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("never: " + what)


@unittest.skipUnless(READY and FIXTURE, SKIP)
class Agent(unittest.TestCase):
    """A real `RuntimeAgent` on the Rust device, the worker's own code path."""

    @classmethod
    def setUpClass(cls):
        cls.info = fixture_info()
        cls.hit_rva, cls.spare_rva = int(cls.info["RVA"], 16), int(cls.info["SPARE"], 16)
        cls.digest = hashlib.sha256(HY_FIXTURE.read_bytes()).hexdigest()

    def setUp(self):
        self.dir = workdir("rt-live-")
        self.device = rust_frida.RustDevice()
        self.agents = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for raw in list(self.device._live.values()):
            try:
                raw.terminate()
            except Exception:  # noqa: BLE001 - already gone
                pass
        for agent in self.agents:
            try:
                if not agent.closed:
                    agent.cleanup()
            except Exception:  # noqa: BLE001
                pass
        for raw in list(self.device._live.values()):
            raw.close()
        self.dir.cleanup()

    def start(self, *argv, cwd=None, env=None):
        from hydralysis.runtime_worker import RuntimeAgent
        directory = Path(self.dir.name) / uuid.uuid4().hex
        directory.mkdir()
        agent = RuntimeAgent(directory, self.device)
        self.agents.append(agent)
        initial = {"action": "spawn", "exe": str(HY_FIXTURE), "sha256": self.digest, "argv": [str(a) for a in argv], "env": env or {}}
        if cwd:
            initial["cwd"] = str(cwd)
        agent.startup(initial)
        return agent

    def events(self, agent, hook, kind=None):
        listed = agent.handle("status", {"limit": 200})["events"]
        payloads = [e["message"]["payload"] for e in listed if (e["message"].get("payload") or {}).get("hook_id") == hook]
        return [p for p in payloads if kind is None or p.get("event") == kind]

    def probe(self, agent, rva=None, **options):
        rva = self.hit_rva if rva is None else rva
        head = self.info["BYTES"] if rva == self.hit_rva else self.info["SPAREBYTES"]
        args = {"module": HY_FIXTURE.name, "rva": hex(rva), "sha256": self.digest, "expect": spaced(head, 8), "limit": 3, **options}
        return agent.handle(args.pop("action", "observe"), args)

    # -- decoding of captured arguments and samples -----------------------------------------------------------------

    def test_captured_arguments_are_decoded_in_the_worker(self):
        go = Path(self.dir.name) / "go"
        agent = self.start("hits", 5, go)
        agent.handle("resume", {})
        capture = [{"arg": 0, "as": "u64", "names": {"0": "zero", "0x1": "one"}, "label": "index"},
                   {"reg": "rcx", "as": "pointer", "label": "rcx"},
                   {"arg": 0, "as": "hex", "size": 8, "deref": [0], "label": "deref"},
                   {"arg": 0, "as": "i32", "label": "small"}]
        hook = self.probe(agent, capture=capture)["hook_id"]
        go.write_text("go")
        entered = wait_until("three enters", lambda: (lambda e: e if len(e) >= 3 else None)(self.events(agent, hook, "enter")))
        for index, event in enumerate(entered[:3]):
            self.assertNotIn("captures", event, "the raw captures are replaced by the decoded rows")
            rows = {row["label"]: row for row in event["decoded"]}
            names = {0: {"value": 0, "name": "zero"}, 1: {"value": 1, "name": "one"}}
            self.assertEqual(rows["index"]["value"], names.get(index, {"value": index, "name": None}))
            self.assertEqual((rows["rcx"]["reg"], rows["rcx"]["value"]), ("rcx", hex(index)))
            self.assertEqual(rows["small"]["value"], index)
            self.assertIn("error", rows["deref"], "address %d is not readable" % index)
        specs = agent.scripts[hook]["captures"]
        self.assertEqual([spec["as"] for spec in specs], ["u64", "pointer", "hex", "i32"])
        self.assertTrue(specs[0]["value_only"])

    def test_an_unreadable_pointer_is_a_decoded_error_row_not_a_failure(self):
        go = Path(self.dir.name) / "go"
        agent = self.start("hits", 5, go)
        agent.handle("resume", {})
        hook = self.probe(agent, capture=[{"arg": 0, "as": "utf8", "deref": [0], "size": 16}])["hook_id"]
        go.write_text("go")
        entered = wait_until("an enter", lambda: self.events(agent, hook, "enter"))
        rows = entered[0]["decoded"]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].get("error") or rows[0].get("value") is not None, rows)
        self.assertEqual(agent.handle("status", {})["state"], "running")

    def test_a_numeric_capture_is_sampled_over_a_window(self):
        go = Path(self.dir.name) / "go"
        agent = self.start("hits", 5, go)
        agent.handle("resume", {})
        hook = self.probe(agent, limit=200, capture=[{"arg": 0, "as": "u64"}], sample={"window_s": 1, "capture": 0})["hook_id"]
        go.write_text("go")
        samples = wait_until("a sample window", lambda: [s for s in self.events(agent, hook, "sample") if s["count"]], 30)
        window = samples[0]
        self.assertEqual((window["count"], window["min"], window["max"], window["last"]), (5, 0, 4, 4), window)
        self.assertEqual(window["window_s"], 1)
        self.assertEqual(self.events(agent, hook, "enter"), [], "a sampling probe aggregates; it sends no per-hit event")

    def test_the_sample_option_is_validated(self):
        agent = self.start("hits", 1, Path(self.dir.name) / "never")
        agent.handle("resume", {})
        for sample in ({"window_s": 0, "capture": 0}, {"window_s": 1, "capture": 3}, {"window_s": 1, "extra": 1}, 5):
            with self.subTest(sample=sample), self.assertRaises(ValueError):
                self.probe(agent, capture=[{"arg": 0, "as": "u64"}], sample=sample)
        with self.assertRaises(ValueError):
            self.probe(agent, capture=[{"arg": 0, "as": "hex"}], sample={"window_s": 1, "capture": 0})

    # -- cwd and environment of a spawned session -------------------------------------------------------------------

    def test_spawn_honours_cwd_and_env_and_restores_the_worker_only_variables(self):
        target = Path(self.dir.name) / "game-dir"
        target.mkdir()
        proof = Path(self.dir.name) / "proof.txt"
        restore = json.dumps({"PYTHONPATH": None, "TEMP": os.environ.get("TEMP")})
        with patch.dict(os.environ, {"HYDRALYSIS_TARGET_ENV_RESTORE": restore, "PYTHONPATH": "worker-only"}):
            agent = self.start("env", proof, cwd=target, env={"RRE_PROOF": "from-caller"})
        agent.handle("resume", {})
        text = wait_until("the proof file", lambda: proof.is_file() and proof.read_text())
        cwd, value, leaked, pythonpath, temp = text.split("|")
        self.assertEqual(Path(cwd).resolve(), target.resolve())
        self.assertEqual(value, "from-caller")
        self.assertEqual(leaked, "none", "the restore variable itself must not reach the target")
        self.assertEqual(pythonpath, "none", "a worker-only variable is removed from the target's environment")
        self.assertEqual(temp, os.environ.get("TEMP", "none"))

    def test_spawn_without_cwd_inherits_the_callers(self):
        proof = Path(self.dir.name) / "proof.txt"
        agent = self.start("env", proof)
        agent.handle("resume", {})
        text = wait_until("the proof file", lambda: proof.is_file() and proof.read_text())
        self.assertEqual(Path(text.split("|")[0]).resolve(), Path.cwd().resolve())
        self.assertEqual(text.split("|")[1], "none")

    # -- a live detour --------------------------------------------------------------------------------------------

    def patched(self):
        go = Path(self.dir.name) / "go"
        agent = self.start("patched", go)
        agent.handle("resume", {})
        base = int(agent.control.exports_sync.info(str(HY_FIXTURE))["main"]["base"], 16)
        wait_until("the detour", lambda: bytes(agent.control.exports_sync.read(hex(base + self.spare_rva), 1)) == b"\xe9")
        return agent, go

    def test_a_live_detour_is_reported_with_the_file_bytes_and_its_patcher(self):
        agent, _ = self.patched()
        rows = [{"module": HY_FIXTURE.name, "rva": hex(self.spare_rva), "size": 5}, {"module": HY_FIXTURE.name, "rva": hex(self.hit_rva), "size": 5}]
        found = agent.handle("patches", {"rows": rows, "sha256": self.digest})
        self.assertEqual((found["checked"], found["patched"]), (2, 1))
        spare, untouched = found["rows"]
        self.assertTrue(spare["patched"])
        self.assertEqual(spare["file_bytes"], spaced(self.info["SPAREBYTES"], 5))
        self.assertEqual(spare["live_bytes"][:2], "E9")
        self.assertEqual(spare["patch"]["jump"], "jmp rel32")
        self.assertEqual(spare["patch"]["patcher_module"], HY_FIXTURE.name)
        self.assertEqual(int(spare["patch"]["detour"], 16), int(agent.control.exports_sync.info(str(HY_FIXTURE))["main"]["base"], 16) + self.hit_rva)
        self.assertFalse(untouched["patched"])
        self.assertNotIn("patch", untouched)

    def test_a_probe_past_a_detour_needs_accept_patch_and_the_original_prologue(self):
        agent, _ = self.patched()
        with self.assertRaisesRegex(ValueError, "live detour jmp rel32"):
            self.probe(agent, self.spare_rva)
        with self.assertRaisesRegex(ValueError, "original prologue"):
            self.probe(agent, self.spare_rva, expect="90 90 90 90 90", accept_patch=True)
        self.assertEqual(agent.scripts, {}, "a refused probe loads nothing")
        installed = self.probe(agent, self.spare_rva, accept_patch=True)
        self.assertTrue(installed["verified"])
        self.assertEqual(installed["past_patch"]["jump"], "jmp rel32")

    def test_the_probe_past_a_detour_fires_through_it(self):
        agent, go = self.patched()
        hook = self.probe(agent, self.spare_rva, accept_patch=True, capture=[{"arg": 0, "as": "u64"}])["hook_id"]
        go.write_text("go")
        entered = wait_until("three enters through the detour", lambda: (lambda e: e if len(e) >= 3 else None)(self.events(agent, hook, "enter")))
        self.assertEqual([row["decoded"][0]["value"] for row in entered[:3]], [0, 1, 2])
        agent.handle("unload", {"hook_id": hook})
        after = bytes(agent.control.exports_sync.read(hex(int(agent.control.exports_sync.info(str(HY_FIXTURE))["main"]["base"], 16) + self.spare_rva), 1))
        self.assertEqual(after, b"\xe9", "unloading the probe leaves the other tool's detour in place")


@unittest.skipUnless(READY and FIXTURE, SKIP)
class MCP(unittest.TestCase):
    """The real stdio MCP server with a worker on the Rust device (a `frida` directory that is not a stand-in)."""

    @classmethod
    def setUpClass(cls):
        from test_mcp_runtime import Server
        cls.info = fixture_info()
        cls.work = workdir("rt-mcp-")
        cls.root = Path(cls.work.name)
        package = cls.root / "runtime-backend" / "frida-17.24.3" / "frida"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("__version__ = '17.24.3'\n")        # the backend gate only; not HYDRALYSIS_STAND_IN
        cls.exe = str(HY_FIXTURE.resolve())
        cls.digest = hashlib.sha256(HY_FIXTURE.read_bytes()).hexdigest()
        cls.first = Server(cls.root, HYDRALYSIS_IMPL="rust", HYDRALYSIS_HARNESS="harness-a")
        cls.second = Server(cls.root, HYDRALYSIS_IMPL="rust", HYDRALYSIS_HARNESS="harness-b")
        cls.children = []

    @classmethod
    def tearDownClass(cls):
        for server in (cls.first, cls.second):
            server.close()
        for child in cls.children:
            child.kill()
            child.wait(10)
        end = time.monotonic() + 10
        while Path(cls.work.name).exists() and time.monotonic() < end:
            cls.work.cleanup()
            time.sleep(0.1)

    def call(self, server, action, error=False, **options):
        result, _ = server.tool("runtime", {"action": action, "options": options})
        text = result["content"][0]["text"]
        self.assertEqual(result["isError"], error, text[:1500])
        return text if error else json.loads(text)

    def driven(self, server, started):
        """End the session when the test does, so a failing test cannot hold the program for the next one."""
        def release():
            result, _ = server.tool("runtime", {"action": "detach", "options": {"session": started["session"], "owner": started.get("owner", "")}})
            return result
        self.addCleanup(release)
        return started

    def spawned(self, *argv, **options):
        started = self.call(self.first, "spawn", exe=self.exe, sha256=self.digest, argv=[str(a) for a in argv], **options)
        self.children.append(_Pid(int(started["worker"]["target"]["pid"])))
        return self.driven(self.first, started)

    def test_the_session_runs_on_the_rust_device(self):
        proof = self.root / "device.txt"
        started = self.spawned("env", proof)
        self.assertEqual(self.call(self.first, "status", session=started["session"])["state"], "spawn_paused")
        self.call(self.first, "resume", session=started["session"])
        wait_until("the target runs", lambda: proof.is_file())
        self.call(self.first, "detach", session=started["session"])

    def test_spawn_honours_cwd_and_env(self):
        target = self.root / "game-dir"
        target.mkdir(exist_ok=True)
        proof = self.root / "cwd-env.txt"
        started = self.spawned("env", proof, cwd=str(target), env={"RRE_PROOF": "from-caller"})
        self.assertEqual(started["cwd"], str(target.resolve()))
        self.assertEqual(started["env_keys"], ["RRE_PROOF"])
        self.call(self.first, "resume", session=started["session"])
        text = wait_until("the proof file", lambda: proof.is_file() and proof.read_text())
        cwd, value, leaked, pythonpath, _ = text.split("|")
        self.assertEqual(Path(cwd).resolve(), target.resolve())
        self.assertEqual((value, leaked), ("from-caller", "none"))
        self.assertEqual(pythonpath, str(HERE.parent / "src"), "the server's own PYTHONPATH, not the worker's private backend path")
        self.assertEqual(self.call(self.first, "modules", session=started["session"])["total"] >= 1, True)
        self.call(self.first, "detach", session=started["session"])

    def test_the_second_harness_reads_but_cannot_drive_or_attach(self):
        target = subprocess.Popen([self.exe, "write"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        self.children.append(target)
        started = self.driven(self.first, self.call(self.first, "attach", exe=self.exe, sha256=self.digest, pid=target.pid))
        session = started["session"]
        self.assertTrue(started["owner"])
        refused = self.call(self.second, "attach", error=True, exe=self.exe, sha256=self.digest, pid=target.pid)
        self.assertIn("harness-a", refused)
        modules = self.call(self.second, "modules", session=session)
        self.assertIn(HY_FIXTURE.name.lower(), [m["name"].lower() for m in modules["modules"]])
        self.assertGreaterEqual(self.call(self.second, "threads", session=session)["total"], 1)
        self.assertIn("state", self.call(self.second, "status", session=session))
        info = self.call(self.second, "read", session=session, module=HY_FIXTURE.name, rva="0x0", size=2)
        self.assertEqual(info["bytes"], "4D 5A")
        for action, options in (("detach", {}), ("resume", {}),
                                ("observe", {"module": HY_FIXTURE.name, "rva": hex(int(self.info["RVA"], 16)), "sha256": self.digest,
                                             "expect": spaced(self.info["BYTES"], 8)})):
            denied = self.call(self.second, action, error=True, session=session, **options)
            self.assertIn("owned by", denied, action)
            self.assertIn("harness-a", denied, action)
        self.assertEqual(self.call(self.second, "detach", session=session, owner=started["owner"])["state"], "detached")
        again = self.call(self.second, "attach", exe=self.exe, sha256=self.digest, pid=target.pid)
        self.assertEqual(self.call(self.second, "detach", session=again["session"])["state"], "detached")

    def attached_patched(self):
        go = self.root / ("go-" + uuid.uuid4().hex[:8])
        target = subprocess.Popen([self.exe, "patched", str(go)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
        self.children.append(target)
        self.assertIn(b"PATCHED", target.stdout.readline())
        started = self.driven(self.first, self.call(self.first, "attach", exe=self.exe, sha256=self.digest, pid=target.pid))
        return started["session"], go

    def test_live_patch_is_reported_over_mcp(self):
        session, _ = self.attached_patched()
        spare = int(self.info["SPARE"], 16)
        found = self.call(self.first, "patches", session=session, sha256=self.digest,
                          rows=[{"module": HY_FIXTURE.name, "rva": hex(spare), "size": 5}])
        row = found["rows"][0]
        self.assertTrue(row["patched"])
        self.assertEqual(row["file_bytes"], spaced(self.info["SPAREBYTES"], 5))
        self.assertEqual(row["patch"]["jump"], "jmp rel32")
        self.assertEqual(row["patch"]["patcher_module"], HY_FIXTURE.name)
        self.call(self.first, "detach", session=session)

    def test_probe_past_a_detour_only_with_accept_patch_over_mcp(self):
        session, go = self.attached_patched()
        spare = int(self.info["SPARE"], 16)
        original = spaced(self.info["SPAREBYTES"], 5)
        site = {"session": session, "module": HY_FIXTURE.name, "rva": hex(spare), "sha256": self.digest}
        refused = self.call(self.first, "observe", error=True, **site, expect=original)
        self.assertIn("live detour jmp rel32", refused)
        wrong = self.call(self.first, "observe", error=True, **site, expect="90 90 90 90 90", accept_patch=True)
        self.assertIn("original prologue", wrong)
        probe = self.call(self.first, "observe", **site, expect=original, accept_patch=True, limit=3)
        self.assertTrue(probe["verified"])
        self.assertEqual(probe["past_patch"]["jump"], "jmp rel32")
        go.write_text("go")
        events = wait_until("three enters", lambda: (lambda e: e if len([x for x in e if x.get("event") == "enter"]) >= 3 else None)(
            self.hook_events(session, probe["hook_id"])))
        self.assertEqual(sorted(int(x["arguments"][0], 16) for x in events if x.get("event") == "enter"), [0, 1, 2])
        self.call(self.first, "detach", session=session)

    def hook_events(self, session, hook):
        listed = self.call(self.first, "status", session=session, limit=200)["events"]
        return [e["message"]["payload"] for e in listed if (e["message"].get("payload") or {}).get("hook_id") == hook]


class _Pid:
    """A process this test only knows by pid (a spawned target the worker owns): kill it when the class ends."""

    def __init__(self, pid: int):
        self.pid = pid

    def kill(self):
        subprocess.run(["taskkill", "/F", "/PID", str(self.pid)], capture_output=True, timeout=30)

    def wait(self, timeout):
        pass


if __name__ == "__main__":
    unittest.main()
