"""Every runtime action through the real stdio MCP server, with stdin held open.

An MCP client keeps the server's stdin open and the server blocks reading it.
Children that inherited that pipe hung on Windows until their timeouts (15 s and
20 s) while the CLI answered in 0.3 s. These tests keep stdin open the same way,
start real child processes, and require every answer well inside those budgets.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from support import REPOSITORY, workdir

FAKE_FRIDA = REPOSITORY / "tests" / "fakefrida" / "frida"
BUDGET_S = 10


class Server:
    def __init__(self, root: Path, **extra):
        env = dict(os.environ)
        env.pop("RUSTICRE_CONFIG", None)
        env.update(RUSTICRE_ROOT=str(root), PYTHONPATH=str(REPOSITORY / "src"), **extra)
        self.process = subprocess.Popen([sys.executable, "-m", "rusticre", "mcp"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=str(root))
        self.replies: queue.Queue = queue.Queue()
        self.readers = [threading.Thread(target=self._read, daemon=True),
                        threading.Thread(target=self.process.stderr.read, daemon=True)]
        for reader in self.readers:
            reader.start()
        self.ident = 0
        self.request("initialize", {"protocolVersion": "2025-06-18", "clientInfo": {"name": "transport-test"}})

    def _read(self):
        for line in self.process.stdout:
            self.replies.put(json.loads(line))

    def request(self, method, params):
        self.ident += 1
        message = {"jsonrpc": "2.0", "id": self.ident, "method": method, "params": params}
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()
        started = time.monotonic()
        reply = self.replies.get(timeout=BUDGET_S + 20)
        return reply, time.monotonic() - started

    def tool(self, name, arguments):
        reply, elapsed = self.request("tools/call", {"name": name, "arguments": arguments})
        return reply["result"], elapsed

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=20)
        for reader in self.readers:
            reader.join(timeout=20)
        self.process.stdout.close()
        self.process.stderr.close()


class RuntimeOverMCP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = workdir("mcp-runtime")
        cls.root = Path(cls.work.name)
        site = cls.root / "runtime-backend" / "frida-17.24.3"
        shutil.copytree(FAKE_FRIDA, site / "frida")
        cls.exe = str(Path(sys.executable).resolve())
        cls.digest = hashlib.sha256(Path(cls.exe).read_bytes()).hexdigest()
        cls.head = " ".join("%02X" % byte for byte in Path(cls.exe).read_bytes()[:5])
        cls.server = Server(cls.root)
        cls.children: list[subprocess.Popen | int] = []

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        for child in cls.children:
            try:
                if isinstance(child, int):
                    os.kill(child, 9)  # spawned by the worker, not this test process
                else:
                    child.kill()
            except OSError:
                pass
            if not isinstance(child, int):
                child.wait(timeout=10)
        # A killed child releases its working directory a moment later on Windows.
        deadline = time.monotonic() + 10
        while Path(cls.work.name).exists() and time.monotonic() < deadline:
            cls.work.cleanup()
            time.sleep(0.1)

    def call(self, name, arguments, error=False):
        result, elapsed = self.server.tool(name, arguments)
        text = result["content"][0]["text"]
        self.assertLess(elapsed, BUDGET_S, "%s %s took %.1f s: %s" % (name, arguments.get("action"), elapsed, text[:300]))
        self.assertEqual(result["isError"], error, text[:2000])
        return text

    def runtime(self, action, **options):
        return json.loads(self.call("runtime", {"action": action, "options": options}))

    def test_backend_inspect_runtime(self):
        report = json.loads(self.call("backend", {"action": "inspect", "component": "runtime"}))
        self.assertTrue(report["ready"])

    def test_setup_reuses_an_installed_backend_as_a_job(self):
        job = json.loads(self.call("runtime", {"action": "setup"}))
        deadline = time.monotonic() + 30
        while True:
            status = json.loads(self.call("job", {"id": job["job_id"]}))
            if status["state"] in ("done", "failed", "cancelled", "cleanup_failed") or time.monotonic() > deadline:
                break
            time.sleep(0.2)
        self.assertEqual(status["state"], "done", status)

    def test_processes(self):
        self.assertTrue(self.runtime("processes", limit=5)["processes"])

    def test_spawn_session_lifecycle_honours_cwd_and_env(self):
        target = self.root / "game-dir"
        target.mkdir()
        proof = "import os,time;open('cwd-proof.txt','w').write(os.getcwd()+'|'+os.environ.get('RRE_PROOF','')+'|'+os.environ.get('RUSTICRE_TARGET_ENV_RESTORE','none'));time.sleep(60)"
        started = self.runtime("spawn", exe=self.exe, sha256=self.digest, argv=["-c", proof],
                               cwd=str(target), env={"RRE_PROOF": "from-caller"})
        session = started["session"]
        self.children.append(int(started["worker"]["target"]["pid"]))
        self.assertEqual(started["cwd"], str(target.resolve()))
        self.assertEqual(started["env_keys"], ["RRE_PROOF"])
        deadline = time.monotonic() + 10
        while not (target / "cwd-proof.txt").is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.2)
        cwd, value, leaked = (target / "cwd-proof.txt").read_text().split("|")
        self.assertEqual(Path(cwd).resolve(), target.resolve())
        self.assertEqual(value, "from-caller")
        self.assertEqual(leaked, "none")

        module = Path(self.exe).name
        self.assertIn("state", self.runtime("status", session=session))
        self.assertEqual(self.runtime("modules", session=session)["total"], 1)
        self.assertEqual(self.runtime("threads", session=session)["total"], 1)
        read = self.runtime("read", session=session, module=module, rva="0x0", size=5)
        self.assertEqual(read["bytes"], self.head)
        observed = self.runtime("observe", session=session, module=module, rva="0x0", sha256=self.digest, expect=self.head)
        self.assertTrue(observed["verified"])
        paused = self.runtime("break", session=session, module=module, rva="0x0", sha256=self.digest, expect=self.head)
        self.assertTrue(paused["verified"])
        events = self.runtime("status", session=session)["events"]
        self.assertTrue(any(event["message"].get("payload", {}).get("event") == "break" for event in events))
        self.assertEqual(self.runtime("continue", session=session)["continued"], "all")
        self.assertEqual(self.runtime("unload", session=session, hook_id=observed["hook_id"])["unloaded"], observed["hook_id"])
        self.assertEqual(self.runtime("resume", session=session)["state"], "running")
        self.assertEqual(self.runtime("detach", session=session)["state"], "detached")

    def test_probe_decodes_captured_arguments_and_samples(self):
        target = subprocess.Popen([self.exe, "-c", "import time;time.sleep(60)"], stdin=subprocess.DEVNULL)
        self.children.append(target)
        session = self.runtime("attach", exe=self.exe, sha256=self.digest, pid=target.pid)["session"]
        try:
            site = {"session": session, "module": Path(self.exe).name, "rva": "0x0", "sha256": self.digest, "expect": self.head}
            self.runtime("observe", **site, capture=[{"arg": 1, "deref": [0], "size": 8, "as": "utf8", "label": "path"}])
            sampled = self.runtime("observe", **site, capture=[{"arg": 2, "as": "f32"}], sample={"window_s": 10, "capture": 0})
            events = [event["message"]["payload"] for event in self.runtime("status", session=session, limit=200)["events"]
                      if event["message"].get("type") == "send"]
            hit = next(event for event in events if event.get("event") == "enter" and event.get("decoded"))
            self.assertEqual(hit["decoded"][0], {"arg": 1, "label": "path", "pointer": "0x140000000", "value": "ABC"})
            summary = next(event for event in events if event.get("event") == "sample" and event["hook_id"] == sampled["hook_id"])
            self.assertEqual((summary["count"], summary["max"]), (120, 4.0))
            text = self.call("runtime", {"action": "observe", "options": {**site, "sample": {"window_s": 10, "capture": 0}}}, error=True)
            self.assertIn("decoder is a number", text)
        finally:
            self.runtime("detach", session=session)

    def test_observe_without_hash_names_the_option(self):
        target = subprocess.Popen([self.exe, "-c", "import time;time.sleep(60)"], stdin=subprocess.DEVNULL)
        self.children.append(target)
        session = self.runtime("attach", exe=self.exe, sha256=self.digest, pid=target.pid)["session"]
        text = self.call("runtime", {"action": "observe", "options": {"session": session, "module": Path(self.exe).name,
                                                                         "rva": "0x0", "expect": self.head}}, error=True)
        self.assertIn("options.sha256", text)
        self.assertEqual(self.runtime("detach", session=session)["state"], "detached")

    def test_attach_requires_the_build_hash(self):
        text = self.call("runtime", {"action": "attach", "options": {"exe": self.exe, "pid": os.getpid()}}, error=True)
        self.assertIn("options.sha256", text)


class TwoHarnessesOneGame(unittest.TestCase):
    """One driving session per program; the other harness reads, and a project lock can refuse."""

    @classmethod
    def setUpClass(cls):
        cls.work = workdir("mcp-owners")
        cls.root = Path(cls.work.name)
        shutil.copytree(FAKE_FRIDA, cls.root / "runtime-backend" / "frida-17.24.3" / "frida")
        cls.exe = str(Path(sys.executable).resolve())
        cls.digest = hashlib.sha256(Path(cls.exe).read_bytes()).hexdigest()
        cls.first = Server(cls.root, RUSTICRE_HARNESS="harness-a")
        cls.second = Server(cls.root, RUSTICRE_HARNESS="harness-b")
        refuse = cls.root / "refuse.json"
        refuse.write_text(json.dumps({"runtime_lock_check": [sys.executable, "-c", "import sys; print('held by agent-x'); sys.exit(2)"]}))
        shutil.copytree(FAKE_FRIDA, cls.root / "locked-root" / "runtime-backend" / "frida-17.24.3" / "frida")
        cls.locked = Server(cls.root / "locked-root", RUSTICRE_CONFIG=str(refuse), RUSTICRE_HARNESS="harness-c")
        cls.target = subprocess.Popen([cls.exe, "-c", "import time;time.sleep(60)"], stdin=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.first, cls.second, cls.locked):
            server.close()
        cls.target.kill()
        cls.target.wait(10)
        deadline = time.monotonic() + 10
        while Path(cls.work.name).exists() and time.monotonic() < deadline:
            cls.work.cleanup()
            time.sleep(0.1)

    def tool(self, server, action, error=False, **options):
        result, elapsed = server.tool("runtime", {"action": action, "options": options})
        self.assertLess(elapsed, BUDGET_S)
        text = result["content"][0]["text"]
        self.assertEqual(result["isError"], error, text[:1500])
        return text if error else json.loads(text)

    def test_the_second_harness_reads_but_cannot_drive_or_attach(self):
        started = self.tool(self.first, "attach", exe=self.exe, sha256=self.digest, pid=self.target.pid)
        session = started["session"]
        self.assertTrue(started["owner"])
        refused = self.tool(self.second, "attach", error=True, exe=self.exe, sha256=self.digest, pid=self.target.pid)
        self.assertIn("harness-a", refused)
        self.assertEqual(self.tool(self.second, "modules", session=session)["total"], 1)
        denied = self.tool(self.second, "detach", error=True, session=session)
        self.assertIn("owned by", denied)
        self.assertIn("harness-a", denied)
        self.assertEqual(self.tool(self.second, "detach", session=session, owner=started["owner"])["state"], "detached")
        again = self.tool(self.second, "attach", exe=self.exe, sha256=self.digest, pid=self.target.pid)
        self.assertEqual(self.tool(self.second, "detach", session=again["session"])["state"], "detached")

    def test_the_projects_own_game_lock_can_refuse(self):
        refused = self.tool(self.locked, "attach", error=True, exe=self.exe, sha256=self.digest, pid=self.target.pid)
        self.assertIn("held by agent-x", refused)


class PatchedFunctionOverMCP(RuntimeOverMCP):
    """A function another tool detoured: reported with its patcher, and probed past on request."""

    @classmethod
    def setUpClass(cls):
        import pefile
        exe = Path(sys.executable).resolve()
        pe = pefile.PE(str(exe), fast_load=True)
        text = next(section for section in pe.sections if section.Characteristics & 0x20000000)
        cls.site = text.VirtualAddress + 0x10
        cls.original = " ".join("%02X" % byte for byte in pe.get_data(cls.site, 5))
        pe.close()
        cls.work = workdir("mcp-patch")
        cls.root = Path(cls.work.name)
        shutil.copytree(FAKE_FRIDA, cls.root / "runtime-backend" / "frida-17.24.3" / "frida")
        cls.exe = str(exe)
        cls.digest = hashlib.sha256(exe.read_bytes()).hexdigest()
        cls.head = " ".join("%02X" % byte for byte in exe.read_bytes()[:5])
        cls.server = Server(cls.root, RUSTICRE_FAKE_PATCH="%#x=E9 FB FF FF FF" % cls.site)
        cls.children = []

    def attached(self):
        target = subprocess.Popen([self.exe, "-c", "import time;time.sleep(60)"], stdin=subprocess.DEVNULL)
        self.children.append(target)
        return self.runtime("attach", exe=self.exe, sha256=self.digest, pid=target.pid)["session"]

    def test_live_patch_is_reported_with_the_file_bytes_and_its_patcher(self):
        session = self.attached()
        found = self.runtime("patches", session=session, sha256=self.digest,
                             rows=[{"module": Path(self.exe).name, "rva": hex(self.site), "size": 5}])
        row = found["rows"][0]
        self.assertTrue(row["patched"])
        self.assertEqual(row["file_bytes"], self.original)
        self.assertEqual(row["live_bytes"], "E9 FB FF FF FF")
        self.assertEqual(row["patch"]["jump"], "jmp rel32")
        self.assertEqual(row["patch"]["patcher_module"], Path(self.exe).name)
        table = json.loads(self.call("prologue", {"exe": self.exe, "session": session,
                                                  "checks": [{"address": "rva:%#x" % self.site, "expect": self.original}]}))
        self.assertTrue(table["matched"])
        self.assertTrue(table["rows"][0]["live_patched"])
        self.runtime("detach", session=session)

    def test_probe_past_a_detour_only_with_accept_patch_and_the_original_bytes(self):
        session = self.attached()
        site = {"session": session, "module": Path(self.exe).name, "rva": hex(self.site), "sha256": self.digest}
        refused = self.call("runtime", {"action": "observe", "options": {**site, "expect": self.original}}, error=True)
        self.assertIn("live detour jmp rel32", refused)
        wrong = self.call("runtime", {"action": "observe", "options": {**site, "expect": "90 90 90 90 90", "accept_patch": True}}, error=True)
        self.assertIn("original prologue", wrong)
        probe = self.runtime("observe", **site, expect=self.original, accept_patch=True)
        self.assertTrue(probe["verified"])
        self.assertEqual(probe["past_patch"]["jump"], "jmp rel32")
        self.runtime("detach", session=session)

    # The inherited lifecycle tests run unpatched code paths; only the patch tests matter here.
    test_spawn_session_lifecycle_honours_cwd_and_env = None
    test_observe_without_hash_names_the_option = None
    test_setup_reuses_an_installed_backend_as_a_job = None


if __name__ == "__main__":
    unittest.main()
