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
    def __init__(self, root: Path):
        env = dict(os.environ, RUSTICRE_ROOT=str(root), PYTHONPATH=str(REPOSITORY / "src"))
        env.pop("RUSTICRE_CONFIG", None)
        self.process = subprocess.Popen([sys.executable, "-m", "rusticre", "mcp"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=str(root))
        self.replies: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self.process.stderr.read, daemon=True).start()
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
        cls.children: list[int] = []

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        for pid in cls.children:
            try:
                os.kill(pid, 9)
            except OSError:
                pass
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

    def test_observe_without_hash_names_the_option(self):
        target = subprocess.Popen([self.exe, "-c", "import time;time.sleep(60)"], stdin=subprocess.DEVNULL)
        self.children.append(target.pid)
        session = self.runtime("attach", exe=self.exe, sha256=self.digest, pid=target.pid)["session"]
        text = self.call("runtime", {"action": "observe", "options": {"session": session, "module": Path(self.exe).name,
                                                                         "rva": "0x0", "expect": self.head}}, error=True)
        self.assertIn("options.sha256", text)
        self.assertEqual(self.runtime("detach", session=session)["state"], "detached")

    def test_attach_requires_the_build_hash(self):
        text = self.call("runtime", {"action": "attach", "options": {"exe": self.exe, "pid": os.getpid()}}, error=True)
        self.assertIn("options.sha256", text)


if __name__ == "__main__":
    unittest.main()
