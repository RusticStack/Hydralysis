"""The native MCP host (native/hydralysis-mcp) against the Python server: the same wire bytes for the same requests.

The tests that need the binary skip when it is not built (python tools/build_mcp_host.py, or HYDRALYSIS_MCP_BIN).
"""

from __future__ import annotations

import json
import os
import queue
import struct
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from support import WorkDir

from hydralysis import api, mcp, mcp_launch

REPOSITORY = Path(__file__).resolve().parent.parent
SOURCE = REPOSITORY / "src"


def binary() -> str | None:
    explicit = os.environ.get("HYDRALYSIS_MCP_BIN")
    if explicit:
        return explicit if Path(explicit).is_file() else None
    for candidate in (REPOSITORY / "native" / "hydralysis-mcp" / "target" / "release" / mcp_launch.BINARY,
                      SOURCE / "hydralysis" / "bin" / mcp_launch.BINARY):
        if candidate.is_file():
            return str(candidate)
    return None


BINARY = binary()
needs_binary = unittest.skipUnless(BINARY, "hydralysis-mcp is not built (python tools/build_mcp_host.py)")


# ---- a small PE32+ with code, strings, pdata, imports and (optionally) a version resource -------------------------

def _utf16(text: str) -> bytes:
    return text.encode("utf-16le") + b"\0\0"


def _pad4(blob: bytes) -> bytes:
    return blob + b"\0" * (-len(blob) % 4)


def _block(key: str, value: bytes, children: bytes, kind: int, value_length: int) -> bytes:
    head = _pad4(struct.pack("<HHH", 0, value_length, kind) + _utf16(key))
    body = _pad4(head + value) + children
    return struct.pack("<H", len(body)) + body[2:]


def version_resource(version: str, copyright_text: str) -> bytes:
    def string(key, value):
        return _pad4(_block(key, _utf16(value), b"", 1, len(value) + 1))
    table = _block("040904B0", b"", string("FileVersion", version) + string("LegalCopyright", copyright_text), 1, 0)
    info = _block("StringFileInfo", b"", _pad4(table), 1, 0)
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x10000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return _block("VS_VERSION_INFO", fixed, _pad4(info), 0, len(fixed))


def build_pe(path: Path, *, version: str | None = None) -> Path:
    """A strictly aligned PE32+ whose .text calls 0x1100, loads a string and returns; imports from KERNEL32."""
    text = bytearray(0x200)
    text[0:5] = bytes.fromhex("48895c2408")                                   # mov [rsp+8], rbx
    text[5:10] = b"\xe8" + struct.pack("<i", 0x1100 - (0x1005 + 5))           # call 0x1100
    text[10:17] = b"\x48\x8d\x05" + struct.pack("<i", 0x2000 - (0x100A + 7))  # lea rax, [rip+...] -> 0x2000
    text[17] = 0xC3
    text[0x100:0x107] = bytes.fromhex("48895c240857c3")
    rdata = bytearray(0x200)
    rdata[0:18] = b"Hello Native Host\0"
    wide = "Wide String Value".encode("utf-16le") + b"\0\0"
    rdata[0x40:0x40 + len(wide)] = wide
    pdata = bytearray(0x200)
    struct.pack_into("<IIIIII", pdata, 0, 0x1000, 0x1020, 0x2100, 0x1100, 0x1110, 0x2100)
    idata = bytearray(0x200)
    struct.pack_into("<IIIII", idata, 0, 0x4040, 0, 0, 0x40C0, 0x4060)
    struct.pack_into("<QQ", idata, 0x40, 0x4080, 0x40A0)
    struct.pack_into("<QQ", idata, 0x60, 0x4080, 0x40A0)
    idata[0x80:0x80 + 2 + 12] = struct.pack("<H", 1) + b"ExitProcess\0"
    idata[0xA0:0xA0 + 2 + 13] = struct.pack("<H", 2) + b"GetLastError\0"
    idata[0xC0:0xC0 + 13] = b"KERNEL32.dll\0"
    sections = [(b".text", 0x1000, text, 0x60000020), (b".rdata", 0x2000, rdata, 0x40000040),
                (b".pdata", 0x3000, pdata, 0x40000040), (b".idata", 0x4000, idata, 0xC0000040)]
    resource_dir = (0, 0)
    if version is not None:
        blob = version_resource(version, "(c) caf\u00e9 Corp")
        rsrc = bytearray(0x400)
        struct.pack_into("<IIHHHH", rsrc, 0, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", rsrc, 16, 16, 0x80000018)                      # type 16 -> dir at 0x18
        struct.pack_into("<IIHHHH", rsrc, 0x18, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", rsrc, 0x28, 1, 0x80000030)                     # id 1 -> dir at 0x30
        struct.pack_into("<IIHHHH", rsrc, 0x30, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", rsrc, 0x40, 0x409, 0x48)                       # lang -> data entry at 0x48
        struct.pack_into("<IIII", rsrc, 0x48, 0x5000 + 0x60, len(blob), 0, 0)
        rsrc[0x60:0x60 + len(blob)] = blob
        sections.append((b".rsrc", 0x5000, rsrc, 0x40000040))
        resource_dir = (0x5000, 0x400)
    header = bytearray(0x400)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x84, 0x8664, len(sections), 0x5F5E1000, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<HBB", header, optional, 0x20B, 14, 0)
    struct.pack_into("<IIIII", header, optional + 4, 0x200, 0x600, 0, 0x1000, 0x1000)
    struct.pack_into("<Q", header, optional + 24, 0x140000000)
    struct.pack_into("<II", header, optional + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", header, optional + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<IIII", header, optional + 56, 0x6000, 0x400, 0, 3)
    struct.pack_into("<I", header, optional + 108, 16)
    directories = optional + 112
    struct.pack_into("<II", header, directories + 8, 0x4000, 0x28)           # import
    struct.pack_into("<II", header, directories + 16, *resource_dir)        # resource
    struct.pack_into("<II", header, directories + 24, 0x3000, 0x18)         # exception
    table = optional + 240
    data = bytearray(header)
    offset = 0x400
    for index, (name, rva, content, flags) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", data, table + 40 * index, name, len(content), rva, len(content), offset,
                         0, 0, 0, 0, flags)
        data += content
        offset += len(content)
    path.write_bytes(bytes(data))
    return path


def reference(tool: str, arguments: dict) -> str:
    """What the Python server says for the call: the text, or `Type: message` of the error it raised."""
    try:
        return api.call(tool, arguments)
    except Exception as exc:   # the server turns any exception into a tool error
        return "%s: %s" % (type(exc).__name__, exc)


class Host:
    """The native host on pipes; replies are read by a thread so a test can wait with a timeout."""

    def __init__(self, extra_env: dict | None = None, python_path: str | None = None):
        env = dict(os.environ)
        env.update({"HYDRALYSIS_PYTHON": sys.executable, "HYDRALYSIS_MCP_ENV_TTL_S": "0",
                    "PYTHONPATH": python_path or str(SOURCE)})
        env.update(extra_env or {})
        self.process = subprocess.Popen([BINARY], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
        self.lines: queue.Queue = queue.Queue()
        self.counter = 0
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def send(self, message: dict | bytes) -> None:
        raw = message if isinstance(message, bytes) else json.dumps(message).encode("utf-8") + b"\n"
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def line(self, timeout: float = 60.0) -> bytes | None:
        return self.lines.get(timeout=timeout)

    def request(self, method: str, params: dict | None = None, timeout: float = 60.0) -> bytes:
        self.counter += 1
        message = {"jsonrpc": "2.0", "id": self.counter, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        return self.line(timeout)

    def call(self, tool: str, arguments: dict | None = None) -> dict:
        params = {"name": tool}
        if arguments is not None:
            params["arguments"] = arguments
        return json.loads(self.request("tools/call", params))["result"]

    def close(self):
        try:
            self.process.stdin.close()
            self.process.wait(timeout=30)
        finally:
            if self.process.poll() is None:
                self.process.kill()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def python_line(message: dict) -> bytes:
    """The line the Python server writes for MESSAGE."""
    response = mcp.Server().handle(message)
    return json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"


class CatalogFile(unittest.TestCase):
    def test_checked_in_catalog_matches_api_and_mcp(self):
        sys.path.insert(0, str(REPOSITORY / "tools"))
        try:
            import gen_mcp_catalog
        finally:
            sys.path.pop(0)
        current = gen_mcp_catalog.TARGET.read_text(encoding="utf-8").replace("\r\n", "\n")   # autocrlf checkouts
        self.assertEqual(current, gen_mcp_catalog.render(), "run python tools/gen_mcp_catalog.py")

    def test_catalog_epoch_and_budget_are_unchanged(self):
        data = json.loads((REPOSITORY / "native" / "hydralysis-mcp" / "catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(data["epoch"], 5)
        self.assertEqual(data["hash"], api.catalog_hash())
        self.assertLess(len(json.dumps(data["tools"]).encode("utf-8")), 9216)


class Launcher(unittest.TestCase):
    def test_mode_and_binary_lookup(self):
        self.assertEqual(mcp_launch.mode({}), "auto")
        self.assertEqual(mcp_launch.mode({"HYDRALYSIS_MCP": "Python"}), "python")
        self.assertEqual(mcp_launch.mode({"HYDRALYSIS_MCP": "native"}), "native")
        self.assertEqual(mcp_launch.mode({"HYDRALYSIS_MCP": "other"}), "auto")
        self.assertIsNone(mcp_launch.find_binary({"HYDRALYSIS_MCP_BIN": str(REPOSITORY / "missing.exe")}))

    def test_python_mode_and_missing_binary_fall_back_to_the_python_server(self):
        self.assertIsNone(mcp_launch.run_native({"HYDRALYSIS_MCP": "python"}))
        with patch.object(mcp_launch, "find_binary", return_value=None):
            self.assertIsNone(mcp_launch.run_native({}))
            self.assertEqual(mcp_launch.run_native({"HYDRALYSIS_MCP": "native"}), 2)

    def test_hydralysis_mcp_command_prefers_the_native_host_then_the_python_server(self):
        from hydralysis.cli import main
        with patch.object(mcp_launch, "run_native", return_value=7), patch.object(mcp.Server, "serve") as serve:
            self.assertEqual(main(["mcp"]), 7)
            serve.assert_not_called()
        with patch.object(mcp_launch, "run_native", return_value=None), patch.object(mcp.Server, "serve") as serve:
            self.assertEqual(main(["mcp"]), 0)
            serve.assert_called_once()


@needs_binary
class Wire(unittest.TestCase):
    def test_control_messages_are_byte_identical_to_the_python_server(self):
        with Host() as host:
            for method, params in (("ping", None), ("tools/list", None), ("resources/list", None),
                                   ("resources/templates/list", None), ("prompts/list", None),
                                   ("nonsense/method", None),
                                   ("initialize", {"protocolVersion": "2025-06-18"}),
                                   ("initialize", {"protocolVersion": "1999-01-01", "capabilities": {}})):
                with self.subTest(method=method, params=params):
                    message = {"jsonrpc": "2.0", "id": 1, "method": method}
                    if params is not None:
                        message["params"] = params
                    host.send(message)
                    self.assertEqual(host.line(), python_line(message))

    def test_notifications_and_requests_without_a_reply_stay_silent(self):
        with Host() as host:
            host.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            host.send({"jsonrpc": "2.0", "id": 9, "method": "notifications/initialized"})
            host.send({"jsonrpc": "2.0", "id": None, "method": "no/such"})
            host.send({"jsonrpc": "2.0", "method": "no/such"})
            self.assertEqual(json.loads(host.request("ping"))["id"], 1)   # the first line out is the ping's

    def test_ids_of_every_json_type_are_echoed_like_python(self):
        with Host() as host:
            for ident in ("a", 7, None, 1.5, "ü"):
                message = {"jsonrpc": "2.0", "id": ident, "method": "ping"}
                host.send(message)
                self.assertEqual(host.line(), python_line(message))

    def test_tools_list_is_the_python_table_with_the_python_separators(self):
        with Host() as host:
            line = host.request("tools/list")
        expected = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": api.tool_table()}}, ensure_ascii=False)
        self.assertEqual(line.decode("utf-8"), expected + "\n")

    def test_malformed_input_gets_the_json_rpc_errors_of_the_python_server(self):
        with Host() as host:
            host.send(b"{not json\n")
            self.assertEqual(json.loads(host.line())["error"]["code"], -32700)
            host.send(b"[]\n")
            self.assertEqual(host.line(), b'{"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "invalid request"}}\n')
            host.send(b"null\n")
            self.assertEqual(json.loads(host.line())["error"]["code"], -32600)
            host.send(b'{"jsonrpc":"2.0","id":5,"method":"ping","params":[1]}\n')
            self.assertEqual(host.line(), b'{"jsonrpc": "2.0", "id": 5, "error": {"code": -32602, "message": "params must be an object"}}\n')
            host.send(b'{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope"}}\n')
            reply = json.loads(host.line())["result"]
            self.assertEqual((reply["isError"], reply["content"][0]["text"]), (True, "ValueError: unknown tool nope"))
            # The session survives all of it.
            self.assertEqual(json.loads(host.request("ping"))["result"], {})

    def test_framed_input_gets_a_framed_reply(self):
        env = dict(os.environ, HYDRALYSIS_PYTHON=sys.executable, HYDRALYSIS_MCP_ENV_TTL_S="0", PYTHONPATH=str(SOURCE))
        process = subprocess.Popen([BINARY], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
        try:
            body = b'{"jsonrpc":"2.0","id":3,"method":"ping"}'
            process.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
            process.stdin.flush()
            reply = b'{"jsonrpc": "2.0", "id": 3, "result": {}}'
            expected = b"Content-Length: %d\r\n\r\n" % len(reply) + reply
            self.assertEqual(process.stdout.read(len(expected)), expected)
        finally:
            process.stdin.close()
            process.wait(timeout=30)


@needs_binary
class NativeTools(unittest.TestCase):
    """Replies of the ported tools equal the Python implementation's, and no worker is needed for them."""

    @classmethod
    def setUpClass(cls):
        cls.work = WorkDir("native")
        cls.plain = build_pe(Path(cls.work.name) / "plain.exe")
        cls.versioned = build_pe(Path(cls.work.name) / "versioned.exe", version="9.8.7.6")

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def cases(self, exe: Path) -> list[tuple[str, dict]]:
        e = str(exe)
        return [
            ("fingerprint", {"exe": e}), ("fingerprint", {"exe": e, "detail": "sections"}),
            ("imports", {"exe": e}), ("imports", {"exe": e, "pattern": "exit", "limit": 1}),
            ("imports", {"exe": e, "pattern": "^nothing$"}), ("imports", {"exe": e, "limit": 1}),
            ("function", {"exe": e, "address": "rva:0x1004"}), ("function", {"exe": e, "address": "va:0x140001100"}),
            ("function", {"exe": e, "address": "0x1100"}), ("function", {"exe": e, "address": 4352}),
            ("function", {"exe": e, "address": "rva:0x2000"}),
            ("bytes", {"exe": e, "address": "rva:0x1000"}), ("bytes", {"exe": e, "address": "rva:0x1000", "size": 64}),
            ("bytes", {"exe": e, "address": "0x2000", "size": 5}),
            ("strings", {"exe": e, "pattern": "Hello|Wide"}), ("strings", {"exe": e, "pattern": "Wide", "limit": 1}),
            ("strings", {"exe": e, "pattern": "^[A-Z]"}), ("strings", {"exe": e, "pattern": "zzzz"}),
            ("strings", {"exe": e, "pattern": ""}),
            ("sigscan", {"exe": e, "pattern": "48 89 5C 24 ??"}), ("sigscan", {"exe": e, "pattern": "48895c24", "limit": 1}),
            ("sigscan", {"exe": e, "pattern": "de ad be ef"}),
            ("callers", {"exe": e, "address": "rva:0x1100"}), ("callers", {"exe": e, "address": "0x1100", "limit": 1}),
            ("xrefs", {"exe": e, "address": "rva:0x2000"}), ("xrefs", {"exe": e, "address": "rva:0x2040", "limit": 1}),
            ("xrefs", {"exe": e, "address": "va:0x140002000"}),
        ]

    def test_ported_tools_equal_the_python_replies(self):
        with Host({"HYDRALYSIS_PYTHON": str(REPOSITORY / "no-such-python.exe")}) as host:
            for exe in (self.plain, self.versioned):
                for tool, arguments in self.cases(exe):
                    with self.subTest(tool=tool, arguments=arguments):
                        expected = reference(tool, arguments)
                        reply = host.call(tool, arguments)
                        # No Python was available: an equal reply is a native one.
                        self.assertFalse(reply["isError"], reply["content"][0]["text"][:200])
                        self.assertEqual(reply["content"][0]["text"], expected)

    def test_the_version_resource_reaches_the_header(self):
        with Host({"HYDRALYSIS_PYTHON": str(REPOSITORY / "no-such-python.exe")}) as host:
            text = host.call("fingerprint", {"exe": str(self.versioned)})["content"][0]["text"]
        self.assertIn(" version 9.8.7.6\n", text)
        self.assertIn('"file_version": "9.8.7.6"', text)

    def test_system_images_match_when_present(self):
        root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        names = [name for name in ("notepad.exe", "kernel32.dll", "ntdll.dll", "calc.exe", "cmd.exe", "user32.dll")
                 if (root / name).is_file()]
        if not names:
            self.skipTest("no system images")
        with Host() as host:
            for name in names:
                exe = str(root / name)
                header = reference("fingerprint", {"exe": exe})
                entry = header.split("entry_rva ")[1].split()[0]
                for tool, arguments in (("fingerprint", {"exe": exe}), ("imports", {"exe": exe, "limit": 200}),
                                        ("function", {"exe": exe, "address": "rva:" + entry}),
                                        ("bytes", {"exe": exe, "address": "rva:" + entry, "size": 48}),
                                        ("strings", {"exe": exe, "pattern": "Microsoft", "limit": 5}),
                                        ("sigscan", {"exe": exe, "pattern": "48 89 5C 24 ??", "limit": 5}),
                                        ("callers", {"exe": exe, "address": "rva:" + entry, "limit": 5}),
                                        ("xrefs", {"exe": exe, "address": "rva:" + entry, "limit": 5})):
                    with self.subTest(image=name, tool=tool):
                        self.assertEqual(host.call(tool, arguments)["content"][0]["text"], reference(tool, arguments))


@needs_binary
class Delegation(unittest.TestCase):
    """What the native code does not answer goes to the real Python worker, byte for byte."""

    @classmethod
    def setUpClass(cls):
        cls.work = WorkDir("delegate")
        cls.exe = build_pe(Path(cls.work.name) / "plain.exe")

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def test_unported_tools_and_error_paths_equal_the_python_replies(self):
        e = str(self.exe)
        calls = [("disasm", {"exe": e, "address": "rva:0x1000", "count": 4}), ("inspect", {"exe": e, "address": "rva:0x1100"}),
                 ("callees", {"exe": e, "address": "rva:0x1000"}), ("fingerprint", {"exe": e, "detail": "exports"}),
                 ("function", {"exe": e, "address": "rva:0xffffffff"}),       # not in a section: a ValueError
                 ("function", {"exe": str(self.exe) + ".missing", "address": "rva:0x1000"}),
                 ("bytes", {"exe": e, "address": "rva:0x1000", "size": 0}),   # limit out of range
                 ("strings", {"exe": e, "pattern": "(?i)hello"}), ("strings", {"exe": e, "pattern": "("}),
                 ("sigscan", {"exe": e, "pattern": "zz"}),
                 ("evidence_list", {"db": str(Path(self.work.name) / "evidence.db")})]
        with Host() as host:
            for tool, arguments in calls:
                with self.subTest(tool=tool, arguments=arguments):
                    reply = host.call(tool, arguments)
                    expected = reference(tool, arguments)
                    self.assertEqual(reply["content"][0]["text"], expected)
                    self.assertEqual(reply["isError"], not self._succeeds(tool, arguments))

    @staticmethod
    def _succeeds(tool, arguments):
        try:
            api.call(tool, arguments)
            return True
        except Exception:
            return False


FAKE_WORKER = '''
import json, os, sys, threading, time
log = open(os.environ["FAKE_WORKER_LOG"], "a", buffering=1)
def say(message):
    sys.stdout.write(json.dumps(message) + "\\n"); sys.stdout.flush()
log.write("start %d\\n" % os.getpid())
say({"ready": True})
def run(ident, params):
    hold = float((params.get("arguments") or {}).get("hold", 0))
    time.sleep(hold)
    say({"id": ident, "result": {"content": [{"type": "text", "text": "held %s" % params.get("name")}], "isError": False}})
for line in sys.stdin:
    message = json.loads(line)
    op = message.get("op")
    log.write("%s %s\\n" % (op, json.dumps({k: v for k, v in message.items() if k != "params"})))
    if op == "call":
        threading.Thread(target=run, args=(message["id"], message["params"])).start()
    elif op == "environment":
        say({"id": message["id"], "environment": {"version": "fake", "warnings": []}, "announce": ""})
    elif op == "exit":
        break
log.write("exit\\n")
'''


@needs_binary
class WorkerLifecycle(unittest.TestCase):
    """Spawn on demand, idle exit, cancellation and lane limits, against a stand-in worker that logs what it is told."""

    def setUp(self):
        self.work = WorkDir("worker")
        package = Path(self.work.name) / "fake" / "hydralysis"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "worker.py").write_text(FAKE_WORKER, encoding="utf-8")
        self.log = Path(self.work.name) / "worker.log"
        self.env = {"FAKE_WORKER_LOG": str(self.log), "HYDRALYSIS_WORKER_IDLE_S": "1"}
        self.fake = str(Path(self.work.name) / "fake")

    def tearDown(self):
        self.work.cleanup()

    def entries(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.is_file() else []

    def wait_for(self, predicate, seconds=15.0):
        import time
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return True
            time.sleep(0.1)
        return False

    def test_native_calls_never_start_a_worker_and_a_delegated_call_starts_one_that_idles_out(self):
        with Host(self.env, self.fake) as host:
            # The environment report is asked at launch (the one worker use of a pure native session).
            self.assertTrue(self.wait_for(lambda: any(item.startswith("environment") for item in self.entries())))
            self.assertTrue(self.wait_for(lambda: self.entries()[-1:] == ["exit"], 20.0), self.entries())
            starts = len([item for item in self.entries() if item.startswith("start")])
            for _ in range(3):
                self.assertEqual(json.loads(host.request("ping"))["result"], {})
            self.assertEqual(len([item for item in self.entries() if item.startswith("start")]), starts)
            reply = host.call("job", {"action": "status"})
            self.assertEqual(reply["content"][0]["text"], "held job")
            self.assertEqual(len([item for item in self.entries() if item.startswith("start")]), starts + 1)
            self.assertTrue(self.wait_for(lambda: self.entries()[-1:] == ["exit"], 20.0), self.entries())
            # And again on the next call: the worker is restarted, not reused after its exit.
            self.assertEqual(host.call("backend", {})["content"][0]["text"], "held backend")
            self.assertEqual(len([item for item in self.entries() if item.startswith("start")]), starts + 2)

    def test_cancelled_calls_are_forwarded_and_not_answered(self):
        with Host({**self.env, "HYDRALYSIS_WORKER_IDLE_S": "30"}, self.fake) as host:
            host.send({"jsonrpc": "2.0", "id": 41, "method": "tools/call",
                       "params": {"name": "ghidra_query", "arguments": {"hold": 1.5}}})
            self.assertTrue(self.wait_for(lambda: any(item.startswith("call") for item in self.entries())))
            host.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 41, "reason": "test"}})
            self.assertTrue(self.wait_for(lambda: any(item.startswith("cancel") for item in self.entries())))
            self.assertEqual(json.loads(host.request("ping"))["id"], host.counter)   # the next line is the ping, not 41
            import time
            time.sleep(2.0)
            self.assertTrue(host.lines.empty())

    def test_a_full_lane_answers_server_busy_with_the_retry_hint(self):
        with Host({**self.env, "HYDRALYSIS_WORKER_IDLE_S": "30"}, self.fake) as host:
            held = mcp.LONG_SLOTS
            for number in range(held):
                host.send({"jsonrpc": "2.0", "id": 100 + number, "method": "tools/call",
                           "params": {"name": "prepare", "arguments": {"hold": 2.0}}})
            host.send({"jsonrpc": "2.0", "id": 200, "method": "tools/call", "params": {"name": "prepare", "arguments": {}}})
            reply = json.loads(host.line())
            self.assertEqual(reply["id"], 200)
            self.assertTrue(reply["result"]["isError"])
            self.assertEqual(reply["result"]["structuredContent"],
                             {"error": "busy", "lane": "long", "outstanding": held, "retryAfterMs": mcp.RETRY_AFTER_MS})
            self.assertIn("retryAfterMs=%d" % mcp.RETRY_AFTER_MS, reply["result"]["content"][0]["text"])
            # The engine lane is separate: a short tool is still answered.
            self.assertEqual(host.call("job", {"hold": 0})["content"][0]["text"], "held job")


if __name__ == "__main__":
    unittest.main()
