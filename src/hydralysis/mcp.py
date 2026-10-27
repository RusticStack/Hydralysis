"""Stdio MCP server. Newline JSON by default; legacy framed input is echoed.

The tool list is the dispatch table in api.py. Nothing else is registered.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor

from hydralysis import __version__
from hydralysis import compat
from hydralysis.api import TOOL_NAMES, call, instructions, tool_table

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "hydralysis", "version": __version__}
MAX_OUTPUT_BYTES = 128 * 1024
TOOL_WORKERS = 4
MAX_OUTSTANDING = 8


class Server:
    def __init__(self):
        self.protocol = PROTOCOL_VERSIONS[0]

    def handle(self, message: dict) -> dict | None:
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}
        if method == "initialize":
            want = params.get("protocolVersion")
            self.protocol = want if want in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            # The client's own name labels every engine request, overlay and claim, so
            # several harnesses sharing one engine can tell who holds what.
            client = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
            if client.get("name") and not compat.env("HARNESS"):
                from hydralysis import hydra
                hydra.set_harness(str(client["name"]))
            return _ok(msg_id, {
                "protocolVersion": self.protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
                "instructions": instructions(),
            })
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if method == "ping":
            return _ok(msg_id, {})
        if method == "tools/list":
            return _ok(msg_id, {"tools": tool_table()})
        if method == "tools/call":
            name = params.get("name")
            try:
                if name not in TOOL_NAMES:
                    raise ValueError("unknown tool %s" % name)
                text = call(name, params.get("arguments"))
                return _tool_result(msg_id, text)
            except Exception as exc:
                detail = "%s: %s" % (type(exc).__name__, exc)
                return _tool_result(msg_id, detail, error=True)
        if method in ("resources/list", "resources/templates/list"):
            return _ok(msg_id, {"resources": []} if "templates" not in method else {"resourceTemplates": []})
        if method == "prompts/list":
            return _ok(msg_id, {"prompts": []})
        if msg_id is None:
            return None
        return _err(msg_id, -32601, "method not found: %s" % method)

    def serve(self, stdin=None, stdout=None) -> None:
        stdin = stdin if stdin is not None else sys.stdin.buffer
        stdout = stdout if stdout is not None else sys.stdout.buffer
        output_lock = threading.Lock()
        slots = threading.BoundedSemaphore(MAX_OUTSTANDING)

        def write(response, framed):
            if response is not None:
                with output_lock:
                    _write_message(stdout, response, framed=framed)

        def dispatch(message, framed):
            try:
                response = self.handle(message)
            except Exception:
                sys.stderr.write(traceback.format_exc())
                if message.get("id") is not None:
                    response = _err(message["id"], -32603, "internal error")
                else:
                    response = None
            write(response, framed)

        def work(message, framed):
            try:
                dispatch(message, framed)
            finally:
                slots.release()

        # Keep reading control messages while bounded workers run expensive tools.
        # A queue bound matters: ThreadPoolExecutor's own queue is unbounded.
        with ThreadPoolExecutor(max_workers=TOOL_WORKERS, thread_name_prefix="hydralysis") as pool:
            while True:
                try:
                    message, framed = _read_envelope(stdin)
                except _ParseError as exc:
                    write(_err(None, -32700, "parse error: %s" % exc), exc.framed)
                    continue
                if message is None:
                    return
                if not isinstance(message, dict) or not isinstance(message.get("method"), str):
                    write(_err(None, -32600, "invalid request"), framed)
                    continue
                if "params" in message and not isinstance(message["params"], dict):
                    write(_err(message.get("id"), -32602, "params must be an object"), framed)
                    continue
                if "id" not in message:
                    # Notifications never receive replies or consume a tool slot.
                    continue
                if message["method"] == "tools/call":
                    if slots.acquire(blocking=False):
                        pool.submit(work, message, framed)
                    else:
                        write(_tool_result(message["id"],
                            "Server busy: %d tool calls are outstanding. "
                            "Wait for a result before retrying this call." % MAX_OUTSTANDING,
                            error=True), framed)
                else:
                    dispatch(message, framed)


def _ok(msg_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _tool_result(msg_id, text: str, error: bool = False) -> dict:
    encoded = str(text).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        marker = ("\n[OUTPUT TRUNCATED: original %d UTF-8 bytes; only the head and tail "
                  "are shown within a %d-byte limit. Middle output was discarded. "
                  "Narrow the query or use a smaller page.]\n" % (len(encoded), MAX_OUTPUT_BYTES)).encode("utf-8")
        budget = MAX_OUTPUT_BYTES - len(marker)
        head = encoded[:budget // 2].decode("utf-8", errors="ignore")
        tail = encoded[-(budget - budget // 2):].decode("utf-8", errors="ignore")
        text = head + marker.decode("utf-8") + tail
        error = True
    return _ok(msg_id, {"content": [{"type": "text", "text": str(text)}], "isError": error})


class _ParseError(ValueError):
    def __init__(self, detail: str, framed: bool):
        super().__init__(detail)
        self.framed = framed


def _read_message(stdin) -> dict | None:
    return _read_envelope(stdin)[0]


def _read_envelope(stdin) -> tuple[dict | None, bool]:
    while True:
        first = stdin.readline()
        if not first:
            return None, False
        if first.strip():
            break
    framed = first.lower().startswith(b"content-length:")
    try:
        if framed:
            length = int(first.split(b":", 1)[1].strip())
            if length < 0:
                raise ValueError("negative Content-Length")
            while True:
                line = stdin.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            body = stdin.read(length)
            if len(body) != length:
                raise ValueError("incomplete Content-Length body")
        else:
            body = first.strip()
        message = json.loads(body.decode("utf-8"))
        # JSON null is not EOF; let the request validator reject it.
        if message is None:
            message = []
        return message, framed
    except (ValueError, UnicodeError) as exc:
        raise _ParseError(str(exc), framed) from exc


def _write_message(stdout, payload: dict, *, framed: bool = False) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if framed:
        stdout.write(b"Content-Length: %d\r\n\r\n" % len(body))
        stdout.write(body)
    else:
        stdout.write(body + b"\n")
    stdout.flush()
