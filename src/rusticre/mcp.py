"""Stdio MCP server. Speaks Content-Length frames and newline JSON.

The tool list is the dispatch table in api.py. Nothing else is registered.
"""

from __future__ import annotations

import json
import sys
import traceback

from rusticre import __version__
from rusticre.api import call, instructions, tool_table

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "rusticre", "version": __version__}


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
                text = call(name, params.get("arguments") or {})
                return _ok(msg_id, {"content": [{"type": "text", "text": text}], "isError": False})
            except Exception as exc:
                detail = "%s: %s" % (type(exc).__name__, exc)
                return _ok(msg_id, {"content": [{"type": "text", "text": detail}], "isError": True})
        if method in ("resources/list", "resources/templates/list"):
            return _ok(msg_id, {"resources": []} if "templates" not in method else {"resourceTemplates": []})
        if method == "prompts/list":
            return _ok(msg_id, {"prompts": []})
        if msg_id is None:
            return None
        return _err(msg_id, -32601, "method not found: %s" % method)

    def serve(self) -> None:
        stdin = sys.stdin.buffer
        stdout = sys.stdout.buffer
        while True:
            message = _read_message(stdin)
            if message is None:
                return
            try:
                response = self.handle(message)
            except Exception:
                sys.stderr.write(traceback.format_exc())
                if message.get("id") is not None:
                    response = _err(message["id"], -32603, "internal error")
                else:
                    response = None
            if response is not None:
                _write_message(stdout, response)


def _ok(msg_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _read_message(stdin) -> dict | None:
    first = stdin.readline()
    if not first:
        return None
    if first.lower().startswith(b"content-length:"):
        length = int(first.split(b":", 1)[1].strip())
        while True:
            line = stdin.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        body = stdin.read(length)
        return json.loads(body.decode("utf-8"))
    text = first.strip()
    if not text:
        return _read_message(stdin)
    return json.loads(text.decode("utf-8"))


def _write_message(stdout, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    stdout.write(b"Content-Length: %d\r\n\r\n" % len(body))
    stdout.write(body)
    stdout.flush()
