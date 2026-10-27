"""Stdio MCP server. Newline JSON by default; legacy framed input is echoed.

The tool list is the dispatch table in api.py. Nothing else is registered.

Concurrency: tools run on two lanes, `fast` (offline PE tools and the evidence store) and `engine` (every tool
that can wait on the Hydra daemon), each with FAST_WORKERS / TOOL_WORKERS threads. MAX_OUTSTANDING is a limit PER LANE:
at most 8 accepted and unanswered calls on each, so the total can reach 16. A call that finds its lane full is
answered at once with a `Server busy` tool error that carries the retry hint twice: in the text (for an agent
reading prose) and as `structuredContent.retryAfterMs` (for a client that parses). Clients that predate
structuredContent (MCP 2025-06-18) ignore the extra field and still have the text.
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
# Two lanes, each with its own workers and its own outstanding budget, so calls that
# block on the Hydra daemon can never starve or crowd out the offline PE tools.
FAST_WORKERS = 4
RETRY_AFTER_MS = 2000
# Tools that talk to the engine (directly or through a workflow). Everything else is
# local/offline (PE-only tools and the evidence store) and runs on the fast lane.
ENGINE_TOOLS = frozenset({"ghidra_run", "ghidra_query", "backend", "prepare", "job", "runtime"})


def lane_of(name) -> str:
    return "engine" if isinstance(name, str) and name in ENGINE_TOOLS else "fast"


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
        slots = {"fast": threading.BoundedSemaphore(MAX_OUTSTANDING),
                 "engine": threading.BoundedSemaphore(MAX_OUTSTANDING)}

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

        def work(message, framed, lane):
            try:
                dispatch(message, framed)
            finally:
                slots[lane].release()

        # Keep reading control messages while bounded workers run tools. Each lane has
        # a queue bound because ThreadPoolExecutor's own queue is unbounded. Leaving the
        # with block waits for every accepted call, so shutdown answers them all first.
        with ThreadPoolExecutor(max_workers=FAST_WORKERS, thread_name_prefix="hydralysis-fast") as fast_pool, \
                ThreadPoolExecutor(max_workers=TOOL_WORKERS, thread_name_prefix="hydralysis-engine") as engine_pool:
            pools = {"fast": fast_pool, "engine": engine_pool}
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
                    lane = lane_of(message["params"].get("name") if "params" in message else None)
                    if slots[lane].acquire(blocking=False):
                        pools[lane].submit(work, message, framed, lane)
                    else:
                        write(_tool_result(message["id"],
                            "Server busy: %d %s tool calls are outstanding. "
                            "Retry this call in about %d ms (retryAfterMs=%d), or after a result arrives."
                            % (MAX_OUTSTANDING, lane, RETRY_AFTER_MS, RETRY_AFTER_MS),
                            error=True,
                            structured={"error": "busy", "lane": lane, "outstanding": MAX_OUTSTANDING,
                                        "retryAfterMs": RETRY_AFTER_MS}), framed)
                else:
                    dispatch(message, framed)


def _ok(msg_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _tool_result(msg_id, text: str, error: bool = False, structured: dict | None = None) -> dict:
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
    result = {"content": [{"type": "text", "text": str(text)}], "isError": error}
    if structured is not None:
        result["structuredContent"] = structured
    return _ok(msg_id, result)


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
