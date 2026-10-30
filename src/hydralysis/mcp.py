"""Stdio MCP server. Newline JSON by default; legacy framed input is echoed.

The tool list is the dispatch table in api.py. Nothing else is registered.

Concurrency: tools run on three lanes, each with its own threads and its own outstanding budget, sized from the CPUs
the OS grants this process (`os.process_cpu_count()`, which honours affinity and PYTHON_CPU_COUNT):

- `fast`: offline PE tools and the evidence store (CPU work in this process);
- `engine`: the short tools that wait on the Hydra daemon (queries, job/backend control, runtime requests);
- `long`: the tools that can hold the engine for minutes (`ghidra_run`, `prepare`), so they never take the threads the
  short engine tools need.

On the two engine lanes every accepted call has its own thread at once (workers == outstanding): no accepted call waits
in a queue behind another call that is blocked on an engine socket. A call that finds its lane full is answered at once
with a `Server busy` tool error that carries the retry hint twice: in the text (for an agent reading prose) and as
`structuredContent.retryAfterMs` (for a client that parses). Clients that predate structuredContent (MCP 2025-06-18)
ignore the extra field and still have the text.

Cancellation: `notifications/cancelled` for an accepted, unanswered tool call fires that call's token
(hydralysis.cancel). A call still queued never starts; a running call's engine wait sends `cancel` to the engine and
returns; no response is sent for a cancelled request (MCP: the receiver SHOULD NOT respond), and its lane slot is freed.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor

from hydralysis import __version__
from hydralysis import cancel, compat, environment
from hydralysis.api import TOOL_NAMES, call, catalog, instructions, tool_table

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "hydralysis", "version": __version__}
MAX_OUTPUT_BYTES = 128 * 1024
RETRY_AFTER_MS = 2000
# Tools that talk to the engine (directly or through a workflow). Everything else is
# local/offline (PE-only tools and the evidence store) and runs on the fast lane.
ENGINE_TOOLS = frozenset({"ghidra_run", "ghidra_query", "backend", "prepare", "job", "runtime"})
# The engine tools that can hold the engine for minutes: a user script, an adopt or import. They get their own lane.
LONG_TOOLS = frozenset({"ghidra_run", "prepare"})
# The bounds of the short engine lane (README and docs/data/claims.json quote them): 2 calls per granted CPU.
ENGINE_SLOTS_MIN = 8
ENGINE_SLOTS_MAX = 32


class Lane:
    __slots__ = ("name", "workers", "outstanding")

    def __init__(self, name: str, workers: int, outstanding: int):
        if not 1 <= workers <= outstanding:
            raise ValueError("lane %s: need 1 <= workers <= outstanding" % name)
        self.name, self.workers, self.outstanding = name, workers, outstanding

    def __repr__(self):
        return "Lane(%r, workers=%d, outstanding=%d)" % (self.name, self.workers, self.outstanding)


def granted_cpus() -> int:
    """The CPUs the OS grants this process (affinity, PYTHON_CPU_COUNT), not the machine's count."""
    count = os.process_cpu_count() if hasattr(os, "process_cpu_count") else None
    return max(1, int(count or os.cpu_count() or 1))


def lane_sizes(cpus: int | None = None) -> dict[str, Lane]:
    """Lane sizes from the granted CPUs. Every budget is at least the 0.6.0 one (4 workers, 8 outstanding per lane), so
    a small machine never gets less than before.

    fast: CPU work under the GIL, so workers follow the CPUs (4..16) and a short queue is fine (outstanding 2x, >= 8).
    engine: threads that wait on a socket, not on a CPU: 2 per CPU, 8..32, each with its own thread.
    long: one per CPU, 8..16, each with its own thread; the engine itself admits and schedules the work.
    """
    cpus = granted_cpus() if cpus is None else max(1, int(cpus))
    fast = min(16, max(4, cpus))
    engine = min(ENGINE_SLOTS_MAX, max(ENGINE_SLOTS_MIN, 2 * cpus))
    long = min(16, max(8, cpus))
    return {"fast": Lane("fast", fast, max(8, 2 * fast)),
            "engine": Lane("engine", engine, engine),
            "long": Lane("long", long, long)}


LANES = lane_sizes()
# The names of 0.6.0, for callers and tests that import them: the short engine lane's budget.
TOOL_WORKERS = LANES["engine"].workers
MAX_OUTSTANDING = LANES["engine"].outstanding
FAST_WORKERS = LANES["fast"].workers


_ENVIRONMENT: dict | None = None


def _environment() -> dict:
    """The environment report of this launch, computed once. Reads files only; never starts the engine."""
    global _ENVIRONMENT
    if _ENVIRONMENT is None:
        _ENVIRONMENT = environment.describe()
    return _ENVIRONMENT


def lane_of(name) -> str:
    if not isinstance(name, str) or name not in ENGINE_TOOLS:
        return "fast"
    return "long" if name in LONG_TOOLS else "engine"


def _request_key(msg_id):
    """1 and "1" are different JSON-RPC ids; True is not 1."""
    return (type(msg_id).__name__, msg_id) if isinstance(msg_id, (str, int)) and not isinstance(msg_id, bool) else None


class Server:
    def __init__(self, lanes: dict[str, Lane] | None = None):
        self.protocol = PROTOCOL_VERSIONS[0]
        self.lanes = dict(lanes or LANES)

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
                # The tool table is cached for the life of this session (listChanged is false): the epoch
                # and hash say which table the session was started with.
                "_meta": {"hydralysis/catalog": catalog(), "hydralysis/environment": _environment()},
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
        # The launch banner: root, configuration, engine release and file system, once, on stderr (stdout is the transport).
        environment.announce(_environment())
        stdin = stdin if stdin is not None else sys.stdin.buffer
        stdout = stdout if stdout is not None else sys.stdout.buffer
        output_lock = threading.Lock()
        lanes = self.lanes
        slots = {name: threading.BoundedSemaphore(lane.outstanding) for name, lane in lanes.items()}
        # Accepted and unanswered tool calls by request id: their cancel tokens.
        inflight: dict = {}
        inflight_lock = threading.Lock()

        def write(response, framed):
            if response is not None:
                with output_lock:
                    _write_message(stdout, response, framed=framed)

        def dispatch(message, framed, token=None):
            try:
                response = self.handle(message)
            except Exception:
                sys.stderr.write(traceback.format_exc())
                if message.get("id") is not None:
                    response = _err(message["id"], -32603, "internal error")
                else:
                    response = None
            if token is not None and token.cancelled:
                return   # MCP: no response for a cancelled request
            write(response, framed)

        def work(message, framed, lane, token, key):
            try:
                if not token.cancelled:   # cancelled while queued: never started
                    with cancel.scope(token):
                        dispatch(message, framed, token)
            finally:
                if key is not None:
                    with inflight_lock:
                        if inflight.get(key) is token:
                            del inflight[key]
                slots[lane].release()

        def cancelled(params):
            key = _request_key(params.get("requestId")) if isinstance(params, dict) else None
            if key is None:
                return
            with inflight_lock:
                token = inflight.get(key)
            if token is not None:
                reason = params.get("reason")
                token.cancel(str(reason) if isinstance(reason, str) else "cancelled by the client")

        # Keep reading control messages while bounded workers run tools. Each lane has
        # a queue bound because ThreadPoolExecutor's own queue is unbounded. Leaving the
        # with block waits for every accepted call, so shutdown answers them all first.
        with contextlib.ExitStack() as stack:
            pools = {name: stack.enter_context(ThreadPoolExecutor(max_workers=lane.workers,
                                                                  thread_name_prefix="hydralysis-" + name))
                     for name, lane in lanes.items()}
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
                    if message["method"] == "notifications/cancelled":
                        cancelled(message.get("params"))
                    continue
                if message["method"] == "tools/call":
                    lane = lane_of(message["params"].get("name") if "params" in message else None)
                    if slots[lane].acquire(blocking=False):
                        token = cancel.Token()
                        key = _request_key(message["id"])
                        if key is not None:
                            with inflight_lock:
                                inflight[key] = token
                        pools[lane].submit(work, message, framed, lane, token, key)
                    else:
                        outstanding = lanes[lane].outstanding
                        write(_tool_result(message["id"],
                            "Server busy: %d %s tool calls are outstanding. "
                            "Retry this call in about %d ms (retryAfterMs=%d), or after a result arrives."
                            % (outstanding, lane, RETRY_AFTER_MS, RETRY_AFTER_MS),
                            error=True,
                            structured={"error": "busy", "lane": lane, "outstanding": outstanding,
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
