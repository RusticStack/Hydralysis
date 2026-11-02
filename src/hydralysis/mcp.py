"""Stdio MCP server. Newline JSON by default; legacy framed input is echoed.

The tool list is the dispatch table in api.py. Nothing else is registered.

Concurrency: tools run on three lanes, each with its own threads and its own outstanding budget, sized from the CPUs
the OS grants this process (`granted_cpus()`: the process affinity on Windows, `os.process_cpu_count()` elsewhere, and
PYTHON_CPU_COUNT / -X cpu_count when set):

- `fast`: offline PE tools and the evidence store (CPU work in this process);
- `engine`: the short tools that wait on the Hydra daemon (queries, job/backend control, runtime requests);
- `long`: the tools that can hold the engine for minutes (`ghidra_run`, `prepare`), so they never take the threads the
  short engine tools need.

On the two engine lanes every accepted call has its own thread at once (workers == outstanding): no accepted call waits
in a queue behind another call that is blocked on an engine socket. A call that finds its lane full is answered at once
with a `Server busy` tool error that carries the retry hint twice: in the text (for an agent reading prose) and as
`structuredContent.retryAfterMs` (for a client that parses). Clients that predate structuredContent (MCP 2025-06-18)
ignore the extra field and still have the text.

The two engine lanes together never admit more calls than the engine runs in parallel on one connection
(ENGINE_PARALLEL_MAX, the engine's Connection.MAX_PARALLEL): every engine call of this process shares one connection on
hydra.4, so a call the MCP accepts is never refused by the engine as busy.

Cancellation: `notifications/cancelled` for an accepted, unanswered tool call fires that call's token
(hydralysis.cancel). A call still queued never starts. A running call that waits on the engine in this process
(ghidra_run, ghidra_query, job/backend engine calls, the wait for a pool connection) sends `cancel` to the engine,
waits the grace (hydra.DEADLINE_GRACE_S) and returns, which frees its lane slot. A tool body that never reaches such a
wait (offline tools, `prepare`, whose import runs in a subprocess, runtime requests) runs to its end and holds its slot
until then; only its reply is dropped. No response is sent for a cancelled request (MCP: the receiver SHOULD NOT
respond). The cancel callbacks run on the stdin reader thread and only set events: no engine I/O happens there.
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
ENGINE_TOOLS = frozenset({"ghidra_run", "ghidra_query", "backend", "prepare", "job", "runtime", "trace"})
# The engine tools that can hold the engine for minutes: a user script, an adopt or import. They get their own lane.
LONG_TOOLS = frozenset({"ghidra_run", "prepare"})
# `trace` is a short engine-lane tool except for the actions that are jobs on the engine (export, import, resymbolize).
LONG_TRACE_ACTIONS = frozenset({"export", "import", "resymbolize", "reprocess", "relations", "evict"})
# The engine runs at most this many parallel requests per client connection (hydra-engine Connection.MAX_PARALLEL);
# more get BUSY. On hydra.4 every engine call of this process goes through one shared connection, so the engine and
# long lanes together stay within it.
ENGINE_PARALLEL_MAX = 32
# The long lane: `ghidra_run` and `prepare` hold the engine for minutes; 8 of them at once is the 0.6.0 budget.
LONG_SLOTS = 8
# The bounds of the short engine lane (README and docs/data/claims.json quote them): 2 calls per granted CPU, and
# never more than the engine's parallel limit leaves after the long lane.
ENGINE_SLOTS_MIN = 8
ENGINE_SLOTS_MAX = 24
assert ENGINE_SLOTS_MAX + LONG_SLOTS <= ENGINE_PARALLEL_MAX


class Lane:
    __slots__ = ("name", "workers", "outstanding")

    def __init__(self, name: str, workers: int, outstanding: int):
        if not 1 <= workers <= outstanding:
            raise ValueError("lane %s: need 1 <= workers <= outstanding" % name)
        self.name, self.workers, self.outstanding = name, workers, outstanding

    def __repr__(self):
        return "Lane(%r, workers=%d, outstanding=%d)" % (self.name, self.workers, self.outstanding)


def _windows_granted_cpus() -> int | None:
    """The CPUs in this process's affinity on Windows (os.process_cpu_count() ignores affinity there), or None."""
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        process_mask, system_mask = ctypes.c_size_t(0), ctypes.c_size_t(0)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.POINTER(ctypes.c_size_t),
                                                    ctypes.POINTER(ctypes.c_size_t))
        if kernel32.GetProcessAffinityMask(kernel32.GetCurrentProcess(), ctypes.byref(process_mask),
                                           ctypes.byref(system_mask)) and process_mask.value:
            return bin(process_mask.value).count("1")
        # Zero masks: the process has threads in several processor groups; it may run on every active processor.
        kernel32.GetActiveProcessorCount.restype = wintypes.DWORD
        count = kernel32.GetActiveProcessorCount(0xFFFF)   # ALL_PROCESSOR_GROUPS
        return int(count) or None
    except (OSError, AttributeError, ValueError):
        return None


def granted_cpus() -> int:
    """The CPUs the OS grants this process, not the machine's count.

    PYTHON_CPU_COUNT / -X cpu_count win when set (os.process_cpu_count() returns them). Otherwise, on Windows the
    process affinity mask (os.process_cpu_count() ignores it there), elsewhere os.process_cpu_count(), which uses
    sched_getaffinity."""
    override = os.environ.get("PYTHON_CPU_COUNT") or getattr(sys, "_xoptions", {}).get("cpu_count")
    count = None
    if sys.platform == "win32" and not override:
        count = _windows_granted_cpus()
    if count is None:
        count = os.process_cpu_count() if hasattr(os, "process_cpu_count") else None
    if count is None and hasattr(os, "sched_getaffinity"):
        count = len(os.sched_getaffinity(0))
    return max(1, int(count or os.cpu_count() or 1))


def lane_sizes(cpus: int | None = None) -> dict[str, Lane]:
    """Lane sizes from the granted CPUs. Every budget is at least the 0.6.0 one (4 workers, 8 outstanding per lane), so
    a small machine never gets less than before.

    fast: CPU work under the GIL, so workers follow the CPUs (4..16) and a short queue is fine (outstanding 2x, >= 8).
    engine: threads that wait on a socket, not on a CPU: 2 per CPU, 8..24, each with its own thread.
    long: 8, each with its own thread; the engine itself admits and schedules the work.
    engine + long never pass ENGINE_PARALLEL_MAX, the engine's parallel limit for the one shared connection.
    """
    cpus = granted_cpus() if cpus is None else max(1, int(cpus))
    fast = min(16, max(4, cpus))
    engine = min(ENGINE_SLOTS_MAX, max(ENGINE_SLOTS_MIN, 2 * cpus), ENGINE_PARALLEL_MAX - LONG_SLOTS)
    return {"fast": Lane("fast", fast, max(8, 2 * fast)),
            "engine": Lane("engine", engine, engine),
            "long": Lane("long", LONG_SLOTS, LONG_SLOTS)}


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


def lane_of(name, arguments=None) -> str:
    if not isinstance(name, str) or name not in ENGINE_TOOLS:
        return "fast"
    if name == "trace":
        action = arguments.get("action") if isinstance(arguments, dict) else None
        return "long" if action in LONG_TRACE_ACTIONS else "engine"
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
                    params = message.get("params") if isinstance(message.get("params"), dict) else {}
                    lane = lane_of(params.get("name"), params.get("arguments"))
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
