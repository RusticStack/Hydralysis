"""Short-lived Python worker for the native MCP host (`hydralysis-mcp`).

The native host owns the MCP transport, the catalog, the lanes and the offline PE tools. Everything else is delegated
here: the host spawns `python -m hydralysis.worker` on the first delegated call and closes it after an idle period, so
the resident process is the native host and this interpreter lives only while a delegated tool runs.

Protocol: one JSON object per line on stdin and stdout (UTF-8, ASCII-escaped, never a raw newline).

  host -> worker  {"op": "call", "id": N, "params": <tools/call params>}
                  {"op": "cancel", "id": N, "reason": "..."}
                  {"op": "harness", "name": <clientInfo.name>}
                  {"op": "environment", "id": N}
                  {"op": "exit"}
  worker -> host  {"id": N, "result": <tools/call result>}      the exact result mcp.Server.handle builds
                  {"id": N, "error": {"code": C, "message": M}}  an internal error (Server's -32603)
                  {"id": N, "environment": <environment.describe()>, "announce": <the launch banner text>}
                  {"ready": true}                                 once, after the imports

A call runs `mcp.Server.handle` itself, so a delegated tool's reply, error envelope and truncation are the Python
server's own. The worker keeps stdout for the protocol only: file descriptor 1 is pointed at stderr for everything else.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import traceback


def main() -> int:
    protocol_fd = os.dup(1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    out = os.fdopen(protocol_fd, "wb", buffering=0)
    lock = threading.Lock()

    def send(message: dict) -> None:
        data = (json.dumps(message, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        with lock:
            out.write(data)

    from hydralysis import cancel, compat
    from hydralysis.mcp import Server

    server = Server()
    tokens: dict[int, cancel.Token] = {}
    token_lock = threading.Lock()
    state = {"harness": None}
    threads: list[threading.Thread] = []

    # The client name labels engine requests, overlays, claims and runtime sessions; the offline PE tools never read it,
    # so they do not pay for importing the engine client to set it.
    offline = frozenset({"fingerprint", "imports", "disasm", "inspect", "xrefs", "callers", "callees", "function", "bytes",
                         "strings", "sigscan"})

    harness_lock = threading.Lock()

    def apply_harness() -> None:
        with harness_lock:
            if state["harness"] is not None and not compat.env("HARNESS"):
                from hydralysis import hydra
                hydra.set_harness(str(state["harness"]))
            state["harness"] = None

    def run_call(ident: int, params: dict, token: cancel.Token) -> None:
        message = {"jsonrpc": "2.0", "id": ident, "method": "tools/call", "params": params}
        try:
            if params.get("name") not in offline:
                apply_harness()
            with cancel.scope(token):
                response = server.handle(message)
            send({"id": ident, "result": response["result"]})
        except Exception:
            sys.stderr.write(traceback.format_exc())
            send({"id": ident, "error": {"code": -32603, "message": "internal error"}})
        finally:
            with token_lock:
                tokens.pop(ident, None)

    def run_environment(ident: int) -> None:
        try:
            import io
            from hydralysis import environment
            report = environment.describe()
            banner = io.StringIO()
            environment.announce(report, banner)
            send({"id": ident, "environment": report, "announce": banner.getvalue()})
        except Exception:
            sys.stderr.write(traceback.format_exc())
            send({"id": ident, "error": {"code": -32603, "message": "internal error"}})

    send({"ready": True})
    for raw in sys.stdin.buffer:
        raw = raw.strip()
        if not raw:
            continue
        try:
            message = json.loads(raw.decode("utf-8"))
        except ValueError:
            continue
        op = message.get("op") if isinstance(message, dict) else None
        if op == "exit":
            break
        if op == "harness":
            state["harness"] = message.get("name")
        elif op == "cancel":
            with token_lock:
                token = tokens.get(message.get("id"))
            if token is not None:
                reason = message.get("reason")
                token.cancel(str(reason) if isinstance(reason, str) else "cancelled by the client")
        elif op in ("call", "environment"):
            ident = message.get("id")
            if op == "environment":
                worker = threading.Thread(target=run_environment, args=(ident,), daemon=False)
            else:
                params = message.get("params") if isinstance(message.get("params"), dict) else {}
                token = cancel.Token()
                with token_lock:
                    tokens[ident] = token
                worker = threading.Thread(target=run_call, args=(ident, params, token), daemon=False)
            threads = [item for item in threads if item.is_alive()]
            threads.append(worker)
            worker.start()
    for item in threads:
        item.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
