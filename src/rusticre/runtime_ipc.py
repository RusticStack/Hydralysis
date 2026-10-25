"""Bounded authenticated JSON RPC over a single local loopback connection."""

from __future__ import annotations

import hmac
import json
import math
import re
import socket
import struct
import time

MAX_FRAME = 262144


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("local IPC deadline exceeded")
    return remaining


def _deadline(connection: socket.socket, deadline: float | None) -> float:
    return deadline if deadline is not None else time.monotonic() + (connection.gettimeout() or 3)


def _exact(connection: socket.socket, length: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < length:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise ValueError("runtime IPC peer closed an incomplete frame")
        result.extend(chunk)
    return bytes(result)


def receive(connection: socket.socket, *, max_frame: int = MAX_FRAME, deadline: float | None = None) -> dict:
    deadline = _deadline(connection, deadline)
    length = struct.unpack("!I", _exact(connection, 4, deadline))[0]
    if not 1 <= length <= max_frame:
        raise ValueError("local IPC frame must be 1..%s bytes" % max_frame)
    value = json.loads(_exact(connection, length, deadline).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("runtime IPC frame must contain a JSON object")
    return value


def send(connection: socket.socket, value: dict, *, max_frame: int = MAX_FRAME, deadline: float | None = None) -> None:
    payload = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if not 1 <= len(payload) <= max_frame:
        raise ValueError("local IPC frame must be 1..%s bytes" % max_frame)
    connection.settimeout(_remaining(_deadline(connection, deadline)))
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def _uuid(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def _secret(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate(request: dict, secret: str) -> None:
    supplied = request.get("token")
    if not _secret(supplied) or not hmac.compare_digest(supplied, secret):
        raise ValueError("runtime IPC authentication failed")
    if not _uuid(request.get("id")):
        raise ValueError("runtime IPC request id must be a full UUID hex value")
    if not isinstance(request.get("action"), str) or not 1 <= len(request["action"]) <= 32:
        raise ValueError("runtime IPC action must be a bounded name")
    if not isinstance(request.get("args"), dict):
        raise ValueError("runtime IPC args must be an object")
    budget = request.get("deadline_s")
    if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= 60:
        raise ValueError("runtime IPC deadline_s must be 1..60")


def serve(connection: socket.socket, secret: str, handler) -> bool:
    """Serve exactly one request. Bad peers do not retire the target session."""
    request = {}
    admitted = False
    try:
        request = receive(connection)
        _validate(request, secret)
        admitted = True
        connection.settimeout(request["deadline_s"] + 3)
        result = handler(request["action"], request["args"], request["deadline_s"])
        response = {"id": request["id"], "ok": True, "result": result}
        send(connection, response)
    except Exception as exc:
        # Never echo the incoming token field, arbitrary packet or secret.
        error = str(exc).replace(secret, "[redacted]")[:2048]
        response = {"id": request.get("id") if _uuid(request.get("id")) else None,
                    "ok": False, "error": error}
        try:
            send(connection, response)
        except (OSError, ValueError):
            pass  # The peer may already have closed or exceeded its deadline.
    return admitted


def rpc(endpoint: dict, packet: dict, timeout_s: float, *, request_limit: int = MAX_FRAME,
        response_limit: int = MAX_FRAME) -> dict:
    """The only destination is hardcoded loopback; callers cannot supply URLs."""
    port, secret = endpoint.get("port"), endpoint.get("token")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("runtime IPC endpoint has an invalid local port")
    if not _secret(secret):
        raise ValueError("runtime IPC endpoint has an invalid authentication secret")
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or not math.isfinite(timeout_s) or not 0 < timeout_s <= 603:
        raise ValueError("local IPC timeout must be finite and at most 603 seconds")
    if not isinstance(packet, dict) or not _uuid(packet.get("id")):
        raise ValueError("local IPC request id must be a full UUID hex value")
    deadline = time.monotonic() + timeout_s
    with socket.create_connection(("127.0.0.1", port), timeout=_remaining(deadline)) as connection:
        send(connection, {**packet, "token": secret}, max_frame=request_limit, deadline=deadline)
        response = receive(connection, max_frame=response_limit, deadline=deadline)
    if response.get("id") != packet["id"] or not isinstance(response.get("ok"), bool):
        raise ValueError("runtime IPC response does not match the admitted request")
    return response


def request(endpoint: dict, request_id: str, action: str, args: dict, budget: int) -> dict:
    packet = {"id": request_id, "token": endpoint.get("token"), "action": action,
              "args": args, "deadline_s": budget}
    _validate(packet, endpoint.get("token") or "")
    return rpc(endpoint, packet, budget + 3)
