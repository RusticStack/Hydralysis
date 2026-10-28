"""A runtime session's event record: a bounded ring for `status`, and a durable append-only log with a hash chain.

Every message a script or the control channel sends gets a sequence number, is counted, kept in the ring (at most
RING_EVENTS events and RING_BYTES bytes: older ones are evicted and counted) and appended to `events.log` in the
session folder. The log is CRC-framed JSON lines (the format of `durable.AppendLog`, so `durable.scan_file` reads
it); each record carries the hash of the one before it, so a removed, reordered or edited record is found by
`verify_log`.

What the log promises, and what it does not:
- the worker is its only writer; a record is handed to the operating system when it is appended, so it survives
  the worker's death. It is synced to disk every SYNC_EVERY records and at a capture's start and stop, so a power
  loss can cost the unsynced tail, and the chain then ends earlier; it never leaves a gap in the middle;
- a log past LOG_MAX_BYTES stops recording (one `log_full` record says so) and counts what it dropped. A failed
  write is counted too, and the chain shows a gap there. Both are limitations of any capture that spans them;
- the counters (`messages`, per event kind, per script, evicted, clipped, dropped) are kept as a message arrives,
  before any clipping, eviction or write, so they stay true when the record is incomplete.
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import threading
import time
import zlib
from pathlib import Path

RING_EVENTS = 1000
RING_BYTES = 262144
LOG_MAX_BYTES = 64 * 1024 * 1024
LOG_MARKER_SLACK = 1024 * 1024  # markers (capture start/stop, log_full) are still written past the limit
SYNC_EVERY = 64
LOG_NAME = "events.log"
GENESIS = "hydralysis-runtime-events/1\n"
MAX_SCRIPT_COUNTERS = 256


def genesis_hash(session: str) -> str:
    return hashlib.sha256((GENESIS + session).encode("utf-8")).hexdigest()


def _finite(value):
    """The JSON value with non-finite numbers as strings (a log line refuses NaN and Infinity)."""
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if isinstance(value, dict):
        return {str(key): _finite(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_finite(item) for item in value]
    return value


def record_hash(record: dict) -> str:
    """The chain hash of one record: SHA-256 of its canonical JSON without the `hash` field."""
    body = {key: value for key, value in record.items() if key != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                     allow_nan=False).encode("ascii")).hexdigest()


def _frame(record: dict) -> bytes:
    body = json.dumps(record, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return b"%08x %s\n" % (zlib.crc32(body) & 0xFFFFFFFF, body)


def _parse(line: bytes):
    """The record of one framed line, or None when the CRC or the JSON is bad."""
    if len(line) < 10 or line[8:9] != b" ":
        return None
    try:
        crc = int(line[:8], 16)
    except ValueError:
        return None
    body = line[9:]
    if zlib.crc32(body) & 0xFFFFFFFF != crc:
        return None
    try:
        value = json.loads(body.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def iter_records(path: Path):
    """Yield (record, error) for the log's lines: error is None for a valid line. Stops after the first bad line.

    A last line without its LF is a torn tail (error "torn"): a writer killed mid-line. A line that has its LF
    but fails its CRC or is not a record is "corrupt", wherever it sits, the last line included: a flipped byte
    in the final record is not a torn write.

    Limit: this relies on the writer putting each record and its LF in one write. A torn write that stopped exactly
    after a complete record's last byte but before its LF is the one case that reads as a torn tail, and a cut that
    lands exactly on a record boundary (after an LF) cannot be told from a clean end.
    """
    try:
        handle = open(path, "rb")
    except FileNotFoundError:
        return
    with handle:
        for line in handle:
            if not line.endswith(b"\n"):
                yield None, "torn"
                return
            record = _parse(line[:-1])
            if record is None:
                yield None, "corrupt"
                return
            yield record, None


def read_events(directory: Path, after: int = 0, limit: int = 200, upto: int | None = None) -> dict:
    """Events (not markers) with sequence > after, at most `limit`, up to sequence `upto`, from the durable log."""
    events, next_after, truncated, problem = [], after, False, None
    for record, error in iter_records(Path(directory) / LOG_NAME):
        if error:
            problem = error
            break
        n = record.get("n", 0)
        if n <= after:
            continue
        if upto is not None and n > upto:
            break
        if len(events) >= limit:
            truncated = True
            break
        next_after = n
        if record.get("type") == "event":
            events.append({"sequence": n, "script": record.get("script"), "t_ms": record.get("t"),
                           "message": record.get("message")})
    return {"events": events, "next_after": next_after, "truncated": truncated, **({"log_problem": problem} if problem else {})}


def verify_log(directory: Path, session: str, upto: int | None = None, expect: dict | None = None) -> dict:
    """Walk the whole log from its genesis. ok is False at the first record that breaks the chain or the numbering.

    A torn tail is reported but is not a failure (a writer killed mid-line); anything else is. `expect` maps a
    sequence number to the hash its record must have (a capture's start and stop markers).
    """
    previous, count, last_n, head = genesis_hash(session), 0, 0, genesis_hash(session)
    pending = dict(expect or {})
    result = {"ok": True, "records": 0, "head": head, "last_sequence": 0}
    for record, error in iter_records(Path(directory) / LOG_NAME):
        if error == "torn":
            result["torn_tail"] = True
            break
        if error:
            return {**result, "ok": False, "first_bad": {"after_sequence": last_n, "reason": "a line fails its CRC or is not a record"}}
        n = record.get("n")
        if upto is not None and isinstance(n, int) and n > upto:
            break
        if not isinstance(n, int) or n <= last_n:
            return {**result, "ok": False, "first_bad": {"sequence": n, "reason": "sequence does not increase"}}
        if record.get("prev") != previous:
            return {**result, "ok": False, "first_bad": {"sequence": n, "reason": "prev does not match the record before it"
                    + (" (a record is missing or a write failed here)" if n != last_n + 1 else "")}}
        if record.get("hash") != record_hash(record):
            return {**result, "ok": False, "first_bad": {"sequence": n, "reason": "hash does not match the record's content"}}
        if n in pending:
            if pending.pop(n) != record["hash"]:
                return {**result, "ok": False, "first_bad": {"sequence": n, "reason": "the record is not the one the capture names"}}
        previous = head = record["hash"]
        count += 1
        last_n = n
        result.update(records=count, head=head, last_sequence=last_n)
    if pending:
        return {**result, "ok": False, "first_bad": {"sequence": min(pending), "reason": "the record the capture names is not in the log"}}
    return result


class EventLog:
    """The ring, the counters and the durable chain of one session. Thread-safe: the worker's message thread and its
    request thread both use it."""

    def __init__(self, directory: Path, session: str, *, ring_events: int = RING_EVENTS, ring_bytes: int = RING_BYTES,
                 log_max_bytes: int = LOG_MAX_BYTES, durable_log: bool = True):
        self.directory = Path(directory)
        self.session = session
        self.ring_events, self.ring_bytes, self.log_max_bytes = ring_events, ring_bytes, log_max_bytes
        self.durable_log = durable_log
        self.path = self.directory / LOG_NAME
        self.lock = threading.RLock()
        self.ring: collections.deque = collections.deque()
        self.ring_size = 0
        self.sequence = 0
        self.dropped = 0
        self.head = genesis_hash(session)   # the chain hash of the last record the log accepted
        self.records = 0
        self.log_bytes = 0
        self.full = False
        self.error = ""
        self._fd: int | None = None
        self._unsynced = 0
        self.counters = {"messages": 0, "by_type": {}, "by_event": {}, "by_script": {}, "ring_evicted": 0,
                         "clipped": 0, "recorded": 0, "log_failed": 0, "log_full_dropped": 0}

    # ---- counting: before any clipping, eviction or write -----------------------------------------------------
    def _count(self, script: str, message: dict) -> None:
        counters = self.counters
        counters["messages"] += 1
        kind = str(message.get("type") or "")
        counters["by_type"][kind] = counters["by_type"].get(kind, 0) + 1
        payload = message.get("payload")
        event = str(payload.get("event") or "") if isinstance(payload, dict) else ""
        if event:
            counters["by_event"][event] = counters["by_event"].get(event, 0) + 1
        row = counters["by_script"].get(script)
        if row is None and len(counters["by_script"]) < MAX_SCRIPT_COUNTERS:
            row = counters["by_script"][script] = {"seen": 0, "events": {}}
        if row is not None:
            row["seen"] += 1
            if event:
                row["events"][event] = row["events"].get(event, 0) + 1

    def count_message(self, script: str, message: dict, clipped: bool) -> None:
        """Count a message the caller has just clipped (or not) and is about to record."""
        with self.lock:
            self._count(script, message)
            if clipped:
                self.counters["clipped"] += 1

    # ---- the log ----------------------------------------------------------------------------------------------
    def _open(self) -> int:
        if self._fd is None:
            self.directory.mkdir(parents=True, exist_ok=True)
            self._fd = os.open(os.fspath(self.path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o666)
            self.log_bytes = os.lseek(self._fd, 0, os.SEEK_END)
        return self._fd

    def _append(self, record: dict, marker: bool) -> bool:
        """Chain and write one record. False when it was not recorded (log full or a failed write)."""
        record["prev"] = self.head
        record["hash"] = record_hash(record)
        line = _frame(record)
        if not self.durable_log:
            self.head = record["hash"]
            return False
        limit = self.log_max_bytes + (LOG_MARKER_SLACK if marker else 0)
        if self.log_bytes + len(line) > limit and not marker:
            if not self.full:
                self.full = True
                self._marker("log_full", {"limit_bytes": self.log_max_bytes})
            self.counters["log_full_dropped"] += 1
            return False
        try:
            descriptor = self._open()
            view = memoryview(line)
            while view:
                view = view[os.write(descriptor, view):]
        except OSError as exc:
            self.counters["log_failed"] += 1
            self.error = "%s: %s" % (type(exc).__name__, exc)
            # The logical stream goes on; the file has a hole here and verify_log says so.
            self.head = record["hash"]
            return False
        self.head = record["hash"]
        self.log_bytes += len(line)
        self.records += 1
        self.counters["recorded"] += 1
        self._unsynced += 1
        if self._unsynced >= SYNC_EVERY:
            self.sync()
        return True

    def _marker(self, kind: str, body: dict) -> dict:
        """A record that is not a script event: it takes a sequence number and is written even when the log is full."""
        self.sequence += 1
        record = {"n": self.sequence, "t": int(time.time() * 1000), "type": kind, **body}
        self._append(record, marker=True)
        return record

    def sync(self) -> None:
        with self.lock:
            if self._fd is not None and self._unsynced:
                try:
                    os.fsync(self._fd)
                    self._unsynced = 0
                except OSError as exc:
                    self.error = "%s: %s" % (type(exc).__name__, exc)

    def close(self) -> None:
        with self.lock:
            self.sync()
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None

    # ---- events -----------------------------------------------------------------------------------------------
    def record(self, script: str, message: dict) -> dict:
        """Give a (counted, clipped) message its sequence number; ring it and append it to the log."""
        message = _finite(message)
        with self.lock:
            self.sequence += 1
            event = {"sequence": self.sequence, "script": script, "message": message}
            size = len(json.dumps(event, ensure_ascii=False).encode("utf-8"))
            self.ring.append((event, size))
            self.ring_size += size
            while self.ring_size > self.ring_bytes or len(self.ring) > self.ring_events:
                _, old = self.ring.popleft()
                self.ring_size -= old
                self.dropped += 1
                self.counters["ring_evicted"] += 1
            self._append({"n": self.sequence, "t": int(time.time() * 1000), "type": "event", "script": script,
                          "message": message}, marker=False)
            return event

    def marker(self, kind: str, body: dict) -> dict:
        with self.lock:
            record = self._marker(kind, body)
            self.sync()
            return record

    def head_info(self) -> dict:
        with self.lock:
            return {"records": self.records, "head": self.head, "last_sequence": self.sequence, "bytes": self.log_bytes,
                    "full": self.full, **({"error": self.error} if self.error else {})}

    def counters_copy(self) -> dict:
        with self.lock:
            return json.loads(json.dumps(self.counters))
