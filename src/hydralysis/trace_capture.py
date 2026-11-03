"""The writer side of an in-process trace capture: batches in, a chained raw segment out, with the health counters.

One `TraceSource` owns one segment (`<session>/trace/agent.seg`), the only file it writes. It never symbolizes, parses
or re-encodes an event: the encoder (`hydralysis_native.SegmentEncoder`, or its Python twin in `trace_wire`) turns each
agent batch into chained lines and this class appends them. Three hops keep separate counters, so a loss can be placed:

    producer   the agent's rings: attempted, dropped (ring full), read failures, threads without a ring
    transport  Frida's delivery: batches the agent sent against batches that arrived, bytes, decode failures
    writer     this class: lines appended, bytes, failed and retried writes, records refused at the size limit

The ingester finds new data by the directory change and by the sidecar `agent.seg.head` (record count, chain head,
bytes), replaced atomically after each group of appends and at most every NOTIFY_EVERY_S.

Claims (spec 14.1) are reported one by one and never imply each other: attached, observing, data integrity, capture
coverage, fault-free. A zero loss counter with no observer is not coverage.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from pathlib import Path

from hydralysis import durable
from hydralysis import trace_wire as tw

try:  # optional Rust capture writer (native/src/trace/pump.rs); HYDRALYSIS_NATIVE=0 or a missing wheel uses the Python writer below
    from hydralysis_native import TracePump as _TracePump  # type: ignore[import-not-found]
except ImportError:
    _TracePump = None
try:
    from hydralysis_native import verify_segment_file as _verify_file  # type: ignore[import-not-found]
except ImportError:
    _verify_file = None

SEGMENT = "agent.seg"
NOTIFY_EVERY_S = 0.02
SYNC_EVERY_BYTES = 1 << 20
MAX_SEGMENT_BYTES = 1 << 30
MAX_PENDING_BYTES = 8 << 20
FAULT_POLICIES = ("tolerant", "fatal", "freezes")


class TraceRefused(ValueError):
    """The request cannot be honoured; the message says why. Recorded as a capture refusal, never worked around."""


def check_probe_policy(policy: str, probe: dict) -> str | None:
    """Why `probe` cannot be armed under the host's fault policy, or None (spec 15.1).

    Under `fatal` or `freezes` every read a probe makes must be non-faulting: kernel-mediated (ReadProcessMemory on the
    calling process) or a validated page range. A probe that asks for direct dereferences, a pause (a breakpoint stops
    the thread inside the host's exception machinery) or an unknown read mode is refused, not armed. An unknown policy
    is treated as `fatal`: nothing is assumed tolerant.
    """
    if policy not in FAULT_POLICIES:
        return "fault policy %r is not one of %s" % (policy, ", ".join(FAULT_POLICIES))
    if policy == "tolerant":
        return None
    if probe.get("read_mode", "kernel") != "kernel":
        return "read_mode %r is not non-faulting; a %s host cannot take a caught fault" % (probe.get("read_mode"), policy)
    if probe.get("pause"):
        return "a pausing probe stops the thread inside the host's fault machinery; refused under %s" % policy
    if probe.get("deref_chain"):
        return "a pointer-chain read is not a single validated range; refused under %s" % policy
    return None


class TraceSource:
    def __init__(self, directory: Path, *, session: str, source_id: str = "agent", producer_gen: int, process_id: int, sites: dict,
                 qpc_freq: int, key: bytes | None = None, fault_policy: str = "fatal", payload_authorized: bool = False,
                 max_payload: int = 4096, max_bytes: int = MAX_SEGMENT_BYTES, scope: str | None = None, encoder=None,
                 notify=None, native: bool | None = None):
        self.session, self.source_id, self.producer_gen, self.process_id = session, source_id, producer_gen, process_id
        self.directory = Path(directory) / "trace"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / SEGMENT
        self.scope = scope or ("session:" + session)
        self.key = key if key is not None else self._load_key()
        self.key_id = hashlib.sha256(b"hydra.trace.key-id\0" + self.key).hexdigest()[:16]
        self.max_bytes = max_bytes
        self.payload_authorized = payload_authorized
        self.fault_policy = fault_policy
        self.segment_id = "%s/%s/%d" % (session, source_id, producer_gen)
        # The native pump decodes, encodes, chains and writes a batch with the GIL released; the Python path is the same
        # work in the encoder's twin and this class's own writer (kept for HYDRALYSIS_NATIVE=0, an injected encoder, and
        # tests that fail its os-level calls).
        self._pump = None
        if encoder is None and native is not False and _TracePump is not None and os.environ.get("HYDRALYSIS_NATIVE", "1") != "0":
            self._pump = _TracePump(os.fspath(self.directory), self.segment_id, source_id, producer_gen, process_id, sites, self.key,
                                    int(qpc_freq), payload_authorized, max_payload, max_bytes, SYNC_EVERY_BYTES, NOTIFY_EVERY_S)
            self.encoder = self._pump
        else:
            make = encoder or tw.make_encoder
            self.encoder = make(self.segment_id, source_id, producer_gen, process_id, sites, self.key, qpc_freq,
                                payload_authorized=payload_authorized, max_payload=max_payload)
        self.lock = threading.Lock()
        self.sites = sites
        self.lifetimes_done = False
        self.qpc_freq = int(qpc_freq)
        self.modules_seen: set = set()
        self.notify = notify
        self._fd: int | None = None
        self._pending = bytearray()
        self._unsynced = 0
        self._notified = 0.0
        self.full = False
        self.finalized = False
        self.opened_ns: int | None = None
        self.closed_ns: int | None = None
        self.transport = {"batches": 0, "bytes": 0, "decode_failed": 0, "agent_batches_sent": None, "counter_messages": 0}
        self._skipped_reported: dict = {}
        self.producer: dict = {"attempted": 0, "dropped": 0, "read_failed": 0, "no_ring": 0, "rings": []}
        self.writer = {"lines": 0, "bytes": 0, "write_failed": 0, "retried_bytes": 0, "refused_after_full": 0, "artifacts": 0,
                       "artifact_failed": 0, "syncs": 0}
        self.errors: list = []
        self.context: dict = {}
        self.first_event_ns: int | None = None

    # ---- the scope key: the correlation ids are only comparable under the same key ----------------------------------
    def _load_key(self) -> bytes:
        path = self.directory / "scope.key"
        try:
            data = path.read_bytes()
            if len(data) == 32:
                return data
        except FileNotFoundError:
            pass
        key = secrets.token_bytes(32)
        durable.atomic_write(path, key)
        return key

    # ---- appending ------------------------------------------------------------------------------------------------------
    def _open(self) -> int:
        if self._fd is None:
            self._fd = os.open(os.fspath(self.path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o666)
        return self._fd

    def _flush_pending(self) -> bool:
        """Write the pending lines; a failed write keeps them (and the chain stays in step with what the file will hold)."""
        while self._pending:
            try:
                written = os.write(self._open(), memoryview(self._pending))
            except OSError as exc:
                self.writer["write_failed"] += 1
                self.errors.append("%s: %s" % (type(exc).__name__, exc))
                self.errors = self.errors[-5:]
                return False
            if written <= 0:
                self.writer["write_failed"] += 1
                return False
            self.writer["bytes"] += written
            self._unsynced += written
            del self._pending[:written]
        if self._unsynced >= SYNC_EVERY_BYTES:
            self.sync()
        return True

    def sync(self) -> None:
        if self._fd is not None and self._unsynced:
            try:
                os.fsync(self._fd)
                self._unsynced = 0
                self.writer["syncs"] += 1
            except OSError as exc:
                self.errors.append("fsync: %s" % exc)

    def _size(self) -> int:
        return self.writer["bytes"] + len(self._pending)

    def _append(self, lines: bytes) -> bool:
        """Queue and write encoded lines (they are already chained: they must reach the file, in order)."""
        if not lines:
            return True
        self._pending += lines
        self.writer["lines"] += lines.count(b"\n")
        self._flush_pending()
        self._notify()
        return True

    def _over_limit(self) -> bool:
        """True once the segment is at its size limit. The limit is checked before each batch is encoded (a chained line
        cannot be un-made), so a segment may pass it by at most one batch. Recording then stops with an explicit gap."""
        if self.full:
            return True
        if self._size() < self.max_bytes and len(self._pending) <= MAX_PENDING_BYTES:
            return False
        self.full = True
        reason = "segment size limit" if self._size() >= self.max_bytes else "writer cannot keep up"
        self._emit("core.capture.gap", self._now_ns(), {
            "reason": "budget", "detail": reason, "limit_bytes": self.max_bytes, "out_of_band": False})
        return True

    @staticmethod
    def _now_ns() -> int:
        """Control events share the agent's clock: on Windows `perf_counter_ns` is QueryPerformanceCounter in nanoseconds."""
        return time.perf_counter_ns()

    def _emit(self, kind: str, t_ns: int, payload: dict) -> None:
        """Encode one control event onto the chain and append it."""
        if self._pump is not None:
            self._pump.event(kind, t_ns, payload)
            self._after_native()
        else:
            self._append(self.encoder.encode_event(kind, t_ns, payload))

    def _after_native(self) -> None:
        """Take over the pump's counters and errors; run the ingester's callback when the sidecar was just replaced."""
        pump = self._pump
        self.writer = pump.writer
        fresh = pump.take_errors()
        if fresh:
            self.errors = (self.errors + fresh)[-5:]
        self.full = pump.full
        if pump.take_notified() and self.notify is not None:
            self._notify_callback()

    def _notify(self, force: bool = False) -> None:
        if self._pump is not None:
            self._pump.notify(force)
            self._after_native()
            return
        now = time.monotonic()
        if not force and now - self._notified < NOTIFY_EVERY_S:
            return
        self._notified = now
        info = {"records": self.encoder.count, "head": self.encoder.head, "bytes": self.writer["bytes"],
                "full": self.full, "finalized": self.finalized}
        try:
            durable.atomic_write(self.path.with_name(SEGMENT + ".head"), json.dumps(info, sort_keys=True).encode("ascii"), sync=False)
        except OSError as exc:
            self.errors.append("notify: %s" % exc)
        if self.notify is not None:
            self._notify_callback(info)

    def _notify_callback(self, info: dict | None = None) -> None:
        if info is None:
            info = {"records": self.encoder.count, "head": self.encoder.head, "bytes": self.writer["bytes"],
                    "full": self.full, "finalized": self.finalized}
        try:
            self.notify(self.path, info)
        except Exception as exc:  # the ingester's trouble never stops the writer
            self.errors.append("notify callback: %r" % exc)

    # ---- events from the agent ----------------------------------------------------------------------------------------------
    def on_ready(self, message: dict, qpc_ns: int | None = None) -> None:
        """The agent attached: record the host's fault context and the installed probes as a `core.capture.source`."""
        with self.lock:
            self.context = {k: message.get(k) for k in ("context", "installed", "rings", "ring_bytes", "batch_ms", "arch", "bp_us", "window")}
            self.opened_ns = self._now_ns()
            payload = {"source_type": "inprocess-frida", "state": "activated", "producer_gen": self.producer_gen,
                       "fault_policy": self.fault_policy, "fault_context": message.get("context"),
                       "probes": message.get("installed"), "rings": message.get("rings"), "ring_bytes": message.get("ring_bytes"),
                       "batch_ms": message.get("batch_ms"), "backpressure_us": message.get("bp_us"),
                       "ack_window": message.get("window"), "sampling": message.get("sampling"), "clock": {"domain": "qpc-10mhz", "unit": "qpc-tick",
                                                                       "frequency_hz": int(message.get("qpc_freq", 0) or 0)},
                       "scope": {"name": self.scope, "key_id": self.key_id}, "payload_mode": self.payload_authorized,
                       "capabilities_refused": []}
            self._emit("core.capture.source", self.opened_ns, payload)

    def record_lifetimes(self, process: dict, modules: list[dict], *, late: bool = False) -> int:
        """The process and its mapped modules as `core.process.start` / `core.module.load`, the lifetime facts an ingester needs to
        turn an address into (module, rva). Only modules not already recorded are written; LATE marks modules seen after the start."""
        written = 0
        with self.lock:
            if self.finalized:
                return 0
            now = self._now_ns()
            if not late and not self.lifetimes_done:
                self._emit("core.process.start", now, {
                    "pid": self.process_id, "image": process.get("image"), "image_sha256": process.get("image_sha256"),
                    "observed": "attach"})
                self.lifetimes_done = True
            for item in modules:
                key = (item.get("name"), item.get("base"))
                if key in self.modules_seen:
                    continue
                self.modules_seen.add(key)
                payload = {"name": item.get("name"), "path": item.get("path"), "base": int(str(item["base"]), 0),
                           "size": int(item["size"]), "build": item.get("file_sha256"), "observed": "late" if late else "attach"}
                self._emit("core.module.load", now, payload)
                written += 1
        return written

    def on_module(self, message: dict) -> None:
        """A module loaded or unloaded while recording (the agent's module observer): a lifetime fact with the base it had."""
        with self.lock:
            if self.finalized:
                return
            try:
                ticks, base = int(message["t"]), int(str(message["base"]), 0)
            except (KeyError, ValueError):
                self.errors.append("module message: %r" % (message,))
                return
            t_ns = ticks * 1_000_000_000 // (self.qpc_freq or 10_000_000)
            load = message.get("op") == "load"
            payload = {"name": message.get("name"), "path": message.get("path"), "base": base, "size": int(message.get("size") or 0),
                       "observed": "live"}
            if load:
                payload["build"] = None
                self.modules_seen.add((message.get("name"), message.get("base")))
            self._emit("core.module.load" if load else "core.module.unload", t_ns, payload)

    def refuse(self, what: str, reason: str, limitation: str | None = None) -> None:
        """A capability that was asked for and not given (an optional hook, ETW without elevation): recorded as a source event."""
        with self.lock:
            payload = {"source_type": what, "state": "refused", "reason": reason}
            if limitation:
                payload["limitation"] = limitation
            self._emit("core.capture.source", self._now_ns(), payload)

    def on_batch(self, data) -> dict:
        """Append one agent batch. A batch that does not decode is counted and never written; the stream goes on."""
        data = bytes(data)
        with self.lock:
            if self.finalized:
                return {"ok": False, "reason": "finalized"}
            self.transport["batches"] += 1
            self.transport["bytes"] += len(data)
            if self._pump is not None:
                return self._native_batch(data)
            if self._over_limit():
                self.writer["refused_after_full"] += 1
                return {"ok": False, "reason": "budget"}
            try:
                lines, artifacts, info = self.encoder.encode_batch(data)
            except ValueError as exc:
                self.transport["decode_failed"] += 1
                self.errors.append("batch: %s" % exc)
                self.errors = self.errors[-5:]
                return {"ok": False, "reason": str(exc)}
            for digest, blob in artifacts.items():
                if not self._artifact(digest, bytes(blob)):
                    # The reference must not commit without its bytes: refuse the whole batch's lines.
                    self.writer["artifact_failed"] += 1
                    return {"ok": False, "reason": "artifact could not be made durable"}
            self._append(bytes(lines))
            return {"ok": True, **info}

    def _native_batch(self, data: bytes) -> dict:
        status, reason, records, batch_seq = self._pump.batch(data, self._now_ns())
        self._after_native()
        if status == "ok":
            return {"ok": True, "records": records, "batch_seq": batch_seq}
        if status == "decode":
            self.transport["decode_failed"] += 1
            self.errors.append("batch: %s" % reason)
            self.errors = self.errors[-5:]
        return {"ok": False, "reason": reason}

    def _artifact(self, digest: str, blob: bytes) -> bool:
        target = self.directory / "artifacts" / digest
        if target.exists():
            return True
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            durable.atomic_write(target, blob)      # fsynced before the lines that name it are appended
            self.writer["artifacts"] += 1
            return True
        except OSError as exc:
            self.errors.append("artifact: %s" % exc)
            return False

    def on_counters(self, message: dict) -> None:
        with self.lock:
            self.transport["counter_messages"] += 1
            self.transport["agent_batches_sent"] = message.get("batches_sent")
            self.producer = {"attempted": message.get("attempted", 0), "dropped": message.get("dropped", 0),
                             "read_failed": message.get("read_failed", 0), "no_ring": message.get("no_ring", 0),
                             "rings": message.get("rings", []), "entered": message.get("entered"), "left": message.get("left"),
                             "busy": message.get("busy"), "final": bool(message.get("final")),
                             # backpressure, out of band: how often and how long a hook waited for the drain, how often the
                             # agent held back for an unacknowledged window, and how many rings a later thread reused
                             "stalls": message.get("stalls", 0), "stall_ticks": message.get("stall_ticks", 0),
                             "window_waits": message.get("window_waits", 0), "ring_reuses": message.get("ring_reuses", 0),
                             "bp_us": message.get("bp_us"), "qpc_freq": message.get("qpc_freq"),
                             "sampling": message.get("sampling")}
            self._sampling_gaps(message.get("sampling"), bool(message.get("final")))

    def _sampling_gaps(self, sampling: dict | None, final: bool) -> None:
        """Hits the sampling policy skipped are not lost silently: for each probe, the exact number skipped since the last
        report is one `core.capture.gap` (reason `budget`, `sampled: true`, with the stride in force), so a coverage
        claim over a sampled probe says how many hits it stands for. The caller holds the lock."""
        if not sampling or self.finalized:
            return
        for row in sampling.get("sites", ()):
            skipped = int(row.get("skipped", 0))
            new = skipped - self._skipped_reported.get(row["site"], 0)
            if new <= 0:
                continue
            self._skipped_reported[row["site"]] = skipped
            self._emit("core.capture.gap", self._now_ns(), {
                "reason": "budget", "dropped": new, "sampled": True, "probe": row.get("probe"), "site": row["site"],
                "policy": sampling.get("policy"), "stride": row.get("stride"), "rate_per_s": row.get("rate_per_s"),
                "kept": row.get("kept"), "hits": row.get("hits"), "out_of_band": True,
                "detail": "skipped by the declared sampling policy; kept records carry confidence sampled"})

    # ---- the end -----------------------------------------------------------------------------------------------------------
    def finalize(self, *, detach: dict | None = None, reason: str = "stopped") -> dict:
        """Close the segment: the loss only the out-of-band counters know, the deactivation, then a sync and a verify."""
        with self.lock:
            if self.finalized:
                return self.health(locked=True)
            t_ns = self._now_ns()
            rows = [{"ring": r["ring"], "attempted": r["attempted"], "dropped": r["dropped"]} for r in self.producer.get("rings", [])]
            if self._pump is not None:
                self._pump.finalize_rings(rows, t_ns, int(self.producer.get("no_ring", 0) or 0))
                self._after_native()
            else:
                self._append(bytes(self.encoder.finalize(rows, t_ns, int(self.producer.get("no_ring", 0) or 0))))
            quiescent = None if detach is None else bool(detach.get("quiescent"))
            self._emit("core.capture.source", t_ns, {
                "source_type": "inprocess-frida", "state": "deactivated" if quiescent in (None, True) else "detach-failed",
                "reason": reason, "producer": self.producer, "transport": self.transport, "writer": self.writer,
                "detach": detach})
            self.finalized = True
            self.closed_ns = t_ns
            if self._pump is not None:
                self._pump.close()          # flush, fsync, final sidecar, close
                self._after_native()
                return self.health(locked=True)
            self._flush_pending()
            self.sync()
            self._notify(force=True)
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
            return self.health(locked=True)

    # ---- health ------------------------------------------------------------------------------------------------------------
    def verify(self) -> dict:
        return verify_segment(self.path, self.segment_id)

    def hits(self, name: str) -> int:
        """Records seen so far at the probe called NAME (the progress counter of a frame-stall watchdog)."""
        with self.lock:
            counts = dict(self.encoder.site_hits())
            return sum(counts.get(site, 0) for site, row in self.sites.items() if row.get("name") == name)

    def health(self, locked: bool = False) -> dict:
        def build():
            producer = self.producer
            expected_batches = self.transport["agent_batches_sent"]
            lost_batches = None if expected_batches is None else max(0, expected_batches - self.transport["batches"])
            claims = {
                "attached": bool(self.context),
                "observing": self.transport["batches"] > 0 or self.encoder.stats.get("events", 0) > 1,
                "finalized": self.finalized,
                # A read of unreadable memory is done with a non-faulting copy and counted (`reads_refused`); no exception is taken,
                # so it is not a fault. A fault is a writer error here or a handler run reported by the producer.
                "fault_free": not self.errors and not producer.get("faults", 0),
            }
            state = "final" if producer.get("final") else ("ended-without-final-counters" if self.finalized else "running")
            return {"segment": SEGMENT, "records": self.encoder.count, "head": self.encoder.head, "full": self.full,
                    "producer": producer, "producer_state": state,
                    "reads_refused": producer.get("read_failed", 0) + self.encoder.stats.get("read_failures", 0),
                    "transport": {**self.transport, "batches_missing": lost_batches, "gaps_reported": self.encoder.stats.get("transport_gaps", 0)},
                    "writer": dict(self.writer, pending_bytes=self._pump.pending_bytes if self._pump is not None else len(self._pending)),
                    "encoder": dict(self.encoder.stats), "errors": list(self.errors), "claims": claims,
                    "coverage": {"observer": "agent", "state": "closed" if self.finalized else "active",
                                 "note": "a zero loss counter is coverage only while the observer was active"}}
        if locked:
            return build()
        with self.lock:
            return build()


def verify_segment(path: Path, segment_id: str) -> dict:
    """Walk a raw segment: CRC, numbering, chain. The outcomes TRACE-1 keeps distinct: empty, clean, torn tail, corrupt, chain break, missing."""
    path = Path(path)
    if not path.exists():
        return {"outcome": "missing", "records": 0}
    if os.environ.get("HYDRALYSIS_NATIVE", "1") != "0" and _verify_file is not None:
        walked = _verify_file(os.fspath(path), tw.genesis_hash(segment_id))
        if walked is not None:
            outcome, records, offset, n, head = walked
            out = {"outcome": outcome, "records": records}
            if outcome in ("torn-tail", "corrupt", "chain-break"):
                out["offset"] = offset
            if outcome == "chain-break":
                out["n"] = n
            if outcome == "clean":
                out["head"] = head
            return out
    data = path.read_bytes()
    if not data:
        return {"outcome": "empty", "records": 0}
    previous, expect_n, cursor, records = tw.genesis_hash(segment_id), 0, 0, 0
    while cursor < len(data):
        end = data.find(b"\n", cursor)
        if end < 0:
            return {"outcome": "torn-tail", "records": records, "offset": cursor}
        line = data[cursor:end]
        record = durable._parse(line)
        if record is None:
            more = end + 1 < len(data)
            return {"outcome": "corrupt" if more else "torn-tail", "records": records, "offset": cursor}
        value = record[0] if isinstance(record, tuple) else record
        if value.get("n") != expect_n or value.get("prev") != previous or value.get("hash") != tw.record_hash(value):
            return {"outcome": "chain-break", "records": records, "offset": cursor, "n": value.get("n")}
        previous, expect_n, cursor, records = value["hash"], expect_n + 1, end + 1, records + 1
    return {"outcome": "clean", "records": records, "head": previous}


def read_events(path: Path, segment_id: str, limit: int | None = None) -> list:
    """The records of a clean-prefix segment as dicts (tests and small exports)."""
    out = []
    data = Path(path).read_bytes() if Path(path).exists() else b""
    for line in data.split(b"\n"):
        if not line:
            continue
        parsed = durable._parse(line)
        if parsed is None:
            break
        out.append(parsed[0] if isinstance(parsed, tuple) else parsed)
        if limit and len(out) >= limit:
            break
    return out


def export_jsonl(path: Path, segment_id: str, *, include_payload_refs: bool = False, for_import: bool = False) -> tuple:
    """(lines, omitted): the segment's events as JSON lines (FOR_IMPORT drops the producer chain hash, which the ingester recomputes). Payload artifacts are omitted unless separately authorized:
    a reference to an artifact loses its digest and path and says `omitted` (the exact range stays in the store)."""
    omitted = 0
    out = []
    for event in read_events(path, segment_id):
        payload = event.get("payload")
        if isinstance(payload, dict) and not include_payload_refs:
            def scrub(value):
                nonlocal omitted
                if isinstance(value, dict):
                    if "artifact" in value:
                        value = {k: v for k, v in value.items() if k != "artifact"}
                        value["payload"] = "omitted"
                        omitted += 1
                    return {k: scrub(v) for k, v in value.items()}
                return value
            event = {**event, "payload": scrub(payload)}
        if for_import:
            event = {k: v for k, v in event.items() if k != "hash"}
        out.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
    return out, omitted
