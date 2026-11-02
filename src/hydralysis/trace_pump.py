"""The live ingester of a capture: tail the producer's raw segment and append it to the engine's trace session.

The capture (`TraceSource`) writes a chained raw segment and never talks to the engine; this module is the one writer of
the session's store. It follows the growing segment, verifies the chain, and sends new events in batches under the
session's writer capability. Two properties matter for recovery and for readers:

* **The segment is the truth.** The pump keeps no state of its own. A new pump (after the old one was killed) reads the
  segment from its start and skips the records the engine already holds (`trace_info` sources[].records), so nothing is
  sent twice and nothing is lost: the capture kept writing while no pump ran.
* **Readers are never blocked.** The pump sends bounded batches; the engine commits each batch as one revision and
  readers are served from committed snapshots, so a reader sees whole batches only.

Run in-process (`Pump.start`) or as its own process (`python -m hydralysis.trace_pump`), which is how a writer that dies
leaves the capture and the engine's lease behind for a takeover.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

from hydralysis import durable, trace_canon

BATCH_EVENTS = 200
POLL_S = 0.02


class SegmentTail:
    """An incremental reader of one chained segment: complete, verified records after the ones already read."""

    def __init__(self, path: Path, segment_id: str, skip: int = 0):
        self.path = Path(path)
        self.segment_id = segment_id
        self.offset = 0
        self.count = 0           # records read so far (verified)
        self.head = trace_canon.genesis_hash(segment_id)
        self.skip = skip         # records the engine already holds: verified but not returned
        self.damage: dict | None = None

    def read(self, limit: int = BATCH_EVENTS) -> list[dict]:
        """Up to LIMIT new events (a torn last line is left for the next call; a bad record stops the tail with `damage`).
        Records the engine already holds are verified and passed over, so an empty answer means the end of the segment."""
        out: list[dict] = []
        while len(out) < limit and self.damage is None:
            before = self.offset
            out.extend(self._chunk(limit - len(out)))
            if self.offset == before:
                break
        return out

    def _chunk(self, limit: int) -> list[dict]:
        if self.damage is not None:
            return []
        try:
            with open(self.path, "rb") as handle:
                handle.seek(self.offset)
                data = handle.read(max(1 << 16, limit * 4096))
        except FileNotFoundError:
            return []
        out: list[dict] = []
        cursor = 0
        while len(out) < limit:
            end = data.find(b"\n", cursor)
            if end < 0:
                break
            parsed = durable._parse(data[cursor:end])
            if parsed is None:
                if self.offset + end + 1 < self.path.stat().st_size:
                    self.damage = {"kind": "corrupt", "offset": self.offset + cursor}
                break
            record = parsed[0]
            try:
                expected = trace_canon.record_hash(record)
            except trace_canon.NotCanonical:
                expected = None
            if record.get("n") != self.count or record.get("prev") != self.head or expected != record.get("hash"):
                self.damage = {"kind": "chain_break", "offset": self.offset + cursor, "n": record.get("n")}
                break
            self.head, self.count = expected, self.count + 1
            cursor = end + 1
            if self.count > self.skip:
                out.append({key: value for key, value in record.items() if key != "hash"})
        self.offset += cursor
        return out


class Pump:
    """Tail SEGMENT into SESSION until `stop()` and the segment has been drained."""

    def __init__(self, client, session: str, cap: str, segment: Path, segment_id: str, *, skip_ingested: bool = True,
                 batch: int = BATCH_EVENTS, source_id: str = "agent"):
        self.client, self.session, self.cap = client, session, cap
        self.batch = batch
        skip = 0
        if skip_ingested:
            info = client.info(session)
            skip = next((int(s["records"]) for s in info.get("sources", []) if s.get("source_id") == source_id), 0)
        self.tail = SegmentTail(segment, segment_id, skip)
        self.appended = 0
        self.skipped = skip
        self.rejected = 0
        self.error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def step(self) -> int:
        events = self.tail.read(self.batch)
        if events:
            reply = self.client.append(self.session, events, cap=self.cap)
            self.appended += int(reply.get("accepted", 0))
            self.rejected += len(reply.get("rejected") or [])
        return len(events)

    def drain(self) -> None:
        while self.step():
            pass

    def run(self) -> None:
        try:
            while True:
                if not self.step():
                    if self._stop.is_set():
                        self.drain()
                        return
                    time.sleep(POLL_S)
        except Exception as exc:  # noqa: BLE001 - the pump's trouble is reported, it never takes the capture down
            self.error = "%s: %s" % (type(exc).__name__, exc)

    def start(self) -> "Pump":
        self._thread = threading.Thread(target=self.run, name="trace-pump", daemon=True)
        self._thread.start()
        return self

    def stop(self, timeout: float = 60.0) -> dict:
        """Drain what the capture wrote and end. Returns the pump's counters."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
        return self.report()

    def report(self) -> dict:
        return {"appended": self.appended, "skipped_already_ingested": self.skipped, "rejected": self.rejected,
                "records_read": self.tail.count, "damage": self.tail.damage, "error": self.error}


def main(argv: list[str]) -> int:
    """`python -m hydralysis.trace_pump` reads one JSON object on stdin: {settings, session, cap?, segment, segment_id,
    stop_file?, resume?}; it runs until the stop file exists (and the segment is drained). The capability is never on a command line."""
    spec = json.loads(sys.stdin.read())
    from hydralysis import trace
    client = trace.TraceClient(trace._engine(spec["settings"]))
    # The lease belongs to the connection that opened the session: this process is the writer, so it opens (or, with a
    # capability, reclaims) the session itself.
    opened = client.begin(session=spec["session"], create=not spec.get("cap"), mode="write", cap=spec.get("cap"))
    cap = (opened.get("lease") or {}).get("cap") or spec.get("cap")
    pump = Pump(client, spec["session"], cap, Path(spec["segment"]), spec["segment_id"],
                skip_ingested=bool(spec.get("resume", True)))
    pump.start()
    stop_file = spec.get("stop_file")
    print(json.dumps({"pump": "started", "skipped": pump.skipped, "pid": os.getpid(), "cap": cap,
                      "lease": opened.get("lease")}), flush=True)
    while pump._thread.is_alive():
        if stop_file and Path(stop_file).exists():
            pump._stop.set()
        time.sleep(0.05)
    print(json.dumps({"pump": "ended", **pump.report()}), flush=True)
    return 1 if pump.error else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
