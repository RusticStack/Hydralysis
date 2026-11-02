"""One reading agent as its own process (M3): query a live trace over and over until the stop file exists.

usage: python trace_agent_proc.py <spec.json>      spec: {settings, session, stop_file, out, full_every}
Writes <out> (JSON) when it ends: how many whole-trace reads it made, the revisions it saw, every inconsistency it found
(a partial row, a gap in the visible prefix, a revision that went back, a pinned read that changed) and the scheduler
counters it sampled from the daemon (requests that queued, lock waits)."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

REQUIRED = ("event_id", "kind", "seq", "source_id", "payload", "t_mono_ns")


def waits(engine) -> dict:
    st = engine.call("status")
    sched = st.get("scheduler", {})
    return {"ever_queued": sum(int(lane.get("everQueued", 0)) for lane in sched.values()),
            "queued_now": sum(int(lane.get("queued", 0)) for lane in sched.values()),
            "oldest_wait_ms": max(int(lane.get("oldestWaitMs", 0)) for lane in sched.values()),
            "admitted": sum(int(lane.get("admitted", 0)) for lane in sched.values()),
            "contended": int(st.get("waits", {}).get("contended", 0)),
            "foreign_blocked": int(st.get("waits", {}).get("foreignBlocked", {}).get("total", 0))}


def read_all(client, session: str) -> tuple[list[dict], int, int]:
    """Every row of one pinned snapshot: (rows, revision, up_to)."""
    rows, after, up_to, revision = [], None, None, None
    while True:
        reply = client.query(session, limit=1000, after=after, up_to=up_to)
        revision = reply.get("revision") if revision is None else revision
        rows.extend(reply.get("rows") or [])
        after, up_to = reply.get("next"), reply.get("up_to")
        if not after:
            return rows, revision, up_to


def main() -> int:
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    os.environ["HYDRALYSIS_ROOT"] = spec["settings"]["root"]
    from hydralysis import hydra, trace
    engine = hydra.Engine(spec["settings"])
    client = trace.TraceClient(engine)
    session, stop = spec["session"], Path(spec["stop_file"])
    problems: list[str] = []
    seen: dict[int, str] = {}                  # revision -> digest of the whole read
    revisions: list[int] = []
    counts: list[int] = []
    started = time.time()
    before = waits(engine)
    iteration, peak_queued, max_ms = 0, 0, 0.0
    last_rev = -1
    while not stop.exists():
        iteration += 1
        t0 = time.perf_counter()
        info = client.info(session)
        max_ms = max(max_ms, (time.perf_counter() - t0) * 1000)
        rev = int(info["revision"])
        if rev < last_rev:
            problems.append("revision went back %d -> %d" % (last_rev, rev))
        last_rev = rev
        if iteration % int(spec.get("full_every", 3)) == 1:
            t0 = time.perf_counter()
            rows, revision, up_to = read_all(client, session)
            max_ms = max(max_ms, (time.perf_counter() - t0) * 1000)
            for index, row in enumerate(rows, 1):
                missing = [k for k in REQUIRED if row.get(k) is None]
                if missing:       # thread_id / process_gen may be null; the required ones may not
                    problems.append("partial row seq=%s missing %s" % (row.get("seq"), missing))
                    break
                if row["seq"] != index:
                    problems.append("gap in the visible prefix: row %d has seq %s" % (index, row["seq"]))
                    break
                try:
                    json.loads(row["payload"])
                except ValueError:
                    problems.append("payload of seq %s is not complete JSON" % row["seq"])
                    break
            if rows and up_to is not None and len(rows) != up_to:
                problems.append("%d rows but the snapshot is pinned at seq %s" % (len(rows), up_to))
            digest = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
            if revision in seen and seen[revision] != digest:
                problems.append("revision %s read twice with different content" % revision)
            seen[revision] = digest
            revisions.append(int(revision))
            counts.append(len(rows))
        now = waits(engine)
        peak_queued = max(peak_queued, now["queued_now"])
        time.sleep(float(spec.get("pause", 0.0)))
    after = waits(engine)
    rows, revision, _ = read_all(client, session)
    result = {"iterations": iteration, "full_reads": len(revisions), "revisions": revisions, "counts": counts, "problems": problems,
              "final_rows": len(rows), "final_revision": revision, "seconds": time.time() - started,
              "digests": {str(k): v for k, v in seen.items()},
              "waits_before": before, "waits_after": after, "peak_queued_now": peak_queued, "slowest_ms": max_ms}
    Path(spec["out"]).write_text(json.dumps(result), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
