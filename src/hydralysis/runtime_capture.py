"""Captures and snapshots of a runtime session: the worker's handlers and the host's file-based readers.

A **capture** is a window of the session's durable event log (runtime_events): `capture start` writes a marker
record, `capture stop` writes another and seals a summary. `capture_id` is `cap_` + the start marker's chain hash,
so it names exactly one place in one session's log and can be given to `evidence_add` as `from_capture`.

The summary says what the window can and cannot show. Its numbers come from two independent sources: the records
the log holds for the window, and each probe's own counter of how often it fired (`counters()` in the probe
script), which keeps counting after the probe stopped sending. Where they disagree the capture is `partial` and
says why. `complete` means: every event the installed probes raised in the window was recorded, none clipped, no
probe sampled, no probe at its limit, the log neither full nor failing. It does not mean anything about code that
no probe watched; `coverage.diagnostics` says what was watched.

A **snapshot** is a record of one moment (runtime_snapshot): modules, a thread count, named memory regions, the
counters. The host side reads captures and compares snapshots from the session folder alone, so both work after the
worker has ended.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from hydralysis import durable
from hydralysis.runtime_events import _finite, iter_records, read_events, verify_log
from hydralysis.runtime_snapshot import SNAPSHOT_ID, SNAPSHOT_NAME, VERSION, compare, snapshot_id, stable_sha256

CAPTURE_ID = re.compile(r"^cap_[0-9a-f]{64}$")
SESSION_ID = re.compile(r"^[0-9a-f]{32}$")
CAPTURES, SNAPSHOTS = "captures", "snapshots"
# Counters whose change over a window matters to coverage.
DELTA_KEYS = ("messages", "clipped", "recorded", "log_failed", "log_full_dropped", "ring_evicted")
# Limitation codes that bound what a capture covers (evidence.LIMITATIONS says the same; a test keeps them in step).
BOUNDING = ("hit_limit_reached", "sampled", "payload_clipped", "runtime:event_log_full", "runtime:event_log_write_failed",
            "runtime:events_missing", "runtime:counters_unavailable", "runtime:capture_open")
MAX_REGIONS = 32
MAX_REGION_BYTES = 4096
MAX_SNAPSHOT_BYTES = 131072


def _store(path: Path, value: dict) -> None:
    durable.write_sealed(path, _finite(value), indent=None)


def _fetch(path: Path) -> dict | None:
    return durable.read_sealed(path, default=None)


def _capture_name(value) -> str:
    name = str(value or "")
    if name and not SNAPSHOT_NAME.match(name):
        raise ValueError("name is 1..40 letters, digits, `_`, `.` or `-`")
    return name


# ---- reading the window back ------------------------------------------------------------------------------------

def window_counts(directory: Path, from_sequence: int, to_sequence: int | None) -> dict:
    """Per script, how many records of each event kind the log holds strictly inside the window."""
    by_script: dict[str, dict] = {}
    clipped = 0
    for record, error in iter_records(Path(directory) / "events.log"):
        if error:
            break
        n = record.get("n", 0)
        if n <= from_sequence:
            continue
        if to_sequence is not None and n >= to_sequence:
            break
        if record.get("type") != "event":
            continue
        message = record.get("message") or {}
        payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
        kind = str(payload.get("event") or message.get("type") or "other")
        row = by_script.setdefault(str(record.get("script")), {})
        row[kind] = row.get(kind, 0) + 1
        if message.get("type") == "truncated" or message.get("data_truncated"):
            clipped += 1
    return {"by_script": by_script, "clipped": clipped, "events": sum(sum(row.values()) for row in by_script.values())}


def summarize(directory: Path, session: str, record: dict, stop: dict, hooks: list[dict], end_counters: dict,
              totals: dict, log: dict) -> dict:
    """The coverage and limitations of a closed capture, from the log window and the probes' own counters.

    Limits of the word "complete": the baseline and end counters are read in calls of their own, apart from the
    start and stop marker writes. For a probe that is still firing, an event counted just before the stop marker
    but delivered after it reads as lost, and an event in flight from before the start marker reads as extra; the
    two can cancel, so seen == recorded does not prove that no event is missing at the window's edges. "complete"
    is exact for a quiet probe and a statement about the counters, not a proof, for a live one (the diagnostics of
    a complete capture say so).
    """
    window = window_counts(directory, record["from_sequence"], stop["n"])
    start_totals = record["baseline"]["counters"]
    delta = {key: totals.get(key, 0) - start_totals.get(key, 0) for key in DELTA_KEYS}
    baseline_hooks = record["baseline"]["hooks"]
    limits: set[str] = {"single_run"}
    rows = []
    for hook in hooks:
        hook_id = hook["hook_id"]
        counted = window["by_script"].get(hook_id, {})
        recorded = counted.get("enter", 0) + counted.get("break", 0)
        end = end_counters.get(hook_id) or {}
        start = baseline_hooks.get(hook_id) or {}
        row = {**hook, "recorded": recorded, "samples": counted.get("sample", 0), "returns": counted.get("return", 0)}
        if isinstance(end.get("seen"), int):
            seen = end["seen"] - (start["seen"] if isinstance(start.get("seen"), int) else 0)
            lost = 0 if hook["sampled"] else max(0, seen - recorded)
            row.update(seen=seen, lost=lost)
            if lost:
                limits.add("hit_limit_reached" if end["seen"] > (hook.get("limit") or 0) else "runtime:events_missing")
                row["limit_reached"] = end["seen"] > (hook.get("limit") or 0)
        else:
            row.update(seen=None, lost=None, counters_unavailable=end.get("unavailable", "no counters"))
            limits.add("runtime:counters_unavailable")
        if hook["sampled"]:
            limits.add("sampled")
        rows.append(row)
    if delta["clipped"] or window["clipped"]:
        limits.add("payload_clipped")
    if delta["log_full_dropped"] or log.get("full"):
        limits.add("runtime:event_log_full")
    if delta["log_failed"]:
        limits.add("runtime:event_log_write_failed")
    bounding = sorted(code for code in limits if code in BOUNDING)
    if not rows:
        coverage = {"status": "unknown", "reason": "no probe was installed during the capture"}
    elif bounding:
        coverage = {"status": "partial", "limitations": bounding}
    else:
        coverage = {"status": "complete", "diagnostics": [
            "every event of %d installed probe(s) was recorded; code no probe watched is not covered" % len(rows),
            "counted against the probes' own counters, read apart from the window's markers: an event in flight at "
            "either edge of a probe that keeps firing can offset another"]}
    codes = sorted(limits | ({"coverage_unknown"} if coverage["status"] == "unknown" else set()))
    return {"events_recorded": window["events"], "hooks": rows, "counters": delta, "coverage": coverage,
            "limitations": codes, "log": {"head": log.get("head"), "records": log.get("records")},
            "evidence": {"from_capture": "cap_" + record["start_hash"], "coverage": coverage, "limitations": codes,
                         "subject_sha256": record.get("target", {}).get("exe_sha256", ""),
                         "parameters": {"capture": "cap_" + record["start_hash"], "session": session,
                                        "script_sha256": sorted({row["script_sha256"] for row in rows}),
                                        "hooks": [{key: row.get(key) for key in ("module", "rva", "export", "kind", "limit",
                                                                                "script_sha256")} for row in rows]}}}


# ---- the host's readers: files only, so they work when the worker has ended --------------------------------------

def _find(directory: Path, selector) -> dict:
    """A capture record by id or name (the most recent of that name)."""
    folder = Path(directory) / CAPTURES
    selector = str(selector or "")
    if CAPTURE_ID.match(selector):
        record = _fetch(folder / (selector + ".json"))
        if record is None:
            raise ValueError("this session has no capture %s" % selector)
        return record
    found = [record for record in (_fetch(path) for path in sorted(folder.glob("cap_*.json"))) if record]
    if selector:
        found = [record for record in found if record.get("name") == selector]
    if not found:
        raise ValueError("this session has no capture%s" % (" named %s" % selector if selector else ""))
    return max(found, key=lambda record: record["from_sequence"])


def list_captures(directory: Path) -> dict:
    rows = []
    for path in sorted((Path(directory) / CAPTURES).glob("cap_*.json")):
        record = _fetch(path)
        if record:
            rows.append({key: record.get(key) for key in ("capture", "name", "state", "from_sequence", "to_sequence", "started_ms")}
                        | {"coverage": (record.get("coverage") or {}).get("status")})
    return {"captures": sorted(rows, key=lambda row: row["from_sequence"])}


def read_capture(directory: Path, args: dict) -> dict:
    """A capture's summary and a page of its events, straight from the durable log (nothing is evicted)."""
    record = _find(directory, args.get("capture"))
    limit, after = int(args.get("limit", 40)), int(args.get("after", record["from_sequence"]))
    if not 1 <= limit <= 200 or after < record["from_sequence"]:
        raise ValueError("limit is 1..200; after is not before the capture's start (%d)" % record["from_sequence"])
    upto = record.get("to_sequence")
    page = read_events(directory, after=after, limit=limit, upto=(upto - 1) if upto else None)
    summary = {key: value for key, value in record.items() if key != "baseline"}
    if record["state"] != "closed":
        summary["limitations"] = ["runtime:capture_open", "single_run"]
        summary["coverage"] = {"status": "partial", "limitations": ["runtime:capture_open"]}
        summary["note"] = "the capture has not been stopped: events after its start are shown, but it has no seal"
    return {**summary, **page}


def verify_capture(directory: Path, session: str, args: dict) -> dict:
    """Walk the session's whole log; for a named capture also check its start and stop markers are the sealed ones."""
    if args.get("capture"):
        record = _find(directory, args["capture"])
        expect = {record["from_sequence"]: record["start_hash"]}
        if record.get("to_sequence"):
            expect[record["to_sequence"]] = record["end_hash"]
        result = verify_log(directory, session, expect=expect)
        return {"capture": record["capture"], "state": record["state"], **result}
    return verify_log(directory, session)


def _snapshot_path(directory: Path, snapshot: str) -> Path:
    if not SNAPSHOT_ID.match(str(snapshot)):
        raise ValueError("a snapshot is named by its id, snap_ and 64 hex digits")
    return Path(directory) / SNAPSHOTS / (snapshot + ".json")


def load_snapshot(directory: Path, snapshot: str) -> dict:
    record = _fetch(_snapshot_path(directory, snapshot))
    if record is None:
        raise ValueError("no snapshot %s in that session" % snapshot)
    if snapshot_id(record) != snapshot:
        raise ValueError("snapshot %s does not match its own id: the file was changed" % snapshot)
    return record


def list_snapshots(directory: Path) -> dict:
    rows = []
    for path in sorted((Path(directory) / SNAPSHOTS).glob("snap_*.json")):
        record = _fetch(path)
        if record:
            rows.append({"snapshot": record.get("snapshot"), "name": record.get("name"), "taken_at_ms": record.get("taken_at_ms"),
                         "stable_sha256": stable_sha256(record)})
    return {"snapshots": sorted(rows, key=lambda row: row["taken_at_ms"] or 0)}


def compare_snapshots(root: Path, session: str, args: dict) -> dict:
    """compare a and b (snapshot ids); b may be in another session (other_session)."""
    other = str(args.get("other_session") or session)
    if not SESSION_ID.match(other):
        raise ValueError("other_session must be a runtime session id")
    a = load_snapshot(Path(root) / session, str(args.get("a") or ""))
    b = load_snapshot(Path(root) / other, str(args.get("b") or ""))
    unknown = set(args) - {"session", "other_session", "a", "b", "mask", "mask_defaults", "predicates", "limit", "owner"}
    if unknown:
        raise ValueError("unknown compare options: %s" % ", ".join(sorted(unknown)))
    return compare(a, b, mask=args.get("mask") or [], predicates=args.get("predicates") or [],
                   use_default_mask=args.get("mask_defaults", True) is not False, limit=int(args.get("limit", 200)))


def capture_host_op(directory: Path, session: str, args: dict) -> dict | None:
    """The capture ops that need no worker (read, verify, list); None for start and stop."""
    op = str(args.get("op") or "")
    if op == "list":
        return list_captures(directory)
    if op == "read":
        return read_capture(directory, args)
    if op == "verify":
        return verify_capture(directory, session, args)
    return None


# ---- the worker's handlers --------------------------------------------------------------------------------------

class CaptureMixin:
    """Capture and snapshot actions of `runtime_worker.RuntimeAgent`."""

    open_capture: dict | None = None

    def _hook_meta(self, hook_id: str, entry: dict) -> dict:
        export = entry.get("export")
        return {"hook_id": hook_id, "kind": entry.get("kind"), "module": (entry.get("module") or {}).get("name"),
                "rva": entry.get("rva"), "export": export.get("name") if isinstance(export, dict) else None,
                "limit": entry.get("limit"), "sampled": bool(entry.get("sample")),
                "script_sha256": entry.get("source_sha256")}

    def _hooks(self) -> list[dict]:
        return [self._hook_meta(hook_id, entry) for hook_id, entry in self.scripts.items()
                if entry.get("kind") in ("observe", "break")]

    def _counters_of(self, hook_id: str, entry: dict) -> dict:
        """A probe's own count of how often it fired. A paused probe cannot answer (its script thread waits)."""
        if hook_id in self.pauses:
            return {"unavailable": "the probe is paused at a breakpoint"}
        try:
            value = entry["handle"].exports_sync.counters()
        except Exception as exc:  # a probe destroyed with its target, or an old probe without counters
            return {"unavailable": "%s: %s" % (type(exc).__name__, str(exc)[:100])}
        if isinstance(value, dict) and isinstance(value.get("seen"), int) and not isinstance(value.get("seen"), bool):
            return {"seen": value["seen"], "hits": value.get("hits"), "limit": value.get("limit")}
        return {"unavailable": "the probe gave no counters"}

    def _all_counters(self) -> dict:
        return {hook_id: self._counters_of(hook_id, entry) for hook_id, entry in list(self.scripts.items())
                if entry.get("kind") in ("observe", "break")}

    def _retire_hook(self, script_id: str) -> None:
        """Keep a probe's last counters when it is unloaded inside an open capture."""
        entry = self.scripts.get(script_id)
        if self.open_capture is None or entry is None or entry.get("kind") not in ("observe", "break"):
            return
        self.open_capture.setdefault("_retired", {})[script_id] = {"meta": self._hook_meta(script_id, entry),
                                                                   "counters": self._counters_of(script_id, entry)}

    def _marker_or_raise(self, kind: str, body: dict) -> dict:
        before = self.log.counters["recorded"], self.log.counters["log_failed"]
        marker = self.log.marker(kind, body)
        if self.log.counters["log_failed"] != before[1] or self.log.counters["recorded"] == before[0]:
            raise RuntimeError("the event log could not record the %s marker (%s); the capture would have no seal"
                               % (kind, self.log.error or "log not writable"))
        return marker

    def capture(self, args: dict) -> dict:
        op = str(args.get("op") or "")
        unknown = set(args) - {"op", "name", "capture", "after", "limit", "session", "trace", "owner", "scope"}
        if unknown:
            raise ValueError("unknown capture options: %s" % ", ".join(sorted(unknown)))
        active = getattr(self, "trace", None) is not None and not self.trace.finalized
        if active and op in ("start", "stop", "scope"):
            self._require_trace_owner(op, args.get("owner"))
        if op == "scope":
            if not active:
                raise ValueError("no trace capture is running; there is no scope to change")
            added = args.get("scope") or {}
            if not isinstance(added, dict):
                raise ValueError("scope is an object {add: [...]}")
            self.trace_scope_added = list(getattr(self, "trace_scope_added", [])) + list(added.get("add") or [])
            return {"scope": {"added": self.trace_scope_added}, "by": "owner"}
        if op == "start":
            trace_args = self._trace_option(args["trace"]) if args.get("trace") is not None else None
            started = self._capture_start(_capture_name(args.get("name")))
            if trace_args is not None:
                try:
                    started["trace"] = self.trace_start(trace_args)
                except Exception:
                    self._capture_stop(None)          # no capture is left open without the trace it was asked to run
                    raise
            return started
        if op == "stop":
            trace_stopped = None
            if getattr(self, "trace", None) is not None and not self.trace.finalized:
                trace_stopped = self.trace_stop({"reason": "capture stopped"})
            closed = self._capture_stop(args.get("capture"))
            if trace_stopped is not None:
                closed["trace"] = trace_stopped
            return closed
        if op == "counters":
            return {"counters": self.log.counters_copy(), "log": self.log.head_info(), "hooks": self._all_counters()}
        result = capture_host_op(self.directory, self.directory.name, args)
        if result is None:
            raise ValueError("capture op is one of start, stop, read, verify, list, counters")
        return result

    def _require_trace_owner(self, op: str, presented) -> None:
        """Arming, widening the scope of and stopping a running trace belong to its owner (the writer capability)."""
        expected = getattr(self, "trace_owner", None)
        if expected and presented != expected:
            raise PermissionError("not_owner: this trace capture belongs to another client; %s needs the owner's capability" % op)

    def _trace_option(self, option) -> dict:
        """The `trace` option of `capture start`: {session, owner?, hooks, probes, ...recorder settings}. The probes are the verified
        hooks of the profile (see `profiles.probe_specs`); every enabled hook must have one, so a hook is never silently dropped."""
        if not isinstance(option, dict):
            raise ValueError("trace is an object {session, owner, hooks, probes}")
        known = {"session", "owner", "hooks", "probes", "profile", "fault_policy", "builtin", "ring_bytes", "rings", "batch_ms",
                 "batch_bytes", "counter_ms", "bp_ms", "window", "authorize_payload", "authorize_preview", "producer_gen", "watchdog", "etw",
                 "scope", "scope_key"}
        unknown = set(option) - known
        if unknown:
            raise ValueError("unknown trace options: %s" % ", ".join(sorted(unknown)))
        session = option.get("session")
        if not isinstance(session, str) or not session:
            raise ValueError("trace.session is the name of the trace session the capture feeds")
        hooks = option.get("hooks") or []
        if not isinstance(hooks, list) or not all(isinstance(h, str) for h in hooks):
            raise ValueError("trace.hooks is a list of hook ids")
        probes = [dict(p) for p in option.get("probes") or []]
        missing = [h for h in hooks if all(p.get("hook", p.get("name")) != h for p in probes)]
        if missing:
            raise ValueError("trace.hooks without a probe: %s (pass trace.probes from the verified profile)" % ", ".join(missing))
        self.trace_owner = option.get("owner")                # kept in memory only; never written to the capture record or logs
        self.trace_session_name = session
        out = {key: value for key, value in option.items() if key not in ("session", "owner", "hooks", "profile")}
        out["probes"] = probes
        return out

    def _capture_start(self, name: str) -> dict:
        if self.open_capture is not None:
            raise ValueError("capture %s is open; stop it first (one capture at a time)" % self.open_capture["capture"])
        totals = self.log.counters_copy()
        hooks = self._hooks()
        baseline = self._all_counters()
        marker = self._marker_or_raise("capture_start", {"name": name, "hooks": [hook["hook_id"] for hook in hooks]})
        record = {"version": 1, "capture": "cap_" + marker["hash"], "name": name, "session": self.directory.name,
                  "state": "open", "from_sequence": marker["n"], "start_hash": marker["hash"], "started_ms": marker["t"],
                  "target": {"pid": self.pid, "exe": self.target_exe, "exe_sha256": self.target_sha256},
                  "hooks_at_start": hooks,
                  "baseline": {"counters": {key: totals.get(key, 0) for key in DELTA_KEYS}, "hooks": baseline}}
        _store(self.directory / CAPTURES / (record["capture"] + ".json"), record)
        self.open_capture = record
        self.publish()
        return {key: record[key] for key in ("capture", "name", "state", "from_sequence", "started_ms")}

    def _capture_stop(self, selector) -> dict:
        record = self.open_capture
        if record is None:
            raise ValueError("no capture is open")
        if selector and selector not in (record["capture"], record["name"]):
            raise ValueError("the open capture is %s (%s)" % (record["capture"], record["name"] or "unnamed"))
        end = self._all_counters()
        hooks = {hook["hook_id"]: hook for hook in record["hooks_at_start"]}
        for hook in self._hooks():
            hooks.setdefault(hook["hook_id"], hook)
        for hook_id, kept in (record.get("_retired") or {}).items():
            hooks.setdefault(hook_id, kept["meta"])
            end.setdefault(hook_id, kept["counters"])
        stop = self._marker_or_raise("capture_stop", {"capture": record["capture"]})
        closed = {key: value for key, value in record.items() if key != "_retired"}
        closed.update(summarize(self.directory, self.directory.name, record, stop, list(hooks.values()), end,
                                self.log.counters_copy(), self.log.head_info()))
        closed.update(state="closed", to_sequence=stop["n"], end_hash=stop["hash"], ended_ms=stop["t"])
        _store(self.directory / CAPTURES / (record["capture"] + ".json"), closed)
        self.open_capture = None
        self.publish()
        return closed

    # ---- snapshot -------------------------------------------------------------------------------------------
    def snapshot_take(self, args: dict) -> dict:
        unknown = set(args) - {"op", "session", "name", "regions", "hash_modules", "threads", "keep_bytes", "modules_limit", "sha256"}
        if unknown:
            raise ValueError("unknown snapshot options: %s; accepted: name, regions, hash_modules, threads, keep_bytes, "
                             "modules_limit" % ", ".join(sorted(unknown)))
        if args.get("op") == "list":
            return list_snapshots(self.directory)
        if args.get("op") not in (None, "", "take"):
            raise ValueError("snapshot op is take (the default) or list")
        name = _capture_name(args.get("name"))
        regions = args.get("regions") or []
        if not isinstance(regions, list) or len(regions) > MAX_REGIONS:
            raise ValueError("regions is a list of at most %d {name, module+rva | address, size, layout?}" % MAX_REGIONS)
        limit = int(args.get("modules_limit", 200))
        if not 1 <= limit <= 200:
            raise ValueError("modules_limit is 1..200")
        keep = args.get("keep_bytes", True) is not False
        info = self.control.exports_sync.info(self.target_exe)
        modules = self.control.exports_sync.modules(limit)
        wanted = args.get("hash_modules")
        if wanted is None:
            wanted = [Path(self.target_exe).name]
        if not isinstance(wanted, list) or any(not isinstance(item, str) for item in wanted):
            raise ValueError("hash_modules is a list of module names")
        wanted = {item.lower() for item in wanted}
        rows = []
        for module in modules.get("modules", []):
            row = {"name": module["name"], "path": module["path"], "base": module["base"], "size": module["size"]}
            if module["name"].lower() in wanted:
                row["file_sha256"] = self.target_sha256 if _same(module["path"], self.target_exe) else _file_sha256(module["path"])
            rows.append(row)
        threads = self.control.exports_sync.threads(1)
        record = {"version": VERSION, "name": name, "session": self.directory.name, "taken_at_ms": int(time.time() * 1000),
                  "sequence": self.log.sequence, "log_head": self.log.head,
                  "target": {"pid": self.pid, "created_ms": self.target_created_ms, "exe": self.target_exe,
                             "exe_sha256": self.target_sha256, "arch": info.get("arch"), "pointer_size": info.get("pointer_size")},
                  "modules": rows, "modules_complete": not modules.get("truncated"),
                  "threads": {"count": threads.get("total")}, "regions": [], "hooks": [],
                  "counters": {key: self.log.counters[key] for key in ("messages", "clipped", "recorded", "ring_evicted")}}
        if args.get("threads"):
            listing = self.control.exports_sync.threads(200)
            record["threads"]["items"] = [{"name": "t%d" % index, "id": item["id"], "state": item["state"]}
                                          for index, item in enumerate(listing.get("threads", []))]
        total = 0
        seen = set()
        for index, row in enumerate(regions):
            region = self._snapshot_region(row, keep, index)
            if region["name"] in seen:
                raise ValueError("region name %s is used twice" % region["name"])
            seen.add(region["name"])
            total += len(region.get("bytes") or "") // 2
            if total > MAX_SNAPSHOT_BYTES:
                raise ValueError("the regions hold more than %d bytes together" % MAX_SNAPSHOT_BYTES)
            record["regions"].append(region)
        record["regions_complete"] = all(region.get("ok") for region in record["regions"])
        record["hooks"] = [{key: hook[key] for key in ("hook_id", "kind", "module", "rva", "export")} for hook in self._hooks()]
        record["snapshot"] = snapshot_id(_finite(record))
        _store(self.directory / SNAPSHOTS / (record["snapshot"] + ".json"), record)
        return {**record, "stable_sha256": stable_sha256(record)}

    def _snapshot_region(self, row, keep: bool, index: int) -> dict:
        if not isinstance(row, dict):
            raise ValueError("a region is {name, module+rva | address, size, layout?}")
        unknown = set(row) - {"name", "module", "rva", "address", "size", "layout", "type_name", "layout_source", "sha256"}
        if unknown:
            raise ValueError("unknown region fields: %s" % ", ".join(sorted(unknown)))
        name = str(row.get("name") or "")
        if not SNAPSHOT_NAME.match(name):
            raise ValueError("region %d needs a name: 1..40 letters, digits, `_`, `.` or `-`" % index)
        request = {key: row[key] for key in ("module", "rva", "address", "layout", "type_name") if key in row}
        request["size"] = int(row.get("size", 64))
        if not 1 <= request["size"] <= MAX_REGION_BYTES:
            raise ValueError("a region is 1..%d bytes" % MAX_REGION_BYTES)
        if "module" in request:
            request["sha256"] = row.get("sha256") or ""
        try:
            read = self.handle("read", request)
        except Exception as exc:  # one unreadable region does not stop the snapshot; the record says so
            return {"name": name, "ok": False, "error": "%s: %s" % (type(exc).__name__, str(exc)[:300])}
        data = bytes.fromhex(read["bytes"].replace(" ", ""))
        region = {"name": name, "ok": True, "address": read["address"], "size": len(data),
                  "module": (read.get("module") or {}).get("name"), "rva": read.get("rva"),
                  "sha256": hashlib.sha256(data).hexdigest(),
                  "range": {key: (read.get("range") or {}).get(key) for key in ("base", "protection")}}
        if keep:
            region["bytes"] = data.hex()
        if "fields" in read:
            layout = request.get("layout") or []
            region["type"] = read.get("type")
            region["fields"] = [{"name": (layout[i].get("name") if i < len(layout) else item.get("name")), "offset": item.get("offset"),
                                 "type": item.get("type"), **({"value": item["value"]} if "value" in item else {"bytes": item.get("bytes")}),
                                 **({"member": item["name"]} if i < len(layout) and item.get("name") != layout[i].get("name") else {})}
                                for i, item in enumerate(read["fields"])]
        if row.get("layout_source"):
            region["layout_source"] = row["layout_source"]
        return region


def _same(a: str, b: str) -> bool:
    import os
    return os.path.normcase(str(Path(a).resolve())) == os.path.normcase(str(Path(b).resolve()))


def _file_sha256(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
