"""The overlay store as a sealed snapshot plus a per-view append log (H16).

Before: every mutation rewrote the whole sealed store (`overlays/<key>.json`) and copied the previous version to `.bak`:
two or three fsyncs and O(store) bytes per edit. Now a mutation appends ONE framed record (durable.AppendLog: CRC-framed
JSON line, fsynced before the call returns, so O2 "durable before ack" holds) to `overlays/<key>.json.log`, and every
SNAPSHOT_EVERY records (or when the log grows past SNAPSHOT_LOG_BYTES) the whole store is written again as the snapshot.

Format
------
The snapshot is the v3 store record plus `log_anchor` (a fresh random id per snapshot) and `log_prev` (the anchor of the
snapshot it replaced). A log row is `{"a": anchor, "n": k, "set": {field: value}, "lists": {field: {"drop": i, "push": [..]}}}`
- one row per mutation, however many fields it changed (a multi-field update is one framed record). `n` counts 1, 2, ...
within the snapshot named by `a`; the first row after a snapshot also carries `prev` (the anchor before it).

Recovery (reader, no lock): read the snapshot (the file, else its `.bak`: durable.read_sealed rules), then apply the rows of
its anchor in order, and then the rows of each later snapshot whose `prev` chains to it. A torn tail is ignored (the writer
repairs it on its next append); corruption inside the log is `store_corrupt`. A snapshot without `log_anchor` (written by an
older Hydralysis, by hand, or with HYDRALYSIS_STORE_LOG=0) takes no rows, so a stale log can never be replayed onto it.

Compaction: the mutation that reaches SNAPSHOT_EVERY is appended to the log first (durable), then the new snapshot (that
state, with a new anchor) is written with durable.write_sealed (which keeps the old one as `.bak`), then the log is trimmed
to the rows from the `.bak` snapshot on. So `.bak` plus the log still reaches the newest state, and a crash at any point
leaves a chain that reads as the last acknowledged state.

The writer must hold the view's lock (every caller of workcopy._save_store does). It keeps, per store path, the state it
last wrote or read (keyed by the snapshot's and the log's stat), so a mutation costs a diff of the record against that copy
plus one fsynced append; another process' write changes the stat and forces a re-read.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path

from hydralysis import durable

SNAPSHOT_EVERY = 64
SNAPSHOT_LOG_BYTES = 4 * 1024 * 1024
LIST_FIELDS = ("edits", "reverted", "journal", "commits", "archived", "changesets")


def enabled() -> bool:
    """HYDRALYSIS_STORE_LOG=0 writes whole snapshots again (the reader always honours a log)."""
    return os.environ.get("HYDRALYSIS_STORE_LOG", "1") != "0"


def log_path(path) -> Path:
    path = Path(path)
    return path.with_name(path.name + ".log")


def _log(path) -> durable.AppendLog:
    return durable.AppendLog(log_path(path))


# --------------------------------------------------------------------------------------------------------- reading

def _rows(path) -> list[dict]:
    target = log_path(path)
    if not target.is_file():
        return []
    scan = durable.scan_file(target)
    if scan.corrupt:
        raise durable.StoreCorrupt(Path(path), target, {target.name: "log corrupt at byte %d" % scan.corrupt["offset"]})
    return scan.records


def apply_row(record: dict, row: dict) -> None:
    for field, value in (row.get("set") or {}).items():
        record[field] = value
    for field, change in (row.get("lists") or {}).items():
        current = record.get(field) if isinstance(record.get(field), list) else []
        record[field] = current[int(change.get("drop", 0)):] + list(change.get("push") or [])


def chain(record: dict, rows: list[dict]) -> tuple[dict, dict]:
    """Apply to RECORD (a snapshot) the rows that follow it. Returns (record, position) where position names the anchor
    and the last `n` applied under it, and the anchor of the snapshot the reader started from."""
    anchor = record.get("log_anchor")
    if not isinstance(anchor, str):
        return record, {"anchor": None, "n": 0, "start": None}
    start, current, n = anchor, anchor, 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("a") == current and row.get("n") == n + 1:
            apply_row(record, row)
            n += 1
        elif row.get("a") != current and row.get("n") == 1 and row.get("prev") == current and n > 0:
            # the rows of the next snapshot: it holds exactly this state, so its rows continue the chain
            current, n = row["a"], 0
            apply_row(record, row)
            n = 1
    return record, {"anchor": current, "n": n, "start": start}


READ_RETRIES = 8


def _identity(path: Path):
    try:
        found = Path(path).stat()
        return found.st_ino, found.st_mtime_ns, found.st_size
    except (FileNotFoundError, NotADirectoryError):
        return None


def read(path, record: dict | None, reread=None) -> dict | None:
    """The store at PATH: RECORD (its snapshot, as workcopy read it) with the log applied.

    The reader holds no lock. When the snapshot file was replaced while the snapshot and then the log were read, the log
    may already be trimmed past the snapshot read (two compactions in between), and the chain would silently stop at that
    snapshot. So REREAD (a call that reads the snapshot again) is used to read both again until the snapshot stayed the
    same file across the read (bounded: READ_RETRIES; the writer compacts only every SNAPSHOT_EVERY mutations)."""
    before = _identity(path)
    for attempt in range(READ_RETRIES + 1):
        if attempt:
            before = _identity(path)
            record = reread()
        if record is None or not isinstance(record.get("log_anchor"), str):
            return record
        rows = _rows(path)
        if reread is None or _identity(path) == before:
            break
    return chain(record, rows)[0]


# --------------------------------------------------------------------------------------------------------- writing

_CACHE: dict[str, dict] = {}
_GUARD = threading.Lock()


def _stat(path: Path):
    try:
        found = path.stat()
        return found.st_mtime_ns, found.st_size
    except FileNotFoundError:
        return None


def _signature(path: Path):
    return _stat(path), _stat(log_path(path))


def known_edits(path) -> list | None:
    """The clean records of the store on disk as this process last wrote or read them, when the files are unchanged
    since (else None). Read-only for the caller."""
    path = Path(path)
    with _GUARD:
        cached = _CACHE.get(os.path.normcase(os.path.abspath(path)))
    if not cached or cached["signature"] != _signature(path):
        return None
    edits = cached["record"].get("edits")
    return edits if isinstance(edits, list) else None


def _owned(value):
    return json.loads(json.dumps(value))


def _current(path: Path) -> dict | None:
    """What the writer diffs against: the on-disk chain (cached while the files are unchanged), or None when there is no
    log-anchored snapshot to append to."""
    key = os.path.normcase(os.path.abspath(path))
    signature = _signature(path)
    with _GUARD:
        cached = _CACHE.get(key)
    if cached and cached["signature"] == signature:
        return cached
    try:
        kind, snapshot, _ = durable.inspect_file(path)
    except OSError:
        return None
    if kind != "sealed" or not isinstance(snapshot.get("log_anchor"), str) or snapshot.get("version") != 3:
        return None  # no snapshot, a .bak-only read, an old format: the next write is a snapshot
    rows = _rows(path)
    record, position = chain(snapshot, rows)
    # The log bytes of the current anchor's rows: the size trigger counts what was appended since the last snapshot, not
    # the rows of the `.bak` snapshot that the trim keeps (else a size-triggered compaction is followed by another one).
    since = sum(len(durable.frame(row)) for row in rows if isinstance(row, dict) and row.get("a") == position["anchor"])
    found = {"signature": signature, "record": record, "anchor": position["anchor"], "n": position["n"],
             "prev": snapshot.get("log_prev"), "key": key, "size": path.stat().st_size, "since": since}
    _remember(key, found)
    return found


CACHE_ENTRIES = 32  # store paths kept per process (each entry holds a parsed store of up to MAX_HISTORY_BYTES)


def _remember(key: str, entry: dict) -> None:
    with _GUARD:
        _CACHE.pop(key, None)
        _CACHE[key] = entry
        while len(_CACHE) > CACHE_ENTRIES:
            _CACHE.pop(next(iter(_CACHE)))


def _list_change(old: list, new: list):
    """{"drop": i, "push": [...]} when NEW is OLD without its first i items plus some new ones; else None (set whole)."""
    if not new:
        return None
    if len(new) >= len(old) and new[:len(old)] == old:
        return {"drop": 0, "push": new[len(old):]}
    for drop in range(1, len(old) + 1):
        kept = len(old) - drop
        if kept <= len(new) and old[drop:] == new[:kept]:
            return {"drop": drop, "push": new[kept:]}
    return None


def diff(old: dict, new: dict) -> dict:
    """The row body that turns OLD into NEW: whole fields in `set`, list fields as drop/push when they only shifted."""
    row: dict = {}
    for field in new:
        if field in ("log_anchor", "log_prev"):
            continue
        before, after = old.get(field, None), new[field]
        if field in old and before == after and type(before) is type(after):
            continue
        if field in LIST_FIELDS and isinstance(before, list) and isinstance(after, list):
            change = _list_change(before, after)
            if change is not None:
                if change["drop"] or change["push"]:
                    row.setdefault("lists", {})[field] = change
                continue
        row.setdefault("set", {})[field] = after
    for field in old:
        if field not in new and field not in ("log_anchor", "log_prev"):
            row.setdefault("set", {})[field] = None
    return row


def _snapshot(path: Path, record: dict, prev: str | None, max_bytes, too_large) -> None:
    anchor = uuid.uuid4().hex
    body = {**record, "log_anchor": anchor}
    if prev:
        body["log_prev"] = prev
    payload = durable.write_sealed(path, body, max_bytes=max_bytes, too_large=too_large)
    # From here the snapshot is durable: what follows is upkeep, and a failure of it must not be reported as a failed
    # write (the caller would undo or retry a mutation that is stored). The next write retries it.
    key = os.path.normcase(os.path.abspath(path))
    try:
        if prev is None and not durable.backup_path(path).is_file():
            # The first snapshot is also the `.bak`: a damaged main file then still reads (from it plus the log) as the
            # newest state, where the whole-store writer had no previous version until its second write.
            durable.atomic_write(durable.backup_path(path), payload, point="backup")
        durable.fault("store.after_snapshot")
        _trim(path, prev)
    except OSError as error:
        _upkeep_failed(path, "snapshot upkeep", error)
        with _GUARD:
            _CACHE.pop(key, None)
        return
    _remember(key, {"signature": _signature(path), "record": _owned(body), "anchor": anchor, "n": 0, "prev": prev,
                    "key": key, "size": path.stat().st_size, "since": 0})


# The last compaction failure per store path (an OSError after the mutation was durable): reported, never raised.
UPKEEP_ERRORS: dict[str, str] = {}


def _upkeep_failed(path: Path, what: str, error: BaseException) -> None:
    with _GUARD:
        UPKEEP_ERRORS[os.path.normcase(os.path.abspath(path))] = "%s: %s" % (what, error)
        while len(UPKEEP_ERRORS) > CACHE_ENTRIES:
            UPKEEP_ERRORS.pop(next(iter(UPKEEP_ERRORS)))


def _trim(path: Path, keep_from: str | None) -> None:
    """Drop the log rows older than the `.bak` snapshot's (anchor KEEP_FROM); they can no longer be reached."""
    target = log_path(path)
    if not target.is_file():
        return
    log = durable.AppendLog(target)
    with durable.file_lock(log.lock_path, None, what="log " + target.name):
        scan = durable.scan_file(target)
        if scan.corrupt:
            return  # leave it for review; readers report it
        lines = []
        keeping = False
        with open(target, "rb") as handle:
            raw = handle.read(scan.valid_end)
        for line, row in zip(raw.splitlines(keepends=True), scan.records):
            if keep_from is not None and isinstance(row, dict) and row.get("a") == keep_from:
                keeping = True
            if keeping:
                lines.append(line)
        data = b"".join(lines)
        if data == raw and scan.size == scan.valid_end:
            return
        durable.atomic_write(target, data, point="store.trim")
        log._remember(len(data))


def _fits(record: dict, max_bytes: int | None, too_large: str | None) -> None:
    """The whole-store writer's budget, measured exactly (as durable.write_sealed does), before anything is written."""
    if max_bytes is not None and len(durable.dumps_sealed({**record, "log_anchor": "0" * 32, "log_prev": "0" * 32})) > max_bytes:
        raise ValueError(too_large or "record would exceed %d bytes; existing file preserved" % max_bytes)


def save(path, record: dict, *, max_bytes: int | None, too_large: str | None) -> None:
    """Write RECORD (the complete v3 store) as one log row, or as a snapshot when there is none to append to or the log
    is due for compaction. Durable (fsynced) before it returns."""
    path = Path(path)
    if not enabled():
        durable.write_sealed(path, record, max_bytes=max_bytes, too_large=too_large)
        return
    current = _current(path)
    if current is None:
        _snapshot(path, record, None, max_bytes, too_large)
        return
    body = diff(current["record"], record)
    if not body:
        return  # nothing changed: the store on disk already is RECORD
    after = current["n"] + 1
    row = {"a": current["anchor"], "n": after, **body}
    if current["n"] == 0 and current.get("prev"):
        row["prev"] = current["prev"]
    line = durable.frame(row)
    since = current.get("since", 0)
    due = after >= SNAPSHOT_EVERY or since + len(line) > SNAPSHOT_LOG_BYTES
    # Budget: an upper estimate (snapshot size plus four times every row since) decides when to measure exactly, so a
    # store that would pass the whole-store writer's 20 MiB limit is refused here too, before the row is appended.
    estimate = current["size"] + 4 * len(line)
    if max_bytes is not None and (due or estimate > max_bytes // 2):
        _fits(record, max_bytes, too_large)
    _log(path).append(row)
    durable.fault("store.after_append")
    apply_row(current["record"], _owned(row))
    state = {**current, "n": after, "size": estimate, "signature": _signature(path), "since": since + len(line)}
    _remember(current["key"], state)
    if due:
        # The mutation is durable (the row above): compaction is best effort from here. A failure (disk full, a sharing
        # violation that outlasts replace_file's retries) is recorded, the log stays whole, and the next write is due again.
        try:
            _snapshot(path, record, current["anchor"], max_bytes, too_large)
        except (OSError, ValueError) as error:
            _upkeep_failed(path, "compaction", error)
            with _GUARD:
                _CACHE.pop(current["key"], None)
