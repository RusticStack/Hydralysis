"""Durable IO: the one way record-bearing state is written (PROTOCOL-3.md section 4.1).

* atomic_write: temporary file in the same directory, write, flush, fsync, replace
  (MoveFileExW with write-through on Windows, os.replace plus a directory fsync
  elsewhere). A PermissionError (an antivirus scan or an indexer holding the target)
  is retried with backoff.
* Sealed JSON: a top-level `seal` over the canonical body. A reader that finds a
  zero-length, unparseable or mis-sealed file falls back to `<file>.bak`, the previous
  sealed version kept by the writer, and otherwise raises `store_corrupt`. It never
  starts empty. A file that was never written is not corruption.
* AppendLog: CRC-32 framed JSON lines. Readers never write and ignore a torn final
  fragment; writers check the tail on EVERY acquisition of the writer lock (the file ends
  in LF and its size equals the end of the last valid line, otherwise the new bytes are
  scanned) and repair a torn tail under that lock before appending; an invalid line
  followed by a valid one is corruption (`lineage_corrupt`) and is refused. Logs are read
  by streaming, not through localio.read_bytes, so the 32 MiB metadata budget does not
  apply to them.
* fault(name): a test hook, inert unless HYDRALYSIS_TEST_MODE=1 and
  HYDRALYSIS_TEST_FAULT=<name>:<action> are both set.

Measured cost (input for gate 9.10): write_sealed is a read, a `.bak` atomic_write and a main
atomic_write, i.e. two fsyncs and two replaces: about 16 ms per 600-byte record on D: (mean of
100 writes, Y0a review), against 0.11 ms per read_sealed. Not measured on F:, C: or E:.

What is not verified: whether write-through is honoured by the owner's ReFS Dev Drive,
and anything about power loss. The claims are tested by killing a writer process and by
torn-file injection, and rest on the documented flags.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
import uuid
import zlib
from contextlib import contextmanager
from pathlib import Path

from hydralysis.localio import read_bytes
from hydralysis.locks import locked

# --------------------------------------------------------------------------- errors


class StoreCorrupt(ValueError):
    """No valid version of a record file exists (the file and its .bak are both unusable)."""

    code = "store_corrupt"

    def __init__(self, path, backup, reasons: dict):
        self.path, self.backup, self.reasons = str(path), str(backup), dict(reasons)
        detail = "; ".join("%s: %s" % (name, reason) for name, reason in self.reasons.items())
        super().__init__("store_corrupt: no valid version of %s (previous version %s); %s. "
                         "Nothing was started empty; preserve both files and repair them." % (path, backup, detail))


class LineageCorrupt(ValueError):
    """An append log has an invalid line followed by a valid one."""

    code = "lineage_corrupt"

    def __init__(self, path, offset: int, records: list):
        self.path, self.offset, self.records = str(path), int(offset), records
        super().__init__("lineage_corrupt: %s has an invalid line at byte %d followed by a valid line; "
                         "reads stop at the last good line, appends are refused until it is repaired" % (path, offset))


class FaultInjected(RuntimeError):
    pass


# --------------------------------------------------------------------------- test hook

def fault(name: str) -> int | None:
    """No-op unless HYDRALYSIS_TEST_MODE=1 and HYDRALYSIS_TEST_FAULT=<name>:<action>.

    Names: atomic.{torn,before_replace,after_replace} (the main write), backup.* and aside.* (the same three
    points for the `.bak` and `.corrupt-*` copies), log.copy.*, log.{torn_append,before_write,after_append},
    log.repair.{after_copy,after_truncate}, sealed.after_backup.

    Actions: `exit` (end the process at once, as kill -9 would), `raise` (FaultInjected),
    `torn:<n>` (returns n; the call site writes n bytes and then ends the process).
    """
    spec = os.environ.get("HYDRALYSIS_TEST_FAULT")
    if not spec or os.environ.get("HYDRALYSIS_TEST_MODE") != "1":
        return None
    target, _, action = spec.partition(":")
    if target != name:
        return None
    if action == "exit":
        _die()
    if action == "raise":
        raise FaultInjected(name)
    if action.startswith("torn:") and action[5:].isdigit():
        return int(action[5:])
    raise ValueError("HYDRALYSIS_TEST_FAULT action must be exit, raise or torn:<n>, got %r" % action)


def _die() -> None:
    try:
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(137)


# --------------------------------------------------------------------------- replace

RETRY_FIRST_S = 0.05
RETRY_MAX_DELAY_S = 0.5
RETRY_TOTAL_S = 10.0
LOCK_TIMEOUT_S = 30.0
NATIVE_MOVE = os.name == "nt"
_sleep = time.sleep


def _extended(path) -> str:
    text = os.path.abspath(os.fspath(path))
    if len(text) >= 240 and not text.startswith("\\\\?\\"):
        text = "\\\\?\\UNC\\" + text[2:] if text.startswith("\\\\") else "\\\\?\\" + text
    return text


def _move_file_ex(source, destination) -> None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    kernel.MoveFileExW.restype = wintypes.BOOL
    # MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH: returns only when the move is on disk.
    if not kernel.MoveFileExW(_extended(source), _extended(destination), 0x1 | 0x8):
        raise ctypes.WinError(ctypes.get_last_error())


def _fsync_directory(directory) -> None:
    if os.name == "nt":
        return  # directory entries cannot be forced from Python on Windows; every state self-validates
    try:
        descriptor = os.open(os.fspath(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _replace_once(source, destination) -> None:
    if NATIVE_MOVE:
        _move_file_ex(source, destination)
        return
    os.replace(source, destination)
    _fsync_directory(Path(destination).parent)


def replace_file(source, destination) -> None:
    """Replace destination with source, retrying a PermissionError with backoff."""
    delay, waited = RETRY_FIRST_S, 0.0
    while True:
        try:
            _replace_once(source, destination)
            return
        except PermissionError:
            if waited + delay > RETRY_TOTAL_S:
                raise
            _sleep(delay)
            waited += delay
            delay = min(delay * 2, RETRY_MAX_DELAY_S)


def _write_file(path: Path, data: bytes) -> None:
    with open(path, "xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def atomic_write(path, data: bytes, *, point: str = "atomic") -> None:
    """Write bytes so that a reader sees the old file or the new one, never a mixture."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        torn = fault(point + ".torn")
        if torn is not None:
            # A non-atomic writer killed halfway: n bytes land in the file itself.
            with open(path, "wb") as handle:
                handle.write(data[:torn])
                handle.flush()
                os.fsync(handle.fileno())
            _die()
        _write_file(temporary, data)
        fault(point + ".before_replace")
        replace_file(temporary, path)
        fault(point + ".after_replace")
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- sealed JSON

def canonical(value) -> bytes:
    """The canonical form of PROTOCOL-3.md 3.4: sorted keys, minimal separators, UTF-8, floats allowed."""
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
                          allow_nan=False).encode("utf-8")
    except UnicodeEncodeError as exc:  # an unpaired surrogate cannot be UTF-8; 3.4 refuses it
        raise ValueError("canonical form refuses an unpaired surrogate (PROTOCOL-3.md 3.4): %s" % exc) from exc


def seal_of(body: dict) -> dict:
    return {"algo": "sha256", "value": hashlib.sha256(canonical(body)).hexdigest()}


def dumps_sealed(value: dict, indent: int | None = 2) -> bytes:
    if not isinstance(value, dict):
        raise ValueError("a sealed record must be a JSON object")
    if "seal" in value:
        raise ValueError("a sealed record cannot carry its own top-level 'seal' key")
    return json.dumps({**value, "seal": seal_of(value)}, indent=indent).encode("utf-8")


def _classify(raw: bytes | None) -> tuple[str, dict | None, str]:
    """(kind, value, reason). kind: missing | invalid | sealed | unsealed (a pre-seal record)."""
    if raw is None:
        return "missing", None, "missing"
    if not raw:
        return "invalid", None, "zero-length"
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return "invalid", None, "unparseable (%s)" % str(exc)[:80]
    if not isinstance(value, dict):
        return "invalid", None, "not a JSON object"
    if "seal" not in value:
        return "unsealed", value, ""
    claimed = value.pop("seal")
    if not isinstance(claimed, dict) or claimed.get("algo") != "sha256" or not isinstance(claimed.get("value"), str):
        return "invalid", None, "malformed seal"
    try:
        actual = seal_of(value)["value"]
    except (ValueError, TypeError):
        return "invalid", None, "body cannot be canonicalised"
    if actual != claimed["value"]:
        return "invalid", None, "mis-sealed (content does not match its seal)"
    return "sealed", value, ""


def _read(path, max_bytes: int | None) -> bytes | None:
    try:
        return read_bytes(path) if max_bytes is None else read_bytes(path, max_bytes=max_bytes)
    except FileNotFoundError:
        return None


def backup_path(path) -> Path:
    path = Path(path)
    return path.with_name(path.name + ".bak")


def inspect_file(path, max_bytes: int | None = None, require_seal: bool = False) -> tuple[str, dict | None, str]:
    kind, value, reason = _classify(_read(path, max_bytes))
    if kind == "unsealed" and require_seal:
        return "invalid", None, "no seal"
    return kind, value, reason


def exists(path) -> bool:
    """True when a record file or its previous version is present (a missing main with a .bak is not 'no record')."""
    path = Path(path)
    return path.is_file() or backup_path(path).is_file()


_MISSING = object()


def read_sealed_info(path, *, default=_MISSING, max_bytes: int | None = None,
                     require_seal: bool = False) -> tuple[dict, str]:
    """Return (record, source) with source `file` or `backup`.

    Falls back to `<file>.bak` when the file is missing, zero-length, unparseable or mis-sealed.
    Raises StoreCorrupt when neither is valid; FileNotFoundError (or `default`) only when
    neither exists. A permission error or a read-budget error is not corruption and propagates.
    """
    path = Path(path)
    kind, value, reason = inspect_file(path, max_bytes, require_seal)
    if value is not None:
        return value, "file"
    backup = backup_path(path)
    bkind, bvalue, breason = inspect_file(backup, max_bytes, require_seal)
    if bvalue is not None:
        return bvalue, "backup"
    if kind == "missing" and bkind == "missing":
        if default is _MISSING:
            raise FileNotFoundError(str(path))
        return default, "missing"
    raise StoreCorrupt(path, backup, {path.name: reason, backup.name: breason})


def read_sealed(path, **options) -> dict:
    return read_sealed_info(path, **options)[0]


def _keep_previous(path: Path) -> None:
    """Under the writer's exclusion: keep the current file as `.bak` if it is valid, else preserve it aside."""
    raw = _read(path, None) if path.exists() else None
    kind, _, _ = _classify(raw)
    if kind in ("sealed", "unsealed"):
        backup = backup_path(path)
        if _read(backup, None) != raw:
            atomic_write(backup, raw, point="backup")
        fault("sealed.after_backup")
    elif kind == "invalid" and raw:
        # Never let a bad file replace the good previous version; keep it for review.
        atomic_write(path.with_name("%s.corrupt-%s" % (path.name, hashlib.sha256(raw).hexdigest()[:8])), raw,
                     point="aside")


def write_sealed(path, value: dict, *, indent: int | None = 2, max_bytes: int | None = None,
                too_large: str | None = None) -> bytes:
    """Seal, keep the previous valid version as `.bak`, then replace atomically. Returns the bytes written."""
    path = Path(path)
    payload = dumps_sealed(value, indent)
    if max_bytes is not None and len(payload) > max_bytes:
        raise ValueError(too_large or "record would exceed %d bytes; existing file preserved" % max_bytes)
    path.parent.mkdir(parents=True, exist_ok=True)
    _keep_previous(path)
    atomic_write(path, payload)
    return payload


@contextmanager
def file_lock(path, timeout_s: float | None = None, what: str = "durable record"):
    """Cross-process exclusive lock (released by the OS if the holder dies)."""
    with locked(Path(path), LOCK_TIMEOUT_S if timeout_s is None else timeout_s, what=what):
        yield


def update_sealed(path, update, *, lock_path=None, default=None, timeout_s: float | None = None) -> dict:
    """Read-modify-write a sealed record under a cross-process lock; no update is lost."""
    path = Path(path)
    with file_lock(lock_path or path.with_name(path.name + ".lock"), timeout_s, what="record " + path.name):
        current = read_sealed(path, default=default if default is not None else {})
        result = update(current)
        value = current if result is None else result
        write_sealed(path, value)
        return value


# --------------------------------------------------------------------------- append log

_HEX = frozenset(b"0123456789abcdef")
# key -> end of the last line this process knows to be valid (the size after its own last append or repair).
# An entry only lets a writer skip a scan: every lock acquisition still checks the size and the final LF.
_VERIFIED: dict[str, int] = {}
_VERIFIED_GUARD = threading.Lock()
CHUNK = 1 << 20
TAIL_WINDOW = 64 * 1024
TAIL_WINDOW_MAX = 8 * 1024 * 1024
_UNBOUNDED = object()


def frame(record) -> bytes:
    """`crc-hex8 SP json LF`, CRC-32 (IEEE 802.3, zlib.crc32) of the JSON bytes, ASCII only."""
    body = json.dumps(record, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return b"%08x %s\n" % (zlib.crc32(body) & 0xFFFFFFFF, body)


def _parse(line: bytes):
    if len(line) < 10 or line[8:9] != b" " or not all(byte in _HEX for byte in line[:8]):
        return None
    body = line[9:]
    if zlib.crc32(body) & 0xFFFFFFFF != int(line[:8], 16):
        return None
    try:
        return (json.loads(body.decode("utf-8")),)
    except (UnicodeDecodeError, ValueError):
        return None


class Scan:
    """What a reader sees: the valid prefix, a torn tail (ignored) or mid-log corruption."""

    def __init__(self, records: list, valid_end: int, size: int, torn: dict | None, corrupt: dict | None):
        self.records, self.valid_end, self.size = records, valid_end, size
        self.torn_tail, self.corrupt = torn, corrupt

    def as_status(self) -> dict:
        return {"records": len(self.records), "valid_bytes": self.valid_end, "size": self.size,
                "torn_tail": self.torn_tail, "corrupt": self.corrupt}


def scan_chunks(chunks, base: int = 0, collect: bool = True, size: int | None = None) -> Scan:
    """Scan consecutive chunks that start at byte `base` of a log (`base` must be a line start).

    `size` is the total size to report (default: base plus the bytes seen). With collect=False the
    lines are validated but the records are not kept (`Scan.records` is then empty).
    """
    records: list = []
    pending, pending_start, seen = b"", base, base
    bad_from, bad_line, line_no = None, 0, 0
    for chunk in chunks:
        seen += len(chunk)
        pending += chunk
        cursor = 0
        while True:
            end = pending.find(b"\n", cursor)
            if end < 0:
                break
            line_no += 1
            parsed = _parse(pending[cursor:end])
            if parsed is None:
                if bad_from is None:
                    bad_from, bad_line = pending_start + cursor, line_no
            elif bad_from is not None:
                return Scan(records, bad_from, seen if size is None else size, None,
                            {"offset": bad_from, "line": bad_line, "error": "lineage_corrupt"})
            elif collect:
                records.append(parsed[0])
            cursor = end + 1
        pending_start += cursor
        pending = pending[cursor:]
    total = seen if size is None else size
    if pending and bad_from is None:  # an unterminated fragment is never valid, even if its CRC happens to match
        bad_from, bad_line = pending_start, line_no + 1
    if bad_from is None:
        return Scan(records, total, total, None, None)
    return Scan(records, bad_from, total, {"offset": bad_from, "bytes": total - bad_from}, None)


def scan_bytes(data: bytes) -> Scan:
    return scan_chunks([data])


def _file_chunks(handle, start: int, stop: int):
    handle.seek(start)
    remaining = stop - start
    while remaining > 0:
        chunk = handle.read(min(CHUNK, remaining))
        if not chunk:
            return
        remaining -= len(chunk)
        yield chunk


def scan_file(path, start: int = 0, collect: bool = True) -> Scan:
    """Scan a log by streaming, from byte `start` (a line start) to its size at the moment it was opened."""
    try:
        handle = open(path, "rb")
    except FileNotFoundError:
        return Scan([], 0, 0, None, None)
    with handle:
        stop = os.fstat(handle.fileno()).st_size
        if start > stop:
            start = 0
        return scan_chunks(_file_chunks(handle, start, stop), start, collect, stop)


def _complete_lines(path):
    """Yield every LF-terminated line of a file by streaming (a missing file yields nothing)."""
    try:
        handle = open(path, "rb")
    except FileNotFoundError:
        return
    with handle:
        stop = os.fstat(handle.fileno()).st_size
        pending = b""
        for chunk in _file_chunks(handle, 0, stop):
            pending += chunk
            *lines, pending = pending.split(b"\n")
            yield from lines


def _tail_last_valid(path):
    """`(record,)` for the last valid line, None when there is none, or _UNBOUNDED.

    Reads from the end in growing windows. It trusts the tail: it does not look for corruption earlier
    in the log. _UNBOUNDED means TAIL_WINDOW_MAX was reached without finding a valid line.
    """
    try:
        handle = open(path, "rb")
    except FileNotFoundError:
        return None
    with handle:
        size = os.fstat(handle.fileno()).st_size
        window = TAIL_WINDOW
        while True:
            start = max(0, size - window)
            handle.seek(start)
            data = handle.read(size - start)
            if start:  # the first line of the window may be cut: begin at the next line
                cut = data.find(b"\n")
                data = b"" if cut < 0 else data[cut + 1:]
            lines = data.split(b"\n")[:-1]  # the last element is empty or an unterminated fragment
            for line in reversed(lines):
                parsed = _parse(line)
                if parsed is not None:
                    return parsed
            if start == 0:
                return None
            if window >= TAIL_WINDOW_MAX:
                return _UNBOUNDED
            window *= 4


class AppendLog:
    """CRC-framed JSON lines. `lock_path` is the log's writer lock (default `<log>.lock`)."""

    def __init__(self, path, lock_path=None, by: str | None = None, lock_timeout_s: float | None = None):
        self.path = Path(path)
        self.lock_path = Path(lock_path) if lock_path else self.path.with_name(self.path.name + ".lock")
        self.by = by or "pid:%d" % os.getpid()
        self.lock_timeout_s = lock_timeout_s
        self._key = os.path.normcase(os.path.abspath(self.path))

    # readers: no lock, never write; streamed, so the 32 MiB localio budget does not apply
    def scan(self) -> Scan:
        return scan_file(self.path)

    def read(self) -> list:
        """The valid prefix; a torn tail is ignored. Mid-log corruption raises LineageCorrupt. O(n)."""
        result = self.scan()
        if result.corrupt:
            raise LineageCorrupt(self.path, result.corrupt["offset"], result.records)
        return result.records

    def status(self) -> dict:
        return self.scan().as_status()

    def last(self, *, strict: bool = False):
        """The last valid record, or None.

        By default only the tail is read (bounded) and corruption earlier in the log is not looked for;
        strict=True scans the whole log and raises LineageCorrupt like read().
        """
        if not strict:
            found = _tail_last_valid(self.path)
            if found is not _UNBOUNDED:
                return None if found is None else found[0]
        records = self.read()
        return records[-1] if records else None

    def repairs(self) -> list:
        rows = []
        for line in _complete_lines(self.path.with_name(self.path.name + ".repairs")):
            parsed = _parse(line)
            if parsed is not None:
                rows.append(parsed[0])
        return rows

    # writers
    def append(self, record, *, lock_held: bool = False) -> int:
        """Append one line, fsynced. Returns its byte offset. Pass lock_held when the caller holds the writer lock."""
        line = frame(record)
        if lock_held:
            return self._append_locked(line)
        with file_lock(self.lock_path, self.lock_timeout_s, what="log " + self.path.name):
            return self._append_locked(line)

    def repair(self, *, lock_held: bool = False) -> dict | None:
        """Repair a torn tail (and refuse corruption) without appending. Returns the repair record or None."""
        if lock_held:
            return self._check_tail()
        with file_lock(self.lock_path, self.lock_timeout_s, what="log " + self.path.name):
            return self._check_tail()

    def _check_tail(self) -> dict | None:
        """The check made on EVERY acquisition of the writer lock; returns the repair record, if one was made.

        Cheap case: the size equals the end this process last saw valid and the file ends in LF. Otherwise
        scan what this process has not verified (from its last known valid end when that is still a line
        boundary, else from the start), refuse mid-log corruption and repair a torn tail. A writer in another
        process that was killed mid-line changes the size and leaves no final LF, so it is always noticed.
        """
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            size = 0
        if size == 0:
            self._remember(0)
            return None
        with _VERIFIED_GUARD:
            known = _VERIFIED.get(self._key)
        start = 0
        if known and known <= size:
            with open(self.path, "rb") as handle:
                handle.seek(known - 1)
                if handle.read(1) == b"\n":
                    start = known
        if start == size:  # nothing new, and the byte before `start` is the LF that ends the last line
            return None
        result = scan_file(self.path, start, collect=False)
        if result.corrupt:
            raise LineageCorrupt(self.path, result.corrupt["offset"], [])
        if not result.torn_tail:
            self._remember(result.size)
            return None
        entry = self._repair_tail(result.torn_tail["offset"], result.size)
        self._remember(entry["offset"])
        return entry

    def _remember(self, valid_end: int) -> None:
        with _VERIFIED_GUARD:
            _VERIFIED[self._key] = valid_end

    def _repair_tail(self, offset: int, size: int) -> dict:
        with open(self.path, "rb") as handle:
            handle.seek(offset)
            tail = handle.read(size - offset)
        digest = hashlib.sha256(tail).hexdigest()
        # (c) preserve the fragment and force the copy; every step is idempotent.
        atomic_write(self.path.with_name("%s.torn-%d-%s" % (self.path.name, offset, digest[:8])), tail, point="log.copy")
        fault("log.repair.after_copy")
        with open(self.path, "r+b") as handle:
            handle.truncate(offset)
            handle.flush()
            os.fsync(handle.fileno())
        fault("log.repair.after_truncate")
        entry = {"at": time.time(), "offset": offset, "bytes": len(tail), "sha256": digest, "by": self.by}
        try:  # best effort: losing it costs only the record of the repair
            self._raw_append(self.path.with_name(self.path.name + ".repairs"), frame(entry), repair_tail=True, faults=False)
        except OSError:
            pass
        return entry

    @staticmethod
    def _raw_append(path: Path, data: bytes, repair_tail: bool = False, faults: bool = True) -> int:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
        fresh = not path.exists()
        descriptor = os.open(os.fspath(path), flags, 0o666)
        try:
            offset = os.lseek(descriptor, 0, os.SEEK_END)
            if repair_tail and offset:
                with open(path, "rb") as handle:
                    handle.seek(offset - 1)
                    if handle.read(1) != b"\n":
                        data = b"\n" + data
            torn = fault("log.torn_append") if faults else None
            if torn is not None:
                os.write(descriptor, data[:torn])
                os.fsync(descriptor)
                _die()
            if faults:
                fault("log.before_write")
            view = memoryview(data)
            while view:
                view = view[os.write(descriptor, view):]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if fresh:
            _fsync_directory(path.parent)
        return offset

    def _append_locked(self, line: bytes) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._check_tail()
            offset = self._raw_append(self.path, line)
            self._remember(offset + len(line))
            fault("log.after_append")
            return offset
        except BaseException:
            with _VERIFIED_GUARD:
                _VERIFIED.pop(self._key, None)
            raise
