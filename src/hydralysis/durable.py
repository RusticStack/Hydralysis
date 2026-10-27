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
  fragment; writers repair it under the log's lock before appending; an invalid line
  followed by a valid one is corruption (`lineage_corrupt`) and is refused.
* fault(name): a test hook, inert unless HYDRALYSIS_TEST_MODE=1 and
  HYDRALYSIS_TEST_FAULT=<name>:<action> are both set.

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
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("utf-8", "surrogatepass")


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
_VERIFIED: set[str] = set()
_VERIFIED_GUARD = threading.Lock()


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


def scan_bytes(data: bytes) -> Scan:
    records, position, bad_from, line_no = [], 0, None, 0
    bad_line = 0
    while position < len(data):
        end = data.find(b"\n", position)
        if end < 0:  # an unterminated fragment is never valid, even if its CRC happens to match
            if bad_from is None:
                bad_from, bad_line = position, line_no + 1
            break
        line_no += 1
        parsed = _parse(data[position:end])
        if parsed is None:
            if bad_from is None:
                bad_from, bad_line = position, line_no
        elif bad_from is not None:
            return Scan(records, bad_from, len(data), None,
                        {"offset": bad_from, "line": bad_line, "error": "lineage_corrupt"})
        else:
            records.append(parsed[0])
        position = end + 1
    if bad_from is None:
        return Scan(records, len(data), len(data), None, None)
    return Scan(records, bad_from, len(data), {"offset": bad_from, "bytes": len(data) - bad_from}, None)


class AppendLog:
    """CRC-framed JSON lines. `lock_path` is the log's writer lock (default `<log>.lock`)."""

    def __init__(self, path, lock_path=None, by: str | None = None, lock_timeout_s: float | None = None):
        self.path = Path(path)
        self.lock_path = Path(lock_path) if lock_path else self.path.with_name(self.path.name + ".lock")
        self.by = by or "pid:%d" % os.getpid()
        self.lock_timeout_s = lock_timeout_s
        self._key = os.path.normcase(os.path.abspath(self.path))

    # readers: no lock, never write
    def scan(self) -> Scan:
        data = _read(self.path, None)
        return scan_bytes(data or b"")

    def read(self) -> list:
        """The valid prefix; a torn tail is ignored. Mid-log corruption raises LineageCorrupt."""
        result = self.scan()
        if result.corrupt:
            raise LineageCorrupt(self.path, result.corrupt["offset"], result.records)
        return result.records

    def status(self) -> dict:
        return self.scan().as_status()

    def last(self):
        records = self.read()
        return records[-1] if records else None

    def repairs(self) -> list:
        data = _read(self.path.with_name(self.path.name + ".repairs"), None) or b""
        rows = []
        for line in data.split(b"\n"):
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
            return self._repair()
        with file_lock(self.lock_path, self.lock_timeout_s, what="log " + self.path.name):
            return self._repair()

    def _clean_tail(self) -> bool:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return True
        if size == 0:
            return True
        with open(self.path, "rb") as handle:
            handle.seek(size - 1)
            return handle.read(1) == b"\n"

    def _repair(self) -> dict | None:
        data = _read(self.path, None) or b""
        result = scan_bytes(data)
        if result.corrupt:
            raise LineageCorrupt(self.path, result.corrupt["offset"], result.records)
        if not result.torn_tail:
            return None
        offset = result.torn_tail["offset"]
        tail = data[offset:]
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
        with _VERIFIED_GUARD:
            verified = self._key in _VERIFIED
        try:
            # Before the first append in a process, after any failed append, and whenever the file does
            # not end in LF (another process's failed append): scan, refuse corruption, repair a torn tail.
            if not verified or not self._clean_tail():
                self._repair()
                with _VERIFIED_GUARD:
                    _VERIFIED.add(self._key)
            offset = self._raw_append(self.path, line)
            fault("log.after_append")
            return offset
        except BaseException:
            with _VERIFIED_GUARD:
                _VERIFIED.discard(self._key)
            raise
