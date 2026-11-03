"""Rust implementation of the storage layer behind HYDRALYSIS_IMPL=rust.

`durable.py` and `storelog.py` call `install_durable` / `install_storelog` at import time when the environment variable
HYDRALYSIS_IMPL is `rust`; the public functions are then replaced by thin wrappers over the `hydralysis_rs` extension
(rust/crates/hy-py, built from the hy-core and hy-store crates). The Python code stays the reference: without the
variable nothing here is imported. JSON crosses the boundary as text.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys

from hydralysis._seams import Seam, any_active, guarded

# Child processes that import hydralysis with their own sys.path find the extension through HYDRALYSIS_RS_DIR
# (os.pathsep separated directories that hold hydralysis_rs.pyd).
for _directory in filter(None, os.environ.get("HYDRALYSIS_RS_DIR", "").split(os.pathsep)):
    if _directory not in sys.path:
        sys.path.append(_directory)

try:
    import hydralysis_rs as rs
except ImportError as exc:  # pragma: no cover - only with HYDRALYSIS_IMPL=rust
    raise ImportError("HYDRALYSIS_IMPL=rust needs the hydralysis_rs extension (rust/crates/hy-py): %s" % exc) from exc

_MISSING = object()

# The Python objects a white-box test patches (see _seams.py; hy-store/TESTMAP.md lists them). install_durable fills them in
# once the wrappers are installed, so a patch of a wrapper itself (durable.replace_file, durable.scan_file) counts too; the
# lineage, storelog and events routing reuse them for the same primitives.
FILE_SEAM = Seam()    # replace / fsync / sleep / native move / process exit: atomic_write, replace_file, anything above them
WRITE_SEAM = Seam()   # the steps write_sealed takes in Python: atomic_write, _keep_previous
READ_SEAM = Seam()    # the byte reads under read_sealed_info / inspect_file
LOG_SEAM = Seam()     # the steps an AppendLog append takes in Python
LOG_SEAMS = (FILE_SEAM, LOG_SEAM)


def _dump(value) -> str:
    return json.dumps(value)


def _load(text):
    return None if text is None else json.loads(text)


def _has_surrogate(value) -> bool:
    if isinstance(value, str):
        return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)
    if isinstance(value, dict):
        return any(_has_surrogate(k) or _has_surrogate(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_has_surrogate(v) for v in value)
    return False


def _refuse_surrogate(value, exc):
    """Python's canonical form refuses an unpaired surrogate (PROTOCOL-3.md 3.4); serde_json refuses it earlier."""
    if _has_surrogate(value):
        raise ValueError("canonical form refuses an unpaired surrogate (PROTOCOL-3.md 3.4): %s" % exc) from exc
    raise exc


class Verified:
    """Stands in for the Python module's `_VERIFIED` memo (log key -> end of the last line known valid). The memo lives in
    Rust; this is its mapping surface, so the tests and the Python fallback of `AppendLog` read and write the one memo."""

    def get(self, key, default=None):
        found = rs.log_verified_get(key)
        return default if found is None else found

    def __getitem__(self, key):
        found = rs.log_verified_get(key)
        if found is None:
            raise KeyError(key)
        return found

    def __setitem__(self, key, value):
        rs.log_verified_set(key, value)

    def __contains__(self, key):
        return rs.log_verified_get(key) is not None

    def pop(self, key, *default):
        found = rs.log_verified_pop(key)
        if found is not None:
            return found
        if default:
            return default[0]
        raise KeyError(key)

    def clear(self):
        rs.log_clear_verified()


def install_durable(durable) -> None:
    from hydralysis import localio

    original_log = durable.AppendLog
    original_scan = durable.Scan
    python = {name: getattr(durable, name) for name in (
        "atomic_write", "replace_file", "write_sealed", "inspect_file", "read_sealed_info")}

    def canonical(value) -> bytes:
        try:
            return rs.canonical(_dump(value))
        except ValueError as exc:
            _refuse_surrogate(value, exc)

    def dumps_sealed(value, indent=2) -> bytes:
        if not isinstance(value, dict):
            raise ValueError("a sealed record must be a JSON object")
        try:
            return rs.dumps_sealed(_dump(value), indent)
        except ValueError as exc:
            _refuse_surrogate(value, exc)

    def frame(record) -> bytes:
        return rs.frame(_dump(record))

    def inspect_file(path, max_bytes=None, require_seal=False):
        kind, value, reason = rs.inspect_file(os.fspath(path), max_bytes, require_seal)
        return kind, _load(value), reason

    def read_sealed_info(path, *, default=_MISSING, max_bytes=None, require_seal=False):
        record, source = rs.read_sealed_info(os.fspath(path), None if default is _MISSING else _dump(default),
                                             max_bytes, require_seal)
        return json.loads(record), source

    def read_sealed(path, **options):
        return durable.read_sealed_info(path, **options)[0]

    def write_sealed(path, value, *, indent=2, max_bytes=None, too_large=None):
        if not isinstance(value, dict):
            raise ValueError("a sealed record must be a JSON object")
        try:
            return rs.write_sealed(os.fspath(path), _dump(value), indent, max_bytes, too_large)
        except ValueError as exc:
            if _has_surrogate(value):
                _refuse_surrogate(value, exc)
            raise

    def atomic_write(path, data, *, point="atomic", sync=True):
        rs.atomic_write(os.fspath(path), bytes(data), point, sync)

    def replace_file(source, destination):
        rs.replace_file(os.fspath(source), os.fspath(destination))

    def _scan(text) -> object:
        raw = json.loads(text)
        return original_scan(raw["records"], raw["valid_end"], raw["size"], raw["torn_tail"], raw["corrupt"])

    def scan_file(path, start=0, collect=True):
        return _scan(rs.scan_file(os.fspath(path), start, collect))

    def scan_bytes(data):
        return _scan(rs.scan_bytes(bytes(data)))

    @contextlib.contextmanager
    def file_lock(path, timeout_s=None, what="durable record"):
        held = rs.FileLock(os.fspath(path), durable.LOCK_TIMEOUT_S if timeout_s is None else timeout_s, what)
        try:
            yield
        finally:
            held.release()

    class AppendLog(original_log):
        def _lock(self):
            return os.fspath(self.lock_path)

        def scan(self):
            return durable.scan_file(self.path)

        def last(self, *, strict=False):
            return _load(rs.log_last(os.fspath(self.path), strict))

        def repairs(self):
            return json.loads(rs.log_repairs(os.fspath(self.path)))

        def append(self, record, *, lock_held=False):
            if any_active(LOG_SEAMS):
                return original_log.append(self, record, lock_held=lock_held)
            return rs.log_append(os.fspath(self.path), _dump(record), self._lock(), self.by, self.lock_timeout_s, lock_held)

        def repair(self, *, lock_held=False):
            if any_active(LOG_SEAMS):
                return original_log.repair(self, lock_held=lock_held)
            return _load(rs.log_repair(os.fspath(self.path), self._lock(), self.by, self.lock_timeout_s, lock_held))

    for function in (canonical, dumps_sealed, frame, scan_file, scan_bytes, file_lock):
        setattr(durable, function.__name__, function)
    durable.inspect_file = guarded(inspect_file, python["inspect_file"], READ_SEAM)
    durable.read_sealed_info = guarded(read_sealed_info, python["read_sealed_info"], READ_SEAM)
    durable.read_sealed = read_sealed
    durable.write_sealed = guarded(write_sealed, python["write_sealed"], FILE_SEAM, WRITE_SEAM)
    durable.atomic_write = guarded(atomic_write, python["atomic_write"], FILE_SEAM)
    durable.replace_file = guarded(replace_file, python["replace_file"], FILE_SEAM)
    durable.AppendLog = AppendLog
    durable._VERIFIED = Verified()
    durable.IMPL = "rust"

    FILE_SEAM.add((os, "fsync"), (os, "replace"), (durable, "_replace_once"), (durable, "_move_file_ex"), (durable, "_sleep"),
                  (durable, "NATIVE_MOVE"), (durable, "_write_file"), (durable, "_fsync_directory"), (durable, "_die"),
                  (durable, "replace_file"))
    WRITE_SEAM.add((durable, "atomic_write"), (durable, "_keep_previous"))
    READ_SEAM.add((durable, "read_bytes"), (localio, "read_bytes"), (localio, "_kernel"))
    LOG_SEAM.add((os, "write"), (AppendLog, "_raw_append"), (AppendLog, "_check_tail"), (AppendLog, "_repair_tail"),
                 (AppendLog, "_append_locked"), (durable, "scan_file"), (durable, "file_lock"), (durable, "atomic_write"))


def install_storelog(storelog) -> None:
    from hydralysis import durable

    python = {name: getattr(storelog, name) for name in ("save", "read", "known_edits")}

    class Cache(dict):
        """The Python module's `_CACHE` (the Python fallback below fills it), plus the Rust cache: cleared together by the
        tests and measured together by `len`."""

        def clear(self):
            super().clear()
            rs.storelog_clear_cache()

        def __len__(self):
            return super().__len__() + rs.storelog_cache_len()

    def configure():  # the patchable constants of the Python module are honoured at call time
        rs.storelog_configure(storelog.SNAPSHOT_EVERY, storelog.SNAPSHOT_LOG_BYTES, storelog.CACHE_ENTRIES)

    def save(path, record, *, max_bytes, too_large):
        configure()
        rs.storelog_save(os.fspath(path), _dump(record), max_bytes, too_large)

    def read(path, record, reread=None):
        again = None
        if reread is not None:
            def again():
                value = reread()
                return None if value is None else _dump(value)
        return _load(rs.storelog_read(os.fspath(path), None if record is None else _dump(record), again))

    def known_edits(path):
        known = _load(rs.storelog_known_edits(os.fspath(path)))
        if known is None:
            # The whole-store routes of `viewnative` keep their own copy of the Rust store (another extension).
            from hydralysis import viewnative
            native = viewnative.native_views()
            if native is not None:
                known = viewnative.call(native, "storelog_known_edits", [{}, os.fspath(path)])
        return known

    def diff(old, new):
        return json.loads(rs.storelog_diff(_dump(old), _dump(new)))

    def chain(record, rows):
        text, anchor, n, start = rs.storelog_chain(_dump(record), _dump(rows))
        updated = json.loads(text)
        record.clear()
        record.update(updated)
        return record, {"anchor": anchor, "n": n, "start": start}

    for function in (diff, chain):
        setattr(storelog, function.__name__, function)
    # The Python objects a white-box test patches (see _seams.py; hy-store/TESTMAP.md lists them): the writer's and the
    # reader's helpers, and the durable primitives under them.
    writing = Seam((durable, "write_sealed"), (storelog, "_snapshot"), (storelog, "_trim"), (storelog, "_current"),
                   (storelog, "_fits"))
    reading = Seam((durable, "scan_file"), (storelog, "_identity"), (storelog, "_rows"))
    storelog.save = guarded(save, python["save"], writing, WRITE_SEAM, *LOG_SEAMS)
    storelog.read = guarded(read, python["read"], reading)
    storelog.known_edits = guarded(known_edits, python["known_edits"], writing)
    constants = (storelog.SNAPSHOT_EVERY, storelog.SNAPSHOT_LOG_BYTES, storelog.CACHE_ENTRIES)

    def unpatched() -> bool:
        """True while no seam of the store writer or reader is replaced and its limits are the defaults: the whole-store
        routes of `viewnative` (load_store, save_store) have their own copy of the Rust store and cannot see a patch."""
        return (not writing.active() and not reading.active() and not WRITE_SEAM.active() and not any_active(LOG_SEAMS)
                and (storelog.SNAPSHOT_EVERY, storelog.SNAPSHOT_LOG_BYTES, storelog.CACHE_ENTRIES) == constants)

    storelog.rust_unpatched = unpatched
    storelog._CACHE = Cache()
    storelog.IMPL = "rust"
    assert durable  # the durable module is installed first when HYDRALYSIS_IMPL=rust
