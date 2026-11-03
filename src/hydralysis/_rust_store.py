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


def install_durable(durable) -> None:
    original_log = durable.AppendLog
    original_scan = durable.Scan

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
        return read_sealed_info(path, **options)[0]

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
            return scan_file(self.path)

        def last(self, *, strict=False):
            return _load(rs.log_last(os.fspath(self.path), strict))

        def repairs(self):
            return json.loads(rs.log_repairs(os.fspath(self.path)))

        def append(self, record, *, lock_held=False):
            return rs.log_append(os.fspath(self.path), _dump(record), self._lock(), self.by, self.lock_timeout_s, lock_held)

        def repair(self, *, lock_held=False):
            return _load(rs.log_repair(os.fspath(self.path), self._lock(), self.by, self.lock_timeout_s, lock_held))

    for function in (canonical, dumps_sealed, frame, inspect_file, read_sealed_info, read_sealed, write_sealed,
                     atomic_write, replace_file, scan_file, scan_bytes, file_lock):
        setattr(durable, function.__name__, function)
    class Verified:
        """Stands in for the Python module's `_VERIFIED` memo: the tests only clear it."""

        def clear(self):
            rs.log_clear_verified()

    durable.AppendLog = AppendLog
    durable._VERIFIED = Verified()
    durable.IMPL = "rust"


def install_storelog(storelog) -> None:
    from hydralysis import durable

    class Cache:
        """Stands in for the Python module's `_CACHE` (cleared by tests, measured by `len`)."""

        def clear(self):
            rs.storelog_clear_cache()

        def __len__(self):
            return rs.storelog_cache_len()

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
        return _load(rs.storelog_known_edits(os.fspath(path)))

    def diff(old, new):
        return json.loads(rs.storelog_diff(_dump(old), _dump(new)))

    def chain(record, rows):
        text, anchor, n, start = rs.storelog_chain(_dump(record), _dump(rows))
        updated = json.loads(text)
        record.clear()
        record.update(updated)
        return record, {"anchor": anchor, "n": n, "start": start}

    for function in (save, read, known_edits, diff, chain):
        setattr(storelog, function.__name__, function)
    storelog._CACHE = Cache()
    storelog.IMPL = "rust"
    assert durable  # the durable module is installed first when HYDRALYSIS_IMPL=rust
