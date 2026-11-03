"""Rust implementation of lineage, backups and runtime_events behind HYDRALYSIS_IMPL=rust.

`lineage.py`, `backups.py` and `runtime_events.py` call `install_lineage` / `install_backups` / `install_events` at the
bottom of the module when the environment variable is `rust`; the public functions are then replaced by wrappers over
the `hydralysis_rs` extension (rust/crates/hy-py/src/lineage.rs, from the hy-store crate). What stays Python: the three
path helpers of lineage (they depend on the configured root), the targets mirror of `lineage.ensure`, everything in
backups that drives a `hydra.Engine` (make, seal, adopt_legacy, handle) and the engine-facing private helpers.
JSON crosses the boundary as text. `_rust_store` (imported first) locates the extension.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from hydralysis import _rust_store  # noqa: F401  (puts HYDRALYSIS_RS_DIR on sys.path)

import hydralysis_rs as rs


def _dump(value) -> str:
    return json.dumps(value, default=str)


def _load(text):
    return None if text is None else json.loads(text)


def _path(value) -> str:
    return os.fspath(value)


def install_lineage(lineage) -> None:
    original_register = lineage.register
    original_canonical = lineage.canonical

    def canonical(value) -> bytes:
        try:
            return rs.lin_canonical(_dump(value))
        except ValueError:
            original_canonical(value)  # raises the exact exception Python gives (UnicodeEncodeError for a surrogate, ...)
            raise

    def fileset_sha256(files):
        return rs.lin_fileset_sha256(_dump(files))

    def self_hash(manifest):
        return rs.lin_self_hash(_dump(manifest))

    def find(settings, origin_key):
        return rs.lin_find(_dump(settings), origin_key)

    def load(settings, lineage_id):
        return json.loads(rs.lin_load(_dump(settings), lineage_id))

    def ensure(settings, target):
        record = json.loads(rs.lin_ensure(_dump(settings), _dump(target)))
        original_register(settings, target, record["id"], target.get("origin_key") or target["key"])
        return lineage.load(settings, record["id"])

    def append_current(settings, lineage_id, record, lock_held=False):
        return json.loads(rs.lin_append_current(_dump(settings), lineage_id, _dump(record), lock_held))

    def head(settings, lineage_id):
        return json.loads(rs.lin_head(_dump(settings), lineage_id))

    def history(settings, lineage_id):
        return json.loads(rs.lin_history(_dump(settings), lineage_id))

    def resolve(settings, item, key):
        return json.loads(rs.lin_resolve(_dump(settings), _dump(item)))

    def tree_files(folder):
        return json.loads(rs.lin_tree_files(_path(folder)))

    def tree_hash(folder):
        return rs.lin_tree_hash(_path(folder))

    def write_manifest(folder, body):
        return json.loads(rs.lin_write_manifest(_path(folder), _dump(body)))

    def read_manifest(folder):
        return _load(rs.lin_read_manifest(_path(folder)))

    def manifest_file_sha256(folder):
        return rs.lin_manifest_file_sha256(_path(folder))

    def verify_manifest(folder):
        return json.loads(rs.lin_verify_manifest(_path(folder)))

    def reserved_generations(settings, lineage_id):
        return set(rs.lin_reserved_generations(_dump(settings), lineage_id))

    def next_generation(settings, lineage_id):
        return rs.lin_next_generation(_dump(settings), lineage_id)

    def verify_head(settings, lineage_id):
        return json.loads(rs.lin_verify_head(_dump(settings), lineage_id))

    def tampered(settings, lineage_id):
        return json.loads(rs.lin_tampered(_dump(settings), lineage_id))

    def status(settings, target):
        return json.loads(rs.lin_status(_dump(settings), _dump(target)))

    for function in (canonical, fileset_sha256, self_hash, find, load, ensure, append_current, head, history, resolve, tree_files,
                     tree_hash, write_manifest, read_manifest, manifest_file_sha256, verify_manifest, reserved_generations,
                     next_generation, verify_head, tampered, status):
        setattr(lineage, function.__name__, function)
    lineage.IMPL = "rust"


def install_backups(backups) -> None:
    original_protected = backups.protected_generations

    def policy(settings):
        return json.loads(rs.bak_policy(_dump(settings)))

    def size_of(folder):
        return rs.bak_size_of(_path(folder))

    def backup_id(revision, purpose, when=None):
        return rs.bak_backup_id(revision, purpose, when)

    def logged(settings, lineage_id):
        return json.loads(rs.bak_logged(_dump(settings), lineage_id))

    def cumulative(settings, lineage_id, root):
        return rs.bak_cumulative(_dump(settings), lineage_id, root)

    def preview(settings, lineage_id, source_gpr):
        return json.loads(rs.bak_preview(_dump(settings), lineage_id, source_gpr))

    def manifest_files(rows):
        return json.loads(rs.bak_manifest_files(_dump(rows)))

    def read_backup(folder):
        return _load(rs.bak_read_backup(_path(folder)))

    def verify(folder):
        return json.loads(rs.bak_verify(_path(folder)))

    def usable(settings, lineage_id, identifier, manifest_sha256=None):
        return _load(rs.bak_usable(_dump(settings), lineage_id, identifier, manifest_sha256))

    def listing(settings, lineage_id, verify_all=False):
        return json.loads(rs.bak_listing(_dump(settings), lineage_id, verify_all))

    def protected_generations(settings, lineage_id, selected_stores=None):
        if selected_stores is not None:  # the caller-supplied stores are read in Python (they come from workcopy)
            return original_protected(settings, lineage_id, selected_stores)
        return {int(key): reason for key, reason in json.loads(rs.bak_protected_generations(_dump(settings), lineage_id)).items()}

    def remove(settings, lineage_id, options):
        return json.loads(rs.bak_remove(_dump(settings), lineage_id, _dump(options)))

    for function in (policy, size_of, backup_id, logged, cumulative, preview, manifest_files, read_backup, verify, usable, listing,
                     protected_generations, remove):
        setattr(backups, function.__name__, function)
    backups.IMPL = "rust"


def install_events(events) -> None:
    def genesis_hash(session):
        return rs.ev_genesis_hash(session)

    def record_hash(record):
        return rs.ev_record_hash(_dump(record))

    def _frame(record):
        return rs.ev_frame(_dump(record))

    def iter_records(path):
        for record, error in rs.ev_iter_records(_path(path)):
            yield (None if record is None else json.loads(record)), error

    def read_events(directory, after=0, limit=200, upto=None):
        return json.loads(rs.ev_read_events(_path(directory), after, limit, upto))

    def verify_log(directory, session, upto=None, expect=None):
        return json.loads(rs.ev_verify_log(_path(directory), session, upto, dict(expect) if expect else None))

    class EventLog:
        """The ring, the counters and the durable chain of one session (Rust). The attributes callers have always used
        are properties over the Rust object."""

        def __init__(self, directory, session, *, ring_events=events.RING_EVENTS, ring_bytes=events.RING_BYTES,
                     log_max_bytes=events.LOG_MAX_BYTES, durable_log=True):
            self.directory = Path(directory)
            self.session = session
            self.ring_events, self.ring_bytes, self.log_max_bytes = ring_events, ring_bytes, log_max_bytes
            self.durable_log = durable_log
            self.path = self.directory / events.LOG_NAME
            self._rust = rs.EventLog(_path(self.directory), session, ring_events, ring_bytes, log_max_bytes, durable_log)

        @property
        def ring(self):
            rows = []
            for text in self._rust.ring():
                event = json.loads(text)
                rows.append((event, len(json.dumps(event, ensure_ascii=False).encode("utf-8"))))
            return rows

        @property
        def ring_size(self):
            return sum(size for _, size in self.ring)

        @property
        def sequence(self):
            return self._rust.sequence()

        @property
        def dropped(self):
            return self._rust.dropped()

        @property
        def head(self):
            return self._rust.head_hash()

        @property
        def counters(self):
            return json.loads(self._rust.counters_copy())

        @property
        def records(self):
            return json.loads(self._rust.head_info())["records"]

        @property
        def log_bytes(self):
            return json.loads(self._rust.head_info())["bytes"]

        @property
        def full(self):
            return json.loads(self._rust.head_info())["full"]

        @property
        def error(self):
            return json.loads(self._rust.head_info()).get("error", "")

        def count_message(self, script, message, clipped):
            self._rust.count_message(script, _dump(message), clipped)

        def record(self, script, message):
            return json.loads(self._rust.record(script, _dump(message)))

        def marker(self, kind, body):
            return json.loads(self._rust.marker(kind, _dump(body)))

        def sync(self):
            self._rust.sync()

        def close(self):
            self._rust.close()

        def head_info(self):
            return json.loads(self._rust.head_info())

        def counters_copy(self):
            return json.loads(self._rust.counters_copy())

    for function in (genesis_hash, record_hash, _frame, iter_records, read_events, verify_log):
        setattr(events, function.__name__, function)
    events.EventLog = EventLog
    events.IMPL = "rust"
