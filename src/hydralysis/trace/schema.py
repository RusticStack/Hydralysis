"""The trace store's on-disk schema and record validation (package T0, M0 of hydra-semantic-trace.md).

A session is a directory holding ONE SQLite database (`trace.db`, WAL) plus `artifacts/` for private payload bytes.
Producers are rows with session-local generations, not files. Health claims, gaps, counters and relations are
separate tables, never fields of an event, so a stored event says what was observed and nothing about how complete
the capture was.
"""

from __future__ import annotations

import json
import re

STORE_SCHEMA = "hydralysis.trace.store/1"
SESSION_SCHEMA = "hydra.trace.session/1"
EVENT_SCHEMA = "hydra.trace.event/1"
DB_VERSION = 1
DB_NAME = "trace.db"

# ---- names ------------------------------------------------------------------------------------------------------

PRODUCER = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
# `<namespace>.<name>[.<name>...]`, lower case: core.* for the generic schema, <profile>.* for a profile's own kinds.
KIND = re.compile(r"^[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_-]{0,47}){1,6}$")
CLOCK = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
SCOPE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SESSION_ID = re.compile(r"^tr_[A-Za-z0-9_-]{1,64}$")
UNCLOCKED = "unclocked"     # an event without a monotonic observation: ordered only by its sequences

CONFIDENCES = ("exact", "inferred", "sampled")
RELATION_STATUSES = ("supported", "inferred", "unresolved")
# §14.1: separate claims, none of which implies the next. fault_free is §15.1.
CLAIM_KINDS = ("finalized", "attached", "observing", "data_integrity", "capture_coverage", "scenario_coverage",
               "behavioral_equivalence", "fault_free")
PRODUCER_CLAIM_KINDS = ("finalized", "attached", "observing", "data_integrity", "capture_coverage", "fault_free")
CLAIM_STATUSES = ("true", "false", "unknown")
COUNTER_LAYERS = ("producer", "transport", "writer", "import")
GAP_KINDS = ("loss", "queue_overflow", "producer_restart", "producer_lost", "read_failure", "filtered",
             "unattached", "corrupt_input", "truncated_input", "payload_omitted", "observer_inactive")

MAX_PAYLOAD_JSON = 4096          # metadata only: a bigger payload is refused, never clipped silently
MAX_PREVIEW_BYTES = 256
MAX_BATCH = 50_000
MAX_KEY = 512

DDL = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS clock_domains (
    name TEXT PRIMARY KEY, units TEXT NOT NULL, resolution REAL, uncertainty REAL, calibration TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS producers (
    producer TEXT NOT NULL, generation INTEGER NOT NULL,
    pid INTEGER, process_start TEXT, process_key TEXT, image_sha256 TEXT,
    clock_domain TEXT NOT NULL, start_mono INTEGER, start_wall REAL, observes TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (producer, generation));
CREATE TABLE IF NOT EXISTS batches (
    batch_id INTEGER PRIMARY KEY, producer TEXT NOT NULL, generation INTEGER NOT NULL, count INTEGER NOT NULL,
    first_seq INTEGER, last_seq INTEGER, committed_wall REAL);
CREATE TABLE IF NOT EXISTS events (
    ingest_seq INTEGER PRIMARY KEY,               -- collector ingestion ordinal for the session, not execution order
    event_id TEXT NOT NULL UNIQUE,
    producer TEXT NOT NULL, generation INTEGER NOT NULL, producer_seq INTEGER NOT NULL,
    kind TEXT NOT NULL, kind_version INTEGER NOT NULL,
    clock_domain TEXT NOT NULL, t_mono INTEGER NOT NULL, t_wall REAL,
    pid INTEGER, tid INTEGER, process_key TEXT, thread_key TEXT,
    resource_key TEXT, state_key TEXT, object_key TEXT,
    phase TEXT, operation_id TEXT, frame INTEGER, thread_role TEXT,
    confidence TEXT NOT NULL,
    unresolved TEXT, payload TEXT, artifacts TEXT,
    batch_id INTEGER NOT NULL,
    UNIQUE (producer, generation, producer_seq));
CREATE INDEX IF NOT EXISTS ev_order ON events (clock_domain, t_mono);
CREATE INDEX IF NOT EXISTS ev_kind ON events (kind, clock_domain, t_mono);
CREATE INDEX IF NOT EXISTS ev_resource ON events (resource_key, clock_domain, t_mono);
CREATE INDEX IF NOT EXISTS ev_state ON events (state_key, clock_domain, t_mono);
CREATE INDEX IF NOT EXISTS ev_align ON events (phase, operation_id);
CREATE TABLE IF NOT EXISTS resources (
    resource_key TEXT PRIMARY KEY, type TEXT, provider TEXT, precedence TEXT, shadowed TEXT, sha256 TEXT,
    size INTEGER, first_event TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS states (
    state_key TEXT PRIMARY KEY, scope TEXT, object TEXT, key TEXT, offset INTEGER, name TEXT, type TEXT,
    first_event TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identities (
    identity_key TEXT PRIMARY KEY, kind TEXT NOT NULL, raw TEXT, start_observation TEXT,
    lifetime TEXT NOT NULL, first_event TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS relations (
    relation_id TEXT PRIMARY KEY, from_event TEXT NOT NULL, to_event TEXT NOT NULL, relation TEXT NOT NULL,
    basis TEXT NOT NULL, status TEXT NOT NULL, unresolved TEXT NOT NULL, rule_revision TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL, range_start INTEGER,
    range_end INTEGER, path TEXT NOT NULL, first_event TEXT);
CREATE TABLE IF NOT EXISTS claims (
    id INTEGER PRIMARY KEY, producer TEXT NOT NULL DEFAULT '', generation INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL, status TEXT NOT NULL, subject TEXT NOT NULL,
    kinds TEXT NOT NULL DEFAULT '[]', phases TEXT NOT NULL DEFAULT '[]', whole_session INTEGER NOT NULL DEFAULT 0,
    clock_domain TEXT, start INTEGER, end INTEGER, reason TEXT NOT NULL DEFAULT '', basis TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS counters (
    producer TEXT NOT NULL DEFAULT '', generation INTEGER NOT NULL DEFAULT 0, layer TEXT NOT NULL,
    name TEXT NOT NULL, value INTEGER NOT NULL, PRIMARY KEY (producer, generation, layer, name));
CREATE TABLE IF NOT EXISTS gaps (
    id INTEGER PRIMARY KEY, producer TEXT NOT NULL DEFAULT '', generation INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL, layer TEXT NOT NULL, count INTEGER, kinds TEXT NOT NULL DEFAULT '[]',
    phase TEXT, clock_domain TEXT, start INTEGER, end INTEGER, reason TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS correlation_scopes (scope_id TEXT PRIMARY KEY);
"""

EVENT_COLUMNS = ("event_id", "producer", "generation", "producer_seq", "kind", "kind_version", "clock_domain",
                 "t_mono", "t_wall", "pid", "tid", "process_key", "thread_key", "resource_key", "state_key",
                 "object_key", "phase", "operation_id", "frame", "thread_role", "confidence", "unresolved",
                 "payload", "artifacts", "batch_id")


class TraceError(ValueError):
    """A refused record or operation. `code` is stable for callers and tests."""

    def __init__(self, message: str, code: str = "invalid"):
        super().__init__(message)
        self.code = code


def event_id(producer: str, generation: int, producer_seq: int) -> str:
    return "ev:%s:%d:%d" % (producer, generation, producer_seq)


def dumps(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def loads(text, default):
    return json.loads(text) if text else default


def _int(value, field, minimum=None):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TraceError("%s must be an integer" % field, "bad_field")
    if minimum is not None and value < minimum:
        raise TraceError("%s must be >= %d" % (field, minimum), "bad_field")
    return value


def _text(value, field, limit=MAX_KEY):
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > limit:
        raise TraceError("%s must be a non-empty string of at most %d characters" % (field, limit), "bad_field")
    return value


def check_kind(kind) -> tuple[str, int]:
    """`core.resource.open` or `core.resource.open/2`: the namespaced kind and its version (default 1)."""
    if not isinstance(kind, str):
        raise TraceError("kind must be a string", "bad_kind")
    name, _, version = kind.partition("/")
    if not KIND.match(name):
        raise TraceError("kind %r is not namespaced (<namespace>.<name>)" % kind, "bad_kind")
    if version and not version.isdigit():
        raise TraceError("kind version must be a positive integer", "bad_kind")
    return name, int(version) if version else 1


def identity_key(kind: str, raw, start_observation, fallback_scope: str) -> tuple[str, str]:
    """A session-local identity: the raw id (PID, TID, address) plus its start observation. Without one the lifetime
    is unresolved and the key is scoped to `fallback_scope`, so two unresolved uses of one raw value never merge."""
    if start_observation:
        return "%s:%s@%s" % (kind, raw, start_observation), "observed"
    return "%s:%s@unresolved:%s" % (kind, raw, fallback_scope), "unresolved"
