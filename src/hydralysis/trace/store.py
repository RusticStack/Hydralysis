"""Trace sessions on disk: one directory, one SQLite database, one in-process writer thread with group commit.

    session/
      trace.db                  WAL; session metadata, producers, events, relations, claims, gaps, counters
      artifacts/<sha256>.bin    private payload artifacts (payload mode only), durable before an event cites them

Why this shape (measured, C:/dev-overflow/dbbench/gc_bench.py): one Hydralysis server process serves every agent.
48 threads each writing through their own connection reached 1.6k durable writes/s with a 7 s worst write
(starvation on the file lock). One writer thread per store that drains up to 512 queued writes of all callers into
one BEGIN IMMEDIATE ... COMMIT reached 7.5k durable (synchronous=FULL) writes/s, p99 10 ms, max 16 ms, while
readers on their own connections were never blocked. Different sessions are different files and never contend.

`TraceStore` owns that writer thread. Every write is a closure queued FIFO; the thread runs each one inside its own
SAVEPOINT of the group transaction, so one refused batch rolls back alone and the others still commit, and a caller
is woken only after the COMMIT that made its write durable. A batch is therefore all-or-nothing on disk and a reader
(any number of read-only, thread-local connections) never sees part of one.

A second process (a CLI next to the server) may open the same session with its own `TraceStore`. Its writer thread
takes the database write lock with BEGIN IMMEDIATE, retried until a deadline (the evidence ledger's `_enter_wal`
pattern), so it works, but it is not the fast path: the server process is meant to be the one writer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

from . import schema as S
from .schema import TraceError

ARTIFACTS = "artifacts"
BUSY_TIMEOUT_MS = 15000          # same budget as the evidence ledger
MAX_GROUP = 512                  # queued writes drained into one transaction
DEFAULT_CLOCK = {"name": "host-mono", "units": "ns", "resolution": 100.0, "uncertainty": 0.0, "calibration": {}}

# ---- privacy ----------------------------------------------------------------------------------------------------

SECRET_KEY = re.compile(r"(pass(word|wd|phrase)?|secret|token|api[_-]?key|auth(orization)?|cookie|credential|"
                        r"private[_-]?key|session[_-]?key|bearer)", re.I)
SECRET_VALUE = re.compile(r"(bearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
                          r"\b(?:pass(?:word)?|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+)", re.I)
LONG_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")
HEX = re.compile(r"^[0-9a-fA-F]+$")


def default_privacy(**overrides) -> dict:
    privacy = {"mode": "metadata", "previews": False, "payload_export": False, "max_artifact_bytes": 65536}
    privacy.update(overrides)
    if privacy["mode"] not in ("metadata", "payload"):
        raise TraceError("privacy.mode is metadata or payload", "bad_privacy")
    return privacy


def looks_secret(text: str) -> bool:
    """Credential-shaped text, or a long mixed-alphabet token (an API key, a JWT segment). A hex digest is not."""
    if SECRET_VALUE.search(text):
        return True
    for token in LONG_TOKEN.findall(text):
        body = token.rstrip("=")
        if not HEX.match(body) and any(c.isdigit() for c in body) and any(c.isalpha() for c in body):
            return True
    return False


_OMIT = object()


def sanitize_payload(payload, privacy: dict, tally: dict) -> dict | None:
    """Metadata only. Secret-named keys and secret-looking strings are omitted (counted, never stored); previews are
    absent unless the session allows them, and then at most 256 bytes; raw bytes are refused (they are artifacts)."""
    if payload is None:
        return None
    if not isinstance(payload, dict):
        raise TraceError("payload must be an object", "bad_payload")

    def bump(name):
        tally[name] = tally.get(name, 0) + 1

    def clean(value):
        if isinstance(value, (bytes, bytearray, memoryview)):
            raise TraceError("payload bytes are not metadata; use an authorized artifact", "payload_bytes")
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                if not isinstance(k, str):
                    raise TraceError("payload keys are strings", "bad_payload")
                if SECRET_KEY.search(k):
                    bump("secret_omitted")
                    continue
                if k == "preview" or k.endswith("_preview"):
                    if not privacy.get("previews"):
                        bump("preview_omitted")
                        continue
                    if not isinstance(v, str):
                        raise TraceError("a preview is a string", "bad_payload")
                    if looks_secret(v):
                        bump("secret_omitted")
                        continue
                    raw = v.encode("utf-8")
                    if len(raw) > S.MAX_PREVIEW_BYTES:
                        v = raw[:S.MAX_PREVIEW_BYTES].decode("utf-8", "ignore")
                        out[k + "_clipped"] = True
                    out[k] = v
                    continue
                cleaned = clean(v)
                if cleaned is not _OMIT:
                    out[k] = cleaned
            return out
        if isinstance(value, list):
            return [c for c in (clean(v) for v in value) if c is not _OMIT]
        if isinstance(value, str) and looks_secret(value):
            bump("secret_omitted")
            return _OMIT
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        raise TraceError("payload values are JSON scalars, lists or objects", "bad_payload")

    return clean(payload)


class CorrelationKeyring:
    """Per-scope HMAC keys kept OUTSIDE every session directory. A session stores only the scope id; the key never
    enters the database or an export. One scope shared by two sessions is what makes their ids comparable."""

    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)

    def _key(self, scope: str) -> bytes:
        if not S.SCOPE_ID.match(scope or ""):
            raise TraceError("bad correlation scope id", "bad_scope")
        path = self.directory / ("%s.key" % scope)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
        except FileExistsError:
            for _ in range(100):
                data = path.read_bytes()
                if len(data) == 32:
                    return data
                time.sleep(0.01)
            raise TraceError("correlation key %s is unreadable" % scope, "bad_scope")
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(32))
            handle.flush()
            os.fsync(handle.fileno())
        return path.read_bytes()

    def correlation_id(self, scope: str, value: str) -> str:
        digest = hmac.new(self._key(scope), value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
        return "cid:%s:%s" % (scope, digest)


# ---- connections ------------------------------------------------------------------------------------------------

def _locked(exc: Exception) -> bool:
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def _retry(fn, deadline_s: float = BUSY_TIMEOUT_MS / 1000):
    """Run `fn` until it stops failing with 'database is locked/busy' or the deadline passes. SQLite does not apply
    the busy timeout to every lock acquisition (the WAL switch, some BEGIN IMMEDIATE races between processes)."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            if not _locked(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(0.005)


def _connect_rw(path: Path, synchronous: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None, check_same_thread=False)
    db.execute("PRAGMA busy_timeout = %d" % BUSY_TIMEOUT_MS)

    def wal():
        if str(db.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "wal":
            db.execute("PRAGMA journal_mode = WAL")
    _retry(wal)
    db.execute("PRAGMA synchronous = %s" % synchronous)
    return db


def connect_ro(session_dir) -> sqlite3.Connection:
    """A read-only connection to a session's database. Never blocks the writer and never sees an uncommitted row."""
    path = Path(session_dir) / S.DB_NAME
    if not path.exists():
        raise TraceError("%s is not a trace session" % session_dir, "not_a_session")
    uri = "file:%s?mode=ro" % urllib.parse.quote(path.resolve().as_posix(), safe="/:")
    db = sqlite3.connect(uri, uri=True, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None,
                         check_same_thread=False)
    db.execute("PRAGMA busy_timeout = %d" % BUSY_TIMEOUT_MS)
    db.execute("PRAGMA query_only = 1")
    return db


def read_manifest(db: sqlite3.Connection) -> dict:
    rows = dict(db.execute("SELECT key, value FROM meta"))
    if "session" not in rows:
        raise TraceError("not a trace session database", "not_a_session")
    manifest = json.loads(rows["session"])
    manifest["revision"] = int(rows.get("revision", "0"))
    manifest["clock_domains"] = {r[0]: {"name": r[0], "units": r[1], "resolution": r[2], "uncertainty": r[3],
                                        "calibration": S.loads(r[4], {})}
                                 for r in db.execute("SELECT * FROM clock_domains WHERE name != ?", (S.UNCLOCKED,))}
    return manifest


def _check_clock(domain: dict) -> dict:
    if not isinstance(domain, dict) or not S.CLOCK.match(str(domain.get("name", ""))):
        raise TraceError("a clock domain has a name", "bad_clock")
    if domain["name"] == S.UNCLOCKED:
        raise TraceError("%s is reserved" % S.UNCLOCKED, "bad_clock")
    if domain.get("units") not in ("ns", "us", "ms", "s", "ticks"):
        raise TraceError("clock units are ns, us, ms, s or ticks", "bad_clock")
    out = {"name": domain["name"], "units": domain["units"], "resolution": domain.get("resolution"),
           "uncertainty": domain.get("uncertainty"), "calibration": domain.get("calibration") or {}}
    for field in ("resolution", "uncertainty"):
        if out[field] is not None and (isinstance(out[field], bool) or not isinstance(out[field], (int, float))):
            raise TraceError("clock %s is a number in its units" % field, "bad_clock")
    return out


def create_session(directory, *, profile: str, scenario: str, session_id: str | None = None, target=None,
                   scope=None, clock_domains=None, allow_payload: bool = False, previews: bool = False,
                   allow_payload_export: bool = False, retention=None, notes=(), synchronous: str = "FULL"
                   ) -> "TraceStore":
    """A new, empty session, opened. Payload mode is a separate permission given here and only here (§14.6)."""
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=False)       # exclusive: two creators of one directory cannot both succeed
    session_id = session_id or "tr_" + uuid.uuid4().hex
    if not S.SESSION_ID.match(session_id):
        raise TraceError("session id is tr_<id>", "bad_session")
    domains = [_check_clock(d) for d in (clock_domains or [DEFAULT_CLOCK])]
    privacy = default_privacy(mode="payload" if allow_payload else "metadata", previews=bool(previews),
                              payload_export=bool(allow_payload and allow_payload_export))
    manifest = {"schema": S.SESSION_SCHEMA, "store": S.STORE_SCHEMA, "session_id": session_id, "profile": profile,
                "scenario": scenario, "target": target or {}, "scope": scope or {}, "privacy": privacy,
                "created_wall": time.time(), "status": "open", "retention": retention or {"policy": "keep"},
                "notes": list(notes)}
    db = _connect_rw(path / S.DB_NAME, synchronous)
    try:
        db.executescript(S.DDL)
        db.execute("BEGIN IMMEDIATE")
        for key, value in (("store", S.STORE_SCHEMA), ("db_version", str(S.DB_VERSION)),
                           ("session", S.dumps(manifest)), ("revision", "1")):
            db.execute("INSERT INTO meta VALUES (?,?)", (key, value))
        for d in domains:
            db.execute("INSERT INTO clock_domains VALUES (?,?,?,?,?)",
                       (d["name"], d["units"], d["resolution"], d["uncertainty"], S.dumps(d["calibration"])))
        db.execute("INSERT INTO clock_domains VALUES (?,?,?,?,?)", (S.UNCLOCKED, "none", None, None, "{}"))
        db.execute("COMMIT")
    finally:
        db.close()
    return TraceStore(path, synchronous=synchronous)


# ---- the store --------------------------------------------------------------------------------------------------

class Ticket:
    """One queued write. `wait()` returns once the transaction holding it committed (durable), or raises its error."""

    __slots__ = ("work", "event", "result", "error", "enqueued", "done")

    def __init__(self, work):
        self.work = work
        self.event = threading.Event()
        self.result = None
        self.error: BaseException | None = None
        self.enqueued = time.perf_counter()
        self.done = 0.0

    def wait(self, timeout: float | None = None):
        if not self.event.wait(timeout):
            raise TraceError("write not acknowledged within %ss" % timeout, "write_timeout")
        if self.error is not None:
            raise self.error
        return self.result

    @property
    def latency_s(self) -> float:
        return self.done - self.enqueued if self.done else float("nan")


_STOP = object()


class TraceStore:
    """The one writer of a session in this process, plus its readers. Use as a context manager or call close()."""

    def __init__(self, directory, *, synchronous: str = "FULL", max_group: int = MAX_GROUP):
        self.path = Path(directory)
        if synchronous not in ("FULL", "NORMAL", "EXTRA"):
            raise TraceError("synchronous is FULL, NORMAL or EXTRA", "bad_option")
        self.synchronous = synchronous
        self.max_group = max_group
        self._local = threading.local()
        self._readers: list[sqlite3.Connection] = []
        self._readers_lock = threading.Lock()
        manifest = read_manifest(self.reader())
        self.session_id = manifest["session_id"]
        self.privacy = manifest["privacy"]
        self.domains = manifest["clock_domains"]
        self.groups = 0
        self.group_sizes: list[int] = []
        self._queue: queue.SimpleQueue = queue.SimpleQueue()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._closed = False
        self._thread = threading.Thread(target=self._run, name="trace-writer-%s" % self.session_id, daemon=True)
        self._thread.start()
        self._ready.wait()
        if self._startup_error is not None:
            raise self._startup_error

    # -- the writer thread --

    def _run(self):
        try:
            db = _connect_rw(self.path / S.DB_NAME, self.synchronous)
        except BaseException as exc:            # report to the constructor, never die silently
            self._startup_error = exc
            self._ready.set()
            return
        self._ready.set()
        try:
            while True:
                first = self._queue.get()
                if first is _STOP:
                    return
                items = [first]
                stop = False
                while len(items) < self.max_group:
                    try:
                        item = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if item is _STOP:
                        stop = True
                        break
                    items.append(item)
                self._commit_group(db, items)
                if stop:
                    return
        finally:
            db.close()

    def _commit_group(self, db: sqlite3.Connection, items: list[Ticket]) -> None:
        try:
            _retry(lambda: db.execute("BEGIN IMMEDIATE"))     # the cross-process writer ticket
        except BaseException as exc:
            self._wake(items, error=TraceError("could not take the session write lock: %s" % exc, "write_locked"))
            return
        try:
            for ticket in items:
                db.execute("SAVEPOINT w")
                try:
                    ticket.result = ticket.work(db)
                    db.execute("RELEASE w")
                except BaseException as exc:
                    db.execute("ROLLBACK TO w")
                    db.execute("RELEASE w")
                    ticket.error = (TraceError("refused: %s" % exc, "duplicate_seq")
                                    if isinstance(exc, sqlite3.IntegrityError) else exc)
            db.execute("UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'revision'")
            db.execute("COMMIT")
        except BaseException as exc:
            if db.in_transaction:
                db.execute("ROLLBACK")
            for ticket in items:
                ticket.result = None
                ticket.error = ticket.error or TraceError("group commit failed: %s" % exc, "commit_failed")
        self.groups += 1
        self.group_sizes.append(len(items))
        if len(self.group_sizes) > 4096:
            del self.group_sizes[:2048]
        self._wake(items)

    @staticmethod
    def _wake(items, error=None):
        now = time.perf_counter()
        for ticket in items:
            if error is not None:
                ticket.error = error
            ticket.done = now
            ticket.event.set()

    # -- API --

    def submit(self, work) -> Ticket:
        """Queue `work(db)`; it runs in the writer thread inside its own savepoint of a group transaction."""
        if self._closed:
            raise TraceError("store is closed", "store_closed")
        ticket = Ticket(work)
        self._queue.put(ticket)
        return ticket

    def write(self, work, timeout: float | None = None):
        return self.submit(work).wait(timeout)

    def flush(self, timeout: float | None = None) -> None:
        """Return once every write queued before this call has committed."""
        self.write(lambda db: None, timeout)

    def reader(self) -> sqlite3.Connection:
        """This thread's read-only connection (created on first use)."""
        db = getattr(self._local, "db", None)
        if db is None:
            db = connect_ro(self.path)
            self._local.db = db
            with self._readers_lock:
                self._readers.append(db)
        return db

    def manifest(self) -> dict:
        return read_manifest(self.reader())

    def producer(self, name: str, *, pid: int | None = None, process_start: str | None = None,
                 image_sha256: str | None = None, clock_domain: str | None = None, start_mono: int | None = None,
                 observes=(), attached: bool | None = None) -> "Producer":
        """Register a new generation of `name`. A reconnecting producer always gets a new generation (§14.9)."""
        if not S.PRODUCER.match(name or ""):
            raise TraceError("producer is [a-z0-9][a-z0-9_.-]*", "bad_producer")
        clock = clock_domain or sorted(self.domains)[0]
        if clock not in self.domains:
            raise TraceError("clock domain %s is not declared by the session" % clock, "unknown_clock")
        process_key = lifetime = None

        def register(db):
            status = json.loads(db.execute("SELECT value FROM meta WHERE key='session'").fetchone()[0])["status"]
            if status != "open":
                raise TraceError("session is %s" % status, "session_closed")
            (generation,) = db.execute("SELECT COALESCE(MAX(generation), 0) + 1 FROM producers WHERE producer=?",
                                       (name,)).fetchone()
            scope = "%s:%d" % (name, generation)
            key, life = S.identity_key("proc", pid, process_start, scope) if pid is not None else (None, None)
            db.execute("INSERT INTO producers VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (name, generation, pid, process_start, key, image_sha256, clock, start_mono, time.time(),
                        S.dumps(sorted(observes))))
            if key:
                db.execute("INSERT OR IGNORE INTO identities VALUES (?,?,?,?,?,?)",
                           (key, "proc", str(pid), process_start, life, "producer:" + scope))
            if attached is not None:
                _insert_claim(db, name, generation, "attached", "true" if attached else "false", subject=scope,
                              reason="" if attached else "intended target was not reached")
            return generation, key

        generation, process_key = self.write(register)
        return Producer(self, name, generation, pid=pid, process_start=process_start, process_key=process_key,
                        clock=clock)

    def session_claim(self, kind: str, status: str, *, reason: str = "", basis=(), phases=()) -> None:
        """Session-level claims (finalized, scenario coverage, behavioral equivalence), stored as rows."""
        if kind not in ("finalized", "scenario_coverage", "behavioral_equivalence"):
            raise TraceError("session claims are finalized, scenario_coverage or behavioral_equivalence", "bad_claim")
        self.write(lambda db: _insert_claim(db, "", 0, kind, status, subject="session", reason=reason, basis=basis,
                                            phases=phases))

    def close_session(self, status: str = "closed") -> None:
        if status not in ("closed", "failed"):
            raise TraceError("status is closed or failed", "bad_status")

        def change(db):
            manifest = json.loads(db.execute("SELECT value FROM meta WHERE key='session'").fetchone()[0])
            manifest["status"] = status
            db.execute("UPDATE meta SET value=? WHERE key='session'", (S.dumps(manifest),))
            _insert_claim(db, "", 0, "finalized", "true" if status == "closed" else "false", subject="session",
                          reason="" if status == "closed" else "session failed", basis=["session.close"])
        self.write(change)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._queue.put(_STOP)
            self._thread.join()
            with self._readers_lock:
                for db in self._readers:
                    try:
                        db.close()
                    except sqlite3.ProgrammingError:
                        pass
                self._readers.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _insert_claim(db, producer, generation, kind, status, *, subject, kinds=(), phases=(), whole_session=False,
                  clock_domain=None, start=None, end=None, reason="", basis=()):
    if kind not in S.CLAIM_KINDS or status not in S.CLAIM_STATUSES:
        raise TraceError("claim kind %r / status %r" % (kind, status), "bad_claim")
    db.execute("INSERT INTO claims (producer,generation,kind,status,subject,kinds,phases,whole_session,clock_domain,"
               "start,end,reason,basis) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (producer, generation, kind, status, subject, S.dumps(sorted(kinds)), S.dumps(sorted(phases)),
                int(bool(whole_session)), clock_domain, start, end, reason, S.dumps(list(basis))))


class Producer:
    """One producer generation. Validation runs in the caller's thread; the store's writer thread only inserts."""

    def __init__(self, store: TraceStore, name: str, generation: int, *, pid, process_start, process_key, clock):
        self.store = store
        self.name = name
        self.generation = generation
        self.scope = "%s:%d" % (name, generation)
        self.pid = pid
        self.process_start = process_start
        self.process_key = process_key
        self.clock = clock
        self.privacy = store.privacy
        self.domains = store.domains
        self.events = 0
        self.batches = 0

    # -- events --

    def _row(self, ev: dict, extra: list, tally: dict) -> tuple:
        if not isinstance(ev, dict):
            raise TraceError("an event is an object", "bad_event")
        kind, version = S.check_kind(ev.get("kind"))
        if "kind_version" in ev:
            version = S._int(ev["kind_version"], "kind_version", 1)
        seq = S._int(ev.get("producer_seq"), "producer_seq", 0)
        if seq is None:
            raise TraceError("producer_seq is required", "bad_event")
        eid = S.event_id(self.name, self.generation, seq)
        t_mono = S._int(ev.get("t_mono"), "t_mono")
        domain = ev.get("clock_domain") or self.clock
        if t_mono is None:
            domain, t_mono = S.UNCLOCKED, 0
        elif domain not in self.domains:
            raise TraceError("clock domain %s is not declared" % domain, "unknown_clock")
        t_wall = ev.get("t_wall")
        if t_wall is not None and (isinstance(t_wall, bool) or not isinstance(t_wall, (int, float))):
            raise TraceError("t_wall is a number", "bad_field")
        pid, tid = S._int(ev.get("pid"), "pid", 0), S._int(ev.get("tid"), "tid", 0)
        if pid is None:
            process_key = None
        elif pid == self.pid and ev.get("process_start") in (None, self.process_start):
            process_key = self.process_key
        else:
            process_key, life = S.identity_key("proc", pid, ev.get("process_start"), eid)
            extra.append(("identity", (process_key, "proc", str(pid), ev.get("process_start"), life, eid)))
        thread_key = None
        if tid is not None:
            thread_key, life = S.identity_key("thread", tid, ev.get("thread_start"), eid)
            extra.append(("identity", (thread_key, "thread", str(tid), ev.get("thread_start"), life, eid)))
        resource_key = state_key = object_key = None
        resource = ev.get("resource")
        if resource is not None:
            if not isinstance(resource, dict):
                raise TraceError("resource is an object", "bad_field")
            resource_key = S._text(resource.get("key"), "resource.key")
            extra.append(("resource", (resource_key, resource.get("type"), resource.get("provider"),
                                       S.dumps(resource.get("precedence") or []),
                                       S.dumps(resource.get("shadowed") or []), resource.get("sha256"),
                                       resource.get("size"), eid)))
        state = ev.get("state")
        if state is not None:
            if not isinstance(state, dict):
                raise TraceError("state is an object", "bad_field")
            state_key = S._text(state.get("key"), "state.key")
            extra.append(("state", (state_key, state.get("scope"), state.get("object"), state.get("key"),
                                    state.get("offset"), state.get("name"), state.get("type"), eid)))
        obj = ev.get("object")
        if obj is not None:
            if not isinstance(obj, dict) or obj.get("address") is None:
                raise TraceError("object has an address", "bad_field")
            object_key, life = S.identity_key("obj", obj["address"], obj.get("generation"), eid)
            extra.append(("identity", (object_key, "obj", str(obj["address"]), obj.get("generation"), life, eid)))
        confidence = ev.get("confidence")
        if confidence not in S.CONFIDENCES:
            raise TraceError("confidence is one of %s" % ", ".join(S.CONFIDENCES), "bad_event")
        unresolved = ev.get("unresolved")
        if unresolved is not None and (not isinstance(unresolved, dict) or
                                       not all(isinstance(v, str) for v in unresolved.values())):
            raise TraceError("unresolved maps a field to its reason", "bad_field")
        payload = sanitize_payload(ev.get("payload"), self.privacy, tally)
        payload_json = S.dumps(payload) if payload is not None else None
        if payload_json is not None and len(payload_json.encode()) > S.MAX_PAYLOAD_JSON:
            raise TraceError("payload exceeds %d bytes of metadata" % S.MAX_PAYLOAD_JSON, "payload_too_large")
        artifacts = ev.get("artifacts")
        if artifacts:
            if self.privacy["mode"] != "payload":
                raise TraceError("payload artifacts need payload mode at session creation", "payload_not_authorized")
            for ref in artifacts:
                self._check_durable(ref)
                extra.append(("artifact", (ref["artifact_id"], ref["sha256"], ref["size"], ref.get("range_start"),
                                           ref.get("range_end"), ref["path"], eid)))
            artifacts = S.dumps([r["artifact_id"] for r in artifacts])
        else:
            artifacts = None
        return (eid, self.name, self.generation, seq, kind, version, domain, t_mono, t_wall, pid, tid, process_key,
                thread_key, resource_key, state_key, object_key, S._text(ev.get("phase"), "phase", 128),
                S._text(ev.get("operation_id"), "operation_id", 256), S._int(ev.get("frame"), "frame"),
                S._text(ev.get("thread_role"), "thread_role", 128), confidence,
                S.dumps(unresolved) if unresolved else None, payload_json, artifacts)

    def append_events_async(self, batch) -> Ticket:
        """Validate now, queue the insert; the ticket resolves when the batch is durable. All of it or none of it."""
        batch = list(batch)
        if len(batch) > S.MAX_BATCH:
            raise TraceError("a batch holds at most %d events" % S.MAX_BATCH, "batch_too_large")
        extra: list = []
        tally: dict = {}
        rows = [self._row(ev, extra, tally) for ev in batch]
        seqs = [r[3] for r in rows]
        if len(set(seqs)) != len(seqs):
            raise TraceError("a batch repeats a producer_seq", "duplicate_seq")
        name, generation = self.name, self.generation
        insert = "INSERT INTO events (%s) VALUES (%s)" % (",".join(S.EVENT_COLUMNS), ",".join("?" * len(S.EVENT_COLUMNS)))

        def work(db):
            if not rows:
                return {"batch_id": None, "count": 0}
            cur = db.execute("INSERT INTO batches (producer,generation,count,first_seq,last_seq,committed_wall) "
                             "VALUES (?,?,?,?,?,?)", (name, generation, len(rows), min(seqs), max(seqs), time.time()))
            batch_id = cur.lastrowid
            db.executemany(insert, (row + (batch_id,) for row in rows))
            for table, values in extra:
                if table == "identity":
                    db.execute("INSERT OR IGNORE INTO identities VALUES (?,?,?,?,?,?)", values)
                elif table == "resource":
                    db.execute("INSERT OR IGNORE INTO resources VALUES (?,?,?,?,?,?,?,?)", values)
                elif table == "state":
                    db.execute("INSERT OR IGNORE INTO states VALUES (?,?,?,?,?,?,?,?)", values)
                else:
                    db.execute("INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?,?)", values)
            _upsert_counters(db, name, generation, "writer", {"events": len(rows), "batches": 1, **tally}, add=True)
            return {"batch_id": batch_id, "count": len(rows), "first_event": rows[0][0], "last_event": rows[-1][0]}

        ticket = self.store.submit(work)
        self.events += len(rows)
        self.batches += 1 if rows else 0
        return ticket

    def append_events(self, batch, timeout: float | None = None) -> dict:
        return self.append_events_async(batch).wait(timeout)

    # -- private artifacts (payload mode) --

    def put_artifact(self, data: bytes, *, range_start: int | None = None) -> dict:
        """Store selected bytes outside the database, durably (fsync then rename), BEFORE any event references them."""
        if self.privacy["mode"] != "payload":
            raise TraceError("payload artifacts need payload mode at session creation", "payload_not_authorized")
        data = bytes(data)
        if len(data) > int(self.privacy["max_artifact_bytes"]):
            raise TraceError("artifact exceeds %d bytes" % self.privacy["max_artifact_bytes"], "artifact_too_large")
        digest = hashlib.sha256(data).hexdigest()
        folder = self.store.path / ARTIFACTS
        folder.mkdir(exist_ok=True)
        final = folder / ("%s.bin" % digest)
        if not final.exists():
            tmp = folder / ("%s.%s.tmp" % (digest, uuid.uuid4().hex[:8]))
            with open(tmp, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.replace(tmp, final)
            except PermissionError:
                tmp.unlink(missing_ok=True)
                if not final.exists():
                    raise
        start = range_start if range_start is not None else 0
        return {"artifact_id": "art:" + digest, "sha256": digest, "size": len(data), "range_start": start,
                "range_end": start + len(data), "path": "%s/%s.bin" % (ARTIFACTS, digest)}

    def _check_durable(self, ref) -> None:
        if not isinstance(ref, dict) or not str(ref.get("artifact_id", "")).startswith("art:"):
            raise TraceError("an artifact reference comes from put_artifact", "bad_artifact")
        path = self.store.path / ref["path"]
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            raise TraceError("artifact %s is not durable" % ref["artifact_id"], "artifact_missing") from None
        if size != ref["size"]:
            raise TraceError("artifact %s has the wrong size" % ref["artifact_id"], "artifact_missing")

    # -- out-of-band health, relations --

    def claim(self, kind: str, status: str, *, kinds=(), phases=(), whole_session: bool = False,
              clock_domain: str | None = None, start: int | None = None, end: int | None = None, reason: str = "",
              basis=()) -> None:
        if kind not in S.PRODUCER_CLAIM_KINDS:
            raise TraceError("producer claims are %s" % ", ".join(S.PRODUCER_CLAIM_KINDS), "bad_claim")
        if kind == "capture_coverage" and status == "true" and not (phases or whole_session or start is not None):
            raise TraceError("a coverage claim names phases, an interval or the whole session", "bad_claim")
        domain = clock_domain or (self.clock if start is not None or end is not None else None)
        self.store.write(lambda db: _insert_claim(db, self.name, self.generation, kind, status, subject=self.scope,
                                                  kinds=kinds, phases=phases, whole_session=whole_session,
                                                  clock_domain=domain, start=start, end=end, reason=reason,
                                                  basis=basis))

    def gap(self, kind: str, layer: str, *, count: int | None = None, kinds=(), phase: str | None = None,
            clock_domain: str | None = None, start: int | None = None, end: int | None = None,
            reason: str = "") -> None:
        if kind not in S.GAP_KINDS or layer not in S.COUNTER_LAYERS:
            raise TraceError("gap kind %r / layer %r" % (kind, layer), "bad_gap")
        domain = clock_domain or (self.clock if start is not None or end is not None else None)
        self.store.write(lambda db: db.execute(
            "INSERT INTO gaps (producer,generation,kind,layer,count,kinds,phase,clock_domain,start,end,reason) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (self.name, self.generation, kind, layer, count, S.dumps(sorted(kinds)), phase, domain, start, end,
             reason)))

    def counters(self, layer: str, values: dict, *, add: bool = False) -> None:
        if layer not in S.COUNTER_LAYERS:
            raise TraceError("counter layer %r" % layer, "bad_counter")
        self.store.write(lambda db: _upsert_counters(db, self.name, self.generation, layer, values, add=add))

    def relation(self, from_event: str, to_event: str, relation: str, *, basis, status: str, rule_revision: str,
                 unresolved=()) -> str:
        if status not in S.RELATION_STATUSES:
            raise TraceError("relation status is %s" % ", ".join(S.RELATION_STATUSES), "bad_relation")
        if not rule_revision:
            raise TraceError("a relation cites the rule revision that produced it", "bad_relation")
        if status == "supported" and not basis:
            raise TraceError("a supported relation states its basis", "bad_relation")
        content = S.dumps([from_event, to_event, relation, sorted(basis), status, sorted(unresolved), rule_revision])
        rid = "rel:" + hashlib.sha256(content.encode()).hexdigest()[:24]
        self.store.write(lambda db: db.execute(
            "INSERT OR IGNORE INTO relations VALUES (?,?,?,?,?,?,?,?)",
            (rid, from_event, to_event, relation, S.dumps(sorted(basis)), status, S.dumps(sorted(unresolved)),
             rule_revision)))
        return rid

    def correlation_id(self, keyring: CorrelationKeyring, scope: str, value: str) -> str:
        session = self.store.path.resolve()
        if keyring.directory == session or session in keyring.directory.parents:
            raise TraceError("the correlation keyring must live outside the session", "keyring_inside_session")
        cid = keyring.correlation_id(scope, value)
        self.store.write(lambda db: db.execute("INSERT OR IGNORE INTO correlation_scopes VALUES (?)", (scope,)))
        return cid

    def finalize(self, *, producer_counters: dict | None = None) -> None:
        """Writer bookkeeping for this generation completed. Says nothing about attachment or observation."""
        if producer_counters:
            self.counters("producer", producer_counters)
        self.claim("finalized", "true", basis=["producer.finalize"])


def _upsert_counters(db, producer, generation, layer, values, *, add):
    sql = ("INSERT INTO counters VALUES (?,?,?,?,?) ON CONFLICT(producer,generation,layer,name) DO UPDATE SET value=" +
           ("value+excluded.value" if add else "excluded.value"))
    for name, value in sorted(values.items()):
        db.execute(sql, (producer, generation, layer, name, int(value)))


# ---- health -----------------------------------------------------------------------------------------------------

def coverage_revision(db) -> str:
    (claims,) = db.execute("SELECT COALESCE(MAX(id), 0) FROM claims").fetchone()
    (gaps,) = db.execute("SELECT COALESCE(MAX(id), 0) FROM gaps").fetchone()
    return "c%d.g%d" % (claims, gaps)


def load_claims(db, producer=None):
    sql = ("SELECT producer,generation,kind,status,subject,kinds,phases,whole_session,clock_domain,start,end,reason,"
           "basis,id FROM claims")
    return [{"producer": r[0], "generation": r[1], "kind": r[2], "status": r[3], "subject": r[4],
             "kinds": S.loads(r[5], []), "phases": S.loads(r[6], []), "whole_session": bool(r[7]),
             "clock_domain": r[8], "start": r[9], "end": r[10], "reason": r[11], "basis": S.loads(r[12], []),
             "id": r[13]} for r in db.execute(sql + " ORDER BY id")]


def load_gaps(db):
    sql = "SELECT producer,generation,kind,layer,count,kinds,phase,clock_domain,start,end,reason,id FROM gaps"
    return [{"producer": r[0], "generation": r[1], "kind": r[2], "layer": r[3], "count": r[4],
             "kinds": S.loads(r[5], []), "phase": r[6], "clock_domain": r[7], "start": r[8], "end": r[9],
             "reason": r[10], "id": r[11]} for r in db.execute(sql + " ORDER BY id")]


def health(db) -> dict:
    """Every claim, gap and counter, per producer generation and for the session, kept apart. A claim kind with no
    row is `unknown` with reason `not_reported`; nothing is inferred from another claim."""
    manifest = read_manifest(db)
    claims, gaps = load_claims(db), load_gaps(db)
    counters: dict = {}
    for producer, generation, layer, name, value in db.execute(
            "SELECT producer,generation,layer,name,value FROM counters ORDER BY 1,2,3,4"):
        counters.setdefault((producer, generation), {}).setdefault(layer, {})[name] = value
    stored = {(p, g): (n, b) for p, g, n, b in db.execute(
        "SELECT producer, generation, SUM(count), COUNT(*) FROM batches GROUP BY producer, generation")}
    producers = []
    for name, generation, pid, process_key, observes in db.execute(
            "SELECT producer,generation,pid,process_key,observes FROM producers ORDER BY producer, generation"):
        mine = [c for c in claims if (c["producer"], c["generation"]) == (name, generation)]
        summary = {}
        for kind in S.PRODUCER_CLAIM_KINDS:
            rows = [c for c in mine if c["kind"] == kind]
            if not rows:
                summary[kind] = {"status": "unknown", "reason": "not_reported"}
            elif kind == "capture_coverage":
                summary[kind] = {"status": "true" if any(c["status"] == "true" for c in rows) else rows[-1]["status"],
                                 "intervals": len(rows)}
            else:
                summary[kind] = {"status": rows[-1]["status"], "reason": rows[-1]["reason"]}
        events, batches = stored.get((name, generation), (0, 0))
        producers.append({"producer": name, "generation": generation, "pid": pid, "process_key": process_key,
                          "observes": S.loads(observes, []), "stored_events": events or 0, "committed_batches": batches,
                          "summary": summary, "claims": mine,
                          "gaps": [g for g in gaps if (g["producer"], g["generation"]) == (name, generation)],
                          "counters": counters.get((name, generation), {})})
    session_claims = [c for c in claims if c["producer"] == ""]
    return {"session_id": manifest["session_id"], "status": manifest["status"], "revision": manifest["revision"],
            "coverage_revision": coverage_revision(db), "session_claims": session_claims,
            "session_gaps": [g for g in gaps if g["producer"] == ""], "session_counters": counters.get(("", 0), {}),
            "producers": producers}
