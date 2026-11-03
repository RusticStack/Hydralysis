"""Bounded, address-based queries on saved analysis, through Hydra Engine.

The analysed project opens in place through the engine's read-only view: no lock,
no copy, nothing written. Every Hydralysis process on the root shares one daemon,
so the program and its decompilers stay warm across harnesses. Each query is one
contained run of RusticQuery.java, which the engine rolls back, so a query can
never change what another client reads. Targets with cited overlays are answered
from their working copy (see workcopy.py).
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
import zlib
from contextlib import contextmanager
from pathlib import Path

from hydralysis import hydra, lineage, staticplane, targets, viewgov, views, workcopy
from hydralysis import decompile_result
from hydralysis.analysis import ADVANCED_ACTIONS, BULK_KINDS, validate_options
from hydralysis.locks import LockBusy

ACTIONS = {"decompile", "function", "functions", "xrefs", "status", "stop"} | ADVANCED_ACTIONS
ADDRESS_ACTIONS = {"decompile", "function", "xrefs", "variables", "dossier", "blocks", "pcode", "trace", "data", "scan", "vtables"}
_ADDRESS = re.compile(r"(?:(?:rva|va):)?(?:0x)?[0-9a-fA-F]+")
MAX_CHARS = 16_000_000
# A background save of a large working copy holds its program for up to a few minutes;
# requests wait for it rather than fail.
BUSY_WAIT_MS = 180_000

# Program keys per (root, project, program) for this process. The daemon may
# restart; a stale key is reopened once.
_keys: dict[tuple, dict] = {}
_keys_guard = threading.Lock()
# Program key -> the open of it in flight: the threads that want the same program meanwhile wait for that open and take its
# outcome, the row or the refusal (they do not each wait out a busy program again in turn).
_opening: dict[tuple, "_Flight"] = {}
# (connection key, daemon program) -> how many reads of this process use it now: the cap's LRU close takes them last.
_in_use: dict[tuple, int] = {}
# The marks of the read this thread runs (`_holding`): a program is marked in use as its row is handed out.
_held = threading.local()
# Reads on hydra.4 are spread over this many reader connections by view key (`readerLanes`); lane 0 is the shared one.
# One by default: a lane keeps the generations its views read before a publish open until its own cap closes them, so the
# daemon would hold up to `maxViewsPerClient` programs per lane (gate 9.17's view-leak test counts them as held).
READER_LANES = 1
# shared reader key -> {lane: Engine} of this process (`QueryRunner.reader`).
_lanes: dict[str, dict[int, object]] = {}
_ENGINE = hydra.Engine   # the real class, taken at import: a stand-in (a test patches hydra.Engine) keeps one reader
# Lineages whose orphaned views this process has already listed in a reply (`adoptable`, once per lineage, 4.10).
_announced: set[str] = set()
# origin key -> (lineage id or None, when it was looked up): a lineage found stays found, "none" is asked again after a few seconds.
_lineage_ids: dict[str, tuple[str | None, float]] = {}
_NO_LINEAGE_S = 5.0
# Edits that make no new record: a view is not created, and its record is not made, by these.
_NO_NEW_RECORDS = ("revert", "commit", "commit_revert", "commit_abort", "publish", "rebase")


def _native(name: str):
    """The Rust twin NAME (rust/crates/hy-query/src/session.rs) when HYDRALYSIS_IMPL=rust and it is built, else None."""
    if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() != "rust":
        return None
    try:
        import hydralysis_native as native
    except ImportError:
        return None
    return getattr(native, name, None)


def _json_text(*values):
    """The JSON text of each value, or None when one is not plain JSON data (the Python path then answers)."""
    try:
        return [json.dumps(value, ensure_ascii=False, allow_nan=False) for value in values]
    except (TypeError, ValueError):
        return None


def accepted(action: str, response: dict) -> dict:
    """The engine's answer as the caller gets it: an error raises; a decompile the engine stopped on purpose is a partial
    result (it keeps `c`, `fragments`, `truncated`, `bytes_emitted`, `reason`) and gains a `decompile` summary."""
    rust, texts = _native("session_accepted_rs"), None
    if rust is not None and isinstance(response, dict) and isinstance(action, str):
        texts = _json_text(response)
    if texts is not None:
        return json.loads(rust(action, texts[0]))
    if not response.get("ok"):
        partial = decompile_result.from_error(json.dumps(response)) if action == "decompile" else None
        if partial is None:
            raise RuntimeError(json.dumps(_public(response), ensure_ascii=False))
        response = {**partial, "ok": True, "engine_ok": False}
    if action == "decompile":
        decompile_result.annotate(response)
    return response


def _public(value):
    """Engine credentials never enter MCP/status/export output."""
    rust = _native("session_public_rs")
    texts = _json_text(value) if rust is not None else None
    if texts is not None:
        return json.loads(rust(texts[0]))
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if key not in ("ipc", "token", "secret")}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


def open_program(engine: hydra.Engine, gpr: str, program: str, sha256: str, *, writable: bool = False,
                 upgrade: bool = False, refresh: bool = False, share: bool = True, backup: str | None = None,
                 project: str | None = None) -> dict:
    """Join (or open) one program and check the build before anything is answered from it.

    `share=False` opens a writable program for its caller alone (a commit's candidate); `backup` is the verified
    backup an upgrading writable open names on an engine with the upgrade gate; PROJECT is the id of a project this
    connection has just made (a fork), which saves the `open_project` round trip that would only look it up again."""
    cache_key = (engine.key, str(Path(gpr)).lower(), program, writable)
    while True:
        with _keys_guard:
            known = _keys.get(cache_key)
            if known and not refresh:
                _keys[cache_key] = _keys.pop(cache_key)   # most recently used last: eviction takes the oldest first
                return _hold(engine, known)
            flight = _opening.get(cache_key)
            if flight is None:
                flight = _opening[cache_key] = _Flight()
                break
        flight.done.wait()
        if not refresh:
            if flight.error is not None:
                raise flight.error
            if flight.row is not None:
                with _keys_guard:
                    return _hold(engine, flight.row)
        # A refresh opens again itself after the open in flight, and so does a waiter whose opener was interrupted.
    try:
        flight.row = _open(engine, cache_key, gpr, program, sha256, writable, upgrade, share, backup, project)
        return flight.row
    except Exception as error:
        flight.error = error
        raise
    finally:
        with _keys_guard:
            del _opening[cache_key]
        flight.done.set()


class _Flight:
    """One open in progress (`open_program`): the threads that join it wait for `done` and take `row` or `error`."""

    def __init__(self):
        self.done = threading.Event()
        self.row: dict | None = None
        self.error: BaseException | None = None


def _open(engine: hydra.Engine, cache_key: tuple, gpr: str, program: str, sha256: str, writable: bool, upgrade: bool,
          share: bool, backup: str | None, project: str | None = None) -> dict:
    wait = hydra.patience_ms(engine, BUSY_WAIT_MS)
    # A project this connection has just made is open already: `open_project` would only look it up (and ask for the
    # writable lock this fork already holds), one engine round trip per rebuilt working copy.
    opened = {"id": project, "gpr": gpr} if project else engine.call("open_project", path=gpr, writable=writable, wait=wait)
    fields = {"path": program, "project": opened["id"]}
    if writable:
        fields.update(writable=True, share=share, upgrade=upgrade)
        if backup:
            fields["backup"] = backup
    try:
        info = engine.call("open_program", wait=wait, **fields)
    except hydra.EngineError as error:
        if not at_client_cap(error):
            raise
        info = _open_after_eviction(engine, cache_key, fields, wait, error)
    if str(info.get("sha256", "")).lower() != sha256:
        raise ValueError("%s in %s reports SHA-256 %s, not the target build %s; nothing was answered"
                         % (program, opened.get("gpr", gpr), info.get("sha256"), sha256))
    result = {"key": info["key"], "project": opened["id"], "gpr": opened.get("gpr", gpr), "revision": info.get("revision"),
              "project_revision": opened.get("revision"), "image_base": info.get("imageBase"),
              "functions": info.get("functions"), "analyzed": info.get("analyzed"), "mode": info.get("mode")}
    with _keys_guard:
        _keys[cache_key] = result
        return _hold(engine, result)


def at_client_cap(error: hydra.EngineError) -> bool:
    """hydra.4's per-connection view cap (`maxViewsPerClient`, PROTOCOL-3.md 3.11): `busy` with resource `client_cap`."""
    return error.code == "busy" and error.details.get("resource") == "client_cap"


_GONE = ("no_program", "no_project", "not_found", "closed")


def _open_after_eviction(engine: hydra.Engine, cache_key: tuple, fields: dict, wait: int, error: hydra.EngineError) -> dict:
    """Open again after closing this connection's least recently used read-only programs, one at a time.

    The cache keeps every program it opened on a connection, so a process that reads several views (each a working copy)
    reaches hydra.4's cap of `maxViewsPerClient` (4) programs per connection and every later open was refused `busy`. Only
    read-only rows are closed (a writable program may hold unsaved edits); a read that still uses a closed key gets
    `no_program` and reopens once (`QueryRunner._ask`). A program no read of this process is using goes first; when every
    one is in use, the least recently used of them is closed all the same. When nothing is left to close, the engine's
    refusal stands."""
    while True:
        with _keys_guard:
            rows = [(key, value) for key, value in _keys.items() if key[0] == engine.key and key != cache_key and not key[3]]
            rows = [row for row in rows if not _in_use.get((engine.key, row[1]["key"]))] or rows
        if not rows:
            raise error
        program = rows[0][1]["key"]
        try:
            engine.call("close_program", program=program)
        except hydra.EngineError as closing:
            if closing.code not in _GONE:
                raise error from closing
        with _keys_guard:
            for key in [key for key, value in _keys.items() if key[0] == engine.key and value["key"] == program]:
                _keys.pop(key, None)
        try:
            return engine.call("open_program", wait=wait, **fields)
        except hydra.EngineError as again:
            if not at_client_cap(again):
                raise
            error = again


def forget(engine: hydra.Engine) -> None:
    """Drop the rows of one connection: the shared Engine, or a pool entry (`forget(entry)`, I2). Its key is the rows' first element."""
    with _keys_guard:
        for key in [key for key in _keys if key[0] == engine.key]:
            _keys.pop(key, None)


def _drop_program(engine: hydra.Engine, program: str) -> None:
    """Drop the rows of one daemon program on ENGINE's connection (the program is gone there)."""
    with _keys_guard:
        for key in [key for key, value in _keys.items() if key[0] == engine.key and value.get("key") == program]:
            _keys.pop(key, None)


def _drop_rows_under(engine: hydra.Engine, folders) -> None:
    """Drop ENGINE's rows of programs whose project lies under one of FOLDERS (a reopen joins the same program again)."""
    roots = [Path(folder).resolve() for folder in folders]
    with _keys_guard:
        rows = [(key, value) for key, value in _keys.items() if key[0] == engine.key]
    # `resolve` asks the file system: outside the guard, and a row replaced meanwhile stays.
    gone = [(key, value) for key, value in rows if any(Path(key[1]).resolve().is_relative_to(root) for root in roots)]
    with _keys_guard:
        for key, value in gone:
            if _keys.get(key) is value:
                _keys.pop(key, None)


def _hold(engine: hydra.Engine, row: dict) -> dict:
    """ROW, marked in use when this thread runs a read (`_holding`). Called under `_keys_guard` where the row is handed out,
    so no cap close of another thread comes between the open and the mark."""
    marks = getattr(_held, "marks", None)
    if marks is not None:
        mark = (engine.key, row["key"])
        _in_use[mark] = _in_use.get(mark, 0) + 1
        marks.append(mark)
    return row


@contextmanager
def _holding():
    """Mark every program this thread's opens hand out in the block as used by its read: `_open_after_eviction` closes
    them last."""
    previous, marks = getattr(_held, "marks", None), []
    _held.marks = marks
    try:
        yield
    finally:
        _held.marks = previous
        with _keys_guard:
            for mark in marks:
                if _in_use[mark] > 1:
                    _in_use[mark] -= 1
                else:
                    del _in_use[mark]


def reader_lanes(settings: dict) -> int:
    """How many reader connections a hydra.4 process spreads its reads over (`readerLanes`, 1..64, default READER_LANES)."""
    rust = _native("session_reader_lanes_rs")
    texts = _json_text(settings) if rust is not None and isinstance(settings, dict) else None
    if texts is not None:
        return rust(texts[0])
    value = settings.get("readerLanes", settings.get("reader_lanes"))
    return value if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 64 else READER_LANES


def readers(engine: hydra.Engine) -> list:
    """ENGINE and the reader lanes this process made beside it (`QueryRunner.reader`): every connection whose rows a view's
    release or a stop must look at."""
    with _keys_guard:
        return [engine, *(lane for lane in _lanes.get(engine.key, {}).values() if lane.key != engine.key)]


def forget_role(engine: hydra.Engine) -> None:
    """Drop every row of the role: the shared connection's and every pool entry's (`<root>|<role>|`)."""
    prefix = engine.key + "|"
    with _keys_guard:
        for key in [key for key in _keys if key[0] == engine.key or key[0].startswith(prefix)]:
            _keys.pop(key, None)


# RusticQuery actions whose output depends only on the request and the program's state (not on the overlay files
# or the clock): the engine caches their output per program state. overlay_state, trace, fingerprints and the
# writers (apply_overlays, type_edit) are left out.
PURE_ACTIONS = frozenset({
    "decompile", "function", "functions", "xrefs", "types", "type", "data", "scan", "variables", "dossier", "blocks",
    "pcode", "vcalls", "vtables", "writes", "orphans"})


def run_script(engine: hydra.Engine, program: dict, request: dict, timeout_s: int, request_dir: Path | None = None,
               wait_ms: int = 0, deadline_s: float | None = None) -> tuple[dict, dict]:
    """One RusticQuery run. Large requests travel as a file, not a command argument.

    A read goes to the quick lane when the engine has the lane hint (7.6); `deadline_s` is passed to a client library that
    times its own wait (library 1.1.0). On hydra.2/3 the deadline is the attempt's, kept by the pool entry that is `engine`."""
    body = json.dumps(request, ensure_ascii=False)
    argument = body
    path = None
    if len(body) > 256 * 1024:
        if request_dir is None:
            raise ValueError("request too large to send inline")
        request_dir.mkdir(parents=True, exist_ok=True)
        path = request_dir / ("request-%s.json" % uuid.uuid4().hex)
        path.write_text(body, encoding="utf-8")
        argument = "@" + str(path)
    try:
        extra = {"lane": "quick"} if hydra.supports(engine, "laneHint") else {}
        if request.get("action") in PURE_ACTIONS and not path:
            # the output is a function of the script, the request and the program's state: the engine
            # may answer a repeat on an unchanged program from the output of an earlier run
            extra["pure"] = True
        if deadline_s is not None:
            extra["deadline"] = deadline_s
        result = engine.call("script", script="RusticQuery.java", program=program["key"], args=[argument],
                             maxChars=MAX_CHARS, timeout=timeout_s + 5, wait=wait_ms or hydra.patience_ms(engine, BUSY_WAIT_MS),
                             **extra)
    finally:
        if path is not None:
            path.unlink(missing_ok=True)
    lines = [line for line in str(result.get("output", "")).splitlines() if line.startswith("{")]
    if not lines or result.get("truncated"):
        raise RuntimeError("RusticQuery returned no complete answer (truncated=%s): %s"
                           % (result.get("truncated"), str(result.get("output", ""))[-2000:]))
    return json.loads(lines[-1]), result


FALLBACK_TIMEOUT_S = 3600   # the engine's own decompile of a huge function: minutes (370 s measured), never the script's 30 s
ENGINE_FIELDS = (("max_result_mb", "maxResultMb"), ("max_result_kb", "maxResultKb"), ("offset", "offset"))


class DeferDecompile(RuntimeError):
    """A decompile that needs the engine's long path and so runs as a job (`decompile_job`) instead of blocking the caller."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def engine_decompile(engine: hydra.Engine, program: dict, request: dict, timeout_s: int, response: dict,
                     inline: bool = False) -> dict:
    """RESPONSE of a decompile, completed with the engine's own `decompile` answer where that carries more.

    RusticQuery decompiles on its own and knows neither the engine's whole-reply bound (`max_result_mb`, `max_result_kb`),
    its paging (`offset`) nor its fragment report for a body in several pieces. So the engine's command is asked too when the
    caller set one of those, or when the script could not decompile at all ("No pcode", a timeout, a buffer overflow). That
    second answer can take minutes: unless INLINE (the job worker) the call raises DeferDecompile and the caller starts a job.
    The answer of a failed script is labelled `fallback`. Its fields are merged by `decompile_result.merge`."""
    rust = _native("session_engine_decompile_rs")
    texts = None
    if rust is not None and isinstance(request, dict) and isinstance(response, dict) and isinstance(program.get("key"), str)             and isinstance(request.get("options") or {}, dict) and isinstance(timeout_s, int) and not isinstance(timeout_s, bool):
        texts = _json_text(request, response)
    if texts is not None:
        kind, text = rust(engine, program["key"], texts[0], timeout_s, texts[1], bool(inline))
        if kind == "answer":
            answer = json.loads(text)
            return response if answer == response else answer
        if kind == "defer":
            raise DeferDecompile(text)
        if kind in ("type", "value"):
            raise (TypeError if kind == "type" else ValueError)(text)
        # "unsupported": a shape the port does not model; the original below answers.
    if request.get("action") != "decompile":
        return response
    options = request.get("options") or {}
    explicit = {engine_name: options[name] for name, engine_name in ENGINE_FIELDS if options.get(name) is not None}
    failed = response.get("ok") is False
    if not explicit and not failed:
        return response
    reason = str(response.get("error") or response.get("message") or "")[:600] if failed else ""
    if failed and not inline:
        raise DeferDecompile(reason or "the script could not decompile")
    fields = {"maxChars": int(options.get("max_characters", 32000)), **explicit}
    timeout = FALLBACK_TIMEOUT_S if failed else timeout_s + 5
    started = time.monotonic()
    try:
        reply = engine.call("decompile", program=program["key"], address=request["address"], timeout=timeout, **fields)
    except hydra.EngineError as error:
        slow = error.code in ("timeout", "deadline", "timed_out") or "timeout" in str(error.details.get("reason", "")).lower()             or "timed out" in error.message.lower()
        if inline or not slow:   # a refusal keeps the script's answer; only a clock that ran out becomes a job
            return response
        raise DeferDecompile("the engine decompile did not answer in %d s: %s" % (timeout, str(error)[:300])) from error
    merged = decompile_result.merge(response, reply)
    if failed and merged is not response:
        merged["fallback"] = {"via": "engine_decompile", "reason": reason, "engine_s": round(time.monotonic() - started, 1),
                              "timeout_s": timeout}
    return merged


class QueryRunner:
    def __init__(self, settings: dict, engine: hydra.Engine | None = None):
        self.settings = settings
        self.inline = False   # True in a decompile job's worker: a long engine decompile runs here instead of becoming a job
        self.engine = engine or hydra.Engine(settings)
        self.requests = Path(settings["root"]) / "hydra" / "requests"

    def target(self, name: str) -> dict:
        return targets.resolve(self.settings, name)

    def reader(self, target: dict):
        """The connection that reads TARGET. On hydra.4 a connection holds at most `maxViewsPerClient` programs and one
        reader is shared by every thread, so reads are spread over `readerLanes` connections by view key: a view always reads
        on the same one, and lane 0 is the shared connection. hydra.2/3 (the pool of 7.6) and a stand-in keep the one."""
        lanes = reader_lanes(self.settings)
        engine = self.engine
        if lanes < 2 or type(engine) is not _ENGINE or engine.role != "reader" or engine.lane \
                or self._native_deadline(0) is None:
            return engine
        lane = zlib.crc32(str(target.get("key") or target["name"]).encode("utf-8")) % lanes
        if lane == 0:
            return engine
        with _keys_guard:
            known = _lanes.setdefault(engine.key, {}).get(lane)
            if known is None or known.settings is not self.settings:
                known = _lanes[engine.key][lane] = type(engine)(self.settings, role=engine.role, start=engine.start,
                                                                lane="shard-%d" % lane)
            return known

    def program_for(self, target: dict, *, for_overlays: bool = True, engine=None) -> dict:
        """The master's read-only view, or the working copy that holds the view's overlays (never for a master read).

        ENGINE is the pool entry of an attempt (7.6); it defaults to the shared connection."""
        engine = engine or self.engine
        if for_overlays and not target.get("master_read"):
            if workcopy.has_overlays(self.settings, target):
                return workcopy.reader(self.settings, engine, target)
            # A view without pending records is its base generation: the head unless the view is behind it (gate 9.17 H).
            return open_program(engine, workcopy.read_gpr(self.settings, target), target["program"], target["sha256"])
        return open_program(engine, target["gpr"], target["program"], target["sha256"])

    def _pool(self):
        """The pool of deadline-bound attempts, or None: only a real engine on hydra.2/3 (library 1.0.0) uses it. On hydra.4
        the library times its own wait and nothing is abandoned; a stand-in without `connect_entry` runs as before."""
        engine = self.engine
        if not hasattr(engine, "connect_entry") or not hasattr(engine, "pool"):
            return None
        try:
            return engine.pool() if engine.deadline_mode() == "helper" else None
        except Exception:
            return None

    def _native_deadline(self, timeout_s: int) -> float | None:
        """The deadline a hydra.4 client library enforces itself (P1b); None on hydra.2/3 (the pool does) and on a stand-in."""
        try:
            native = hasattr(self.engine, "deadline_mode") and self.engine.deadline_mode() == "native"
        except Exception:
            native = False
        return self._deadline(timeout_s) if native else None

    @staticmethod
    def _deadline(timeout_s: int) -> float:
        """`deadline_s` of a quick-lane attempt: 60 s, and never below the script's own timeout plus its margin."""
        return max(hydra.DEADLINE_S, timeout_s + 10.0)

    # --- identity, routing, the governor (Y5: D43, D59, 4.10) -----------------------------------------------------------

    def _release(self, entry) -> None:
        """The governor's callback: close this process's programs of one view (discard, keep the folder)."""
        workcopy.release(self.engine, self.settings, entry.target)

    def _route(self, base: dict, who: dict, explicit: str, scope: str, action: str) -> tuple[dict, str]:
        """Which store a call reads or writes. `master` (a sealed-master read), `agent` (the caller's own view),
        `shared` (the collaboration view) or `named` (an explicit `options.view`)."""
        writes = action == "type_edit"
        if scope == "master" and writes:
            raise ValueError("options.scope 'master' reads the sealed master; an edit always goes to a view")
        if explicit == "master":
            raise ValueError("view 'master' is reserved: it labels reads of the sealed master")
        if explicit:
            selected = workcopy.with_view(base, explicit)
            mode = "shared" if selected["view"] == "shared" else "named"
        elif who["shared"]:
            selected, mode = workcopy.with_view(base, "shared"), "shared"
        else:
            selected, mode = workcopy.with_view(base, who["name"]), "agent"
            if not writes and not workcopy.view_exists(self.settings, selected):
                return workcopy.master_target(base), "master"
        if scope == "master" and not writes:
            return workcopy.master_target(base), "master"
        return selected, mode

    def _register(self, base_name: str, selected: dict, who: dict, mode: str) -> dict:
        """The first edit of an agent creates its view: the lineage (generation 0 is the adopted master, never written), then
        the view's record with the agent id, the boot id, the pid and the lease. Idempotent; a later call only refreshes."""
        if mode != "agent":
            return selected
        link = selected.get("lineage")
        lineage_id = link["id"] if link else views.ensure_lineage(self.settings, selected)["id"]
        if not link:
            selected = workcopy.with_view(self.target(base_name), selected["view"])
        views.claim(self.settings, selected, who, lineage_id, self._lease())
        return selected

    def _lineage_id(self, selected: dict) -> str | None:
        """The lineage that holds the view records of this target: the resolved one, else the one created for its origin key
        (a target defined only by configuration has no registry row, so it resolves without a lineage but can still have one)."""
        link = selected.get("lineage")
        if link:
            return link["id"]
        origin = selected.get("origin_key") or selected["key"]
        with _keys_guard:
            known, stamp = _lineage_ids.get(origin, (None, 0.0))
        if known is None and time.monotonic() - stamp > _NO_LINEAGE_S:
            known = lineage.find(self.settings, origin)
            with _keys_guard:
                _lineage_ids[origin] = (known, time.monotonic())
        return known

    def _lease(self) -> float:
        value = self.settings.get("viewLeaseS", self.settings.get("view_lease_s"))
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 5 else views.LEASE_S

    def _touch(self, selected: dict, who: dict, mode: str) -> None:
        """A read of an agent's existing view keeps its lease (never creates a record)."""
        lineage_id = self._lineage_id(selected) if mode == "agent" else None
        if lineage_id:
            views.claim(self.settings, selected, who, lineage_id, self._lease(), create=False)

    def _frame(self, selected: dict, mode: str, who: dict, store: dict | None = None) -> dict:
        """What every reply says about where it came from (4.10): `view`, `agent`, `base` and, when behind, `stale`.

        STORE is the copy this call already loaded, when nothing has changed it since."""
        link = selected.get("lineage")
        head = {"lineage": link["id"], "generation": link["generation"]} if link else None
        frame = {"view": selected["view"], "agent": who["agent"]}
        if mode == "master":
            return {**frame, "base": head}
        try:
            if store is None:
                store = workcopy.load_store(self.settings, selected)
        except (ValueError, OSError):
            return {**frame, "base": head}
        base = store.get("base")
        frame["base"] = base
        if workcopy.stale_reason(store, selected):
            frame["stale"] = {"base": (base or {}).get("generation", 0), "head": link["generation"],
                              "behind": link["generation"] - (base or {}).get("generation", 0)}
        return frame

    def _stamp(self, payload: dict, ctx: dict) -> dict:
        """Add the frame (without overwriting what the reply already says) and the one-time `view_rebuilt`."""
        store = ctx.get("store") if ctx.get("store_fresh") else None
        for key, value in self._frame(ctx["selected"], ctx["mode"], ctx["who"], store).items():
            payload.setdefault(key, value)
        pin = ctx.get("pin")
        if pin is not None and pin.rebuilt and "view_rebuilt" not in payload:
            payload["view_rebuilt"] = {"replayed": ctx["trace"].get("replayed", 0),
                                       "ms": round((time.monotonic() - pin.started) * 1000)}
        return payload

    def _announce(self, response: str, base: dict, who: dict) -> str:
        """The first reply of a default-id process on a lineage names the orphaned views of the same agent that hold pending
        records (`adoptable`, 4.10 b); `options.as:"<old id>"` re-attaches. Later replies stay as they are."""
        lineage_id = self._lineage_id(base)
        if not lineage_id or who["kind"] != "default":
            return response
        with _keys_guard:
            first = lineage_id not in _announced
            _announced.add(lineage_id)
        if not first:
            return response
        orphans = views.adoptable(self.settings, base, lineage_id)
        if not orphans:
            return response
        try:
            decoded = json.loads(response)
        except ValueError:
            return response
        if not isinstance(decoded, dict):
            return response
        decoded["adoptable"] = orphans
        decoded["adoptable_note"] = ("these views of an earlier process of the same agent still hold pending records; "
                                     "pass options.as with one of the listed agent ids to adopt it, or set HYDRALYSIS_AGENT_ID "
                                     "so a restarted server keeps its id")
        return json.dumps(decoded, ensure_ascii=False)

    def _housekeeping(self, base: dict) -> None:
        """Before a call: close the views that have been idle past `viewIdleEvictS`, and now and then delete the folders of
        views nobody holds that were idle for `viewIdleDeleteS`. Failures here never fail the call."""
        try:
            viewgov.GOVERNOR.sweep(self.settings, self._release)
            lineage_id = self._lineage_id(base)
            if lineage_id and viewgov.GOVERNOR.due_for_delete_sweep(lineage_id):
                viewgov.delete_idle_folders(self.settings, base, lineage_id, self.engine)
        except Exception:  # noqa: BLE001
            pass

    def _structured(self, error: hydra.EngineError, call: dict) -> RuntimeError:
        """Map the engine's refusals that have a ready answer to a `next` call (4.11): the payload keeps everything the
        engine said and adds `next`, so the caller can act without reading prose."""
        payload = json.loads(str(error))
        reason = str(payload.get("reason") or error.details.get("reason") or "")
        payload["error"] = error.code
        if error.code == "busy":
            payload["reason"] = reason or "busy"
            payload.setdefault("retryAfterMs", error.retry_after_ms or 2000)
            payload.setdefault("next", {"tool": "ghidra_query", "after_ms": payload["retryAfterMs"], "arguments": call})
        elif error.code == "sealed":
            payload.setdefault("next", {"tool": "ghidra_query", "action": "status", "options": {"show": "lineage"}})
        elif error.code == "corrupt_newest":
            payload.setdefault("next", {"tool": "backend", "action": "doctor"})
        return RuntimeError(json.dumps(payload, ensure_ascii=False))

    def query(self, target: str, action: str = "decompile", address: str = "",
              limit: int = 40, cursor: str = "", contains: str = "", timeout_s: int = 30,
              options: dict | None = None) -> str:
        """One query. The view is `options.view` when named, else the caller's own: `options.as`, else the process default
        `<client name>@<boot id>`. A caller without a view reads the sealed master; its first edit creates the view."""
        call = {"target": target, "action": action, "address": address, "limit": limit, "cursor": cursor, "contains": contains,
                "timeout_s": timeout_s, **({"options": options} if options else {})}
        for attempt in (0, 1):
            try:
                return self._query(target, action, address, limit, cursor, contains, timeout_s, options)
            except DeferDecompile as deferred:
                if self.inline:
                    raise
                from hydralysis import decompile_job
                return json.dumps(decompile_job.start(self.settings, call, deferred.reason), ensure_ascii=False)
            except hydra.EngineError as error:
                if (attempt == 0 and error.code == "busy" and str(error.details.get("reason")) == "capacity"
                        and viewgov.GOVERNOR.evict_lru(self._release)):
                    continue  # the engine refused a view for capacity: an idle one of ours was closed, so try once more
                if error.code in ("busy", "sealed", "corrupt_newest"):
                    raise self._structured(error, call) from error
                raise
            except viewgov.Capacity as error:
                raise RuntimeError(json.dumps({"error": "busy", "reason": "capacity", "message": str(error),
                                               "retryAfterMs": error.retry_after_ms,
                                               "next": {"tool": "ghidra_query", "after_ms": error.retry_after_ms,
                                                        "arguments": call}})) from error
        raise RuntimeError("unreachable")

    def _query(self, target: str, action: str, address: str, limit: int, cursor: str, contains: str, timeout_s: int,
               options: dict | None) -> str:
        if action not in ACTIONS:
            raise ValueError("unknown saved-analysis query action; use backend help")
        if options is not None and not isinstance(options, dict):
            raise ValueError("options must be an object")
        options = dict(options or {})
        explicit = options.pop("view", "")
        scope, follow = options.pop("scope", ""), options.pop("follow", "")
        if scope not in ("", "master", "view"):
            raise ValueError("options.scope must be 'master' (the sealed master) or 'view' (the caller's view, the default)")
        if follow not in ("", "head"):
            raise ValueError("options.follow must be 'head'")
        who = views.identify(options)
        base = self.target(target)
        self._housekeeping(base)
        selected, mode = self._route(base, who, explicit, scope, action)
        guarded = views.ViewError
        if mode == "master":
            ctx = {"selected": selected, "mode": mode, "who": who, "trace": {}}
            return self._announce(self._run(target, selected, ctx, action, address, limit, cursor, contains, timeout_s, options,
                                            follow), base, who)
        try:
            if action == "type_edit" and options.get("kind") not in _NO_NEW_RECORDS:
                selected = self._register(target, selected, who, mode)
            else:
                self._touch(selected, who, mode)
        except guarded as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        viewgov.arm_session_end(self.settings)   # the process's exit closes the views it used (9.17: no orphaned copies)
        with viewgov.GOVERNOR.hold(selected, self.settings, self._release) as pin:
            ctx = {"selected": selected, "mode": mode, "who": who, "pin": pin, "trace": {},
                   # A read that cannot move the view may hand its store to the reply frame: one load per call, not three.
                   "store_fresh": action != "type_edit" and follow != "head"}
            try:
                pin.update(len(workcopy.pending_of(self._store(ctx))))
            except (ValueError, OSError):
                pass
            try:
                response = self._run(target, selected, ctx, action, address, limit, cursor, contains, timeout_s, options, follow)
            finally:
                try:  # the keep-warm rule counts the records the view holds now, edits included
                    if action == "type_edit":
                        ctx["store"] = None   # the run may have changed (or rebased) the store: read it again
                    pin.update(len(workcopy.pending_of(self._store(ctx))))
                except (ValueError, OSError, RuntimeError):
                    pass
        return self._announce(response, base, who)

    def _store(self, ctx: dict) -> dict:
        """The view's store, loaded once for this call (the frame and the pending count share it)."""
        store = ctx.get("store")
        if store is None:
            store = ctx["store"] = workcopy.load_store(self.settings, ctx["selected"])
        return store

    def _auto_rebase(self, selected: dict, expect, timeout_s: int) -> tuple[dict | None, int | None]:
        """A view that is behind the head and holds records is rebased first, clean-only (4.10): when a record would conflict
        nothing changes, and the edit that follows is refused with `stale_view` naming the editors. Returns the rebase result
        and the revision the caller's edit should now name."""
        store = workcopy.load_store(self.settings, selected)
        if not workcopy.stale_reason(store, selected):
            return None, expect
        try:
            result = views.rebase(self.settings, self.engine, selected, {"kind": "rebase", "expect_revision": store["revision"]},
                                  timeout_s)
        except (views.ViewError, RuntimeError):
            return None, expect
        if not result.get("ok") or not result.get("rebased"):
            return None, expect
        # The caller read the revision before the rebase and nothing else has moved the view: its edit follows the rebase.
        return result, (result["revision"] if expect == store["revision"] else expect)

    def _run(self, target: str, selected: dict, ctx: dict, action: str, address: str, limit: int, cursor: str, contains: str,
             timeout_s: int, options: dict, follow: str) -> str:
        view, mode = selected["view"], ctx["mode"]
        if action == "type_edit" and options.get("kind") in ("commit", "commit_revert", "commit_abort"):
            return self._commit(target, options, selected, timeout_s)
        if action == "type_edit" and options.get("kind") in ("publish", "merge", "rebase"):
            return self._views(target, options, selected, timeout_s)
        if action == "status" and options.get("show") == "views":
            return json.dumps(_public(views.views_status(self.settings, selected, self._lineage_id(selected), ctx["who"])),
                              ensure_ascii=False)
        if action == "status" and options.get("show") in ("queue", "publish"):
            return json.dumps(_public(self.queue(selected, options.get("csid"))), ensure_ascii=False)
        if action == "status" and options.get("show") == "lineage":
            return json.dumps(_public({"target": {key: selected[key] for key in ("name", "program", "sha256", "view")},
                                       **lineage.status(self.settings, selected)}), ensure_ascii=False)
        supplied_options = options
        options = validate_options(action, supplied_options)
        # Batch/corpus normalization constructs a new dict; retain the already
        # validated revision for the eventual write, including durable jobs.
        if action == "type_edit" and "expect_revision" in supplied_options:
            options["expect_revision"] = supplied_options["expect_revision"]
        if not 1 <= limit <= 200 or not 1 <= timeout_s <= 300:
            raise ValueError("limit must be 1..200; timeout_s must be 1..300")
        requires_address = action in ADDRESS_ACTIONS
        requires_address |= action == "type_edit" and options.get("kind") not in ("struct", "batch", "revert", "import_types", "import_archive")
        if requires_address and not address:
            raise ValueError("address is required (a VA such as 0x140001000, or rva:0x1000)")
        if action == "type" and not (address or options.get("path")):
            raise ValueError("type requires options.path or a typed-data address")
        if address and not _ADDRESS.fullmatch(address):
            raise ValueError("use a numeric VA or an rva:/va: prefix, not a symbol name")
        if cursor and not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", cursor):
            raise ValueError("use a numeric VA or hexadecimal row cursor, not a symbol name")
        if mode != "master" and action != "stop":
            if workcopy.heal(self.settings, selected):  # settle a commit that died between its CURRENT.log line and its store write
                ctx["store"] = None   # the heal wrote the store: the copy read above the run is old
            workcopy.close_superseded_readers(self.settings, selected)  # 9.17: a copy another process retired, still read here
            if follow == "head" and action != "type_edit":
                followed = self._auto_rebase(selected, None, timeout_s)[0]
                if followed:
                    ctx["store"] = None   # the rebase rewrote the store (revision, base)
                ctx["followed"] = bool(followed) or not workcopy.stale_reason(workcopy.load_store(self.settings, selected), selected)
        if action == "type_edit":
            # Every mutation, on the shared view and on named views, names the revision it read.
            workcopy.require_revision(self.settings, selected, options.get("expect_revision"), "type_edit")
        if action == "status":
            ctx["store_fresh"] = True   # after any follow=rebase: the copy used for the reply is the current one
            return json.dumps(_public(self._stamp(self.status(selected, options, limit, ctx, store=self._store(ctx)), ctx)),
                              ensure_ascii=False)
        if action == "stop":
            # As for a named view: the caller's own view is released and the master stays open for the others; a caller with
            # no view of its own releases the master (and the shared view's copy), which is all it uses.
            released = self.stop({**selected, "view": "shared"} if mode == "master" else selected)
            viewgov.GOVERNOR.forget(selected["key"])
            return json.dumps(released)
        if action == "type_edit" and options.get("kind") == "revert":
            return json.dumps(self._stamp({**workcopy.revert(self.settings, selected, options["ids"], options.get("expect_revision"),
                                                             bool(options.get("cascade", False))), "view": view}, ctx))
        if action == "diff":
            from hydralysis import overlayjobs
            self.target(options["against"])
            return json.dumps(overlayjobs.start(self.settings, selected["name"], "diff", "", options, view=view), ensure_ascii=False)
        if action == "type_edit" and options.get("kind") in BULK_KINDS:
            from hydralysis import overlayjobs
            job = overlayjobs.start(self.settings, selected["name"], "edit", address, options, view=view)
            # The job applies the edit later, under the revision it was started with; report the revision seen now.
            return json.dumps(self._stamp({**job, "view_revision": workcopy.load_store(self.settings, selected)["revision"]}, ctx),
                              ensure_ascii=False)
        if action == "type_edit":
            if address.startswith(("rva:", "va:")):
                # Overlay records hold plain VAs, so replay never depends on how an edit was typed.
                image = open_program(self.engine, selected["gpr"], selected["program"], selected["sha256"])["image_base"]
                value = int(address.split(":", 1)[1].removeprefix("0x"), 16)
                address = hex(int(image, 16) + value if address.startswith("rva:") else value)
            rebased, options["expect_revision"] = self._auto_rebase(selected, options.get("expect_revision"), timeout_s)
            edited = workcopy.edit(self.settings, self.engine, selected, address, options, timeout_s)
            if rebased:
                edited["auto_rebased"] = {key: rebased.get(key) for key in ("outcome", "from_generation", "to_generation", "kept",
                                                                             "dropped_in_master")}
            return json.dumps(_public(self._stamp({**edited, "view": view}, ctx)), ensure_ascii=False)
        request = {"id": uuid.uuid4().hex, "action": action, "address": address, "limit": limit, "cursor": cursor,
                   "contains": contains, "timeout_s": timeout_s, "options": options, "expected_sha256": selected["sha256"]}
        started = time.monotonic()
        response = self._ask(selected, request, timeout_s, ctx["trace"])
        response.update(target=selected["name"], view=view, query_s=round(time.monotonic() - started, 3))
        response = accepted(action, response)
        if ctx.get("followed") is False:
            response["follow"] = {"followed": False, "reason": "the view holds records the head would conflict with; rebase it"}
        return json.dumps(_public(self._stamp(response, ctx)), ensure_ascii=False)

    def _commit(self, target: str, options: dict, selected: dict, timeout_s: int) -> str:
        """`type_edit kind=commit|commit_revert|commit_abort`: a commit is a job; a dry run and a revert answer at once."""
        from hydralysis import commits, locks, overlayjobs
        view = selected["view"]
        try:
            clean = commits.validate(options)
            if clean["kind"] == "commit_revert":
                return json.dumps({**commits.revert(self.settings, selected, clean, self.engine), "view": view})
            if clean["kind"] == "commit_abort":
                return json.dumps({**commits.request_abort(self.settings, selected, clean["cid"]), "view": view})
            if clean.get("dry_run"):
                return json.dumps({**commits.run_commit(self.settings, selected, clean, self.engine, timeout_s), "view": view})
            # Everything that can be refused before a worker is started is refused here: it creates nothing.
            commits.preconditions(self.settings, selected, clean, self.engine)
            commits._plan_confirmation(clean)
            link = selected.get("lineage")
            if link and locks.held(str(lineage.commit_lock_path(self.settings, link["id"]))):
                raise commits.CommitError("commit_busy", "another commit holds this lineage's commit lock; retry when it finishes",
                                          retryAfterMs=5000)
            clean["cid"] = clean.get("cid") or commits.new_cid()
            job = overlayjobs.start(self.settings, selected["name"], "commit", "", clean, view=view)
        except commits.CommitError as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        except lineage.LineageError as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        return json.dumps({**job, "cid": clean["cid"], "view": view, "view_revision": workcopy.load_store(self.settings, selected)["revision"]},
                          ensure_ascii=False)

    def _views(self, target: str, options: dict, selected: dict, timeout_s: int) -> str:
        """`type_edit kind=rebase|merge|publish` (4.7, 4.8, 4.10). Rebase and the merge of a view into another answer at once;
        a publish to the master seals a changeset and answers with a job and its position in the queue."""
        from hydralysis import commits, views
        view = selected["view"]
        sealed = None
        try:
            clean = views.validate(options)
            if clean["kind"] == "rebase":
                return json.dumps(_public(views.rebase(self.settings, self.engine, selected, clean, timeout_s)), ensure_ascii=False)
            if clean["kind"] == "merge" or clean.get("to"):
                other = workcopy.with_view(self.target(target), clean["from"] if clean["kind"] == "merge" else clean["to"])
                source, destination = (other, selected) if clean["kind"] == "merge" else (selected, other)
                return json.dumps(_public(views.merge(self.settings, self.engine, source, destination, clean, timeout_s)), ensure_ascii=False)
            sealed = views.seal_changeset(self.settings, selected, clean)
            if sealed.get("state") == "done":  # the same records were decided while this call was being made
                return json.dumps({**sealed, "view": view}, ensure_ascii=False)
            job = views.start_job(self.settings, selected["name"], {"csid": sealed["csid"], "lineage": sealed["lineage"]}, view=view)
        except (views.ViewError, commits.CommitError) as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        except lineage.LineageError as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        except LockBusy as error:
            # The changeset was sealed but its worker could not be started (the overlay-jobs lock was held). It stays
            # pending and the next publish (from any view) leads the queue; name it so the caller can retry at once.
            payload = error.payload()
            if sealed is not None:
                payload.update(csid=sealed.get("csid"), sealed=True,
                               next={"tool": "ghidra_query", "action": "type_edit",
                                     "options": {"kind": "publish", "confirm_one_way_upgrade": True,
                                                 "expect_revision": workcopy.load_store(self.settings, selected)["revision"]}})
            raise RuntimeError(json.dumps(payload)) from error
        return json.dumps({**job, "csid": sealed["csid"], "reused": sealed["reused"], "view": view,
                           "publish_pending": {key: sealed.get(key) for key in ("state", "csid", "position", "etaMs", "leader")},
                           "position": sealed.get("position"), "etaMs": sealed.get("etaMs"),
                           "view_revision": workcopy.load_store(self.settings, selected)["revision"]}, ensure_ascii=False)

    def queue(self, selected: dict, csid: str | None = None) -> dict:
        """`status show=queue`: the publish queue of the target's lineage."""
        from hydralysis import views
        link = selected.get("lineage")
        if not link:
            return {"target": {key: selected[key] for key in ("name", "view")}, "lineage": None,
                    "queue": {"length": 0, "leader": False, "changesets": []},
                    "note": "no publish has been made on this target; there is no queue"}
        if csid:
            views.wait_decision(self.settings, link["id"], csid)   # a still-queued changeset: answer when it is decided, or in 0.5 s
        return {"target": {key: selected[key] for key in ("name", "view")}, **views.queue_status(self.settings, link["id"], csid)}

    def _scripted(self, engine, program: dict, request: dict, timeout_s: int, **extra) -> tuple[dict, dict]:
        """The RusticQuery answer, with the engine's decompile where the script cannot answer (see `engine_decompile`)."""
        decompile = request.get("action") == "decompile"
        try:
            response, raw = run_script(engine, program, request, timeout_s, self.requests, **extra)
        except hydra.EngineError as error:
            if not decompile or error.code in ("no_program", "not_found", "no_project", "closed", "busy", "sealed", "corrupt_newest"):
                raise
            failure = error
        except RuntimeError as error:
            if not decompile:
                raise
            failure = error
        else:
            return engine_decompile(engine, program, request, timeout_s, response, self.inline), raw
        stub = {"ok": False, "error": str(failure)[:2000]}
        answer = engine_decompile(engine, program, request, timeout_s, stub, self.inline)
        if answer is stub:
            raise failure
        return answer, {}

    def _static(self, selected: dict, request: dict, expected_state) -> dict | None:
        """The answer of the static read plane (`staticplane`, no engine) or None, and then the engine answers.

        Only with `HYDRALYSIS_IMPL=rust` and the native module, only for a read that no overlay touches, and only for
        what the plane answers exactly; any refusal of the plane (an unsupported database, a changing file, a question
        it does not answer) is None, never a partial or guessed reply."""
        if expected_state is not None or os.environ.get("HYDRALYSIS_TEST_FAULT"):
            return None
        if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() != "rust":
            return None
        gpr = selected["gpr"] if selected.get("master_read") else workcopy.read_gpr(self.settings, selected)
        reply, seconds = staticplane.timed(gpr, selected["program"], request)
        if reply is None:
            return None
        reply["engine"] = {"program": None, "mode": "static", "script_s": round(seconds, 6)}
        return reply

    def _ask(self, selected: dict, request: dict, timeout_s: int, trace: dict | None = None) -> dict:
        expected_state = None if selected.get("master_read") else workcopy.expected_state(self.settings, selected)
        static = self._static(selected, request, expected_state)
        if static is not None:
            return static
        for attempt in (0, 1):
            pool = self._pool()
            reader = self.engine if pool is not None else self.reader(selected)
            with _holding():   # the programs this read opens are closed last for the view cap while it runs
                if pool is None:
                    program = self.program_for(selected, engine=reader)
                try:
                    if pool is None:
                        response, raw = self._scripted(reader, program, request, timeout_s,
                                                       deadline_s=self._native_deadline(timeout_s))
                    else:
                        # One attempt, one entry: the opens and the script run on it with one clock (7.6). A retry takes another.
                        with pool.attempt(self._deadline(timeout_s)) as entry:
                            program = self.program_for(selected, engine=entry)
                            response, raw = self._scripted(entry, program, request, timeout_s)
                except hydra.EngineError as error:
                    if attempt == 0 and error.code in ("no_program", "not_found", "no_project", "closed"):
                        if pool is not None and error.code == "closed":
                            pool.invalidate()   # the daemon went away: the idle entries are as dead as the one that failed
                        if pool is None and error.code != "closed":
                            # One program is gone (the LRU close of the view cap closed it, or its project was closed): only its
                            # rows go. Forgetting every row would hide programs the connection still has open from that LRU close,
                            # and the cap (maxViewsPerClient) would then refuse every open with nothing left to close.
                            _drop_program(reader, program["key"])
                        else:
                            forget(reader)   # the entry that failed was retired by the pool and its rows dropped with it
                        continue
                    raise
            state = response.get("overlay_state") or ""
            if expected_state is not None and state != expected_state:
                if attempt == 0:
                    # The working copy does not hold the store's state (a daemon restart lost
                    # unsaved changes, or another process is mid-edit): replay from the store.
                    stored = workcopy.load_store(self.settings, selected)
                    if workcopy.heavy(stored):
                        workcopy.rebuilding(self.settings, selected)
                    if trace is not None:
                        trace["replayed"] = len(workcopy.pending_of(stored))
                    workcopy.repair(self.settings, self.engine, selected)
                    # The copies the repair replaced were closed by it (`workcopy.discard_forks`); the rows of the view's copies
                    # are dropped so the next open reads the repaired one afresh. The connection's other rows stay: they are
                    # programs it still has open, and the LRU close of the view cap must still see them.
                    for holder in readers(self.engine):
                        _drop_rows_under(holder, workcopy.view_folders(self.settings, selected))
                    continue
                raise RuntimeError("working copy answers with overlay state %r, expected %r; refused rather than "
                                   "answer from the wrong overlay version" % (state, expected_state))
            response["engine"] = {"program": program["key"], "mode": raw.get("mode"), "script_s": raw.get("seconds")}
            if expected_state is not None:
                response["overlays"] = json.loads(expected_state) if expected_state else None
            return response
        raise RuntimeError("program could not be reopened")

    def status(self, selected: dict, options: dict | None = None, limit: int = 40, ctx: dict | None = None,
               store: dict | None = None) -> dict:
        """STORE is the copy this call already loaded (the reply frame and the summary share it)."""
        options = options or {}
        master = selected.get("master_read")
        target = {key: selected[key] for key in ("name", "program", "sha256", "view")}
        if options.get("show") == "changes":
            # What changed in this view: its records with their subject record (effects) and commit state.
            if master:
                return {"target": target, "view_revision": 0, "since": options.get("since", 0), "state": options.get("state", "all"),
                        "changes": [], "truncated": False, "archived_commits": 0,
                        "note": "this agent has no view yet: it reads the sealed master, which has no unpublished records"}
            return {"target": target, **workcopy.changes(self.settings, selected, options.get("since", 0), options.get("state", "all"), limit)}
        hello = self.engine.hello()
        info = {key: hello.get(key) for key in ("protocol", "hydraVersion", "ghidraVersion", "installId", "pid", "startedAt")}
        who = (ctx or {}).get("who") or {}
        session = {"boot_id": views.BOOT_ID, "agent": who.get("agent"), "agent_kind": who.get("kind"), "agent_name": views.agent_name()}
        if master:
            overlays = {"revision": 0, "view_revision": 0, "edits": 0, "pending": 0, "committed": 0, "latest_editor": None,
                        "reverted": 0, "working_copy": None, "working_state": None, "in_sync": True, "last_sync": None, "recent": []}
            return {"engine": info, "target": {**{key: selected[key] for key in ("name", "gpr", "program", "sha256")}, "view": "master"},
                    "view_revision": 0, "overlays": overlays, "identity": hydra.identity(), "session": session,
                    "note": "this agent has no view yet; it reads the sealed master and its first edit creates its view "
                            "(expect_revision 0)"}
        overlays = workcopy.summary(self.settings, selected, store=store)
        return {"engine": info, "target": {key: selected[key] for key in ("name", "gpr", "program", "sha256", "view")},
                "view_revision": overlays["view_revision"], "overlays": overlays, "identity": hydra.identity(), "session": session}

    def stop(self, selected: dict) -> dict:
        """Release this process's use of the target's programs; the shared daemon keeps serving others."""
        released = []
        failed = []
        master = str(Path(selected["gpr"])).lower()
        working = workcopy._directory(self.settings, selected).resolve()
        # Every generation of the lineage is released too (the head, the older ones the target resolved to, the shared bases).
        roots = [working, workcopy.bases_root(self.settings, selected).resolve()]
        if selected.get("lineage"):
            roots.append(lineage.lineage_dir(self.settings, selected["lineage"]["id"]).resolve())
        adopted = str(Path(selected.get("adopted_gpr") or selected["gpr"])).lower()

        pool = self._pool()
        # Read the pool's entries before taking `_keys_guard`: the pool takes its own lock first and then (through
        # `on_retire`) the row guard, so the other order would be a lock-order inversion.
        owned = pool.owned_keys() if pool is not None else set()
        holders = {holder.key: holder for holder in readers(self.engine)}

        def belongs(key):
            if (key[0] not in holders and key[0] not in owned) \
                    or key[2].lstrip("/") != selected["program"].lstrip("/"):
                return False
            if key[1] in (master, adopted) and selected.get("view", "shared") == "shared":
                return True
            return any(Path(key[1]).resolve().is_relative_to(root) for root in roots)

        with _keys_guard:
            entries = [(key, value) for key, value in _keys.items() if belongs(key)]
        # Several cache entries can refer to one daemon program, on the shared connection and on pool entries.
        groups = {}
        for key, value in entries:
            groups.setdefault(value["key"], []).append((key, value))
        if pool is not None:
            pool.registry.drain(hydra.DEADLINE_GRACE_S)   # the gate for the target's programs, at most the grace
        closed = deferred = 0
        for program, group in groups.items():
            by_connection = {}
            for key, value in group:
                by_connection.setdefault(key[0], []).append((key, value))
            done = False
            for connection, rows in by_connection.items():
                holder = holders.get(connection) or (pool.entry_for(connection) if pool is not None else None)
                try:
                    if holder is None:
                        deferred += 1   # a checked-out or retired entry closes it on its return or through the gate
                    elif connection in holders:
                        holder.call("close_program", program=program)
                        closed += 1
                        done = True
                    elif holder.close_program(program):
                        closed += 1
                        done = True
                    else:
                        deferred += 1
                        continue
                except hydra.EngineError as exc:
                    failed.append({"program": program, "entry": "shared" if holder is self.engine else connection, "error": str(exc)})
                    continue
                with _keys_guard:
                    for key, value in rows:
                        if _keys.get(key) is value:
                            _keys.pop(key, None)
            if done:
                released.append(program)
        # The view's working copies: a reader's close only leaves them, and the edits a sync left there unsaved would stay in
        # the daemon as an orphan for ever. They are closed with discard (the records are in the store; the next use replays).
        discarded = []
        if workcopy.view_exists(self.settings, selected) or workcopy._forks_on_disk(self.settings, selected):
            try:
                discarded = workcopy.release(self.engine, self.settings, selected)
            except (RuntimeError, hydra.EngineError) as exc:
                failed.append({"view": selected.get("view", "shared"), "error": str(exc)[:300]})
        result = {"ok": not failed, "released": released, "failed": failed, "discarded": discarded,
                  "note": "the shared engine keeps warm programs for keepWarm seconds"}
        if pool is not None:
            result["entries"] = {"closed": closed, "deferred": deferred}
        return result
