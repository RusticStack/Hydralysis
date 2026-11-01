"""Hydralysis's analysis engine: Hydra Engine's headless session daemon.

Hydralysis calls Hydra; it contains no Ghidra code. One daemon serves every
Hydralysis process that shares a data root (its own state dir and instance, so it
never collides with another tool's daemon). Projects open in place: a read-only
view takes no lock and writes nothing, so no snapshot copy is needed.

The release is pinned. The engine and its Python client come from the same
release, are verified against the release's SHA256SUMS at install, and a daemon
that speaks another protocol, or needs a newer client, is refused by name.
"""

from __future__ import annotations

import contextlib
import hashlib
import itertools
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

from hydralysis import cancel, compat, durable
from hydralysis.paths import root_path

RELEASE = "12.3-hydra.5"
PROTOCOL = 3
# The oldest engine protocol this client still speaks: a protocol-3 client library connects to a released protocol-2
# engine (hydra.2, hydra.3) and negotiates down; the features of 3 are used only when hello advertises them (7.5).
PROTOCOL_MIN = 2
CLIENT_VERSION = "1.1.0"
# The daemon instance id and the client attribution prefix are deliberately still
# "rusticre" for this release (0.5.0.dev0). A running daemon is found and locked by its
# instance id, and its state directory, log and job-owner records carry that name.
# Renaming it now would start a second daemon beside the one a RusticRE install left
# running and orphan its locks and attributed jobs. Change it only together with a
# documented stop-and-restart.
INSTANCE = "rusticre"
ATTRIBUTION = "rusticre"
_BASE = "https://github.com/RusticStack/hydra-engine/releases/download/v" + RELEASE + "/"
# PENDING PUBLICATION: the release v12.3-hydra.4 is not tagged yet. The sizes and digests below were taken from a hand-built
# stand-in dist (engine 338,530 bytes, not the real archive), so `backend install` cannot succeed until the coordinator
# publishes the release and re-runs `tools/bump_hydra.py --release 12.3-hydra.4 --dist <published files> --write`.
# Until then the next line (the one `bump_hydra.py` rewrites) is NOT true: the digests and sizes are those of the stand-in
# dist, not a published SHA256SUMS, and nothing was checked after a download.
# SHA256SUMS of the release, observed 2026-11-01 and checked after download.
ASSETS = {
    "engine": {"url": _BASE + "hydra-engine-" + RELEASE + "-win_x86_64.zip",
               "sha256": "7f9d0a097b22f1dad5666968541e079529fdd171e1c7152ce07da3696161cb1e", "size": 381563431},
    "client": {"url": _BASE + "hydra-client-" + RELEASE + ".zip",
               "sha256": "b4b9580f9e5884377fdc2f3271479c0d0c7e81ca84fa68bf903a04ffc99b7fbe", "size": 51807},
}
SESSION_MODULE = Path("Ghidra", "Features", "HeadlessSession")


LIST_CAP = 5
# What an error never shortens: `next` is a ready request (a capped args list would be a different request)
# and `retryAfterMs` is a number. `queue` is the engine's own queue structure: it is not cut to LIST_CAP (the
# position and the waiting clients are what a caller needs to judge how long to wait), but it is not unbounded
# either, because that it is "small by construction" was never verified against a real engine: its lists keep
# at most QUEUE_CAP entries and `more` says how many were left out (key `queue.waiting`, like any capped list).
UNCAPPED = frozenset({"next", "retryAfterMs"})
QUEUE_CAP = 64

# Commands that may be sent again after the connection ended with no reply: they only read, or
# they open/close what a new connection opens/closes to the same end. Everything else is not
# retried, because the engine may have applied it before the reply was lost (spec 4.3): save,
# import, fork_project, edit, rename, comment, analyze, discard_edits, promote_overlay, cancel
# (a request id means something only on the connection that sent it) and shutdown.
IDEMPOTENT_COMMANDS = frozenset({
    "ping", "hello", "health", "status", "projects", "programs", "overlays", "journal",
    "open_project", "open_program", "switch", "close_project", "close_program", "refresh", "reopen",
    "project", "list", "info", "functions", "decompile"})
# Retry policy judgement (N4/N5): close_project, refresh, switch and reopen stay retryable. They converge on
# the same end state however many times they run, so a lost reply cannot be made worse by a resend, and the
# one harm is a retry that answers not_found/unknown project after the first close landed, which the caller
# reads as "already closed" (workcopy passes discard=True). Calling them ambiguous would fail syncs that the
# next attempt would have completed. A mutation that does NOT converge (save, fork, edit, import) is never here.
#
# Idle connection probe: a socket that went stale while idle (a daemon restart) is only found when the
# first call is sent. For a call that may mutate, that would be reported as ambiguous although nothing was
# sent. After STALE_S of idleness a `ping` (a read, answered inline by the engine) goes first.
STALE_S = 30.0

# RusticQuery actions that do not change the program, even when the call runs as the owner.
# apply_overlays and type_edit (a dry run only while contained) are deliberately absent.
READ_ACTIONS = frozenset({
    "overlay_state", "decompile", "function", "functions", "xrefs", "types", "type", "data", "scan",
    "variables", "dossier", "blocks", "pcode", "trace", "vcalls", "vtables", "writes", "orphans", "fingerprints"})


def _script_action(fields: dict) -> str | None:
    """The RusticQuery action a `script` call carries, or None when it is not one."""
    if fields.get("script") != "RusticQuery.java":
        return None
    args = fields.get("args") or ()
    try:
        body = str(args[0])
        if body.startswith("@"):
            body = Path(body[1:]).read_text(encoding="utf-8")
        action = json.loads(body).get("action")
    except (IndexError, OSError, ValueError, AttributeError):
        return None
    return action if isinstance(action, str) else None


def idempotent(command: str, fields: dict | None = None) -> bool:
    """Whether sending COMMAND again after a lost reply cannot do harm. Unknown means no."""
    if command == "script":
        return _script_action(fields or {}) in READ_ACTIONS
    return command in IDEMPOTENT_COMMANDS


def _capped(value, name: str, more: dict, cap: int = LIST_CAP):
    """Lists in an error stay short: `cap` entries (five by default), and `more` says how many were left out."""
    if isinstance(value, list):
        if len(value) > cap:
            more[name] = len(value) - cap
        return [_capped(item, name, more, cap) for item in value[:cap]]
    if isinstance(value, dict):
        return {key: _capped(item, name + "." + key if name else key, more, cap) for key, item in value.items()}
    return value


class EngineError(RuntimeError):
    """An ok:false answer from the engine. str() is JSON an agent can act on.

    Lists in the payload are capped at LIST_CAP entries plus a `more` map, except the UNCAPPED keys
    (`next`, `retryAfterMs`): a ready request must reach the caller exactly as the engine sent it. The lists
    of `queue` are capped at QUEUE_CAP (64) entries, with the count left out in `more["queue.waiting"]` (or
    `queue.<key>`), so a pathological engine reply cannot reach the caller unbounded. `self.queue` keeps the
    structure as the engine sent it; only the JSON text in str() is bounded.

    Beside `code` and `details` it carries what a v3 engine adds to an error: `retry_after_ms`
    (`error.retryAfterMs`, a sibling of `details`, present on `busy`), `next` (a ready request),
    `queue` (`details.queue`), and from `details` the `holderInfo`, `heldMs` and `current` that
    say who holds what. `ambiguous` (in `details`) means the connection ended while the call was
    in flight and the engine may have applied it: read the state back before sending it again.
    """

    def __init__(self, code: str, message: str, details: dict | None = None, command: str = "",
                 retry_after_ms: int | None = None, next: dict | None = None, queue: dict | None = None):
        self.code = code
        self.message = message
        self.command = command
        self.details = details or {}
        self.retry_after_ms = retry_after_ms
        self.next = next
        self.queue = queue if queue is not None else self.details.get("queue")
        self.holder_info = self.details.get("holderInfo")
        held = self.details.get("heldMs")
        if held is None and isinstance(self.holder_info, dict):
            held = self.holder_info.get("heldMs")
        self.held_ms = held
        payload = {"engine_error": code, "message": message, "command": command}
        if "output" in self.details and code == "failed":
            # A script that failed to compile says why only in its output.
            payload["output_tail"] = str(self.details["output"])[-2000:]
        for key in ("holder", "holderInfo", "suggest", "suggestion", "alternatives", "reason", "program", "project",
                    "current", "running", "ambiguous"):
            if key in self.details:
                payload[key] = self.details[key]
        if self.held_ms is not None:
            payload["heldMs"] = self.held_ms
        if self.queue is not None:
            payload["queue"] = self.queue
        if retry_after_ms is not None:
            payload["retryAfterMs"] = retry_after_ms
        if next is not None:
            payload["next"] = next
        more: dict = {}
        payload = {key: item if key in UNCAPPED else _capped(item, key, more, QUEUE_CAP if key == "queue" else LIST_CAP)
                   for key, item in payload.items()}
        if more:
            payload["more"] = more
        super().__init__(json.dumps(payload, ensure_ascii=False))

    @property
    def ambiguous(self) -> bool:
        return bool(self.details.get("ambiguous"))


def engine_release(directory: Path) -> str | None:
    """The Hydra release an engine install was built as, from its own jar."""
    jar = directory / SESSION_MODULE / "lib" / "HeadlessSession.jar"
    if not jar.is_file():
        return None
    try:
        import zipfile   # lazy: zipfile pulls in bz2, lzma and zstd, which a query never needs
        with zipfile.ZipFile(jar) as archive:
            text = archive.read("hydra.properties").decode("utf-8", "replace")
    except (KeyError, OSError, zipfile.BadZipFile):
        return None
    match = re.search(r"^hydra\.version=(\S+)", text, re.M)
    return match.group(1) if match else None


def _properties(path: Path) -> dict:
    result = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                result[key.strip()] = value.strip()
    return result


def inspect_engine(directory: str | Path, allow_unpinned: bool = False) -> dict:
    path = Path(directory).expanduser().resolve()
    application = _properties(path / "Ghidra" / "application.properties")
    report = {"component": "analysis", "path": str(path), "ready": False}
    if not application.get("application.version"):
        return {**report, "reason": "not a Ghidra/Hydra install (no Ghidra/application.properties)"}
    release = engine_release(path)
    report.update(ghidra_version=application["application.version"], hydra_release=release,
                  java_min=int(application.get("application.java.min") or 21),
                  java_max=int(application["application.java.max"]) if application.get("application.java.max") else None)
    if release is None:
        return {**report, "reason": "a stock Ghidra without Hydra's HeadlessSession module; Hydralysis drives Hydra Engine "
                                    "%s (backend install); a stock Ghidra is never used" % RELEASE}
    if release != RELEASE and not allow_unpinned:
        return {**report, "reason": "Hydra Engine %s; this Hydralysis pins %s (set hydra_allow_unpinned to try it)" % (release, RELEASE)}
    native = path / "Ghidra" / "Features" / "Decompiler" / "os"
    if not any(native.glob("*/decompile*")):
        return {**report, "reason": "native decompiler missing under %s" % native}
    return {**report, "ready": True, "pinned": release == RELEASE}


# (path as given, allow_unpinned) -> (mtime_ns, size, module): the stamps of a file that has not changed are not read again.
_CLIENTS: dict[tuple, tuple] = {}


def load_client(path: str | Path, allow_unpinned: bool = False):
    """Import the release's ghidra_session.py from its install, after checking its stamps."""
    memo = (str(path), bool(allow_unpinned))
    try:
        found = os.stat(path)
    except OSError:
        found = None
    known = _CLIENTS.get(memo)
    if found is not None and known is not None and known[:2] == (found.st_mtime_ns, found.st_size):
        return known[2]
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError("Hydra client missing: %s; run backend install" % path)
    text = path.read_text(encoding="utf-8", errors="replace")
    stamps = {name: (re.search(r'^%s\s*=\s*"?([^"\n]+)"?' % name, text, re.M) or [None, None])[1]
              for name in ("PROTOCOL", "CLIENT_VERSION", "HYDRA_RELEASE")}
    wanted = range(PROTOCOL_MIN, PROTOCOL + 1) if allow_unpinned else (PROTOCOL,)
    if not (stamps["PROTOCOL"] or "").isdigit() or int(stamps["PROTOCOL"]) not in wanted:
        raise ValueError("Hydra client %s speaks protocol %s; Hydralysis needs %s" % (
            path, stamps["PROTOCOL"], PROTOCOL if not allow_unpinned else "%d to %d" % (PROTOCOL_MIN, PROTOCOL)))
    if not allow_unpinned and (stamps["HYDRA_RELEASE"] != RELEASE or stamps["CLIENT_VERSION"] != CLIENT_VERSION):
        raise ValueError("Hydra client %s is release %s / client %s; this Hydralysis pins %s / %s"
                         % (path, stamps["HYDRA_RELEASE"], stamps["CLIENT_VERSION"], RELEASE, CLIENT_VERSION))
    name = "rusticre_hydra_client_" + hashlib.sha256(str(path).encode()).hexdigest()[:12]
    module = sys.modules.get(name)
    if module is None:
        import importlib.util   # lazy: only loading the engine client needs it
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    if found is not None:
        _CLIENTS[memo] = (found.st_mtime_ns, found.st_size, module)
    return module


def state_dir(settings: dict) -> Path:
    return root_path(settings) / "hydra" / "state"


def script_dirs(settings: dict) -> list[Path]:
    base = root_path(settings) / "hydra"
    return [base / "scripts", base / "user-scripts"]


def sync_scripts(settings: dict) -> Path:
    """Hydra only loads Java scripts from its scriptPath; Hydralysis's live under its root."""
    target = script_dirs(settings)[0]
    target.mkdir(parents=True, exist_ok=True)
    script_dirs(settings)[1].mkdir(parents=True, exist_ok=True)
    for source in Path(__file__).with_name("scripts").glob("*.java"):
        destination = target / source.name
        data = source.read_bytes()
        if not destination.is_file() or destination.read_bytes() != data:
            temporary = destination.with_name(destination.name + ".tmp")
            temporary.write_bytes(data)
            temporary.replace(destination)
    return target


def daemon_config(settings: dict) -> dict:
    root = root_path(settings)
    config = {"scriptPath": [str(path) for path in script_dirs(settings)],
              "tmpdir": str(root / "hydra" / "tmp"),
              "idleTimeout": int(settings.get("hydra_idle_s", 7200)),
              "keepWarm": int(settings.get("hydra_keep_warm_s", 3600))}
    if settings.get("java_home"):
        config["java"] = str(settings["java_home"])
    # Ghidra's per-user settings and caches (the OSGi script bundles among them) belong to this
    # root: two daemons sharing them collide, and they stay off the system drive.
    config["vmargs"] = ["-Dapplication.settingsdir=" + str(root / "hydra" / "ghidra-settings"),
                        "-Dapplication.cachedir=" + str(root / "hydra" / "ghidra-cache")]
    if settings.get("hydra_max_heap"):
        config["maxHeap"] = str(settings["hydra_max_heap"])
    # The lane caps of the daemon this client launches (PROTOCOL-3.md D54): sized from the number of agents the owner
    # expects to work at once, so that a seventh client's quick call is not queued behind six long scripts. An
    # explicit `hydra` setting wins; a daemon that is already running keeps the caps it started with.
    agents = expected_agents(settings)
    config["maxLong"] = max(8, -(-agents * 3 // 2))
    config["maxQuick"] = max(16, agents * 2)
    for key in ("maxImports", "maxQuick", "maxLong", "forkCopyLimitMb"):
        if key in (settings.get("hydra") or {}):
            config[key] = settings["hydra"][key]
    return config


DEFAULT_EXPECTED_AGENTS = 16


def expected_agents(settings: dict) -> int:
    """How many agents are expected at once (`expected_agents`, 1..256, default 16)."""
    value = settings.get("expected_agents", DEFAULT_EXPECTED_AGENTS)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 256:
        raise ValueError("expected_agents must be an integer 1..256")
    return value


def write_daemon_config(settings: dict) -> Path:
    state = state_dir(settings)
    state.mkdir(parents=True, exist_ok=True)
    (root_path(settings) / "hydra" / "tmp").mkdir(parents=True, exist_ok=True)
    path = state / "config.json"
    wanted = daemon_config(settings)
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        current = None
    if current != wanted:
        # Durable (fsync, write-through replace) but NOT sealed: the engine's launcher reads this file and must
        # see the plain JSON object it expects, so it carries no `seal` key and no `.bak` is kept (PROTOCOL-3.md 8.2).
        durable.atomic_write(path, json.dumps(wanted, indent=2).encode("utf-8"))
    return path


_IDENTITY = {"client": "%s:%d" % (ATTRIBUTION, os.getpid()), "harness": compat.env("HARNESS") or "cli"}


def set_harness(name: str) -> None:
    """The MCP client's name (initialize.clientInfo) labels every engine request."""
    if name and isinstance(name, str):
        _IDENTITY["harness"] = re.sub(r"[^A-Za-z0-9._ -]", "-", name)[:64]


def identity() -> dict:
    return dict(_IDENTITY)


class Engine:
    """One connection per process, root and role, shared by every thread.

    A `lane` gives a caller its own connection of that role (PROTOCOL-3.md 4.10, BP20): a working-copy sync
    uses one writer connection per view, so one sync's `reset` closes only the connection it opened, never the
    projects another thread's sync is using.
    """

    _connections: dict[str, object] = {}
    _used: dict[str, float] = {}  # connection key -> time.monotonic() when it last carried a call
    _guard = threading.Lock()
    # One connect at a time per key (the first may start the daemon). `_guard` is never held across a connect, so a thread
    # whose connection is up does not wait for a daemon start, and neither does a connect to another root's daemon.
    _connecting: dict[str, threading.Lock] = {}
    # `sync_scripts` and `write_daemon_config` write fixed paths: connects of different keys take turns at them.
    _preparing = threading.Lock()
    # state folder -> the lock of this process's connects that may start its daemon. The library's start lock orders starts
    # between processes; on POSIX it is a record lock (fcntl) that a second thread of the same process also gets.
    _starting: dict[str, threading.Lock] = {}

    def __init__(self, settings: dict, role: str = "reader", start: bool = True, lane: str = ""):
        # Reads use one long-lived connection and run contained (in parallel, rolled back).
        # A writer gets its own connection: a client that may write a program runs its
        # scripts as owner, exclusively, which reads must not do.
        self.settings = settings
        self.root = root_path(settings)
        self.engine_dir = Path(settings["hydra_dir"])
        self.client_path = Path(settings["hydra_client"])
        self.allow_unpinned = bool(settings.get("hydra_allow_unpinned"))
        self.role = role
        # A helper that must not launch a daemon passes start=False: it joins a running one or fails.
        self.start = start
        self.lane = lane
        self.key = (str(self.root).lower() if os.name == "nt" else str(self.root)) + "|" + role + ("|" + lane if lane else "")

    def module(self):
        return load_client(self.client_path, self.allow_unpinned)

    def _connect(self):
        module = self.module()
        with self._preparing:
            sync_scripts(self.settings)
            write_daemon_config(self.settings)
        state = str(state_dir(self.settings))
        with self._guard:
            starting = self._starting.setdefault(state, threading.Lock()) if self.start else contextlib.nullcontext()
        try:
            with starting:
                session = module.connect(client=_IDENTITY["client"], harness=_IDENTITY["harness"],
                                         ghidra=str(self.engine_dir), state=state, instance=INSTANCE, start=self.start)
        except module.IncompatibleError as exc:
            raise RuntimeError("Hydra engine refused: %s. Stop the old daemon (backend action=stop) or install the "
                               "pinned release %s" % (exc, RELEASE)) from exc
        except module.LaunchError as exc:
            raise RuntimeError("Hydra engine did not start: %s; log %s" % (exc, state_dir(self.settings) / (INSTANCE + ".log"))) from exc
        hello = getattr(session, "hello", {}) or {}
        if hello.get("hydraVersion") != RELEASE and not self.allow_unpinned:
            session.close()
            raise RuntimeError("the running Hydralysis daemon is Hydra %s, not the pinned %s; stop it (backend action=stop)"
                               % (hello.get("hydraVersion"), RELEASE))
        found = hello.get("protocol")
        if isinstance(found, int) and not PROTOCOL_MIN <= found <= PROTOCOL:
            session.close()
            raise RuntimeError("the running Hydralysis daemon speaks protocol %s; this Hydralysis speaks %d to %d"
                               % (found, PROTOCOL_MIN, PROTOCOL))
        return session

    def connect_entry(self):
        """A new connection for the pool (7.6): `connect` and the identity check, and not `sync_scripts` or `write_daemon_config`
        (they run once per process when the shared connection is made; a replacement must not fsync a config per abandon)."""
        module = self.module()
        try:
            session = module.connect(client=_IDENTITY["client"], harness=_IDENTITY["harness"], ghidra=str(self.engine_dir),
                                     state=str(state_dir(self.settings)), instance=INSTANCE, start=False)
        except (module.IncompatibleError, module.LaunchError) as exc:
            raise RuntimeError("Hydra engine refused a pool connection: %s" % exc) from exc
        hello = getattr(session, "hello", {}) or {}
        if hello.get("hydraVersion") != RELEASE and not self.allow_unpinned:
            session.close()
            raise RuntimeError("the running Hydralysis daemon is Hydra %s, not the pinned %s" % (hello.get("hydraVersion"), RELEASE))
        return session

    _pools: dict[str, "Pool"] = {}

    def pool(self) -> "Pool":
        """The entries of deadline-bound attempts for this root and role (one pool per process, 7.6)."""
        with self._guard:
            found = self._pools.get(self.key)
            if found is None:
                found = self._pools[self.key] = Pool(self, on_retire=_forget_rows)
                fresh = True
            else:
                fresh = False
        if fresh:
            supervise(self)
        return found

    def protocol(self) -> int:
        """The protocol this connection negotiated: what hello reports; an engine that reports nothing speaks 2."""
        found = self.hello().get("protocol")
        return found if isinstance(found, int) and not isinstance(found, bool) else PROTOCOL_MIN

    def deadline_mode(self) -> str:
        """"native" when the loaded client library times its own `wait` (library 1.1.0, P1b; the connection survives),
        else "helper" (the worker-thread abandon helper of 7.6 on hydra.2/3)."""
        return "native" if getattr(self.session(), "supports_deadline", False) else "helper"

    def supports(self, name: str) -> bool:
        return name in self.capabilities()

    def session(self):
        with self._guard:
            session = self._connections.get(self.key)
            if session is not None and not getattr(session, "_closed", False):
                return session
            gate = self._connecting.setdefault(self.key, threading.Lock())
        with gate:
            with self._guard:
                session = self._connections.get(self.key)
            if session is None or getattr(session, "_closed", False):
                session = self._connect()
                with self._guard:
                    self._connections[self.key] = session
            return session

    def connected(self) -> bool:
        """Whether this process holds a live connection of this key now (asking never connects, so it never starts a daemon)."""
        with self._guard:
            session = self._connections.get(self.key)
        return session is not None and not getattr(session, "_closed", False)

    def reset(self) -> None:
        """Drop the shared connection, and with it every pool entry of the role: a daemon restart (or a connection that
        died) takes the context of all of them (7.6, I2; 7.2 lists the restart as a retire event)."""
        with self._guard:
            session = self._connections.pop(self.key, None)
            self._used.pop(self.key, None)
            pool = self._pools.get(self.key)
        if pool is not None:
            pool.invalidate()
        if session is not None:
            try:
                session.close()
            except Exception:
                pass

    @staticmethod
    def _envelope(session, exc) -> dict:
        """The whole `error` object of the reply that raised EXC, as far as the library kept it.

        Library 1.0.0 puts only `code`, `message`, `details` and `trace` on SessionError and drops
        the v3 siblings (`retryAfterMs`, `next`). It does keep the whole reply on `last_response`,
        which another thread's reply may replace, so it counts only when it is this very error.
        """
        error = getattr(exc, "error", None)
        if isinstance(error, dict):
            return error
        reply = getattr(session, "last_response", None)
        error = reply.get("error") if isinstance(reply, dict) and reply.get("ok") is False else None
        if isinstance(error, dict) and error.get("code") == exc.code and error.get("message") == exc.message:
            return error
        return {}

    def _error(self, session, exc, command: str, ambiguous: bool = False) -> EngineError:
        envelope = self._envelope(session, exc)
        details = dict(exc.details or {})
        message = exc.message
        if ambiguous:
            details["ambiguous"] = True
            message = ("%s; the connection ended while %s was in flight, so the engine may or may not have applied it. "
                       "Read the state back before sending it again" % (message, command))
        retry = getattr(exc, "retry_after_ms", None)
        return EngineError(exc.code, message, details, command,
                           retry_after_ms=retry if retry is not None else envelope.get("retryAfterMs"),
                           next=getattr(exc, "next", None) or envelope.get("next"),
                           queue=getattr(exc, "queue", None))

    def _probe(self, session, module):
        """Ping a connection that was idle for STALE_S before a call that may mutate; reconnect if it is dead."""
        now = time.monotonic()
        with self._guard:
            idle = now - self._used.get(self.key, now)
            self._used[self.key] = now
        if idle < STALE_S:
            return session
        try:
            session.call("ping", client=_IDENTITY["client"], harness=_IDENTITY["harness"], parallel=True)
            return session
        except module.SessionError as exc:
            if exc.code != "closed":
                return session
        except OSError:
            pass
        self.reset()
        session = self.session()
        with self._guard:
            self._used[self.key] = time.monotonic()
        return session

    def call(self, command: str, raw: bool = False, **fields):
        """A labelled, parallel request. A read is sent again once if the daemon went away.

        A call that may have changed something is never sent again: its reply was lost, not its
        effect. It raises EngineError(code "closed", details.ambiguous true) and the caller
        reconciles (4.3): re-read the marker, check whether the fork appeared.
        """
        module = self.module()
        labels = {"client": _IDENTITY["client"], "harness": _IDENTITY["harness"], "parallel": True}
        if fields.get("deadline") is None:
            fields.pop("deadline", None)   # `deadline` reaches the library only when set (library 1.1.0)
        retry = idempotent(command, fields)
        for attempt in (0, 1):
            session = self.session()
            if not retry and attempt == 0:
                session = self._probe(session, module)
            else:
                with self._guard:
                    self._used[self.key] = time.monotonic()
            try:
                if raw:
                    return session.call_raw(command, **labels, **fields)
                return _cancellable_call(session, command, labels, fields)
            except module.SessionError as exc:
                if exc.code != "closed":
                    raise self._error(session, exc, command) from exc
                self.reset()
                if retry and attempt == 0:
                    continue
                raise self._error(session, exc, command, ambiguous=not retry) from exc
            except OSError as exc:
                self.reset()
                if retry and attempt == 0:
                    continue
                if retry:
                    raise
                raise EngineError("closed", "the connection to the engine failed while %s was in flight (%s), so the engine "
                                  "may or may not have applied it. Read the state back before sending it again" % (command, exc),
                                  {"ambiguous": True, "cause": type(exc).__name__}, command) from exc

    def send(self, command: str, **fields) -> int:
        """Start a long request without waiting (an import, an export script); see wait/cancel."""
        labels = {"client": _IDENTITY["client"], "harness": _IDENTITY["harness"], "parallel": True}
        return self.session().send(command, **labels, **fields)

    def wait(self, request_id: int, command: str = ""):
        module = self.module()
        session = self.session()
        try:
            return session.wait(request_id)
        except module.SessionError as exc:
            # send/wait is never retried; a lost connection leaves the outcome unknown unless it was a read.
            raise self._error(session, exc, command, ambiguous=exc.code == "closed" and not idempotent(command)) from exc

    def cancel(self, request_id: int) -> dict:
        return self.call("cancel", target=request_id)

    def on_event(self, callback) -> None:
        self.session().on_event = callback

    def hello(self) -> dict:
        info = dict(getattr(self.session(), "hello", {}) or {})
        info.pop("token", None)
        return info

    def capabilities(self) -> dict:
        """What the engine advertises in hello (name -> version), or {} when it advertises nothing.

        A protocol-2 engine (hydra.2, and hydra.3 as this client's library speaks to it) has no
        `capabilities`: that is the degraded mode of 7.5, not an error, so an older engine never
        makes this raise. A client uses a feature only if its name is here.
        """
        info = self.hello()
        found = info.get("capabilities")
        if not isinstance(found, dict) or (isinstance(info.get("protocol"), int) and info["protocol"] < 3):
            return {}
        return {str(name): value for name, value in found.items() if isinstance(value, int) and not isinstance(value, bool)}

    def stop(self, force: bool = False) -> dict:
        module = self.module()
        unsupervise(self)   # a stopped daemon is not restarted behind the caller's back
        with self._guard:
            pool = self._pools.pop(self.key, None)
        if pool is not None:
            pool.close_all(0.0)
        self.reset()
        daemon = module.Daemon(str(self.engine_dir), str(state_dir(self.settings)), INSTANCE)
        return {"stopped": daemon.stop(force=force)}


# ---- deadlines on hydra.2/3: the abandon helper, the pool of entries, the leave gate (PROTOCOL-3.md 7.6) ----------

DEADLINE_S = 60.0          # the deadline of one attempt (7.6), not of each call
CONNECT_FLOOR_S = 5.0      # the least time a new pool connection gets for its hello (Pool._connect_within)
DEADLINE_GRACE_S = 5.0     # after `cancel`, before the connection is abandoned
USER_CAP = 8               # abandoned user calls at a time (unmeasured policy, 7.6 step 5)
PROBE_CAP = 3              # abandoned supervisor probes: the number of consecutive misses that make a wedge (7.2)
CLOSING_CAP = 8            # the closing list of the leave gate (rule L3)
POOL_SIZE = 4              # live entries per role (the engine's per-client view budget); more MCP calls wait in acquire, cancellable
PATIENCE_S = 25.0          # the patience budget of a lock wait (7.6, Waits)
# An error after which the entry is retired and the retry takes another one (I3).
RETIRE_CODES = frozenset({"no_program", "no_project", "not_found", "closed"})
# Calls whose `wait` is bound below the attempt's deadline (N2): the two opens and the script.
WAITING_COMMANDS = frozenset({"open_project", "open_program", "script"})


def _cancellable_call(session, command: str, labels: dict, fields: dict, grace_s: float | None = None):
    """`session.call`, which is `wait(send(...))`, with the client's cancel of the MCP request wired in.

    Under a cancel token (hydralysis.cancel, set by the MCP server) the wait runs on a helper thread and this thread
    waits for the answer or the cancel. The token's callback only sets an event (it runs on the MCP stdin reader thread,
    which must never block on engine I/O). On a cancel this thread sends `cancel` for the request id the way the
    library's own deadline does (parallel, with the request's labels, its answer dropped), waits the grace for the
    engine to answer the request, and returns: with the engine's answer, or EngineError("cancelled") when the engine did
    not answer within the grace. The helper thread stays in `wait` and consumes the late answer, so nothing is left in
    the session's pending map. Without a token, or with a stand-in session that has no send/wait, it is `session.call`
    unchanged."""
    token = cancel.current()
    if token is None or not (hasattr(session, "send") and hasattr(session, "wait")):
        return session.call(command, **labels, **fields)
    if token.cancelled:
        raise EngineError("cancelled", "the client cancelled the request before %s was sent" % command, {}, command)
    fields = dict(fields)
    deadline = fields.pop("deadline", None)
    if deadline is not None and hasattr(session, "_check_deadline"):
        session._check_deadline(deadline)
    rid = session.send(command, **labels, **fields)
    box: dict = {}
    done, wake = threading.Event(), threading.Event()

    def work():
        try:
            box["value"] = session.wait(rid, deadline) if deadline is not None else session.wait(rid)
        except BaseException as exc:   # noqa: BLE001 - handed to the caller, or dropped when it has left
            box["error"] = exc
        finally:
            done.set()
            wake.set()

    threading.Thread(target=work, name="hydra-call-%s" % rid, daemon=True).start()
    remove = token.add(wake.set)
    try:
        while not done.is_set() and not token.cancelled:
            wake.wait(1.0)
            wake.clear()   # both conditions are checked again at the top, so a wake set before this clear is not lost
    finally:
        remove()
    if not done.is_set():
        _send_cancel(session, rid, labels)
        if not done.wait(DEADLINE_GRACE_S if grace_s is None else grace_s):
            raise EngineError("cancelled", "the client cancelled %s; cancel sent, the engine did not answer within the "
                              "grace; its late answer is read and dropped" % command,
                              {"target": rid, "command": command}, command)
    if "error" in box:
        raise box["error"]
    return box["value"]


def _send_cancel(session, rid: int, labels: dict) -> None:
    """`cancel target=RID` as the library's deadline sends it: parallel (a plain cancel would queue behind the request it
    is meant to end on a connection that keeps order), with the request's labels (cancel is scoped by them), and with
    its own answer marked abandoned, so it never stays in the session's pending map."""
    fields = {"target": rid, "parallel": True}
    for name in ("client", "harness"):
        if labels.get(name) is not None:
            fields[name] = labels[name]
    try:
        send_request = getattr(session, "_send_request", None)
        if callable(send_request):
            send_request("cancel", fields, abandon=True)
        else:
            session.send("cancel", **fields)
    except Exception:   # noqa: BLE001 - the connection is gone: the wait reports what happened to the request
        pass


class DeadlineError(EngineError):
    """`deadline_exceeded` and `abandoned_cap`: errors of the client-side deadline, not of the engine."""


def _forget_rows(entry) -> None:
    """The pool's `on_retire` in production: the retired entry's rows of `query._keys` go with it (I2). `query` imports this
    module, so it is imported here, when an entry retires."""
    from hydralysis import query
    query.forget(entry)


def _forget_role_rows(engine) -> None:
    from hydralysis import query
    query.forget_role(engine)


def supports(engine, name: str) -> bool:
    """Whether the engine advertises capability NAME. A stand-in without `capabilities` supports nothing."""
    found = getattr(engine, "capabilities", None)
    if not callable(found):
        return False
    try:
        return name in found()
    except Exception:
        return False


def patience_ms(engine, default_ms: int) -> int:
    """The wait a read sends: DEFAULT_MS (the old 180 s budget), or the 25 s patience budget once the engine reports queue information."""
    return min(default_ms, int(PATIENCE_S * 1000)) if supports(engine, "queueInfo") else default_ms


class Registry:
    """The process-wide state of abandoned requests, reads in flight and the closing list (7.6, step 5, rules L2 and L3).

    Two budgets: at most USER_CAP abandoned user calls and PROBE_CAP abandoned probes; a probe is exempt from the user
    budget. `reads` counts the scripts in flight (answered or not by the engine) per daemon program key; the leave gate
    closes an entry that joined a program only when no read is in flight on any program it joined.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.abandoned: dict[int, dict] = {}
        self.reads: dict[str, int] = {}
        self.closing: list = []
        self.closed: list[str] = []   # entry keys closed by the gate, in order (diagnostics and tests)
        self._ids = 0

    def abandon(self, entry, command: str, program: str | None) -> int:
        with self.lock:
            self._ids += 1
            self.abandoned[self._ids] = {"id": self._ids, "kind": entry.kind, "cmd": command, "program": program,
                                         "label": "%s/%s" % (_IDENTITY["client"], _IDENTITY["harness"]),
                                         "entry": entry.key, "since": time.monotonic()}
            return self._ids

    def answered(self, token: int) -> None:
        with self.lock:
            self.abandoned.pop(token, None)

    def count(self, kind: str) -> int:
        with self.lock:
            return sum(1 for item in self.abandoned.values() if item["kind"] == kind)

    def check_cap(self, kind: str) -> None:
        """Fail fast, before anything is sent, when the budget of KIND is full."""
        cap = PROBE_CAP if kind == "probe" else USER_CAP
        with self.lock:
            if self.count(kind) < cap:
                return
            listing = [{"cmd": item["cmd"], "label": item["label"], "program": item["program"],
                        "ageS": round(time.monotonic() - item["since"], 1)}
                       for item in self.abandoned.values() if item["kind"] == kind]
        raise DeadlineError("abandoned_cap", "%d requests that ignore cancel are still running on the engine; "
                            "no further call is sent until some end" % cap, {"cap": cap, "abandoned": listing},
                            next={"cmd": "doctor"})

    # --- the leave gate ------------------------------------------------------------------------------------------

    def read_begin(self, program: str | None) -> None:
        if program:
            with self.lock:
                self.reads[program] = self.reads.get(program, 0) + 1

    def read_end(self, program: str | None) -> None:
        if not program:
            return
        with self.lock:
            left = self.reads.get(program, 0) - 1
            if left > 0:
                self.reads[program] = left
            else:
                self.reads.pop(program, None)
            ready = [entry for entry in self.closing if not self._busy(entry)]
            for entry in ready:
                self.closing.remove(entry)
        for entry in ready:
            self._close(entry)

    def _busy(self, entry) -> bool:
        return any(self.reads.get(program) for program in entry.joined)

    def leave(self, entry) -> str:
        """Close ENTRY when this process has no read in flight on a program it joined; otherwise queue it.

        Returns "dropped" (its connection had failed: nothing to leave), "closed" or "deferred". A ninth entry in the
        list closes the oldest regardless (L3)."""
        if entry.broken:
            entry.close_now()   # its connection failed: no request is in flight and it holds no lock; free the socket
            return "dropped"
        with self.lock:
            if entry.joined and self._busy(entry):
                self.closing.append(entry)
                oldest = self.closing.pop(0) if len(self.closing) > CLOSING_CAP else None
                state = "deferred"
            else:
                oldest, state = entry, "closed"
        if oldest is not None:
            self._close(oldest)
        return state

    def _close(self, entry) -> None:
        with self.lock:
            self.closed.append(entry.key)
        entry.close_now()

    def drain(self, grace_s: float) -> None:
        """Wait for the gate (at most GRACE_S), then close everything still waiting: `stop` and the exit of the process."""
        end = time.monotonic() + grace_s
        while time.monotonic() < end:
            with self.lock:
                if not self.closing:
                    return
            time.sleep(0.02)
        with self.lock:
            left, self.closing = self.closing, []
        for entry in left:
            self._close(entry)

    def snapshot(self) -> dict:
        """What the doctor lists: both budgets, the reads in flight, the closing list."""
        with self.lock:
            now = time.monotonic()
            items = [{**{k: v for k, v in item.items() if k != "since"}, "ageS": round(now - item["since"], 1)}
                     for item in self.abandoned.values()]
            return {"abandoned": {"user": self.count("user"), "probe": self.count("probe"), "userCap": USER_CAP,
                                  "probeCap": PROBE_CAP, "items": items},
                    "reads": dict(self.reads), "closing": [entry.key for entry in self.closing]}


REGISTRY = Registry()
_SERIALS = itertools.count(1)   # never reused in the process (I1)


class Entry:
    """A connection plus the context it holds: the unit of the pool (7.6). One attempt owns it; one request is ever in flight."""

    def __init__(self, engine, session, kind: str = "user", registry: Registry | None = None, on_retire=None):
        self.engine = engine
        self.session = session
        self.kind = kind
        self.registry = registry or REGISTRY
        self.serial = next(_SERIALS)
        self.key = "%s|%d" % (engine.key, self.serial)   # "<root>|<role>|<serial>": the rows of `_keys` it owns start with it
        self.joined: set[str] = set()                    # daemon program keys this entry opened
        self.abandoned = False
        self.broken = False
        self.finished = False                            # closed or dropped
        self.on_retire = on_retire
        self.deadline_at = 0.0
        self.grace_s = DEADLINE_GRACE_S
        self._guard = threading.Lock()
        self._inflight = False
        self._ended = False
        self._retired = False
        self._token = None
        self.pending_close: set[str] = set()
        self.generation = 0

    def begin(self, deadline_s: float) -> "Entry":
        """Start the attempt's clock (when the entry is acquired)."""
        self.deadline_at = time.monotonic() + deadline_s
        return self

    def remaining(self) -> float:
        return self.deadline_at - time.monotonic()

    @staticmethod
    def _program_of(command: str, fields: dict) -> str | None:
        if command == "script":
            return fields.get("program")
        if command == "open_program" and fields.get("project") and fields.get("path"):
            return "%s:%s" % (fields["project"], fields["path"])
        return None

    def call(self, command: str, raw: bool = False, **fields):
        """One engine call of the attempt, in a worker thread the caller never enters (steps 2 to 5)."""
        labels = {"client": _IDENTITY["client"], "harness": _IDENTITY["harness"], "parallel": True}
        with self._guard:
            if self.abandoned or self.broken or self.finished:
                raise RuntimeError("entry %s is retired; it is never used again" % self.key)
            if self._inflight:
                raise RuntimeError("entry %s has a request in flight; one request at a time (7.6 step 1)" % self.key)
            self.registry.check_cap(self.kind)
            remaining = self.remaining()
            if remaining <= 0:
                raise DeadlineError("deadline_exceeded", "the deadline of the attempt passed before %s was sent" % command,
                                    {"connection_abandoned": False}, command)
            self._inflight = True
            self._ended = False
        if command in WAITING_COMMANDS and "wait" in fields:
            fields["wait"] = max(1, int(min(PATIENCE_S, remaining / 2) * 1000))
        reading = command == "script"
        program = self._program_of(command, fields)
        if reading:
            self.registry.read_begin(program)
        box: dict = {}
        done = threading.Event()
        # `wake` ends the caller's wait: the answer (`done`), or the client's cancel of the MCP request (cancel.current()),
        # which is handled like a deadline that came early: `cancel` is sent to the engine, then the grace, then abandon.
        wake = threading.Event()
        module = self.engine.module()
        token = cancel.current()

        def work():
            try:
                rid = self.session.send(command, **labels, **fields)
                box["rid"] = rid
                if token is not None and token.cancelled:
                    wake.set()   # cancelled before the request id was known: the caller can send `cancel` now
                box["value"] = self.session.wait(rid)
            except BaseException as exc:   # noqa: BLE001 - handed to the caller, or dropped when it has left
                box["error"] = exc
            self._worker_done(command, reading, program, box, done)
            wake.set()

        threading.Thread(target=work, name="hydra-deadline-" + self.key, daemon=True).start()
        remove = token.add(wake.set) if token is not None else (lambda: None)
        try:
            end = time.monotonic() + max(0.0, remaining)
            while not done.is_set():
                if token is not None and token.cancelled and box.get("rid") is not None:
                    break
                left = end - time.monotonic()
                if left <= 0:
                    break
                wake.wait(left)
                wake.clear()   # the condition is checked again at the top, so a wake set before this clear is not lost
        finally:
            remove()
        if not done.is_set():
            cancelled = token is not None and token.cancelled
            rid = box.get("rid")
            if rid is not None:
                try:
                    self.session.send("cancel", target=rid)   # thread-safe; the only thing sent (rule L1)
                except Exception:
                    pass
            if not done.wait(self.grace_s):
                with self._guard:
                    abandon = not self._ended
                    if abandon:
                        self.abandoned = True
                        self._token = self.registry.abandon(self, command, program)
                if abandon:
                    # Nothing more is sent: no shutdown, no close(), no FIN. The worker closes the session itself,
                    # through the gate, when the engine answers.
                    if cancelled:
                        raise EngineError("cancelled", "the client cancelled %s; cancel sent, the engine did not stop within "
                                          "the grace, the connection is abandoned" % command,
                                          {"connection_abandoned": True, "command": command}, command)
                    raise DeadlineError("deadline_exceeded", "no answer to %s within the deadline; cancel sent, the connection "
                                        "is abandoned" % command, {"connection_abandoned": True, "command": command}, command)
                done.wait()
        return self._outcome(box, module, command)

    def _worker_done(self, command: str, reading: bool, program, box: dict, done: threading.Event) -> None:
        value = box.get("value")
        error = box.get("error")
        if command == "open_program" and isinstance(value, dict) and value.get("key"):
            self.joined.add(str(value["key"]))
        if error is not None and (isinstance(error, OSError) or getattr(error, "code", None) == "closed"):
            self.broken = True
        if reading:
            self.registry.read_end(program)
        with self._guard:
            self._inflight = False
            self._ended = True
            was_abandoned = self.abandoned
        done.set()
        if was_abandoned:
            self._after_answer()

    def _after_answer(self) -> None:
        """The abandoned request ended: the count drops, the rows leave `_keys`, the session goes to the leave gate (step 5)."""
        with self._guard:
            if self._retired:
                return
            self._retired = True
        if self._token is not None:
            self.registry.answered(self._token)
        if self.on_retire is not None:
            self.on_retire(self)
        self.registry.leave(self)

    def _outcome(self, box: dict, module, command: str):
        error = box.get("error")
        if error is None:
            return box["value"]
        if isinstance(error, module.SessionError):
            raise self.engine._error(self.session, error, command) from error
        if isinstance(error, OSError):
            raise EngineError("closed", "the connection to the engine failed while %s was in flight (%s)" % (command, error),
                              {"cause": type(error).__name__}, command) from error
        raise error

    def capabilities(self) -> dict:
        return self.engine.capabilities()

    def module(self):
        return self.engine.module()

    def close_program(self, program: str, grace_s: float = DEADLINE_GRACE_S) -> bool:
        """Leave one program this idle entry joined (`QueryRunner.stop`). A close is a leave, so it passes the gate: while a
        read is in flight on the program it is only noted (`pending_close`, sent when the entry is returned): False."""
        if self.registry.reads.get(program):
            self.pending_close.add(program)
            return False
        self.begin(grace_s + 5.0)
        self.call("close_program", program=program)
        self.joined.discard(program)
        return True

    def close_now(self) -> None:
        self.finished = True
        try:
            self.session.close()
        except Exception:
            pass

    def retire(self) -> None:
        """Drop the entry from use: forget its rows (I2) and leave its programs through the gate (I3)."""
        with self._guard:
            if self._retired:
                return
            self._retired = True
        if self.on_retire is not None:
            self.on_retire(self)
        self.registry.leave(self)


class Pool:
    """At most POOL_SIZE live entries per engine role; an entry is created lazily by the next acquire (7.6, Pool size)."""

    def __init__(self, engine, size: int = POOL_SIZE, registry: Registry | None = None, on_retire=None):
        self.engine = engine
        self.size = size
        self.registry = registry or REGISTRY
        self.on_retire = on_retire
        self._cond = threading.Condition()
        self._idle: list[Entry] = []
        self._live: set[Entry] = set()
        self._probe: Entry | None = None
        self.generation = 0   # bumped by `invalidate`: an entry of an older generation is never reused

    def _new(self, kind: str = "user", deadline_s: float = DEADLINE_S) -> Entry:
        entry = Entry(self.engine, self._connect_within(deadline_s), kind, self.registry, self.on_retire)
        entry.generation = self.generation
        return entry

    def _connect_within(self, deadline_s: float):
        """`connect_entry` bounded by DEADLINE_S. Making a connection sends `hello` and waits for its answer, and the 1.0.0
        library (hydra.2/3) waits for it with no timeout: a suspended or wedged daemon still accepts the TCP connection
        (the backlog), so the wait never ended and a supervisor probe hung for good instead of counting a miss (gate 9.8,
        test_supervisor.RealPolicy on hydra.3). The connection is made in a worker thread; past the deadline the caller gets
        `deadline_exceeded` and a connection that arrives later is closed by that thread, never handed out. The bound is at
        least CONNECT_FLOOR_S: the attempt's own clock starts after the connection (`Entry.begin`), as before, and a short
        attempt deadline must not turn a slow but healthy hello under load into a failure."""
        deadline_s = max(deadline_s, CONNECT_FLOOR_S)
        lock = threading.Lock()
        state: dict = {}
        done = threading.Event()

        def work():
            try:
                session, error = self.engine.connect_entry(), None
            except BaseException as exc:   # noqa: BLE001 - handed to the caller, or dropped when it has left
                session, error = None, exc
            with lock:
                late = state.get("late", False)
                state.update(session=session, error=error)
                done.set()
            if late and session is not None:
                try:
                    session.close()
                except Exception:   # noqa: BLE001 - nobody waits for this connection any more
                    pass

        threading.Thread(target=work, name="hydra-connect-" + str(getattr(self.engine, "key", "")), daemon=True).start()
        done.wait(max(0.0, deadline_s))
        with lock:
            if not done.is_set():
                state["late"] = True
                raise DeadlineError("deadline_exceeded", "no answer to hello within %.1f s: the daemon accepts connections but does not "
                                    "answer (suspended or wedged); the late connection is closed when it arrives" % deadline_s,
                                    {"connection_abandoned": True, "command": "hello"}, "hello")
        if state["error"] is not None:
            raise state["error"]
        return state["session"]

    def invalidate(self) -> None:
        """The daemon restarted (or the connection died): retire every idle entry, mark the checked-out ones stale (they
        retire when returned) and drop every row of the role (`forget_role`). The pool makes new entries on demand."""
        with self._cond:
            self.generation += 1
            idle, self._idle = self._idle, []
            probe, self._probe = self._probe, None
            for entry in idle:
                self._live.discard(entry)
            self._cond.notify_all()
        for entry in idle:
            if not entry.abandoned:
                entry.broken = True
                entry.retire()
        if probe is not None:
            probe.broken = True   # a probe in flight is not closed under its request; the next probe opens a new connection
            if not probe._inflight and not probe.abandoned:
                probe.retire()
        if self.on_retire is not None:
            _forget_role_rows(self.engine)

    def live(self) -> int:
        with self._cond:
            return len(self._live)

    def owns(self, key: str) -> bool:
        """Whether KEY (a `_keys` row's first element) is a live entry of this pool."""
        with self._cond:
            return any(entry.key == key for entry in self._live)

    def entry_for(self, key: str) -> "Entry | None":
        """The idle entry named KEY, or None (a checked-out entry is never touched from outside its attempt)."""
        with self._cond:
            return next((entry for entry in self._idle if entry.key == key), None)

    def owned_keys(self) -> set:
        """The keys of the live entries, taken under `_cond` alone (a caller that holds another lock reads this first)."""
        with self._cond:
            return {entry.key for entry in self._live}

    def acquire(self, deadline_s: float = DEADLINE_S) -> Entry:
        end = time.monotonic() + deadline_s
        while True:
            dead: list[Entry] = []
            chosen: Entry | None = None
            with self._cond:
                while self._idle:
                    entry = self._idle.pop()
                    if getattr(entry.session, "_closed", False) and not entry.abandoned:
                        entry.broken = True   # the library closed it (the daemon went away): never handed out
                    if not (entry.abandoned or entry.broken or entry.finished) and entry.generation == self.generation:
                        chosen = entry.begin(deadline_s)
                        break
                    self._live.discard(entry)
                    if not entry.abandoned:
                        entry.broken = True
                        dead.append(entry)
                if chosen is None and not dead:
                    if len(self._live) < self.size:
                        chosen = self._new(deadline_s=deadline_s)
                        self._live.add(chosen)
                        chosen.begin(deadline_s)
                    else:
                        left = end - time.monotonic()
                        if left <= 0:
                            raise EngineError("busy", "all %d connections of this process are in use" % self.size,
                                              {"reason": "pool_full"}, retry_after_ms=2000)
                        token = cancel.current()
                        if token is not None and token.cancelled:
                            raise EngineError("cancelled", "the client cancelled the request while it waited for one of the "
                                              "%d connections of this process" % self.size, {"reason": "pool_full"})
                        remove = token.add(self._wake) if token is not None else None
                        try:
                            self._cond.wait(left)
                        finally:
                            if remove is not None:
                                remove()
                        continue
            # `retire` runs `on_retire` (which takes the query row guard) and the gate: never under `_cond` (lock order).
            try:
                for entry in dead:
                    entry.retire()
            except BaseException:
                if chosen is not None:
                    self.release(chosen)   # it was begun and counted live: give the slot back instead of holding it for good
                raise
            if chosen is not None:
                return chosen

    def _wake(self) -> None:
        """A cancel of a request that waits in `acquire`: wake the waiters, the cancelled one leaves."""
        with self._cond:
            self._cond.notify_all()

    def release(self, entry: Entry, error: BaseException | None = None) -> None:
        """Return ENTRY after an attempt: a healthy one goes back; an abandoned, broken or error-retired one does not."""
        stale = entry.generation != self.generation
        if stale and not entry.abandoned:
            entry.broken = True
        retire = entry.abandoned or entry.broken or (isinstance(error, EngineError) and error.code in RETIRE_CODES)
        if retire and not entry.abandoned:
            entry.retire()
        elif entry.pending_close and not retire:
            for program in sorted(entry.pending_close):
                try:
                    if entry.close_program(program):
                        entry.pending_close.discard(program)
                except EngineError:
                    entry.pending_close.discard(program)
        with self._cond:
            if retire:
                self._live.discard(entry)
            else:
                self._idle.append(entry)
            self._cond.notify()

    @contextlib.contextmanager
    def attempt(self, deadline_s: float = DEADLINE_S):
        entry = self.acquire(deadline_s)
        try:
            yield entry
        except BaseException as exc:
            self.release(entry, exc)
            raise
        else:
            self.release(entry)

    def probe(self, command: str = "ping", deadline_s: float = 5.0, **fields):
        """A supervisor probe on its own connection (no context, outside the pool); an expired one is abandoned (budget 3)."""
        with self._cond:
            entry = self._probe
            if entry is None or entry.abandoned or entry.broken or entry.finished:
                entry = self._probe = self._new("probe", deadline_s)
        entry.begin(deadline_s)
        entry.grace_s = min(DEADLINE_GRACE_S, deadline_s)
        return entry.call(command, **fields)

    def close_all(self, grace_s: float = DEADLINE_GRACE_S) -> None:
        """At exit: the gate waits at most the grace, then everything is closed."""
        self.registry.drain(grace_s)
        with self._cond:
            entries = list(self._idle) + ([self._probe] if self._probe else [])
            self._idle.clear()
            self._live.clear()
            self._probe = None
        for entry in entries:
            if not entry.finished and not entry.abandoned:
                self.registry._close(entry)


# ---- the supervisor (PROTOCOL-3.md 7.2, D55) ----------------------------------------------------------------------

PROBE_PERIOD_S = 5.0       # a probe every 5 s while the engine is in use
WEDGE_MISSES = 3           # consecutive probes that make a wedge
RESTART_BUDGET = 3         # restarts ...
RESTART_WINDOW_S = 600.0   # ... per 10 minutes, then `daemon_unhealthy`
EXIT_WAIT_S = 45.0         # the wait for the process object to exit (maximum seen 39 s under load)


def wedge_signal(health: dict | None, stall_ms: int = 30_000) -> str | None:
    """Why one probe counts as a miss, or None. NONE is `no answer to ping`; the others read the `health` reply."""
    if health is None:
        return "no_answer"
    if health.get("state") == "suspect":
        return "suspect"
    tick = health.get("tick") or {}
    stall = health.get("watchdogStallMs", stall_ms)
    if isinstance(tick, dict) and isinstance(tick.get("ageMs"), (int, float)) and tick["ageMs"] > stall:
        return "tick_stalled"
    if health.get("schedulerLockOk") is False:
        return "scheduler_lock"
    return None


class Supervisor:
    """Probe, decide, restart within a budget, and record every event in `supervisor.json` through `durable`.

    Everything that touches the world is injected, so the policy is tested against a fake and the same code drives the
    real daemon (`for_engine`):

    * `probe()` returns the `health` reply (or the `ping` reply on an engine without `health`) and raises on no answer;
    * `pid_alive()` and `lock_free()` say whether the daemon process exists and whether its instance lock is free;
    * `status()` returns the engine `status` (programs with `unsavedEdits`, running jobs), kept at each probe;
    * `restart(force)` stops the daemon, waits for the process to exit and starts it again;
    * `recoverable(program)` says whether a program's edits are in the store or the intent log (`working/`, a commit candidate);
    * `durable_journal()` is `journal.durable` (D55); `publish_in_flight()` is true while a publish has no recorded intent;
    * `mark_lost(entries)` marks the in-flight Hydralysis jobs `lost_on_restart`.
    """

    def __init__(self, path, *, probe, pid_alive, lock_free, restart, status=lambda: {}, recoverable=lambda program: False,
                 durable_journal=lambda: False, publish_in_flight=lambda: False, mark_lost=lambda entries: None,
                 abandoned=lambda: {}, clock=time.monotonic, stall_ms: int = 30_000):
        self.path = Path(path)
        self.probe, self.pid_alive, self.lock_free, self.restart_daemon = probe, pid_alive, lock_free, restart
        self.status, self.recoverable, self.durable_journal = status, recoverable, durable_journal
        self.publish_in_flight, self.mark_lost, self.abandoned = publish_in_flight, mark_lost, abandoned
        self.clock = clock
        self.stall_ms = stall_ms
        self.misses = 0
        self.last_status: dict = {}
        self.restarts: list[float] = []
        self.unhealthy = False
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._guard = threading.Lock()

    # --- the record ------------------------------------------------------------------------------------------------

    def record(self, event: dict) -> dict:
        """Append EVENT to supervisor.json (sealed, under the cross-process lock)."""
        event = {"at": time.time(), **event}

        def add(current):
            events = list(current.get("events", []))[-199:] + [event]
            return {"events": events}

        durable.update_sealed(self.path, add, default={"events": []})
        return event

    def events(self) -> list[dict]:
        return list(durable.read_sealed(self.path, default={"events": []}).get("events", []))

    # --- what dies with a restart ----------------------------------------------------------------------------------

    def lost_on_restart(self) -> list[dict]:
        """Programs with non-recoverable unsaved edits and in-flight imports or exports, from the last `status`."""
        lost = []
        for program in self.last_status.get("programs") or []:
            edits = program.get("unsavedEdits") or 0
            name = program.get("key") or program.get("path") or program.get("program")
            if edits and not self.recoverable(name):
                lost.append({"program": name, "unsavedEdits": edits, "by": program.get("lastEditor") or program.get("by")})
        for job in self.last_status.get("jobs") or []:
            if job.get("kind") in ("import", "export") and job.get("state", "running") == "running":
                lost.append({"program": job.get("program") or job.get("id"), "unsavedEdits": 0, "by": job.get("kind")})
        return lost

    # --- one cycle -------------------------------------------------------------------------------------------------

    def tick(self, force: bool = False) -> dict:
        """One probe cycle. Returns the event it decided (also recorded when it is a restart decision)."""
        with self._guard:
            return self._tick(force)

    def _tick(self, force: bool) -> dict:
        if self.unhealthy:
            return {"event": "daemon_unhealthy"}   # the budget is spent: no further attempt, whatever the window says (7.2)
        alive = self.pid_alive()
        if not alive and self.lock_free():
            self.misses = 0
            return self._restart("dead", force, answers=False)
        if not alive:
            return {"event": "no_process"}
        answers, reply = True, None
        try:
            reply = self.probe()
        except Exception:   # an expired probe is abandoned by the helper; a miss is a miss
            answers = False
        signal = wedge_signal(reply if answers else None, self.stall_ms)
        if signal is None:
            self.misses = 0
            try:
                found = self.status()
                if isinstance(found, dict):
                    self.last_status = found
            except Exception:
                pass
            return {"event": "ok"}
        self.misses += 1
        if self.misses < WEDGE_MISSES:
            return {"event": "miss", "signal": signal, "misses": self.misses}
        return self._restart("wedged:" + signal, force, answers=answers)

    def _budget_left(self) -> int:
        now = self.clock()
        self.restarts = [moment for moment in self.restarts if now - moment < RESTART_WINDOW_S]
        return RESTART_BUDGET - len(self.restarts)

    def _restart(self, why: str, force: bool, answers: bool) -> dict:
        if not self.durable_journal():
            return self.record({"event": "restart_refused", "reason": "journal_not_durable", "why": why})
        if self.publish_in_flight():
            return self.record({"event": "restart_refused", "reason": "publish_in_flight", "why": why})
        if self._budget_left() <= 0:
            self.unhealthy = True
            return self.record({"event": "daemon_unhealthy", "why": why, "restarts": len(self.restarts),
                                "window_s": RESTART_WINDOW_S, "doctor": self.summary()})
        lost = [] if why == "dead" else self.lost_on_restart()
        if lost and answers and not force:
            # A daemon that is merely slow keeps running while a restart would lose work.
            return self.record({"event": "restart_refused", "reason": "unsaved_edits", "why": why, "lost_on_restart": lost})
        self.restarts.append(self.clock())
        if lost:
            self.mark_lost(lost)
        try:
            self.restart_daemon(force)
        except Exception as exc:   # noqa: BLE001 - recorded, never raised into the probe loop
            return self.record({"event": "restart_failed", "why": why, "error": "%s: %s" % (type(exc).__name__, exc),
                                "lost_on_restart": lost})
        self.misses = 0
        self.last_status = {}
        return self.record({"event": "restarted", "why": why, "lost_on_restart": lost})

    def reset_budget(self) -> None:
        """An operator's decision (after the doctor's report): forget the restarts and the verdict, and probe again."""
        with self._guard:
            self.restarts.clear()
            self.unhealthy = False
            self.misses = 0
        self.record({"event": "budget_reset"})

    def summary(self) -> dict:
        """The doctor summary: both abandoned budgets are reported as a finding of their own (7.2)."""
        return {"misses": self.misses, "restarts_in_window": len(self.restarts), "unhealthy": self.unhealthy,
                "abandoned": self.abandoned()}

    # --- the loop --------------------------------------------------------------------------------------------------

    def start(self, period_s: float = PROBE_PERIOD_S) -> None:
        if self._thread is not None:
            return

        def loop():
            while not self._stop.wait(period_s):
                try:
                    self.tick()
                except Exception:   # noqa: BLE001 - the loop never dies; the next tick looks again
                    continue

        self._thread = threading.Thread(target=loop, name="hydra-supervisor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    @classmethod
    def for_engine(cls, engine: "Engine", settings: dict, **overrides) -> "Supervisor":
        """A supervisor over the real daemon of ENGINE, fed by real sources:

        * `pid_alive`: the pid in the daemon's endpoint file exists as a process; `lock_free`: the instance lock
          (`<instance>.lock`, held by the JVM for its whole life) is free: two different facts, as 7.2 needs them;
        * `probe`: `health` (or `ping` on hydra.2/3) on the pool's own probe connection, with a deadline;
        * `status`: the engine `status`, kept for `lost_on_restart`; a program is recoverable when it lives under
          `working/` or `lineages/` of the root (the store or the intent log is its record);
        * `publish_in_flight` and `mark_lost`: the job records of the root (`overlay-jobs/*/job.json`): an active publish or
          commit job refuses the restart (stricter than 7.2, which allows it once an intent is recorded), and every active
          job of the root is marked `lost_on_restart` when the restart goes ahead;
        * `durable_journal`: `journal_durable` (see there)."""
        module = engine.module()
        daemon = module.Daemon(str(engine.engine_dir), str(state_dir(settings)), INSTANCE)
        root = root_path(settings)
        keep: set[str] = set()   # program keys found recoverable in the last `status`

        def pid_alive() -> bool:
            from hydralysis.preparation import process_start_ms
            found = (daemon.read_endpoint() or {}).get("pid")
            return isinstance(found, int) and not isinstance(found, bool) and process_start_ms(found) > 0

        def probe():
            if "health" in engine.capabilities():
                return engine.pool().probe("health", 5.0)
            engine.pool().probe("ping", 5.0)
            return {}

        def restart(force):
            engine.reset()
            daemon.kill()
            end = time.monotonic() + EXIT_WAIT_S
            while daemon.jvm_alive() and time.monotonic() < end:
                time.sleep(0.2)
            if daemon.jvm_alive():
                raise RuntimeError("the daemon process did not exit within %d s" % EXIT_WAIT_S)
            engine.session()

        def status():
            found = engine.call("status")
            places = [root / "working", root / "lineages"]
            keep.clear()
            for program in (found.get("programs") or []) if isinstance(found, dict) else []:
                name = program.get("key") or program.get("path") or program.get("program")
                texts = [value for value in program.values() if isinstance(value, str)]
                if name and any(_under(text, places) for text in texts):
                    keep.add(name)
            return found

        def publish_in_flight() -> bool:
            return any(job.get("kind") in ("publish", "commit") for job in active_jobs(settings))

        def mark_lost(entries):
            from hydralysis import overlayjobs
            for job in active_jobs(settings):
                overlayjobs._update(overlayjobs.job_path(settings, job["id"]), lost_on_restart=True,
                                    lost_on_restart_at=time.time(), lost_on_restart_programs=[item.get("program") for item in entries])

        found = dict(probe=probe, pid_alive=pid_alive, lock_free=lambda: not daemon.jvm_alive(), restart=restart, status=status,
                     recoverable=lambda program: program in keep, abandoned=REGISTRY.snapshot,
                     durable_journal=lambda: journal_durable(settings), publish_in_flight=publish_in_flight, mark_lost=mark_lost)
        found.update(overrides)
        return cls(state_dir(settings) / "supervisor.json", **found)


def _under(text: str, places: list[Path]) -> bool:
    try:
        path = Path(text).resolve()
    except (OSError, ValueError):
        return False
    return any(path.is_relative_to(place.resolve()) for place in places)


def active_jobs(settings: dict, limit: int = 50) -> list[dict]:
    """The Hydralysis jobs of the root that are queued, running or cancelling (the 50 newest records)."""
    from hydralysis import overlayjobs
    folder = root_path(settings) / "overlay-jobs"
    if not folder.is_dir():
        return []
    found = []
    paths = sorted(folder.glob("overlay-*/job.json"), key=lambda item: item.stat().st_mtime_ns, reverse=True)[:limit]
    for path in paths:
        try:
            record = overlayjobs.status(settings, path.parent.name)
        except Exception:   # noqa: BLE001 - a record that cannot be read is not an active job
            continue
        if record.get("state") in overlayjobs.ACTIVE:
            found.append(record)
    return found


_SUPERVISORS: dict[str, Supervisor] = {}


def _root_key(engine) -> str:
    return str(engine.root).lower() if os.name == "nt" else str(engine.root)


def supervise(engine, settings: dict | None = None) -> "Supervisor | None":
    """Start the supervisor of ENGINE's root, once per process (7.2: probes while the engine is in use). It is called when the
    first pool of a root is made, which is the first deadline-bound read of a long-lived process. Anything that keeps a
    supervisor from being built (a client without `Daemon`, `hydra_supervisor: false`) leaves the engine unsupervised and
    never fails the read. `Engine.stop` stops it."""
    settings = settings if settings is not None else getattr(engine, "settings", {})
    if settings.get("hydra_supervisor") is False or not isinstance(engine, Engine):
        return None
    key = _root_key(engine)
    with Engine._guard:
        found = _SUPERVISORS.get(key)
        if found is not None:
            return found
        try:
            found = _SUPERVISORS[key] = Supervisor.for_engine(engine, settings)
        except Exception:   # noqa: BLE001 - see above
            return None
    found.start()
    return found


def unsupervise(engine) -> None:
    if not isinstance(engine, Engine):
        return
    with Engine._guard:
        found = _SUPERVISORS.pop(_root_key(engine), None)
    if found is not None:
        found.stop()


def journal_durable(settings: dict) -> bool:
    """`journal.durable` (D55): the overlay store is version 3 (its edits are sealed and flushed before they are applied, 4.10
    W1 to W4) and a start-up self-test (write, read back) passes.

    The "kill the writer" step of D55 is the crash tests' (`durable.fault`) and is not done here: this checks that a record
    appended to a log under the state directory reads back exactly through the sealed, fsynced path the intent logs use,
    and that the store this Hydralysis writes is v3. It does not prove the write-ahead record against a killed writer."""
    path = state_dir(settings) / "journal-selftest.log"
    try:
        from hydralysis import workcopy
        if workcopy.STORE_VERSION < 3:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        log = durable.AppendLog(path)
        token = hashlib.sha256(os.urandom(16)).hexdigest()
        log.append({"selftest": token})
        last = log.last(strict=True)
        return bool(last and last.get("selftest") == token)
    except Exception:   # noqa: BLE001 - a journal that cannot prove itself is not durable
        return False


# ---- install ---------------------------------------------------------------------------------

def install(settings: dict, download, extract, cancelled=lambda: False) -> dict:
    """Download, verify and unpack the pinned engine and its client under root/backends."""
    import shutil   # lazy: shutil pulls in the archive modules, which a query never needs
    root = root_path(settings)
    backends = root / "backends"
    backends.mkdir(parents=True, exist_ok=True)
    engine = backends / ("hydra-" + RELEASE)
    client_dir = backends / ("hydra-client-" + RELEASE)
    if not engine.exists():
        archive = download(ASSETS["engine"], root / "downloads", cancelled)
        unpacked = extract(archive, backends / ("unpack-hydra-" + RELEASE), cancelled)
        unpacked.rename(engine)
        shutil.rmtree(backends / ("unpack-hydra-" + RELEASE), ignore_errors=True)
    if not (client_dir / "ghidra_session.py").is_file():
        archive = download(ASSETS["client"], root / "downloads", cancelled)
        unpacked = extract(archive, backends / ("unpack-hydra-client-" + RELEASE), cancelled)
        unpacked.rename(client_dir)
        shutil.rmtree(backends / ("unpack-hydra-client-" + RELEASE), ignore_errors=True)
    report = inspect_engine(engine)
    if not report["ready"]:
        raise ValueError("installed Hydra engine did not validate: %s" % report.get("reason"))
    load_client(client_dir / "ghidra_session.py")
    return {"hydra_dir": str(engine), "hydra_client": str(client_dir / "ghidra_session.py")}
