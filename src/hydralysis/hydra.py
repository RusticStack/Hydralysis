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

import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import threading
import time
import zipfile
from pathlib import Path

from hydralysis import compat
from hydralysis.paths import root_path

RELEASE = "12.3-hydra.2"
PROTOCOL = 2
CLIENT_VERSION = "1.0.0"
# The daemon instance id and the client attribution prefix are deliberately still
# "rusticre" for this release (0.5.0.dev0). A running daemon is found and locked by its
# instance id, and its state directory, log and job-owner records carry that name.
# Renaming it now would start a second daemon beside the one a RusticRE install left
# running and orphan its locks and attributed jobs. Change it only together with a
# documented stop-and-restart.
INSTANCE = "rusticre"
ATTRIBUTION = "rusticre"
_BASE = "https://github.com/RusticStack/hydra-engine/releases/download/v" + RELEASE + "/"
# SHA256SUMS of the release, observed 2026-10-26 and checked after download.
ASSETS = {
    "engine": {"url": _BASE + "hydra-engine-" + RELEASE + "-win_x86_64.zip",
               "sha256": "f5cc0d721d401660556e28af6c104ee75a23fdc62803a419789d799a00ee6218", "size": 378876631},
    "client": {"url": _BASE + "hydra-client-" + RELEASE + ".zip",
               "sha256": "f26e9ebc3d242d1f8ad4872acd2c5219addfc7a615c4e4334d7189c81792c773", "size": 22901},
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


def load_client(path: str | Path, allow_unpinned: bool = False):
    """Import the release's ghidra_session.py from its install, after checking its stamps."""
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError("Hydra client missing: %s; run backend install" % path)
    text = path.read_text(encoding="utf-8", errors="replace")
    stamps = {name: (re.search(r'^%s\s*=\s*"?([^"\n]+)"?' % name, text, re.M) or [None, None])[1]
              for name in ("PROTOCOL", "CLIENT_VERSION", "HYDRA_RELEASE")}
    if stamps["PROTOCOL"] != str(PROTOCOL):
        raise ValueError("Hydra client %s speaks protocol %s; Hydralysis needs %s" % (path, stamps["PROTOCOL"], PROTOCOL))
    if not allow_unpinned and (stamps["HYDRA_RELEASE"] != RELEASE or stamps["CLIENT_VERSION"] != CLIENT_VERSION):
        raise ValueError("Hydra client %s is release %s / client %s; this Hydralysis pins %s / %s"
                         % (path, stamps["HYDRA_RELEASE"], stamps["CLIENT_VERSION"], RELEASE, CLIENT_VERSION))
    name = "rusticre_hydra_client_" + hashlib.sha256(str(path).encode()).hexdigest()[:12]
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
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
    for key in ("maxImports", "maxQuick", "maxLong", "forkCopyLimitMb"):
        if key in (settings.get("hydra") or {}):
            config[key] = settings["hydra"][key]
    return config


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
        temporary = path.with_name("config.json.tmp")
        temporary.write_text(json.dumps(wanted, indent=2), encoding="utf-8")
        temporary.replace(path)
    return path


_IDENTITY = {"client": "%s:%d" % (ATTRIBUTION, os.getpid()), "harness": compat.env("HARNESS") or "cli"}


def set_harness(name: str) -> None:
    """The MCP client's name (initialize.clientInfo) labels every engine request."""
    if name and isinstance(name, str):
        _IDENTITY["harness"] = re.sub(r"[^A-Za-z0-9._ -]", "-", name)[:64]


def identity() -> dict:
    return dict(_IDENTITY)


class Engine:
    """One connection per process and root, shared by every thread."""

    _connections: dict[str, object] = {}
    _used: dict[str, float] = {}  # connection key -> time.monotonic() when it last carried a call
    _guard = threading.Lock()

    def __init__(self, settings: dict, role: str = "reader", start: bool = True):
        # Reads use one long-lived connection and run contained (in parallel, rolled back).
        # A writer gets its own connection: a client that may write a program runs its
        # scripts as owner, exclusively, which reads must not do.
        self.settings = settings
        self.root = root_path(settings)
        self.engine_dir = Path(settings["hydra_dir"])
        self.client_path = Path(settings["hydra_client"])
        self.allow_unpinned = bool(settings.get("hydra_allow_unpinned"))
        self.role = role
        # A background helper (the saver) joins a running daemon but never starts one.
        self.start = start
        self.key = (str(self.root).lower() if os.name == "nt" else str(self.root)) + "|" + role

    def module(self):
        return load_client(self.client_path, self.allow_unpinned)

    def _connect(self):
        module = self.module()
        sync_scripts(self.settings)
        write_daemon_config(self.settings)
        try:
            session = module.connect(client=_IDENTITY["client"], harness=_IDENTITY["harness"],
                                     ghidra=str(self.engine_dir), state=str(state_dir(self.settings)), instance=INSTANCE,
                                     start=self.start)
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
        return session

    def session(self):
        with self._guard:
            session = self._connections.get(self.key)
            if session is None or getattr(session, "_closed", False):
                session = self._connections[self.key] = self._connect()
            return session

    def reset(self) -> None:
        with self._guard:
            session = self._connections.pop(self.key, None)
            self._used.pop(self.key, None)
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
                return session.call(command, **labels, **fields)
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
        self.reset()
        daemon = module.Daemon(str(self.engine_dir), str(state_dir(self.settings)), INSTANCE)
        return {"stopped": daemon.stop(force=force)}


# ---- install ---------------------------------------------------------------------------------

def install(settings: dict, download, extract, cancelled=lambda: False) -> dict:
    """Download, verify and unpack the pinned engine and its client under root/backends."""
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
