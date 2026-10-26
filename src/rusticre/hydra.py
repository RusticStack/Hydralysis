"""RusticRE's analysis engine: Hydra Engine's headless session daemon.

RusticRE calls Hydra; it contains no Ghidra code. One daemon serves every
RusticRE process that shares a data root (its own state dir and instance, so it
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
import zipfile
from pathlib import Path

from rusticre.paths import root_path

RELEASE = "12.3-hydra.2"
PROTOCOL = 2
CLIENT_VERSION = "1.0.0"
INSTANCE = "rusticre"
_BASE = "https://github.com/RusticStack/hydra-engine/releases/download/v" + RELEASE + "/"
# SHA256SUMS of the release, observed 2026-10-26 and checked after download.
ASSETS = {
    "engine": {"url": _BASE + "hydra-engine-" + RELEASE + "-win_x86_64.zip",
               "sha256": "f5cc0d721d401660556e28af6c104ee75a23fdc62803a419789d799a00ee6218", "size": 378876631},
    "client": {"url": _BASE + "hydra-client-" + RELEASE + ".zip",
               "sha256": "f26e9ebc3d242d1f8ad4872acd2c5219addfc7a615c4e4334d7189c81792c773", "size": 22901},
}
SESSION_MODULE = Path("Ghidra", "Features", "HeadlessSession")


class EngineError(RuntimeError):
    """An ok:false answer from the engine. str() is JSON an agent can act on."""

    def __init__(self, code: str, message: str, details: dict | None = None, command: str = ""):
        self.code = code
        self.details = details or {}
        payload = {"engine_error": code, "message": message, "command": command}
        for key in ("holder", "suggest", "suggestion", "alternatives", "reason", "program", "project"):
            if key in self.details:
                payload[key] = self.details[key]
        super().__init__(json.dumps(payload, ensure_ascii=False))


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
        return {**report, "reason": "a stock Ghidra without Hydra's HeadlessSession module; RusticRE drives Hydra Engine "
                                    "%s (backend install), never analyzeHeadless" % RELEASE}
    if release != RELEASE and not allow_unpinned:
        return {**report, "reason": "Hydra Engine %s; this RusticRE pins %s (set hydra_allow_unpinned to try it)" % (release, RELEASE)}
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
        raise ValueError("Hydra client %s speaks protocol %s; RusticRE needs %s" % (path, stamps["PROTOCOL"], PROTOCOL))
    if not allow_unpinned and (stamps["HYDRA_RELEASE"] != RELEASE or stamps["CLIENT_VERSION"] != CLIENT_VERSION):
        raise ValueError("Hydra client %s is release %s / client %s; this RusticRE pins %s / %s"
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
    """Hydra only loads Java scripts from its scriptPath; RusticRE's live under its root."""
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


_IDENTITY = {"client": "rusticre:%d" % os.getpid(), "harness": os.environ.get("RUSTICRE_HARNESS") or "cli"}


def set_harness(name: str) -> None:
    """The MCP client's name (initialize.clientInfo) labels every engine request."""
    if name and isinstance(name, str):
        _IDENTITY["harness"] = re.sub(r"[^A-Za-z0-9._ -]", "-", name)[:64]


def identity() -> dict:
    return dict(_IDENTITY)


class Engine:
    """One connection per process and root, shared by every thread."""

    _connections: dict[str, object] = {}
    _guard = threading.Lock()

    def __init__(self, settings: dict, role: str = "reader"):
        # Reads use one long-lived connection and run contained (in parallel, rolled back).
        # A writer gets its own connection: a client that may write a program runs its
        # scripts as owner, exclusively, which reads must not do.
        self.settings = settings
        self.root = root_path(settings)
        self.engine_dir = Path(settings["hydra_dir"])
        self.client_path = Path(settings["hydra_client"])
        self.allow_unpinned = bool(settings.get("hydra_allow_unpinned"))
        self.role = role
        self.key = (str(self.root).lower() if os.name == "nt" else str(self.root)) + "|" + role

    def module(self):
        return load_client(self.client_path, self.allow_unpinned)

    def _connect(self):
        module = self.module()
        sync_scripts(self.settings)
        write_daemon_config(self.settings)
        try:
            session = module.connect(client=_IDENTITY["client"], harness=_IDENTITY["harness"],
                                     ghidra=str(self.engine_dir), state=str(state_dir(self.settings)), instance=INSTANCE)
        except module.IncompatibleError as exc:
            raise RuntimeError("Hydra engine refused: %s. Stop the old daemon (backend action=stop) or install the "
                               "pinned release %s" % (exc, RELEASE)) from exc
        except module.LaunchError as exc:
            raise RuntimeError("Hydra engine did not start: %s; log %s" % (exc, state_dir(self.settings) / (INSTANCE + ".log"))) from exc
        hello = getattr(session, "hello", {}) or {}
        if hello.get("hydraVersion") != RELEASE and not self.allow_unpinned:
            session.close()
            raise RuntimeError("the running RusticRE daemon is Hydra %s, not the pinned %s; stop it (backend action=stop)"
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
        if session is not None:
            try:
                session.close()
            except Exception:
                pass

    def call(self, command: str, raw: bool = False, **fields):
        """A labelled, parallel request. Reconnects once if the daemon went away."""
        module = self.module()
        labels = {"client": _IDENTITY["client"], "harness": _IDENTITY["harness"], "parallel": True}
        for attempt in (0, 1):
            session = self.session()
            try:
                if raw:
                    return session.call_raw(command, **labels, **fields)
                return session.call(command, **labels, **fields)
            except module.SessionError as exc:
                if exc.code == "closed" and attempt == 0:
                    self.reset()
                    continue
                raise EngineError(exc.code, exc.message, exc.details, command) from exc
            except OSError:
                if attempt == 0:
                    self.reset()
                    continue
                raise

    def send(self, command: str, **fields) -> int:
        """Start a long request without waiting (an import, an export script); see wait/cancel."""
        labels = {"client": _IDENTITY["client"], "harness": _IDENTITY["harness"], "parallel": True}
        return self.session().send(command, **labels, **fields)

    def wait(self, request_id: int, command: str = ""):
        module = self.module()
        try:
            return self.session().wait(request_id)
        except module.SessionError as exc:
            raise EngineError(exc.code, exc.message, exc.details, command) from exc

    def cancel(self, request_id: int) -> dict:
        return self.call("cancel", target=request_id)

    def on_event(self, callback) -> None:
        self.session().on_event = callback

    def hello(self) -> dict:
        info = dict(getattr(self.session(), "hello", {}) or {})
        info.pop("token", None)
        return info

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
