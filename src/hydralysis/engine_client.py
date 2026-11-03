"""The engine client Hydralysis uses by default: `hydralysis_native.Session` (Rust), with the engine's own `ghidra_session.py`
(library 1.1.0) as the fallback that gives the same results.

`hydralysis.hydra.load_client` returns a `NativeClient` instead of importing the engine's Python library when

* `hydralysis_native` is importable and `HYDRALYSIS_NATIVE` is not `0`,
* the library file is a 1.1.0 library of protocol 3 (the version this client was written against: deadlines are the
  library's own, `wait(rid, deadline)`), and
* the native build speaks the same protocol range and client version as `hydralysis.hydra` pins.

A `NativeClient` looks like that library to `hydra.py`: `connect`, `SessionError`, `LaunchError`, `IncompatibleError` and
`Daemon`. The framing, the request ids, the `hello` negotiation, the waits and their deadlines and the mapping of an
answer to `SessionError` are in Rust. What stays in Python is what is not on the request path: finding the daemon's
endpoint (and its lock, to know a daemon is alive), and starting one. The first is done here without importing the
library; a daemon that is not running, a wedged one, a mismatched install and every error that needs the library's
own wording all go to the library (`ghidra_session.connect`), which is then imported, and its answer is turned into the
same exception classes and a native session on the endpoint it found or started. Anything else the library offers
(`Install`, `build_aot`, `Daemon.stop` ...) is reached through `__getattr__` on the imported library.

Differences from the library, all in the native session: a connection that died is seen at once (`_closed`) and not at
the next wait; progress events are delivered when they arrive and not during a wait; `labelled` and the named `trace_*`
methods are not provided (Hydralysis does not use them: it calls `trace_*` commands by name); a reply line that is
not valid JSON ends the session with a `ValueError` for the waiters.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

try:   # optional Rust extension (native/, PyO3 abi3); the library below is the fallback
    import hydralysis_native as _native   # type: ignore[import-not-found]
    if not hasattr(_native, "connect_endpoint"):
        _native = None
except ImportError:
    _native = None


class SessionError(Exception):
    """An `ok:false` answer (the library's class: `code`, `message`, `details`, `trace`; the whole `error` object on `.error`)."""

    def __init__(self, code, message, details=None, trace=None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}
        self.trace = trace


class LaunchError(RuntimeError):
    """The session could not be started or joined (the library's class)."""

    def __init__(self, message, code=None, details=None):
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


class IncompatibleError(LaunchError):
    """The engine speaks another protocol, or requires a newer client."""

    def __init__(self, message, code="incompatible", details=None):
        super().__init__(message, code, details)


if _native is not None:
    _native.register_errors(SessionError, IncompatibleError)

HELLO_DEADLINE_S = 5.0
_INSTANCE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_INSTALLS: dict[str, str | None] = {}


def enabled() -> bool:
    """Whether the native client may be used at all (the extension is there and `HYDRALYSIS_NATIVE` is not 0)."""
    return _native is not None and os.environ.get("HYDRALYSIS_NATIVE", "1") != "0"


def usable(protocol: str | None, client_version: str | None, pins: tuple[int, int, str]) -> bool:
    """Whether the library whose stamps are PROTOCOL / CLIENT_VERSION is served by the native client. PINS is
    (protocol, protocol_min, client_version) of `hydralysis.hydra`."""
    if not enabled() or (protocol or "") != str(pins[0]) or client_version != pins[2]:
        return False
    return tuple(_native.client_pins()) == tuple(pins)


def _lock_held(path: Path) -> bool:
    """Whether some process holds the lock file (the library's `FileLock.try_acquire`, which is how it tells a daemon lives)."""
    if not path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 0)
                fcntl.lockf(fd, fcntl.LOCK_UN, 1, 0)
        except OSError:
            return True
        return False
    finally:
        os.close(fd)


def _is_protocol(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class _Daemon:
    """The part of the library's `Daemon` that Hydralysis reads on its own account (the endpoint, whether a JVM holds the
    lock); every other attribute (`stop`, `kill`, `health`, `connect` ...) is the library's `Daemon`, built on first use."""

    def __init__(self, client: "NativeClient", ghidra, state, instance, cfg):
        if not _INSTANCE.fullmatch(instance):
            raise LaunchError(f"bad instance name {instance!r}")
        self._client, self._args = client, (ghidra, state, instance, cfg)
        self._real = None
        self.ghidra = ghidra
        self.state = Path(state).resolve()
        self.instance = instance
        self.endpoint_file = self.state / f"{instance}.json"
        self.lock_file = self.state / f"{instance}.lock"
        self.start_lock_file = self.state / f"{instance}.start.lock"
        self.launch_file = self.state / f"{instance}.launch.json"

    def read_endpoint(self) -> dict | None:
        try:
            return json.loads(self.endpoint_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def jvm_alive(self) -> bool:
        return _lock_held(self.lock_file)

    def __getattr__(self, name):
        if name.startswith("__") or name in ("_client", "_args", "_real"):
            raise AttributeError(name)
        if self._real is None:
            ghidra, state, instance, cfg = self._args
            self._real = self._client.library().Daemon(ghidra, state, instance, **cfg)
        return getattr(self._real, name)


class NativeClient:
    """What `hydra.load_client` returns in place of the engine's `ghidra_session` module. PATH is that library's file."""

    SessionError = SessionError
    LaunchError = LaunchError
    IncompatibleError = IncompatibleError
    native = True

    def __init__(self, path, load_library):
        self.path = Path(path)
        self._load = load_library
        self._library = None
        self._lock = threading.Lock()

    def library(self):
        """The engine's own `ghidra_session` module, imported on first need."""
        with self._lock:
            if self._library is None:
                self._library = self._load(self.path)
            return self._library

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return getattr(self.library(), name)

    def Daemon(self, ghidra=None, state=None, instance="default", **cfg):   # noqa: N802 - the library's name
        if not state:
            return self.library().Daemon(ghidra, state, instance, **cfg)
        return _Daemon(self, ghidra, state, instance, cfg)

    def _install_ok(self, ghidra, endpoint: dict) -> bool:
        """The checks of `Install.locate` and `Daemon._check_install` that pass silently; any doubt goes to the library."""
        if not ghidra:
            return False
        key = os.path.abspath(ghidra)
        if key not in _INSTALLS:
            base = Path(ghidra).resolve()
            ok = ((base / "Ghidra" / "application.properties").is_file()
                  and (base / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar").is_file()
                  and (base / "Ghidra" / "Features" / "HeadlessSession" / "lib" / "HeadlessSession.jar").is_file())
            _INSTALLS[key] = str(base) if ok else None
        base = _INSTALLS[key]
        if base is None:
            return False
        their = endpoint.get("install")
        if their and str(Path(their).resolve()) != base:
            return False
        low, high = endpoint.get("protocolMin", endpoint.get("protocol")), endpoint.get("protocolMax", endpoint.get("protocol"))
        pins = _native.client_pins()
        return _is_protocol(low) and _is_protocol(high) and high >= pins[1] and low <= pins[0]

    def _attach(self, client, harness, ghidra, state, instance):
        """Join the running daemon with no library: its endpoint file, its lock and the native hello. None when anything
        is not plain (no daemon, a stale endpoint, another install, no answer): the library then decides and says why."""
        if not state or not _INSTANCE.fullmatch(instance):
            return None
        daemon = _Daemon(self, ghidra, state, instance, {})
        try:
            text = daemon.endpoint_file.read_text(encoding="utf-8")
            endpoint = json.loads(text)
        except (OSError, ValueError):
            return None
        if not isinstance(endpoint, dict) or not endpoint or not daemon.jvm_alive() or not self._install_ok(ghidra, endpoint):
            return None
        try:
            session = _native.connect_endpoint(text, client, harness, HELLO_DEADLINE_S)
        except (OSError, SessionError, KeyError, ValueError):
            return None
        launch = _read_launch(daemon, endpoint)
        if launch:
            session.launch = launch
            session.warnings = list(launch.get("warnings") or [])
        return session

    def connect(self, client="", harness="", ghidra=None, state=None, instance="default", start=True, **cfg):
        """The library's `connect`: join the daemon, starting it first when there is none and START."""
        session = None if cfg else self._attach(client, harness, ghidra, state, instance)
        if session is not None:
            return session
        library = self.library()
        try:
            found = library.connect(client, harness, ghidra=ghidra, state=state, instance=instance, start=start, **cfg)
        except library.IncompatibleError as exc:
            raise IncompatibleError(str(exc), exc.code, exc.details) from exc
        except library.LaunchError as exc:
            raise LaunchError(str(exc), exc.code, exc.details) from exc
        except library.SessionError as exc:
            raise SessionError(exc.code, exc.message, exc.details, exc.trace) from exc
        try:   # the library found or started the daemon; the session this process keeps is the native one on its endpoint
            session = _native.connect_endpoint(json.dumps(found.endpoint), client, harness, HELLO_DEADLINE_S)
        except (OSError, SessionError, KeyError, ValueError):
            return found
        session.launch, session.started, session.warnings = found.launch, found.started, list(found.warnings)
        found.close()
        return session


def _read_launch(daemon: _Daemon, endpoint: dict) -> dict | None:
    """How the running daemon was started (`Daemon._read_launch`), or None."""
    try:
        record = json.loads(daemon.launch_file.read_text(encoding="utf-8"))
        if record.get("pid") == endpoint.get("pid"):
            return record.get("launch")
    except (OSError, ValueError, AttributeError):
        pass
    return None
