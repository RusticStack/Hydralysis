"""Generic local runtime sessions; optional Frida lives outside the MCP process.

Only the backend is installed. REA and other MCP servers are never dependencies.
Each target session has its own worker, mailbox, log and OS request lock.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

from rusticre.ghidra import LaneLock
from rusticre.query import _identity, _json as _query_json, _stop, _write
from rusticre.runtime_ipc import request as ipc_request

FRIDA_VERSION = "17.24.3"
ACTION_NAMES = ("setup", "processes", "spawn", "attach", "status", "modules", "threads", "read",
                "observe", "break", "continue", "unload", "resume", "detach")


def _json(path: Path) -> dict:
    try:
        return _query_json(path)
    except OSError as exc:
        raise RuntimeError("runtime mailbox read failed: errno=%s winerror=%s path=%s: %s"
                           % (exc.errno, getattr(exc, "winerror", None), path, exc)) from exc


def _public_ready(ready: dict) -> dict:
    # Authentication material belongs only in the worker's local ready record.
    return {key: value for key, value in ready.items() if key != "ipc"}


def _root(settings: dict, create: bool = True) -> Path:
    directory = Path(settings.get("root") or os.environ.get("RUSTICRE_ROOT") or "F:/dev-cache/rusticre").resolve()
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


def _environment(settings: dict, create: bool = True) -> dict:
    root = _root(settings, create=create)
    site = root / "runtime-backend" / ("frida-" + FRIDA_VERSION)
    temp = root / "runtime-backend" / "tmp"
    if create:
        temp.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(temp)
    package_root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = os.pathsep.join([str(site), package_root])
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def inspect(settings: dict) -> dict:
    """Probe the optional Python binding without creating files or installing."""
    site = _root(settings, create=False) / "runtime-backend" / ("frida-" + FRIDA_VERSION)
    command = [sys.executable, "-c", "import frida,json; print(json.dumps({'version':frida.__version__,'path':frida.__file__}))"]
    process = subprocess.run(command, env=_environment(settings, create=False), capture_output=True, text=True,
                             timeout=15, **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}))
    if process.returncode:
        return {"ready": False, "component": "runtime", "version": FRIDA_VERSION, "path": str(site),
                "reason": "optional runtime backend is not available; use backend install component=runtime"}
    result = json.loads(process.stdout)
    return {"ready": result.get("version") == FRIDA_VERSION, "component": "runtime", **result,
            "expected_version": FRIDA_VERSION}


def setup(settings: dict) -> dict:
    """Explicit, hash-verified optional backend installation under root."""
    root = _root(settings) / "runtime-backend"
    root.mkdir(parents=True, exist_ok=True)
    lock = LaneLock(str(root / ".install.lock"))
    if not lock.acquire():
        raise ValueError("runtime backend installation is already in progress")
    try:
        site = root / ("frida-" + FRIDA_VERSION)
        env = _environment(settings)
        probe = [sys.executable, "-c", "import frida,json; print(json.dumps({'version':frida.__version__}))"]
        result = subprocess.run(probe, capture_output=True, text=True, env=env, timeout=15)
        if result.returncode == 0:
            version = json.loads(result.stdout)["version"]
            if version != FRIDA_VERSION:
                raise RuntimeError("runtime backend version differs from the pinned version: %s" % version)
            return {"state": "ready", "version": version, "path": str(site), "reused": True}
        if site.exists():
            raise RuntimeError("existing runtime backend is incomplete; preserved at %s; inspect before repairing" % site)
        url = "https://pypi.org/pypi/frida/%s/json" % FRIDA_VERSION
        with urllib.request.urlopen(url, timeout=30) as response:
            metadata = json.load(response)
        hashes = sorted({item["digests"]["sha256"] for item in metadata.get("urls", [])
                         if item.get("packagetype") == "bdist_wheel"})
        if not hashes or any(not re.fullmatch("[0-9a-f]{64}", digest) for digest in hashes):
            raise RuntimeError("PyPI did not supply wheel SHA-256 values for the pinned runtime backend")
        requirement = root / "requirements.txt"
        requirement.write_text("frida==%s %s\n" % (FRIDA_VERSION, " ".join("--hash=sha256:" + digest for digest in hashes)))
        log = root / "install.log"
        command = [sys.executable, "-m", "pip", "--isolated", "--disable-pip-version-check", "install",
                   "--only-binary=:all:", "--no-deps", "--require-hashes", "--target", str(site),
                   "--cache-dir", str(root / "cache"), "-r", str(requirement)]
        with log.open("wb") as output:
            result = subprocess.run(command, stdout=output, stderr=output, env=env, timeout=240,
                                    **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}))
        if result.returncode:
            raise RuntimeError("runtime backend installation failed, exit=%s; log=%s" % (result.returncode, log))
        verify = subprocess.run(probe, capture_output=True, text=True, env=env, timeout=15)
        if verify.returncode or json.loads(verify.stdout).get("version") != FRIDA_VERSION:
            raise RuntimeError("runtime backend import verification failed; log=%s; %s" % (log, verify.stderr[-1000:]))
        manifest = {"state": "ready", "version": FRIDA_VERSION, "path": str(site), "reused": False,
                    "source": url, "wheel_sha256": hashes, "log": str(log)}
        _write(root / "manifest.json", manifest)
        return manifest
    finally:
        lock.release()


class RuntimeRunner:
    def __init__(self, settings: dict):
        self.settings = settings
        self.root = _root(settings) / "runtime-sessions"
        self.root.mkdir(parents=True, exist_ok=True)

    def call(self, action: str, args: dict | None = None) -> dict:
        if args is not None and not isinstance(args, dict):
            raise ValueError("runtime options must be an object")
        args = dict(args or {})
        if action not in ACTION_NAMES:
            raise ValueError("runtime action must be one of: " + ", ".join(ACTION_NAMES))
        if action == "setup":
            return setup(self.settings)
        if action == "processes":
            limit = int(args.get("limit", 40))
            if not 1 <= limit <= 200:
                raise ValueError("limit must be 1..200")
            process = subprocess.run([sys.executable, "-m", "rusticre.runtime_worker", "--processes", str(limit)],
                                     env=_environment(self.settings), capture_output=True, text=True, timeout=20,
                                     **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}))
            if process.returncode:
                raise RuntimeError("runtime discovery failed; run runtime action=setup first: " + process.stderr[-2000:])
            result = json.loads(process.stdout)
            if not result.get("ok"):
                raise RuntimeError(json.dumps(result))
            return result
        if action in ("spawn", "attach"):
            return self._start(action, args)
        session_id = str(args.get("session") or "")
        if not re.fullmatch(r"[0-9a-f]{32}", session_id):
            raise ValueError("session must be the runtime session id returned by spawn/attach")
        directory = self.root / session_id
        ready = _json(directory / "ready.json")
        alive = _identity(int(ready.get("pid", 0)), int(ready.get("started_ms", 0)))
        if not alive:
            state = _json(directory / "state.json")
            if action == "status":
                return {"session": session_id, "worker_alive": False, "state": state,
                        "log": str(directory / "worker.log")}
            raise RuntimeError("runtime worker is no longer alive; target state is unknown; log=%s" % (directory / "worker.log"))
        timeout = int(args.pop("timeout_s", 15))
        if not 1 <= timeout <= 60:
            raise ValueError("runtime timeout_s must be 1..60")
        lock = LaneLock(str(directory / ".request.lock"))
        if not lock.acquire():
            raise ValueError("runtime session is busy; retry after the current bounded request")
        try:
            request_id = uuid.uuid4().hex
            try:
                response = ipc_request(ready.get("ipc") or {}, request_id, action, args, timeout)
            except TimeoutError as exc:
                # The worker also attempts deadline cleanup. Retire only the
                # identity-checked worker if native code failed to return.
                _stop(ready)
                raise TimeoutError("runtime request timed out; worker retired; target state unknown; log=%s"
                                   % (directory / "worker.log")) from exc
            except OSError as exc:
                raise RuntimeError("runtime IPC failed: errno=%s winerror=%s; log=%s: %s"
                                   % (exc.errno, getattr(exc, "winerror", None), directory / "worker.log", exc)) from exc
            if not response.get("ok"):
                raise RuntimeError(json.dumps(response))
            return response["result"]
        finally:
            lock.release()

    def _start(self, action: str, args: dict) -> dict:
        exe = Path(str(args.get("exe") or "")).resolve()
        if not exe.is_file():
            raise ValueError("spawn/attach requires the exact executable path in exe")
        digest = hashlib.sha256(exe.read_bytes()).hexdigest()
        if args.get("sha256") and str(args["sha256"]).lower() != digest:
            raise ValueError("target executable SHA256 does not match")
        argv = args.get("argv", [])
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv) or len(argv) > 100:
            raise ValueError("argv must be a list of at most 100 strings")
        if action == "attach" and (isinstance(args.get("pid"), bool) or int(args.get("pid", 0)) <= 0):
            raise ValueError("attach requires a positive process id")
        session_id = uuid.uuid4().hex
        directory = self.root / session_id
        directory.mkdir()
        initial = {"action": action, "exe": str(exe), "sha256": digest, "argv": argv,
                   "pid": int(args.get("pid", 0)), "session": session_id,
                   "idle_s": int(self.settings.get("runtime_idle_s", 600))}
        _write(directory / "start.json", initial)
        with (directory / "worker.log").open("wb") as output:
            process = subprocess.Popen([sys.executable, "-m", "rusticre.runtime_worker", str(directory)],
                                       env=_environment(self.settings), stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                       **({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ready = _json(directory / "ready.json")
            if ready:
                ready["group_id"] = process.pid
                _write(directory / "ready.json", ready)
                if not ready.get("ok"):
                    process.wait(timeout=10)
                    raise RuntimeError("runtime startup failed: %s; log=%s" % (ready.get("error"), directory / "worker.log"))
                return {"session": session_id, "worker": _public_ready(ready), "log": str(directory / "worker.log")}
            if process.poll() is not None:
                raise RuntimeError("runtime worker exited %s; install optional backend with action=setup; log=%s"
                                   % (process.returncode, directory / "worker.log"))
            time.sleep(0.05)
        # Worker itself publishes a deadline cleanup before this budget expires.
        ready = _json(directory / "ready.json")
        if ready:
            _stop(ready)
        else:
            from rusticre.ghidra import _terminate_owned_tree
            _terminate_owned_tree(process)
        raise TimeoutError("runtime startup timed out; target state unknown; inspect %s" % (directory / "worker.log"))


def runtime(action: str, args: dict | None, settings: dict) -> str:
    return json.dumps(RuntimeRunner(settings).call(action, args), ensure_ascii=False)
