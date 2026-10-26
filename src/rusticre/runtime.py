"""Generic local runtime sessions; optional Frida lives outside the MCP process.

Only the backend is installed. REA and other MCP servers are never dependencies.
Each target session has its own worker, mailbox, log and OS request lock.
"""

from __future__ import annotations

import hashlib
import json
import os
import hmac
import re
import secrets
import sys
import time
import urllib.request
import uuid
from pathlib import Path

from rusticre import proc
from rusticre.locks import LaneLock
from rusticre.paths import root_path
from rusticre.proc import identity as _identity, stop as _stop
from rusticre.localio import read_text as local_read_text
from rusticre.runtime_ipc import request as ipc_request

FRIDA_VERSION = "17.24.3"
ACTION_NAMES = ("setup", "processes", "spawn", "attach", "status", "modules", "threads", "read", "patches",
                "observe", "break", "continue", "unload", "resume", "detach")
# Only the session's owner drives the target; any client may look.
MUTATING = ("observe", "break", "continue", "unload", "resume", "detach")
# Owner tokens of the sessions this process started (an MCP server keeps its own).
_TOKENS: dict[str, str] = {}


def _write(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


def _json(path: Path) -> dict:
    try:
        try:
            return json.loads(local_read_text(path))
        except (FileNotFoundError, ValueError):
            return {}
    except OSError as exc:
        raise RuntimeError("runtime mailbox read failed: errno=%s winerror=%s path=%s: %s"
                           % (exc.errno, getattr(exc, "winerror", None), path, exc)) from exc


def _public_ready(ready: dict) -> dict:
    # Authentication material belongs only in the worker's local ready record.
    return {key: value for key, value in ready.items() if key != "ipc"}


def _root(settings: dict, create: bool = True) -> Path:
    # The same resolver as static analysis, so a session and its target's
    # evidence can never live under roots with different rules.
    directory = root_path(settings)
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


# The worker's own environment points TEMP and PYTHONPATH at RusticRE's private
# backend. A spawned target must not inherit that; the worker restores these.
WORKER_ONLY = ("TEMP", "TMP", "TMPDIR", "PYTHONPATH", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE")


def _site(settings: dict) -> Path:
    return _root(settings, create=False) / "runtime-backend" / ("frida-" + FRIDA_VERSION)


def _missing(settings: dict) -> str | None:
    """Answer at once when the optional backend was never installed."""
    site = _site(settings)
    if not (site / "frida").is_dir():
        return "optional runtime backend is not installed under %s; run backend action=install component=runtime" % site
    return None


def _environment(settings: dict, create: bool = True) -> dict:
    root = _root(settings, create=create)
    site = root / "runtime-backend" / ("frida-" + FRIDA_VERSION)
    temp = root / "runtime-backend" / "tmp"
    if create:
        temp.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["RUSTICRE_TARGET_ENV_RESTORE"] = json.dumps({key: os.environ.get(key) for key in WORKER_ONLY})
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(temp)
    package_root = str(Path(__file__).resolve().parent.parent)
    # The worker ignores the user site (so no other frida shadows the pinned one), but it
    # needs RusticRE's own dependencies from wherever this process found them.
    import capstone
    import pefile
    dependencies = sorted({str(Path(module.__file__).resolve().parent.parent) if module.__name__ == "capstone"
                           else str(Path(module.__file__).resolve().parent) for module in (capstone, pefile)})
    env["PYTHONPATH"] = os.pathsep.join([str(site), package_root, *dependencies])
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def inspect(settings: dict) -> dict:
    """Probe the optional Python binding without creating files or installing."""
    site = _site(settings)
    missing = _missing(settings)
    if missing:
        return {"ready": False, "component": "runtime", "version": FRIDA_VERSION, "path": str(site), "reason": missing}
    command = [sys.executable, "-c", "import frida,json; print(json.dumps({'version':frida.__version__,'path':frida.__file__}))"]
    process = proc.run(command, env=_environment(settings, create=False), capture_output=True, text=True, timeout=15)
    if process.returncode:
        return {"ready": False, "component": "runtime", "version": FRIDA_VERSION, "path": str(site),
                "reason": "optional runtime backend is not available; use backend install component=runtime"}
    result = json.loads(process.stdout)
    return {"ready": result.get("version") == FRIDA_VERSION, "component": "runtime", **result,
            "expected_version": FRIDA_VERSION}


def _inside(path: str, folder: Path) -> bool:
    try:
        return Path(path).resolve().is_relative_to(folder.resolve())
    except (OSError, ValueError):
        return False


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
        probe = [sys.executable, "-c", "import frida,json; print(json.dumps({'version':frida.__version__,'path':frida.__file__}))"]
        result = proc.run(probe, capture_output=True, text=True, env=env, timeout=15) if site.exists() else None
        # Only a frida loaded from this folder is ours: the worker's path also holds RusticRE's
        # dependencies, and a frida installed beside them would otherwise pass for an install.
        if result is not None and result.returncode == 0 and _inside(json.loads(result.stdout)["path"], site):
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
            result = proc.run(command, stdout=output, stderr=output, env=env, timeout=240)
        if result.returncode:
            raise RuntimeError("runtime backend installation failed, exit=%s; log=%s" % (result.returncode, log))
        verify = proc.run(probe, capture_output=True, text=True, env=env, timeout=15)
        if verify.returncode or json.loads(verify.stdout).get("version") != FRIDA_VERSION \
                or not _inside(json.loads(verify.stdout).get("path", ""), site):
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
            missing = _missing(self.settings)
            if missing:
                raise RuntimeError(missing)
            process = proc.run([sys.executable, "-m", "rusticre.runtime_worker", "--processes", str(limit)],
                               env=_environment(self.settings), capture_output=True, text=True, timeout=20)
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
        token = str(args.pop("owner", "") or _TOKENS.get(session_id, ""))
        owner = _json(directory / "owner.json")
        if action in MUTATING and owner and not hmac.compare_digest(
                hashlib.sha256(token.encode()).hexdigest(), str(owner.get("token_sha256", ""))):
            raise PermissionError("runtime session %s is owned by %s (%s) since %s; other clients may use status, modules, "
                                  "threads, read and patches; driving it needs options.owner, the token its spawn/attach returned"
                                  % (session_id, owner.get("client"), owner.get("harness"), owner.get("since")))
        if action == "read" and "type" in args:
            args.update(self._layout(args))
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
            if action == "detach":
                self._release(owner.get("exe", ""), session_id)
            return response["result"]
        finally:
            lock.release()

    def _start(self, action: str, args: dict) -> dict:
        allowed = {"spawn": {"exe", "sha256", "argv", "cwd", "env"}, "attach": {"exe", "sha256", "pid"}}[action]
        unknown = set(args) - allowed
        if unknown:
            raise ValueError("unknown %s options: %s; accepted: %s"
                             % (action, ", ".join(sorted(unknown)), ", ".join(sorted(allowed))))
        exe = Path(str(args.get("exe") or "")).resolve()
        if not args.get("exe") or not exe.is_file():
            raise ValueError("%s requires options.exe: the exact executable path" % action)
        expected = str(args.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("%s requires options.sha256: the full SHA-256 of options.exe, so that a mistyped "
                             "path cannot select another program" % action)
        digest = hashlib.sha256(exe.read_bytes()).hexdigest()
        if expected != digest:
            raise ValueError("options.sha256 does not match %s (its SHA-256 is %s)" % (exe, digest))
        argv = args.get("argv", [])
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv) or len(argv) > 100:
            raise ValueError("argv must be a list of at most 100 strings")
        cwd = None
        if "cwd" in args:
            if not isinstance(args["cwd"], str) or not Path(args["cwd"]).is_absolute() or not Path(args["cwd"]).is_dir():
                raise ValueError("options.cwd must be an absolute, existing directory")
            cwd = str(Path(args["cwd"]).resolve())
        env = args.get("env", {})
        if not isinstance(env, dict) or len(env) > 64 or any(
                not isinstance(key, str) or not isinstance(value, str) or not key or "=" in key
                or "\x00" in key + value or len(key) > 256 or len(value) > 32768 for key, value in env.items()):
            raise ValueError("options.env must map at most 64 variable names to string values")
        if action == "attach" and (isinstance(args.get("pid"), bool) or int(args.get("pid", 0)) <= 0):
            raise ValueError("attach requires options.pid: a positive process id")
        missing = _missing(self.settings)
        if missing:
            raise RuntimeError(missing)
        self._external_lock(action, exe)
        session_id = uuid.uuid4().hex
        token = secrets.token_hex(16)
        self._claim(exe, session_id)
        directory = self.root / session_id
        directory.mkdir()
        from rusticre import hydra
        who = hydra.identity()
        _write(directory / "owner.json", {"client": who["client"], "harness": who["harness"], "exe": str(exe),
                                          "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                                          "since": time.strftime("%Y-%m-%dT%H:%M:%S")})
        _TOKENS[session_id] = token
        initial = {"action": action, "exe": str(exe), "sha256": digest, "argv": argv, "cwd": cwd, "env": env,
                   "pid": int(args.get("pid", 0)), "session": session_id,
                   "idle_s": int(self.settings.get("runtime_idle_s", 600))}
        _write(directory / "start.json", initial)
        with (directory / "worker.log").open("wb") as output:
            process = proc.popen([sys.executable, "-m", "rusticre.runtime_worker", str(directory)],
                                 env=_environment(self.settings), stdout=output, stderr=output,
                                 **({} if os.name == "nt" else {"start_new_session": True}))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ready = _json(directory / "ready.json")
            if ready:
                ready["group_id"] = process.pid
                _write(directory / "ready.json", ready)
                if not ready.get("ok"):
                    process.wait(timeout=10)
                    raise RuntimeError("runtime startup failed: %s; log=%s" % (ready.get("error"), directory / "worker.log"))
                return {"session": session_id, "owner": token, "exe": str(exe), "sha256": digest, "cwd": cwd, "env_keys": sorted(env),
                        "worker": _public_ready(ready), "log": str(directory / "worker.log")}
            if process.poll() is not None:
                raise RuntimeError("runtime worker exited %s; install optional backend with action=setup; log=%s"
                                   % (process.returncode, directory / "worker.log"))
            time.sleep(0.05)
        # Worker itself publishes a deadline cleanup before this budget expires.
        ready = _json(directory / "ready.json")
        if ready:
            _stop(ready)
        else:
            proc.terminate_tree(process)
        raise TimeoutError("runtime startup timed out; target state unknown; inspect %s" % (directory / "worker.log"))


    def _layout(self, args: dict) -> dict:
        """A type from a target's saved analysis (imported or overlay types included), as a read layout."""
        from rusticre.backends import resolved
        from rusticre.query import QueryRunner
        name, target = str(args.pop("type")), str(args.pop("target", "") or "")
        if not target:
            raise ValueError("read with type needs options.target: the analysis target that defines the type")
        answer = json.loads(QueryRunner(resolved(self.settings)).query(target, "type", options={"path": name}, limit=200))
        described = answer["type"]
        layout = [{"name": field.get("field") or "field_%x" % field["offset"], "offset": field["offset"],
                   "type": field.get("name", ""), "size": field.get("length")} for field in described.get("fields", [])]
        if not layout:
            raise ValueError("type %s has no fields to read" % name)
        size = int(args.get("size") or described.get("length") or 0)
        return {"layout": layout, "size": max(1, min(4096, size)), "type_name": described.get("path")}

    # ---- one driving session per executable, and an optional external game lock ----------------
    def _lock_path(self, exe: Path) -> Path:
        key = hashlib.sha256(os.path.normcase(str(exe)).encode()).hexdigest()[:16]
        return self.root.parent / "runtime-locks" / (key + ".json")

    def _live(self, session_id: str) -> bool:
        ready = _json(self.root / session_id / "ready.json")
        return _identity(int(ready.get("pid", 0)), int(ready.get("started_ms", 0)))

    def _claim(self, exe: Path, session_id: str) -> None:
        from rusticre import hydra
        from rusticre.locks import locked
        path = self._lock_path(exe)
        with locked(path.with_suffix(".lock"), what="runtime lock"):
            held = _json(path)
            starting = held and time.time() - float(held.get("at", 0)) < 60 and not (self.root / held["session"] / "ready.json").exists()
            if held and (self._live(held["session"]) or starting):
                raise PermissionError("%s is driven by runtime session %s of %s (%s) since %s; one session drives a program "
                                      "at a time: read its status, or wait for its detach" % (exe.name, held["session"], held.get("client"),
                                                                                             held.get("harness"), held.get("since")))
            who = hydra.identity()
            path.parent.mkdir(parents=True, exist_ok=True)
            _write(path, {"session": session_id, "client": who["client"], "harness": who["harness"], "exe": str(exe),
                          "since": time.strftime("%Y-%m-%dT%H:%M:%S"), "at": time.time()})

    def _release(self, exe: str, session_id: str) -> None:
        if not exe:
            return
        path = self._lock_path(Path(exe))
        if _json(path).get("session") == session_id:
            path.unlink(missing_ok=True)

    def _external_lock(self, action: str, exe: Path) -> None:
        """A project's own game lock (runtime_lock_check: a command; non-zero exit refuses)."""
        command = self.settings.get("runtime_lock_check")
        if not command:
            return
        if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
            raise ValueError("runtime_lock_check must be a command as a list of strings")
        result = proc.run([*command, "--tool", "rusticre", "--command", "%s %s" % (action, exe.name)],
                          capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise PermissionError("the external game lock refused %s (exit %d): %s"
                                  % (action, result.returncode, (result.stdout + result.stderr).strip()[-1500:]))


def runtime(action: str, args: dict | None, settings: dict) -> str:
    return json.dumps(RuntimeRunner(settings).call(action, args), ensure_ascii=False)
