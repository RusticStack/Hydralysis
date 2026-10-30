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

from hydralysis import durable, hydra, proc, runtime_capture as capture
from hydralysis.locks import LaneLock
from hydralysis.paths import root_path
from hydralysis.proc import identity as _identity, stop as _stop
from hydralysis.localio import read_text as local_read_text
from hydralysis.runtime_ipc import request as ipc_request

FRIDA_VERSION = "17.24.3"
ACTION_NAMES = ("setup", "processes", "spawn", "attach", "status", "modules", "threads", "read", "patches",
                "observe", "break", "continue", "unload", "resume", "detach", "writers", "capture", "snapshot", "compare",
                "write", "watch")
# Only the session's owner drives the target; any client may look.
# Actions that need no session request lock (they read the worker's in-memory state under its own lock).
LOCK_FREE = frozenset({"status"})
MUTATING = ("observe", "break", "continue", "unload", "resume", "detach", "writers", "write", "watch")
# capture start/stop write the session's event log: the owner's. read, verify, list, counters and snapshot only look.
CAPTURE_OWNER_OPS = ("start", "stop")
# A store site's memory operand, as the analysis prints it: [BASE + 0xOFF].
_STORE_OPERAND = re.compile(r"\[([A-Za-z][A-Za-z0-9]*)\s*\+\s*0x([0-9a-fA-F]+)\]")
# How many bytes past a site a probe may overwrite; no jump may land inside them.
_PROBE_SPAN = 8
# Owner tokens of the sessions this process started (an MCP server keeps its own).
_TOKENS: dict[str, str] = {}


def _write(path: Path, value: dict) -> None:
    """A mailbox record: sealed, the previous version kept as `.bak`, atomic and fsynced (durable.write_sealed)."""
    durable.write_sealed(path, value, indent=None)


def _load(path: Path) -> dict:
    """One mailbox file, unsealed. A file from before the seal (no `seal` key) loads as it is.

    FileNotFoundError when the file is absent; ValueError when it is not a JSON object or its seal does not match.
    """
    value = json.loads(local_read_text(path))
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    if "seal" in value:
        claimed = value.pop("seal")
        if claimed != durable.seal_of(value):
            raise ValueError("mis-sealed (content does not match its seal)")
    return value


def _json(path: Path) -> dict:
    """A mailbox record, {} when it was never written. A bad file falls back to its `.bak` (the previous sealed
    version) and, when that is no better, raises durable.StoreCorrupt: it never reads as empty."""
    try:
        reasons = {}
        for candidate in (path, durable.backup_path(path)):
            try:
                return _load(candidate)
            except FileNotFoundError:
                reasons[candidate.name] = "missing"
            except ValueError as exc:
                reasons[candidate.name] = str(exc)[:80]
        if all(reason == "missing" for reason in reasons.values()):
            return {}
        raise durable.StoreCorrupt(path, durable.backup_path(path), reasons)
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


# The worker's own environment points TEMP and PYTHONPATH at Hydralysis's private
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
    env["HYDRALYSIS_TARGET_ENV_RESTORE"] = json.dumps({key: os.environ.get(key) for key in WORKER_ONLY})
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(temp)
    # The worker ignores the user site (so no other frida shadows the pinned one), but it
    # needs Hydralysis's own dependencies from wherever this process found them.
    env["PYTHONPATH"] = proc.worker_path(str(site))
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
        # Only a frida loaded from this folder is ours: the worker's path also holds Hydralysis's
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


class _NoLock:
    def acquire(self) -> bool:
        return True

    def release(self) -> None:
        pass


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
            process = proc.run([sys.executable, "-m", "hydralysis.runtime_worker", "--processes", str(limit)],
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
        # Reading a finished capture or comparing snapshots needs the session's files, not its worker.
        if action == "compare":
            return capture.compare_snapshots(self.root, session_id, args)
        if action == "capture" and str(args.get("op") or "") in ("read", "verify", "list"):
            return capture.capture_host_op(directory, session_id, args)
        if action == "snapshot" and args.get("op") == "list":
            return capture.list_snapshots(directory)
        ready = _json(directory / "ready.json")
        alive = _identity(int(ready.get("pid", 0)), int(ready.get("started_ms", 0)))
        if not alive:
            state = _json(directory / "state.json")
            if action == "status":
                return {"session": session_id, "worker_alive": False, "state": state,
                        "log": str(directory / "worker.log")}
            if state.get("detached"):
                raise RuntimeError("runtime session %s has ended (%s); the target was detached cleanly and keeps "
                                   "running: attach again with pid %s" % (session_id, state.get("ended") or "detached",
                                                                          state.get("pid")))
            raise RuntimeError("runtime worker is no longer alive; target state is unknown; log=%s" % (directory / "worker.log"))
        token = str(args.pop("owner", "") or _TOKENS.get(session_id, ""))
        owner = _json(directory / "owner.json")
        owner_only = action in MUTATING or (action == "capture" and str(args.get("op") or "") in CAPTURE_OWNER_OPS)
        if owner_only and owner and not hmac.compare_digest(
                hashlib.sha256(token.encode()).hexdigest(), str(owner.get("token_sha256", ""))):
            raise PermissionError("runtime session %s is owned by %s (%s) since %s; other clients may use status, modules, "
                                  "threads, read and patches; driving it needs options.owner, the token its spawn/attach returned"
                                  % (session_id, owner.get("client"), owner.get("harness"), owner.get("since")))
        if action == "read" and "type" in args:
            args.update(self._layout(args))
        if action == "writers":
            return self._writers(session_id, args, token, owner)
        if action == "snapshot":
            args = self._snapshot_layouts(args)
        if action in ("write", "watch"):
            args = self._memory_gate(directory, args)
        timeout = int(args.pop("timeout_s", 15))
        if not 1 <= timeout <= 60:
            raise ValueError("runtime timeout_s must be 1..60")
        # `status` reads the worker's in-memory snapshot and needs no session lock: it is answered beside a running
        # request (the worker serves it on its own thread) instead of failing with "busy".
        lock = LaneLock(str(directory / ".request.lock")) if action not in LOCK_FREE else _NoLock()
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
            except PermissionError:
                raise
            except OSError as exc:
                raise RuntimeError("runtime IPC failed: errno=%s winerror=%s; log=%s: %s"
                                   % (exc.errno, getattr(exc, "winerror", None), directory / "worker.log", exc)) from exc
            if not response.get("ok"):
                error_type = {"PermissionError": PermissionError, "ValueError": ValueError}.get(
                    response.get("error_type"), RuntimeError)
                raise error_type(json.dumps(response))
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
        from hydralysis import hydra
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
            process = proc.popen([sys.executable, "-m", "hydralysis.runtime_worker", str(directory)],
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
                target = ready.get("target") or {}
                return {"session": session_id, "owner": token, "pid": target.get("pid"), "arch": target.get("arch"),
                        "pointer_size": target.get("pointer_size"), "state": ready.get("state"),
                        "exe": str(exe), "sha256": digest, "cwd": cwd, "env_keys": sorted(env),
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


    def _memory_gate(self, directory: Path, args: dict) -> dict:
        """The fixture gate of `write` and `watch` (Z12). The caller cannot supply it: the client adds it from its own
        settings (`runtime_fixture_sha256`, a list of build hashes) and the conformance stamps it holds."""
        args.pop("_gate", None)
        digest = str(_json(directory / "start.json").get("sha256") or "")
        allowed = self.settings.get("runtime_fixture_sha256") or []
        gate = {"fixture_sha256": digest if digest in allowed else "", "frida": FRIDA_VERSION, "stamps": {},
                "conformance": bool(self.settings.get("runtime_watch_conformance_run"))}
        for arch in ("x64", "x86"):
            stamp = _json(_root(self.settings) / "watch-stamps" / (arch + ".json"))
            if stamp:
                gate["stamps"][arch] = stamp
        return {**args, "_gate": gate}

    def _layout(self, args: dict) -> dict:
        """A type from a target's saved analysis (imported or overlay types included), as a read layout."""
        from hydralysis.backends import resolved
        from hydralysis.query import QueryRunner
        name, target = str(args.pop("type")), str(args.pop("target", "") or "")
        view = args.pop("view", "")
        if not target:
            raise ValueError("read with type needs options.target: the analysis target that defines the type")
        selection = {"view": view} if view else {}
        runner = QueryRunner(resolved(self.settings))
        answer = json.loads(runner.query(target, "type", options={"path": name, **selection}, limit=200))
        described = answer["type"]
        layout, enums = [], {}
        for field in described.get("fields", []):
            row = {"name": field.get("field") or "field_%x" % field["offset"], "offset": field["offset"],
                   "type": field.get("name", ""), "size": field.get("length")}
            # An enum reads as its unsigned value plus the member name (a few per type; each is one query).
            if field.get("kind") == "EnumDB" and field.get("length") in (1, 2, 4, 8) and len(enums) < 32:
                if field["path"] not in enums:
                    members = json.loads(runner.query(
                        target, "type", options={"path": field["path"], **selection}, limit=200)).get("type", {}).get("values", [])
                    enums[field["path"]] = {str(int(str(item["value"]), 0)): item["name"] for item in members}
                row.update({"enum": row["type"], "type": "u%d" % (8 * field["length"]), "names": enums[field["path"]]})
            layout.append(row)
        if not layout:
            raise ValueError("type %s has no fields to read" % name)
        size = int(args.get("size") or described.get("length") or 0)
        return {"layout": layout, "size": max(1, min(4096, size)), "type_name": described.get("path"),
                "layout_source": self._layout_source(runner, target, view)}

    def _layout_source(self, runner, target: str, view: str) -> dict:
        """Which view of which analysis the layout came from, and that view's revision when it was read."""
        source = {"target": target, "view": view or "shared"}
        try:
            from hydralysis import workcopy
            selected = workcopy.with_view(runner.target(target), view)
            source.update(view=selected["view"], revision=workcopy.load_store(self.settings, selected)["revision"])
        except Exception as exc:  # said, not hidden: a read without a revision is not a read of a known revision
            source.update(revision=None, revision_error="%s: %s" % (type(exc).__name__, str(exc)[:160]))
        return source

    def _snapshot_layouts(self, args: dict) -> dict:
        """Regions of a snapshot may name a type (`type` + `target`): resolve each like a typed read."""
        regions = args.get("regions")
        if not isinstance(regions, list):
            return args
        rows = []
        for row in regions:
            if isinstance(row, dict) and "type" in row:
                row = {**row}
                resolved_layout = self._layout(row)
                row.update(layout=resolved_layout["layout"], type_name=resolved_layout["type_name"],
                           layout_source=resolved_layout["layout_source"])
                row.setdefault("size", resolved_layout["size"])
                row.pop("view", None)
            rows.append(row)
        return {**args, "regions": rows}

    def _writers(self, session_id: str, args: dict, token: str, owner: dict) -> dict:
        probes = {}
        primary = None
        try:
            result = self._collect_writers(session_id, args, token, owner, probes)
        except BaseException as exc:
            primary = exc

        failures = []
        for hook_id in probes:
            try:
                self.call("unload", {"session": session_id, "owner": token, "hook_id": hook_id})
            except Exception as exc:
                failures.append((hook_id, exc))
        if failures:
            detail = "; ".join("%s: %s: %s" % (hook, type(exc).__name__, exc) for hook, exc in failures)
            message = "writer probe cleanup failed (%s); inspect the session and retry unloading the listed probes" % detail
            if primary is not None:
                if not isinstance(primary, Exception):
                    primary.add_note(message)
                    raise primary.with_traceback(primary.__traceback__)
                message = "%s: %s; %s" % (type(primary).__name__, primary, message)
            error_type = PermissionError if isinstance(primary, PermissionError) or any(
                isinstance(exc, PermissionError) for _, exc in failures) else RuntimeError
            raise error_type(message) from primary
        if primary is not None:
            raise primary.with_traceback(primary.__traceback__)
        return result

    def _collect_writers(self, session_id: str, args: dict, token: str, owner: dict, probes: dict) -> dict:
        """Which static store sites write one live object's field during a window.

        rows are what ghidra_query action=writes returned (site/rva and instruction). Each site
        gets a probe that captures its base register; a hit whose base + displacement is
        object + offset wrote the field. A site is refused when the analysis shows a jump into
        the bytes a probe would overwrite, or when its live bytes differ from the file.
        """
        from hydralysis.backends import resolved
        from hydralysis.pe import Image
        from hydralysis.query import QueryRunner
        rows, target = args.get("rows"), str(args.get("target") or "")
        if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
            raise ValueError("writers needs rows: 1..32 store sites from ghidra_query action=writes")
        if not target:
            raise ValueError("writers needs target: the analysis target, to check each site before probing it")
        try:
            offset = int(str(args.get("offset")), 0)
            obj = int(str(args.get("object")), 0)
        except ValueError as exc:
            raise ValueError("writers needs object (the live object's address) and offset (the field's)") from exc
        size = int(args.get("size", 4))
        window = float(args.get("window_s", 5))
        if not 1 <= size <= 64 or not 1 <= window <= 60:
            raise ValueError("writers size is 1..64 and window_s 1..60")
        exe = Path(owner.get("exe", ""))
        image = Image(exe)
        digest = str(_json(self.root / session_id / "ready.json").get("sha256", ""))
        query = QueryRunner(resolved(self.settings))
        driver = {"session": session_id, "owner": token}
        report = []
        for row in rows:
            site = int(str(row.get("site") or "0"), 16) if row.get("site") else image.base + int(str(row.get("rva")), 16)
            rva = site - image.base
            entry = {"site": hex(site), "rva": hex(rva), "instruction": str(row.get("instruction", ""))[:256]}
            operand = _STORE_OPERAND.search(entry["instruction"])
            if not operand or int(operand.group(2), 16) != offset:
                report.append({**entry, "probed": False, "reason": "no [register + offset] store operand at this offset"})
                continue
            base = operand.group(1).lower()
            landing = []
            for inside in range(1, _PROBE_SPAN):
                answer = json.loads(query.query(target, "xrefs", hex(site + inside), limit=5))
                landing += [ref.get("from") for ref in answer.get("references", [])]
            if landing:
                report.append({**entry, "probed": False, "reason": "a jump lands inside the bytes a probe would overwrite: %s" % landing[:4]})
                continue
            expect = image.read_rva(rva, _PROBE_SPAN).hex(" ").upper()
            try:
                hook = self.call("observe", {**driver, "module": exe.name, "rva": hex(rva), "sha256": digest, "expect": expect,
                                             "limit": 200, "instruction": True,
                                             "capture": [{"reg": base, "as": "pointer", "label": base}]})
                probes[hook["hook_id"]] = entry
                entry.update({"probed": True, "via": "site", "base": base, "calls": 0, "wrote": 0, "other_objects": []})
                report.append(entry)
                continue
            except ValueError as exc:
                refused = str(exc)[:300]
            # Too little room for a probe (a short setter ends right after its store): when the
            # base register is still one of the function's arguments, probe its direct call sites
            # and capture that argument before the call.
            function = query.query(target, "function", hex(site), limit=1)
            entry_va = int(json.loads(function)["function"]["address"], 16)
            source = _base_argument(image, entry_va - image.base, rva, base)
            callers = json.loads(query.query(target, "xrefs", hex(entry_va), limit=32)).get("references", []) if source else []
            calls = [int(ref["from"], 16) for ref in callers if "CALL" in str(ref.get("type", ""))]
            if not calls:
                report.append({**entry, "probed": False, "reason": refused + ("; its base register is not an argument at the "
                               "store" if not source else "; no direct call sites in the analysis")})
                continue
            if source[0] == "reg":
                capture = {"reg": source[1], "as": "pointer", "label": source[1]}
            else:
                # At the call instruction the i-th stack argument is at [esp + 4i]; the capture's
                # pointer is that argument (the bytes read behind it are not used).
                capture = {"reg": "esp", "deref": [4 * source[1]], "as": "hex", "size": 1, "label": "stack argument %d" % source[1]}
            entry.update({"probed": False, "via": "call_site", "base": base, "argument": list(source), "calls": 0, "wrote": 0,
                          "other_objects": [], "call_sites": [], "note": "the store's own bytes cannot hold a probe (%s); the "
                          "function receives the base as %s %s, so each call is counted where it returns, with the object "
                          "it was given: a conditional store may not run on every call" % (refused[:120], source[0], source[1])})
            for call in calls[:8]:
                # Never probe the call itself (see the worker's call-in-span refusal): probe the
                # instruction it returns to, where the argument is still known.
                listing = json.loads(query.query(target, "scan", hex(call - 0x40), limit=64,
                                                 options={"end": hex(call + 0x10)})).get("instructions", [])
                known = _argument_at_return(listing, call, source, image.bits)
                after = [row for row in listing if int(row["address"], 16) > call]
                if not known or not after:
                    continue
                back = int(after[0]["address"], 16)
                landing = []
                for inside in range(1, _PROBE_SPAN):
                    answer = json.loads(query.query(target, "xrefs", hex(back + inside), limit=5))
                    landing += [ref.get("from") for ref in answer.get("references", [])]
                if landing:
                    continue
                if known[0] == "static":
                    capture = None
                elif known[0] == "reg":
                    capture = {"reg": known[1], "as": "pointer", "label": known[1]}
                else:
                    capture = {"reg": "esp", "deref": [4 * known[1]], "as": "hex", "size": 1, "label": "stack argument %d" % known[1]}
                try:
                    hook = self.call("observe", {**driver, "module": exe.name, "rva": hex(back - image.base), "sha256": digest,
                                                 "expect": image.read_rva(back - image.base, _PROBE_SPAN).hex(" ").upper(),
                                                 "limit": 200, "instruction": True, **({"capture": [capture]} if capture else {})})
                except ValueError:
                    continue
                probes[hook["hook_id"]] = entry
                entry.setdefault("returns", {})[hook["hook_id"]] = list(known)
                entry["call_sites"].append({"call": hex(call), "probed_at": hex(back), "argument": list(known)})
            entry["probed"] = bool(entry["call_sites"])
            if not entry["probed"]:
                entry["reason"] = refused + "; none of its call sites could hold a probe either"
            report.append(entry)
        # Count only calls after the probes were in place: start at the session's latest event.
        cursor = int(self.call("status", {"session": session_id, "limit": 1}).get("last_sequence", 0)) if probes else 0
        # Where the module is loaded, for a fixed address the analysis gave as a VA.
        loaded = [m for m in self.call("modules", {"session": session_id, "limit": 200}).get("modules", [])
                  if m.get("name", "").lower() == exe.name.lower()]
        module_base = int(loaded[0]["base"], 16) if loaded else image.base
        deadline = time.monotonic() + window
        while probes and time.monotonic() < deadline:
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        if probes:
            while probes:
                status = self.call("status", {"session": session_id, "after": cursor, "limit": 200})
                for event in status.get("events", []):
                    payload = (event.get("message") or {}).get("payload") or {}
                    entry = probes.get(event.get("script"))
                    if entry is None or payload.get("event") != "enter":
                        continue
                    entry["calls"] += 1
                    decoded = (payload.get("decoded") or [{}])[0]
                    known = entry.get("returns", {}).get(event.get("script"))
                    if known and known[0] == "static":
                        value = hex(known[1] - image.base + module_base)
                    elif known and known[0] == "stack":
                        value = decoded.get("pointer")
                    else:
                        value = decoded.get("value")
                    address = int(value, 16) + offset if isinstance(value, str) else None
                    if address is not None and obj + offset <= address < obj + offset + size:
                        entry["wrote"] += 1
                    elif address is not None and len(entry["other_objects"]) < 4 and hex(address - offset) not in entry["other_objects"]:
                        entry["other_objects"].append(hex(address - offset))
                cursor = status.get("next_after", cursor)
                if not status.get("truncated"):
                    break
        return {"object": hex(obj), "offset": hex(offset), "size": size, "window_s": window,
                "writers": [entry for entry in report if entry.get("wrote")], "sites": report,
                "coverage": "the given static sites only (ghidra_query action=writes and what it does not cover: computed "
                            "offsets, block copies, stores outside analysed code); a site counts as a writer when a probed "
                            "call's base register plus the displacement addressed the field during the window. Up to 200 "
                            "calls are recorded per site."}

    # ---- one driving session per executable, and an optional external game lock ----------------
    def _lock_path(self, exe: Path) -> Path:
        key = hashlib.sha256(os.path.normcase(str(exe)).encode()).hexdigest()[:16]
        return self.root.parent / "runtime-locks" / (key + ".json")

    def _live(self, session_id: str) -> bool:
        ready = _json(self.root / session_id / "ready.json")
        return _identity(int(ready.get("pid", 0)), int(ready.get("started_ms", 0)))

    def _claim(self, exe: Path, session_id: str) -> None:
        from hydralysis import hydra
        from hydralysis.locks import locked
        path = self._lock_path(exe)
        with locked(path.with_suffix(".lock"), what="runtime lock"):
            held = _json(path)
            starting = held and time.time() - float(held.get("at", 0)) < 60 and not (self.root / held["session"] / "ready.json").exists()
            # A session whose target process has exited drives nothing, whatever its worker does.
            target = _json(self.root / held["session"] / "state.json") if held else {}
            gone = bool(target.get("pid") and target.get("target_created_ms")) \
                and not _identity(int(target["pid"]), int(target["target_created_ms"]))
            if held and not gone and (self._live(held["session"]) or starting):
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
            # The previous sealed version goes too: a missing record with a `.bak` reads as the `.bak`.
            durable.backup_path(path).unlink(missing_ok=True)
            path.unlink(missing_ok=True)

    def _external_lock(self, action: str, exe: Path) -> None:
        """A project's own game lock (runtime_lock_check: a command; non-zero exit refuses)."""
        command = self.settings.get("runtime_lock_check")
        if not command:
            return
        if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
            raise ValueError("runtime_lock_check must be a command as a list of strings")
        result = proc.run([*command, "--tool", hydra.ATTRIBUTION, "--command", "%s %s" % (action, exe.name)],
                          capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise PermissionError("the external game lock refused %s (exit %d): %s"
                                  % (action, result.returncode, (result.stdout + result.stderr).strip()[-1500:]))


_X64_ARGUMENTS = ("rcx", "rdx", "r8", "r9")
# Registers a callee preserves, by the 64-bit and 32-bit Windows conventions.
_PRESERVED = {64: {"RBX", "RBP", "RSI", "RDI", "R12", "R13", "R14", "R15"}, 32: {"EBX", "EBP", "ESI", "EDI"}}
_FAMILY = {"rcx": {"RCX", "ECX"}, "rdx": {"RDX", "EDX"}, "r8": {"R8", "R8D"}, "r9": {"R9", "R9D"}}


def _argument_at_return(listing: list[dict], call: int, source: tuple, bits: int):
    """How the call's argument is still known once the call has returned, from the listing.

    ("static", va): the caller passed a fixed address (LEA reg, [addr] or PUSH addr);
    ("reg", name): it copied the argument from a register the callee preserves;
    ("stack", i): x86, the caller removes its arguments after the call (ADD ESP), so the
    i-th one is still at [esp + 4i] at the return site. None when none of these holds.
    """
    before = [row for row in listing if int(row["address"], 16) < call]
    after = [row for row in listing if int(row["address"], 16) > call]
    if source[0] == "reg" and bits == 64:
        family = _FAMILY.get(source[1], set())
        for row in reversed(before[-12:]):
            operands = [part.strip() for part in row["operands"].split(",", 1)]
            if not operands or operands[0].upper() not in family:
                continue
            if row["mnemonic"] == "LEA":
                fixed = re.fullmatch(r"\[(0x[0-9a-fA-F]+)\]", operands[1].strip()) if len(operands) > 1 else None
                return ("static", int(fixed.group(1), 16)) if fixed else None
            if row["mnemonic"] == "MOV" and len(operands) > 1 and operands[1].upper() in _PRESERVED[64]:
                return ("reg", operands[1].lower())
            return None
        return None
    if source[0] == "stack" and bits == 32:
        pushes = [row for row in reversed(before[-12:]) if row["mnemonic"] == "PUSH"]
        if len(pushes) > source[1]:
            pushed = pushes[source[1]]["operands"].strip()
            if re.fullmatch(r"0x[0-9a-fA-F]+", pushed):
                return ("static", int(pushed, 16))
        if after and after[0]["mnemonic"] == "ADD" and after[0]["operands"].upper().startswith("ESP"):
            return ("stack", source[1])
        if len(pushes) > source[1] and pushes[source[1]]["operands"].strip().upper() in _PRESERVED[32]:
            return ("reg", pushes[source[1]]["operands"].strip().lower())
    return None


def _base_argument(image, entry_rva: int, site_rva: int, base: str):
    """How a caller passes the store's base register, if the function has not changed it.

    Decodes from the function's entry to the store. ("reg", name): the register is untouched
    since entry and is an argument register (x64 rcx/rdx/r8/r9, or a 32-bit thiscall ecx);
    ("stack", i): on x86 it was loaded from the i-th stack argument before the stack moved.
    None when it was computed some other way.
    """
    import capstone
    decoder = image._decoder()
    decoder.detail = True
    code = image.read_rva(entry_rva, site_rva - entry_rva)
    wide = image.bits == 64
    depth = 0
    source = None
    for instruction in decoder.disasm(code, entry_rva):
        if instruction.address >= site_rva:
            break
        written = {instruction.reg_name(r) for r in instruction.regs_access()[1]}
        text = "%s %s" % (instruction.mnemonic, instruction.op_str)
        if base in written:
            if wide or source is not None:
                return None
            loaded = re.fullmatch(r"mov %s, dword ptr \[esp(?: \+ (0x[0-9a-f]+|\d+))?\]" % base, text)
            if not loaded:
                return None
            source = ("stack", (int(loaded.group(1) or "0", 0) + depth - 4) // 4)
            continue
        if not wide:
            if instruction.mnemonic == "push":
                depth -= 4
            elif instruction.mnemonic == "pop":
                depth += 4
            elif "esp" in written:
                return None if source is None else source
    if source is not None:
        return source if source[1] >= 0 else None
    if (wide and base in _X64_ARGUMENTS) or (not wide and base == "ecx"):
        return ("reg", base)
    return None


def runtime(action: str, args: dict | None, settings: dict) -> str:
    return json.dumps(RuntimeRunner(settings).call(action, args), ensure_ascii=False)
