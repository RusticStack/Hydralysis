"""Small address-based queries in a reusable, read-only Ghidra process.

Each worker owns a snapshot and an authenticated loopback socket. Callers
serialize through an OS lock. Failed workers are retired, never reused. Durable
startup metadata remains on disk; per-call requests and responses do not.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path

from rusticre.ghidra import GhidraRunner, LaneLock, build_command, ghidra_environment, launch_command, _terminate_owned_tree
from rusticre.analysis import ADVANCED_ACTIONS, load_overlays, save_overlay, validate_options
from rusticre.runtime_ipc import rpc
from rusticre.localio import read_text as local_read_text


def _json(path: Path) -> dict:
    try:
        return json.loads(local_read_text(path))
    except (FileNotFoundError, ValueError):
        return {}


def _write(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


def _public(value):
    """Local endpoint credentials never enter MCP/status/export output."""
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if key not in ("ipc", "token", "secret")}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


def _identity(pid: int, started_ms: int) -> bool:
    """Do not adopt or kill a recycled PID. Compare OS process creation time."""
    if pid <= 0 or not started_ms:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            exit_code = wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)) or exit_code.value != 259:
                return False
            values = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *[ctypes.byref(x) for x in values]):
                return False
            ticks = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
            actual_ms = ticks // 10000 - 11644473600000
            return abs(actual_ms - started_ms) <= 2
        finally:
            kernel.CloseHandle(handle)
    try:
        # Linux /proc identity, without an optional process-management dependency.
        stat = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
        if stat[0] == "Z":
            return False
        boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines()
                    if line.startswith("btime "))
        actual_ms = (boot + int(stat[19]) / os.sysconf("SC_CLK_TCK")) * 1000
        return abs(actual_ms - started_ms) <= 1000
    except (OSError, ValueError, StopIteration, IndexError):
        return False


def _stop(ready: dict) -> None:
    pid, started = int(ready.get("pid", 0)), int(ready.get("started_ms", 0))
    if not _identity(pid, started):
        return
    if os.name == "nt":
        stopped = subprocess.run(["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                                 capture_output=True, timeout=15)
        if stopped.returncode and _identity(pid, started):
            raise RuntimeError("could not stop owned Ghidra worker %d: %s" % (pid, stopped.stderr))
    else:
        import signal
        group = int(ready.get("group_id", 0))
        if group <= 0 or os.getpgid(pid) != group:
            raise RuntimeError("worker process group identity changed; refusing to stop an unrelated group")
        os.killpg(group, signal.SIGKILL)
    deadline = time.monotonic() + 10
    while _identity(pid, started) and time.monotonic() < deadline:
        time.sleep(0.05)
    if _identity(pid, started):
        raise RuntimeError("owned worker %d has not exited; its snapshot remains reserved" % pid)


def _process_start_ms(pid: int) -> int:
    from rusticre.preparation import process_start_ms
    return process_start_ms(pid)


def _sessions(directory: Path) -> list[dict]:
    """Include Java readiness left behind before current.json was committed."""
    failure = _json(directory / "startup-failure.json")
    result = []
    for path in directory.glob("*/ready.json"):
        ready = _json(path)
        if not ready:
            continue
        if str(path.parent) == failure.get("session") and not ready.get("group_id"):
            ready = {**ready, "group_id": failure.get("launcher", {}).get("group_id", 0)}
        if _identity(int(ready.get("pid", 0)), int(ready.get("started_ms", 0))):
            result.append({"session": str(path.parent), "worker": ready})
    return result


def _reserved_workers(directory: Path) -> int:
    sessions = _sessions(directory)
    failure = _json(directory / "startup-failure.json")
    # An unconfirmed launch also reserves capacity before Java writes ready.json.
    return len(sessions) + int(bool(failure) and not any(row["session"] == failure.get("session") for row in sessions))


def _stop_target(directory: Path) -> list[str]:
    sessions = _sessions(directory)
    for row in sessions:
        _stop(row["worker"])
    reservation = directory / "startup-failure.json"
    failure = _json(reservation)
    if failure:
        launcher = failure.get("launcher", {})
        if not launcher.get("pid") or not launcher.get("started_ms"):
            raise RuntimeError("startup cleanup identity is incomplete; reservation retained at %s; inspect %s" % (reservation, failure.get("log")))
        _stop(launcher)
    if _sessions(directory):
        raise RuntimeError("owned sessions remain live; target reservation retained at %s" % directory)
    if failure:
        reservation.unlink()
    return [row["session"] for row in sessions]


def _source_stamp(project: dict) -> str:
    from rusticre.ghidra import _snapshot_identity

    identity = _snapshot_identity(project)
    root = Path(project["dir"])
    marker = root / (project["name"] + ".gpr")
    rep = root / (project["name"] + ".rep")
    if not marker.is_file() or not rep.is_dir():
        raise ValueError("expected an existing analysed .gpr and .rep: %s" % marker)
    for suffix in (".lock", ".lock~"):
        if (root / (project["name"] + suffix)).exists():
            raise ValueError("master project is open; close it before querying")
    return identity["source_stat_sha256"]


def _expected_hash(project: dict) -> str:
    expected = str(project.get("sha256") or "").lower()
    if project.get("exe"):
        digest = hashlib.sha256()
        with open(project["exe"], "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        actual = digest.hexdigest()
        if expected and expected != actual:
            raise ValueError("configured sha256 does not match target exe; verify the build")
        expected = actual
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("query target needs exe or a full sha256 to verify the analysed program")
    return expected


class QueryRunner:
    def __init__(self, settings: dict):
        self.settings = settings
        self.runner = GhidraRunner(settings)
        self.root = Path(settings["root"]) / "workers"
        self.root.mkdir(parents=True, exist_ok=True)

    def query(self, target: str, action: str = "decompile", address: str = "",
              limit: int = 40, cursor: str = "", contains: str = "", timeout_s: int = 30,
              options: dict | None = None) -> str:
        if action not in {"decompile", "function", "functions", "xrefs", "status", "stop"} | ADVANCED_ACTIONS:
            raise ValueError("unknown saved-analysis query action; use backend help")
        options = validate_options(action, options)
        if not 1 <= limit <= 200 or not 1 <= timeout_s <= 300:
            raise ValueError("limit must be 1..200; timeout_s must be 1..300")
        requires_address = action in ("decompile", "function", "xrefs", "variables", "dossier", "blocks", "pcode", "trace", "data", "scan")
        requires_address |= action == "type_edit" and options.get("kind") not in ("struct", "batch")
        if requires_address and not address:
            raise ValueError("address is required (a Ghidra VA, for example 0x140001000)")
        if action == "type" and not (address or options.get("path")):
            raise ValueError("type requires options.path or a typed-data address")
        if address and not re.fullmatch(r"(?:(?:rva|va):)?(?:0x)?[0-9a-fA-F]+", address):
            raise ValueError("use a numeric Ghidra VA or rva:/va: prefix, not a symbol name")
        if cursor and not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", cursor):
            raise ValueError("use a numeric Ghidra VA or hexadecimal row cursor, not a symbol name")
        project = self.runner.project(target, require_scripts=False)
        key = hashlib.sha256((str(Path(project["dir"]).resolve()) + "\n" + project["name"]
                              + "\n" + project["program"]).encode()).hexdigest()[:16]
        directory = self.root / key
        directory.mkdir(exist_ok=True)
        lease = LaneLock(str(directory / ".request.lock"))
        if not lease.acquire():
            raise ValueError("target worker is busy; retry after the current bounded query")
        try:
            current = _json(directory / "current.json")
            ready = _json(Path(current.get("session", str(directory))) / "ready.json")
            alive = _identity(int(ready.get("pid", 0)), int(ready.get("started_ms", 0)))
            sessions = _sessions(directory)
            failure = _json(directory / "startup-failure.json")
            if action == "status":
                return json.dumps(_public({"alive": bool(sessions), "session": current.get("session"), "worker": ready,
                                           "sessions": sessions, "startup_failure": failure or None}))
            if action == "stop":
                stopped = _stop_target(directory)
                return json.dumps({"stopped": True, "session": current.get("session"), "sessions": stopped})
            if failure or any(row["session"] != current.get("session") for row in sessions):
                raise RuntimeError("an uncommitted Ghidra startup/session is reserved for this target; inspect action=status, "
                                   "then use action=stop for verified owned-process cleanup before another launch. Directory: %s" % directory)
            stamp = _source_stamp(project)
            expected = _expected_hash(project)
            worker_hash = hashlib.sha256(Path(__file__).with_name("scripts").joinpath("RusticQuery.java").read_bytes()).hexdigest()
            transport_hash = hashlib.sha256(Path(__file__).with_name("runtime_ipc.py").read_bytes()).hexdigest()
            version = {"source": stamp, "sha256": expected, "worker": worker_hash, "transport": transport_hash}
            if alive and current.get("version") != version:
                self._retire(directory, current["session"], ready, "source or worker changed")
                alive = False
            cold = not alive
            startup = time.monotonic()
            if cold:
                current, ready = self._start(directory, project, version)
            if address.startswith("rva:"):
                if not ready.get("image_base"):
                    raise RuntimeError("worker did not report its analysed image base; no RVA query was sent")
                address = hex(int(ready["image_base"], 16) + int(address[4:].removeprefix("0x"), 16))
            elif address.startswith("va:"):
                address = hex(int(address[3:].removeprefix("0x"), 16))
            startup_s = time.monotonic() - startup if cold else 0
            session = Path(current["session"])
            request_id = uuid.uuid4().hex
            request = {"id": request_id, "action": action, "address": address, "limit": limit,
                       "cursor": cursor, "contains": contains, "timeout_s": timeout_s,
                       "options": options, "overlays": load_overlays(self.settings["root"], key, expected)}
            started = time.monotonic()
            try:
                endpoint = ready.get("ipc")
                if not isinstance(endpoint, dict):
                    raise ValueError("worker did not publish an authenticated local query endpoint")
                response = rpc(endpoint, request, timeout_s + 2, request_limit=32 * 1024 * 1024,
                               response_limit=16 * 1024 * 1024)
            except TimeoutError as error:
                self._retire(directory, session, ready, "query RPC deadline exceeded")
                raise TimeoutError("Ghidra query exceeded %ss; worker retired. Next call starts a fresh session. Log: %s"
                                   % (timeout_s, session / "worker.log")) from error
            except (OSError, ValueError) as error:
                alive = _identity(int(ready["pid"]), int(ready["started_ms"]))
                self._retire(directory, session, ready, "query RPC transport failed: %s" % error)
                detail = "worker exited" if not alive else "transport failed"
                raise RuntimeError("Ghidra query %s; worker retired. Next call starts a fresh session. Log: %s; %s"
                                   % (detail, session / "worker.log", error)) from error
            response.update(cold=cold, startup_s=round(startup_s, 3), query_s=round(time.monotonic() - started, 3),
                            session=str(session), log=str(session / "worker.log"))
            if not response.get("ok"):
                # Explicit backend validation/miss results leave the JVM usable.
                # Unknown errors, mutation failures and decompiler faults retire it.
                if response.get("recoverable") is not True or action == "type_edit":
                    self._retire(directory, session, ready, str(response.get("error", "query failed")))
                raise RuntimeError(json.dumps(_public(response)))
            if action == "type_edit":
                try:
                    record = save_overlay(self.settings["root"], key, expected,
                                          {"id": request_id, "address": address, "options": options})
                except Exception as error:
                    self._retire(directory, session, ready, "overlay persistence failed: %s" % error)
                    raise
                response["overlay_id"] = record["id"]
                response["persistence"] = "build-bound overlay; canonical project unchanged"
            return json.dumps(_public(response), ensure_ascii=False)
        finally:
            lease.release()

    def _retire(self, directory: Path, session: str | Path, ready: dict, reason: str) -> None:
        try:
            _stop(ready)
        except Exception as cleanup:
            reservation = directory / "startup-failure.json"
            _write(reservation, {"state": "cleanup_failed", "session": str(session), "launcher": ready,
                                 "log": str(Path(session) / "worker.log"), "error": reason[:4096],
                                 "cleanup_error": str(cleanup)[:4096]})
            raise RuntimeError("owned Ghidra retirement cleanup is unconfirmed; target reserved at %s; "
                               "use action=status/stop before querying again: %s" % (reservation, cleanup)) from cleanup

    def _start(self, directory: Path, project: dict, version: dict) -> tuple[dict, dict]:
        capacity = LaneLock(str(self.root / ".startup.lock"))
        if not capacity.acquire():
            raise ValueError("another worker is starting; retry shortly")
        process = None
        reservation = directory / "startup-failure.json"
        launch = {}
        ready = {}
        try:
            active = sum(_reserved_workers(path) for path in self.root.iterdir() if path.is_dir())
            if active >= int(self.settings.get("query_workers", 2)):
                raise ValueError("query worker limit reached; use ghidra-query action=stop on an idle target")
            session = directory / uuid.uuid4().hex[:12]
            session.mkdir()
            # The target request lock guards preparation; no other caller can copy here.
            snapshot = session / "project"
            self.runner.ensure_snapshot(str(snapshot), project)
            scripts = Path(__file__).with_name("scripts")
            log = session / "worker.log"
            command = build_command(self.settings["ghidra_dir"], str(snapshot), project["name"],
                                    project["program"], str(scripts), "RusticQuery.java",
                                    [str(session), version["sha256"], str(int(self.settings.get("query_idle_s", 300)))],
                                    str(session / "ghidra.log"), int(self.settings.get("max_cpu", 4)))
            env = ghidra_environment(self.settings)
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
            # Reserve before Popen: even a later filesystem error must not make
            # an unconfirmed live child look like a free target/capacity slot.
            launch = {"state": "starting", "session": str(session), "log": str(log)}
            _write(reservation, launch)
            with log.open("wb") as output:
                process = subprocess.Popen(launch_command(command), env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=output, **options)
            launch["launcher"] = {"pid": process.pid, "started_ms": _process_start_ms(process.pid), "group_id": process.pid}
            _write(reservation, launch)
            started = time.monotonic()
            deadline = started + int(self.settings.get("query_startup_s", 180))
            while time.monotonic() < deadline:
                ready = _json(session / "ready.json")
                if ready:
                    if not ready.get("ok"):
                        raise RuntimeError("Ghidra refused the project: %s. Log: %s" % (ready.get("error"), log))
                    current = {"session": str(session), "version": version, "command": command}
                    ready["group_id"] = process.pid
                    _write(session / "ready.json", ready)
                    _write(directory / "current.json", current)
                    reservation.unlink()
                    return current, ready
                if process.poll() is not None:
                    raise RuntimeError("Ghidra exited %s before ready; inspect %s" % (process.returncode, log))
                time.sleep(0.1)
            raise TimeoutError("Ghidra startup exceeded %ss; inspect %s" % (self.settings.get("query_startup_s", 180), log))
        except Exception as error:
            if process is not None:
                try:
                    if process.poll() is None:
                        _terminate_owned_tree(process)
                    elif ready and _identity(int(ready.get("pid", 0)), int(ready.get("started_ms", 0))):
                        _stop(ready)
                except Exception as cleanup:
                    launch.update(state="cleanup_failed", error=str(error), cleanup_error=str(cleanup))
                    try:
                        _write(reservation, launch)
                    except OSError as metadata:
                        raise RuntimeError("owned Ghidra startup cleanup is unconfirmed; reservation retained at %s; "
                                           "metadata update failed: %s; log=%s" % (reservation, metadata, launch.get("log"))) from error
                    raise RuntimeError("owned Ghidra startup cleanup is unconfirmed; reservation retained at %s; "
                                       "use action=status/stop; cleanup=%s; log=%s" % (reservation, cleanup, launch.get("log"))) from error
            if reservation.exists():
                reservation.unlink()
            raise
        finally:
            capacity.release()
