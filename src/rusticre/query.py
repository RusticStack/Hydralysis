"""Small address-based queries in a reusable, read-only Ghidra process.

The mailbox is local files, not a network service. Each worker owns a snapshot;
callers serialize through an OS lock. A failed worker is retired, never reused.
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


def _json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


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
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
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
              limit: int = 40, cursor: str = "", contains: str = "", timeout_s: int = 30) -> str:
        if action not in ("decompile", "function", "functions", "xrefs", "status", "stop"):
            raise ValueError("action must be decompile, function, functions, xrefs, status or stop")
        if not 1 <= limit <= 200 or not 1 <= timeout_s <= 300:
            raise ValueError("limit must be 1..200; timeout_s must be 1..300")
        if action in ("decompile", "function", "xrefs") and not address:
            raise ValueError("address is required (a Ghidra VA, for example 0x140001000)")
        for value in (address, cursor):
            if value and not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", value):
                raise ValueError("use a numeric Ghidra VA, not a symbol name")
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
            if action == "status":
                return json.dumps({"alive": alive, "session": current.get("session"), "worker": ready})
            if action == "stop":
                _stop(ready)
                return json.dumps({"stopped": True, "session": current.get("session")})
            stamp = _source_stamp(project)
            expected = _expected_hash(project)
            worker_hash = hashlib.sha256(Path(__file__).with_name("scripts").joinpath("RusticQuery.java").read_bytes()).hexdigest()
            version = {"source": stamp, "sha256": expected, "worker": worker_hash}
            if alive and current.get("version") != version:
                _stop(ready)
                alive = False
            cold = not alive
            startup = time.monotonic()
            if cold:
                current, ready = self._start(directory, project, version)
            startup_s = time.monotonic() - startup if cold else 0
            session = Path(current["session"])
            request_id = uuid.uuid4().hex
            request = {"id": request_id, "action": action, "address": address, "limit": limit,
                       "cursor": cursor, "contains": contains, "timeout_s": timeout_s}
            _write(session / "request.json", request)
            started = time.monotonic()
            deadline = started + timeout_s + 2
            response = {}
            while time.monotonic() < deadline:
                response = _json(session / "response.json")
                if response.get("id") == request_id:
                    break
                if not _identity(int(ready["pid"]), int(ready["started_ms"])):
                    raise RuntimeError("Ghidra worker exited; next call starts a fresh session. Log: %s" % (session / "worker.log"))
                time.sleep(0.05)
            else:
                _stop(ready)
                raise TimeoutError("Ghidra query exceeded %ss; worker retired. Next call starts a fresh session. Log: %s"
                                   % (timeout_s, session / "worker.log"))
            response.update(cold=cold, startup_s=round(startup_s, 3), query_s=round(time.monotonic() - started, 3),
                            session=str(session), log=str(session / "worker.log"))
            if not response.get("ok"):
                # Retire on refusal as well: do not return a poisoned decompiler session.
                _stop(ready)
                raise RuntimeError(json.dumps(response))
            return json.dumps(response, ensure_ascii=False)
        finally:
            lease.release()

    def _start(self, directory: Path, project: dict, version: dict) -> tuple[dict, dict]:
        capacity = LaneLock(str(self.root / ".startup.lock"))
        if not capacity.acquire():
            raise ValueError("another worker is starting; retry shortly")
        try:
            active = 0
            for path in self.root.glob("*/current.json"):
                existing = _json(Path(_json(path).get("session", str(path.parent))) / "ready.json")
                active += bool(_identity(int(existing.get("pid", 0)), int(existing.get("started_ms", 0))))
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
            with log.open("wb") as output:
                process = subprocess.Popen(launch_command(command), env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=output, **options)
            started = time.monotonic()
            deadline = started + int(self.settings.get("query_startup_s", 180))
            while time.monotonic() < deadline:
                ready = _json(session / "ready.json")
                if ready:
                    if not ready.get("ok"):
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            _terminate_owned_tree(process)
                        raise RuntimeError("Ghidra refused the project: %s. Log: %s" % (ready.get("error"), log))
                    current = {"session": str(session), "version": version, "command": command}
                    ready["group_id"] = process.pid
                    _write(session / "ready.json", ready)
                    _write(directory / "current.json", current)
                    return current, ready
                if process.poll() is not None:
                    raise RuntimeError("Ghidra exited %s before ready; inspect %s" % (process.returncode, log))
                time.sleep(0.1)
            # Before ready, we own the launcher Popen; stop its entire process tree.
            _terminate_owned_tree(process)
            raise TimeoutError("Ghidra startup exceeded %ss; inspect %s" % (self.settings.get("query_startup_s", 180), log))
        finally:
            capacity.release()
