"""Durable explicit import/analyse-once jobs and the prepared-target registry."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from rusticre.backends import ensure, inspect, read_json, root_path, sha256, write_json
from rusticre.ghidra import LaneLock

ACTIVE = ("queued", "running", "cancelling")


@contextmanager
def locked(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lease = LaneLock(str(path))
    deadline = time.monotonic() + 5
    while not lease.acquire():
        if time.monotonic() >= deadline:
            raise ValueError("job/target registry is busy; retry shortly")
        time.sleep(0.05)
    try:
        yield
    finally:
        lease.release()


def process_start_ms(pid: int) -> int:
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
            return 0
        try:
            exit_code = wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)) or exit_code.value != 259:
                return 0
            times = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *[ctypes.byref(item) for item in times]):
                return 0
            ticks = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            return ticks // 10000 - 11644473600000
        finally:
            kernel.CloseHandle(handle)
    try:
        process = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
        if process[0] == "Z":
            return 0
        boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
        return int((boot + int(process[19]) / os.sysconf("SC_CLK_TCK")) * 1000)
    except (OSError, ValueError, IndexError, StopIteration):
        return 0


def job_path(settings: dict, job_id: str) -> Path:
    if not re.fullmatch(r"(?:prepare|setup)-[0-9a-f]{12}", job_id):
        raise ValueError("invalid preparation job id")
    return root_path(settings) / "preparation" / "jobs" / job_id / "job.json"


def update_job(path: Path, **changes) -> dict:
    with locked(path.with_suffix(".lock")):
        record = read_json(path)
        record.update(changes, updated_at=time.time())
        write_json(path, record)
    return record


def registry(settings: dict) -> dict:
    return read_json(root_path(settings) / "targets.json").get("targets", {})


def register(settings: dict, names: list[str], project: dict) -> None:
    root = root_path(settings)
    with locked(root / ".targets.lock"):
        data = read_json(root / "targets.json") or {"version": 1, "targets": {}}
        for name in names:
            existing = data["targets"].get(name)
            if existing and existing.get("sha256") != project["sha256"]:
                raise ValueError("target %s already names another build; choose a new target" % name)
        for name in names:
            data["targets"][name] = project
        write_json(root / "targets.json", data)


def _cancel_owned_headless(record: dict) -> None:
    """Retry cleanup only for the recorded launcher with its original identity."""
    pid = int(record.get("headless_pid") or 0)
    started = int(record.get("headless_started_ms") or 0)
    if not pid or not started or process_start_ms(pid) != started:
        raise RuntimeError("cannot verify the original owned headless process; no process was signalled and the build reservation remains")
    if os.name == "nt":
        result = subprocess.run(["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                                capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise RuntimeError("owned process-tree cleanup was not confirmed: %s" % (result.stderr or result.stdout)[-1000:])
    else:
        import signal
        group = int(record.get("headless_group_id") or pid)
        if os.getpgid(pid) != group:
            raise RuntimeError("owned headless process group changed; no group was signalled")
        os.killpg(group, signal.SIGKILL)
    deadline = time.monotonic() + 10
    while process_start_ms(pid) == started and time.monotonic() < deadline:
        time.sleep(0.05)
    if process_start_ms(pid) == started:
        raise RuntimeError("owned headless process has not exited; the build reservation remains")


def status(settings: dict, job_id: str = "", limit: int = 20) -> dict:
    if not 1 <= limit <= 100:
        raise ValueError("job limit must be 1..100")
    if not job_id:
        directory = root_path(settings) / "preparation" / "jobs"
        paths = sorted(directory.glob("*/job.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True)[:limit]
        return {"jobs": [status(settings, p.parent.name) for p in paths]}
    path = job_path(settings, job_id)
    record = read_json(path)
    if not record:
        raise ValueError("no preparation job %s" % job_id)
    if record.get("state") in ACTIVE and time.time() - record.get("created_at", 0) > 5:
        pid, started = record.get("worker_pid", 0), record.get("worker_started_ms", 0)
        if not pid or not started or process_start_ms(pid) != started:
            if record.get("headless_pid"):
                headless_started = record.get("headless_started_ms") or 0
                alive = bool(headless_started and process_start_ms(record["headless_pid"]) == headless_started)
                detail = "the owned headless process is still live" if alive else "headless tree exit was not confirmed"
                record = update_job(path, state="cleanup_failed", stage="cleanup", error="preparation worker exited and %s; build reservation retained. Retry job cancel only for the verified owned process; inspect the retained log." % detail)
            else:
                record = update_job(path, state="interrupted", stage="failed", error="preparation worker exited before a terminal result; inspect the retained log")
    log = Path(record["log_path"])
    if log.is_file():
        with log.open("rb") as handle:
            handle.seek(max(0, log.stat().st_size - 12000))
            tail = handle.read().decode("utf-8", "replace")
        record["progress_tail"] = "\n".join(tail.splitlines()[-12:])
    record["elapsed_s"] = round(record.get("finished_at", time.time()) - record["created_at"], 2)
    return record


def cancel(settings: dict, job_id: str) -> dict:
    record = status(settings, job_id)
    if record["state"] == "cleanup_failed":
        path = job_path(settings, job_id)
        with locked(path.with_suffix(".lock")):
            current = read_json(path)
            if current.get("state") != "cleanup_failed":
                return current
            (path.parent / "cancel.request").write_text("cleanup retry requested\n", encoding="utf-8")
            try:
                _cancel_owned_headless(current)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                current.update(state="cleanup_failed", stage="cleanup", error="%s; reservation retained; log=%s" % (exc, current["log_path"]), updated_at=time.time())
                write_json(path, current)
                raise RuntimeError(current["error"]) from exc
            current.update(state="cancelled", stage="cancelled", cleanup_confirmed=True, previous_error=current.get("error", ""), error="", finished_at=time.time(), updated_at=time.time())
            write_json(path, current)
        return status(settings, job_id)
    if record["state"] not in ACTIVE:
        return record
    path = job_path(settings, job_id)
    with locked(path.with_suffix(".lock")):
        current = read_json(path)
        if current.get("state") not in ACTIVE:
            return current
        (path.parent / "cancel.request").write_text("cancel requested\n", encoding="utf-8")
        current.update(state="cancelling", updated_at=time.time())
        write_json(path, current)
    return status(settings, job_id)


def _launch(settings: dict, record: dict) -> dict:
    path = job_path(settings, record["job_id"])
    path.parent.mkdir(parents=True)
    write_json(path, record)
    runtime = {key: settings[key] for key in ("root", "ghidra_dir", "java_home", "max_mem", "max_cpu") if key in settings}
    runtime["root"] = str(root_path(settings))
    write_json(path.parent / "settings.json", runtime)
    env = dict(os.environ)
    temporary = root_path(settings) / "runtime" / "tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(temporary)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    try:
        with (path.parent / "worker.log").open("wb") as output:
            process = subprocess.Popen([sys.executable, "-m", "rusticre.preparation_worker", str(path)],
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=output, env=env, **options)
        # A Windows venv launcher can spawn the real Python worker. Do not
        # overwrite the child's published identity if it reached running first.
        with locked(path.with_suffix(".lock")):
            current = read_json(path)
            if current.get("state") == "queued" and not current.get("worker_pid"):
                current.update(worker_pid=process.pid, worker_started_ms=process_start_ms(process.pid), updated_at=time.time())
                write_json(path, current)
    except OSError as exc:
        update_job(path, state="failed", stage="launch", finished_at=time.time(), error=str(exc))
        raise
    return read_json(path)


def start_install(settings: dict, component: str = "analysis") -> dict:
    if component not in ("analysis", "runtime"):
        raise ValueError("component must be analysis or runtime")
    root = root_path(settings)
    with locked(root / ".preparation.lock"):
        for path in (root / "preparation" / "jobs").glob("setup-*/job.json"):
            record = status(settings, path.parent.name)
            if record.get("state") in ACTIVE and record.get("component", "analysis") == component:
                return record
        job_id = "setup-" + uuid.uuid4().hex[:12]
        record = {"job_id": job_id, "kind": "install", "component": component, "state": "queued", "stage": "setup", "created_at": time.time(),
                  "install": True, "log_path": str(job_path(settings, job_id).parent / "worker.log")}
        return _launch(settings, record)


def _subject(exe: str, target: str, timeout_s: int) -> tuple:
    if not 30 <= timeout_s <= 14400:
        raise ValueError("analysis timeout_s must be 30..14400 seconds")
    source = Path(exe).expanduser().resolve()
    if not source.is_file():
        raise ValueError("binary is missing: %s" % source)
    before = source.stat()
    digest = sha256(source)
    after = source.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("binary changed while hashing; use a stable build")
    if not target:
        target = re.sub(r"[^A-Za-z0-9._-]", "-", source.stem).strip("-._")[:45] + "-" + digest[:12]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", target):
        raise ValueError("target must be a simple 1..64 character name")
    preflight = {"format": "backend-detected", "warnings": []}
    with source.open("rb") as handle:
        pe_header = handle.read(2) == b"MZ"
    if pe_header:
        from rusticre.pe import Image
        image = Image(source)
        observed = image.fingerprint()
        if observed["sha256"] != digest:
            raise ValueError("binary changed during preflight; use a stable build")
        wrappers = [section.Name.rstrip(b"\0").decode("ascii", "replace") for section in image.sections
                    if section.Name.rstrip(b"\0").lower() in (b".bind", b"upx0", b"upx1", b"upx2", b".aspack", b".adata", b".vmp0", b".vmp1", b".themida")]
        preflight = {"format": "PE", "bits": image.bits, "packing_status": observed["packing_status"],
                     "warnings": observed["analysis_warnings"], "wrapper_sections": wrappers}
    else:
        wrappers = []
    return source, digest, after, target, preflight, wrappers


def _configured_match(settings: dict, source: Path, digest: str) -> tuple[str, dict] | None:
    for name, item in (settings.get("targets") or settings.get("projects") or {}).items():
        expected = str(item.get("sha256") or "").lower()
        same_path = bool(item.get("exe") and Path(item["exe"]).expanduser().resolve() == source)
        if expected == digest or same_path and not expected:
            return name, item
    return None


def plan(settings: dict, exe: str, target: str = "", timeout_s: int = 3600, install: bool = True) -> dict:
    """Read-only first-use preflight: no job, import, download or target launch."""
    source, digest, stat, target, preflight, wrappers = _subject(exe, target, timeout_s)
    backend = inspect(settings)
    existing = next((name for name, item in registry(settings).items() if item.get("sha256") == digest), None)
    configured = (settings.get("targets") or settings.get("projects") or {}).get(target)
    matching = _configured_match(settings, source, digest)
    return {"kind": "prepare_plan", "state": "blocked" if wrappers else "planned", "target": target,
            "exe": str(source), "sha256": digest, "size": stat.st_size, "timeout_s": timeout_s,
            "preflight": preflight, "backend_ready": backend["ready"], "backend": backend,
            "matching_prepared_target": existing, "configured_target": bool(configured),
            "matching_configured_target": matching[0] if matching else None,
            "would_import": not wrappers and not existing and not configured and not matching,
            "would_install": bool(not backend["ready"] and install and not wrappers and not configured and not matching), "started": False,
            "reason": "needs_unwrapped_artifact" if wrappers else "analysis already configured; query the matching existing target" if configured or matching else "explicit prepare is required to start analysis"}


def prepare(settings: dict, exe: str, target: str = "", timeout_s: int = 3600, install: bool = True) -> dict:
    source, digest, after, target, preflight, wrappers = _subject(exe, target, timeout_s)
    root = root_path(settings)
    with locked(root / ".preparation.lock"):
        configured = {**registry(settings), **(settings.get("targets") or settings.get("projects") or {})}
        existing = configured.get(target)
        existing_hash = str(existing.get("sha256") or "").lower() if existing else None
        if existing and not existing_hash and existing.get("exe"):
            existing_hash = sha256(Path(existing["exe"]))
        if existing and existing_hash != digest:
            raise ValueError("target %s already exists; choose a new build-specific target" % target)
        index_path = root / "preparation" / "index.json"
        index = read_json(index_path)
        if digest in index:
            previous = status(settings, index[digest])
            if previous.get("state") == "cleanup_failed":
                raise ValueError("analysis cleanup is unconfirmed for job %s; refusing another import of this build. Use job cancel to retry verified owned-tree cleanup and inspect %s" % (previous["job_id"], previous["log_path"]))
            if previous.get("state") == "done" and Path(previous["project"]["dir"], previous["project"]["name"] + ".gpr").is_file() and Path(previous["project"]["dir"], previous["project"]["name"] + ".rep").is_dir():
                register(settings, [target], previous["project"])
                return {**previous, "reused": True, "target": target}
            if previous.get("state") in ACTIVE:
                aliases = sorted(set(previous.get("aliases", [previous["target"]])) | {target})
                previous = update_job(job_path(settings, previous["job_id"]), aliases=aliases)
                return {**previous, "reused": True}
            if previous.get("state") == "blocked" and wrappers:
                return {**previous, "reused": True}
        if existing:
            # Manually configured analysis predates this job index. Never
            # replace it with an implicit fresh import or pretend it verified.
            return {"kind": "prepare", "state": "configured", "started": False, "reused": True,
                    "target": target, "sha256": digest, "project": existing,
                    "reason": "target already configured; ghidra_query verifies its saved analysis before serving results"}
        matching = _configured_match(settings, source, digest)
        if matching:
            return {"kind": "prepare", "state": "configured", "started": False, "reused": True,
                    "target": matching[0], "requested_target": target, "sha256": digest, "project": matching[1],
                    "reason": "this build already has configured analysis; query the returned target to verify it. No alias or import was created."}
        if not wrappers and not install and not inspect(settings)["ready"]:
            raise ValueError("analysis backend is missing; use install=true or backend install")
        job_id = "prepare-" + uuid.uuid4().hex[:12]
        record = {"job_id": job_id, "kind": "prepare", "state": "queued", "stage": "setup", "created_at": time.time(),
                  "target": target, "aliases": [target], "exe": str(source), "sha256": digest, "size": after.st_size,
                  "timeout_s": timeout_s, "install": bool(install),
                  "preflight": preflight,
                  "log_path": str(job_path(settings, job_id).parent / "headless.log")}
        if wrappers:
            record.update(state="blocked", stage="preflight", finished_at=time.time(),
                          error="needs_unwrapped_artifact: known wrapper/packer sections %s; select a legitimate unwrapped artifact. No unpacking, launch or import was attempted." % ", ".join(wrappers))
            path = job_path(settings, job_id)
            write_json(path, record)
            index[digest] = job_id
            write_json(index_path, index)
            return record
        result = _launch(settings, record)
        index[digest] = job_id
        write_json(index_path, index)
        return result
