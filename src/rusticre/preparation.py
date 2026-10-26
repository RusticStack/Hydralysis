"""Durable setup and analyse-once jobs, adopting analysed projects, and the target registry.

A fresh executable is imported and analysed once by the engine, in a project of
RusticRE's own, as a background job that outlives the tool call. A build that is
already analysed somewhere is adopted instead: its project opens in place,
read-only, and is named after its program's recorded SHA-256 matches. Engines
are installed only on request (backend install, or install=true).
"""

from __future__ import annotations

import os
import re
import sys
import time
import uuid
from pathlib import Path

from rusticre import proc, targets
from rusticre.backends import inspect, read_json, root_path, sha256, write_json
from rusticre.locks import locked as _locked

ACTIVE = ("queued", "running", "cancelling")


def locked(path: Path, timeout_s: float = 5):
    return _locked(path, timeout_s, "job/target registry")


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
    return targets.registry(settings)


def register(settings: dict, names: list[str], project: dict) -> None:
    targets.register(settings, names, project)


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
            # The engine cancels a request whose client went away; nothing is left running.
            record = update_job(path, state="interrupted", stage="failed",
                                error="preparation worker exited before a terminal result; the engine cancelled its "
                                      "request; inspect the retained log, then prepare again")
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
    keys = ("root", "hydra_dir", "hydra_client", "java_home", "hydra_idle_s", "hydra_keep_warm_s", "hydra_max_heap",
            "hydra_allow_unpinned", "hydra", "fork_mode", "fork_max_copy_mb", "forbidden_drives")
    runtime = {key: settings[key] for key in keys if key in settings}
    runtime["root"] = str(root_path(settings))
    write_json(path.parent / "settings.json", runtime)
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    from rusticre import hydra
    env["RUSTICRE_HARNESS"] = hydra.identity()["harness"]
    options = {} if os.name == "nt" else {"start_new_session": True}
    try:
        with (path.parent / "worker.log").open("wb") as output:
            process = proc.popen([sys.executable, "-m", "rusticre.preparation_worker", str(path)],
                                 stdout=output, stderr=output, env=env, **options)
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
        record = {"job_id": job_id, "kind": "install", "component": component, "state": "queued", "stage": "setup",
                  "created_at": time.time(), "install": True,
                  "log_path": str(job_path(settings, job_id).parent / "worker.log")}
        return _launch(settings, record)


_WRAPPERS = (b".bind", b"upx0", b"upx1", b"upx2", b".aspack", b".adata", b".vmp0", b".vmp1", b".themida")


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
        target = targets.default_name(source.stem, digest)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", target):
        raise ValueError("target must be a simple 1..64 character name")
    preflight = {"format": "engine-detected", "warnings": []}
    with source.open("rb") as handle:
        pe_header = handle.read(2) == b"MZ"
    wrappers = []
    if pe_header:
        from rusticre.pe import Image
        image = Image(source)
        observed = image.fingerprint()
        if observed["sha256"] != digest:
            raise ValueError("binary changed during preflight; use a stable build")
        wrappers = [section.Name.rstrip(b"\0").decode("ascii", "replace") for section in image.sections
                    if section.Name.rstrip(b"\0").lower() in _WRAPPERS]
        preflight = {"format": "PE", "bits": image.bits, "packing_status": observed["packing_status"],
                     "warnings": observed["analysis_warnings"], "wrapper_sections": wrappers}
    return source, digest, after, target, preflight, wrappers


def _known(settings: dict, source: Path, digest: str) -> tuple[str, dict] | None:
    """A registered or configured target that already names this build."""
    for name, item in targets.configured(settings).items():
        expected = str(item.get("sha256") or "").lower()
        same_path = bool(item.get("exe") and Path(item["exe"]).expanduser().resolve() == source)
        if expected == digest or (same_path and not expected):
            return name, item
    return None


def plan(settings: dict, exe: str, target: str = "", timeout_s: int = 3600, install: bool = False) -> dict:
    """Read-only first-use preflight: no job, import, download or launch."""
    source, digest, stat, target, preflight, wrappers = _subject(exe, target, timeout_s)
    backend = inspect(settings)
    known = _known(settings, source, digest)
    configured = targets.configured(settings).get(target)
    return {"kind": "prepare_plan", "state": "blocked" if wrappers else "planned", "target": target,
            "exe": str(source), "sha256": digest, "size": stat.st_size, "timeout_s": timeout_s,
            "preflight": preflight, "backend_ready": backend["ready"], "backend": backend,
            "matching_target": known[0] if known else None, "configured_target": bool(configured),
            "would_import": not wrappers and not known and not configured,
            "would_install": bool(not backend["ready"] and install and not wrappers and not known), "started": False,
            "reason": "needs_unwrapped_artifact" if wrappers
            else "this build already has a target; query it" if known or configured
            else "if this build is already analysed in a Ghidra project, adopt it (prepare action=adopt path=<.gpr or "
                 "folder> exe=...) instead of importing again; otherwise an explicit prepare starts the analysis"}


def prepare(settings: dict, exe: str, target: str = "", timeout_s: int = 3600, install: bool = False) -> dict:
    source, digest, after, target, preflight, wrappers = _subject(exe, target, timeout_s)
    root = root_path(settings)
    with locked(root / ".preparation.lock"):
        existing = targets.configured(settings).get(target)
        if existing:
            existing_hash = str(existing.get("sha256") or "").lower()
            if not existing_hash and existing.get("exe"):
                existing_hash = targets.exe_sha256(settings, existing["exe"])
            if existing_hash != digest:
                raise ValueError("target %s already exists for another build; choose a new build-specific target" % target)
            return {"kind": "prepare", "state": "configured", "started": False, "reused": True,
                    "target": target, "sha256": digest, "project": existing,
                    "reason": "target already names this build; queries verify the saved program before answering"}
        index_path = root / "preparation" / "index.json"
        index = read_json(index_path)
        if digest in index:
            previous = status(settings, index[digest])
            if previous.get("state") == "done" and previous.get("project") and Path(previous["project"]["gpr"]).is_file():
                register(settings, [target], previous["project"])
                return {**previous, "reused": True, "target": target}
            if previous.get("state") in ACTIVE:
                aliases = sorted(set(previous.get("aliases", [previous["target"]])) | {target})
                previous = update_job(job_path(settings, previous["job_id"]), aliases=aliases)
                return {**previous, "reused": True}
            if previous.get("state") == "blocked" and wrappers:
                return {**previous, "reused": True}
        known = _known(settings, source, digest)
        if known:
            return {"kind": "prepare", "state": "configured", "started": False, "reused": True,
                    "target": known[0], "requested_target": target, "sha256": digest, "project": known[1],
                    "reason": "this build already has a target; query the returned one. No alias or import was created."}
        if not wrappers and not install and not inspect(settings)["ready"]:
            raise ValueError("analysis engine is missing; run backend install (or prepare with install=true)")
        job_id = "prepare-" + uuid.uuid4().hex[:12]
        record = {"job_id": job_id, "kind": "prepare", "state": "queued", "stage": "setup", "created_at": time.time(),
                  "target": target, "aliases": [target], "exe": str(source), "sha256": digest, "size": after.st_size,
                  "timeout_s": timeout_s, "install": bool(install), "preflight": preflight,
                  "log_path": str(job_path(settings, job_id).parent / "worker.log")}
        if wrappers:
            record.update(state="blocked", stage="preflight", finished_at=time.time(),
                          error="needs_unwrapped_artifact: known wrapper/packer sections %s; select a legitimate unwrapped "
                                "artifact. No unpacking, launch or import was attempted." % ", ".join(wrappers))
            path = job_path(settings, job_id)
            write_json(path, record)
            index[digest] = job_id
            write_json(index_path, index)
            return record
        result = _launch(settings, record)
        index[digest] = job_id
        write_json(index_path, index)
        return result


def adopt(settings: dict, path: str, exe: str = "", sha256_value: str = "", program: str = "", target: str = "") -> dict:
    """Register an analysed project in place. Fast and synchronous: nothing is imported or copied."""
    from rusticre import hydra
    from rusticre.backends import resolved
    ready = resolved(settings)
    return targets.adopt(ready, hydra.Engine(ready), path, exe=exe, expected=sha256_value, program=program, target=target)
