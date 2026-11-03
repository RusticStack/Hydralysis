"""Durable, resumable file exports from already analysed projects.

MCP returns job metadata. Function bodies and recovered types are streamed to
owned JSONL files, never forced through a tool reply or a repeated import.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path

from hydralysis import hydra, proc, targets, workcopy
from hydralysis.backends import read_json, root_path, write_json
from hydralysis.locks import held as _held
from hydralysis.preparation import locked, process_start_ms

ACTIVE = ("queued", "running", "cancelling")
MAX_OUTPUT_BYTES = 1024 * 1024 * 1024
MAX_ROW_BYTES = 16 * 1024 * 1024


def job_path(settings: dict, job_id: str) -> Path:
    if not re.fullmatch(r"export-[0-9a-f]{12}", job_id):
        raise ValueError("invalid export job id")
    return root_path(settings) / "exports" / job_id / "job.json"


def update(path: Path, **changes) -> dict:
    with locked(path.with_suffix(".meta.lock")):
        record = read_json(path)
        record.update(changes, updated_at=time.time())
        write_json(path, record)
        return record


def normalized(options: dict | None) -> dict:
    if options is not None and not isinstance(options, dict):
        raise ValueError("export options must be an object")
    options = dict(options or {})
    unknown = set(options) - {"mode", "limit", "contains", "timeout_s", "resume", "out", "start", "end", "regex", "view"}
    if unknown:
        raise ValueError("unknown export options: " + ", ".join(sorted(unknown)))
    mode = options.get("mode", "decompile")
    if mode not in ("decompile", "functions", "types"):
        raise ValueError("export mode must be decompile, functions or types")
    count, timeout = options.get("limit", 100000), options.get("timeout_s", 30)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 100000:
        raise ValueError("export limit must be an integer in 1..100000")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 300:
        raise ValueError("export timeout_s must be an integer in 1..300")
    contains = options.get("contains", "")
    if not isinstance(contains, str) or len(contains) > 256 or "\0" in contains:
        raise ValueError("export contains must be text of at most 256 characters")
    result = {"mode": mode, "limit": count, "contains": contains, "timeout_s": timeout}
    view = workcopy.with_view({"key": "validation"}, options.get("view", ""))["view"]
    if view != "shared":
        result["view"] = view
    for name in ("start", "end"):
        if name in options:
            value = options[name]
            if not isinstance(value, str) or not re.fullmatch(r"(?:va:)?(?:0x)?[0-9a-fA-F]{1,16}", value):
                raise ValueError("export %s must be a numeric VA such as 0x140001000" % name)
            if mode == "types":
                raise ValueError("export start/end select functions; types are filtered by contains/regex")
            result[name] = hex(int(value.removeprefix("va:"), 16))
    if "start" in result and "end" in result and int(result["end"], 16) < int(result["start"], 16):
        raise ValueError("export end precedes start")
    if "regex" in options:
        pattern = options["regex"]
        if not isinstance(pattern, str) or not 0 < len(pattern) <= 512:
            raise ValueError("export regex must be a pattern of at most 512 characters")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError("export regex does not compile: %s" % exc) from exc
        result["regex"] = pattern
    if "out" in options:
        out = options["out"]
        if not isinstance(out, str) or not Path(out).is_absolute() or not out.endswith(".jsonl"):
            raise ValueError("export out must be an absolute path ending in .jsonl")
        destination = Path(out).resolve()
        if not destination.parent.is_dir():
            raise ValueError("export out folder does not exist: %s" % destination.parent)
        if any(part.endswith(".rep") for part in destination.parts):
            raise ValueError("export out must not be inside a Ghidra project")
        result["out"] = str(destination)
    return result


def code_sha256() -> str:
    package = Path(__file__).parent
    code = hashlib.sha256()
    for name in ("query.py", "analysis.py", "exporting.py", "export_worker.py", "workcopy.py", "hydra.py", "targets.py",
                 "scripts/RusticQuery.java"):
        code.update(name.encode())
        code.update((package / name).read_bytes())
    return code.hexdigest()


def master_revision(settings: dict, selected: dict) -> str | None:
    """The saved state the export reads: the master's revision as the engine computes it."""
    opened = hydra.Engine(settings).call("open_project", path=selected["gpr"])
    return opened.get("revision")


def provenance(settings: dict, target: str, view: str = "") -> tuple[dict, dict]:
    selected = workcopy.with_view(targets.resolve(settings, target), view)
    project = dict(targets.configured(settings)[target])
    result = {"version": 2, "gpr": str(Path(selected["gpr"]).resolve()), "program": selected["program"],
              "sha256": selected["sha256"], "master_revision": master_revision(settings, selected),
              "code_sha256": code_sha256(), "overlay_state": workcopy.expected_state(settings, selected),
              "engine_release": hydra.RELEASE, "query_key": selected["key"]}
    if selected["view"] != "shared":
        result["view"] = selected["view"]
    if selected.get("lineage"):
        # The header names the generation the export reads (4.7): a commit moves it, and a resume is then refused because
        # the recorded provenance no longer equals the observed one (generation, master revision and engine release included).
        result["lineage"] = selected["lineage"]["id"]
        result["generation"] = selected["lineage"]["generation"]
    if project.get("exe"):
        stat = Path(project["exe"]).stat()
        result["exe_stat"] = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    return project, result


def worker_settings(settings: dict, target: str, project: dict) -> dict:
    fields = ("root", "hydra_dir", "hydra_client", "java_home", "hydra_idle_s", "hydra_keep_warm_s", "hydra_max_heap",
              "hydra_allow_unpinned", "hydra", "fork_mode", "fork_max_copy_mb", "forbidden_drives")
    result = {name: settings[name] for name in fields if name in settings}
    result["root"] = str(root_path(settings))
    result["targets"] = {target: project}
    return result


def _launch(path: Path, record: dict, settings: dict) -> dict:
    generation = uuid.uuid4().hex
    record = update(path, state="queued", stage="starting", generation=generation, cancel_requested=False,
                    worker_pid=0, worker_started_ms=0, error="", queued_at=time.time())
    env = dict(os.environ)
    # The user site is ignored; Hydralysis's own dependencies come from where this process found them.
    env["PYTHONPATH"] = proc.worker_path()
    env["HYDRALYSIS_HARNESS"] = hydra.identity()["harness"]
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [sys.executable, "-m", "hydralysis.export_worker", str(path), generation]
    try:
        with Path(record["log_path"]).open("ab") as output:
            process = proc.popen(command, env=env, stdout=output, stderr=output,
                                 **({} if os.name == "nt" else {"start_new_session": True}))
    except OSError as exc:
        update(path, state="failed", stage="launch", error=str(exc))
        raise
    # A venv launcher may spawn the real Python process. The child replaces
    # this provisional identity immediately after acquiring its run lock.
    with locked(path.with_suffix(".meta.lock")):
        current = read_json(path)
        if current.get("generation") == generation and current.get("state") == "queued":
            current.update(worker_pid=process.pid, worker_started_ms=process_start_ms(process.pid), updated_at=time.time())
            write_json(path, current)
    return status(settings, record["id"])


def start(settings: dict, target: str, options: dict | None = None) -> dict:
    if options is not None and not isinstance(options, dict):
        raise ValueError("export options must be an object")
    options = dict(options or {})
    resume = str(options.get("resume") or "")
    if resume:
        path = job_path(settings, resume)
        with locked(path.parent / ".control.lock"):
            record = status(settings, resume)
            if record["target"] != target:
                raise ValueError("export resume target differs from the recorded target")
            if record.get("state") in ACTIVE or _held(str(path.parent / ".run.lock")):
                raise ValueError("export is already running; no duplicate worker was launched")
            supplied = {key: value for key, value in options.items() if key != "resume"}
            if any(key not in record["options"] or record["options"][key] != value for key, value in supplied.items()):
                raise ValueError("resume cannot change the recorded export mode, filter, limit or timeout")
            project, observed = provenance(settings, target, record["options"].get("view", ""))
            if observed != record["provenance"]:
                raise ValueError("export source/build/code/overlays changed; resume refused; old output preserved")
            from hydralysis.export_worker import load_snapshot, replay, validate_completed
            # The snapshot taken at export start is part of what a resume stands on: a missing or edited one is refused.
            load_snapshot(path, record)
            if record.get("state") == "done":
                validate_completed(path, record)
                return {**record, "reused": True}
            replay(path, record)
            return _launch(path, record, settings)
    selected = normalized(options)
    project, identity = provenance(settings, target, selected.get("view", ""))
    directory = root_path(settings) / "exports"
    with locked(directory / ".start.lock"):
        for existing in sorted(directory.glob("export-*/job.json"), key=lambda item: item.stat().st_mtime_ns, reverse=True)[:200]:
            previous = read_json(existing)
            if (previous.get("target") == target and previous.get("options") == selected
                    and previous.get("provenance") == identity and previous.get("state") in (*ACTIVE, "done")):
                observed = status(settings, previous["id"])
                if observed["state"] in (*ACTIVE, "done"):
                    if observed["state"] == "done":
                        from hydralysis.export_worker import validate_completed
                        validate_completed(existing, observed)
                    return {**observed, "reused": True}
        return _new(settings, target, project, identity, selected)


def _new(settings: dict, target: str, project: dict, identity: dict, selected: dict) -> dict:
    job_id = "export-" + uuid.uuid4().hex[:12]
    path = job_path(settings, job_id)
    path.parent.mkdir(parents=True, exist_ok=False)
    record = {"version": 1, "id": job_id, "target": target, "created_at": time.time(), "updated_at": time.time(),
              "options": selected, "provenance": identity, "settings": worker_settings(settings, target, project),
              "state": "queued", "stage": "starting", "cursor": "", "completed": 0, "succeeded": 0,
              "failed": 0, "truncated": 0, "output_bytes": 0, "cancel_requested": False,
              "output_path": selected.get("out") or str(path.parent / (selected["mode"] + ".jsonl")),
              "imports_path": str(path.parent / "imports.json"), "log_path": str(path.parent / "worker.log")}
    from hydralysis import jobowner
    token = jobowner.issue(record)
    write_json(path, record)
    with locked(path.parent / ".control.lock"):
        return {**_launch(path, record, settings), "owner_token": token}


def status(settings: dict, job_id: str) -> dict:
    path = job_path(settings, job_id)
    record = read_json(path)
    if not record:
        raise ValueError("no export job %s" % job_id)
    if record.get("state") in ACTIVE and time.time() - record.get("queued_at", record["created_at"]) > 5:
        pid, created = int(record.get("worker_pid", 0)), int(record.get("worker_started_ms", 0))
        alive = pid > 0 and created > 0 and process_start_ms(pid) == created
        if not alive and not _held(str(path.parent / ".run.lock")):
            record = update(path, state="interrupted", stage="interrupted", error="export worker exited; output preserved; resume this id to continue")
    # Worker settings are internal configuration, not part of every MCP reply.
    from hydralysis.jobowner import public
    result = public({key: value for key, value in record.items() if key != "settings"})
    log = Path(record["log_path"])
    if log.is_file():
        with log.open("rb") as handle:
            handle.seek(max(0, log.stat().st_size - 2000))
            result["log_tail"] = handle.read(2000).decode("utf-8", "replace")
    return result


def cancel(settings: dict, job_id: str, owner: str = "") -> dict:
    from hydralysis.jobowner import check
    path = job_path(settings, job_id)
    check(read_json(path), owner)
    record = status(settings, job_id)
    if record.get("state") in ACTIVE:
        update(path, cancel_requested=True, state="cancelling", stage="waiting for the current bounded query")
    elif record.get("state") in ("paused", "interrupted"):
        # No worker is running: nothing will observe a flag, so the job is closed here, under the control lock that
        # also serialises a resume. The output stays for a later resume; the cancel is not lost.
        with locked(path.parent / ".control.lock"):
            if not _held(str(path.parent / ".run.lock")) and read_json(path).get("state") in ("paused", "interrupted"):
                update(path, state="cancelled", stage="cancelled while " + record["state"], cancel_requested=False,
                       complete=False, all_succeeded=False)
    return status(settings, job_id)


# --- HYDRALYSIS_IMPL=rust ----------------------------------------------------------------------------------------
def _delegating_code_sha256(python_impl):
    names = ("query.py", "analysis.py", "exporting.py", "export_worker.py", "workcopy.py", "hydra.py", "targets.py",
             "scripts/RusticQuery.java")

    def code_sha256_():
        if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() == "rust":
            try:
                import hydralysis_native as native
                return native.export_code_sha256_rs(str(Path(__file__).parent), list(names))
            except (ImportError, AttributeError, OSError):
                pass
        return python_impl()
    code_sha256_.__name__ = python_impl.__name__
    code_sha256_.__doc__ = python_impl.__doc__
    return code_sha256_


code_sha256 = _delegating_code_sha256(code_sha256)
