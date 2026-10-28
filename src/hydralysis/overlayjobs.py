"""Bulk overlay work as durable jobs: type imports, and rebuilds that must replay them.

A corpus of 16,000 classes takes minutes to apply, longer than a tool call
should hold. The job runs in its own process with its own engine connection.
Cancelling it ends that process: the engine cancels its running request and
rolls back the uncommitted transaction, so the working copy is either at the
new state or unchanged, and the overlay store records nothing for it.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import uuid
from pathlib import Path

from hydralysis import hydra, proc
from hydralysis.backends import read_json, write_json
from hydralysis.locks import locked
from hydralysis.paths import root_path

ACTIVE = ("queued", "running", "cancelling")
TIMEOUT_S = 4 * 3600


def job_path(settings: dict, job_id: str) -> Path:
    if not re.fullmatch(r"overlay-[0-9a-f]{12}", job_id):
        raise ValueError("invalid overlay job id")
    return root_path(settings) / "overlay-jobs" / job_id / "job.json"


def _update(path: Path, **changes) -> dict:
    with locked(path.with_suffix(".lock"), what="overlay job"):
        record = read_json(path)
        record.update(changes, updated_at=time.time())
        write_json(path, record)
        return record


def _alive(record: dict) -> bool:
    return proc.identity(int(record.get("worker_pid", 0)), int(record.get("worker_started_ms", 0)))


def active(settings: dict, target: str, view: str = "") -> dict | None:
    directory = root_path(settings) / "overlay-jobs"
    for path in sorted(directory.glob("overlay-*/job.json"), key=lambda item: item.stat().st_mtime_ns, reverse=True)[:50]:
        record = status(settings, path.parent.name)
        if (record.get("target") == target and record.get("view", "") == view
                and record.get("state") in ACTIVE):
            return record
    return None


def start(settings: dict, target: str, kind: str, address: str = "", options: dict | None = None,
          view: str = "") -> dict:
    """kind: edit (apply and record one bulk overlay), sync (rebuild the working copy), commit, diff or publish."""
    root = root_path(settings)
    with locked(root / "overlay-jobs" / ".start.lock", what="overlay jobs"):
        view = "" if view == "shared" else view
        running = active(settings, target, view)
        if running and kind == "sync" and running["kind"] == "sync":
            return {**running, "reused": True}
        job_id = "overlay-" + uuid.uuid4().hex[:12]
        path = job_path(settings, job_id)
        path.parent.mkdir(parents=True)
        record = {"id": job_id, "kind": kind, "target": target, "view": view, "address": address, "options": options or {},
                  "state": "queued", "created_at": time.time(), "by": hydra.identity(),
                  "log_path": str(path.parent / "worker.log")}
        from hydralysis import jobowner
        token = jobowner.issue(record)
        write_json(path, record)
        keys = ("root", "hydra_dir", "hydra_client", "java_home", "hydra_idle_s", "hydra_keep_warm_s", "hydra_max_heap",
                "hydra_allow_unpinned", "hydra", "fork_mode", "fork_max_copy_mb", "forbidden_drives", "targets", "expected_agents")
        write_json(path.parent / "settings.json", {key: settings[key] for key in keys if key in settings})
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent),
                   HYDRALYSIS_HARNESS=hydra.identity()["harness"])
        with Path(record["log_path"]).open("ab") as log:
            child = proc.popen([sys.executable, "-m", "hydralysis.overlayjobs", str(path)], env=env, stdout=log, stderr=log,
                               **({} if os.name == "nt" else {"start_new_session": True}))
        # A Windows venv launcher may have already started the real worker,
        # which publishes its own identity before this parent resumes.
        with locked(path.with_suffix(".lock"), what="overlay job"):
            current = read_json(path)
            if current.get("state") == "queued" and not current.get("worker_pid"):
                current.update(worker_pid=child.pid, worker_started_ms=proc_start(child.pid), updated_at=time.time())
                write_json(path, current)
        return {**status(settings, job_id), "owner_token": token}


def proc_start(pid: int) -> int:
    from hydralysis.preparation import process_start_ms
    return process_start_ms(pid)


def status(settings: dict, job_id: str) -> dict:
    path = job_path(settings, job_id)
    record = read_json(path)
    if not record:
        raise ValueError("no overlay job %s" % job_id)
    if record.get("state") in ACTIVE and time.time() - record.get("created_at", 0) > 10 and not _alive(record):
        record = _update(path, state="interrupted", error="worker exited; the engine rolled back its uncommitted work",
                         finished_at=time.time())
    record["elapsed_s"] = round(record.get("finished_at", time.time()) - record["created_at"], 2)
    from hydralysis.jobowner import public
    return public(record)


def cancel(settings: dict, job_id: str, owner: str = "") -> dict:
    from hydralysis.jobowner import check
    path = job_path(settings, job_id)
    check(read_json(path), owner)
    record = status(settings, job_id)
    if record.get("state") in ACTIVE:
        (path.parent / "cancel.request").write_text("cancel\n", encoding="utf-8")
        record = _update(path, state="cancelling")
    return record


def run(path: Path) -> None:
    from hydralysis import targets, workcopy
    record = read_json(path)
    settings = read_json(path.parent / "settings.json")
    cancel_file = path.parent / "cancel.request"

    def watch():
        while True:
            if cancel_file.exists():
                _update(path, state="cancelled", finished_at=time.time(),
                        error="cancelled; the engine discards the uncommitted change when this worker exits")
                os._exit(3)
            time.sleep(0.5)

    threading.Thread(target=watch, daemon=True).start()
    _update(path, state="running", worker_pid=os.getpid(), worker_started_ms=proc_start(os.getpid()), started_at=time.time())
    try:
        selected = workcopy.with_view(targets.resolve(settings, record["target"]), record.get("view", ""))
        engine = hydra.Engine(settings)
        if record["kind"] == "diff":
            from hydralysis import crossbuild
            result = crossbuild.run(settings, record, path.parent)
        elif record["kind"] == "edit":
            result = workcopy.edit(settings, engine, selected, record["address"], dict(record["options"]), TIMEOUT_S)
        elif record["kind"] == "commit":
            from hydralysis import commits
            try:
                result = commits.run_commit(settings, selected, dict(record["options"]), engine, TIMEOUT_S)
            except commits.CommitError as error:
                _update(path, state="failed", error="%s: %s" % (error.code, error), error_payload=error.payload(), finished_at=time.time())
                return
        elif record["kind"] == "publish":
            from hydralysis import views
            try:
                result = views.run_publish_job(settings, selected, dict(record["options"]), engine, TIMEOUT_S,
                                               progress=lambda info: _update(path, publish_pending=info))
            except views.ViewError as error:
                _update(path, state="failed", error="%s: %s" % (error.code, error), error_payload=error.payload(), finished_at=time.time())
                return
        else:
            result = workcopy.repair(settings, engine, selected, TIMEOUT_S)
        _update(path, state="done", result=result, finished_at=time.time())
    except Exception as exc:
        _update(path, state="failed", error="%s: %s" % (type(exc).__name__, exc), finished_at=time.time())


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())
