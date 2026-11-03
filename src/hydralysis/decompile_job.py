"""A decompile that needs the engine's long path (minutes) runs as a job, so a CLI or MCP call does not hang.

`ghidra_query decompile` first asks the RusticQuery script (seconds). When the script cannot answer ("No pcode could be
generated", a timeout, a buffer overflow), or the engine's `decompile` with the caller's `max_result_*`/`offset` does not answer
in time, the query is handed to a worker process that asks the engine's own `decompile` command with a long timeout and
writes the reply (labelled `fallback`) to `result.json`. The caller gets the job at once:
`{"job": "decompile-...", "state": "queued", ...}`; `job` with that id reports progress and, when done, the `result`.
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
from hydralysis.backends import read_json, root_path, write_json
from hydralysis.preparation import process_start_ms

ACTIVE = ("queued", "running")
TICK_S = 5.0


def job_path(settings: dict, job_id: str) -> Path:
    if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() == "rust":
        try:
            import hydralysis_native as native
            found = native.decompile_job_path_rs(str(root_path(settings)), job_id)
        except (ImportError, AttributeError):
            pass
        else:
            return Path(found)
    if not re.fullmatch(r"decompile-[0-9a-f]{12}", job_id):
        raise ValueError("invalid decompile job id")
    return root_path(settings) / "decompile-jobs" / job_id / "job.json"


def _update(path: Path, **changes) -> dict:
    record = read_json(path)
    record.update(changes, updated_at=time.time())
    write_json(path, record)
    return record


def start(settings: dict, call: dict, reason: str) -> dict:
    """Start (or find the running job of) the decompile CALL, a `QueryRunner.query` argument dict."""
    from hydralysis import exporting, targets
    target = call["target"]
    key = {name: call.get(name) for name in ("target", "action", "address", "timeout_s", "options")}
    directory = root_path(settings) / "decompile-jobs"
    directory.mkdir(parents=True, exist_ok=True)
    for existing in sorted(directory.glob("decompile-*/job.json"), key=lambda item: item.stat().st_mtime_ns, reverse=True)[:50]:
        previous = read_json(existing)
        if previous.get("call_key") == key and previous.get("state") in ACTIVE and status(settings, previous["id"])["state"] in ACTIVE:
            return {**status(settings, previous["id"]), "reused": True}
    project = dict(targets.configured(settings)[target])
    job_id = "decompile-" + uuid.uuid4().hex[:12]
    path = job_path(settings, job_id)
    path.parent.mkdir(parents=True, exist_ok=False)
    record = {"version": 1, "id": job_id, "kind": "decompile", "target": target, "call": call, "call_key": key,
              "fallback_reason": reason, "created_at": time.time(), "updated_at": time.time(), "state": "queued",
              "stage": "starting", "settings": exporting.worker_settings(settings, target, project),
              "result_path": str(path.parent / "result.json"), "log_path": str(path.parent / "worker.log")}
    write_json(path, record)
    env = dict(os.environ)
    env["PYTHONPATH"] = proc.worker_path()
    env["HYDRALYSIS_HARNESS"] = hydra.identity()["harness"]
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [sys.executable, "-m", "hydralysis.decompile_job", str(path)]
    try:
        with Path(record["log_path"]).open("ab") as output:
            process = proc.popen(command, env=env, stdout=output, stderr=output,
                                 **({} if os.name == "nt" else {"start_new_session": True}))
    except OSError as exc:
        _update(path, state="failed", stage="launch", error=str(exc))
        raise
    _update(path, worker_pid=process.pid, worker_started_ms=process_start_ms(process.pid))
    return status(settings, job_id)


def status(settings: dict, job_id: str) -> dict:
    path = job_path(settings, job_id)
    record = read_json(path)
    if not record:
        raise ValueError("no decompile job %s" % job_id)
    if record.get("state") in ACTIVE and time.time() - record["created_at"] > 5:
        pid, created = int(record.get("worker_pid", 0)), int(record.get("worker_started_ms", 0))
        if not (pid > 0 and created > 0 and process_start_ms(pid) == created):
            record = _update(path, state="failed", stage="interrupted", error="the decompile worker exited without a result")
    out = {key: value for key, value in record.items() if key not in ("settings", "call_key")}
    if record.get("state") in ACTIVE:
        out["elapsed_s"] = round(time.time() - record["created_at"], 1)
    result = Path(record["result_path"])
    if record.get("state") == "done" and result.is_file():
        out["result"] = json.loads(result.read_text(encoding="utf-8"))
    log = Path(record["log_path"])
    if log.is_file() and record.get("state") != "done":
        with log.open("rb") as handle:
            handle.seek(max(0, log.stat().st_size - 1000))
            out["log_tail"] = handle.read(1000).decode("utf-8", "replace")
    return out


def run(path: Path) -> int:
    from hydralysis.query import QueryRunner
    record = read_json(path)
    started = time.monotonic()
    _update(path, state="running", stage="engine decompile running", worker_pid=os.getpid(),
            worker_started_ms=process_start_ms(os.getpid()))
    stop = threading.Event()

    def tick():
        while not stop.wait(TICK_S):
            _update(path, stage="engine decompile running (%d s)" % (time.monotonic() - started))
    threading.Thread(target=tick, daemon=True).start()
    try:
        runner = QueryRunner(record["settings"])
        runner.inline = True
        call = dict(record["call"])
        options = dict(call.get("options") or {})
        call["options"] = options
        reply = json.loads(runner.query(**call))
        reply.setdefault("fallback", {"via": "engine_decompile", "reason": record.get("fallback_reason", "")})
        reply["fallback"]["job"] = record["id"]
        Path(record["result_path"]).write_text(json.dumps(reply, ensure_ascii=False), encoding="utf-8")
        stop.set()
        _update(path, state="done", stage="done", elapsed_run_s=round(time.monotonic() - started, 1))
        return 0
    except BaseException as exc:  # noqa: BLE001 - the job records every failure
        stop.set()
        _update(path, state="failed", stage="failed", error=str(exc)[:4000], elapsed_run_s=round(time.monotonic() - started, 1))
        return 1


if __name__ == "__main__":
    sys.exit(run(Path(sys.argv[1])))
