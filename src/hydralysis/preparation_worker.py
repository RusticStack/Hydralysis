"""Background worker for setup and the one initial analysis of a fresh executable.

The import runs inside the engine (one long request on this worker's own
connection). Cancelling the job cancels that request; if this worker dies, the
engine cancels it, and a cancelled import leaves no program in the project.
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from pathlib import Path

from hydralysis import hydra
from hydralysis.backends import ensure, read_json, resolved, root_path, sha256
from hydralysis.preparation import locked, process_start_ms, register, update_job


def _log(path: Path, line: str) -> None:
    with Path(read_json(path)["log_path"]).open("a", encoding="utf-8") as output:
        output.write(time.strftime("%H:%M:%S ") + line.rstrip() + "\n")


def _prepare(path: Path, record: dict, settings: dict, cancelled) -> None:
    settings = resolved(settings)
    engine = hydra.Engine(settings, role="prepare")
    lease_path = root_path(settings) / "preparation" / "build-locks" / (record["sha256"] + ".lock")
    with locked(lease_path, timeout_s=10):
        source = Path(record["exe"])
        if sha256(source) != record["sha256"]:
            raise ValueError("binary changed before analysis; no import started")
        directory = root_path(settings) / "projects" / record["sha256"][:16] / record["job_id"]
        directory.mkdir(parents=True)
        binary = directory / source.name
        shutil.copy2(source, binary)
        if sha256(binary) != record["sha256"]:
            raise ValueError("binary changed during snapshot; no import started")
        created = engine.call("script", script="RusticSetup.java", program=None,
                              args=[str(directory / "project"), "analysis"], timeout=120)
        gpr = directory / "project" / "analysis.gpr"
        if not gpr.is_file():
            raise RuntimeError("project creation did not produce %s: %s" % (gpr, created.get("output")))
        opened = engine.call("open_project", path=str(gpr), writable=True)
        update_job(path, stage="analysing", project_dir=str(directory), analysis_started_at=time.time())
        engine.on_event(lambda event: _log(path, "%s %s/%s" % (event.get("message", ""), event.get("progress", ""),
                                                                event.get("maximum", ""))))
        # A job waits its turn for one of the engine's long slots rather than failing busy.
        request = engine.send("import", file=str(binary), project=opened["id"], analyze=True,
                              timeout=int(record["timeout_s"]), wait=int(record["timeout_s"]) * 1000)
        update_job(path, engine_request=request)
        outcome: dict = {}

        def wait():
            try:
                outcome["result"] = engine.wait(request, "import")
            except Exception as exc:  # carried to the main thread
                outcome["error"] = exc

        waiter = threading.Thread(target=wait, daemon=True)
        waiter.start()
        while waiter.is_alive():
            if cancelled():
                engine.cancel(request)
                waiter.join(60)
                raise InterruptedError("analysis cancelled; the engine discarded the unsaved import")
            waiter.join(0.5)
        if "error" in outcome:
            raise outcome["error"]
        result = outcome["result"]
        if not result.get("imported"):
            raise RuntimeError("engine did not import the file: %s" % result)
        program = result["path"]
        info = engine.call("info", program=result["key"])
        if str(info.get("sha256", "")).lower() != record["sha256"] or not info.get("analyzed"):
            raise RuntimeError("analysis did not verify: sha256=%s analyzed=%s" % (info.get("sha256"), info.get("analyzed")))
        if result.get("analysis", {}).get("cancelled"):
            raise RuntimeError("analysis was cancelled or timed out inside the engine: %s" % result.get("analysis"))
        if sha256(source) != record["sha256"]:
            raise ValueError("original binary changed during analysis; project retained but target not registered")
        engine.call("close_project", project=opened["id"])
        update_job(path, stage="registering", verification={"sha256": info.get("sha256"), "functions": info.get("functions"),
                                                             "analyzed": info.get("analyzed"), "program": program})
        project = {"gpr": str(gpr), "program": program, "exe": str(source), "sha256": record["sha256"],
                   "prepared_job": record["job_id"], "functions": info.get("functions"), "engine": "hydra"}
        with locked(root_path(settings) / ".preparation.lock"):
            if cancelled():
                raise InterruptedError("cancelled before target registration")
            latest = read_json(path)
            register(settings, latest.get("aliases", [record["target"]]), project)
            update_job(path, state="done", stage="ready", project=project, finished_at=time.time(),
                       analysis=result.get("analysis"), import_seconds=result.get("importSeconds"))


def run(path: Path) -> None:
    settings = read_json(path.parent / "settings.json")
    record = read_json(path)
    cancelled = lambda: (path.parent / "cancel.request").exists()
    update_job(path, worker_pid=os.getpid(), worker_started_ms=process_start_ms(os.getpid()), state="running", stage="setup")
    try:
        if cancelled():
            raise InterruptedError("job cancelled before backend setup")
        if record["kind"] == "install" and record.get("component") == "runtime":
            from hydralysis.runtime import setup as setup_runtime
            observed = setup_runtime(settings)
            if cancelled():
                raise InterruptedError("runtime setup completed after cancellation; installed artifacts retained")
            update_job(path, state="done", stage="ready", backend=observed, finished_at=time.time())
            return
        settings = ensure(settings, bool(record.get("install")), cancelled)
        if record["kind"] == "install":
            update_job(path, state="done", stage="ready", finished_at=time.time(),
                       backend={key: settings[key] for key in ("hydra_dir", "hydra_client", "java_home")})
            return
        _prepare(path, record, settings, cancelled)
    except InterruptedError as exc:
        update_job(path, state="cancelled", stage="cancelled", error=str(exc), finished_at=time.time())
    except Exception as exc:
        update_job(path, state="failed", stage="failed", error="%s: %s" % (type(exc).__name__, exc), finished_at=time.time())
        print("Preparation failed:", repr(exc), flush=True)


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())
