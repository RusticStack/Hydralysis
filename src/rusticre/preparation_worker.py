"""Owned background worker for setup and the one initial Ghidra analysis."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from rusticre import proc
from rusticre.backends import ensure, read_json, root_path, sha256
from rusticre.ghidra import LaneLock, _terminate_owned_tree, ghidra_environment, headless_path, launch_command
from rusticre.preparation import locked, process_start_ms, register, update_job


def build_analysis_command(settings: dict, directory: Path, binary: Path, verification: Path, timeout_s: int) -> list[str]:
    scripts = Path(__file__).with_name("scripts")
    args = [headless_path(settings["ghidra_dir"]), str(directory), "analysis", "-import", str(binary),
            "-max-cpu", str(int(settings.get("max_cpu", 4))), "-analysisTimeoutPerFile", str(timeout_s),
            "-scriptPath", str(scripts), "-log", str(verification.parent / "ghidra.log"),
            "-scriptlog", str(verification.parent / "script.log"), "-postScript", "RusticPrepare.java",
            sha256(binary), str(verification)]
    if os.name == "nt":
        if any(re.search(r'[&|<>^%!"\r\n\x00]', arg) for arg in args):
            raise ValueError("Windows analysis arguments must not contain shell metacharacters")
        return ["cmd.exe", "/d", "/c", *args]
    return args


def run(path: Path) -> None:
    settings = read_json(path.parent / "settings.json")
    record = read_json(path)
    cancelled = lambda: (path.parent / "cancel.request").exists()
    process = None
    update_job(path, worker_pid=os.getpid(), worker_started_ms=process_start_ms(os.getpid()), state="running", stage="setup")
    try:
        if cancelled():
            raise InterruptedError("job cancelled before backend setup")
        if record["kind"] == "install" and record.get("component") == "runtime":
            from rusticre.runtime import setup as setup_runtime
            observed = setup_runtime(settings)
            if cancelled():
                raise InterruptedError("runtime setup completed after cancellation; installed artifacts retained")
            update_job(path, state="done", stage="ready", backend=observed, finished_at=time.time())
            return
        settings = ensure(settings, bool(record.get("install")), cancelled)
        if cancelled():
            raise InterruptedError("setup cancelled")
        if record["kind"] == "install":
            update_job(path, state="done", stage="ready", backend={key: settings[key] for key in ("ghidra_dir", "java_home")}, finished_at=time.time())
            return
        lease_path = root_path(settings) / "preparation" / "build-locks" / (record["sha256"] + ".lock")
        with locked(lease_path):
            source = Path(record["exe"])
            if sha256(source) != record["sha256"]:
                raise ValueError("binary changed before analysis; no import started")
            directory = root_path(settings) / "projects" / record["sha256"] / record["job_id"]
            directory.mkdir(parents=True)
            binary = directory / source.name
            shutil.copy2(source, binary)
            if sha256(binary) != record["sha256"]:
                raise ValueError("binary changed during snapshot; no import started")
            verification = path.parent / "verified.json"
            command = build_analysis_command(settings, directory, binary, verification, record["timeout_s"])
            update_job(path, stage="analysing", command=command, project_dir=str(directory), analysis_started_at=time.time())
            options = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
            with Path(record["log_path"]).open("wb") as output:
                process = proc.popen(launch_command(command), stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                           env=ghidra_environment(settings), **options)
            update_job(path, headless_pid=process.pid, headless_started_ms=process_start_ms(process.pid), headless_group_id=process.pid)
            started = time.monotonic()
            while process.poll() is None:
                if cancelled() or time.monotonic() - started >= record["timeout_s"]:
                    reason = "cancelled" if cancelled() else "timeout"
                    try:
                        _terminate_owned_tree(process)
                    except Exception as exc:
                        update_job(path, state="cleanup_failed", stage=reason, error=str(exc), finished_at=time.time())
                        # Do not register or reuse this partially analysed project.
                        return
                    update_job(path, state=reason, stage=reason, exit_code=process.returncode, finished_at=time.time())
                    return
                time.sleep(0.2)
            observed = read_json(verification)
            if cancelled():
                raise InterruptedError("analysis finished after cancellation; project retained without registration")
            failed_line = ""
            with Path(record["log_path"]).open(encoding="utf-8", errors="replace") as log:
                for line in log:
                    if re.match(r"^(?:ERROR|SEVERE)\s", line):
                        failed_line = line.strip()[:1000]
            if process.returncode != 0 or failed_line or not observed.get("analysed") or observed.get("sha256") != record["sha256"]:
                raise RuntimeError("analysis did not verify: exit=%s %s verification=%s; inspect %s" % (process.returncode, failed_line, observed, record["log_path"]))
            if not (directory / "analysis.gpr").is_file() or not (directory / "analysis.rep").is_dir():
                raise RuntimeError("headless did not save the analysed project")
            if sha256(source) != record["sha256"]:
                raise ValueError("original binary changed during analysis; project retained but target not registered")
            update_job(path, stage="registering", verification=observed)
            project = {"dir": str(directory), "name": "analysis", "program": observed["program"], "exe": str(source),
                       "sha256": record["sha256"], "prepared_job": record["job_id"]}
            # The global prepare lock makes alias additions and final registration atomic.
            with locked(root_path(settings) / ".preparation.lock"):
                if cancelled():
                    raise InterruptedError("cancelled before target registration")
                latest = read_json(path)
                register(settings, latest.get("aliases", [record["target"]]), project)
                update_job(path, state="done", stage="ready", project=project, exit_code=process.returncode, finished_at=time.time())
    except InterruptedError as exc:
        update_job(path, state="cancelled", stage="cancelled", error=str(exc), finished_at=time.time())
    except Exception as exc:
        # Metadata/logging failures after Popen must not orphan a live JVM and
        # make this build appear retryable while it still owns a project lock.
        if process is not None and process.poll() is None:
            try:
                _terminate_owned_tree(process)
            except Exception as cleanup:
                update_job(path, state="cleanup_failed", stage="cleanup", headless_pid=process.pid,
                           headless_started_ms=process_start_ms(process.pid), headless_group_id=process.pid,
                           error="%s: %s; owned headless cleanup failed: %s" % (type(exc).__name__, exc, cleanup),
                           finished_at=time.time())
                return
        update_job(path, state="failed", stage="failed", error="%s: %s" % (type(exc).__name__, exc), finished_at=time.time())
        print("Preparation failed:", repr(exc), flush=True)


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())
