"""Run a Ghidra script on a copy of an already analysed project.

The analysed project is opened with `-noanalysis -readOnly`. A run never
re-imports the exe. Each concurrent run gets its own copy, because Ghidra
locks a project directory. The lock is an OS file lock, so two processes
cannot claim the same copy, and it is released if the process is killed.

The script-output filter keeps the lines the script printed and drops
Ghidra's own log. That behaviour comes from the SWTOR `ghidra-batch` server
written on this machine; this module is the version that is not tied to one
game. See THIRD_PARTY.md.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

try:
    import msvcrt
except ImportError:  # pragma: no cover - not Windows
    msvcrt = None
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

SCRIPT_LINE = re.compile(r"^INFO\s+(?P<script>\S+\.(?:java|py))>\s?(?P<text>.*)$")
SCRIPT_END = re.compile(r"\(GhidraScript\)\s*$")
LOG_LINE = re.compile(r"^(?:INFO|ERROR|WARN|DEBUG|SEVERE)\s")


def headless_path(ghidra_dir: str) -> str:
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    return os.path.join(ghidra_dir, "support", name)


def build_command(
    ghidra_dir: str,
    lane_dir: str,
    project_name: str,
    program: str,
    script_dir: str,
    script: str,
    script_args: list[str],
    log_path: str,
    max_cpu: int,
) -> list[str]:
    args = [
        headless_path(ghidra_dir),
        lane_dir,
        project_name,
        "-process",
        program,
        "-noanalysis",
        "-readOnly",
        "-max-cpu",
        str(max_cpu),
        "-scriptPath",
        script_dir,
        "-log",
        log_path,
        "-postScript",
        script,
        *script_args,
    ]
    if os.name == "nt":
        return ["cmd.exe", "/d", "/c", *args]
    return args


def filter_script_output(stdout: str) -> str:
    out: list[str] = []
    block: list[str] | None = None

    def flush() -> None:
        nonlocal block
        if block is not None:
            text = "\n".join(block).rstrip()
            if text:
                out.append(text)
        block = None

    for line in stdout.splitlines():
        match = SCRIPT_LINE.match(line)
        if match:
            flush()
            rest = match.group("text")
            if SCRIPT_END.search(rest):
                out.append(SCRIPT_END.sub("", rest).rstrip())
            else:
                block = [rest] if rest else []
            continue
        if block is not None:
            if SCRIPT_END.search(line):
                block.append(SCRIPT_END.sub("", line).rstrip())
                flush()
                continue
            if LOG_LINE.match(line):
                flush()
                continue
            block.append(line)
            continue
        if line.startswith("ERROR"):
            out.append(line)
    flush()
    return "\n\n".join(out)


class LaneLock:
    def __init__(self, path: str):
        self.path = path
        self.handle = None

    def acquire(self) -> bool:
        if self.handle is not None:
            return True
        try:
            handle = open(self.path, "a+b")
        except OSError:
            return False
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            if msvcrt is not None:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            elif fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:  # pragma: no cover
                handle.close()
                return False
        except OSError:
            handle.close()
            return False
        self.handle = handle
        return True

    def release(self) -> None:
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            if msvcrt is not None:
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            elif fcntl is not None:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            self.handle.close()
        except OSError:
            pass
        self.handle = None


def ghidra_locked(project_dir: str, project_name: str) -> bool:
    return os.path.isfile(os.path.join(project_dir, project_name + ".lock"))


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", name).strip("-")
    if not cleaned:
        raise ValueError("lane name is empty")
    return cleaned


class GhidraRunner:
    def __init__(self, settings: dict):
        self.settings = settings
        self.root = settings["root"]
        self.lanes_dir = os.path.join(self.root, "lanes")
        self.logs_dir = os.path.join(self.root, "logs")
        self.jobs_dir = os.path.join(self.root, "jobs")
        for directory in (self.lanes_dir, self.logs_dir, self.jobs_dir):
            os.makedirs(directory, exist_ok=True)
        self._guard = threading.Lock()

    def project(self, game: str) -> dict:
        projects = self.settings.get("projects") or {}
        if game not in projects:
            raise ValueError("no ghidra project configured for %s" % game)
        item = projects[game]
        for key in ("dir", "name", "program", "scripts"):
            if not item.get(key):
                raise ValueError("ghidra project %s is missing %s" % (game, key))
        return item

    def list_scripts(self, game: str, name_filter: str = "") -> str:
        script_dir = self.project(game)["scripts"]
        if not os.path.isdir(script_dir):
            raise ValueError("script dir does not exist: %s" % script_dir)
        lines = []
        for name in sorted(os.listdir(script_dir)):
            if not name.endswith((".java", ".py")):
                continue
            if name_filter and name_filter.lower() not in name.lower():
                continue
            path = os.path.join(script_dir, name)
            lines.append("%s  %s" % (name, _usage_line(path)))
        if not lines:
            return "no scripts in %s" % script_dir
        return "\n".join(lines)

    def list_lanes(self, game: str) -> str:
        project = self.project(game)
        prefix = _safe_name(game) + "-"
        lines = []
        for name in sorted(os.listdir(self.lanes_dir)):
            if not name.startswith(prefix):
                continue
            directory = os.path.join(self.lanes_dir, name)
            ready = os.path.isfile(os.path.join(directory, project["name"] + ".gpr"))
            busy = ghidra_locked(directory, project["name"]) or _held(os.path.join(directory, ".rusticre.lock"))
            lines.append("%s ready=%s busy=%s" % (name, ready, busy))
        return "\n".join(lines) if lines else "no lanes yet"

    def run(self, game: str, script: str, script_args: list[str], timeout_s: int = 600, lane: str = "") -> str:
        project = self.project(game)
        if not os.path.isfile(headless_path(self.settings["ghidra_dir"])):
            raise ValueError("Ghidra headless launcher is missing under %s" % self.settings["ghidra_dir"])
        if ghidra_locked(project["dir"], project["name"]):
            raise ValueError("the master project is open; close it before copying a lane")
        lane_dir = self._claim(game, project, lane)
        job_id = "job-%s" % uuid.uuid4().hex[:12]
        log_path = os.path.join(self.logs_dir, job_id + ".log")
        script_name = script if script.endswith((".java", ".py")) else script + ".java"
        command = build_command(
            self.settings["ghidra_dir"],
            lane_dir,
            project["name"],
            project["program"],
            project["scripts"],
            script_name,
            script_args,
            log_path,
            int(self.settings.get("max_cpu", 4)),
        )
        env = dict(os.environ)
        env["GHIDRA_MAXMEM"] = str(self.settings.get("max_mem", "6G"))
        env["GHIDRA_HEADLESS_MAXMEM"] = env["GHIDRA_MAXMEM"]
        if self.settings.get("java_home"):
            env["JAVA_HOME"] = self.settings["java_home"]
        started = time.time()
        try:
            proc = subprocess.run(
                command,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_s,
            )
            code = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
            state = "done" if code == 0 else "failed"
        except subprocess.TimeoutExpired as exc:
            code = -1
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", "replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", "replace")
            state = "timeout"
        finally:
            _release(os.path.join(lane_dir, ".rusticre.lock"))
        output = filter_script_output(stdout)
        record = {
            "job_id": job_id,
            "game": game,
            "script": script_name,
            "args": script_args,
            "lane": os.path.basename(lane_dir),
            "state": state,
            "exit_code": code,
            "duration_s": round(time.time() - started, 2),
            "command": command,
            "output": output,
            "stderr_tail": (stderr or "")[-2000:],
        }
        record_path = os.path.join(self.jobs_dir, job_id + ".json")
        with open(record_path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
        return (
            "job=%s game=%s script=%s lane=%s state=%s exit=%s duration=%ss\n--- script output ---\n%s"
            % (job_id, game, script_name, record["lane"], state, code, record["duration_s"], output or "(no script output)")
        )

    def jobs(self, limit: int = 10) -> str:
        names = [name for name in os.listdir(self.jobs_dir) if name.endswith(".json")]
        records = []
        for name in names:
            try:
                with open(os.path.join(self.jobs_dir, name), encoding="utf-8") as handle:
                    records.append(json.load(handle))
            except (OSError, ValueError):
                continue
        records.sort(key=lambda item: item.get("job_id", ""), reverse=True)
        if not records:
            return "no jobs yet"
        lines = []
        for record in records[:limit]:
            lines.append(
                "%s %s %s %s %ss" % (record["job_id"], record.get("state"), record.get("game"), record.get("script"), record.get("duration_s"))
            )
        return "\n".join(lines)

    def _claim(self, game: str, project: dict, lane: str) -> str:
        with self._guard:
            if lane:
                directory = os.path.join(self.lanes_dir, _safe_name(game) + "-" + _safe_name(lane))
                self._ensure(directory, project)
                if not _acquire(os.path.join(directory, ".rusticre.lock")):
                    raise ValueError("lane %s is busy" % lane)
                if ghidra_locked(directory, project["name"]):
                    _release(os.path.join(directory, ".rusticre.lock"))
                    raise ValueError("lane %s is open in Ghidra" % lane)
                return directory
            for index in range(1, 9):
                directory = os.path.join(self.lanes_dir, "%s-%d" % (_safe_name(game), index))
                self._ensure(directory, project)
                if ghidra_locked(directory, project["name"]):
                    continue
                if _acquire(os.path.join(directory, ".rusticre.lock")):
                    return directory
        raise ValueError("no free lane; eight copies are already in use")

    def _ensure(self, directory: str, project: dict) -> None:
        marker = os.path.join(directory, project["name"] + ".gpr")
        if os.path.isfile(marker):
            return
        if os.path.isdir(directory):
            shutil.rmtree(directory)
        os.makedirs(os.path.dirname(directory), exist_ok=True)
        shutil.copytree(project["dir"], directory)


_LOCKS: dict[str, LaneLock] = {}


def _acquire(path: str) -> bool:
    lock = LaneLock(path)
    if not lock.acquire():
        return False
    _LOCKS[path] = lock
    return True


def _release(path: str) -> None:
    lock = _LOCKS.pop(path, None)
    if lock is not None:
        lock.release()


def _held(path: str) -> bool:
    probe = LaneLock(path)
    if not os.path.isfile(path):
        return False
    if probe.acquire():
        probe.release()
        return False
    return True


def _usage_line(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for _ in range(40):
                line = handle.readline()
                if not line:
                    break
                stripped = line.strip()
                if stripped.lower().startswith("usage") or stripped.lower().startswith("// usage"):
                    return stripped.lstrip("/ ").strip()
                if stripped.startswith("public class") or stripped.startswith("import "):
                    break
    except OSError:
        return ""
    return ""
