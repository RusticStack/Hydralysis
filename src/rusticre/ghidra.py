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

import hashlib
import json
import os
import re
import shutil
import signal
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


def ghidra_environment(settings: dict) -> dict[str, str]:
    """Keep JVM settings, caches and temporary files inside this server's root."""
    env = dict(os.environ)
    env["GHIDRA_MAXMEM"] = str(settings.get("max_mem", "6G"))
    env["GHIDRA_HEADLESS_MAXMEM"] = env["GHIDRA_MAXMEM"]
    if settings.get("java_home"):
        env["JAVA_HOME"] = settings["java_home"]
    runtime = Path(settings["root"]).resolve() / "runtime"
    properties = {}
    for folder, keys in (("settings", ("application.settingsdir",)),
                         ("cache", ("application.cachedir",)),
                         ("tmp", ("application.tempdir", "java.io.tmpdir"))):
        directory = runtime / folder
        directory.mkdir(parents=True, exist_ok=True)
        properties.update({key: str(directory) for key in keys})
    env["TEMP"] = env["TMP"] = env["TMPDIR"] = properties["java.io.tmpdir"]
    extra = " ".join('"-D%s=%s"' % item for item in properties.items())
    # The Windows launcher expands GHIDRA_HEADLESS_JAVA_OPTIONS inside a quoted
    # batch argument. Let the JVM parse its own environment instead, including
    # quoted paths with spaces, without changing the installed launch scripts.
    env["JAVA_TOOL_OPTIONS"] = (env.get("JAVA_TOOL_OPTIONS", "") + " " + extra).strip()
    return env


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
        for argument in args:
            if re.search(r'[&|<>^%!"\r\n\x00]', argument):
                raise ValueError("Windows headless arguments must not contain shell metacharacters")
        return ["cmd.exe", "/d", "/c", *args]
    return args


def launch_command(command: list[str]) -> str | list[str]:
    """Quote every batch argument, including semicolon-separated script paths.

    list2cmdline only quotes whitespace. cmd's batch argument parser also splits
    unquoted semicolons, so passing a normal subprocess list loses script paths.
    build_command already rejects expansion and control characters on Windows.
    """
    if os.name != "nt":
        return command
    return 'cmd.exe /d /s /c "' + " ".join('"%s"' % value for value in command[3:]) + '"'


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
    return any(os.path.exists(os.path.join(project_dir, project_name + suffix)) for suffix in (".lock", ".lock~"))


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", name).strip("-")
    if not cleaned:
        raise ValueError("lane name is empty")
    return cleaned


class GhidraJobError(RuntimeError):
    """A failed run with durable diagnostics, including failures with exit code 0."""

    def __init__(self, record: dict, record_path: str):
        self.record = record
        self.job_id = record["job_id"]
        self.log_path = record["log_path"]
        self.record_path = record_path
        super().__init__("Ghidra job %s %s: %s; log=%s record=%s" % (
            self.job_id, record["state"], record.get("error") or "script failed", self.log_path, record_path
        ))


def _snapshot_identity(project: dict) -> dict:
    """Stat every source file so a saved lane cannot silently outlive its master."""
    source = Path(project["dir"]).resolve()
    name = project["name"]
    if name != Path(name).name or name in ("", ".", "..") or "/" in name or "\\" in name:
        raise ValueError("project name must be one file name")
    marker, repository = source / (name + ".gpr"), source / (name + ".rep")
    if not marker.is_file() or not repository.is_dir():
        raise ValueError("analysed project is missing %s.gpr or %s.rep under %s" % (name, name, source))
    if marker.is_symlink() or repository.is_symlink():
        raise ValueError("project files must not be symbolic links")
    entries = [marker, *sorted(repository.rglob("*"))]
    stats = []
    for path in entries:
        if path.is_symlink():
            raise ValueError("project contains a symbolic link: %s" % path)
        if path.is_file():
            stat = path.stat()
            stats.append([path.relative_to(source).as_posix(), stat.st_size, stat.st_mtime_ns])
    return {
        "version": 1, "source": os.path.normcase(str(source)), "name": name,
        "program": project["program"],
        "source_stat_sha256": hashlib.sha256(json.dumps(stats, separators=(",", ":")).encode()).hexdigest(),
    }


def _script_failed(output: str) -> bool:
    return bool(re.search(r"(?:^|\n)(?:\d{4}-\d\d-\d\d [\d:, .]+ )?(?:ERROR|SEVERE)\s|"
                          r"Error running script|Unable to (?:find|load|run) script|SCRIPT ERROR", output, re.IGNORECASE))


def _terminate_owned_tree(proc: subprocess.Popen) -> None:
    """Do not release a lane while a child JVM can still hold its project lock."""
    if os.name == "nt":
        result = subprocess.run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                                capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError("owned process tree cleanup failed: %s" % (result.stderr or result.stdout).strip())
    else:
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait(timeout=30)


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

    def project(self, target: str, require_scripts: bool = True) -> dict:
        projects = self.settings.get("targets") or self.settings.get("projects") or {}
        if target not in projects:
            known = ", ".join(sorted(projects)) or "(none)"
            raise ValueError("no ghidra target %r; configured: %s" % (target, known))
        item = projects[target]
        for key in (("dir", "name", "program", "scripts") if require_scripts else ("dir", "name", "program")):
            if not item.get(key):
                raise ValueError("ghidra target %s is missing %s" % (target, key))
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
        from rusticre.query import _expected_hash

        expected = _expected_hash(project)
        script_name = script if script.endswith((".java", ".py")) else script + ".java"
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:java|py)", script_name):
            raise ValueError("script must be a simple .java or .py file name")
        if not os.path.isfile(os.path.join(project["scripts"], script_name)):
            raise ValueError("script is missing from configured scripts directory: %s" % script_name)
        for argument in script_args:
            if not isinstance(argument, str):
                raise ValueError("script arguments must be strings")
            if argument.startswith("-") and not re.fullmatch(r"-(?:0x[0-9a-fA-F]+|\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)", argument):
                raise ValueError("headless options are forbidden in script arguments: %s" % argument)
        builtin_scripts = str(Path(__file__).with_name("scripts"))
        script_path = builtin_scripts + ";" + project["scripts"]
        # Validate before reserving or copying a lane. The Windows batch launcher
        # interprets shell metacharacters even though subprocess takes a list.
        if os.name == "nt":
            for argument in [headless_path(self.settings["ghidra_dir"]), project["dir"],
                             project["name"], project["program"], script_path,
                             self.settings["root"], *script_args]:
                if re.search(r'[&|<>^%!"\r\n\x00]', argument):
                    raise ValueError("Windows headless arguments must not contain shell metacharacters")
        max_cpu = int(self.settings.get("max_cpu", 4))
        env = ghidra_environment(self.settings)
        if not os.path.isfile(headless_path(self.settings["ghidra_dir"])):
            raise ValueError("Ghidra headless launcher is missing under %s" % self.settings["ghidra_dir"])
        if ghidra_locked(project["dir"], project["name"]):
            raise ValueError("the master project is open; close it before copying a lane")
        lane_dir = self._claim(game, project, lane)
        job_id = "job-%s" % uuid.uuid4().hex[:12]
        log_path = os.path.join(self.logs_dir, job_id + ".log")
        command = build_command(
            self.settings["ghidra_dir"],
            lane_dir,
            project["name"],
            project["program"],
            script_path,
            script_name,
            script_args,
            log_path,
            max_cpu,
        )
        position = command.index("-postScript")
        command[position:position] = ["-preScript", "RusticGuard.java", expected]
        started = time.time()
        proc = None
        release_lane = True
        error = ""
        stdout = stderr = ""
        try:
            proc = subprocess.Popen(
                launch_command(command),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                **({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}),
            )
            stdout, stderr = proc.communicate(timeout=timeout_s)
            code = proc.returncode
            state = "done" if code == 0 and not _script_failed(stdout + "\n" + stderr) else "failed"
            if state == "failed":
                error = "headless exited %s or reported a script error" % code
        except subprocess.TimeoutExpired as exc:
            code = -1
            state = "timeout"
            error = "exceeded %ss; the owned process tree was terminated" % timeout_s
            try:
                _terminate_owned_tree(proc)
                stdout, stderr = proc.communicate(timeout=5)
            except (OSError, RuntimeError, subprocess.SubprocessError) as cleanup_error:
                state = "cleanup_failed"
                release_lane = False
                error = "timeout; lane retained because cleanup could not be confirmed: %s" % cleanup_error
                stdout, stderr = exc.stdout or "", exc.stderr or ""
        except OSError as exc:
            code, state, error = -1, "failed", str(exc)
        finally:
            if release_lane:
                _release(os.path.join(lane_dir, ".rusticre.lock"))
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        transcript_path = os.path.join(self.logs_dir, job_id + ".stdout.log")
        with open(transcript_path, "w", encoding="utf-8") as handle:
            handle.write("--- stdout ---\n" + stdout + "\n--- stderr ---\n" + stderr)
        output = filter_script_output(stdout)
        record = {
            "job_id": job_id,
            "game": game,
            "script": script_name,
            "args": script_args,
            "lane": os.path.basename(lane_dir),
            "state": state,
            "exit_code": code,
            "started_at": started,
            "finished_at": time.time(),
            "duration_s": round(time.time() - started, 2),
            "command": command,
            "output": output,
            "stderr_tail": (stderr or "")[-2000:],
            "log_path": transcript_path,
            "headless_log_path": log_path,
            "error": error,
        }
        record_path = os.path.join(self.jobs_dir, job_id + ".json")
        with open(record_path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
        if state != "done":
            raise GhidraJobError(record, record_path)
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
        records.sort(key=lambda item: item.get("started_at", 0), reverse=True)
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
                os.makedirs(directory, exist_ok=True)
                if not _acquire(os.path.join(directory, ".rusticre.lock")):
                    raise ValueError("lane %s is busy" % lane)
                try:
                    if ghidra_locked(directory, project["name"]):
                        raise ValueError("lane %s is open in Ghidra" % lane)
                    self._ensure(directory, project)
                except BaseException:
                    _release(os.path.join(directory, ".rusticre.lock"))
                    raise
                return directory
            for index in range(1, 9):
                directory = os.path.join(self.lanes_dir, "%s-%d" % (_safe_name(game), index))
                os.makedirs(directory, exist_ok=True)
                lock_path = os.path.join(directory, ".rusticre.lock")
                if not _acquire(lock_path):
                    continue
                try:
                    if ghidra_locked(directory, project["name"]):
                        _release(lock_path)
                        continue
                    self._ensure(directory, project)
                except BaseException:
                    _release(lock_path)
                    raise
                return directory
        raise ValueError("no free lane; eight copies are already in use")

    def ensure_snapshot(self, directory: str, project: dict) -> None:
        """Create/validate a snapshot while the caller holds an exclusive OS lock."""
        self._ensure(directory, project)

    def _ensure(self, directory: str, project: dict) -> None:
        if ghidra_locked(project["dir"], project["name"]):
            raise ValueError("the master project is open; close it before copying a lane")
        identity = _snapshot_identity(project)
        destination = Path(directory)
        destination.mkdir(parents=True, exist_ok=True)
        metadata_path = destination / ".rusticre-snapshot.json"
        marker = destination / (project["name"] + ".gpr")
        repository = destination / (project["name"] + ".rep")
        if metadata_path.is_file():
            saved = json.loads(metadata_path.read_text(encoding="utf-8"))
            if saved != identity:
                raise ValueError("stale lane: source project identity changed; choose a new lane or root")
            if not marker.is_file() or not repository.is_dir():
                raise ValueError("incomplete lane snapshot; choose a new lane or root")
            return
        unknown = set(path.name for path in destination.iterdir()) - {".rusticre.lock"}
        if unknown:
            raise ValueError("refusing to replace an existing unowned or incomplete lane: %s" % destination)
        shutil.copy2(Path(project["dir"]) / marker.name, marker)
        shutil.copytree(Path(project["dir"]) / repository.name, repository)
        if ghidra_locked(project["dir"], project["name"]) or _snapshot_identity(project) != identity:
            raise ValueError("source project changed while copying; snapshot refused; choose a new lane")
        metadata_path.write_text(json.dumps(identity, indent=2), encoding="utf-8")


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
