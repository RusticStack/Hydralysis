"""A live tracing harness over the fixtures: spawn paused, arm the declared profile through `capture start`, run, stop.

Shared by the end-to-end tests and by benchmarks/trace_overhead.py. Windows with Frida only.
"""

from __future__ import annotations

import hashlib
import os
import sys
import threading
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from hydralysis import profiles  # noqa: E402
from hydralysis.pe import Image  # noqa: E402


def specs_for(directory: Path, exe_names: list[str], hooks: list[str] | None = None) -> tuple[list[dict], dict]:
    """(probe specs, verification) of the baseline profile for the fixture images EXE_NAMES in DIRECTORY."""
    profile = profiles.load_baseline()
    images = {name: Image(Path(directory) / name) for name in exe_names}
    verification = profiles.verify_profile(profile, images)
    specs = [s for s in profiles.probe_specs(profile, verification) if s["module"] in exe_names and (hooks is None or s["hook"] in hooks)]
    return specs, verification


# A fixture that hangs (suspended spawn, a debugger call that never returns, a child that ignores its parent's death) must
# fail fast and never outlive the test: every fixture runs in a kill-on-close job object, a watchdog terminates the job at
# a hard deadline, and close() always terminates it. Terminating the job also ends any frida call blocked on the target.
FIXTURE_DEADLINE_S = float(os.environ.get("HYDRA_TEST_FIXTURE_DEADLINE_S", "300"))
CLEANUP_BUDGET_S = 30.0


class KillJob:
    """A Windows job object that kills every process in it (the fixture and its children) when terminated or closed."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.k32 = k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.lock = threading.Lock()
        self.handle = k32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW")

        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class IoCounters(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob")]

        class Extended(ctypes.Structure):
            _fields_ = [("Basic", Basic), ("Io", IoCounters), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]
        info = Extended()
        info.Basic.LimitFlags = 0x2000          # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not k32.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject")

    def add(self, pid: int) -> bool:
        process = self.k32.OpenProcess(0x0100 | 0x0001, False, pid)      # PROCESS_SET_QUOTA | PROCESS_TERMINATE
        if not process:
            return False
        try:
            return bool(self.k32.AssignProcessToJobObject(self.handle, process))
        finally:
            self.k32.CloseHandle(process)

    def kill(self) -> None:
        with self.lock:
            if self.handle:
                self.k32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        with self.lock:
            if self.handle:
                self.k32.TerminateJobObject(self.handle, 1)
                self.k32.CloseHandle(self.handle)
                self.handle = None


class Live:
    """One spawned fixture under a RuntimeAgent worker (in process: the worker class itself, no socket)."""

    def __init__(self, root: Path, exe: Path, argv: list[str] | None = None, cwd: str | None = None,
                 env: dict | None = None, linger_ms: int = 600):
        import frida
        from hydralysis.runtime_worker import RuntimeAgent
        self.dir = Path(root) / uuid.uuid4().hex
        self.dir.mkdir(parents=True)
        self.exe = Path(exe)
        self.agent = RuntimeAgent(self.dir, frida.get_local_device())
        initial = {"action": "spawn", "exe": str(self.exe), "sha256": hashlib.sha256(self.exe.read_bytes()).hexdigest(),
                   "argv": list(argv or []),
                   "env": {"HYDRA_FX_LINGER_MS": str(linger_ms), **(env or {})}}
        if cwd:
            initial["cwd"] = cwd
        self.job = KillJob()
        self.watchdog: threading.Timer | None = None
        try:
            self.info = self.agent.startup(initial)
        except BaseException:
            self._adopt_orphan()
            raise
        self.pid = self.agent.pid
        self.job.add(self.pid)
        self.watchdog = threading.Timer(FIXTURE_DEADLINE_S, self._deadline)
        self.watchdog.daemon = True
        self.watchdog.start()
        self.started: dict | None = None
        self.stopped: dict | None = None

    def _adopt_orphan(self) -> None:
        pid = getattr(self.agent, "pid", None)
        if pid:
            self.job.add(pid)
        self.job.close()

    def _deadline(self) -> None:
        print("fixture %s still alive after %.0f s: killing its job" % (self.exe.name, FIXTURE_DEADLINE_S), file=sys.stderr, flush=True)
        self.job.kill()

    def start(self, specs: list[dict], **trace) -> dict:
        option = {"session": "live-" + uuid.uuid4().hex[:8], "hooks": [s["hook"] for s in specs], "probes": specs, **trace}
        self.started = self.agent.handle("capture", {"op": "start", "name": "live", "trace": option})
        return self.started

    def resume(self) -> None:
        self.agent.handle("resume", {})

    def wait_exit(self, timeout: float = 60.0) -> bool:
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        handle = k32.OpenProcess(0x00100000, False, self.pid)       # SYNCHRONIZE
        if not handle:
            return True
        try:
            return k32.WaitForSingleObject(ctypes.c_void_p(handle), int(timeout * 1000)) == 0
        finally:
            k32.CloseHandle(ctypes.c_void_p(handle))

    def stop(self) -> dict:
        self.stopped = self.agent.handle("capture", {"op": "stop"})
        return self.stopped

    @property
    def segment(self) -> Path:
        return Path(self.started["trace"]["segment"])

    @property
    def segment_id(self) -> str:
        return self.agent.trace.segment_id

    def close(self) -> None:
        """Clean up the recorder with a bounded wait, then kill the fixture's whole tree whatever happened."""
        if self.watchdog is not None:
            self.watchdog.cancel()

        def cleanup():
            try:
                if not self.agent.closed:
                    self.agent.cleanup()
            except Exception:
                pass
        worker = threading.Thread(target=cleanup, daemon=True)
        worker.start()
        worker.join(CLEANUP_BUDGET_S)
        if worker.is_alive():
            self.job.kill()          # a blocked debugger call returns once the target is gone
            worker.join(CLEANUP_BUDGET_S)
        self.job.close()


# ---- ingest helpers ----------------------------------------------------------------------------------------------------
def symbol_table(directory: Path, names: list[str]) -> dict:
    """The engine's TableSymbolizer JSON for fixture images: function ranges from the exception tables, named by the linker map."""
    sys.path.insert(0, str(HERE / "fixtures"))
    import build_fixtures
    modules = {}
    for name in names:
        image = Image(Path(directory) / name)
        named, _data = build_fixtures.symbols(Path(directory) / (name.rsplit(".", 1)[0] + ".map"))
        by_rva = {int(va, 16) - image.base: fn for fn, va in named.items() if "::" not in fn and "!" not in fn}
        pe = image.pe
        pe.parse_data_directories(directories=[3])
        ends = {int(e.struct.BeginAddress): int(e.struct.EndAddress) for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])}
        starts = sorted(by_rva)
        functions = []
        for index, begin in enumerate(starts):
            # a leaf function has no exception-table row: it runs to the next symbol
            end = ends.get(begin) or (starts[index + 1] if index + 1 < len(starts) else begin + 16)
            functions.append({"start": begin, "end": end, "name": by_rva[begin]})
        code = [[int(s.VirtualAddress), int(s.VirtualAddress) + int(s.Misc_VirtualSize)] for s in pe.sections if s.Characteristics & 0x20000000]
        modules[name] = {"code": code, "functions": functions}
    return {"modules": modules}


def ingest(tool: str, root: Path, session: str, segment: Path, segment_id: str, tc, symbols: dict | None = None) -> dict:
    """Export a segment, import it into a store with hydra-trace, rebuild, verify, optionally symbolize. Returns each verb's result."""
    import json
    import subprocess
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    lines, omitted = tc.export_jsonl(segment, segment_id, for_import=True)
    jsonl = root / (session + ".jsonl")
    jsonl.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    out = {"events": len(lines), "omitted": omitted, "jsonl": str(jsonl)}

    def run(*args):
        done = subprocess.run([tool, *args], capture_output=True, text=True, timeout=300)
        return {"exit": done.returncode, "stdout": done.stdout.strip(), "stderr": done.stderr.strip()}
    out["import"] = run("import", str(root), session, str(jsonl))
    out["rebuild"] = run("rebuild", str(root), session)
    out["verify"] = run("verify", str(root), session)
    if symbols is not None:
        table = root / (session + ".symbols.json")
        table.write_text(json.dumps(symbols), encoding="utf-8")
        out["resymbolize"] = run("resymbolize", str(root), session, str(table), "fixture-maps-1")
        try:
            out["symbolization"] = json.loads(out["resymbolize"]["stdout"])["counts"]
        except (ValueError, KeyError):
            out["symbolization"] = None
    out["export"] = run("export", str(root), session, str(root / (session + "-export")), "--overwrite")
    return out
