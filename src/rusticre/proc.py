"""Child processes never inherit the server's stdin.

Under the stdio MCP server the main thread holds a pending read on stdin. On
Windows a child that inherits that pipe blocks during its own start-up until the
read completes, so every runtime probe hung until its timeout over MCP while the
CLI answered at once. Every child RusticRE starts goes through these helpers.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path


def _defaults(kwargs: dict) -> dict:
    if "stdin" in kwargs or "input" in kwargs:
        if kwargs.get("stdin") not in (None, subprocess.DEVNULL) or "input" in kwargs:
            raise ValueError("RusticRE children never read the server's stdin")
    kwargs["stdin"] = subprocess.DEVNULL
    if os.name == "nt" and "creationflags" not in kwargs:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return kwargs


def run(command, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, **_defaults(kwargs))


_children: set[subprocess.Popen] = set()
_children_changed = threading.Condition()
_reaper: threading.Thread | None = None


def _reap_children() -> None:
    """Keep background handles until exit, then reap them without blocking callers."""
    while True:
        with _children_changed:
            while not _children:
                _children_changed.wait()
            children = tuple(_children)
        exited = [child for child in children if child.poll() is not None]
        with _children_changed:
            _children.difference_update(exited)
            if _children:
                _children_changed.wait(timeout=0.25)


def popen(command, **kwargs) -> subprocess.Popen:
    global _reaper
    child = subprocess.Popen(command, **_defaults(kwargs))
    with _children_changed:
        _children.add(child)
        if _reaper is None or not _reaper.is_alive():
            _reaper = threading.Thread(target=_reap_children, name="rusticre-child-reaper", daemon=True)
            _reaper.start()
        _children_changed.notify()
    return child


def identity(pid: int, started_ms: int) -> bool:
    """Do not adopt or kill a recycled PID. Compare OS process creation time."""
    if pid <= 0 or not started_ms:
        return False
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
            return False
        try:
            exit_code = wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)) or exit_code.value != 259:
                return False
            values = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *[ctypes.byref(x) for x in values]):
                return False
            ticks = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
            actual_ms = ticks // 10000 - 11644473600000
            return abs(actual_ms - started_ms) <= 2
        finally:
            kernel.CloseHandle(handle)
    if sys.platform == "darwin":
        from rusticre.darwin_process import created_ms
        try:
            return created_ms(pid) == started_ms
        except PermissionError:
            raise
        except OSError:
            return False
    try:
        # Linux /proc identity, without an optional process-management dependency.
        stat = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
        if stat[0] == "Z":
            return False
        boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines()
                    if line.startswith("btime "))
        actual_ms = (boot + int(stat[19]) / os.sysconf("SC_CLK_TCK")) * 1000
        return abs(actual_ms - started_ms) <= 1000
    except (OSError, ValueError, StopIteration, IndexError):
        return False


def stop(ready: dict) -> None:
    """Stop an owned worker whose identity (pid and creation time) still matches."""
    pid, started = int(ready.get("pid", 0)), int(ready.get("started_ms", 0))
    if not identity(pid, started):
        return
    if os.name == "nt":
        stopped = run(["taskkill.exe", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=15)
        if stopped.returncode and identity(pid, started):
            raise RuntimeError("could not stop owned worker %d: %s" % (pid, stopped.stderr))
    else:
        import signal
        group = int(ready.get("group_id", 0))
        if group <= 0 or os.getpgid(pid) != group:
            raise RuntimeError("worker process group identity changed; refusing to stop an unrelated group")
        os.killpg(group, signal.SIGKILL)
    deadline = time.monotonic() + 10
    while identity(pid, started) and time.monotonic() < deadline:
        time.sleep(0.05)
    if identity(pid, started):
        raise RuntimeError("owned worker %d has not exited" % pid)


def terminate_tree(child: subprocess.Popen) -> None:
    """Stop a child this process started, and everything it started."""
    if os.name == "nt":
        result = run(["taskkill.exe", "/PID", str(child.pid), "/T", "/F"], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError("owned process tree cleanup failed: %s" % (result.stderr or result.stdout).strip())
    else:
        import signal
        os.killpg(child.pid, signal.SIGKILL)
    child.wait(timeout=30)


def worker_path(*first: str) -> str:
    """PYTHONPATH for a RusticRE worker that ignores the user site: the given folders, the
    package, and RusticRE's own dependencies from wherever this process found them."""
    from pathlib import Path
    import capstone
    import pefile
    package = str(Path(__file__).resolve().parent.parent)
    dependencies = sorted({str(Path(module.__file__).resolve().parent.parent) if module.__name__ == "capstone"
                           else str(Path(module.__file__).resolve().parent) for module in (capstone, pefile)})
    return os.pathsep.join([*first, package, *dependencies])
