"""Cross-process OS file locks. Released by the OS if the holder dies."""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import msvcrt
except ImportError:  # pragma: no cover - not Windows
    msvcrt = None
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None


class LockBusy(ValueError):
    """A bounded wait for an OS lock ran out (PROTOCOL-3.md 4.10, D44).

    It is a ValueError, so every caller that caught the old "is busy" ValueError still does. A caller that
    owns a reply turns it into the structured `busy` with `payload()`; `retry_after_ms` is a hint, not a promise.
    """

    def __init__(self, what: str, path, waited_s: float, retry_after_ms: int = 1000):
        self.what = what
        self.path = str(path)
        self.waited_s = round(float(waited_s), 3)
        self.retry_after_ms = int(retry_after_ms)
        super().__init__("%s is busy (%s); retry shortly" % (what, Path(self.path).name))

    def payload(self) -> dict:
        return {"error": "busy", "what": self.what, "lock": Path(self.path).name, "waited_s": self.waited_s,
                "retryAfterMs": self.retry_after_ms,
                "suggest": "another client holds this lock; retry after retryAfterMs, nothing was changed"}


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


def held(path: str) -> bool:
    probe = LaneLock(path)
    if not os.path.isfile(path):
        return False
    if probe.acquire():
        probe.release()
        return False
    return True


# --------------------------------------------------------------------------- the fair bounded wait (Windows)
#
# The old wait polled a non-blocking lock every 50 ms. A holder that releases and asks again at once (a writer
# appending in a loop) always found the lock free before a sleeping waiter woke, so waiters starved: gate 9.10
# measured a 4.5 s (C:) and 8.3 s (D:) single append with 16 writers, and on E: 6 of 16 writers hit LockBusy after
# 30 s. Now a waiter queues in the kernel: LockFileEx without LOCKFILE_FAIL_IMMEDIATELY on an overlapped handle.
# NTFS keeps a pending exclusive request on the file's waiting-lock list and grants it, in arrival order, when the
# range is unlocked, so a releaser that asks again lands behind the waiters already queued. The wait is bounded:
# on timeout the request is cancelled (CancelIoEx) and LockBusy is raised. The range (byte 0, length 1) is the one
# msvcrt.locking takes in LaneLock, so LaneLock, held() and older processes still exclude each other. The OS drops
# the lock of a holder that dies and the next queued waiter is granted it.

_NT = os.name == "nt"
if _NT:
    import ctypes
    from ctypes import wintypes

    class _Overlapped(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t), ("Offset", wintypes.DWORD),
                    ("OffsetHigh", wintypes.DWORD), ("hEvent", wintypes.HANDLE)]

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.HANDLE]
    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    _k32.CreateEventW.restype = wintypes.HANDLE
    _k32.LockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                ctypes.POINTER(_Overlapped)]
    _k32.LockFileEx.restype = wintypes.BOOL
    _k32.UnlockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.POINTER(_Overlapped)]
    _k32.UnlockFileEx.restype = wintypes.BOOL
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.WaitForMultipleObjects.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL, wintypes.DWORD]
    _k32.WaitForMultipleObjects.restype = wintypes.DWORD
    _k32.FindFirstChangeNotificationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
    _k32.FindFirstChangeNotificationW.restype = wintypes.HANDLE
    _k32.FindNextChangeNotification.argtypes = [wintypes.HANDLE]
    _k32.FindNextChangeNotification.restype = wintypes.BOOL
    _k32.FindCloseChangeNotification.argtypes = [wintypes.HANDLE]
    _k32.FindCloseChangeNotification.restype = wintypes.BOOL
    _k32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Overlapped)]
    _k32.CancelIoEx.restype = wintypes.BOOL
    _k32.GetOverlappedResult.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Overlapped),
                                         ctypes.POINTER(wintypes.DWORD), wintypes.BOOL]
    _k32.GetOverlappedResult.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL
    _INVALID = wintypes.HANDLE(-1).value
    _GENERIC_RW = 0x80000000 | 0x40000000
    _SHARE_ALL = 0x1 | 0x2 | 0x4
    _OPEN_ALWAYS = 4
    _FLAG_OVERLAPPED = 0x40000000
    _LOCK_EXCLUSIVE = 0x2
    _ERROR_IO_PENDING = 997
    _WAIT_OBJECT_0 = 0


def wait_handles(handles, timeout_s: float) -> bool:
    """Wait until one of the waitable kernel HANDLES is signalled (True) or TIMEOUT_S passes (False). Windows only."""
    if not handles:
        time.sleep(max(0.0, timeout_s))
        return False
    array = (wintypes.HANDLE * len(handles))(*handles)
    return _k32.WaitForMultipleObjects(len(array), array, False, max(0, min(int(timeout_s * 1000), 0xFFFFFFFE))) == _WAIT_OBJECT_0


class _QueuedLock:
    """One exclusive lock on byte 0 of PATH, waited for in the kernel's queue (Windows)."""

    def __init__(self, path: str):
        self.path = path
        self.handle = None

    def wait(self, timeout_s: float, wake=()) -> bool:
        """Queue for the lock; True once held, False when TIMEOUT_S ran out or one of the WAKE handles (waitable kernel
        handles, such as a `FolderWatch`) was signalled first (the request is withdrawn)."""
        try:
            empty = os.stat(self.path).st_size == 0
        except FileNotFoundError:
            empty = True
        if empty:  # as LaneLock: byte 0 must exist before it is locked, or a LaneLock probe cannot write it
            with open(self.path, "ab") as seed:
                seed.write(b"0")
        handle =_k32.CreateFileW(self.path, _GENERIC_RW, _SHARE_ALL, None, _OPEN_ALWAYS, _FLAG_OVERLAPPED, None)
        if handle is None or handle == _INVALID:
            raise ctypes.WinError(ctypes.get_last_error())
        event = _k32.CreateEventW(None, True, False, None)
        if not event:
            error = ctypes.get_last_error()
            _k32.CloseHandle(handle)
            raise ctypes.WinError(error)
        overlapped = _Overlapped(hEvent=event)
        done = wintypes.DWORD()
        pending = cancelled = False
        try:
            if not _k32.LockFileEx(handle, _LOCK_EXCLUSIVE, 0, 1, 0, ctypes.byref(overlapped)):
                error = ctypes.get_last_error()
                if error != _ERROR_IO_PENDING:
                    raise ctypes.WinError(error)
                pending = True
                milliseconds = max(0, min(int(timeout_s * 1000), 0xFFFFFFFE))
                if wake:
                    handles = (wintypes.HANDLE * (1 + len(wake)))(event, *wake)
                    signalled = _k32.WaitForMultipleObjects(len(handles), handles, False, milliseconds)
                else:
                    signalled = _k32.WaitForSingleObject(event, milliseconds)
                if signalled != _WAIT_OBJECT_0:   # timeout, a WAKE handle, or a failed wait: withdraw the request
                    cancelled = True
                    _k32.CancelIoEx(handle, ctypes.byref(overlapped))
                # Always wait for the request to finish (OVERLAPPED must outlive it). A grant that raced the
                # cancel still counts as held.
                pending = False
                if not _k32.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(done), True):
                    error = ctypes.get_last_error()
                    if not cancelled:
                        raise ctypes.WinError(error)
                    _k32.CloseHandle(handle)
                    return False
        except BaseException:
            if pending:  # interrupted while queued: withdraw the request and let it finish before freeing it
                _k32.CancelIoEx(handle, ctypes.byref(overlapped))
                _k32.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(done), True)
            _k32.CloseHandle(handle)
            raise
        finally:
            _k32.CloseHandle(event)
        self.handle = handle
        return True

    def release(self) -> None:
        handle, self.handle = self.handle, None
        if handle is None:
            return
        try:
            # Unlock explicitly: on close alone the OS releases the range "when resources allow", not at once.
            _k32.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(_Overlapped()))
        finally:
            _k32.CloseHandle(handle)


class FolderWatch:
    """A waitable handle signalled when a file is created, renamed or removed in one of FOLDERS (Windows change
    notification, not recursive); `rearm` after each wake. Changes between a wake and `rearm` are kept by the OS and
    signal again at once, so none is missed. Folders that do not exist are not watched."""

    def __init__(self, folders):
        self.handles = []
        if not _NT:
            return
        for folder in folders:
            handle = _k32.FindFirstChangeNotificationW(str(folder), False, 0x1)   # FILE_NOTIFY_CHANGE_FILE_NAME
            if handle and handle != _INVALID:
                self.handles.append(handle)

    def rearm(self) -> None:
        for handle in self.handles:
            _k32.FindNextChangeNotification(handle)

    def close(self) -> None:
        handles, self.handles = self.handles, []
        for handle in handles:
            _k32.FindCloseChangeNotification(handle)


@contextmanager
def locked(path: Path, timeout_s: float = 5, what: str = "registry"):
    """Wait a bounded time for an exclusive lock; never queue forever.

    On Windows the waiters queue in the kernel and are served in arrival order (see _QueuedLock). Elsewhere, and
    when the lock file cannot be opened for the queued wait (e.g. it is being deleted), it polls as before.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    deadline = started + timeout_s
    lease = _QueuedLock(str(path)) if _NT else LaneLock(str(path))
    while True:
        if _NT:
            try:
                if lease.wait(max(0.0, deadline - time.monotonic())):
                    break
                raise LockBusy(what, path, time.monotonic() - started)
            except OSError:
                pass  # could not queue (the file is being replaced or deleted): retry until the deadline
        elif lease.acquire():
            break
        if time.monotonic() >= deadline:
            raise LockBusy(what, path, time.monotonic() - started)
        time.sleep(0.05)
    try:
        yield
    finally:
        lease.release()
