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


@contextmanager
def locked(path: Path, timeout_s: float = 5, what: str = "registry"):
    """Wait a bounded time for an exclusive lock; never queue forever."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lease = LaneLock(str(path))
    started = time.monotonic()
    deadline = started + timeout_s
    while not lease.acquire():
        if time.monotonic() >= deadline:
            raise LockBusy(what, path, time.monotonic() - started)
        time.sleep(0.05)
    try:
        yield
    finally:
        lease.release()
