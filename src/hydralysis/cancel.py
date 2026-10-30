"""Cancellation of one request: a token the MCP server fires on `notifications/cancelled`.

The MCP server runs each tool call inside `scope(token)`. Code that waits (an engine request through a pool entry, a wait
for a free pool entry) registers a wake-up with `current().add(...)`, so a cancel interrupts the wait at once instead of
after the deadline. Nothing here sends anything to the engine: the waiter decides what a cancel means for its request.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading


class Cancelled(Exception):
    """The request was cancelled by its client before it was answered."""


class Token:
    def __init__(self):
        self._lock = threading.Lock()
        self._cancelled = False
        self._callbacks: dict[int, object] = {}
        self._next = 0
        self.reason = ""

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self, reason: str = "") -> None:
        with self._lock:
            if self._cancelled:
                return
            self._cancelled = True
            self.reason = reason
            callbacks = list(self._callbacks.values())
            self._callbacks.clear()
        for callback in callbacks:   # outside the lock: a callback may take its own locks
            try:
                callback()
            except Exception:   # noqa: BLE001 - one waiter's wake-up must not stop the others
                pass

    def add(self, callback):
        """Call CALLBACK once when the token is cancelled (at once if it already is). Returns the function that removes it."""
        with self._lock:
            if not self._cancelled:
                key = self._next
                self._next += 1
                self._callbacks[key] = callback
                return lambda: self._remove(key)
        callback()
        return lambda: None

    def _remove(self, key: int) -> None:
        with self._lock:
            self._callbacks.pop(key, None)

    def raise_if_cancelled(self) -> None:
        if self._cancelled:
            raise Cancelled(self.reason or "the request was cancelled")


_CURRENT: contextvars.ContextVar[Token | None] = contextvars.ContextVar("hydralysis_cancel", default=None)


def current() -> Token | None:
    return _CURRENT.get()


@contextlib.contextmanager
def scope(token: Token | None):
    reset = _CURRENT.set(token)
    try:
        yield token
    finally:
        _CURRENT.reset(reset)
