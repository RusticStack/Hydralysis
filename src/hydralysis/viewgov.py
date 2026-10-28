"""Which views stay open in this process, and which are let go (Y5, D43, D61, PROTOCOL-3.md 3.11 and 4.10).

Every agent has a view of its own, and a view is a fork opened in the shared engine. The engine admits only so many
(its own `capacity` refusal), so the client decides which to close. This module is that policy and nothing else:

* **LRU and `max_views`.** A process keeps at most `max_views` views open. Opening one more closes the least recently
  used view that has no running request; when every view is busy the caller gets the structured `busy` (reason
  `capacity`), never a silent wait.
* **Idle time.** A view idle for `viewIdleEvictS` (600 s) is closed, unless it has at least `viewKeepWarmRecords` (1000)
  pending records: replaying that many on the next use would cost more than keeping the fork open (D61), so such a view is
  closed only by LRU pressure.
* **The pin-or-evict step (3.11).** A request pins its view before it uses it and unpins when it is answered. The test "no
  running request" and the mark "closing" are one step under one lock, and a request that arrives while a view is closing
  waits for the close to end and then reopens it, so a view is never closed under a running request and a request never
  uses a half-closed view.
* **Nothing is lost.** Closing a view closes its program with the discard option and keeps the folder: every record of the
  view is in the store (write-ahead, 4.10), and the next use replays what the program no longer holds. The reply that
  follows says `view_rebuilt{replayed, ms}` once.
* **Folders.** A view that nobody holds and that was idle for `viewIdleDeleteS` (24 h) has its fork folder deleted; its
  records stay in the store, so nothing is lost (a fork is a disposable cache, D43). Nothing here deletes a store, a
  generation or a candidate.

The governor is per process: it closes only what this process opened. Another process's views are its own to govern.
"""

from __future__ import annotations

import shutil
import threading
import time
from contextlib import contextmanager

DEFAULTS = {"max_views": 24, "idle_evict_s": 600.0, "keep_warm_records": 1000, "idle_delete_s": 86400.0, "wait_s": 30.0}
# The names the settings use (PROTOCOL-3.md 3.7); the snake_case spelling of each is accepted too.
SETTING_NAMES = {"max_views": ("maxViews", "max_views"), "idle_evict_s": ("viewIdleEvictS", "view_idle_evict_s"),
                 "keep_warm_records": ("viewKeepWarmRecords", "view_keep_warm_records"),
                 "idle_delete_s": ("viewIdleDeleteS", "view_idle_delete_s")}
DELETE_SWEEP_S = 600.0     # a process looks for folders to delete at most this often per lineage


def limits(settings: dict | None) -> dict:
    """The governor's limits from the settings, falling back to the defaults for a missing or invalid value."""
    found = dict(DEFAULTS)
    for key, names in SETTING_NAMES.items():
        for name in names:
            value = (settings or {}).get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= (1 if key in ("max_views",) else 0):
                found[key] = value
                break
    return found


class Capacity(RuntimeError):
    """Every open view of this process is running a request: nothing can be closed to make room."""

    def __init__(self, open_views: int, max_views: int, retry_after_ms: int = 2000):
        super().__init__("this process holds %d views open (max_views %d) and every one is running a request" % (open_views, max_views))
        self.open_views, self.max_views, self.retry_after_ms = open_views, max_views, retry_after_ms


class Entry:
    __slots__ = ("key", "name", "target", "last_used", "running", "pending", "state", "opened", "closed", "error")

    def __init__(self, key: str, name: str, target: dict, now: float):
        self.key, self.name, self.target = key, name, target
        self.last_used, self.running, self.pending, self.state = now, 0, 0, "open"
        self.opened, self.closed, self.error = now, 0, ""

    def row(self, now: float) -> dict:
        return {"view": self.name, "key": self.key, "state": self.state, "running": self.running, "pending": self.pending,
                "idle_s": round(now - self.last_used, 1), "closed": self.closed,
                **({"error": self.error} if self.error else {})}


class Pin:
    """A request's hold on a view. `rebuilt` is True when the view was closed since its last use (the reply says so once)."""

    def __init__(self, governor: "Governor", entry: Entry | None, rebuilt: bool):
        self.governor, self.entry, self.rebuilt = governor, entry, rebuilt
        self.started = time.monotonic()

    def update(self, pending: int) -> None:
        if self.entry is not None:
            self.governor.note(self.entry.key, pending)


class Governor:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self._cond = threading.Condition()
        self._entries: dict[str, Entry] = {}
        self._swept: dict[str, float] = {}

    # --- pin and unpin ------------------------------------------------------------------------------------------
    def pin(self, selected: dict, settings: dict | None = None, release=None, pending: int | None = None) -> Pin:
        """Hold the view of SELECTED for a request. Waits (bounded) while the view is being closed; makes room first when the
        view is new and the process is at `max_views` (`release(entry)` closes a victim). Raises `Capacity` when it cannot."""
        limit = limits(settings)
        deadline = self.clock() + limit["wait_s"]
        victims: list[Entry] = []
        with self._cond:
            while True:
                entry = self._entries.get(selected["key"])
                if entry is not None and entry.state == "evicting":
                    if self.clock() >= deadline:
                        raise Capacity(self._open_count(), limit["max_views"], 1000)
                    self._cond.wait(0.05)
                    continue
                break
            rebuilt, created = False, entry is None
            if entry is None:
                entry = Entry(selected["key"], selected.get("view", ""), {key: selected.get(key) for key in
                                                                          ("name", "program", "sha256", "gpr", "key", "view")}, self.clock())
                self._entries[entry.key] = entry
            elif entry.state == "evicted":
                rebuilt, entry.state = True, "open"
            entry.running += 1                      # pin first: from here on this view cannot be chosen as a victim
            entry.last_used = self.clock()
            if pending is not None:
                entry.pending = pending
            while self._open_count() > limit["max_views"]:
                victim = self._victim(exclude=entry.key)
                if victim is None:
                    held = self._open_count()
                    for chosen in victims:  # nothing can be closed after all: leave the ones chosen open
                        chosen.state = "open"
                    entry.running -= 1
                    if created:
                        self._entries.pop(entry.key, None)
                    self._cond.notify_all()
                    raise Capacity(held - 1, limit["max_views"])
                victim.state = "evicting"  # no longer counted as open: it is on its way out
                victims.append(victim)
        self._close(victims, release)
        return Pin(self, entry, rebuilt)

    def unpin(self, pin: Pin) -> None:
        with self._cond:
            if pin.entry is not None and pin.entry.running > 0:
                pin.entry.running -= 1
                pin.entry.last_used = self.clock()
            self._cond.notify_all()

    @contextmanager
    def hold(self, selected: dict, settings: dict | None = None, release=None, pending: int | None = None):
        pin = self.pin(selected, settings, release, pending)
        try:
            yield pin
        finally:
            self.unpin(pin)

    def note(self, key: str, pending: int) -> None:
        with self._cond:
            entry = self._entries.get(key)
            if entry is not None:
                entry.pending = pending

    # --- choosing and closing -----------------------------------------------------------------------------------
    def _open_count(self) -> int:
        """Views this process holds open and keeps: one that is being closed no longer counts."""
        return sum(1 for entry in self._entries.values() if entry.state == "open")

    def _victim(self, exclude: str | None = None) -> Entry | None:
        """The least recently used open view with no running request (any pending count: this is pressure)."""
        idle = [entry for entry in self._entries.values() if entry.state == "open" and entry.running == 0 and entry.key != exclude]
        return min(idle, key=lambda entry: entry.last_used, default=None)

    def _close(self, victims: list[Entry], release) -> list[str]:
        """Close each victim (already marked `evicting`). A close that fails puts the view back to `open` and is not raised:
        the request that triggered it must not fail because a neighbour could not be closed."""
        closed = []
        for entry in victims:
            ok = False
            try:
                if release is not None:
                    release(entry)
                ok = True
            except Exception as error:  # noqa: BLE001 - recorded, never raised into the caller's request
                entry.error = "%s: %s" % (type(error).__name__, error)
            finally:
                with self._cond:
                    entry.state = "evicted" if ok else "open"
                    if ok:
                        entry.closed += 1
                        closed.append(entry.name)
                    self._cond.notify_all()
        return closed

    def sweep(self, settings: dict | None, release) -> list[str]:
        """Close every view that has been idle for `viewIdleEvictS`, except a keep-warm view (pending >= `viewKeepWarmRecords`).
        Each view is tested and marked closing in one step, so a request that pins it a moment later waits and reopens it."""
        limit = limits(settings)
        victims = []
        with self._cond:
            now = self.clock()
            for entry in self._entries.values():
                if (entry.state == "open" and entry.running == 0 and now - entry.last_used >= limit["idle_evict_s"]
                        and entry.pending < limit["keep_warm_records"]):
                    entry.state = "evicting"
                    victims.append(entry)
        return self._close(victims, release)

    def evict(self, key: str, release) -> bool:
        """Close one view now if it has no running request (a test and an operator's call). False when it is running or not open."""
        with self._cond:
            entry = self._entries.get(key)
            if entry is None or entry.state != "open" or entry.running:
                return False
            entry.state = "evicting"
        return bool(self._close([entry], release))

    def evict_lru(self, release, exclude: str | None = None) -> str | None:
        """Close the least recently used idle view (the engine said `capacity`). The name, or None when every view is running."""
        with self._cond:
            victim = self._victim(exclude)
            if victim is None:
                return None
            victim.state = "evicting"
        return victim.name if self._close([victim], release) else None

    def forget(self, key: str) -> None:
        with self._cond:
            self._entries.pop(key, None)

    def snapshot(self) -> list[dict]:
        with self._cond:
            now = self.clock()
            return [entry.row(now) for entry in sorted(self._entries.values(), key=lambda item: item.last_used)]

    def reset(self) -> None:
        with self._cond:
            self._entries.clear()
            self._swept.clear()

    # --- folders ------------------------------------------------------------------------------------------------
    def due_for_delete_sweep(self, lineage_id: str) -> bool:
        with self._cond:
            now = self.clock()
            if now - self._swept.get(lineage_id, -DELETE_SWEEP_S) < DELETE_SWEEP_S:
                return False
            self._swept[lineage_id] = now
            return True


GOVERNOR = Governor()


def delete_idle_folders(settings: dict, template: dict, lineage_id: str, engine, now: float | None = None) -> list[str]:
    """Delete the fork folder of every view of the lineage that nobody holds and that was idle for `viewIdleDeleteS`.

    The store is never touched (it holds every record, so the next use rebuilds the fork), a fork the engine still has open
    is kept, and a view with a live holder is skipped. The record says `deleted`."""
    from hydralysis import views, workcopy
    limit = limits(settings)
    now = time.time() if now is None else now
    removed = []
    for record in views.list_records(settings, lineage_id):
        if views.holder_state(record, now) != "orphaned" or record.get("state") == "deleted":
            continue
        if now - float(record.get("last_seen", now)) < limit["idle_delete_s"]:
            continue
        target = {**template, "key": record["key"], "view": record["view"]}
        state = workcopy._state(settings, target)
        forks = [item for item in [state.get("fork_gpr"), *state.get("retired", [])] if item]
        if forks and workcopy._retire(engine, forks):
            continue  # the engine still has one open: try again later
        shutil.rmtree(workcopy._directory(settings, target), ignore_errors=True)
        views.mark_state(settings, lineage_id, record["view"], "deleted", deleted_at=now)
        removed.append(record["view"])
    return removed
