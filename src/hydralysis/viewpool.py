"""Warm workers for publish jobs: a publish hands its job file to an imported process instead of spawning one.

A publish job (`views.start_job`) used to spawn `python -m hydralysis.views <job.json>` for every publish: every publish
paid CPython's start and the package import in a new process (measured here: 0.12-0.17 s of wall per worker, 0.06 s of
CPU, of which 0.055 s is `import hydralysis.views`), and the agent paid a CreateProcess to make it (23 ms of its CPU).
This module keeps workers alive in this process, each having imported the package once, and hands one a job path at a
time over its stdin; the worker answers on its stdout after `views.run_job` returns.

What does not change: the job is still a separate process (`one job per worker at a time`), so a worker that dies, is
killed or cancels itself with `os._exit(3)` cannot take the agent down and leaves exactly the job record it wrote; the
record file, its fields and who writes them (`overlayjobs._update`, `views.run_job`) are untouched; the worker reads
`settings.json` next to the job exactly as the one-shot worker does; and `python -m hydralysis.views <job.json>` remains
the path for every publish the pool does not serve - the pool is an optimisation in front of it and any failure of the
pool falls back to it.

The pool never holds more workers than `publish_batch_max` (the existing cap on the changesets one publish batch
decides, default 8), spawns them on demand, keeps at most one idle worker per process (a second one is stopped as soon
as its job ends) and stops an idle worker after `IDLE_S`, so the standing cost is one worker while a process publishes
and nothing after `IDLE_S`. One job never runs twice: a job line is only handed to a live worker, and it is handed back
to the caller as "not delivered" (and so retried on the one-shot path) only when the write failed or the worker died
before its hello - and the hello is written before the worker reads any job line.

The worker's environment is fixed when it is spawned. A process whose environment asks for test faults
(`HYDRALYSIS_TEST_MODE` / `HYDRALYSIS_TEST_FAULT`) never pools: a fault point must reach the process that runs the job,
so those runs keep the one-shot path they were written for.
"""

from __future__ import annotations

import atexit
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

# Control lines on the worker's stdout. Anything else it writes (a warning, a library's print) is drained and dropped:
# its stdout was DEVNULL before, and the result of a job is the job record, never its output.
PREFIX = b"@hydralysis-viewpool "
READY_TIMEOUT_S = 10.0     # the first hello of a worker; a worker that is alive but slower still runs its job
IDLE_S = 2.0               # an idle worker is stopped after this long: the next publish of this process is the warm one
KEEP_IDLE = 1              # idle workers kept; a worker whose job ends while another is idle is stopped at once
TICK_S = 0.25
STOP_GRACE_S = 5.0         # an idle worker that does not exit when its stdin closes is killed
BACKSTOP_S = 600.0         # the worker's own idle limit, in case its parent's pipe ever outlives the parent


def command() -> list[str]:
    """The worker command. Tests replace this with a stub that speaks the same two control lines."""
    return [sys.executable, "-m", "hydralysis.viewpool", "--serve"]


def _test_faults() -> bool:
    return os.environ.get("HYDRALYSIS_TEST_MODE") == "1" or bool(os.environ.get("HYDRALYSIS_TEST_FAULT"))


def _say(**message) -> None:
    sys.stdout.buffer.write(PREFIX + json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n")
    sys.stdout.buffer.flush()


class _Worker:
    """One warm process and the reader of its control lines."""

    def __init__(self, child, pool: "Pool"):
        self.child = child
        self.pool = pool
        self.pid = child.pid
        self.ready = threading.Event()
        self.busy = False
        self.dead = False
        self.last_used = time.monotonic()

    def alive(self) -> bool:
        return not self.dead and self.child.poll() is None

    def read(self) -> None:  # the reader thread
        try:
            for line in iter(self.child.stdout.readline, b""):
                if not line.startswith(PREFIX):
                    continue    # a job's own output: it went nowhere before, it goes nowhere now
                try:
                    message = json.loads(line[len(PREFIX):])
                except ValueError:
                    continue
                if not isinstance(message, dict):
                    continue
                if message.get("ready"):
                    self.pid = int(message.get("pid") or self.child.pid)
                    self.ready.set()
                elif message.get("done"):
                    self.pool.finished(self)
        except (OSError, ValueError):
            pass
        finally:
            try:
                self.child.stdout.close()
            except (OSError, ValueError):
                pass
            self.pool.died(self)


class Pool:
    """The warm workers of this process: at most one job each, at most MAX alive, one idle kept."""

    def __init__(self):
        self.lock = threading.Lock()
        self.workers: list[_Worker] = []
        self.stopping: list[tuple[_Worker, float]] = []
        self.sweeper: threading.Thread | None = None
        self.closed = False
        self.broken = False
        self.env: dict | None = None

    # -- dispatch ------------------------------------------------------------------------------------------------------

    def send(self, path: Path, env: dict, max_workers: int) -> bool:
        fresh = False
        with self.lock:
            if self.closed or self.broken:
                return False
            if self.env is None:
                self.env = dict(env)
            elif (self.env.get("PYTHONPATH"), self.env.get("HYDRALYSIS_HARNESS")) != \
                    (env.get("PYTHONPATH"), env.get("HYDRALYSIS_HARNESS")):
                # Another package or another harness names the same worker's import and engine labels: not this pool.
                return False
            self._prune()
            worker = self._idle()
            if worker is not None:
                worker.busy = True
            elif len(self.workers) < max(1, int(max_workers)):
                try:
                    worker = self._spawn()
                except Exception:   # noqa: BLE001 - a spawn that fails is a fallback, never a failed publish
                    worker = None
                if worker is None:
                    self.broken = True
                    return False
                self.workers.append(worker)
                worker.busy = True
                fresh = True
            else:
                return False    # every worker is busy: this publish takes the one-shot path, exactly as before
        delivered = self._hand(worker, path)
        if not delivered and fresh:
            # A worker spawned by this call died before its hello: this environment cannot run the pool. Stop trying:
            # the caller spawns the one-shot worker for this publish and for the following ones.
            self.broken = True
        return delivered

    def _hand(self, worker: _Worker, path: Path) -> bool:
        line = (json.dumps({"job": str(path)}) + "\n").encode("ascii")
        try:
            worker.child.stdin.write(line)
            worker.child.stdin.flush()
        except (OSError, ValueError):
            # The worker's read end was gone before the line arrived: no job ran, so the caller may use the one-shot path.
            with self.lock:
                self._retire(worker)
            return False
        # No hello yet. `serve` writes it before it reads any job line, so a dead worker here never read this job; an
        # alive one is still importing and will read it.
        try:
            deadline = time.monotonic() + READY_TIMEOUT_S
            while not worker.ready.is_set() and worker.alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            return worker.ready.is_set() or worker.alive()
        except Exception:   # noqa: BLE001 - the line is already in the pipe: this job must never be run a second time
            return True

    # -- worker lifecycle ----------------------------------------------------------------------------------------------

    def _spawn(self) -> _Worker | None:
        from hydralysis import proc
        try:
            child = proc.popen(command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=dict(self.env or os.environ), **({} if os.name == "nt" else {"start_new_session": True}))
        except (OSError, ValueError):
            return None
        if getattr(child, "stdin", None) is None or getattr(child, "stdout", None) is None:
            try:
                child.kill()    # a child this process cannot speak to must not linger
            except Exception:   # noqa: BLE001 - it may not be a real process (a stand-in in a test)
                pass
            return None
        worker = _Worker(child, self)
        threading.Thread(target=worker.read, name="hydralysis-viewpool-reader", daemon=True).start()
        return worker

    def _idle(self) -> _Worker | None:
        idle = [worker for worker in self.workers if not worker.busy and worker.alive()]
        return max(idle, key=lambda worker: worker.last_used) if idle else None

    def _prune(self) -> None:
        self.workers = [worker for worker in self.workers if worker.alive()]

    def _retire(self, worker: _Worker) -> None:
        worker.dead = True
        if worker in self.workers:
            self.workers.remove(worker)
        try:
            worker.child.stdin.close()
        except (OSError, ValueError):
            pass

    def finished(self, worker: _Worker) -> None:
        """The worker ran its job: it is idle again, and the pool keeps at most KEEP_IDLE idle workers."""
        with self.lock:
            if worker.dead or worker not in self.workers:
                return
            worker.busy = False
            worker.last_used = time.monotonic()
            idle = [item for item in self.workers if not item.busy and item.alive()]
            excess = idle if self.closed else sorted(idle, key=lambda item: item.last_used)[:-KEEP_IDLE]
            for extra in excess:
                self._stop(extra)
            self._ensure_sweeper()

    def died(self, worker: _Worker) -> None:
        """The worker's stdout ended: it is gone. Its job, if it was running one, is as it left it."""
        with self.lock:
            worker.dead = True
            if worker in self.workers:
                self.workers.remove(worker)
        try:
            worker.child.stdin.close()
        except (OSError, ValueError):
            pass

    def _stop(self, worker: _Worker) -> None:
        """Ask an idle worker to exit by closing its stdin (its next read sees the end); the sweeper kills one that does not."""
        worker.dead = True
        if worker in self.workers:
            self.workers.remove(worker)
        try:
            worker.child.stdin.close()
        except (OSError, ValueError):
            pass
        self.stopping.append((worker, time.monotonic() + STOP_GRACE_S))

    # -- the sweeper: idle timeout, stop grace -------------------------------------------------------------------------

    def _ensure_sweeper(self) -> None:
        if self.sweeper is None or not self.sweeper.is_alive():
            self.sweeper = threading.Thread(target=self._sweep, name="hydralysis-viewpool-sweeper", daemon=True)
            self.sweeper.start()

    def _sweep(self) -> None:
        while True:
            time.sleep(TICK_S)
            kill: list[_Worker] = []
            idle = False
            with self.lock:
                now = time.monotonic()
                for worker in [item for item in self.workers if not item.busy and item.alive()]:
                    if self.closed or now - worker.last_used >= IDLE_S:
                        self._stop(worker)
                for entry in list(self.stopping):
                    worker, deadline = entry
                    if not worker.alive():
                        self.stopping.remove(entry)
                    elif now >= deadline:
                        self.stopping.remove(entry)
                        kill.append(worker)
                idle = not self.workers and not self.stopping
                if idle:
                    self.sweeper = None
            for worker in kill:   # outside the lock: a kill may take a while, and dispatches must not wait for it
                try:
                    from hydralysis import proc
                    proc.terminate_tree(worker.child)
                except (OSError, RuntimeError, ValueError):
                    pass
            if idle:
                return

    def close_all(self) -> None:
        with self.lock:
            self.closed = True
            for worker in [item for item in self.workers if not item.busy]:
                self._stop(worker)
            self._ensure_sweeper()

    def shutdown(self) -> None:
        """At interpreter exit: idle workers get their stop; a busy worker finishes its job and then sees its stdin end."""
        with self.lock:
            self.closed = True
            for worker in [item for item in self.workers if not item.busy]:
                self._stop(worker)


# -- the process's pool -----------------------------------------------------------------------------------------------

class NativePool:
    """The pool of `dispatch` under `HYDRALYSIS_IMPL=rust`: `hy_views::viewpool::Pool` behind `hydralysis_native.ViewPool`.

    It answers what `dispatch`, `disable`, `close_all` and the shutdown ask of a `Pool` (`send`, `broken`, `close_all`,
    `shutdown`, `workers` with `pid` and `busy`). The worker command is asked of `command()` at each send, so a replaced
    `command` is the one that runs. A test that builds `Pool()` itself, or replaces one of the pool's internals, gets the
    Python pool: nothing here is reachable from it."""

    def __init__(self, native):
        self._pool = native.ViewPool(IDLE_S, KEEP_IDLE, STOP_GRACE_S, READY_TIMEOUT_S)

    @classmethod
    def make(cls):
        if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() != "rust":
            return None
        try:
            import hydralysis_native as native
        except ImportError:
            return None
        return cls(native) if hasattr(native, "ViewPool") else None

    def send(self, path: Path, env: dict, max_workers: int) -> bool:
        return self._pool.send(str(path), command(), {key: str(value) for key, value in env.items()}, max(1, int(max_workers)))

    @property
    def broken(self) -> bool:
        return self._pool.broken

    @property
    def workers(self) -> list:
        return self._pool.workers

    def close_all(self) -> None:
        self._pool.close_all()

    def shutdown(self) -> None:
        self._pool.shutdown()


_POOL: Pool | None = None
_POOL_LOCK = threading.Lock()
_DISABLED = False


def dispatch(path: Path, env: dict, max_workers: int = 1) -> bool:
    """Hand the publish job at PATH to a warm worker, or answer False so the caller spawns the one-shot worker."""
    global _POOL
    if _test_faults():
        return False
    with _POOL_LOCK:
        if _DISABLED:
            return False
        if _POOL is None:
            _POOL = NativePool.make() or Pool()
            atexit.register(_shutdown)
        pool = _POOL
    try:
        delivered = pool.send(Path(path), env, max_workers)
    except Exception:   # noqa: BLE001 - a pool that cannot work must never fail a publish
        disable()
        return False
    if pool.broken:
        disable()
    return delivered


def disable() -> None:
    """Stop pooling in this process for good: every later publish takes the one-shot path."""
    global _DISABLED
    with _POOL_LOCK:
        _DISABLED = True
        pool = _POOL
    if pool is not None:
        try:
            pool.close_all()
        except Exception:   # noqa: BLE001 - the fallback path does not depend on this
            pass


def _shutdown() -> None:
    with _POOL_LOCK:
        pool = _POOL
    if pool is not None:
        try:
            pool.shutdown()
        except Exception:   # noqa: BLE001 - nothing here may raise at exit
            pass


def close_all() -> None:
    """Stop every idle worker now (tests and `disable`); busy workers are left to finish their job."""
    with _POOL_LOCK:
        pool = _POOL
    if pool is not None:
        pool.close_all()


# -- the worker --------------------------------------------------------------------------------------------------------

def serve() -> int:
    """`python -m hydralysis.viewpool --serve`: import once, say hello, run the job files this process is handed."""
    import queue

    from hydralysis import views   # the warm import: the job itself must not pay for it

    if os.name == "nt":
        import msvcrt
        msvcrt.setmode(0, os.O_BINARY)     # the job lines are bytes; the CRT must not translate them

    inbox: "queue.Queue[bytes | None]" = queue.Queue()

    def read() -> None:
        # Raw reads on the descriptor, not `sys.stdin.buffer`: a daemon thread blocked inside that buffered object's lock
        # makes CPython's finalization fail (`_enter_buffered_busy`), and this thread is blocked for the process's life.
        pending = b""
        try:
            while True:
                block = os.read(0, 65536)
                if not block:
                    break
                pending += block
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    if line.strip():
                        inbox.put(line)
        except (OSError, ValueError):
            pass
        inbox.put(None)     # the parent closed its end (or died): no job follows

    threading.Thread(target=read, name="hydralysis-viewpool-inbox", daemon=True).start()
    _say(ready=True, pid=os.getpid())
    while True:
        try:
            line = inbox.get(timeout=BACKSTOP_S)
        except queue.Empty:
            os._exit(0)     # a parent that never closed this pipe: end without waiting for the blocked reader thread
        if line is None:
            return 0
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict):
            continue
        if message.get("stop"):
            return 0
        job = message.get("job")
        if not isinstance(job, str) or not job:
            continue
        path = Path(job)
        try:
            views.run_job(path)
        except BaseException as exc:   # noqa: BLE001 - run_job records its own failures; this is what is left
            try:
                from hydralysis import overlayjobs
                overlayjobs._update(path, state="failed", error="%s: %s" % (type(exc).__name__, exc),
                                    finished_at=time.time())
            except Exception:   # noqa: BLE001 - the record is metadata; the exception is the answer
                pass
            _say(done=True)
            raise   # a worker whose job left it in an unknown state ends, as the one-shot worker did
        _say(done=True)


def main(argv: list[str]) -> int:
    if argv[:1] != ["--serve"]:
        sys.stderr.write("usage: python -m hydralysis.viewpool --serve\n")
        return 2
    return serve()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
