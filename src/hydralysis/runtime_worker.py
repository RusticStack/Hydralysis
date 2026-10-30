"""Optional isolated Frida worker. No REA or other MCP dependency."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

from hydralysis import durable
from hydralysis.runtime_actions import ActionsMixin
from hydralysis.runtime_capture import CaptureMixin
from hydralysis.runtime_events import EventLog
from hydralysis.runtime_memory import MemoryMixin
from hydralysis.runtime_agents import (  # noqa: F401  (re-exported: tests and callers import them from here)
    CONTEXT_HELPER, CONTROL, MEMORY_HELPER, _expect, _probe_source)
from hydralysis.runtime_ipc import serve as ipc_serve
from hydralysis.localio import read_text as local_read_text




def _write(path: Path, value: dict) -> None:
    """A mailbox record: sealed, the previous version kept as `.bak`, atomic and fsynced (durable.write_sealed)."""
    durable.write_sealed(path, value, indent=None)


def _load(path: Path) -> dict:
    """One mailbox file, unsealed. A file from before the seal (no `seal` key) loads as it is.

    FileNotFoundError when the file is absent; ValueError when it is not a JSON object or its seal does not match.
    """
    value = json.loads(local_read_text(path))
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    if "seal" in value:
        claimed = value.pop("seal")
        if claimed != durable.seal_of(value):
            raise ValueError("mis-sealed (content does not match its seal)")
    return value


def _read(path: Path) -> dict:
    """A mailbox record, {} when it was never written. A bad file falls back to its `.bak` (the previous sealed
    version) and, when that is no better, raises durable.StoreCorrupt: it never reads as empty."""
    try:
        reasons = {}
        for candidate in (path, durable.backup_path(path)):
            try:
                return _load(candidate)
            except FileNotFoundError:
                reasons[candidate.name] = "missing"
            except ValueError as exc:
                reasons[candidate.name] = str(exc)[:80]
        if all(reason == "missing" for reason in reasons.values()):
            return {}
        raise durable.StoreCorrupt(path, durable.backup_path(path), reasons)
    except OSError as exc:
        raise RuntimeError("runtime mailbox read failed: errno=%s winerror=%s path=%s: %s"
                           % (exc.errno, getattr(exc, "winerror", None), path, exc)) from exc


def _ready_record(worker: dict, observation: dict) -> dict:
    # Worker and target are different processes. Never let the target's pid
    # replace the worker identity used for admission and timeout cleanup.
    return {"ok": True, **observation, **worker}


def _created_ms(pid: int) -> int:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise OSError(ctypes.get_last_error(), "cannot query selected process identity")
        try:
            values = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *[ctypes.byref(value) for value in values]):
                raise OSError(ctypes.get_last_error(), "cannot read selected process creation time")
            ticks = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
            return ticks // 10000 - 11644473600000
        finally:
            kernel.CloseHandle(handle)
    if sys.platform == "darwin":
        from hydralysis.darwin_process import created_ms
        return created_ms(pid)
    stat = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
    boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
    return int((boot + int(stat[19]) / os.sysconf("SC_CLK_TCK")) * 1000)


def _process_path(pid: int) -> str:
    if sys.platform == "darwin":
        from hydralysis.darwin_process import process_path
        return process_path(pid)
    if os.name != "nt":
        return str(Path("/proc/%d/exe" % pid).resolve())
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "cannot inspect selected process path")
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "cannot inspect selected process path")
        return buffer.value
    finally:
        kernel.CloseHandle(handle)


def target_environment(overrides: dict) -> dict:
    """The caller's environment, not this worker's private TEMP/PYTHONPATH, plus overrides."""
    env = dict(os.environ)
    restore = json.loads(env.pop("HYDRALYSIS_TARGET_ENV_RESTORE", "{}") or "{}")
    for key, value in restore.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    env.update(overrides)
    return env


def _same_path(a: str, b: str) -> bool:
    return os.path.normcase(str(Path(a).resolve())) == os.path.normcase(str(Path(b).resolve()))


def decode_detour(data: bytes, address: int) -> dict | None:
    """The jump a hooking library writes over a function's first bytes, if it is one."""
    if len(data) >= 5 and data[0] == 0xE9:
        return {"kind": "jmp rel32", "length": 5, "target": address + 5 + int.from_bytes(data[1:5], "little", signed=True)}
    if len(data) >= 14 and data[:6] == bytes.fromhex("ff2500000000"):
        return {"kind": "jmp [rip+0] abs64", "length": 14, "target": int.from_bytes(data[6:14], "little")}
    if len(data) >= 12 and data[:2] == bytes.fromhex("48b8") and data[10:12] == bytes.fromhex("ffe0"):
        return {"kind": "mov rax, imm64; jmp rax", "length": 12, "target": int.from_bytes(data[2:10], "little")}
    if len(data) >= 13 and data[:2] == bytes.fromhex("49bb") and data[10:13] == bytes.fromhex("41ffe3"):
        return {"kind": "mov r11, imm64; jmp r11", "length": 13, "target": int.from_bytes(data[2:10], "little")}
    return None


_IMAGES: dict = {}


def _image(path: str):
    """A parsed module file, kept while the file is unchanged (a game exe is tens of MB)."""
    from hydralysis.pe import Image
    stat = Path(path).stat()
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    if key not in _IMAGES:
        _IMAGES.clear()
        _IMAGES[key] = Image(Path(path))
    return _IMAGES[key]


def file_bytes(path: str, rva: int, size: int, load_base: int | None = None) -> bytes:
    """What the module's file on disk holds at an RVA: the original, whatever is patched live.
    With load_base, as the loader leaves it there (base relocations applied)."""
    image = _image(path)
    return image.read_rva(rva, size) if load_base is None else image.loaded_bytes(rva, size, load_base)


# Bytes a probe overwrites at its site (a 5-byte jump, rounded up to whole instructions).
PROBE_SPAN = 8
# state.json is rewritten after a message at most this often (see RuntimeAgent._publish_soon).
PUBLISH_EVERY_S = 0.25


def _relocated(module: dict, rva: int, expected: list, actual: list) -> bool:
    """expect is the file's bytes and the live ones differ only by the loader's base relocations."""
    try:
        return list(file_bytes(module["path"], rva, len(expected))) == expected \
            and actual == list(file_bytes(module["path"], rva, len(expected), int(module["base"], 16)))
    except Exception:  # a module file that cannot be decoded gives no evidence
        return False


def _call_in_span(path: str, rva: int) -> str | None:
    """A call instruction inside the bytes a probe would overwrite, or None.

    The instrumentation relocates an overwritten call into its trampoline, so the callee
    returns into it; in testing (Frida 17.24.3, a probe over a call in a loop) such a probe
    could not be released again. Probe the call's target or the instruction after it.
    """
    try:
        image = _image(path)
        decoder = image._decoder()
        code = image.read_rva(rva, PROBE_SPAN + 15)
    except Exception:  # a module file that cannot be decoded gives no evidence either way
        return None
    for instruction in decoder.disasm(code, rva):
        if instruction.address >= rva + 5:
            break
        if instruction.mnemonic.startswith("call"):
            return "%s %s at rva %#x" % (instruction.mnemonic, instruction.op_str, instruction.address)
    return None


def _inside_function(path: str, rva: int) -> bool:
    """True when the module's pdata shows rva inside a function, not at its start (x64 only)."""
    try:
        bounds = _image(path)._bounds(rva)
    except Exception:  # not a PE we can read: no pdata evidence
        return False
    return bounds is not None and bounds[0] != rva




class RuntimeAgent(MemoryMixin, CaptureMixin, ActionsMixin):
    def __init__(self, directory: Path, device):
        self.directory = directory
        self.device = device
        self.session = None
        self.control = None
        self.pid = 0
        self.target_created_ms = 0
        self.target_exe = ""
        self.target_sha256 = ""
        self.paused_spawn = False
        self.detached = False
        self.detach_reason = ""
        self.ended = ""
        self.scripts = {}
        self.pauses = {}
        self.log = EventLog(directory, directory.name)
        self.init_memory()
        self.open_capture = None
        self._publish_gate = threading.Lock()
        self._published = 0.0
        self._timer = None
        self.lock = threading.RLock()
        self.write_lock = threading.Lock()
        self.state = "starting"
        self.closed = False

    # The ring and the counters live in the event log; these names are what callers and tests have always used.
    @property
    def events(self):
        return self.log.ring

    @property
    def event_bytes(self) -> int:
        return self.log.ring_size

    @property
    def sequence(self) -> int:
        return self.log.sequence

    @property
    def dropped(self) -> int:
        return self.log.dropped

    def snapshot(self):
        with self.lock:
            return {"session": self.directory.name, "state": self.state, "pid": self.pid,
                     "target_created_ms": self.target_created_ms, "spawn_paused": self.paused_spawn,
                     "detached": self.detached, "scripts": list(self.scripts), "paused_hooks": list(self.pauses),
                     "last_sequence": self.sequence, "dropped_events": self.dropped,
                     "log": self.log.head_info(), "messages_seen": self.log.counters["messages"],
                     **self.memory_state(), **({"ended": self.ended} if self.ended else {})}

    def publish(self):
        state = self.snapshot()
        with self.write_lock:
            _write(self.directory / "state.json", state)

    def _publish_soon(self):
        """state.json after a message, at most every PUBLISH_EVERY_S: a sealed, fsynced write per message cannot keep up
        with a probe that fires 20 times a second (the backlog delays every later request). The durable event log, not
        state.json, holds each event; the last publish before the worker ends is always made."""
        with self._publish_gate:
            if time.monotonic() - self._published >= PUBLISH_EVERY_S:
                self._published = time.monotonic()
                due = True
            else:
                due = False
                if self._timer is None:
                    self._timer = threading.Timer(PUBLISH_EVERY_S, self._publish_late)
                    self._timer.daemon = True
                    self._timer.start()
        if due:
            self.publish()

    def _publish_late(self):
        with self._publish_gate:
            self._timer = None
            self._published = time.monotonic()
        if self.directory.is_dir():
            try:
                self.publish()
            except Exception as exc:  # the next message or the final publish tries again
                print("deferred state publish failed:", repr(exc), flush=True)

    def message(self, script_id: str, message: dict, data=None):
        original = message
        encoded = json.dumps(message, ensure_ascii=False, default=str).encode("utf-8")
        clipped = False
        if len(encoded) > 8192:
            message = {"type": "truncated", "original_bytes": len(encoded), "head": encoded[:4096].decode("utf-8", "replace")}
            clipped = True
        if data is not None:
            message = {**message, "data_hex": bytes(data[:1024]).hex(), "data_truncated": len(data) > 1024}
            clipped = clipped or len(data) > 1024
        with self.lock:
            # Counted as it arrived: neither the clipping above nor the ring or the log below changes the counts.
            self.log.count_message(script_id, original, clipped)
            payload = message.get("payload", {})
            specs = (self.scripts.get(script_id) or {}).get("captures")
            if specs and isinstance(payload, dict) and payload.get("captures") is not None:
                from hydralysis.runtime_decode import decode_event
                payload["decoded"] = decode_event(specs, payload.pop("captures"))
            self.log.record(script_id, message)
            if message.get("type") == "error" and script_id in self.scripts:
                self.scripts[script_id]["script_error"] = str(message.get("description") or message.get("stack") or "script error")[:1000]
            if message.get("type") == "send" and isinstance(payload, dict) and payload.get("event") == "break":
                hook_id = payload["hook_id"]
                self.pauses[hook_id] = time.monotonic()
        self._publish_soon()

    def startup(self, initial: dict):
        exe = initial["exe"]
        if hashlib.sha256(Path(exe).read_bytes()).hexdigest() != initial["sha256"]:
            raise ValueError("target build changed before runtime startup")
        self.target_exe = exe
        self.target_sha256 = initial["sha256"]
        if initial["action"] == "spawn":
            options = {"envp": target_environment(initial.get("env") or {})}
            if initial.get("cwd"):
                options["cwd"] = initial["cwd"]
            self.pid = self.device.spawn([exe, *initial["argv"]], **options)
            self.paused_spawn = True
        else:
            self.pid = int(initial["pid"])
            if not _same_path(_process_path(self.pid), exe):
                raise ValueError("selected PID executable path differs from exe; attach refused")
        self.target_created_ms = _created_ms(self.pid)
        self.session = self.device.attach(self.pid)
        self.session.on("detached", self._detached)
        identity_error = None
        try:
            identity_ok = (_created_ms(self.pid) == self.target_created_ms
                           and _same_path(_process_path(self.pid), exe))
        except OSError as exc:
            identity_error = exc
            identity_ok = False
        if not identity_ok:
            try:
                self.session.detach()
                self.detached = True
            except Exception as exc:
                raise RuntimeError("target identity changed during attach; detach failed before any probe loaded: %s" % exc) from exc
            if identity_error is not None:
                raise RuntimeError("target identity recheck failed; detached before any probe loaded: errno=%s winerror=%s: %s"
                                   % (identity_error.errno, getattr(identity_error, "winerror", None), identity_error)) from identity_error
            raise ValueError("target identity changed during attach; detached before any probe loaded")
        self.control = self.session.create_script(CONTROL)
        self.control.on("message", lambda message, data: self.message("control", message, data))
        self.control.load()
        info = self.control.exports_sync.info(exe)
        if not _same_path(info["main"]["path"], exe):
            raise ValueError("attached process main module differs from selected executable: observed=%r selected=%r" % (info["main"]["path"], exe))
        self.state = "spawn_paused" if self.paused_spawn else "running"
        self.publish()
        return {"target": info, "sha256": initial["sha256"], "state": self.state,
                "pid": self.pid, "target_created_ms": self.target_created_ms}

    def _detached(self, reason=None, *args):
        self.detach_reason = str(reason or "")
        self.detached = True
        self.state = "detached"
        self.publish()

    def watchdog(self):
        while not self.closed:
            with self.lock:
                expired = [hook for hook, started in self.pauses.items() if time.monotonic() - started >= 30]
            for hook in expired:
                try:
                    self._continue(hook)
                    self.message(hook, {"type": "send", "payload": {"event": "auto_continue", "hook_id": hook, "reason": "30s pause deadline"}})
                except Exception as exc:
                    print("breakpoint auto-continue failed:", repr(exc), flush=True)
            time.sleep(0.1)

    def cleanup(self) -> dict:
        self.memory_before_cleanup()  # raises while a watch is not verified clear: the target keeps its handler
        errors = []
        for script_id in list(self.scripts):
            try:
                self._unload(script_id)
            except Exception as exc:
                errors.append("unload %s: %s" % (script_id, exc))
        detached = self.detached
        if self.session is not None and not detached:
            try:
                self.session.detach()
                detached = self.detached = True
                self.scripts.clear()
                self.pauses.clear()
            except Exception as exc:
                errors.append("detach: " + str(exc))
        if self.paused_spawn and (detached or not self.scripts):
            try:
                if _created_ms(self.pid) != self.target_created_ms:
                    raise RuntimeError("spawn PID identity changed; refusing resume")
                self.device.resume(self.pid)
                self.paused_spawn = False
            except Exception as exc:
                errors.append("resume owned spawn: " + str(exc))
        self.state = "cleanup_failed" if errors else "detached"
        self.publish()
        if errors:
            raise RuntimeError("runtime cleanup incomplete: " + "; ".join(errors))
        self.closed = True
        if self._timer is not None:
            self._timer.cancel()
        self.log.close()
        return {"state": "detached", "target_state": "unknown", "pid": self.pid,
                "spawn_resumed": not self.paused_spawn, "scripts_released": not self.scripts, **self.memory_cleanup_report()}


class RequestGate:
    """Serves each accepted IPC connection on its own thread, so the accept loop never waits for a request.

    `status` reads the in-memory snapshot under the agent's own lock and runs at once, beside a running request (the
    client sends it without the session's request lock). Every other action keeps one-at-a-time order through
    `serial`, as before; the client's session lock already sends at most one of them at a time. Past LIMIT connections
    at once a connection is served on the accept thread, which is the old serial behaviour, never a refusal.
    """

    CONCURRENT = frozenset({"status"})
    LIMIT = 8

    def __init__(self, secret: str, handle_request, limit: int = LIMIT):
        self.secret = secret
        self.handle_request = handle_request
        self.serial = threading.Lock()
        self.slots = threading.BoundedSemaphore(limit)
        self.threads: set[threading.Thread] = set()
        self.guard = threading.Lock()
        self.touched = time.monotonic()
        self.active = 0   # connections being served; the worker is never idle while one runs

    def idle(self, idle_s: float) -> bool:
        """No connection is being served and none was answered for IDLE_S. A request that outlasts the idle time
        keeps the worker (and its session) alive; the clock restarts when it is answered."""
        with self.guard:
            return self.active == 0 and time.monotonic() - self.touched >= idle_s

    def handler(self, action, args, budget):
        if action in self.CONCURRENT:
            return self.handle_request(action, args, budget)
        with self.serial:
            return self.handle_request(action, args, budget)

    def serve(self, connection) -> None:
        with connection:
            connection.settimeout(3)
            if ipc_serve(connection, self.secret, self.handler):
                self.touched = time.monotonic()

    def _finished(self) -> None:
        with self.guard:
            self.active -= 1

    def submit(self, connection) -> None:
        # Counted from the accept until the connection is served, so the loop's idle check never sees 0 in between.
        with self.guard:
            self.active += 1
        if not self.slots.acquire(blocking=False):
            try:
                self.serve(connection)
            finally:
                self._finished()
            return

        def run():
            try:
                self.serve(connection)
            finally:
                with self.guard:
                    self.threads.discard(thread)
                self.slots.release()
                self._finished()

        thread = threading.Thread(target=run, name="runtime-ipc", daemon=True)
        with self.guard:
            self.threads.add(thread)
        try:
            thread.start()
        except BaseException:
            with self.guard:
                self.threads.discard(thread)
            self.slots.release()
            self._finished()
            raise

    def drain(self, timeout: float) -> None:
        end = time.monotonic() + timeout
        with self.guard:
            threads = list(self.threads)
        for thread in threads:
            thread.join(max(0.0, end - time.monotonic()))


def main() -> int:
    import frida
    if len(sys.argv) > 1 and sys.argv[1] == "--processes":
        limit = int(sys.argv[2])
        processes = frida.get_local_device().enumerate_processes()
        print(json.dumps({"ok": True, "processes": [{"pid": p.pid, "name": p.name} for p in processes[:limit]],
                          "total": len(processes), "truncated": len(processes) > limit}))
        return 0
    directory = Path(sys.argv[1]).resolve()
    initial = _read(directory / "start.json")
    agent = RuntimeAgent(directory, frida.get_local_device())
    worker = {"pid": os.getpid(), "started_ms": _created_ms(os.getpid())}
    try:
        # A blocked native attach/spawn must not bypass the startup budget.
        startup_done = threading.Event()
        def startup_guard():
            if not startup_done.wait(25):
                try:
                    agent.cleanup()
                except Exception as exc:
                    print("startup cleanup failed:", repr(exc), flush=True)
        threading.Thread(target=startup_guard, daemon=True).start()
        try:
            observation = agent.startup(initial)
        finally:
            startup_done.set()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(0.25)
        secret = secrets.token_hex(32)
        _write(directory / "ready.json", {**_ready_record(worker, observation),
                                          "ipc": {"port": listener.getsockname()[1], "token": secret},
                                          # This worker answers `status` beside a running request (RequestGate); a
                                          # worker without the field serves one connection at a time.
                                          "concurrent_status": True})
    except Exception as exc:
        cleanup_error = None
        try:
            agent.cleanup()
        except Exception as cleanup:
            cleanup_error = str(cleanup)
        _write(directory / "ready.json", {**worker, "ok": False, "error": str(exc), "cleanup_error": cleanup_error})
        return 1
    threading.Thread(target=agent.watchdog, daemon=True).start()
    touched = time.monotonic()
    exit_code = 0
    def handle_request(action, args, budget):
        done = threading.Event()
        def deadline_guard():
            if not done.wait(budget):
                try:
                    agent.cleanup()
                except Exception as exc:
                    print("deadline cleanup failed:", repr(exc), flush=True)
        threading.Thread(target=deadline_guard, daemon=True).start()
        try:
            return agent.handle(action, args)
        finally:
            done.set()
    gate = RequestGate(secret, handle_request)
    gate.touched = touched
    try:
        while not agent.closed and (agent.tainted or not gate.idle(int(initial.get("idle_s", 600)))):
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            gate.submit(connection)
    finally:
        listener.close()
        gate.drain(65.0)   # the longest request budget (60 s) plus the IPC margin
        if not agent.closed:
            agent.ended = "idle: no request for %d s (runtime_idle_s)" % int(initial.get("idle_s", 600))
            try:
                agent.cleanup()
            except Exception as exc:
                print("runtime exit cleanup failed:", repr(exc), flush=True)
                exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
