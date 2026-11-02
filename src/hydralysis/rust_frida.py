"""The Rust runtime behind the Frida-shaped surface the runtime layer already uses (`HYDRALYSIS_IMPL=rust`).

`RuntimeAgent` talks to a Frida *device*: `spawn`, `attach`, `resume`, a *session* with `create_script`, and *scripts* with
`load`, `post`, `on("message")` and `exports_sync`. This module answers the same calls from `hydralysis_rt` (the PyO3 surface
over the `hy-runtime` crate: suspended spawn, injected agent DLL, shared-memory rings), so the worker, the trace writer and
the tools above them are unchanged. Python and Frida stay the default; nothing imports this module unless the variable says so.

What it serves: the CONTROL script (`info`, `modules`, `threads`, `module`, `locate`, `read`) and the TRACE recorder. The
other script templates (observe/break probes, the memory agent) are refused with a clear error until they are ported.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import sys
import queue
import threading
import time
from pathlib import Path

from hydralysis import runtime_agents

_REPO = Path(__file__).resolve().parents[2]
_RELEASE = _REPO / "rust" / "target" / "release"


class RustRuntimeUnavailable(RuntimeError):
    """The Rust runtime was asked for and its pieces are not there."""


def _load_rt():
    try:
        import hydralysis_rt          # type: ignore
        return hydralysis_rt
    except ImportError:
        pass
    candidates = [Path(p) for p in (os.environ.get("HYDRALYSIS_RT_PYD"),) if p] + [_RELEASE / "hydralysis_rt.dll"]
    for path in candidates:
        if path.is_file():
            loader = importlib.machinery.ExtensionFileLoader("hydralysis_rt", str(path))
            spec = importlib.util.spec_from_file_location("hydralysis_rt", str(path), loader=loader)
            module = importlib.util.module_from_spec(spec)
            sys.modules["hydralysis_rt"] = module
            loader.exec_module(module)
            return module
    raise RustRuntimeUnavailable("hydralysis_rt is not importable; build rust/crates/hy-py or set HYDRALYSIS_RT_PYD")


def agent_dll() -> str:
    path = Path(os.environ.get("HYDRALYSIS_AGENT_DLL") or _RELEASE / "hy_agent_dll.dll")
    if not path.is_file():
        raise RustRuntimeUnavailable("the agent library %s is missing; build rust/crates/hy-agent-dll or set HYDRALYSIS_AGENT_DLL" % path)
    return str(path)


def _hex(value: int) -> str:
    return "0x%x" % value


def _protection(protect: int) -> str:
    readable = protect & (0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80)
    writable = protect & (0x04 | 0x08 | 0x40 | 0x80)
    executable = protect & (0x10 | 0x20 | 0x40 | 0x80)
    return ("r" if readable else "-") + ("w" if writable else "-") + ("x" if executable else "-")


def _wrap_message(payload: dict) -> dict:
    return {"type": "send", "payload": payload}


class _Exports:
    """`script.exports_sync.name(...)` -> `script.rpc_<name>(...)`."""

    def __init__(self, script):
        self._script = script

    def __getattr__(self, name):
        method = getattr(self._script, "rpc_" + name, None)
        if method is None:
            raise AttributeError("the script exports no %r" % name)
        return method


class _Script:
    def __init__(self, session):
        self.session = session
        self._handlers = []
        self.exports_sync = _Exports(self)

    def on(self, event, handler):
        if event == "message":
            self._handlers.append(handler)

    def emit(self, payload: dict, data: bytes | None = None) -> None:
        message = _wrap_message(payload)
        for handler in list(self._handlers):
            handler(message, data)

    def load(self):
        pass

    def unload(self):
        pass

    def post(self, message):
        pass


class ControlScript(_Script):
    """The fixed CONTROL script: what is mapped where, read through the process handle."""

    def _rows(self):
        return self.session.rt.modules()

    @staticmethod
    def _row(m):
        return {"name": m["name"], "path": m["path"], "base": _hex(m["base"]), "size": m["size"]}

    def rpc_info(self, selected=None):
        modules = self._rows()
        same = (lambda p: p.lower())
        matches = [m for m in modules if selected and same(m["path"]) == same(selected)]
        main = matches[0] if len(matches) == 1 else (modules[0] if modules else None)
        if main is None:
            raise RuntimeError("the process has no modules yet")
        return {"pid": self.session.pid, "arch": "x64", "pointer_size": 8, "selected_module_found": len(matches) == 1,
                "main": self._row(main)}

    def rpc_modules(self, limit):
        modules = self._rows()
        return {"total": len(modules), "truncated": len(modules) > limit, "modules": [self._row(m) for m in modules[:limit]]}

    def rpc_threads(self, limit):
        ids = self.session.rt.threads()
        return {"total": len(ids), "truncated": len(ids) > limit,
                "threads": [{"id": tid, "state": "running", "context": {}} for tid in ids[:limit]]}

    def rpc_module(self, name):
        found = [m for m in self._rows() if m["path"] == name or m["name"] == name]
        if len(found) != 1:
            raise RuntimeError("module must match exactly one loaded path/name")
        return self._row(found[0])

    def _containing(self, address):
        for m in self._rows():
            if m["base"] <= address < m["base"] + m["size"]:
                return m
        return None

    def rpc_locate(self, address):
        value = int(str(address), 0)
        try:
            base, size, protect = self.session.rt.query(value)
            region = {"base": _hex(base), "size": size, "protection": _protection(protect)}
        except OSError:
            region = None
        module = self._containing(value)
        return {"range": region, "module": self._row(module) if module else None}

    def rpc_read(self, address, size):
        value = int(str(address), 0)
        base, length, protect = self.session.rt.query(value)
        if "r" not in _protection(protect) or value + size > base + length:
            raise RuntimeError("read exceeds readable memory range")
        return list(self.session.rt.read_memory(value, size))


class TraceScript(_Script):
    """The TRACE recorder: arms the declared probes in the injected agent, pumps its rings into wire batches and answers
    the same messages the Frida recorder sends (`trace_ready`, `trace_batch` with acknowledgements, `trace_counters`)."""

    def __init__(self, session, params: dict):
        super().__init__(session)
        self.p = params
        self.acked = 0
        self.sent = 0
        self.seq = 1
        self.window_waits = 0
        self.released = False
        self.mode = "recording"
        self.stop = threading.Event()
        self.cv = threading.Condition()
        self.thread = None
        self.sampler_thread = None
        self.deliver_thread = None
        self.outbox = queue.Queue()       # batches drained, not yet delivered: bounded by the acknowledgement window
        self.sites = {}                   # site id -> probe

    # ---- loading ----------------------------------------------------------------------------------------------------
    def load(self):
        rt = self.session.rt
        installed = []
        for probe in self.p["probes"]:
            idx = int(probe["id"]) - 1
            buf = probe.get("buf")
            spec = {"module": os.path.basename(probe["module"]), "base": int(str(probe["base"]), 0), "rva": int(probe["rva"]),
                    "expect": list(probe["expect"]), "nargs": int(probe.get("nargs") or 0),
                    "with_leave": bool(probe.get("with_leave")), "stack": int(probe.get("stack") or 1), "stride": 1}
            if buf:
                spec["buf"] = {"ptr_arg": int(buf["ptr_arg"]), "len_arg": buf.get("len_arg"), "fixed": int(buf.get("fixed") or 0),
                               "max": int(buf.get("max") or 64), "wide": bool(buf.get("wide")), "cstr": bool(buf.get("cstr"))}
                if buf.get("len_arg") is None:
                    spec["buf"]["len_arg"] = -1
            started = time.perf_counter()
            ok, code = rt.arm_site(idx, spec)
            if not ok:
                self._rollback()
                raise RuntimeError("PROBE REFUSED by the agent: %s (error %d)" % (probe["name"], code))
            self.sites[int(probe["id"])] = probe
            installed.append({"id": probe["id"], "name": probe["name"],
                              "address": _hex(int(str(probe["base"]), 0) + int(probe["rva"])),
                              "install_ms": int((time.perf_counter() - started) * 1000), "hook": "inline-stub",
                              "inline_refused": None})
        sampling = self.p.get("sampling") or {}
        names = {p["name"]: int(p["id"]) - 1 for p in self.p["probes"]}
        rt.configure_sampling(sampling.get("mode", "adaptive"), float(sampling.get("rate_budget", 120000)), int(sampling.get("stride", 1)),
                              int(sampling.get("interval_ms", 25)), [names[n] for n in sampling.get("exact", []) if n in names])
        self.freq = int(rt.counters()["qpc_freq"])
        context = {"debugger_present": False, "veh": [], "veh_error": None, "uef": None, "uef_error": None,
                   "frida_handler_index": None, "is_debugger_present_api": False, "engine": "hydralysis-rt"}
        self.deliver_thread = threading.Thread(target=self._deliver, name="rust-trace-deliver", daemon=True)
        self.deliver_thread.start()
        self.thread = threading.Thread(target=self._pump, name="rust-trace-pump", daemon=True)
        self.thread.start()
        self.sampler_thread = threading.Thread(target=self._sampler, name="rust-trace-sampler", daemon=True)
        self.sampler_thread.start()
        self.emit({"event": "trace_ready", "context": context, "qpc_freq": str(self.freq), "producer_gen": self.p["producer_gen"],
                   "pid": self.session.pid, "arch": "x64", "rings": self.p["rings"], "ring_bytes": self.p["ring_bytes"],
                   "batch_ms": self.p["batch_ms"], "bp_us": self.p["bp_us"], "window": self.p["window"], "installed": installed,
                   "qpc": str(self._qpc()),
                   "sampling": {"policy": sampling.get("mode", "adaptive"), "rate_budget_per_s": sampling.get("rate_budget"),
                                "stride": sampling.get("stride"), "exact": sampling.get("exact", []),
                                "interval_ms": sampling.get("interval_ms")}})

    def _rollback(self):
        try:
            self.session.rt.detach_sites()
        except Exception:
            pass

    @staticmethod
    def _qpc() -> int:
        import ctypes
        value = ctypes.c_int64()
        ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(value))
        return value.value

    # ---- the pump ---------------------------------------------------------------------------------------------------
    def _drain_once(self, ignore_window: bool = False) -> int:
        with self.cv:
            if not ignore_window and self.sent - self.acked >= self.p["window"]:
                self.window_waits += 1
                return 0
            first = self.seq
        batches = self.session.rt.drain_wire(int(self.p["producer_gen"]), first, int(self.p.get("batch_bytes") or (1 << 20)))
        for batch in batches:
            seq = self.seq
            self.seq += 1
            with self.cv:
                self.sent += 1
            self.outbox.put((seq, bytes(batch)))
        return len(batches)

    def _deliver(self):
        """Hand batches to the message handler (the encoder) off the thread that drains the rings: a slow writer
        delays acknowledgements, which hold the drain back, never the sampling policy or the hooks."""
        while True:
            item = self.outbox.get()
            try:
                if item is None:
                    return
                seq, data = item
                self.emit({"event": "trace_batch", "batch_seq": seq}, data)
            finally:
                self.outbox.task_done()

    def _sampler(self):
        interval = max(0.005, (self.p.get("sampling") or {}).get("interval_ms", 25) / 1000)
        while not self.stop.wait(interval):
            try:
                self.session.rt.sampling_tick()
            except Exception:
                if self.session.exited():
                    return

    def _pump(self):
        counter_every = max(0.01, self.p.get("counter_ms", 250) / 1000)
        batch_every = max(0.001, self.p.get("batch_ms", 20) / 1000)
        last_counter = time.monotonic()
        while not self.stop.is_set():
            moved = 0
            try:
                moved = self._drain_once()
                now = time.monotonic()
                if now - last_counter >= counter_every:
                    self._counters(False)
                    last_counter = now
            except Exception:                      # the target is going away; release() reports what is left
                if self.session.exited():
                    break
            if not moved:
                self.stop.wait(batch_every)

    def _counters(self, final: bool):
        rt = self.session.rt
        c = rt.counters()
        changes, effective, rows = rt.sampling_report()
        sampling_cfg = self.p.get("sampling") or {}
        hits = skipped = 0
        sites = []
        for idx, hit, kept, skip, stride in rows:
            probe = self.sites.get(idx + 1)
            if probe is None:
                continue
            hits += hit
            skipped += skip
            sites.append({"site": idx + 1, "probe": probe["name"], "hits": hit, "kept": kept, "skipped": skip, "stride": stride,
                          "rate_per_s": 0, "exact": probe["name"] in sampling_cfg.get("exact", [])})
        self.emit({"event": "trace_counters", "final": bool(final), "t": str(self._qpc()), "attempted": c["attempted"],
                   "dropped": c["dropped"], "read_failed": c["read_failed"], "no_ring": c["no_ring"], "entered": None, "left": None,
                   "busy": 0, "rings_used": rt.ring_count(), "stalls": c["stalls"], "stall_ticks": 0, "ring_reuses": 0,
                   "qpc_freq": str(self.freq), "window_waits": self.window_waits, "bp_us": self.p["bp_us"],
                   "batches_sent": self.sent, "batches_next": self.seq,
                   "rings": [{"ring": r["ring"], "attempted": r["attempted"], "dropped": r["dropped"], "read_failed": r["read_failed"]}
                             for r in c["rings"]],
                   "sampling": {"policy": sampling_cfg.get("mode", "adaptive"), "rate_budget_per_s": sampling_cfg.get("rate_budget"),
                                "effective_budget_per_s": round(effective), "stride_changes": changes, "hits": hits, "skipped": skipped,
                                "sites": sites}})

    # ---- Frida-shaped surface ---------------------------------------------------------------------------------------
    def post(self, message):
        if isinstance(message, dict) and message.get("type") == "ack":
            with self.cv:
                self.acked = max(self.acked, int(message["seq"]))

    def rpc_status(self):
        return {"installed": True, "mode": "released" if self.released else "recording"}

    def rpc_counters(self):
        c = self.session.rt.counters()
        return {"counters": [c["attempted"], c["dropped"], c["read_failed"], c["no_ring"], 0, 0, 0, self.session.rt.ring_count(),
                             c["stalls"], 0, 0], "rings": c["rings"], "batches_sent": self.sent}

    def rpc_flush(self):
        return self._drain_once(True)

    def rpc_release(self, timeout_ms):
        """Retire every probe (the agent proves no thread is inside a stub), drain what is left, stop the pump."""
        rt = self.session.rt
        started = time.monotonic()
        result = {"quiescent": False, "waited_ms": 0, "busy": 0, "entered": None, "left": None, "inline_sites": len(self.sites),
                  "inline_not_restored": 0}
        try:
            deadline = started + max(0.2, timeout_ms / 1000)
            while True:
                if self.session.exited():
                    # Nothing runs the stubs any more, and the rings live in the host's mapping: what the target wrote is
                    # still there to drain.
                    result["quiescent"] = True
                    result["exited"] = True
                    break
                try:
                    rt.detach_sites()
                    result["quiescent"] = True
                    break
                except Exception as exc:
                    result["error"] = str(exc)
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.02)
        finally:
            self.stop.set()
            for thread in (self.thread, self.sampler_thread):
                if thread is not None:
                    thread.join(2)
        if result["quiescent"]:
            while self._drain_once(True):
                pass
            self.outbox.join()                   # every batch is delivered before the final counters say how many there were
            self.released = True
            self.mode = "released"
            self._counters(True)
            result["note"] = "detached and quiescent; the script may be unloaded"
        else:
            result["note"] = "probes could not be retired; the recorder is retained in pass-through"
        result["waited_ms"] = int((time.monotonic() - started) * 1000)
        return result

    def unload(self):
        self.stop.set()
        if self.deliver_thread is not None:
            self.outbox.put(None)


class _Unsupported(_Script):
    def __init__(self, session, what):
        raise NotImplementedError("%s is not served by the Rust runtime yet; unset HYDRALYSIS_IMPL to use the Frida implementation" % what)


def _trace_params(source: str) -> dict | None:
    head, tail = runtime_agents.TRACE_AGENT.split("PARAMETERS", 1)
    if not (source.startswith(head) and source.endswith(tail)):
        return None
    text = source[len(head):len(source) - len(tail)] if tail else source[len(head):]
    return json.loads(text)


class RustSession:
    def __init__(self, rt, pid: int):
        self.rt = rt
        self.pid = pid
        self._detached_cbs = []
        self._detached_done = False
        self._lock = threading.Lock()
        self._watcher = threading.Thread(target=self._watch, name="rust-exit-watch", daemon=True)
        self._watcher.start()

    def on(self, event, handler):
        if event == "detached":
            self._detached_cbs.append(handler)

    def exited(self) -> bool:
        try:
            return self.rt.exit_code() is not None
        except Exception:
            return True

    def _watch(self):
        while True:
            try:
                if self.rt.wait_exit(200):
                    break
            except Exception:
                break
            if self._detached_done:
                return
        self._fire("process-terminated")

    def _fire(self, reason):
        with self._lock:
            if self._detached_done:
                return
            self._detached_done = True
        for cb in list(self._detached_cbs):
            try:
                cb(reason, None)
            except Exception:
                pass

    def create_script(self, source: str):
        if source == runtime_agents.CONTROL:
            return ControlScript(self)
        params = _trace_params(source)
        if params is not None:
            return TraceScript(self, params)
        if "writeCas" in source or "readback" in source:
            raise NotImplementedError("the memory agent is not served by the Rust runtime through the script surface yet "
                                      "(hydralysis_rt.RtSession.write_cas/arm_watch exist); unset HYDRALYSIS_IMPL for Frida")
        raise NotImplementedError("this script template is not served by the Rust runtime yet; unset HYDRALYSIS_IMPL for Frida")

    def detach(self):
        self._detached_done = True
        try:
            self.rt.detach_sites()
        except Exception:
            pass
        self.rt.close()


class RustDevice:
    """`frida.get_local_device()` as the runtime layer uses it."""

    def __init__(self):
        self._rt = _load_rt()
        self._pending = {}
        self._live = {}

    def spawn(self, argv, envp=None, cwd=None, **_ignored):
        env = None if envp is None else [(str(k), str(v)) for k, v in dict(envp).items()]
        session = self._rt.RtSession.spawn(str(argv[0]), [str(a) for a in argv[1:]], cwd=cwd, env=env)
        self._pending[session.pid] = session
        return session.pid

    def attach(self, pid):
        raw = self._pending.pop(int(pid), None)
        if raw is None:
            raw = self._rt.RtSession.attach(int(pid))
        raw.inject(agent_dll())
        self._live[int(pid)] = raw
        return RustSession(raw, int(pid))

    def resume(self, pid):
        raw = self._live.get(int(pid))
        if raw is None:
            raise RuntimeError("resume: pid %d was not spawned by this device" % int(pid))
        raw.resume()

    def enumerate_processes(self):
        raise NotImplementedError("process enumeration is not part of the Rust runtime surface")
