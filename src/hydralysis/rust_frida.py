"""The Rust runtime behind the Frida-shaped surface the runtime layer already uses (`HYDRALYSIS_IMPL=rust`).

`RuntimeAgent` talks to a Frida *device*: `spawn`, `attach`, `resume`, a *session* with `create_script`, and *scripts* with
`load`, `post`, `on("message")` and `exports_sync`. This module answers the same calls from `hydralysis_rt` (the PyO3 surface
over the `hy-runtime` crate: suspended spawn, injected agent DLL, shared-memory rings), so the worker, the trace writer and
the tools above them are unchanged. Python and Frida stay the default; nothing imports this module unless the variable says so.

What it serves: the CONTROL script (`info`, `modules`, `threads`, `module`, `locate`, `read`), the TRACE recorder, the
observe/break probe (`ObserveScript`) and the memory agent (`MemoryScript`: compare-and-swap writes and hardware watches).
Any other script is refused with a clear error. rust/crates/hy-runtime/PORTING.md lists what differs from the Frida scripts.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import sys
import queue
import struct
import threading
import time
from pathlib import Path

from hydralysis import runtime_agents
from hydralysis.runtime_memory import MEMORY_AGENT

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
        rows = self.session.rt.thread_report()
        return {"total": len(rows), "truncated": len(rows) > limit,
                "threads": [{"id": tid, "state": state, "context": {name: _hex(value) for name, value in regs.items()}}
                            for tid, state, regs in rows[:limit]]}

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
        self.known = {}                   # base -> module row, for the path of an unload

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
        self.known = {m["base"]: m for m in rt.modules()}
        self.session.hub.add(self)
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

    def on_event(self, kind: int, tid: int, data: list, qpc: int) -> None:
        """`trace_module`: the loader told the agent a module was mapped (5) or unmapped (6). The agent sends the base, the
        size and the first 24 characters of the base name; the path is the one the module list gives for that base."""
        if kind not in (5, 6) or self.released:
            return
        base, size = data[0], data[1]
        name = b"".join(int(word).to_bytes(8, "little") for word in data[2:5]).split(b"\0")[0].decode("ascii", "replace")
        if kind == 5:
            try:
                path = next((m["path"] for m in self.session.rt.modules() if m["base"] == base), name)
            except OSError:
                path = name
            row = {"name": name, "path": path, "base": base, "size": size}
            self.known[base] = row
        else:
            row = self.known.pop(base, {"name": name, "path": name, "base": base, "size": size})
        self.emit({"event": "trace_module", "op": "load" if kind == 5 else "unload", "t": str(qpc or self._qpc()),
                   "name": row["name"], "path": row["path"], "base": _hex(base), "size": row["size"]})

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

    def _entered_left(self, c: dict) -> tuple[int, int]:
        """Calls the recorder took into a stub that wants their return, and those that came back (or were abandoned by an
        unwound frame). `entered - left` is what is still inside plus any record the full ring refused."""
        entered = sum(c["sites"][int(i) - 1][1] for i, probe in self.sites.items() if probe.get("with_leave"))
        return entered, c["returned"] + c["unreturned"]

    def _counters(self, final: bool):
        rt = self.session.rt
        c = rt.counters()
        changes, effective, rows = rt.sampling_report()
        sampling_cfg = self.p.get("sampling") or {}
        hits = skipped = 0
        sites = []
        entered, left = self._entered_left(c)
        for idx, hit, kept, skip, stride, rate in rows:
            probe = self.sites.get(idx + 1)
            if probe is None:
                continue
            hits += hit
            skipped += skip
            sites.append({"site": idx + 1, "probe": probe["name"], "hits": hit, "kept": kept, "skipped": skip, "stride": stride,
                          "rate_per_s": round(rate), "exact": probe["name"] in sampling_cfg.get("exact", [])})
        self.emit({"event": "trace_counters", "final": bool(final), "t": str(self._qpc()), "attempted": c["attempted"],
                   "dropped": c["dropped"], "read_failed": c["read_failed"], "no_ring": c["no_ring"], "entered": entered, "left": left,
                   "busy": 0, "rings_used": rt.ring_count(), "stalls": c["stalls"], "stall_ticks": c["stall_ticks"], "ring_reuses": 0,
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
        entered, left = self._entered_left(c)
        return {"counters": [c["attempted"], c["dropped"], c["read_failed"], c["no_ring"], entered, left, 0, self.session.rt.ring_count(),
                             c["stalls"], c["stall_ticks"], 0], "rings": c["rings"], "batches_sent": self.sent}

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
            self.session.hub.remove(self)
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
            result["entered"], result["left"] = self._entered_left(rt.counters())
            result["note"] = "detached and quiescent; the script may be unloaded"
        else:
            result["note"] = "probes could not be retired; the recorder is retained in pass-through"
        result["waited_ms"] = int((time.monotonic() - started) * 1000)
        return result

    def unload(self):
        self.stop.set()
        self.session.hub.remove(self)
        if self.deliver_thread is not None:
            self.outbox.put(None)


# ---- the observe/break probe ------------------------------------------------------------------------------------------
#
# The probe template is recognised by its text (head and tail are the template's own, the middle is its JSON parameters),
# so a script that merely looks like one is refused. Sites 48..63 of the agent belong to these probes; the trace recorder
# owns 0..47, and the PyO3 layer keeps each one's hits apart when both drain the rings.

OBSERVE_BASE = 48
OBSERVE_SITES = 16
_STRIDE_OFF = 1 << 20          # past the hit limit a site keeps one record in a million: hits stay counted, nothing parks
_ARG_REGS = ("rcx", "rdx", "r8", "r9")


def _probe_template() -> tuple[str, str]:
    reference = runtime_agents._probe_source({"path": "m", "base": "0x0"}, 0, [0] * 5, "ID", 1, False)
    return reference[:reference.index("const p=") + 8], reference[reference.index(";\nconst all="):]


def _probe_params(source: str) -> dict | None:
    head, tail = _probe_template()
    if not (source.startswith(head) and source.endswith(tail)):
        return None
    return json.loads(source[len(head):len(source) - len(tail)])


def _scalar(hexed: str, kind: str) -> float | int:
    raw = bytes.fromhex(hexed)
    formats = {"f32": "<f", "f64": "<d", "i32": "<i", "u32": "<I", "i16": "<h", "u16": "<H", "u8": "<B"}
    if kind in formats:
        return struct.unpack(formats[kind], raw[:struct.calcsize(formats[kind])])[0]
    return int.from_bytes(raw[:8], "little") if len(raw) >= 8 else int.from_bytes(raw[:4], "little")


class ObserveScript(_Script):
    """`_probe_source`: one guarded probe at a verified site. The agent hooks it, the hub turns its hits into the events
    the Frida probe sends (`probe_installed`, `enter` or `break`, `return`, `sample`, `probe_removed`)."""

    def __init__(self, session, params: dict):
        super().__init__(session)
        self.p = params
        self.idx = None
        self.emitted = 0
        self.thinned = False
        self.agg = {"count": 0, "min": None, "max": None, "last": None}
        self.next_window = None
        self.removed = False
        self.plain = None                       # index of the capture the agent reads at hit time, if any

    @property
    def pointer(self) -> int:
        return int(str(self.p["base"]), 0) + int(self.p["rva"])

    def _module(self):
        found = [m for m in self.session.rt.modules() if m["path"] == self.p["module"]]
        if len(found) != 1 or _hex(found[0]["base"]) != self.p["base"]:
            raise RuntimeError("module mapping changed before probe installation")
        return found[0]

    def load(self):
        p = self.p
        if p["convention"] != "native":
            raise RuntimeError("convention %s is for 32-bit x86 targets" % p["convention"])
        module = self._module()
        spec = {"module": os.path.basename(p["module"]), "base": int(str(p["base"]), 0), "rva": int(p["rva"]),
                "expect": list(p["expect"]), "nargs": 8, "stride": 1, "pause": bool(p["pause"]),
                "export": p.get("export"), "with_leave": not (p["instruction"] or p["pause"] or p.get("sample")),
                "stack": 1 if p.get("sample") else 15}
        first = p["captures"][0] if p["captures"] else None
        if first and first["reg"] is None and not first["deref"] and not first["value_only"] and first["arg"] < 8:
            size = 8 if first["ptr"] else int(first["size"])
            if 0 < size <= 256:
                spec["buf"] = {"ptr_arg": int(first["arg"]), "len_arg": -1, "fixed": size, "max": size}
                self.plain = 0
        self.idx = self.session.take_site()
        try:
            ok, code = self.session.rt.arm_site(self.idx, spec)
        except BaseException:
            self.session.give_site(self.idx)
            self.idx = None
            raise
        if not ok:
            self.session.give_site(self.idx)
            self.idx = None
            if code == 10:
                raise RuntimeError("PROLOGUE MISMATCH; probe refused")
            if code == 3:
                raise RuntimeError("EXPORT MISMATCH; probe refused")
            raise RuntimeError("PROBE REFUSED by the agent: %s (error %d)" % (p["id"], code))
        self.session.hub.add(self)
        if p.get("sample"):
            self.next_window = time.monotonic() + p["sample"]["window_s"]
        self.emit({"event": "probe_installed", "hook_id": p["id"], "address": _hex(module["base"] + int(p["rva"])),
                   "verified_bytes": list(p["expect"])})

    # ---- hits -------------------------------------------------------------------------------------------------------
    def _capture(self, spec: dict, hit: dict) -> dict:
        rt = self.session.rt
        args = hit["args"]
        if spec["reg"] is not None:
            if spec["reg"] not in _ARG_REGS:
                return {"error": "no register %s on x64" % spec["reg"]}
            value = args[_ARG_REGS.index(spec["reg"])]
        else:
            value = args[spec["arg"]] if spec["arg"] < len(args) else 0
        width = 8 if spec["ptr"] else int(spec["size"])
        if spec["value_only"]:
            return {"pointer": _hex(value), "hex": value.to_bytes(8, "little")[:width].ljust(width, b"\0").hex()}
        try:
            for offset in spec["deref"]:
                value = int.from_bytes(rt.read_memory(value + offset, 8), "little")
        except OSError:
            return {"error": "unreadable pointer at %s" % _hex(value)}
        try:
            return {"pointer": _hex(value), "hex": bytes(rt.read_memory(value, width)).hex()}
        except OSError:
            return {"pointer": _hex(value), "error": "unreadable %d bytes" % width}

    def _captures(self, hit: dict) -> list:
        out = []
        for index, spec in enumerate(self.p["captures"]):
            if index == self.plain:
                pointer = hit["args"][spec["arg"]]
                out.append({"pointer": _hex(pointer), "error": "unreadable %d bytes" % len(hit["buf"])} if hit["buf_failed"] or not hit["buf"]
                           else {"pointer": _hex(pointer), "hex": bytes(hit["buf"]).hex()})
            else:
                out.append(self._capture(spec, hit))
        return out

    def dispatch(self, hit: dict) -> None:
        p = self.p
        if p.get("sample"):
            self.agg["count"] += 1
            captures = self._captures(hit)
            chosen = captures[p["sample"]["capture"]] if p["sample"]["capture"] < len(captures) else None
            if chosen and chosen.get("hex"):
                x = _scalar(chosen["hex"], p["sample"]["as"])
                a = self.agg
                a["last"] = x
                a["min"] = x if a["min"] is None or x < a["min"] else a["min"]
                a["max"] = x if a["max"] is None or x > a["max"] else a["max"]
            return
        if self.emitted >= p["limit"]:
            return
        self.emitted += 1
        args = list(hit["args"]) + [0] * (8 - len(hit["args"]))
        context = {"pc": _hex(self.pointer)}
        context.update({name: _hex(args[i]) for i, name in enumerate(_ARG_REGS)})
        self.emit({"event": "break" if p["pause"] else "enter", "hook_id": p["id"], "hit": self.emitted, "thread": hit["tid"],
                   "address": _hex(self.pointer), "return_address": None if p["instruction"] else _hex(hit["ret_addr"]),
                   "context": context, "arguments": [_hex(a) for a in args[:8]],
                   "backtrace": [_hex(a) for a in hit["stack"][:16]], "captures": self._captures(hit)})
        if hit["returned"]:
            self.emit({"event": "return", "hook_id": p["id"], "thread": hit["tid"], "value": _hex(hit["retval"])})
        if self.emitted >= p["limit"] and not self.thinned:
            self.thinned = True
            self.session.rt.set_stride(self.idx, _STRIDE_OFF)

    def tick(self) -> None:
        sample = self.p.get("sample")
        if sample and self.next_window is not None and time.monotonic() >= self.next_window:
            a, window = self.agg, sample["window_s"]
            self.emit({"event": "sample", "hook_id": self.p["id"], "window_s": window, "count": a["count"],
                       "rate": a["count"] / window, "min": a["min"], "max": a["max"], "last": a["last"]})
            self.agg = {"count": 0, "min": None, "max": None, "last": a["last"]}
            self.next_window += window

    # ---- Frida-shaped surface ---------------------------------------------------------------------------------------
    def post(self, message):
        """`continue:<hook id>` lets the longest-parked thread of this probe run (one `recv().wait()` is released)."""
        if isinstance(message, dict) and message.get("type") == "continue:" + str(self.p["id"]) and self.idx is not None:
            parked = sorted((q for q in self.session.rt.paused() if q[2] == self.idx), key=lambda q: -q[3])
            if parked:
                self.session.rt.continue_breakpoint(parked[0][0])

    def _release_all(self) -> None:
        for slot, _tid, site, _age in self.session.rt.paused():
            if site == self.idx:
                self.session.rt.continue_breakpoint(slot)

    def rpc_status(self):
        return {"installed": self.idx is not None and not self.removed}

    def rpc_counters(self):
        seen = self.session.rt.counters()["sites"][self.idx][0] if self.idx is not None else 0
        return {"seen": seen, "hits": min(seen, self.p["limit"]), "limit": self.p["limit"]}

    def rpc_release(self):
        self._retire()
        self.emit({"event": "probe_removed", "hook_id": self.p["id"]})

    def _retire(self) -> None:
        if self.idx is None or self.removed:
            return
        self.removed = True
        self.session.hub.remove(self)
        try:
            if self.session.exited():
                return                      # nothing runs the stub any more, and the agent cannot answer
            self._release_all()
            ok, code = self.session.rt.retire_site(self.idx)
            if not ok:
                raise RuntimeError("the probe could not be retired (error %d)" % code)
        finally:
            self.session.give_site(self.idx)
            self.idx = None

    def unload(self):
        self._retire()


# ---- the memory agent --------------------------------------------------------------------------------------------------

_MEMORY_REASON = "memory agent call (the worker has applied its own gate)"


class MemoryScript(_Script):
    """`MEMORY_AGENT`: compare-and-swap writes and hardware watches. The worker has already applied the policy gate
    (fixture or authorization), so the runtime's own gate is the fixture gate here: data ranges only, readback, CAS."""

    def __init__(self, session):
        super().__init__(session)
        self.watches = {}                       # watch id -> {"slot" (runtime), "py_slot", "limit", "sent"}

    def load(self):
        self.session.hub.add(self)
        self.emit({"event": "memory_agent_ready", "arch": "x64"})

    def unload(self):
        self.session.hub.remove(self)

    def rpc_writeCas(self, address, expect, value):
        rt = self.session.rt
        target, n = int(str(address), 0), len(expect)
        if n != len(value):
            raise RuntimeError("size mismatch")
        actual = list(rt.read_memory(target, n))
        if actual != list(expect):
            return {"ok": False, "actual": actual}
        try:
            rt.write_cas(target, bytes(expect), bytes(value), _MEMORY_REASON)
        except RuntimeError as exc:
            if "compare failed" in str(exc):          # a racing writer changed it between our read and the swap
                return {"ok": False, "actual": list(rt.read_memory(target, n))}
            raise
        return {"ok": True, "actual": actual, "after": list(rt.read_memory(target, n))}

    def rpc_arm(self, watch_id, slot, address, size, cond):
        rt = self.session.rt
        runtime_slot = rt.arm_watch(int(str(address), 0), int(size), "write" if cond == "w" else "rw", 200)
        self.watches[watch_id] = {"slot": runtime_slot, "py_slot": int(slot), "limit": 20, "sent": 0}
        return {"armed": rt.watch_threads(runtime_slot), "failed": []}

    def rpc_limit(self, watch_id, n):
        if watch_id in self.watches:
            self.watches[watch_id]["limit"] = int(n)
        return True

    def rpc_rearm(self, watch_id):
        w = self.watches.get(watch_id)
        if w is None:
            return {"armed": [], "failed": []}
        rt = self.session.rt
        before = set(rt.watch_threads(w["slot"]))
        rt.sync_watch_threads()
        return {"armed": sorted(set(rt.watch_threads(w["slot"])) - before), "failed": []}

    def rpc_disarm(self, watch_id):
        w = self.watches.get(watch_id)
        if w is None:
            return {"unset": [], "failed": []}
        rt = self.session.rt
        covered = rt.watch_threads(w["slot"])
        try:
            phase = rt.disarm_watch(w["slot"])
        except RuntimeError:                         # already clear: nothing left to unset
            return {"unset": [], "failed": [], "gone": [], "seen": rt.watch_hits(w["slot"])}
        failed = [] if phase == "clear" else [{"id": tid, "error": "debug register not cleared"} for tid in covered]
        return {"unset": covered, "failed": failed, "gone": [], "seen": rt.watch_hits(w["slot"])}

    def rpc_readback(self):
        rows, unreadable = self.session.rt.read_dr7()
        python_slot = {w["slot"]: w["py_slot"] for w in self.watches.values()}
        threads = []
        for tid, dr7 in rows:
            enabled = [python_slot.get(slot, slot) for slot in range(4) if (dr7 >> (2 * slot)) & 3]
            threads.append({"id": tid, "dr7": dr7, "enabled_slots": enabled})
        return {"threads": threads, "unreadable": list(unreadable)}

    def rpc_counters(self, watch_id):
        w = self.watches.get(watch_id)
        return {"seen": self.session.rt.watch_hits(w["slot"]), "limit": w["limit"]} if w else None

    def on_event(self, kind: int, tid: int, data: list, _qpc: int) -> None:
        if kind != 3:
            return
        rip, bitmap = data[0], data[3]
        for watch_id, w in list(self.watches.items()):
            if bitmap & (1 << w["slot"]) and w["sent"] < w["limit"]:
                w["sent"] += 1
                self.emit({"event": "watch_hit", "watch": watch_id, "thread": tid, "pc": _hex(rip), "ctx": {"pc": _hex(rip)}})


class _Hub:
    """One thread per session that moves the agent's side channels into the scripts: probe hits to the observe probes,
    watch events to the memory agent, the sample windows to their timers."""

    def __init__(self, session):
        self.session = session
        self.scripts = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None

    def add(self, script) -> None:
        with self.lock:
            self.scripts.append(script)
            if self.thread is None:
                self.thread = threading.Thread(target=self._run, name="rust-hub", daemon=True)
                self.thread.start()

    def remove(self, script) -> None:
        with self.lock:
            if script in self.scripts:
                self.scripts.remove(script)

    def close(self) -> None:
        self.stop.set()

    def _run(self) -> None:
        rt = self.session.rt
        while not self.stop.wait(0.004):
            with self.lock:
                scripts = list(self.scripts)
            observers = {s.idx: s for s in scripts if isinstance(s, ObserveScript) and s.idx is not None}
            listeners = [s for s in scripts if hasattr(s, "on_event")]
            try:
                if observers:
                    for hit in rt.drain_hits():
                        script = observers.get(hit["site"])
                        if script is not None:
                            script.dispatch(hit)
                if listeners:
                    for kind, _site, tid, _slot, data, qpc in rt.events():
                        for script in listeners:
                            script.on_event(kind, tid, data, qpc)
                for script in scripts:
                    if isinstance(script, ObserveScript):
                        script.tick()
            except Exception:
                if self.session.exited():
                    return


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
        self.hub = _Hub(self)
        self._free_sites = list(range(OBSERVE_BASE, OBSERVE_BASE + OBSERVE_SITES))
        self._watcher = threading.Thread(target=self._watch, name="rust-exit-watch", daemon=True)
        self._watcher.start()

    def take_site(self) -> int:
        with self._lock:
            if not self._free_sites:
                raise RuntimeError("at most %d observe/break probes at once on the Rust runtime" % OBSERVE_SITES)
            return self._free_sites.pop(0)

    def give_site(self, idx: int) -> None:
        with self._lock:
            self._free_sites.insert(0, idx)

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
        probe = _probe_params(source)
        if probe is not None:
            return ObserveScript(self, probe)
        if source == MEMORY_AGENT:
            return MemoryScript(self)
        raise NotImplementedError("this script is not one of the templates the Rust runtime serves (control, trace, probe, "
                                  "memory); unset HYDRALYSIS_IMPL to use the Frida implementation")

    def detach(self):
        self._detached_done = True
        self.hub.close()
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
