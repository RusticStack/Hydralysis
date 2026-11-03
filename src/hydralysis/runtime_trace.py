"""The runtime worker's trace capture: `trace_start`, `trace_status` and `trace_stop` (a mixin of `RuntimeAgent`).

`trace_start` resolves the probes the way `observe` does (the module is the one the hash names, the bytes at the site
are the module file's own, no call sits in the span the hook overwrites), refuses what the host's fault policy forbids,
loads the native recorder (`runtime_agents.trace_agent_source`) and opens a `TraceSource` that appends the batches the
recorder sends. `trace_stop` is the teardown of spec 14.9: pass-through, detach, prove the callbacks quiescent, and
only then free them. A recorder that cannot prove it keeps its safe state (pass-through, still attached) and the stop
says so; the session is not detached underneath it.

The built-in `driver-boundary` set hooks the user-mode side of a driver: `CreateFileW` (device paths), `DeviceIoControl`
(the IOCTL code), SetupAPI and CfgMgr. No driver of ours is involved (plan decision 6).
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
import threading
import time
import uuid

from hydralysis.runtime_agents import normalize_sampling, trace_agent_source
from hydralysis.trace_capture import FAULT_POLICIES, TraceRefused, TraceSource, check_probe_policy

RING_BYTES = (1 << 16, 1 << 24)
# The defaults a capture runs with (no flag changes them for a normal run; a request may override them for a test).
DEFAULT_RING_BYTES = 1 << 20
DEFAULT_RINGS = 32
BATCH_MS = 10
BACKPRESSURE_MS = 2.0     # a hook waits this long for a full ring at most; the sampling policy is the first line, not a stall
ACK_WINDOW = 16
MAX_PROBES = 48
SITE_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:<>~$@?-]{0,95}$")

DRIVER_BOUNDARY = [
    {"name": "CreateFileW", "module": "KernelBase.dll", "export": "CreateFileW", "kind": "open", "nargs": 7, "with_leave": True,
     "buf": {"ptr_arg": 0, "wide": True, "max": 256}, "required": True},
    {"name": "DeviceIoControl", "module": "KernelBase.dll", "export": "DeviceIoControl", "kind": "ioctl", "nargs": 8,
     "with_leave": True, "buf": None, "required": True, "payload_buf": {"ptr_arg": 2, "len_arg": 3, "max": 256}},
    {"name": "SetupDiGetClassDevsW", "module": "setupapi.dll", "export": "SetupDiGetClassDevsW", "kind": "devquery", "nargs": 4,
     "with_leave": True, "buf": {"ptr_arg": 0, "fixed": 16, "max": 16}},
    {"name": "SetupDiEnumDeviceInterfaces", "module": "setupapi.dll", "export": "SetupDiEnumDeviceInterfaces", "kind": "devquery",
     "nargs": 5, "with_leave": True, "buf": {"ptr_arg": 2, "fixed": 16, "max": 16}},
    {"name": "CM_Locate_DevNodeW", "module": "cfgmgr32.dll", "export": "CM_Locate_DevNodeW", "kind": "devquery", "nargs": 3,
     "with_leave": True, "buf": {"ptr_arg": 1, "wide": True, "max": 256}},
    {"name": "CM_Get_Device_IDW", "module": "cfgmgr32.dll", "export": "CM_Get_Device_IDW", "kind": "devquery", "nargs": 4,
     "with_leave": True, "buf": None},
]


HANDLE_LIFETIME = [
    {"name": "CreateFileW", "module": "KernelBase.dll", "export": "CreateFileW", "kind": "open", "nargs": 7, "with_leave": True,
     "buf": {"ptr_arg": 0, "wide": True, "max": 256}, "required": True},
    {"name": "CloseHandle", "module": "KernelBase.dll", "export": "CloseHandle", "kind": "close", "nargs": 1, "with_leave": True,
     "buf": None, "required": True},
]
BUILTIN_SETS = {"driver-boundary": DRIVER_BOUNDARY, "handle-lifetime": HANDLE_LIFETIME}
MAX_STACK = 15


def qpc_frequency() -> int:
    if os.name != "nt":
        raise TraceRefused("the trace clock is QueryPerformanceCounter; this host is not Windows")
    value = ctypes.c_longlong()
    ctypes.WinDLL("kernel32").QueryPerformanceFrequency(ctypes.byref(value))
    return int(value.value)


def _hooking(value) -> str:
    value = "inline" if value is None else value
    if value not in ("inline", "interceptor"):
        raise ValueError("hooking is inline (plain call sites patched directly, the default) or interceptor")
    return value


def prologue_detour(patterns: list[list[int]], actual: list[int]) -> int | None:
    """The offset where an existing `jmp rel32` detour left a declared prologue tail intact, or None.

    Another instrumenter (Frida, a mod loader) overwrites whole instructions with a 5-byte jmp and pads the rest;
    the instructions after the overwritten span stay at their original offsets. A pattern tail of at least six
    bytes, wildcards allowed, proves the site is still the verified function. Returns the offset, used only to say
    that the probe must be armed through Interceptor instead of patching over the other instrumenter's jump.
    """
    if not actual or actual[0] != 0xE9:
        return None
    for pattern in patterns:
        for offset in range(5, min(12, len(pattern) - 6) + 1):
            tail = pattern[offset:]
            if len(tail) >= 6 and all(byte < 0 or byte == actual[offset + i] for i, byte in enumerate(tail)):
                return offset
    return None


class TraceMixin:
    def init_trace(self) -> None:
        self.trace: TraceSource | None = None
        self.trace_info: dict = {}
        self._trace_ready = threading.Event()

    # ---- messages from the recorder ---------------------------------------------------------------------------------------
    def trace_route(self, script_id: str, message: dict, data) -> bool:
        """True when the message belongs to the trace recorder (and was handled here, not stored per event)."""
        trace = getattr(self, "trace", None)
        if trace is None or script_id != self.trace_info.get("script_id"):
            return False
        payload = message.get("payload") if message.get("type") == "send" else None
        event = payload.get("event") if isinstance(payload, dict) else None
        if event == "trace_batch" and data is not None:
            try:
                trace.on_batch(data)
            finally:
                # Acknowledge in every case (a batch that did not decode too): the agent holds at most `window` batches
                # in flight, and a missing acknowledgement would stall it, not the writer.
                self._trace_ack(script_id, payload.get("batch_seq"))
            return True
        if event == "trace_counters":
            trace.on_counters(payload)
            return True
        if event == "trace_module":
            trace.on_module(payload)
            return True
        if event == "trace_ready":
            self.trace_info["ready"] = payload
            trace.on_ready(payload)
            self._trace_ready.set()
            return False        # the ready message is also kept in the session's event log
        return False

    def _trace_ack(self, script_id: str, seq) -> None:
        entry = self.scripts.get(script_id)
        if entry is None or not isinstance(seq, int):
            return
        try:
            entry["handle"].post({"type": "ack", "seq": seq})
        except Exception:        # the script is going away; the agent no longer needs the acknowledgement
            pass

    # ---- building the probe plan ----------------------------------------------------------------------------------------------
    def _trace_probe(self, spec: dict, policy: str, site_id: int) -> dict:
        """One verified probe, or TraceRefused. The checks are `observe`'s."""
        name = str(spec.get("name") or spec.get("export") or "")
        if not SITE_ID.match(name):
            raise TraceRefused("a probe needs a name (1..96 characters)")
        reason = check_probe_policy(policy, spec)
        if reason:
            raise TraceRefused("%s: %s" % (name, reason))
        module = self._module({"module": self._loaded_name(spec["module"]), **({"sha256": spec["sha256"]} if spec.get("sha256") else {})})
        export = self._export(module, spec) if spec.get("export") else None
        rva = export["rva"] if export else int(str(spec.get("rva", "")), 0) if spec.get("rva") not in (None, "") else None
        if rva is None or not 0 <= rva < module["size"]:
            raise TraceRefused("%s: no site (an export or a module RVA inside the module)" % name)
        address = hex(int(module["base"], 16) + rva)
        size = int(spec.get("expect_len", 8))
        from hydralysis.runtime_agents import _expect, _expect_pattern
        if spec.get("expects"):
            patterns = [_expect_pattern(str(text)) for text in spec["expects"]]
        elif spec.get("expect"):
            patterns = [_expect(str(spec["expect"]))]
        else:
            patterns = [list(self._w().file_bytes(module["path"], rva, size, int(module["base"], 16)))]
        size = max(len(pattern) for pattern in patterns)
        expected = patterns[0]
        actual = list(self.control.exports_sync.read(address, size))

        def _prologue_matches(pattern):
            return len(pattern) <= len(actual) and all(byte < 0 or byte == actual[i] for i, byte in enumerate(pattern))

        matched = next((pattern for pattern in patterns if _prologue_matches(pattern)), None)
        detour = None
        if matched is None:
            # Another instrumenter may already have detoured the function with a 5-byte jmp. Frida relocates
            # whole instructions and pads the rest, so the untouched tail of the prologue stays at its original
            # offset. Accept that (the image hash already proved the build) and arm through Interceptor, never by
            # patching over the other instrumenter's jump.
            detour = prologue_detour(patterns, actual)
            if detour is not None:
                matched = patterns[0]
        if matched is None:
            patch = self._patcher(int(address, 16))
            raise TraceRefused("%s: PROLOGUE MISMATCH; hook refused: got %s%s" % (
                name, " ".join("%02X" % b for b in actual),
                "; live detour %s by %s" % (patch["jump"], patch["patcher_module"] or "no module") if patch else ""))
        if detour is not None:
            expected = list(actual)       # the recorder re-checks the bytes the detour left in place
        call = self._w()._call_in_span(module["path"], rva)
        if call:
            raise TraceRefused("%s: the bytes the hook overwrites hold a call (%s)" % (name, call))
        buf = spec.get("buf")
        if buf is not None:
            buf = {"ptr_arg": int(buf["ptr_arg"]), "len_arg": buf.get("len_arg"), "fixed": int(buf.get("fixed", 0)),
                   "max": min(256, int(buf.get("max", 64))), "wide": bool(buf.get("wide")), "cstr": bool(buf.get("cstr"))}
            if not 0 <= buf["ptr_arg"] < 8 or (buf["len_arg"] is not None and not 0 <= int(buf["len_arg"]) < 8):
                raise TraceRefused("%s: buffer argument index must be 0..7" % name)
        nargs = int(spec.get("nargs", 0))
        if not 0 <= nargs <= 8:
            raise TraceRefused("%s: nargs must be 0..8" % name)
        stack = int(spec.get("stack", 1))
        if not 1 <= stack <= MAX_STACK:
            raise TraceRefused("%s: stack depth is 1..%d" % (name, MAX_STACK))
        fields = [{"name": str(f["name"]), "type": str(f["type"]), "source": str(f["source"])} for f in spec.get("fields") or []]
        kind = str(spec.get("kind") or "call")
        if spec.get("event") and kind not in ("open", "ioctl", "devquery", "close"):
            kind = "event"
        return {"id": site_id, "name": name, "kind": kind, "module": module["path"],
                "module_name": module["name"], "base": module["base"], "rva": rva, "expect": expected,
                "expects": [expected] if detour is not None else patterns,
                "nargs": nargs,
                "with_leave": bool(spec.get("with_leave")) or any(f["source"] == "ret" for f in fields), "buf": buf,
                "va": int(address, 16), "module_sha256": module["file_sha256"], "payload": bool(spec.get("payload")),
                "stack": stack, "event": spec.get("event"), "hook": spec.get("hook"), "fields": fields, "const": dict(spec.get("const") or {}),
                "detour": detour, "force_interceptor": detour is not None,
                "buf_arg": buf["ptr_arg"] if buf else None}

    def _loaded_name(self, name: str) -> str:
        """The module's name as the process spells it (Windows names compare without case; the control script does not)."""
        listed = self.control.exports_sync.modules(200)
        for item in listed["modules"]:
            if item["name"].lower() == str(name).lower() or item["path"].lower() == str(name).lower():
                return item["path"]
        return name

    @staticmethod
    def _shared_scope(args: dict) -> dict:
        """An explicitly shared correlation scope (spec 14.6): sessions captured under the same `scope` name and 32-byte
        `scope_key` (hex) give the same keyed ids to the same value, so two runs can be compared. Without it every
        session has its own key and its ids cannot be linked to any other session's."""
        key = args.get("scope_key")
        if key in (None, ""):
            return {}
        try:
            raw = bytes.fromhex(str(key))
        except ValueError:
            raw = b""
        if len(raw) != 32 or not str(args.get("scope") or ""):
            raise ValueError("a shared scope is scope (a name) with scope_key (64 hex digits)")
        return {"key": raw, "scope": str(args["scope"])}

    def trace_plan(self, args: dict) -> tuple:
        """(probes, refusals) for a start request. A refused required probe raises; an optional one is a coverage limitation."""
        policy = str(args.get("fault_policy") or "fatal")
        if policy not in FAULT_POLICIES:
            raise ValueError("fault_policy is one of %s" % ", ".join(FAULT_POLICIES))
        specs = [dict(item) for item in (args.get("probes") or [])]
        for extra in args.get("builtin") or []:
            if extra not in BUILTIN_SETS:
                raise ValueError("builtin probe set must be one of %s" % ", ".join(sorted(BUILTIN_SETS)))
            specs += [dict(item) for item in BUILTIN_SETS[extra] if all(item["name"] != have.get("name") for have in specs)]
        if not 1 <= len(specs) <= MAX_PROBES:
            raise ValueError("trace_start needs 1..%d probes (probes=[...] or builtin=['driver-boundary'])" % MAX_PROBES)
        preview = args.get("authorize_preview")
        preview_sites: set = set()
        if preview is not None:
            if (not isinstance(preview, dict) or not str(preview.get("scope") or "") or not isinstance(preview.get("sites"), list)
                    or not isinstance(preview.get("max_bytes", 128), int) or isinstance(preview.get("max_bytes"), bool)
                    or not 1 <= preview.get("max_bytes", 128) <= 256):
                raise ValueError("authorize_preview is {scope, sites: [probe names], max_bytes: 1..256}")
            preview_sites = {str(x) for x in preview["sites"]}
        auth = args.get("authorize_payload")
        payload_sites = set()
        if auth is not None:
            if not isinstance(auth, dict) or not str(auth.get("scope") or "") or not isinstance(auth.get("sites"), list):
                raise ValueError("authorize_payload is {scope, sites: [probe names], max_bytes}")
            payload_sites = {str(x) for x in auth["sites"]}
        probes, refusals = [], []
        for spec in specs:
            if spec.get("payload_buf") and spec["name"] in payload_sites:
                spec = {**spec, "buf": spec["payload_buf"], "payload": True}
            elif spec.get("payload") and spec.get("name") not in payload_sites:
                refusals.append({"probe": spec.get("name"), "reason": "payload mode needs a separate authorization naming this probe",
                                 "limitation": "payload-not-authorized", "required": False})
                spec = {**spec, "payload": False, "buf": None}
            try:
                probes.append(self._trace_probe(spec, policy, len(probes) + 1))
            except Exception as exc:  # a missing module is a frida RPC error: the probe is refused, the plan goes on
                if spec.get("required"):
                    raise TraceRefused("required probe refused: %s" % exc) from exc
                refusals.append({"probe": spec.get("name"), "reason": str(exc)[:300], "limitation": "optional-hook-refused",
                                 "required": False})
        if not probes:
            raise TraceRefused("every probe was refused: %s" % "; ".join(r["reason"] for r in refusals))
        for probe in probes:
            probe["preview"] = int(preview.get("max_bytes", 128)) if probe["name"] in preview_sites and probe["buf"] else 0
        for name in sorted(preview_sites - {p["name"] for p in probes if p["buf"]}):
            refusals.append({"probe": name, "reason": "a preview needs a probe that records a buffer", "limitation": "preview-not-possible",
                             "required": False})
        return probes, refusals, policy, (int(auth.get("max_bytes", 256)) if auth else 0), auth

    # ---- actions ------------------------------------------------------------------------------------------------------------
    def trace_action(self, action: str, args: dict) -> dict:
        if action == "trace_status":
            return self.trace_snapshot() or {"active": False}
        if action == "trace_stop":
            return self.trace_stop(args)
        return self.trace_start(args)

    def trace_snapshot(self) -> dict | None:
        trace = getattr(self, "trace", None)
        if trace is None:
            return None
        return {"active": not trace.finalized, "script_id": self.trace_info.get("script_id"), "fault_policy": trace.fault_policy,
                "refusals": self.trace_info.get("refusals", []), "scope": {"name": trace.scope, "key_id": trace.key_id},
                "health": trace.health(), "detach_failed": bool(self.trace_info.get("detach_failed"))}

    def trace_start(self, args: dict) -> dict:
        if getattr(self, "trace", None) is not None and not self.trace.finalized:
            raise ValueError("a trace capture is already active in this session; trace_stop it first")
        if self.control is None:
            raise RuntimeError("target session is not attached")
        ring_bytes = int(args.get("ring_bytes", DEFAULT_RING_BYTES))
        if not RING_BYTES[0] <= ring_bytes <= RING_BYTES[1] or ring_bytes & (ring_bytes - 1):
            raise ValueError("ring_bytes is a power of two between 64 KiB and 16 MiB")
        rings = int(args.get("rings", DEFAULT_RINGS))
        if not 1 <= rings <= 128:
            raise ValueError("rings is 1..128 (one per thread that hits a probe)")
        probes, refusals, policy, max_payload, auth = self.trace_plan(args)
        script_id = uuid.uuid4().hex
        gen = int(args.get("producer_gen", 1))
        sites = {p["id"]: {"name": p["name"], "kind": p["kind"], "module": p["module_name"], "va": p["va"],
                           "buf": ("payload" if p["payload"] else ("id" if p["buf"] else None)), "preview": p["preview"],
                           **({"buf_arg": p["buf_arg"]} if p["buf_arg"] is not None else {}),
                           **({"event": p["event"], "hook": p["hook"] or p["name"], "fields": p["fields"], "const": p.get("const") or {}} if p["kind"] == "event" else {})}
                 for p in probes}
        self.trace = TraceSource(self.directory, session=self.directory.name, producer_gen=gen, process_id=self.pid, sites=sites,
                                 qpc_freq=qpc_frequency(), fault_policy=policy, payload_authorized=bool(auth),
                                 max_payload=max(1, max_payload or 256), **self._shared_scope(args))
        self.trace_info = {"script_id": script_id, "refusals": refusals, "probes": [{k: p[k] for k in ("id", "name", "kind", "module_name", "rva", "module_sha256")} for p in probes]}
        self._trace_ready.clear()
        parameters = {"probes": [{k: p[k] for k in ("id", "name", "kind", "module", "base", "rva", "expect", "expects", "nargs", "with_leave", "buf", "stack", "force_interceptor")} for p in probes],
                      "rings": rings, "ring_bytes": ring_bytes, "batch_ms": int(args.get("batch_ms", BATCH_MS)),
                      "counter_ms": int(args.get("counter_ms", 250)), "batch_bytes": int(args.get("batch_bytes", 1 << 20)),
                      "bp_us": int(float(args.get("bp_ms", BACKPRESSURE_MS)) * 1000), "window": int(args.get("window", ACK_WINDOW)),
                      "producer_gen": gen, "fault_policy": policy, "sampling": normalize_sampling(args.get("sampling")),
                      "hooking": _hooking(args.get("hooking"))}
        try:
            self._load(script_id, trace_agent_source(parameters), {"kind": "trace", "probes": self.trace_info["probes"]})
            if not self._trace_ready.wait(10):
                raise RuntimeError("the trace recorder did not report ready")
        except Exception:
            self.trace.finalize(reason="start failed")
            self.trace = None
            raise
        for item in refusals:
            self.trace.refuse("probe:" + str(item["probe"]), item["reason"], item["limitation"])
        detoured = [p["name"] for p in probes if p.get("detour") is not None]
        if detoured:
            self.trace.refuse("prologue-detour", "another instrumenter detoured %s; those probes are armed through Interceptor, "
                               "not by patching over its jump" % ", ".join(detoured), "detour:prologue")
        try:
            self._record_lifetimes()
        except Exception as exc:     # the facts are a convenience for the ingester; the capture itself does not depend on them
            self.trace.refuse("lifetimes", str(exc), "lifetimes-unavailable")
        self.trace_info["etw"] = None
        if args.get("etw"):
            self._start_etw(args["etw"])
        self.trace_info["watchdog"] = None
        if args.get("watchdog"):
            self._start_watchdog(args["watchdog"], probes)
        self.publish()
        ready = self.trace_info.get("ready") or {}
        return {"started": True, "script_id": script_id, "probes": ready.get("installed"), "refusals": refusals,
                "fault_context": ready.get("context"), "fault_policy": policy, "segment": str(self.trace.path),
                "segment_id": self.trace.segment_id,
                "scope": {"name": self.trace.scope, "key_id": self.trace.key_id}, "producer_gen": gen,
                "overhead_note": "install pauses per probe are in `probes[].install_ms`"}

    def _start_etw(self, spec) -> None:
        """Start the ETW consumer beside the recorder. Its refusal (not elevated), a missing tool or a failed start is recorded in the
        segment as a refused source and in the health claims as missing coverage; it never stops the recorder."""
        from hydralysis import trace_etw
        providers = spec.get("providers") if isinstance(spec, dict) else None
        consumer = trace_etw.EtwConsumer(self.trace.directory, self.trace.session, [self.pid], self.trace.directory / "scope.key",
                                         providers=providers)
        started = consumer.start()
        self.trace_info["etw"] = consumer
        self.trace_info["etw_start"] = started
        if started.get("state") not in ("running", "starting"):
            self.trace.refuse("etw", str(started.get("stderr") or started.get("limitation") or started.get("state")),
                              started.get("limitation") or "etw-" + str(started.get("state")))

    def _etw_summary(self) -> dict | None:
        consumer = self.trace_info.get("etw")
        if consumer is None:
            return None
        stopped = consumer.stop()
        return {"start": self.trace_info.get("etw_start"), "stop": stopped, "coverage": consumer.coverage(),
                "segment_id": consumer.segment_id}

    def _record_lifetimes(self, late: bool = False) -> None:
        listed = self.control.exports_sync.modules(200)
        process = {"image": self.target_exe, "image_sha256": self.target_sha256}
        self.trace.record_lifetimes(process, listed["modules"], late=late)

    def _start_watchdog(self, spec: dict, probes: list) -> None:
        """The frame-stall watchdog of the declared main loop: it reads the hit count of the frame probe and, when that stops
        advancing for `stall_s`, captures every thread stack from this (the worker) process by the unwind tables."""
        from hydralysis import trace_watchdog as wd
        hook = str(spec.get("hook") or "")
        if hook not in {p["name"] for p in probes}:
            raise ValueError("watchdog hook %r is not one of the armed probes" % hook)
        trace = self.trace
        stall_dir = self.directory / "trace"

        def on_stall(result: dict) -> None:
            result["hook"] = hook
            result["file"] = str(wd.write_stall(stall_dir, result))

        dog = wd.FrameStallWatchdog(self.pid, lambda: trace.hits(hook), float(spec.get("stall_s", 2.0)), on_stall,
                                    after_s=float(spec.get("after_s", 0.0)))
        self.trace_info["watchdog"] = dog.start()

    def _watchdog_summary(self) -> dict | None:
        dog = self.trace_info.get("watchdog")
        if dog is None:
            return None
        dog.stop()
        return {"captures": dog.captures, "errors": list(dog.errors), "stall_s": dog.stall_s,
                "last": None if dog.last is None else {k: dog.last[k] for k in ("stalled_for_s", "progress", "file", "hook")}}

    def trace_stop(self, args: dict) -> dict:
        trace = getattr(self, "trace", None)
        if trace is None:
            raise ValueError("no trace capture in this session")
        if trace.finalized and not self.trace_info.get("detach_failed"):
            return {"stopped": True, "already": True, "health": trace.health()}
        script_id = self.trace_info["script_id"]
        watchdog = self._watchdog_summary()
        etw = self._etw_summary()
        if not self.detached and not trace.finalized:
            try:
                self._record_lifetimes(late=True)
            except Exception as exc:
                # The target may have exited before this convenience query (the script is gone). That is a
                # coverage limitation, not a probe fault, so `fault_free` stays about the probes.
                trace.refuse("lifetimes-at-stop", str(exc), "lifetimes-unavailable")
        entry = self.scripts.get(script_id)
        detach = {"quiescent": True, "note": "the recorder was already gone"}
        if entry is not None:
            try:
                detach = entry["handle"].exports_sync.release(int(args.get("timeout_ms", 3000)))
            except Exception as exc:
                if self.detached:       # the target is gone: nothing runs the recorder any more, and nothing can be left patched
                    detach = {"quiescent": True, "note": "the target exited; the recorder ended with it", "error": str(exc)}
                else:
                    detach = {"quiescent": False, "note": "release failed: %s" % exc, "error": str(exc)}
        # The recorder's last messages follow its reply: wait until every batch it says it sent has arrived.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and detach.get("quiescent"):
            sent = trace.transport.get("agent_batches_sent")
            if trace.producer.get("final") and sent is not None and trace.transport["batches"] >= sent:
                break
            time.sleep(0.02)
        health = trace.finalize(detach=detach, reason=str(args.get("reason") or "stopped"))   # idempotent on a retry
        health["verify"] = trace.verify()
        if detach.get("quiescent"):
            if entry is not None:
                self._unload(script_id)
            self.trace_info["detach_failed"] = False
        else:
            self.trace_info["detach_failed"] = True
            self.state = "trace_detach_failed"
        self.publish()
        return {"stopped": bool(detach.get("quiescent")), "detach": detach, "health": health, "watchdog": watchdog, "etw": etw,
                "safe_state": None if detach.get("quiescent") else "recorder retained in pass-through; the session stays attached"}

    def trace_cleanup(self) -> list:
        """Called by `cleanup`: stop an active capture. Returns the problems; a recorder that is not quiescent must not be freed."""
        trace = getattr(self, "trace", None)
        if trace is None or (trace.finalized and not self.trace_info.get("detach_failed")):
            return []
        try:
            result = self.trace_stop({"reason": "session cleanup"})
        except Exception as exc:
            return ["trace stop: %s" % exc]
        if not result.get("stopped"):
            return ["trace recorder not quiescent (%s); kept in pass-through and the session kept attached" % result["detach"].get("note")]
        return []
