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

from hydralysis.runtime_agents import trace_agent_source
from hydralysis.trace_capture import FAULT_POLICIES, TraceRefused, TraceSource, check_probe_policy

RING_BYTES = (1 << 16, 1 << 24)
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


def qpc_frequency() -> int:
    if os.name != "nt":
        raise TraceRefused("the trace clock is QueryPerformanceCounter; this host is not Windows")
    value = ctypes.c_longlong()
    ctypes.WinDLL("kernel32").QueryPerformanceFrequency(ctypes.byref(value))
    return int(value.value)


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
            trace.on_batch(data)
            return True
        if event == "trace_counters":
            trace.on_counters(payload)
            return True
        if event == "trace_ready":
            self.trace_info["ready"] = payload
            trace.on_ready(payload)
            self._trace_ready.set()
            return False        # the ready message is also kept in the session's event log
        return False

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
        if spec.get("expect"):
            from hydralysis.runtime_agents import _expect
            expected = _expect(str(spec["expect"]))
        else:
            expected = list(self._w().file_bytes(module["path"], rva, size, int(module["base"], 16)))
        actual = list(self.control.exports_sync.read(address, len(expected)))
        if actual != expected:
            patch = self._patcher(int(address, 16))
            raise TraceRefused("%s: PROLOGUE MISMATCH; hook refused: got %s%s" % (
                name, " ".join("%02X" % b for b in actual),
                "; live detour %s by %s" % (patch["jump"], patch["patcher_module"] or "no module") if patch else ""))
        call = self._w()._call_in_span(module["path"], rva)
        if call:
            raise TraceRefused("%s: the bytes the hook overwrites hold a call (%s)" % (name, call))
        buf = spec.get("buf")
        if buf is not None:
            buf = {"ptr_arg": int(buf["ptr_arg"]), "len_arg": buf.get("len_arg"), "fixed": int(buf.get("fixed", 0)),
                   "max": min(256, int(buf.get("max", 64))), "wide": bool(buf.get("wide"))}
            if not 0 <= buf["ptr_arg"] < 8 or (buf["len_arg"] is not None and not 0 <= int(buf["len_arg"]) < 8):
                raise TraceRefused("%s: buffer argument index must be 0..7" % name)
        nargs = int(spec.get("nargs", 0))
        if not 0 <= nargs <= 8:
            raise TraceRefused("%s: nargs must be 0..8" % name)
        return {"id": site_id, "name": name, "kind": str(spec.get("kind") or "call"), "module": module["path"],
                "module_name": module["name"], "base": module["base"], "rva": rva, "expect": expected, "nargs": nargs,
                "with_leave": bool(spec.get("with_leave")), "buf": buf, "va": int(address, 16),
                "module_sha256": module["file_sha256"], "payload": bool(spec.get("payload"))}

    def _loaded_name(self, name: str) -> str:
        """The module's name as the process spells it (Windows names compare without case; the control script does not)."""
        listed = self.control.exports_sync.modules(200)
        for item in listed["modules"]:
            if item["name"].lower() == str(name).lower() or item["path"].lower() == str(name).lower():
                return item["path"]
        return name

    def trace_plan(self, args: dict) -> tuple:
        """(probes, refusals) for a start request. A refused required probe raises; an optional one is a coverage limitation."""
        policy = str(args.get("fault_policy") or "fatal")
        if policy not in FAULT_POLICIES:
            raise ValueError("fault_policy is one of %s" % ", ".join(FAULT_POLICIES))
        specs = [dict(item) for item in (args.get("probes") or [])]
        for extra in args.get("builtin") or []:
            if extra != "driver-boundary":
                raise ValueError("builtin probe set must be driver-boundary")
            specs += [dict(item) for item in DRIVER_BOUNDARY]
        if not 1 <= len(specs) <= MAX_PROBES:
            raise ValueError("trace_start needs 1..%d probes (probes=[...] or builtin=['driver-boundary'])" % MAX_PROBES)
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
        ring_bytes = int(args.get("ring_bytes", 1 << 18))
        if not RING_BYTES[0] <= ring_bytes <= RING_BYTES[1] or ring_bytes & (ring_bytes - 1):
            raise ValueError("ring_bytes is a power of two between 64 KiB and 16 MiB")
        rings = int(args.get("rings", 32))
        if not 1 <= rings <= 128:
            raise ValueError("rings is 1..128 (one per thread that hits a probe)")
        probes, refusals, policy, max_payload, auth = self.trace_plan(args)
        script_id = uuid.uuid4().hex
        gen = int(args.get("producer_gen", 1))
        sites = {p["id"]: {"name": p["name"], "kind": p["kind"], "module": p["module_name"], "va": p["va"],
                           "buf": ("payload" if p["payload"] else ("id" if p["buf"] else None))} for p in probes}
        self.trace = TraceSource(self.directory, session=self.directory.name, producer_gen=gen, process_id=self.pid, sites=sites,
                                 qpc_freq=qpc_frequency(), fault_policy=policy, payload_authorized=bool(auth),
                                 max_payload=max(1, max_payload or 256))
        self.trace_info = {"script_id": script_id, "refusals": refusals, "probes": [{k: p[k] for k in ("id", "name", "kind", "module_name", "rva", "module_sha256")} for p in probes]}
        self._trace_ready.clear()
        parameters = {"probes": [{k: p[k] for k in ("id", "name", "kind", "module", "base", "rva", "expect", "nargs", "with_leave", "buf")} for p in probes],
                      "rings": rings, "ring_bytes": ring_bytes, "batch_ms": int(args.get("batch_ms", 10)),
                      "counter_ms": int(args.get("counter_ms", 250)), "batch_bytes": int(args.get("batch_bytes", 1 << 20)),
                      "producer_gen": gen, "fault_policy": policy}
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
        self.publish()
        ready = self.trace_info.get("ready") or {}
        return {"started": True, "script_id": script_id, "probes": ready.get("installed"), "refusals": refusals,
                "fault_context": ready.get("context"), "fault_policy": policy, "segment": str(self.trace.path),
                "scope": {"name": self.trace.scope, "key_id": self.trace.key_id}, "producer_gen": gen,
                "overhead_note": "install pauses per probe are in `probes[].install_ms`"}

    def trace_stop(self, args: dict) -> dict:
        trace = getattr(self, "trace", None)
        if trace is None:
            raise ValueError("no trace capture in this session")
        if trace.finalized and not self.trace_info.get("detach_failed"):
            return {"stopped": True, "already": True, "health": trace.health()}
        script_id = self.trace_info["script_id"]
        entry = self.scripts.get(script_id)
        detach = {"quiescent": True, "note": "the recorder was already gone"}
        if entry is not None:
            try:
                detach = entry["handle"].exports_sync.release(int(args.get("timeout_ms", 3000)))
            except Exception as exc:
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
        return {"stopped": bool(detach.get("quiescent")), "detach": detach, "health": health,
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
