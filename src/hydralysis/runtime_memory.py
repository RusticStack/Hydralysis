"""Runtime memory write and hardware watchpoints (Z12): FIXTURE-ONLY, gated, owner-driven.

A mixin of `runtime_worker.RuntimeAgent`. Nothing here runs against a game: every `write` and `watch` request needs

  * the gate the client adds (`options` cannot carry it): the target's SHA-256 is in the setting
    `runtime_fixture_sha256`, and
  * the fixture marker (`FIXTURE_MARKER`) inside the target's own file, which only the verification fixtures hold.

`write` is a compare-and-swap with a required reason, refused in any executable range, with an undo log that reports
DIVERGED instead of overwriting what changed since. `watch` is a state machine
(arming -> armed -> disarming -> clear | tainted) whose only way to `clear` is a debug-register readback of every
thread. A failed disarm taints the session: the worker then refuses to detach (a target left with an armed debug
register and no handler dies with 0x80000004) unless the owner forces it. A watch also needs the per-architecture
conformance stamp that `tools/watch_conformance.py` writes after its real-process matrix passes.
"""

from __future__ import annotations

import re
import time
import uuid
from pathlib import Path

FIXTURE_MARKER = b"HYDRALYSIS_FIXTURE_ONLY"
MEMORY_ACTIONS = ("write", "watch")
SLOTS = 4
MAX_WRITE = 64
MIN_REASON = 8
STAMP_ITERATIONS = 100
DISARM_ATTEMPTS = 5
DISARM_PAUSE_S = 0.02
# debug registers: the watch kinds and the sizes the hardware takes
KINDS = {"write": "w", "readwrite": "rw"}
SIZES = (1, 2, 4, 8)
# watch state machine: state -> states it may move to
EDGES = {"arming": {"armed", "disarming"}, "armed": {"disarming"},
         "disarming": {"clear", "tainted"}, "tainted": {"disarming"}, "clear": set()}

MEMORY_AGENT = r"""
// The fixed memory script: compare-and-swap writes and hardware watchpoints. No caller code runs here.
const IA32 = Process.arch === 'ia32', X64 = Process.arch === 'x64';
const watches = {}, covered = {};
let handlerOn = false;
function range(p, n) { const r = Process.findRangeByAddress(p);
  if (!r || p.add(n).compare(r.base.add(r.size)) > 0) throw new Error('range does not hold the whole span'); return r; }
function bytesOf(p, n) { const b = p.readVolatile(n); if (b === null || b.byteLength !== n) throw new Error('read was incomplete');
  return Array.from(new Uint8Array(b)); }
function ownThread(id) { return id === Process.getCurrentThreadId(); }
function alive(id) { return Process.enumerateThreads().some(t => t.id === id); }
function threads() { return Process.enumerateThreads().filter(t => !ownThread(t.id)); }
function handler(d) {
  if (d.type !== 'single-step') return false;
  // A trap raised just before a disarm is delivered after it (the handler waits for the script lock the disarm holds):
  // it must still be absorbed, or the thread dies with 0x80000004. So once any watch existed, every single-step is ours.
  if (Object.keys(watches).length === 0) return false;
  const live = Object.keys(watches).filter(k => watches[k].armed);
  for (const k of live) { const w = watches[k]; w.seen++;
    if (w.seen <= w.limit) send({event: 'watch_hit', watch: k, thread: Process.getCurrentThreadId(), pc: d.address.toString(),
      ctx: {pc: d.context.pc.toString(), sp: d.context.sp.toString()}}); }
  return true;
}
function ensureHandler() { if (!handlerOn) { Process.setExceptionHandler(handler); handlerOn = true; } }
// Debug registers by GetThreadContext on a suspended thread (the readback that proves a slot clear).
const K = Process.getModuleByName('kernel32.dll');
const OpenThread = new NativeFunction(K.getExportByName('OpenThread'), 'pointer', ['uint32', 'int', 'uint32']);
const SuspendThread = new NativeFunction(K.getExportByName('SuspendThread'), 'uint32', ['pointer']);
const ResumeThread = new NativeFunction(K.getExportByName('ResumeThread'), 'uint32', ['pointer']);
const GetThreadContext = new NativeFunction(K.getExportByName('GetThreadContext'), 'int', ['pointer', 'pointer']);
const CloseHandle = new NativeFunction(K.getExportByName('CloseHandle'), 'int', ['pointer']);
const CTX = IA32 ? {size: 0x2CC, flags: 0x10010, dr7: 0x18} : {size: 0x4D0, flags: 0x100010, dr7: 0x70};
function dr7(tid) {
  const h = OpenThread(0x1A, 0, tid); if (h.isNull()) return null;
  try { const raw = Memory.alloc(CTX.size + 16), ctx = raw.add((16 - (raw.and(15).toInt32())) & 15);
    ctx.add(IA32 ? 0 : 0x30).writeU32(CTX.flags);
    if (SuspendThread(h) === 0xFFFFFFFF) return null;
    let ok; try { ok = GetThreadContext(h, ctx); } finally { ResumeThread(h); }
    return ok ? (IA32 ? ctx.add(CTX.dr7).readU32() : ctx.add(CTX.dr7).readU64().toNumber()) : null;
  } finally { CloseHandle(h); }
}
function slotsOf(v) { const out = []; for (let s = 0; s < 4; s++) if ((v >> (2 * s)) & 3) out.push(s); return out; }
rpc.exports = {
  writeCas(address, expect, value) {
    const p = ptr(address), n = expect.length; if (n !== value.length) throw new Error('size mismatch');
    const r = range(p, n);
    if (r.protection.indexOf('x') >= 0) throw new Error('EXECUTABLE RANGE; write refused');
    if (r.protection.indexOf('w') < 0) throw new Error('range is not writable; write refused');
    const actual = bytesOf(p, n);
    if (actual.some((b, i) => b !== expect[i])) return {ok: false, actual};
    p.writeByteArray(value);
    const after = bytesOf(p, n);
    return {ok: true, actual, after};
  },
  arm(id, slot, address, size, cond) {
    const p = ptr(address), r = range(p, size);
    if (r.protection.indexOf('x') >= 0) throw new Error('EXECUTABLE RANGE; watch refused');
    ensureHandler(); watches[id] = {slot, armed: true, seen: 0, limit: 20, address, size, cond}; covered[id] = [];
    const failed = [];
    for (const t of threads()) { try { t.setHardwareWatchpoint(slot, p, size, cond); covered[id].push(t.id); }
      catch (e) { if (alive(t.id)) failed.push({id: t.id, error: String(e)}); } }
    return {armed: covered[id], failed};
  },
  limit(id, n) { if (watches[id]) watches[id].limit = n; return true; },
  rearm(id) { const w = watches[id]; if (!w || !w.armed) return {armed: [], failed: []};
    const failed = [], added = [];
    for (const t of threads()) { if (covered[id].indexOf(t.id) >= 0) continue;
      try { t.setHardwareWatchpoint(w.slot, ptr(w.address), w.size, w.cond); covered[id].push(t.id); added.push(t.id); }
      catch (e) { if (alive(t.id)) failed.push({id: t.id, error: String(e)}); } }
    return {armed: added, failed};
  },
  disarm(id) {
    const w = watches[id]; if (!w) return {unset: [], failed: []};
    const failed = [], unset = [], gone = [];
    for (const t of threads()) { try { t.unsetHardwareWatchpoint(w.slot); unset.push(t.id); }
      catch (e) { if (alive(t.id)) failed.push({id: t.id, error: String(e)}); else gone.push(t.id); } }
    w.armed = failed.length > 0 ? w.armed : false; return {unset, failed, gone, seen: w.seen};
  },
  readback() {
    const rows = [], unreadable = [];
    for (const t of threads()) { const v = dr7(t.id);
      if (v === null) { if (alive(t.id)) unreadable.push(t.id); } else rows.push({id: t.id, dr7: v, enabled_slots: slotsOf(v)}); }
    return {threads: rows, unreadable};
  },
  counters(id) { const w = watches[id]; return w ? {seen: w.seen, limit: w.limit} : null; }
};
send({event: 'memory_agent_ready', arch: Process.arch});
"""


def parse_hex(text, what: str, low: int = 1, high: int = MAX_WRITE) -> list[int]:
    words = str(text or "").split()
    if not low <= len(words) <= high or any(not re.fullmatch("[0-9A-Fa-f]{2}", w) for w in words):
        raise ValueError("%s must be %d..%d hex bytes such as '02 00 00 00'" % (what, low, high))
    return [int(w, 16) for w in words]


def hexed(values) -> str:
    return " ".join("%02X" % int(v) for v in values)


def fixture_marked(path: str) -> bool:
    """The target's own file carries the fixture marker (only the verification fixtures do)."""
    try:
        with open(path, "rb") as handle:
            return FIXTURE_MARKER in handle.read()
    except OSError:
        return False


def slot_clear(readback: dict, slot: int) -> tuple[bool, dict]:
    """True only when every thread was read and none has `slot` enabled; the second value is the evidence."""
    if not isinstance(readback, dict) or "threads" not in readback:
        return False, {"reason": "no debug-register readback"}
    still = [t["id"] for t in readback["threads"] if slot in t.get("enabled_slots", [])]
    unreadable = list(readback.get("unreadable") or [])
    evidence = {"threads_read": len(readback["threads"]), "still_enabled": still, "unreadable": unreadable}
    return (not still and not unreadable), evidence


class MemoryMixin:
    # ---- state

    def init_memory(self) -> None:
        self.memory_script = None
        self.memory_ready = None
        self.writes: list[dict] = []
        self.watches: dict[str, dict] = {}
        self.tainted = ""
        self._force_detach = False
        self._memory_lock_busy = False

    def memory_state(self) -> dict:
        out = {}
        if self.writes:
            out["writes"] = len(self.writes)
        if self.watches:
            out["watches"] = {k: {"state": w["state"], "slot": w["slot"], "hits": w["hits"]} for k, w in self.watches.items()}
        if self.tainted:
            out["tainted"] = self.tainted
        return out

    def _persist_memory(self) -> None:
        self._w()._write(self.directory / "memory.json", {"writes": self.writes, "watches": self.watches,
                                                           "tainted": self.tainted})

    def _memory_marker(self, kind: str, body: dict) -> None:
        self.log.marker(kind, body)

    # ---- gate

    def _gate(self, action: str, args: dict) -> dict:
        gate = args.pop("_gate", None)
        if not isinstance(gate, dict) or str(gate.get("fixture_sha256") or "") != self.target_sha256:
            raise PermissionError("%s is fixture-only: the target's SHA-256 must be listed in the setting "
                                  "runtime_fixture_sha256; it is not (no game process, no unlisted build)" % action)
        if not fixture_marked(self.target_exe):
            raise PermissionError("%s is fixture-only: the target file does not carry the fixture marker; refused" % action)
        return gate

    def _stamp(self, gate: dict) -> dict:
        if gate.get("conformance"):  # the run that produces the stamp (tools/watch_conformance.py sets it in its own settings)
            return {}
        arch = self.control.exports_sync.info(self.target_exe)["arch"]
        stamp = (gate.get("stamps") or {}).get(arch)
        version = str(gate.get("frida") or "")
        if (not isinstance(stamp, dict) or stamp.get("result") != "pass" or stamp.get("arch") != arch
                or stamp.get("fixture_sha256") != self.target_sha256 or stamp.get("frida") != version
                or int(stamp.get("iterations", 0)) < STAMP_ITERATIONS):
            raise PermissionError("watch needs a passing conformance stamp for %s (frida %s) on this fixture build: run "
                                  "tools/watch_conformance.py; none matches" % (arch, version))
        return stamp

    # ---- the script

    def _memory(self):
        if self.memory_script is None:
            script = self.session.create_script(MEMORY_AGENT)
            script.on("message", lambda message, data: self._memory_message(message, data))
            script.load()
            self.memory_script = script
        return self.memory_script

    def _memory_message(self, message: dict, data=None) -> None:
        payload = message.get("payload") if isinstance(message, dict) else None
        if isinstance(payload, dict) and payload.get("event") == "watch_hit":
            watch = self.watches.get(payload.get("watch"))
            if watch is not None:
                watch["hits"] += 1
        self.message("memory", message, data)

    # ---- address

    def _target_span(self, args: dict, size: int) -> tuple[int, dict | None, dict]:
        if args.get("address"):
            if args.get("module") or "rva" in args:
                raise ValueError("give address or module+rva, not both")
            value = int(str(args["address"]).removeprefix("va:"), 0)
        else:
            _, _, address = self._site(args)
            value = int(address, 16)
        limit = 1 << (int(self.control.exports_sync.info(self.target_exe)["pointer_size"]) * 8)
        if not 0 < value < limit or value + size > limit:
            raise ValueError("address overflows the target pointer width")
        located = self.control.exports_sync.locate(hex(value))
        rng = located.get("range")
        if not rng:
            raise ValueError("address is not mapped in the target")
        base, length = int(rng["base"], 16), int(rng["size"])
        if value < base or value + size > base + length:
            raise ValueError("the span crosses the end of its memory range; refused")
        return value, located.get("module"), rng

    # ---- dispatch

    def handle(self, action: str, args: dict) -> dict:
        if action in MEMORY_ACTIONS and self.detached:
            raise RuntimeError("target session is detached")
        if action == "write":
            return self.memory_write(args)
        if action == "watch":
            return self.memory_watch(args)
        if action == "detach":
            self._force_detach = bool(args.get("force_tainted"))
        return super().handle(action, args)

    # ---- write

    def memory_write(self, args: dict) -> dict:
        self._gate("write", args)
        op = str(args.get("op") or "write")
        if op == "log":
            return {"writes": self.writes, "count": len(self.writes)}
        if op == "undo":
            return self._undo(args)
        if op != "write":
            raise ValueError("write op is write, undo or log")
        reason = str(args.get("reason") or "").strip()
        if len(reason) < MIN_REASON or len(reason) > 300:
            raise ValueError("write requires options.reason: %d..300 characters saying why this memory is changed" % MIN_REASON)
        expect, value = parse_hex(args.get("expect"), "expect"), parse_hex(args.get("bytes"), "bytes")
        if len(expect) != len(value):
            raise ValueError("expect and bytes must have the same length")
        address, module, rng = self._target_span(args, len(value))
        protection = str(rng.get("protection") or "")
        if "x" in protection:
            raise ValueError("EXECUTABLE RANGE (%s); write refused: this tool changes data on fixtures, not code" % protection)
        if "w" not in protection:
            raise ValueError("range %s is not writable; write refused" % protection)
        result = self._memory().exports_sync.writeCas(hex(address), expect, value)
        if not result.get("ok"):
            raise ValueError("CAS MISMATCH; nothing written: expected %s, found %s"
                             % (hexed(expect), hexed(result.get("actual") or [])))
        entry = {"id": uuid.uuid4().hex[:12], "address": hex(address), "size": len(value), "before": hexed(expect),
                 "after": hexed(value), "reason": reason, "at_ms": int(time.time() * 1000), "status": "applied",
                 "module": (module or {}).get("name")}
        self.writes.append(entry)
        self._persist_memory()
        self._memory_marker("memory_write", {"entry": entry})
        self.publish()
        return {"written": True, "entry": entry, "atomicity": "compare and write in one agent call; the target's own "
                "threads are not stopped, so a racing writer can still win after the write"}

    def _undo(self, args: dict) -> dict:
        wanted = str(args.get("id") or "")
        applied = [e for e in self.writes if e["status"] == "applied"]
        entry = next((e for e in reversed(applied) if not wanted or e["id"] == wanted), None)
        if entry is None:
            raise ValueError("no applied write to undo" + (" with id " + wanted if wanted else ""))
        address, _, rng = self._target_span({"address": entry["address"]}, entry["size"])
        if "x" in str(rng.get("protection") or "") or "w" not in str(rng.get("protection") or ""):
            raise ValueError("the range is no longer a writable data range; undo refused")
        result = self._memory().exports_sync.writeCas(hex(address), parse_hex(entry["after"], "after"),
                                                      parse_hex(entry["before"], "before"))
        if not result.get("ok"):
            entry["status"] = "diverged"
            entry["found"] = hexed(result.get("actual") or [])
            self._persist_memory()
            self._memory_marker("memory_undo", {"entry": entry["id"], "status": "diverged"})
            return {"undone": False, "status": "DIVERGED", "entry": entry, "expected": entry["after"],
                    "found": entry["found"], "note": "the memory changed since this write; nothing was written"}
        entry["status"] = "undone"
        self._persist_memory()
        self._memory_marker("memory_undo", {"entry": entry["id"], "status": "undone"})
        return {"undone": True, "status": "UNDONE", "entry": entry}

    # ---- watch

    def _move(self, watch: dict, state: str) -> None:
        if state not in EDGES[watch["state"]]:
            raise RuntimeError("watch %s cannot go from %s to %s" % (watch["id"], watch["state"], state))
        watch["state"] = state
        self._persist_memory()

    def _refresh_taint(self) -> None:
        bad = [w["id"] for w in self.watches.values() if w["state"] == "tainted"]
        self.tainted = ("watch %s not verified clear: a debug register may still be armed" % ", ".join(bad)) if bad else ""

    def memory_watch(self, args: dict) -> dict:
        gate = self._gate("watch", args)
        op = str(args.get("op") or "list")
        if op == "list":
            self._counters()
            return {"watches": list(self.watches.values()), "tainted": self.tainted or None}
        if op == "arm":
            return self._arm(args, gate)
        if op == "disarm":
            return self._disarm_id(self._watch_id(args))
        if op == "rearm":
            watch = self.watches[self._watch_id(args, state="armed")]
            result = self._memory().exports_sync.rearm(watch["id"])
            watch["threads"] = sorted(set(watch["threads"]) | set(result["armed"]))
            watch["failed"] = result["failed"]
            self._persist_memory()
            return {"watch": watch, "added": result["armed"], "failed": result["failed"]}
        raise ValueError("watch op is arm, disarm, rearm or list")

    def _watch_id(self, args: dict, state: str | None = None) -> str:
        watch_id = str(args.get("watch") or "")
        watch = self.watches.get(watch_id)
        if watch is None or (state and watch["state"] != state):
            raise ValueError("watch %r is not a %s watch of this session" % (watch_id, state or "known"))
        return watch_id

    def _counters(self) -> None:
        for watch in self.watches.values():
            if watch["state"] == "armed" and self.memory_script is not None:
                try:
                    seen = self.memory_script.exports_sync.counters(watch["id"])
                    if seen:
                        watch["seen"] = seen["seen"]
                except Exception as exc:  # the list still answers
                    watch["counters_error"] = str(exc)[:200]

    def _arm(self, args: dict, gate: dict) -> dict:
        if self.tainted:
            raise RuntimeError("session is tainted (%s); disarm and verify first, no new watch" % self.tainted)
        self._stamp(gate)
        reason = str(args.get("reason") or "").strip()
        if len(reason) < MIN_REASON:
            raise ValueError("watch requires options.reason (%d characters or more)" % MIN_REASON)
        size = int(args.get("size", 4))
        kind = str(args.get("access") or "write")
        limit = int(args.get("limit", 20))
        if size not in SIZES or kind not in KINDS or not 1 <= limit <= 200:
            raise ValueError("watch size is 1, 2, 4 or 8; access is write or readwrite; limit 1..200")
        address, _, rng = self._target_span(args, size)
        if address % size:
            raise ValueError("a hardware watch must be aligned to its size")
        if "x" in str(rng.get("protection") or ""):
            raise ValueError("EXECUTABLE RANGE; watch refused")
        used = {w["slot"] for w in self.watches.values() if w["state"] != "clear"}
        free = [s for s in range(SLOTS) if s not in used]
        if not free:
            raise ValueError("all %d debug-register slots are in use; disarm one" % SLOTS)
        watch = {"id": uuid.uuid4().hex[:12], "state": "arming", "slot": free[0], "address": hex(address), "size": size,
                 "access": kind, "limit": limit, "reason": reason, "hits": 0, "threads": [], "failed": [],
                 "coverage": "the threads that existed at arm time; rearm adds later ones"}
        self.watches[watch["id"]] = watch
        self._persist_memory()
        problem = ""
        try:
            try:
                script = self._memory()
            except Exception:
                # no script, so nothing was ever armed: the slot goes back without a disarm
                self._move(watch, "disarming")
                watch["verified"] = {"evidence": "never armed: the memory script could not be created",
                                     "at_ms": int(time.time() * 1000)}
                self._move(watch, "clear")
                raise
            result = script.exports_sync.arm(watch["id"], watch["slot"], hex(address), size, KINDS[kind])
            script.exports_sync.limit(watch["id"], limit)
            watch["threads"], watch["failed"] = result["armed"], result["failed"]
            if result["failed"]:
                problem = "arming failed on thread(s) %s" % [f["id"] for f in result["failed"]]
            else:
                seen = script.exports_sync.readback()
                armed = [t for t in seen["threads"] if watch["slot"] in t["enabled_slots"]]
                if {t["id"] for t in armed} != set(result["armed"]) or seen.get("unreadable"):
                    problem = "debug-register readback does not show the watch on every armed thread"
        except Exception as exc:
            problem = "arming failed: %s" % exc
        if problem and watch["state"] == "clear":
            raise RuntimeError("%s; rolled back: clear" % problem)
        if problem:
            outcome = self._disarm_id(watch["id"], rolling_back=True)
            raise RuntimeError("%s; rolled back: %s" % (problem, outcome["state"]))
        self._move(watch, "armed")
        self._memory_marker("watch_armed", {"watch": watch["id"], "slot": watch["slot"], "address": watch["address"]})
        self.publish()
        return {"watch": watch}

    def _disarm_id(self, watch_id: str, rolling_back: bool = False) -> dict:
        watch = self.watches[watch_id]
        if watch["state"] in ("clear",):
            return {"watch": watch, "state": "clear"}
        if watch["state"] != "disarming":
            self._move(watch, "disarming")
        evidence, error = {}, ""
        # A thread inside the exception handler when its register is cleared gets the old one back when the handler
        # returns; one more unset after it has left clears it. So an unverified readback is retried, a few times.
        for attempt in range(1, DISARM_ATTEMPTS + 1):
            error = ""
            try:
                script = self._memory()
                done = script.exports_sync.disarm(watch_id)
                evidence["unset"] = done.get("unset")
                if done.get("failed"):
                    error = "could not unset on thread(s) %s" % [f["id"] for f in done["failed"]]
                if "seen" in done:
                    watch["seen"] = done["seen"]
                ok, proof = slot_clear(script.exports_sync.readback(), watch["slot"])
                evidence.update(proof)
                if not ok and not error:
                    error = "debug-register readback: slot still enabled or thread unreadable"
            except Exception as exc:
                error = "disarm failed: %s" % exc
            evidence["attempts"] = attempt
            if not error:
                break
            time.sleep(DISARM_PAUSE_S)
        watch["verified"] = {**evidence, "at_ms": int(time.time() * 1000)}
        self._move(watch, "tainted" if error else "clear")
        if error:
            watch["error"] = error
        else:
            watch.pop("error", None)
        self._refresh_taint()
        self._memory_marker("watch_clear" if not error else "watch_tainted", {"watch": watch_id, "evidence": watch["verified"]})
        self.publish()
        if error and not rolling_back:
            return {"watch": watch, "state": "tainted", "error": error, "tainted": self.tainted}
        return {"watch": watch, "state": watch["state"], **({"error": error} if error else {})}

    # ---- lifecycle

    def memory_before_cleanup(self) -> None:
        """Disarm every live watch and prove it clear before the worker lets go of the target."""
        for watch_id, watch in list(self.watches.items()):
            if watch["state"] in ("armed", "arming", "disarming", "tainted"):
                if self.detached:
                    # The process or its session is gone: a debug register cannot kill a process that no longer exists.
                    watch["state"] = "clear"
                    watch["verified"] = {"evidence": "target gone", "at_ms": int(time.time() * 1000)}
                    watch.pop("error", None)
                    self._persist_memory()
                    self._refresh_taint()
                    continue
                try:
                    self._disarm_id(watch_id, rolling_back=True)
                except Exception as exc:
                    watch["state"] = "tainted"
                    watch["error"] = str(exc)[:300]
                    self._refresh_taint()
        if self.tainted and not self._force_detach:
            raise RuntimeError("cleanup refused: %s. Detaching now could leave the target with an armed debug register and no "
                               "handler (it would exit 0x80000004). Retry watch op=disarm, or detach with force_tainted=true "
                               "and accept the risk" % self.tainted)
        if self.memory_script is not None:
            try:
                self.memory_script.unload()
            except Exception as exc:
                if "destroyed" not in str(exc):
                    raise
            self.memory_script = None

    def memory_cleanup_report(self) -> dict:
        if self.tainted:
            return {"target_state": "tainted: may exit 0x80000004", "tainted": self.tainted}
        return {}
