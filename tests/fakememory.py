"""A memory-backed stand-in for the target and for the fixed memory script (Z12 unit tests).

`Target` is a tiny address space (one data range, one code range) with per-thread debug-register slots; `Control`
answers the control script's calls the memory code makes; `MemoryScript` answers the memory script's. Every failure the
teardown matrix needs is a switch: an unset that fails on a thread, a readback that is unavailable, a thread that appears
between arm and disarm.
"""

from __future__ import annotations

from types import SimpleNamespace

DATA, CODE = 0x2000, 0x9000


class Target:
    def __init__(self, arch="x64"):
        self.arch = arch
        self.memory = {DATA + i: 0 for i in range(0x100)}
        self.slots: dict[int, set] = {1: set(), 2: set(), 3: set()}   # thread id -> enabled debug-register slots
        self.fail_unset: set = set()
        self.readback_unavailable = False
        self.unreadable: list = []
        self.new_thread_on_disarm = 0
        self.reenable_after_unset = 0     # a thread inside the handler gets its old register back this many times
        self.writer_races = None          # callable(address) run between the compare and the write
        self.ranges = {DATA: ("rw-", 0x100), CODE: ("r-x", 0x100)}

    def put(self, address, values):
        for i, v in enumerate(values):
            self.memory[address + i] = v


class Control:
    def __init__(self, target: Target):
        self.t = target
        self.exports_sync = self

    def info(self, selected=None):
        return {"arch": self.t.arch, "pointer_size": 8 if self.t.arch == "x64" else 4,
                "main": {"path": selected, "name": "t.exe", "base": hex(DATA), "size": 0x100}}

    def locate(self, address):
        value = int(address, 16)
        for base, (protection, size) in self.t.ranges.items():
            if base <= value < base + size:
                return {"range": {"base": hex(base), "size": size, "protection": protection}, "module": None}
        return {"range": None, "module": None}


class MemoryScript:
    def __init__(self, target: Target):
        self.t = target
        self.exports_sync = self
        self.watches = {}
        self.unloaded = False
        self.calls = []

    def unload(self):
        self.unloaded = True

    def writeCas(self, address, expect, value):
        a = int(address, 16)
        self.calls.append(("writeCas", a))
        base = next(b for b in self.t.ranges if b <= a < b + self.t.ranges[b][1])
        if "x" in self.t.ranges[base][0]:
            raise RuntimeError("EXECUTABLE RANGE; write refused")
        actual = [self.t.memory.get(a + i, 0) for i in range(len(expect))]
        if actual != expect:
            return {"ok": False, "actual": actual}
        if self.t.writer_races:
            self.t.writer_races(a)
        self.t.put(a, value)
        return {"ok": True, "actual": actual, "after": value}

    def arm(self, wid, slot, address, size, cond):
        self.calls.append(("arm", wid))
        self.watches[wid] = {"slot": slot, "seen": 0, "limit": 20}
        failed = []
        for tid in list(self.t.slots):
            self.t.slots[tid].add(slot)
        return {"armed": sorted(self.t.slots), "failed": failed}

    def limit(self, wid, n):
        self.watches[wid]["limit"] = n

    def rearm(self, wid):
        slot = self.watches[wid]["slot"]
        added = [t for t, s in self.t.slots.items() if slot not in s]
        for t in added:
            self.t.slots[t].add(slot)
        return {"armed": added, "failed": []}

    def disarm(self, wid):
        slot = self.watches[wid]["slot"]
        failed, unset = [], []
        for tid in list(self.t.slots):
            if tid in self.t.fail_unset:
                failed.append({"id": tid, "error": "access denied"})
            else:
                self.t.slots[tid].discard(slot)
                unset.append(tid)
        if self.t.reenable_after_unset:
            self.t.reenable_after_unset -= 1
            self.t.slots[2].add(slot)
        for _ in range(self.t.new_thread_on_disarm):         # a thread born after the enumeration, slot inherited
            self.t.slots[max(self.t.slots) + 1] = {slot}
        self.t.new_thread_on_disarm = 0
        return {"unset": unset, "failed": failed, "seen": self.watches[wid]["seen"]}

    def readback(self):
        if self.t.readback_unavailable:
            raise RuntimeError("GetThreadContext unavailable")
        return {"threads": [{"id": t, "dr7": 0, "enabled_slots": sorted(s)} for t, s in self.t.slots.items()],
                "unreadable": list(self.t.unreadable)}

    def counters(self, wid):
        return {"seen": self.watches[wid]["seen"], "limit": self.watches[wid]["limit"]}


def wire(agent, target: Target):
    """Point a fake-attached agent at the in-memory target."""
    agent.control = SimpleNamespace(exports_sync=Control(target))
    agent.memory_script = MemoryScript(target)
    return agent.memory_script
