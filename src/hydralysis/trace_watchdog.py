"""Frame-stall watchdog capture, from a separate process (Windows x64).

``capture_stacks(pid)`` suspends each thread of the target for the few microseconds it takes to read its registers,
walks the stack and resumes it. It uses only OpenProcess/OpenThread/SuspendThread/GetThreadContext/ReadProcessMemory:
nothing is written into the target, nothing is injected, and the target needs no cooperation (which is the point: a
stalled frame loop cannot run an in-process recorder).

The walk is by the unwind tables. ``Unwinder`` reads each module's PE headers and its ``.pdata`` (RUNTIME_FUNCTION
table) and ``UNWIND_INFO`` from the target with ReadProcessMemory and applies the unwind codes the way RtlVirtualUnwind
does (push, allocation, frame register, saved registers, chained entries), so the frames are the real caller chain, not a
scan of the stack for words that look like return addresses. A leaf function (no entry) is read as a return address at
the stack pointer. Only when a module has no exception directory at all does a frame fall back to the frame-pointer chain
and then a stack scan, and such a frame says so (``how``: ``unwind``, ``leaf``, ``rbp-chain``, ``stack-scan``).
Not handled: a pc inside an epilogue (the unwind codes then over-pop); this shows as one wrong frame, never as a fault,
because every read is a bounded ReadProcessMemory that the kernel may refuse.

``FrameStallWatchdog`` watches the declared main loop (the hits of the profile's frame hook, or a counter in the target
read from outside) and, when it stops advancing for a declared time, calls ``capture_stacks`` once per stall.
"""
from __future__ import annotations

import bisect
import ctypes
import json
import struct
import threading
import time
from ctypes import wintypes
from pathlib import Path

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_ACCESS = 0x0400 | 0x0010 | 0x0008 | 0x1000  # QUERY_INFORMATION | VM_READ | VM_OPERATION(no write used) | QUERY_LIMITED
THREAD_ACCESS = 0x0002 | 0x0008 | 0x0040 | 0x0800  # SUSPEND_RESUME | GET_CONTEXT | QUERY_INFORMATION | QUERY_LIMITED
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
TH32CS_SNAPTHREAD = 0x4


class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_int64)]


class CONTEXT(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64), ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64), ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD), ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD), ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64), ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64), ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64), ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64), ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64), ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64), ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("FltSave", ctypes.c_byte * 512),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64), ("LastBranchToRip", ctypes.c_uint64), ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64), ("LastExceptionFromRip", ctypes.c_uint64),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD)]


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wintypes.DWORD), ("EntryPoint", ctypes.c_void_p)]


k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenThread.restype = wintypes.HANDLE
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
k32.SuspendThread.argtypes = [wintypes.HANDLE]
k32.ResumeThread.argtypes = [wintypes.HANDLE]
psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(MODULEINFO), wintypes.DWORD]
psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]


def thread_ids(pid: int) -> list[int]:
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    out: list[int] = []
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k32.Thread32First(snap, ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID == pid:
                out.append(entry.th32ThreadID)
            ok = k32.Thread32Next(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return out


def modules(process) -> list[tuple[int, int, str]]:
    needed = wintypes.DWORD()
    arr = (wintypes.HMODULE * 2048)()
    psapi.EnumProcessModulesEx(process, arr, ctypes.sizeof(arr), ctypes.byref(needed), 0x3)
    out = []
    for i in range(min(needed.value // ctypes.sizeof(wintypes.HMODULE), 2048)):
        info = MODULEINFO()
        name = ctypes.create_unicode_buffer(260)
        if psapi.GetModuleInformation(process, arr[i], ctypes.byref(info), ctypes.sizeof(info)):
            psapi.GetModuleBaseNameW(process, arr[i], name, 260)
            out.append((info.lpBaseOfDll or 0, info.SizeOfImage, name.value))
    return sorted(out)


def resolve(addr: int, mods: list[tuple[int, int, str]]) -> str | None:
    for base, size, name in mods:
        if base <= addr < base + size:
            return f"{name}+0x{addr - base:x}"
    return None


def _read(process, addr: int, size: int) -> bytes | None:
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(process, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)) or got.value == 0:
        return None
    return buf.raw[:got.value]


# ---- the unwind tables ---------------------------------------------------------------------------------------------
UWOP_PUSH_NONVOL, UWOP_ALLOC_LARGE, UWOP_ALLOC_SMALL, UWOP_SET_FPREG, UWOP_SAVE_NONVOL, UWOP_SAVE_NONVOL_FAR = 0, 1, 2, 3, 4, 5
UWOP_EPILOG, UWOP_SPARE, UWOP_SAVE_XMM128, UWOP_SAVE_XMM128_FAR, UWOP_PUSH_MACHFRAME = 6, 7, 8, 9, 10
UNW_FLAG_CHAININFO = 4
REG_NAMES = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
MAX_CHAIN = 8


class Unwinder:
    """Walk one thread's stack with the target's own .pdata, read from a separate process."""

    def __init__(self, process, mods):
        self.process = process
        self.mods = mods                                  # [(base, size, name)] sorted
        self._tables: dict = {}

    def _read(self, address: int, size: int):
        return _read(self.process, address, size)

    def _u32(self, address: int):
        data = self._read(address, 4)
        return struct.unpack("<I", data)[0] if data and len(data) == 4 else None

    def _u64(self, address: int):
        data = self._read(address, 8)
        return struct.unpack("<Q", data)[0] if data and len(data) == 8 else None

    def module_at(self, address: int):
        for base, size, name in self.mods:
            if base <= address < base + size:
                return base, size, name
        return None

    def table(self, base: int, size: int):
        """(begin RVAs, [(begin, end, unwind)]) of the module at BASE; None when it has no exception directory."""
        if base in self._tables:
            return self._tables[base]
        found = None
        head = self._read(base, 0x1000)
        if head and head[:2] == b"MZ" and len(head) >= 0x40:
            lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            if lfanew + 0x108 <= len(head) and head[lfanew:lfanew + 4] == b"PE\0\0":
                magic = struct.unpack_from("<H", head, lfanew + 24)[0]
                if magic == 0x20B:
                    directory = lfanew + 24 + 112 + 3 * 8                   # DataDirectory[3] = exception table
                    rva, length = struct.unpack_from("<II", head, directory)
                    raw = self._read(base + rva, length) if rva and length else None
                    if raw:
                        rows = [struct.unpack_from("<III", raw, i) for i in range(0, len(raw) - 11, 12)]
                        rows.sort()
                        found = ([row[0] for row in rows], rows)
        self._tables[base] = found
        return found

    def entry_for(self, address: int):
        """(module base, RUNTIME_FUNCTION row) covering ADDRESS, or (base, None) for a leaf, or (None, None) outside a module."""
        module = self.module_at(address)
        if module is None:
            return None, None
        base, size, _name = module
        table = self.table(base, size)
        if table is None:
            return base, "no-table"
        starts, rows = table
        rva = address - base
        index = bisect.bisect_right(starts, rva) - 1
        if index >= 0 and rows[index][0] <= rva < rows[index][1]:
            return base, rows[index]
        return base, None

    def _unwind_one(self, base: int, row, pc: int, regs: dict):
        """Apply the unwind codes of ROW to REGS (rsp, rbp, rbx, ...). Returns the return address or None."""
        begin, _end, info_rva = row
        offset = pc - (base + begin)
        rsp = regs["rsp"]
        frame_base = rsp
        for _ in range(MAX_CHAIN):
            header = self._read(base + info_rva, 4)
            if not header or len(header) < 4:
                return None
            version_flags, prolog, count, frame = header
            flags = version_flags >> 3
            codes_raw = self._read(base + info_rva + 4, 2 * count) if count else b""
            if count and (not codes_raw or len(codes_raw) < 2 * count):
                return None
            in_prolog = offset < prolog
            frame_reg, frame_off = frame & 15, (frame >> 4) * 16
            codes = [(codes_raw[i], codes_raw[i + 1] & 15, codes_raw[i + 1] >> 4) for i in range(0, len(codes_raw), 2)]
            slot = 0
            applied_fp = False
            if frame_reg and not in_prolog:
                rsp = (regs[REG_NAMES[frame_reg]] - frame_off) & 0xFFFFFFFFFFFFFFFF
                frame_base = rsp
                applied_fp = True
            elif frame_reg:
                # inside the prolog: the frame register is set only if its SET_FPREG code (offset) has run
                for code_offset, op, _info in codes:
                    if op == UWOP_SET_FPREG and code_offset <= offset:
                        rsp = (regs[REG_NAMES[frame_reg]] - frame_off) & 0xFFFFFFFFFFFFFFFF
                        frame_base = rsp
                        applied_fp = True
            while slot < len(codes):
                code_offset, op, opinfo = codes[slot]
                width = 1
                if op == UWOP_ALLOC_LARGE:
                    width = 2 if opinfo == 0 else 3
                elif op in (UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128, UWOP_EPILOG, UWOP_SPARE):
                    width = 2
                elif op in (UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128_FAR):
                    width = 3
                if in_prolog and code_offset > offset:
                    slot += width
                    continue
                if op == UWOP_PUSH_NONVOL:
                    value = self._u64(rsp)
                    if value is None:
                        return None
                    regs[REG_NAMES[opinfo]] = value
                    rsp += 8
                elif op == UWOP_ALLOC_LARGE:
                    if opinfo == 0:
                        rsp += (codes_raw[2 * (slot + 1)] | (codes_raw[2 * (slot + 1) + 1] << 8)) * 8
                    else:
                        rsp += struct.unpack_from("<I", codes_raw, 2 * (slot + 1))[0]
                elif op == UWOP_ALLOC_SMALL:
                    rsp += opinfo * 8 + 8
                elif op == UWOP_SET_FPREG:
                    if not applied_fp:
                        rsp = (regs[REG_NAMES[frame_reg]] - frame_off) & 0xFFFFFFFFFFFFFFFF
                elif op in (UWOP_SAVE_NONVOL, UWOP_SAVE_NONVOL_FAR):
                    where = (codes_raw[2 * (slot + 1)] | (codes_raw[2 * (slot + 1) + 1] << 8)) * 8 if op == UWOP_SAVE_NONVOL \
                        else struct.unpack_from("<I", codes_raw, 2 * (slot + 1))[0]
                    value = self._u64(frame_base + where)
                    if value is None:
                        return None
                    regs[REG_NAMES[opinfo]] = value
                elif op == UWOP_PUSH_MACHFRAME:
                    rsp += 8 if opinfo == 0 else 16          # error code (opinfo 1) then rip, cs, eflags, rsp, ss
                    new_rip = self._u64(rsp)
                    new_rsp = self._u64(rsp + 24)
                    if new_rip is None or new_rsp is None:
                        return None
                    regs["rsp"] = new_rsp
                    return new_rip
                slot += width
            if flags & UNW_FLAG_CHAININFO:
                chain_at = base + info_rva + 4 + ((count + 1) & ~1) * 2
                chained = self._read(chain_at, 12)
                if not chained or len(chained) < 12:
                    return None
                begin, _end, info_rva = struct.unpack("<III", chained)
                offset = 1 << 30                       # the chained entry's prolog is complete
                continue
            break
        ret = self._u64(rsp)
        if ret is None:
            return None
        regs["rsp"] = rsp + 8
        return ret

    def walk(self, context, depth: int):
        """Frames of one thread from its captured CONTEXT: [{pc, at, how}], the first being the thread's own pc."""
        regs = {name: getattr(context, name.capitalize() if name.startswith("r") and name[1:].isalpha() else name.upper())
                for name in ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")}
        for number in range(8, 16):
            regs["r%d" % number] = getattr(context, "R%d" % number)
        pc = context.Rip
        frames = []
        for index in range(depth):
            base, row = self.entry_for(pc if index == 0 else pc - 1)   # a return address may follow a no-return call
            at = resolve(pc, self.mods)
            if base is None:
                if index == 0 or not frames:
                    frames.append({"pc": pc, "at": at, "how": "rip" if index == 0 else "unmapped"})
                break
            if row == "no-table":
                frames.append({"pc": pc, "at": at, "how": "no-table"})
                break
            if row is None:                    # a leaf: the return address is at the top of the stack
                ret = self._u64(regs["rsp"])
                frames.append({"pc": pc, "at": at, "how": "rip" if index == 0 else "leaf"})
                if ret is None:
                    break
                regs["rsp"] += 8
            else:
                frames.append({"pc": pc, "at": at, "how": "rip" if index == 0 else "unwind"})
                ret = self._unwind_one(base, row, pc, regs)
                if ret is None:
                    break
            if ret < 0x10000:
                break
            pc = ret
        return frames


def _walk(process, ctx, mods, depth: int, scan_bytes: int, unwinder: Unwinder | None = None) -> list[dict]:
    """The caller chain by the unwind tables; when the first frame cannot be unwound (no table), the frame-pointer chain and a
    labelled stack scan, as before."""
    unwinder = unwinder or Unwinder(process, mods)
    frames = unwinder.walk(ctx, depth)
    if len(frames) > 1 or (frames and frames[0].get("how") not in ("no-table", "unmapped")):
        return frames
    frames = [{"pc": ctx.Rip, "at": resolve(ctx.Rip, mods), "how": "rip"}]
    seen = {ctx.Rip}
    rbp, rsp = ctx.Rbp, ctx.Rsp
    for _ in range(depth):  # frame-pointer chain
        if rbp < rsp or rbp - rsp > 1 << 20 or rbp & 7:
            break
        word = _read(process, rbp, 16)
        if word is None or len(word) < 16:
            break
        nxt, ret = struct.unpack("<QQ", word)
        at = resolve(ret, mods)
        if at is None:
            break
        frames.append({"pc": ret, "at": at, "how": "rbp-chain"})
        seen.add(ret)
        if nxt <= rbp:
            break
        rbp = nxt
    stack = _read(process, rsp, scan_bytes) or b""  # scan: plausible return addresses (marked as a guess)
    for i in range(0, len(stack) - 7, 8):
        word = struct.unpack_from("<Q", stack, i)[0]
        if word in seen:
            continue
        at = resolve(word, mods)
        if at is not None and len(frames) < depth:
            seen.add(word)
            frames.append({"pc": word, "at": at, "how": "stack-scan"})
    return frames


def capture_stacks(pid: int, depth: int = 24, scan_bytes: int = 4096) -> dict:
    """All thread stacks of ``pid``. Each thread is suspended only for the register read."""
    process = k32.OpenProcess(PROCESS_ACCESS, False, pid)
    if not process:
        return {"state": "refused", "reason": f"OpenProcess failed ({ctypes.get_last_error()})", "threads": []}
    threads = []
    try:
        mods = modules(process)
        unwinder = Unwinder(process, mods)
        for tid in thread_ids(pid):
            handle = k32.OpenThread(THREAD_ACCESS, False, tid)
            if not handle:
                threads.append({"tid": tid, "state": "unreadable", "reason": f"OpenThread failed ({ctypes.get_last_error()})"})
                continue
            try:
                ctx = CONTEXT()
                ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER
                if k32.SuspendThread(handle) == 0xFFFFFFFF:
                    threads.append({"tid": tid, "state": "unreadable", "reason": "SuspendThread failed"})
                    continue
                try:
                    ok = k32.GetThreadContext(handle, ctypes.byref(ctx))
                    frames = _walk(process, ctx, mods, depth, scan_bytes, unwinder) if ok else []
                finally:
                    k32.ResumeThread(handle)
                threads.append({"tid": tid, "state": "captured" if ok else "unreadable", "frames": frames})
            finally:
                k32.CloseHandle(handle)
    finally:
        k32.CloseHandle(process)
    return {"state": "captured", "pid": pid, "threads": threads, "modules": len(mods),
            "note": "no write into the target; threads were suspended only while registers were read; frames by the unwind tables"}


# ---- the frame-stall watchdog ----------------------------------------------------------------------------------------
def counter_reader(pid: int, module: str, symbol: str | None = None, rva: int | None = None, size: int = 4):
    """A progress source read from outside: the integer at an export (or RVA) of a module of the target. Nothing is written."""
    from hydralysis.pe import Image

    def find():
        process = k32.OpenProcess(PROCESS_ACCESS, False, pid)
        if not process:
            return None, None
        try:
            for base, _size, name in modules(process):
                if name.lower() == module.lower():
                    return base, name
        finally:
            k32.CloseHandle(process)
        return None, None

    state: dict = {}

    def read() -> int | None:
        process = k32.OpenProcess(PROCESS_ACCESS, False, pid)
        if not process:
            return None
        try:
            if "address" not in state:
                base, _name = find()
                if base is None:
                    return None
                site = rva
                if site is None:
                    path = ctypes.create_unicode_buffer(1024)
                    psapi.GetModuleFileNameExW(process, ctypes.c_void_p(base), path, 1024)
                    image = Image(Path(path.value))
                    image.pe.parse_data_directories(directories=[0])
                    site = next((int(item.address) for item in getattr(image.pe, "DIRECTORY_ENTRY_EXPORT").symbols
                                 if item.name and item.name.decode() == symbol), None)
                    if site is None:
                        return None
                state["address"] = base + site
            data = _read(process, state["address"], size)
            return int.from_bytes(data, "little") if data and len(data) == size else None
        finally:
            k32.CloseHandle(process)
    return read


class FrameStallWatchdog:
    """Watch a progress counter (frames of the declared main loop) and capture every thread's stack when it stops.

    `progress()` returns the counter, or None when it cannot be read. The loop is armed when the counter has advanced at
    least once after `after_s` (a loop that never started is not a stall). When it has not advanced for `stall_s`, `capture`
    (default `capture_stacks`) runs once and `on_stall` gets the result; it re-arms only after the counter advances again, so
    one stall is one capture. The watchdog runs in this (the worker's) process, never in the target.
    """

    def __init__(self, pid: int, progress, stall_s: float, on_stall, *, after_s: float = 0.0, poll_s: float = 0.05,
                 capture=None, clock=time.monotonic, max_captures: int = 4):
        if stall_s <= 0:
            raise ValueError("stall_s must be positive")
        self.pid, self.progress, self.stall_s, self.on_stall = pid, progress, float(stall_s), on_stall
        self.after_s, self.poll_s, self.clock, self.max_captures = after_s, poll_s, clock, max_captures
        self.capture = capture or capture_stacks
        self.state = "idle"
        self.captures = 0
        self.errors: list = []
        self.last: dict | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "FrameStallWatchdog":
        self.state = "armed-waiting"
        self._thread = threading.Thread(target=self._run, name="frame-stall-watchdog", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self.state = "stopped"

    def _run(self) -> None:
        started = self.clock()
        last_value, last_change, advanced, fired = None, self.clock(), False, False
        while not self._stop.wait(self.poll_s):
            now = self.clock()
            try:
                value = self.progress()
            except Exception as exc:                         # a progress source that fails is reported, never fatal
                self.errors.append("%s: %s" % (type(exc).__name__, exc))
                self.errors = self.errors[-5:]
                continue
            if value is None:
                continue
            if last_value is None or value != last_value:
                if last_value is not None and value != last_value and now - started >= self.after_s:
                    advanced = True
                last_value, last_change, fired = value, now, False
                if advanced:
                    self.state = "watching"
                continue
            if advanced and not fired and now - last_change >= self.stall_s and self.captures < self.max_captures:
                fired = True
                self.state = "captured"
                self.captures += 1
                try:
                    stacks = self.capture(self.pid)
                except Exception as exc:
                    stacks = {"state": "failed", "reason": "%s: %s" % (type(exc).__name__, exc), "threads": []}
                result = {"stalled_for_s": round(now - last_change, 3), "stall_s": self.stall_s, "progress": value,
                          "capture_index": self.captures, "stacks": stacks}
                self.last = result
                try:
                    self.on_stall(result)
                except Exception as exc:
                    self.errors.append("on_stall: %s: %s" % (type(exc).__name__, exc))


def write_stall(directory: Path, result: dict) -> Path:
    """Persist one stall capture as JSON next to the trace segment (atomic)."""
    from hydralysis import durable
    path = Path(directory) / ("stall-%d.json" % result["capture_index"])
    path.parent.mkdir(parents=True, exist_ok=True)
    durable.atomic_write(path, json.dumps(result, sort_keys=True, default=str, indent=1).encode("utf-8"))
    return path
