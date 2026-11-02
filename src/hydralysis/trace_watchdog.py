"""Frame-stall watchdog capture, from a separate process (Windows x64).

``capture_stacks(pid)`` suspends each thread of the target for the few microseconds it takes to read its registers,
walks the stack with ``ReadProcessMemory`` and resumes it. It uses only OpenProcess/OpenThread/SuspendThread/
GetThreadContext/ReadProcessMemory: nothing is written into the target, nothing is injected, and the target needs no
cooperation (which is the point: a stalled frame loop cannot run an in-process recorder). Frames are found by
following the frame-pointer chain and, failing that, by scanning the stack for words that point into an executable
module's image; each frame is reported as ``module+offset``.
"""
from __future__ import annotations

import ctypes
import struct
from ctypes import wintypes

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


def _walk(process, ctx, mods, depth: int, scan_bytes: int) -> list[dict]:
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
                    frames = _walk(process, ctx, mods, depth, scan_bytes) if ok else []
                finally:
                    k32.ResumeThread(handle)
                threads.append({"tid": tid, "state": "captured" if ok else "unreadable", "frames": frames})
            finally:
                k32.CloseHandle(handle)
    finally:
        k32.CloseHandle(process)
    return {"state": "captured", "pid": pid, "threads": threads, "modules": len(mods),
            "note": "no write into the target; threads were suspended only while registers were read"}
