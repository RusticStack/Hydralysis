"""Hang and handler dumps (spec 15.9): read a minidump with the engine's importer, symbolize every thread, and report what
the stacks show, each statement with the threads and frame addresses it cites.

The engine (`hydra-trace dump`) parses the dump, finds the waits and their lock owners in the dump's own memory and reports
the patterns. This module supplies what the engine cannot know: symbol tables for the modules in the dump (function ranges
from the exception tables, names from export tables and linker maps) and the join with the trace session. Nothing here
writes into the target.

What a minidump cannot say is said so: its thread list carries no suspend count for a process that dumped itself, so
`suspended_threads` is built from a live capture (the watchdog's `suspended_before`) and the trace's `SuspendThread` calls.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

FRAME_LIMIT = 64


class DumpError(RuntimeError):
    pass


def _run(tool: str, *args: str, timeout: float = 120.0) -> dict:
    from hydralysis import proc
    done = proc.run([tool, *args], capture_output=True, text=True, timeout=timeout)
    if done.returncode != 0:
        raise DumpError("hydra-trace %s failed (%d): %s" % (args[0] if args else "", done.returncode, (done.stderr or done.stdout).strip()))
    return json.loads(done.stdout)


def locate_module(name: str, directories: list[Path]) -> Path | None:
    """The image file of a dump module: a build directory first, then System32 (a name match, case-insensitive)."""
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    for directory in [*directories, system]:
        candidate = Path(directory) / name
        if candidate.is_file():
            return candidate
        try:
            for entry in Path(directory).iterdir():
                if entry.name.lower() == name.lower() and entry.is_file():
                    return entry
        except OSError:
            continue
    return None


def _exports(pe) -> dict[int, str]:
    pe.parse_data_directories(directories=[0])
    table = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    out: dict[int, str] = {}
    for symbol in getattr(table, "symbols", []) or []:
        if symbol.name and not getattr(symbol, "forwarder", None):
            out.setdefault(int(symbol.address), symbol.name.decode("ascii", "replace"))
    return out


def module_table(path: Path, rvas: set[int], *, named: dict[int, str] | None = None) -> dict:
    """Function ranges for the RVAs of interest in one image: [start, end) from the exception tables (a leaf function with no
    entry runs to the next NAMED symbol), named by NAMED (linker map), else by an export at the function's start, else
    `sub_<rva>` (the code is known to be a function, its name is not)."""
    from hydralysis.pe import Image
    image = Image(path)
    pe = image.pe
    pe.parse_data_directories(directories=[3])
    rows = sorted((int(e.struct.BeginAddress), int(e.struct.EndAddress)) for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []))
    exports = _exports(pe)
    named = named or {}
    starts = sorted(named)
    functions, seen = [], set()
    for rva in sorted(rvas):
        begin_end = next(((b, e) for b, e in rows if b <= rva < e), None)
        if begin_end is None and starts:
            before = [s for s in starts if s <= rva]
            if before:
                later = [s for s in starts if s > before[-1]]
                begin_end = (before[-1], later[0] if later else before[-1] + 16)
        if begin_end is None or begin_end in seen:
            continue
        seen.add(begin_end)
        begin, end = begin_end
        name = named.get(begin) or exports.get(begin) or "sub_%x" % begin
        functions.append({"start": begin, "end": end, "name": name})
    code = [[int(s.VirtualAddress), int(s.VirtualAddress) + int(s.Misc_VirtualSize)] for s in pe.sections if s.Characteristics & 0x20000000]
    return {"code": code, "functions": functions}


def analyse(tool: str, dump: Path, *, directories: list[Path], names: dict[str, dict[int, str]] | None = None,
            waits: list[str] | None = None, fault_handlers: list[str] | None = None, work: Path | None = None,
            source: str = "minidump") -> dict:
    """Parse DUMP, symbolize every frame of every thread and report the patterns.

    DIRECTORIES are searched for the dump's modules before System32; NAMES maps a module name to {rva: function name} for
    images with a linker map. The first pass finds the frames, the second names them (the table only covers the frames)."""
    work = Path(work) if work else Path(tempfile.mkdtemp(prefix="dump-"))
    work.mkdir(parents=True, exist_ok=True)
    first = _run(tool, "dump", str(dump), "--source", source)
    wanted: dict[str, set[int]] = {}
    for thread in first["stacks"]:
        for frame in thread["frames"]:
            if frame["module"] is not None:
                wanted.setdefault(frame["module"], set()).add(frame["rva"])
    modules, missing = {}, []
    for name, rvas in sorted(wanted.items()):
        path = locate_module(name, directories)
        if path is None:
            missing.append(name)
            continue
        modules[name] = module_table(path, rvas, named=(names or {}).get(name))
    table = work / "symbols.json"
    from hydralysis import durable
    durable.atomic_write(table, json.dumps({"modules": modules}).encode("utf-8"))
    args = ["dump", str(dump), "--symbols", str(table), "--source", source]
    for name in waits or []:
        args += ["--wait", name]
    for name in fault_handlers or []:
        args += ["--fault-handler", name]
    report = _run(tool, *args)
    report["unsymbolized_modules"] = missing
    unresolved = []
    for thread in report["stacks"]:
        for frame in thread["frames"]:
            ranges = (modules.get(frame["module"]) or {}).get("code") or []
            # a stack word that points into a module's data is not a return address: it is kept, marked, never named
            frame["code"] = any(start <= (frame["rva"] or -1) < end for start, end in ranges)
            if frame["code"] and frame["function"] is None:
                unresolved.append({"thread_id": thread["thread_id"], "address": frame["address"], "module": frame["module"]})
    report["unresolved_frames"] = unresolved
    return report


def last_events(rows: list[dict], threads: list[int], *, dump_source: str = "minidump") -> dict:
    """For each dump thread the last session event of that thread (by session order). The session's clock is not the dump's
    wall clock, so the join is by thread id and order; a thread with no event says so rather than guessing. The events the
    dump itself was imported as (source DUMP_SOURCE) are the stacks being explained, never what precedes them."""
    by_thread: dict = {}
    for row in sorted(rows, key=lambda r: r.get("seq") or 0):
        if str(row.get("source_id") or "").startswith(dump_source):
            continue
        by_thread[row.get("thread_id")] = row
    out = {}
    for tid in threads:
        row = by_thread.get(tid)
        out[tid] = ({"event_id": row["event_id"], "kind": row["kind"], "seq": row["seq"], "joined_by": "thread id and session order"}
                    if row else {"event_id": None, "reason": "no event of this thread in the session"})
    return out


def suspend_pattern(stall: dict, calls: list[dict], handler_threads: list[int], *, survivors: list[int] | None = None) -> dict:
    """`all threads suspended by thread T`, from independent observations: the live capture says which threads were already
    suspended before it touched them (`suspended_before` > 0), the dump says which thread sits in the host's fault handler
    (HANDLER_THREADS) and, when a recorder was inside the target, the trace says which thread called SuspendThread (CALLS: rows
    with thread_id and event_id).

    With CALLS the pattern is `observed`: every suspension came from the handler thread. Without them it is `inferred`: the
    suspended threads are suspended, the one running application thread is in the host's fault handler, and the handler is
    the code that suspends; the call itself is on no stack any more. The threads that were not suspended are named."""
    threads = [t for t in stall["threads"] if t.get("state") == "captured"]
    suspended = sorted(t["tid"] for t in threads if t.get("suspended_before", 0) > 0)
    running = sorted(t["tid"] for t in threads if t.get("suspended_before", 0) == 0)
    callers = sorted({c["thread_id"] for c in calls})
    in_handler = [t for t in running if t in handler_threads]
    if calls:
        holds = len(callers) == 1 and callers[0] in handler_threads and len(calls) >= len(suspended) > 0
        culprit = callers[0] if len(callers) == 1 else None
    else:
        holds = len(in_handler) == 1 and bool(suspended)
        culprit = in_handler[0] if holds else None
    return {"pattern": "all-threads-suspended" if holds else "not-established", "basis": "observed" if calls else "inferred",
            "suspended_by": culprit, "suspended_threads": suspended, "not_suspended": running, "suspend_calls": len(calls),
            "caller_in_fault_handler": bool(culprit in handler_threads), "survivors_named": sorted(survivors or []),
            "citations": [c["event_id"] for c in calls[:8]]}
