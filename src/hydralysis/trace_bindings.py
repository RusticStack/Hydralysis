"""Script <-> native binding tables (spec 15.7).

Targets with a scripting layer register native functions in a table (`{name, pointer, argc}` rows) or through a
registration call (`lua_register(L, "name", fn)`, JNI `RegisterNatives`, an engine's own `register_native`). A profile
names the layout (`[[bindings]]` in the profile, see docs/trace-profiles.md). This module turns that into

* **rows**: script-visible name -> native address -> parameter count, each citing where it was read;
* a **cited corpus**: functions named and typed in the type-corpus format (docs/type-corpus.md), plus the binding table
  itself, so the import is replayable from its source;
* **cross-layer edges** `script function -> native thunk -> implementation`;
* **trace links**: a script-VM event is linked to the native function event it invoked, so an explanation crosses the
  language boundary instead of stopping at the VM dispatcher.

Everything reads through a small memory interface (`pe.Image` has it): `base`, `read_rva(rva, size)`,
`string_at(rva, limit)`. A pointer that does not land in the image, a name that is not text, or a table that runs off the
end is a row marked `unresolved` with its reason; nothing is invented.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct

MAX_ROWS = 4096
_IDENT = re.compile(r"[^A-Za-z0-9_]")


class BindingError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _site(rva: int) -> str:
    return "rva:%#x" % rva


def _pointer(memory, offset_rva: int, size: int) -> int | None:
    try:
        raw = memory.read_rva(offset_rva, size)
    except (ValueError, OSError):
        return None
    return int.from_bytes(raw, "little")


def _rva_of(memory, pointer: int | None, pointer_size: int) -> int | None:
    """An absolute pointer to an RVA, or None if it is null or outside the image."""
    if not pointer:
        return None
    rva = pointer - memory.base
    if rva <= 0 or rva >= 1 << 32:
        return None
    try:
        memory.read_rva(rva, 1)
    except (ValueError, OSError):
        return None
    return rva


def extract_table(memory, spec: dict, *, pointer_size: int = 8) -> dict:
    """Read a `kind = "table"` binding. SPEC: {id, table_rva, stride, name_offset, fn_offset, count?, argc_offset?,
    argc_size?}. Without `count` the table ends at the first row whose name pointer is null."""
    base, stride = spec["table_rva"], spec["stride"]
    limit = min(spec.get("count") or MAX_ROWS, MAX_ROWS)
    rows, stopped = [], "count" if spec.get("count") else "limit"
    for index in range(limit):
        row_rva = base + index * stride
        name_ptr = _pointer(memory, row_rva + spec["name_offset"], pointer_size)
        if name_ptr is None:
            stopped = "table-ends-outside-the-image"
            break
        if name_ptr == 0 and not spec.get("count"):
            stopped = "null-name"
            break
        fn_ptr = _pointer(memory, row_rva + spec["fn_offset"], pointer_size)
        argc = None
        if spec.get("argc_offset") is not None:
            argc = _pointer(memory, row_rva + spec["argc_offset"], spec.get("argc_size", 4))
        row = {"index": index, "site": _site(row_rva), "source": "table %s at %s, row %d" % (spec["id"], _site(base), index),
               "argc": argc}
        name_rva = _rva_of(memory, name_ptr, pointer_size)
        name = memory.string_at(name_rva, 128) if name_rva is not None else None
        native_rva = _rva_of(memory, fn_ptr, pointer_size)
        problems = []
        if not name:
            problems.append("name pointer %#x does not point at text in the image" % name_ptr)
        if native_rva is None:
            problems.append("function pointer %#x is not in the image" % (fn_ptr or 0))
        row.update(script_name=name, native_rva=_site(native_rva) if native_rva is not None else None,
                   native_va="va:%#x" % (memory.base + native_rva) if native_rva is not None else None)
        row["status"] = "unresolved" if problems else "resolved"
        if problems:
            row["unresolved"] = problems
        rows.append(row)
    return {"binding": spec["id"], "kind": "table", "rows": rows, "ended": stopped}


def bindings_from_call_sites(spec: dict, sites: list[dict], memory=None) -> dict:
    """Rows for a `kind = "call"` binding from the registration call sites.

    SITES are what the engine's constant-propagation (`ghidra_query action=trace`) recovered at each call to the
    registration function: [{site: "rva:0x...", args: [{index, string?, rva?, constant?}]}]. SPEC gives which argument is
    the name (`name_arg`), the native pointer (`fn_arg`) and, optionally, the parameter count (`argc_arg`). An argument
    the analysis could not make constant leaves that field null and the row `unresolved` with the argument named."""
    rows = []
    for number, site in enumerate(sites[:MAX_ROWS]):
        args = {arg.get("index"): arg for arg in site.get("args", []) if isinstance(arg, dict)}
        name = (args.get(spec["name_arg"]) or {}).get("string")
        if name is None and memory is not None and (args.get(spec["name_arg"]) or {}).get("rva") is not None:
            name = memory.string_at(args[spec["name_arg"]]["rva"], 128)
        fn = args.get(spec["fn_arg"]) or {}
        native = fn.get("rva")
        if native is None and fn.get("constant") and memory is not None:
            native = _rva_of(memory, fn["constant"], 8)
        argc = (args.get(spec["argc_arg"]) or {}).get("constant") if spec.get("argc_arg") is not None else None
        problems = []
        if not name:
            problems.append("argument %d (name) was not a constant" % spec["name_arg"])
        if native is None:
            problems.append("argument %d (function) was not a constant" % spec["fn_arg"])
        row = {"index": number, "site": site.get("site"), "script_name": name, "argc": argc,
               "native_rva": _site(native) if native is not None else None,
               "native_va": "va:%#x" % (memory.base + native) if native is not None and memory is not None else None,
               "source": "call to %s at %s" % (spec["id"], site.get("site")),
               "status": "unresolved" if problems else "resolved"}
        if problems:
            row["unresolved"] = problems
        rows.append(row)
    return {"binding": spec["id"], "kind": "call", "rows": rows, "ended": "sites"}


def resolve_thunks(memory, rows: list[dict]) -> list[dict]:
    """Follow a native pointer that is a one-instruction thunk (`jmp rel32`, `jmp [rip+disp32]`) to its implementation.

    The row keeps the thunk as `native_rva` and gains `implementation_rva` and `thunk` = true. Anything else is its own
    implementation."""
    out = []
    for row in rows:
        row = dict(row)
        if row.get("native_rva"):
            rva = int(row["native_rva"][4:], 16)
            try:
                head = memory.read_rva(rva, 6)
            except (ValueError, OSError):
                head = b""
            target = None
            if head[:1] == b"\xe9" and len(head) >= 5:
                target = rva + 5 + struct.unpack("<i", head[1:5])[0]
            elif head[:2] == b"\xff\x25" and len(head) >= 6:
                slot = rva + 6 + struct.unpack("<i", head[2:6])[0]
                target = _rva_of(memory, _pointer(memory, slot, 8), 8)
            if target is not None and target > 0:
                row.update(thunk=True, implementation_rva=_site(target))
            else:
                row.update(thunk=False, implementation_rva=row["native_rva"])
        out.append(row)
    return out


def collect(memory, specs: list[dict], call_sites: dict[str, list[dict]] | None = None) -> dict:
    """All the profile's bindings as one table, thunks resolved, with counts and the unresolved rows separated."""
    tables, rows = [], []
    for spec in specs:
        if spec["kind"] == "table":
            found = extract_table(memory, spec)
        else:
            found = bindings_from_call_sites(spec, (call_sites or {}).get(spec["id"], []), memory)
        found["rows"] = resolve_thunks(memory, found["rows"])
        for row in found["rows"]:
            row["binding"] = spec["id"]
        tables.append({key: found[key] for key in ("binding", "kind", "ended")} | {"rows": len(found["rows"])})
        rows += found["rows"]
    names: dict = {}
    for row in rows:
        if row.get("script_name"):
            names.setdefault(row["script_name"], []).append(row)
    duplicates = {name: [r["source"] for r in group] for name, group in sorted(names.items())
                  if len({r.get("implementation_rva") for r in group}) > 1}
    resolved = [row for row in rows if row["status"] == "resolved"]
    return {"tables": tables, "rows": rows, "counts": {"rows": len(rows), "resolved": len(resolved),
                                                         "unresolved": len(rows) - len(resolved)},
            "conflicting_names": duplicates}


def _identifier(name: str) -> str:
    cleaned = _IDENT.sub("_", name)
    return ("_" + cleaned) if cleaned[:1].isdigit() else cleaned


def to_corpus(table: dict, *, build_sha256: str, source: str, prefix: str = "vm_native_") -> tuple[list[dict], dict]:
    """(corpus records, binding table). The records are type-corpus `function` rows (docs/type-corpus.md): the native
    function named after its script name, typed by its parameter count, with a comment that cites the registration. The
    binding table is the cited whole (it carries the build hash and a content hash), so an import is replayable."""
    records = []
    for row in table["rows"]:
        if row["status"] != "resolved":
            continue
        address = row.get("implementation_rva") or row["native_rva"]
        params = ", ".join("undefined8 arg%d" % index for index in range(row["argc"])) if isinstance(row.get("argc"), int) else "..."
        name = prefix + _identifier(row["script_name"])
        records.append({"kind": "function", "address": address, "name": name,
                        "signature": "undefined8 %s(%s)" % (name, params),
                        "comment": "script native %r, %s parameter(s); cited: %s" % (
                            row["script_name"], row["argc"] if row.get("argc") is not None else "unknown", row["source"])})
    body = {"format": "hydralysis.script-bindings/1", "build_sha256": build_sha256, "source": source,
            "rows": [{key: row.get(key) for key in ("binding", "script_name", "argc", "native_rva", "implementation_rva", "thunk",
                                                    "site", "source", "status", "unresolved")} for row in table["rows"]],
            "counts": table["counts"]}
    body["content_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return records, body


def cross_layer_edges(table: dict) -> list[dict]:
    """script function -> native thunk -> implementation, as cited static edges (not observed calls)."""
    edges = []
    for row in table["rows"]:
        if row["status"] != "resolved":
            continue
        chain = ["script:%s" % row["script_name"], row["native_rva"]]
        if row.get("thunk"):
            chain.append(row["implementation_rva"])
        edges.append({"relation": "script-binding", "status": "supported", "path": chain, "argc": row.get("argc"),
                      "basis": [row["source"]]})
    return edges


def link_events(events: list[dict], table: dict, *, window: int = 8) -> dict:
    """Trace use: link each script-VM event to the native function event it invoked.

    A VM event carries `payload.script_function` (the name the script called). The invoked native is the first
    `core.function.enter` on the same thread generation, after it in the thread's own order, within WINDOW events, whose
    `va` (as an RVA relative to `rva_base`, or the symbolized `function`) is the bound thunk or implementation. The link is
    an `observed-call` relation with basis `binding-table`; a script call whose native was not seen is listed as
    `unlinked`, never dropped."""
    by_name: dict = {}
    for row in table["rows"]:
        if row["status"] == "resolved":
            by_name.setdefault(row["script_name"], set()).update(
                {int(row["native_rva"][4:], 16), int((row.get("implementation_rva") or row["native_rva"])[4:], 16)})
    ordered = sorted((e for e in events if e.get("seq") is not None), key=lambda e: (str(e.get("thread_gen")), e["seq"]))
    links, unlinked = [], []
    for position, event in enumerate(ordered):
        name = (event.get("payload") or {}).get("script_function")
        if not name:
            continue
        wanted = by_name.get(name)
        if wanted is None:
            unlinked.append({"event_id": event.get("event_id"), "script_function": name, "reason": "not in the binding table"})
            continue
        found = None
        for follower in ordered[position + 1: position + 1 + window]:
            if follower.get("thread_gen") != event.get("thread_gen"):
                continue
            rva = follower.get("rva")
            if follower.get("kind") == "core.function.enter" and (rva in wanted):
                found = follower
                break
        if found is None:
            unlinked.append({"event_id": event.get("event_id"), "script_function": name, "reason": "no matching native entry within "
                             "%d events on the same thread (not observed, or not instrumented)" % window})
        else:
            links.append({"relation": "observed-call", "status": "supported", "from": event.get("event_id"), "to": found.get("event_id"),
                          "script_function": name, "basis": ["binding-table", "same thread order"]})
    return {"links": links, "unlinked": unlinked}
