"""Turn bytes a probe captured into values, outside the target process.

A probe only copies bounded bytes (an argument, or what it points to through a
chain of pointer reads, each checked against a readable range); everything
here runs in the worker, so a bad layout can never fault the target.

capture spec: {"arg": 0..7 | "reg": register name, "deref": [offsets]?, "size": 1..4096?, "as": decoder, "names": {hash: name}?}
decoders: utf8, utf16 (NUL-terminated, bounded by size), hex, i8..u64, f32, f64, pointer,
struct (with "fields": [{name, offset, type, size?}] of the same scalar types).
"""

from __future__ import annotations

import re
import struct

SCALARS = {"i8": ("<b", 1), "u8": ("<B", 1), "i16": ("<h", 2), "u16": ("<H", 2), "i32": ("<i", 4),
           "u32": ("<I", 4), "i64": ("<q", 8), "u64": ("<Q", 8), "f32": ("<f", 4), "f64": ("<d", 8),
           "pointer": ("<Q", 8), "bool": ("<?", 1)}
# Common spellings from type corpora and Ghidra.
ALIASES = {"int8": "i8", "uint8": "u8", "byte": "u8", "char": "i8", "int16": "i16", "short": "i16", "uint16": "u16",
           "int32": "i32", "int": "i32", "uint32": "u32", "uint": "u32", "int64": "i64", "longlong": "i64",
           "uint64": "u64", "ulonglong": "u64", "float": "f32", "double": "f64", "bool": "bool",
           "undefined1": "u8", "undefined2": "u16", "undefined4": "u32", "undefined8": "u64", "word": "u16",
           "dword": "u32", "qword": "u64", "long": "i32", "ulong": "u32", "ushort": "u16", "uchar": "u8"}
TEXT = ("utf8", "utf16", "hex")
MAX_CAPTURES = 4


def scalar(name: str) -> str | None:
    name = name.strip()
    if name.endswith("*"):
        return "pointer"
    name = ALIASES.get(name, name)
    return name if name in SCALARS else None


def normalize(captures) -> list[dict]:
    if captures is None:
        return []
    if not isinstance(captures, list) or len(captures) > MAX_CAPTURES:
        raise ValueError("capture must be a list of at most %d argument captures" % MAX_CAPTURES)
    clean = []
    for index, item in enumerate(captures):
        if not isinstance(item, dict) or set(item) - {"arg", "reg", "deref", "size", "as", "fields", "names", "label"}:
            raise ValueError("capture %d accepts arg or reg, deref, size, as, fields, names, label" % index)
        arg, reg = item.get("arg"), item.get("reg")
        if reg is not None:
            # A register by name (ecx for a 32-bit thiscall `this`, rax, ...); the probe refuses a name
            # the target's architecture does not have.
            if arg is not None or not isinstance(reg, str) or not re.fullmatch(r"[a-z][a-z0-9]{1,4}", reg):
                raise ValueError("capture %d: reg is one register name (e.g. ecx, rdx), instead of arg" % index)
        elif isinstance(arg, bool) or not isinstance(arg, int) or not 0 <= arg <= 7:
            raise ValueError("capture %d needs arg 0..7 or reg" % index)
        deref = item.get("deref", [])
        if not isinstance(deref, list) or len(deref) > 4 or any(isinstance(x, bool) or not isinstance(x, int) or not 0 <= x < 1 << 20 for x in deref):
            raise ValueError("capture %d deref is up to 4 offsets: read a pointer at each" % index)
        kind = str(item.get("as", "hex"))
        fields = []
        if kind == "struct":
            for field in item.get("fields") or []:
                if not isinstance(field, dict) or not isinstance(field.get("name"), str) or scalar(str(field.get("type", ""))) is None:
                    raise ValueError("capture %d struct fields need name, offset and a scalar type" % index)
                fields.append({"name": field["name"], "offset": int(field.get("offset", 0)), "type": scalar(field["type"])})
            if not fields:
                raise ValueError("capture %d struct needs fields" % index)
            needed = max(field["offset"] + SCALARS[field["type"]][1] for field in fields)
        elif kind in TEXT:
            needed = 0
        elif scalar(kind):
            kind = scalar(kind)
            needed = SCALARS[kind][1]
        else:
            raise ValueError("capture %d: unknown decoder %s" % (index, kind))
        size = int(item.get("size", needed or 256))
        if not needed <= size <= 4096 or size < 1:
            raise ValueError("capture %d size must be 1..4096 and cover its decoder" % index)
        names = item.get("names") or {}
        if not isinstance(names, dict) or len(names) > 100000:
            raise ValueError("capture %d names maps values to names" % index)
        clean.append({"arg": arg, "reg": reg, "deref": deref, "size": size, "as": kind, "fields": fields,
                      "names": {str(int(str(key), 0)): str(value) for key, value in names.items()},
                      "label": str(item.get("label", ""))[:64], "value_only": not deref and kind in SCALARS and size <= 8})
    return clean


def _unpack(kind: str, data: bytes, offset: int = 0):
    form, size = SCALARS[kind]
    if kind == "pointer" and len(data) - offset == 4:
        form = "<I"  # a 32-bit target's pointer (the probe copies the target's pointer width)
    value = struct.unpack_from(form, data, offset)[0]
    return hex(value) if kind == "pointer" else value


def decode(spec: dict, data: bytes):
    """One captured buffer as its declared value."""
    kind = spec["as"]
    if kind == "utf8":
        return data.split(b"\0", 1)[0].decode("utf-8", "replace")
    if kind == "utf16":
        cut = next((index for index in range(0, len(data) - 1, 2) if data[index:index + 2] == b"\0\0"), len(data) - len(data) % 2)
        return data[:cut].decode("utf-16-le", "replace")
    if kind == "hex":
        return data.hex(" ").upper()
    if kind == "struct":
        return {field["name"]: _unpack(field["type"], data, field["offset"]) for field in spec["fields"]
                if field["offset"] + SCALARS[field["type"]][1] <= len(data)}
    value = _unpack(kind, data)
    if spec["names"]:
        key = str(int(value, 16) if isinstance(value, str) else value)
        return {"value": value, "name": spec["names"].get(key)}
    return value


def decode_event(specs: list[dict], captures: list) -> list[dict]:
    out = []
    for spec, captured in zip(specs, captures or []):
        row = {**({"reg": spec["reg"]} if spec.get("reg") else {"arg": spec["arg"]}),
               **({"label": spec["label"]} if spec["label"] else {})}
        if not isinstance(captured, dict) or captured.get("error"):
            row["error"] = (captured or {}).get("error", "not captured")
        else:
            row["pointer"] = captured.get("pointer")
            try:
                row["value"] = decode(spec, bytes.fromhex(captured.get("hex", "")))
            except (ValueError, struct.error) as exc:
                row["error"] = "decode: %s" % exc
        out.append(row)
    return out


def layout_values(fields: list[dict], data: bytes) -> list[dict]:
    """A typed live read: each field of a layout from the bytes read at its object."""
    rows = []
    for field in fields:
        kind = scalar(str(field.get("type", "")))
        offset, size = int(field["offset"]), int(field.get("size") or (SCALARS[kind][1] if kind else 0))
        row = {"name": field.get("name"), "offset": hex(offset), "type": field.get("type")}
        chunk = data[offset:offset + size]
        if field.get("enum"):
            row["type"] = field["enum"]
        if kind and len(chunk) >= SCALARS[kind][1]:
            row["value"] = _unpack(kind, chunk)
            names = field.get("names")
            if isinstance(names, dict):
                row["name"] = names.get(str(row["value"]), "(no member %s)" % row["value"])
        else:
            row["bytes"] = chunk.hex(" ").upper()
        rows.append(row)
    return rows


# ---- optional Rust implementation (HYDRALYSIS_IMPL=rust) ------------------------------------------------------------------
# crates/hy-runtime `decode` (the pure pieces), bound in crates/hy-rt-py (`hydralysis_rt`), which reads the specs and captures
# straight from the Python objects and builds the answers as Python lists and dicts (no JSON text, no intermediate document).
# The functions above stay the specification: the Rust ones give the same value, with the same key order, for the shapes the
# worker and the MCP layer produce and raise `Unmodelled` for any other (a float where Python calls int(), a negative struct
# offset, a tuple, a subclass, ...), which runs the Python. A ValueError is Python's own, same text.
# Measured against the Python in benchmarks/bench_runtime_decode.py (see rust/crates/hy-runtime/PORTING.md for the table).

_normalize_py, _decode_py, _decode_event_py, _layout_values_py = normalize, decode, decode_event, layout_values


def _install_rust() -> None:
    import os
    import sys
    if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() != "rust":
        return
    try:
        from hydralysis import rust_frida
        rt = rust_frida._load_rt()
        routines = (rt.decode_normalize, rt.decode_value, rt.decode_event, rt.decode_layout_values, rt.Unmodelled)
    except Exception:  # noqa: BLE001 - no Rust runtime built: the Python stays
        return
    from hydralysis._seams import Seam
    module = sys.modules[__name__]
    seam = Seam((module, "scalar"), (module, "_unpack"), (module, "SCALARS"), (struct, "unpack_from"))
    patched = seam.active
    unmodelled = rt.Unmodelled

    def routed(rust_function, python_function):
        # One frame per call: the seam check, the Rust call, and the Python function for a patched seam or an unmodelled shape.
        def call(*args):
            if patched():
                return python_function(*args)
            try:
                return rust_function(*args)
            except unmodelled:
                return python_function(*args)

        call.__name__ = python_function.__name__
        call.__qualname__ = python_function.__qualname__
        call.__doc__ = python_function.__doc__
        call.python_function = python_function
        call.rust_function = rust_function
        return call

    module.normalize = routed(routines[0], _normalize_py)
    module.decode = routed(routines[1], _decode_py)
    module.decode_event = routed(routines[2], _decode_event_py)
    module.layout_values = routed(routines[3], _layout_values_py)


_install_rust()
