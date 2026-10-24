"""One dispatch table for the CLI and the MCP server."""

from __future__ import annotations

import json
from pathlib import Path

from rusticre import __version__
from rusticre.config import evidence_path, load
from rusticre.evidence import add_claim, list_claims
from rusticre.ghidra import GhidraRunner
from rusticre.pe import Image, parse_rva
from rusticre.prologue import compare
from rusticre.query import QueryRunner

# Chosen from what agents actually called, mapped onto generic operations.
# REA's function dossier -> inspect. Ghidra decompile/xrefs/bytes -> the
# matching tools plus ghidra_run. Hook work -> sigscan and prologue.
# Android, browser, firmware and the rest of REA are not registered.
TOOL_NAMES = (
    "fingerprint",
    "sections",
    "imports",
    "exports",
    "disasm",
    "inspect",
    "xrefs",
    "callers",
    "callees",
    "function",
    "bytes",
    "strings",
    "sigscan",
    "prologue",
    "evidence_add",
    "evidence_list",
    "ghidra_run",
    "ghidra_scripts",
    "ghidra_query",
    "ghidra_jobs",
)

# Names that must never appear. They are the REA surface this server exists to avoid.
REJECTED = (
    "adb",
    "android",
    "apk",
    "browser",
    "electron",
    "firmware",
    "frida",
    "hopper",
    "jeb",
    "objc",
    "swift",
)


def tool_table() -> list[dict]:
    def tool(name: str, description: str, properties: dict, required: list[str] | None = None) -> dict:
        schema: dict = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        return {"name": name, "description": description, "inputSchema": schema}

    string = {"type": "string"}
    integer = {"type": "integer"}
    pe_address = {"type": "string", "description": "Use rva:0x... or va:0x...; ambiguous unprefixed addresses are refused."}
    return [
        tool("fingerprint", "Build identity of a PE: size, timestamp, sha256, version, image base.", {"exe": string}, ["exe"]),
        tool("sections", "Section names, RVAs, sizes and execute/read/write flags.", {"exe": string}, ["exe"]),
        tool("imports", "Imported DLL symbols.", {"exe": string, "limit": integer}, ["exe"]),
        tool("exports", "Exported symbols and their RVAs.", {"exe": string, "limit": integer}, ["exe"]),
        tool("disasm", "Disassemble at an RVA or VA. 64-bit rip-relative operands show their target.", {
            "exe": string, "address": pe_address, "count": integer,
        }, ["exe", "address"]),
        tool("inspect", "Cheap PE inspection: x64 pdata bounds, instructions, candidate callers. For analysed bounds/decompile use ghidra_query.", {
            "exe": string, "address": pe_address,
        }, ["exe", "address"]),
        tool("xrefs", "References to an address. 64-bit rip-relative LEA/MOV, 32-bit absolute.", {
            "exe": string, "address": pe_address, "limit": integer,
        }, ["exe", "address"]),
        tool("callers", "Direct E8/E9 sites in executable code that land on an address.", {
            "exe": string, "address": pe_address, "limit": integer,
        }, ["exe", "address"]),
        tool("callees", "Direct E8 calls made from the function that contains an address.", {
            "exe": string, "address": pe_address, "limit": integer,
        }, ["exe", "address"]),
        tool("function", "The pdata function that contains an address, and its first 32 bytes.", {
            "exe": string, "address": pe_address,
        }, ["exe", "address"]),
        tool("bytes", "Raw bytes at an address.", {"exe": string, "address": pe_address, "size": integer}, ["exe", "address"]),
        tool("strings", "Printable strings matching a regular expression.", {
            "exe": string, "pattern": string, "limit": integer,
        }, ["exe", "pattern"]),
        tool("sigscan", "Find a byte pattern in executable sections. ?? is a wildcard. Use this to locate a hook site.", {
            "exe": string, "pattern": string, "limit": integer,
        }, ["exe", "pattern"]),
        tool("prologue", "Compare bytes at an address with an expect prologue. Refuse a hook when this mismatches.", {
            "exe": string, "address": pe_address, "expect": string,
        }, ["exe", "address", "expect"]),
        tool("evidence_add", "Store one proved claim. note and source are required. target is any name you give this binary.", {
            "target": string, "build": string, "kind": string, "name": string,
            "note": string, "source": string, "address": string, "prologue": string, "db": string,
        }, ["target", "build", "kind", "name", "note", "source"]),
        tool("evidence_list", "List stored claims, newest first.", {"target": string, "limit": integer, "db": string}),
        tool("ghidra_run", "Run one Ghidra script on a read-only copy of an already analysed project. Does not re-import the binary.", {
            "target": string, "script": string,
            "args": {"type": "array", "items": string},
            "timeout_s": integer, "lane": string,
        }, ["target", "script"]),
        tool("ghidra_scripts", "List Ghidra scripts for a configured target.", {"target": string, "filter": string}, ["target"]),
        tool("ghidra_query", "Decompile or query an already analysed read-only project in a reusable JVM. Numeric VAs only, no name enumeration. functions pages via next_cursor. status/stop manage the worker. Verify exe/sha256 in target config.", {
            "target": string,
            "action": {"type": "string", "enum": ["decompile", "function", "functions", "xrefs", "status", "stop"]},
            "address": string, "limit": integer, "cursor": string, "contains": string, "timeout_s": integer,
        }, ["target"]),
        tool("ghidra_jobs", "Recent Ghidra script runs.", {"limit": integer}),
    ]


def call(name: str, args: dict | None) -> str:
    args = args or {}
    if name not in TOOL_NAMES:
        raise ValueError("unknown tool %s" % name)
    for key, maximum in (("limit", 200), ("count", 200), ("size", 65536)):
        if key in args and (isinstance(args[key], bool) or not 1 <= int(args[key]) <= maximum):
            raise ValueError("%s must be 1..%d" % (key, maximum))
    if name == "fingerprint":
        image = _image(args)
        return image.header() + "\n" + json.dumps(image.fingerprint(), indent=2)
    if name == "sections":
        return _image(args).sections_text()
    if name == "imports":
        return _image(args).imports_text(int(args.get("limit") or 80))
    if name == "exports":
        return _image(args).exports_text(int(args.get("limit") or 80))
    if name == "disasm":
        image = _image(args)
        return image.disasm(_addr(image, args), int(args.get("count") or 40))
    if name == "inspect":
        image = _image(args)
        return image.inspect(_addr(image, args))
    if name == "xrefs":
        image = _image(args)
        return image.xrefs(_addr(image, args), int(args.get("limit") or 40))
    if name == "callers":
        image = _image(args)
        return image.callers(_addr(image, args), int(args.get("limit") or 50))
    if name == "callees":
        image = _image(args)
        return image.callees(_addr(image, args), int(args.get("limit") or 30))
    if name == "function":
        image = _image(args)
        return image.function_of(_addr(image, args))
    if name == "bytes":
        image = _image(args)
        data = image.read_rva(_addr(image, args), int(args.get("size") or 32))
        return image.header() + "\n" + " ".join("%02X" % byte for byte in data)
    if name == "strings":
        return _image(args).find_strings(str(args.get("pattern") or ""), int(args.get("limit") or 30))
    if name == "sigscan":
        return _image(args).sigscan(str(args.get("pattern") or ""), int(args.get("limit") or 20))
    if name == "prologue":
        from rusticre.prologue import parse_expect
        image = _image(args)
        expected = parse_expect(str(args["expect"]))
        if len(expected) > 4096:
            raise ValueError("expect must be at most 4096 bytes")
        data = image.read_rva(_addr(image, args), len(expected))
        result = image.header() + "\n" + compare(data, str(args["expect"]))
        if "PROLOGUE MISMATCH" in result:
            raise ValueError(result)
        return result
    if name == "evidence_add":
        return add_claim(
            evidence_path(str(args.get("db") or "")),
            game=str(args.get("target") or args.get("game") or ""),
            build=str(args.get("build") or ""),
            kind=str(args.get("kind") or ""),
            name=str(args.get("name") or ""),
            note=str(args.get("note") or ""),
            source=str(args.get("source") or ""),
            address=str(args.get("address") or ""),
            prologue=str(args.get("prologue") or ""),
        )
    if name == "evidence_list":
        return list_claims(
            evidence_path(str(args.get("db") or "")),
            str(args.get("target") or args.get("game") or ""),
            int(args.get("limit") or 50),
        )
    target = str(args.get("target") or args.get("game") or "")
    if name == "ghidra_query":
        return QueryRunner(_settings()).query(
            target, str(args.get("action") or "decompile"), str(args.get("address") or ""),
            int(args.get("limit", 40)), str(args.get("cursor") or ""), str(args.get("contains") or ""),
            int(args.get("timeout_s", 30)),
        )
    if name == "ghidra_run":
        return _ghidra().run(
            target,
            str(args.get("script") or ""),
            [str(item) for item in _list(args.get("args"))],
            int(args.get("timeout_s") or 600),
            str(args.get("lane") or ""),
        )
    if name == "ghidra_scripts":
        return _ghidra().list_scripts(target, str(args.get("filter") or ""))
    if name == "ghidra_jobs":
        return _ghidra().jobs(int(args.get("limit") or 10))
    raise ValueError("unknown tool %s" % name)


def instructions() -> str:
    return (
        "RusticRE %s. Twenty tools for any PE you own. inspect is the function "
        "picture (bounds, prologue, instructions, callers) and does not start a JVM. "
        "sigscan and prologue are how a hook site is found and checked. ghidra_run "
        "executes one script on a read-only copy of a project you already analysed. "
        "Prefer ghidra_query for bounded address-based decompilation and references; "
        "its JVM stays warm across CLI and MCP calls. Addresses there are VAs. "
        "For PE addresses use rva:0x... or va:0x... when the interpretation is ambiguous. "
        "Do not re-import the binary. evidence_add stores a claim only with a source."
        % __version__
    )


def _image(args: dict) -> Image:
    exe = args.get("exe") or os_exe()
    if not exe:
        raise ValueError("exe is required")
    path = Path(str(exe))
    if not path.is_file():
        raise ValueError("exe not found: %s" % path)
    return Image(path)


def os_exe() -> str:
    import os
    return os.environ.get("RUSTICRE_EXE", "")


def _addr(image: Image, args: dict) -> int:
    if "address" not in args:
        raise ValueError("address is required")
    text = str(args["address"]).strip()
    rva = parse_rva(text, image.base)
    if ":" not in text:
        value = int(text, 0)
        if value >= image.base:
            raw_mapped = image.rva_to_offset(value) is not None
            va_mapped = image.rva_to_offset(rva) is not None
            if raw_mapped and va_mapped:
                raise ValueError("ambiguous address %s: RVA %#x and VA %#x (RVA %#x) both map to this image; use rva:%s or va:%s"
                                 % (text, value, value, rva, text, text))
            if raw_mapped:
                return value
    return rva


def _list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    return list(value)


def _ghidra() -> GhidraRunner:
    return GhidraRunner(_settings())


def _settings() -> dict:
    settings = load()
    if not settings.get("root") or not settings.get("ghidra_dir"):
        raise ValueError("set RUSTICRE_CONFIG to a json file with root and ghidra_dir")
    return settings
