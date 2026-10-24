"""One dispatch table for the CLI and the MCP server."""

from __future__ import annotations

from pathlib import Path

from rusticre import __version__
from rusticre.catalog import games_text, systems_text
from rusticre.config import evidence_path, load
from rusticre.evidence import add_claim, list_claims
from rusticre.ghidra import GhidraRunner
from rusticre.pe import Image, parse_rva
from rusticre.prologue import compare
from rusticre.red4ext import lookup_hashes, lookup_rvas

TOOL_NAMES = (
    "fingerprint",
    "disasm",
    "xrefs",
    "callers",
    "funcof",
    "bytes",
    "strings",
    "prologue",
    "hash",
    "addr",
    "evidence_add",
    "evidence_list",
    "ghidra_run",
    "ghidra_scripts",
    "ghidra_lanes",
    "ghidra_jobs",
    "systems",
    "games",
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
    return [
        tool("fingerprint", "Build identity of an exe: size, timestamp, sha256, version.", {"exe": string}, ["exe"]),
        tool("disasm", "Disassemble at an RVA or VA. Rip-relative operands show their target string.", {
            "exe": string, "address": string, "count": integer,
        }, ["exe", "address"]),
        tool("xrefs", "Who points at an address. 64-bit rip-relative, 32-bit absolute.", {
            "exe": string, "address": string, "limit": integer,
        }, ["exe", "address"]),
        tool("callers", "Direct E8/E9 sites that land on an address.", {
            "exe": string, "address": string, "limit": integer,
        }, ["exe", "address"]),
        tool("funcof", "The pdata function that contains an address, and its first 32 bytes.", {
            "exe": string, "address": string,
        }, ["exe", "address"]),
        tool("bytes", "Raw bytes at an address, for an expect prologue.", {
            "exe": string, "address": string, "size": integer,
        }, ["exe", "address"]),
        tool("strings", "Printable strings in the exe matching a regular expression.", {
            "exe": string, "pattern": string, "limit": integer,
        }, ["exe", "pattern"]),
        tool("prologue", "Compare bytes at an address with an expect prologue. ?? is a wildcard.", {
            "exe": string, "address": string, "expect": string,
        }, ["exe", "address", "expect"]),
        tool("hash", "RED4ext address-table hash to segment and RVA. Pass the json path or an exe whose folder contains it.", {
            "table": string, "hashes": {"type": "array", "items": string},
        }, ["hashes"]),
        tool("addr", "RVA to RED4ext hash. Segment 0001 only.", {
            "table": string, "addresses": {"type": "array", "items": string},
        }, ["addresses"]),
        tool("evidence_add", "Store one proved claim. note and source are required.", {
            "game": string, "build": string, "kind": string, "name": string,
            "note": string, "source": string, "address": string, "prologue": string, "db": string,
        }, ["game", "build", "kind", "name", "note", "source"]),
        tool("evidence_list", "List stored claims, newest first.", {
            "game": string, "limit": integer, "db": string,
        }),
        tool("ghidra_run", "Run one Ghidra script on a read-only copy of an analysed project. Does not re-import the exe.", {
            "game": string, "script": string,
            "args": {"type": "array", "items": string},
            "timeout_s": integer, "lane": string,
        }, ["game", "script"]),
        tool("ghidra_scripts", "List Ghidra scripts configured for a game.", {"game": string, "filter": string}, ["game"]),
        tool("ghidra_lanes", "List project copies for a game.", {"game": string}, ["game"]),
        tool("ghidra_jobs", "Recent Ghidra script runs.", {"limit": integer}),
        tool("systems", "Co-op systems and mod-compatibility targets.", {"game": string}),
        tool("games", "The three games this toolkit is for.", {}),
    ]


def call(name: str, args: dict | None) -> str:
    args = args or {}
    if name not in TOOL_NAMES:
        raise ValueError("unknown tool %s" % name)
    if name == "fingerprint":
        return _image(args).header()
    if name == "disasm":
        image = _image(args)
        return image.disasm(_addr(image, args), int(args.get("count") or 40))
    if name == "xrefs":
        image = _image(args)
        return image.xrefs(_addr(image, args), int(args.get("limit") or 40))
    if name == "callers":
        image = _image(args)
        return image.callers(_addr(image, args), int(args.get("limit") or 50))
    if name == "funcof":
        image = _image(args)
        return image.function_of(_addr(image, args))
    if name == "bytes":
        image = _image(args)
        size = int(args.get("size") or 32)
        data = image.read_rva(_addr(image, args), size)
        return image.header() + "\n" + " ".join("%02X" % byte for byte in data)
    if name == "strings":
        return _image(args).find_strings(str(args.get("pattern") or ""), int(args.get("limit") or 30))
    if name == "prologue":
        image = _image(args)
        data = image.read_rva(_addr(image, args), 64)
        return image.header() + "\n" + compare(data, str(args["expect"]))
    if name == "hash":
        wanted = {int(str(item), 0) for item in _list(args.get("hashes"))}
        return "\n".join(lookup_hashes(_table(args), wanted)) or "(no match)"
    if name == "addr":
        image_base = 0x140000000
        rvas = {parse_rva(item, image_base) for item in _list(args.get("addresses"))}
        return "\n".join(lookup_rvas(_table(args), rvas)) or "(no match)"
    if name == "evidence_add":
        return add_claim(
            evidence_path(str(args.get("db") or "")),
            game=str(args.get("game") or ""),
            build=str(args.get("build") or ""),
            kind=str(args.get("kind") or ""),
            name=str(args.get("name") or ""),
            note=str(args.get("note") or ""),
            source=str(args.get("source") or ""),
            address=str(args.get("address") or ""),
            prologue=str(args.get("prologue") or ""),
        )
    if name == "evidence_list":
        return list_claims(evidence_path(str(args.get("db") or "")), str(args.get("game") or ""), int(args.get("limit") or 50))
    if name == "ghidra_run":
        return _ghidra().run(
            str(args.get("game") or ""),
            str(args.get("script") or ""),
            [str(item) for item in _list(args.get("args"))],
            int(args.get("timeout_s") or 600),
            str(args.get("lane") or ""),
        )
    if name == "ghidra_scripts":
        return _ghidra().list_scripts(str(args.get("game") or ""), str(args.get("filter") or ""))
    if name == "ghidra_lanes":
        return _ghidra().list_lanes(str(args.get("game") or ""))
    if name == "ghidra_jobs":
        return _ghidra().jobs(int(args.get("limit") or 10))
    if name == "systems":
        return systems_text(str(args.get("game") or ""))
    if name == "games":
        return games_text()
    raise ValueError("unknown tool %s" % name)


def instructions() -> str:
    return (
        "RusticRE %s. Eighteen tools for an exe you own: disassembly, xrefs, callers, "
        "pdata, RED4ext hashes, an evidence ledger, and a read-only Ghidra script on a "
        "copy of an analysed project. Do not re-import the binary. Store proved names "
        "with evidence_add. systems lists the co-op and mod-compatibility targets."
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
    return parse_rva(str(args["address"]), image.base)


def _list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    return list(value)


def _table(args: dict) -> Path:
    if args.get("table"):
        path = Path(str(args["table"]))
    else:
        exe = args.get("exe") or os_exe()
        if not exe:
            raise ValueError("pass table, or exe next to cyberpunk2077_addresses.json")
        path = Path(str(exe)).parent / "cyberpunk2077_addresses.json"
    if not path.is_file():
        raise ValueError("address table not found: %s" % path)
    return path


def _ghidra() -> GhidraRunner:
    settings = load()
    if not settings.get("root") or not settings.get("ghidra_dir"):
        raise ValueError("set RUSTICRE_CONFIG to a json file with root and ghidra_dir")
    return GhidraRunner(settings)
