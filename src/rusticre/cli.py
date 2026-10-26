"""Command line. Every subcommand calls the same function the MCP server calls."""

from __future__ import annotations

import argparse
import sys

from rusticre.api import TOOL_NAMES, call
from rusticre.mcp import Server
from rusticre.analysis import ADVANCED_ACTIONS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rusticre", description="Reverse engineering for a PE you own.")
    sub = parser.add_subparsers(dest="command")

    for name in ("fingerprint", "sections", "imports", "exports"):
        command = sub.add_parser(name)
        command.add_argument("--exe", required=True)
        if name in ("imports", "exports"):
            command.add_argument("--limit", type=int, default=80)
        if name == "fingerprint":
            command.add_argument("--detail", choices=("header", "sections", "exports"), default="header")

    for name in ("disasm", "inspect", "xrefs", "callers", "callees", "function", "bytes"):
        command = sub.add_parser(name)
        command.add_argument("--exe", required=True)
        command.add_argument("address", help="rva:0x... or va:0x...; unprefixed addresses must be unambiguous")
        if name == "disasm":
            command.add_argument("--count", type=int, default=40)
        if name in ("xrefs", "callers", "callees"):
            command.add_argument("--limit", type=int, default=40)
        if name == "bytes":
            command.add_argument("--size", type=int, default=32)

    for name in ("strings", "sigscan"):
        command = sub.add_parser(name)
        command.add_argument("--exe", required=True)
        command.add_argument("pattern")
        command.add_argument("--limit", type=int, default=30)

    prologue = sub.add_parser("prologue")
    prologue.add_argument("--exe", required=True)
    prologue.add_argument("address", nargs="?", help="rva:0x... or va:0x...; unprefixed addresses must be unambiguous")
    prologue.add_argument("--expect")
    prologue.add_argument("--checks-file", help="JSON array of address/expect/name rows or offset/prologue/names rows")
    prologue.add_argument("--offset-kind", choices=("rva", "va"), help="Explicit interpretation for legacy table offsets")

    add = sub.add_parser("evidence-add")
    add.add_argument("--target", required=True)
    for flag in ("build", "kind", "name", "note", "source"):
        add.add_argument("--" + flag, required=True)
    add.add_argument("--address", default="")
    add.add_argument("--prologue", default="")
    add.add_argument("--db", default="")

    listed = sub.add_parser("evidence-list")
    listed.add_argument("--target", default="")
    listed.add_argument("--limit", type=int, default=50)
    listed.add_argument("--db", default="")

    grun = sub.add_parser("ghidra-run")
    grun.add_argument("--target", required=True)
    grun.add_argument("script")
    grun.add_argument("script_args", nargs="*")
    grun.add_argument("--timeout", type=int, default=600)

    gscripts = sub.add_parser("ghidra-scripts")
    gscripts.add_argument("--target", required=True)
    gscripts.add_argument("--filter", default="")

    query = sub.add_parser("ghidra-query", help="Warm read-only Ghidra query; numeric addresses are VAs")
    query.add_argument("--target", required=True)
    query.add_argument("address", nargs="?", default="")
    query.add_argument("--action", choices=sorted({"decompile", "function", "functions", "xrefs", "status", "stop", "export"} | ADVANCED_ACTIONS), default="decompile")
    query.add_argument("--limit", type=int, default=40)
    query.add_argument("--cursor", default="")
    query.add_argument("--contains", default="")
    query.add_argument("--timeout", type=int, default=30)
    _options_arguments(query)

    backend = sub.add_parser("backend", help="Discover or privately install analysis/runtime engines")
    backend.add_argument("action", nargs="?", choices=("inspect", "install", "status", "stop", "help"), default="inspect")
    backend.add_argument("--component", choices=("analysis", "runtime"), default="analysis")

    prepare = sub.add_parser("prepare", help="Adopt an analysed project in place, or import/analyse once as a background job")
    prepare.add_argument("--exe", default="")
    prepare.add_argument("--adopt", metavar="PATH", help="Register an analysed project (.gpr, its folder or a parent) without importing or copying it")
    prepare.add_argument("--sha256", default="", help="With --adopt: the build hash, when the executable is not at hand")
    prepare.add_argument("--program", default="", help="With --adopt: the program path when the project holds several")
    prepare.add_argument("--target", default="")
    prepare.add_argument("--timeout", type=int, default=3600)
    prepare.add_argument("--install", action="store_true", help="Also download and install missing engines (about 700 MB); off by default")
    prepare.add_argument("--plan", action="store_true", help="Inspect the proposed setup/analysis without creating a job or importing")

    job = sub.add_parser("job", help="Durable setup/analysis status or cancellation")
    job.add_argument("id", nargs="?", default="")
    job.add_argument("--action", choices=("status", "cancel"), default="status")
    job.add_argument("--limit", type=int, default=20)

    runtime = sub.add_parser("runtime", help="Generic runtime debugging/instrumentation; backend help documents options")
    runtime.add_argument("action")
    _options_arguments(runtime)

    sub.add_parser("ghidra-jobs")
    sub.add_parser("tools")
    sub.add_parser("mcp")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    try:
        if args.command == "mcp":
            Server().serve()
            return 0
        if args.command == "tools":
            print("\n".join(TOOL_NAMES))
            return 0
        print(call(*_pair(args)))
        return 0
    except (ValueError, OSError, KeyError, RuntimeError) as exc:
        print("%s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 1


def _pair(args: argparse.Namespace) -> tuple[str, dict]:
    command = args.command.replace("-", "_")
    if command == "backend":
        return command, {"action": args.action, "component": args.component}
    if command == "prepare":
        if args.adopt:
            return command, {"action": "adopt", "path": args.adopt, "exe": args.exe, "sha256": args.sha256,
                             "program": args.program, "target": args.target}
        if not args.exe:
            raise ValueError("prepare needs --exe (a fresh analysis) or --adopt PATH (an analysed project)")
        return command, {"exe": args.exe, "target": args.target, "timeout_s": args.timeout, "install": args.install,
                         "action": "plan" if args.plan else "start"}
    if command == "job":
        return command, {"action": args.action, "id": args.id, "limit": args.limit}
    if command == "runtime":
        return command, {"action": args.action, "options": _options(args)}
    if command == "evidence_add":
        return command, {
            "target": args.target, "build": args.build, "kind": args.kind, "name": args.name,
            "note": args.note, "source": args.source, "address": args.address,
            "prologue": args.prologue, "db": args.db,
        }
    if command == "evidence_list":
        return command, {"target": args.target, "limit": args.limit, "db": args.db}
    if command == "ghidra_run":
        return "ghidra_run", {
            "target": args.target, "script": args.script, "args": args.script_args,
            "timeout_s": args.timeout,
        }
    if command == "ghidra_scripts":
        return command, {"target": args.target, "filter": args.filter}
    if command == "ghidra_query":
        return command, {"target": args.target, "action": args.action, "address": args.address,
                         "limit": args.limit, "cursor": args.cursor, "contains": args.contains,
                         "timeout_s": args.timeout, "options": _options(args)}
    if command == "ghidra_jobs":
        return command, {}
    if command in ("fingerprint", "sections", "imports", "exports"):
        payload = {"exe": args.exe}
        if hasattr(args, "limit"):
            payload["limit"] = args.limit
        if command == "fingerprint":
            payload["detail"] = args.detail
        return command, payload
    if command in ("strings", "sigscan"):
        return command, {"exe": args.exe, "pattern": args.pattern, "limit": args.limit}
    if command == "prologue":
        if args.checks_file:
            if args.address or args.expect:
                raise ValueError("use --checks-file or a single address/--expect pair")
            return command, {"exe": args.exe, **_checks_file(args.checks_file, args.offset_kind)}
        if not args.address or not args.expect:
            raise ValueError("prologue needs an address/--expect pair or --checks-file")
        return command, {"exe": args.exe, "address": args.address, "expect": args.expect}
    payload = {"exe": args.exe, "address": args.address}
    if hasattr(args, "count"):
        payload["count"] = args.count
    if hasattr(args, "limit"):
        payload["limit"] = args.limit
    if hasattr(args, "size"):
        payload["size"] = args.size
    return command, payload


def _json_options(value: str) -> dict:
    import json

    try:
        result = json.loads(value)
        if not isinstance(result, dict):
            raise ValueError("options must be a JSON object")
        return result
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _options_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--options", type=_json_options, default={})
    group.add_argument("--options-file", help="UTF-8 JSON object; avoids shell quoting and command length limits")


def _options(args: argparse.Namespace) -> dict:
    if not args.options_file:
        return args.options
    from pathlib import Path
    path = Path(args.options_file)
    if path.stat().st_size > 256 * 1024:
        raise ValueError("options file must be at most 256 KiB")
    try:
        return _json_options(path.read_text(encoding="utf-8-sig"))
    except argparse.ArgumentTypeError as exc:
        raise ValueError(str(exc)) from exc


def _checks_file(filename: str, offset_kind: str | None) -> dict:
    import json
    from pathlib import Path
    path = Path(filename)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("checks file must be at most 1 MiB")
    rows = json.loads(path.read_text(encoding="utf-8-sig"))
    envelope = {}
    if isinstance(rows, dict):
        envelope, rows = rows, rows.get("checks", rows.get("hooks"))
    if not isinstance(rows, list):
        raise ValueError("checks file must contain a JSON array or an object with checks[]/hooks[]")
    normalized = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("each check must be an object")
        if "offset" not in row:
            normalized.append({key: row[key] for key in ("address", "expect", "name") if key in row})
            continue
        offset = row["offset"]
        if isinstance(offset, int) and not isinstance(offset, bool):
            offset = hex(offset)
        if not isinstance(offset, str):
            raise ValueError("offset must be a number or address string")
        if not offset.startswith(("rva:", "va:")):
            if not offset_kind:
                raise ValueError("legacy offsets need --offset-kind rva or va")
            offset = offset_kind + ":" + offset
        names = row.get("names", row.get("name", ""))
        if isinstance(names, list) and all(isinstance(name, str) for name in names):
            names = ", ".join(names)
        normalized.append({"address": offset, "expect": row.get("prologue"), "name": names})
    payload = {"checks": normalized}
    if "build_sha256" in envelope:
        payload["sha256"] = envelope["build_sha256"]
    elif "sha256" in envelope:
        payload["sha256"] = envelope["sha256"]
    if "image_base" in envelope:
        payload["image_base"] = envelope["image_base"]
    return payload
