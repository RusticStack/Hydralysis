"""Command line. Every subcommand calls the same function the MCP server calls."""

from __future__ import annotations

import argparse
import sys

from rusticre.api import TOOL_NAMES, call
from rusticre.mcp import Server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rusticre", description="Reverse engineering for a PE you own.")
    sub = parser.add_subparsers(dest="command")

    for name in ("fingerprint", "sections", "imports", "exports"):
        command = sub.add_parser(name)
        command.add_argument("--exe", required=True)
        if name in ("imports", "exports"):
            command.add_argument("--limit", type=int, default=80)

    for name in ("disasm", "inspect", "xrefs", "callers", "callees", "function", "bytes"):
        command = sub.add_parser(name)
        command.add_argument("--exe", required=True)
        command.add_argument("address")
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
    prologue.add_argument("address")
    prologue.add_argument("--expect", required=True)

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
    grun.add_argument("--lane", default="")

    gscripts = sub.add_parser("ghidra-scripts")
    gscripts.add_argument("--target", required=True)
    gscripts.add_argument("--filter", default="")

    query = sub.add_parser("ghidra-query", help="Warm read-only Ghidra query; numeric addresses are VAs")
    query.add_argument("--target", required=True)
    query.add_argument("address", nargs="?", default="")
    query.add_argument("--action", choices=("decompile", "function", "functions", "xrefs", "status", "stop"), default="decompile")
    query.add_argument("--limit", type=int, default=40)
    query.add_argument("--cursor", default="")
    query.add_argument("--contains", default="")
    query.add_argument("--timeout", type=int, default=30)

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
            "timeout_s": args.timeout, "lane": args.lane,
        }
    if command == "ghidra_scripts":
        return command, {"target": args.target, "filter": args.filter}
    if command == "ghidra_query":
        return command, {"target": args.target, "action": args.action, "address": args.address,
                         "limit": args.limit, "cursor": args.cursor, "contains": args.contains,
                         "timeout_s": args.timeout}
    if command == "ghidra_jobs":
        return command, {}
    if command in ("fingerprint", "sections", "imports", "exports"):
        payload = {"exe": args.exe}
        if hasattr(args, "limit"):
            payload["limit"] = args.limit
        return command, payload
    if command in ("strings", "sigscan"):
        return command, {"exe": args.exe, "pattern": args.pattern, "limit": args.limit}
    if command == "prologue":
        return command, {"exe": args.exe, "address": args.address, "expect": args.expect}
    payload = {"exe": args.exe, "address": args.address}
    if hasattr(args, "count"):
        payload["count"] = args.count
    if hasattr(args, "limit"):
        payload["limit"] = args.limit
    if hasattr(args, "size"):
        payload["size"] = args.size
    return command, payload
