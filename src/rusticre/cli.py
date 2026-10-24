"""Command line. Every subcommand calls the same function the MCP server calls."""

from __future__ import annotations

import argparse
import sys

from rusticre.api import TOOL_NAMES, call
from rusticre.mcp import Server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rusticre", description="Reverse engineering for games you own.")
    sub = parser.add_subparsers(dest="command")

    fingerprint = sub.add_parser("fingerprint")
    fingerprint.add_argument("--exe", required=True)

    for name in ("disasm", "xrefs", "callers", "funcof", "bytes"):
        command = sub.add_parser(name)
        command.add_argument("--exe", required=True)
        command.add_argument("address")
        if name == "disasm":
            command.add_argument("--count", type=int, default=40)
        if name in ("xrefs", "callers"):
            command.add_argument("--limit", type=int, default=40)
        if name == "bytes":
            command.add_argument("--size", type=int, default=32)

    strings = sub.add_parser("strings")
    strings.add_argument("--exe", required=True)
    strings.add_argument("pattern")
    strings.add_argument("--limit", type=int, default=30)

    prologue = sub.add_parser("prologue")
    prologue.add_argument("--exe", required=True)
    prologue.add_argument("address")
    prologue.add_argument("--expect", required=True)

    hashed = sub.add_parser("hash")
    hashed.add_argument("--table")
    hashed.add_argument("--exe")
    hashed.add_argument("hashes", nargs="+")

    addr = sub.add_parser("addr")
    addr.add_argument("--table")
    addr.add_argument("--exe")
    addr.add_argument("addresses", nargs="+")

    add = sub.add_parser("evidence-add")
    for flag in ("game", "build", "kind", "name", "note", "source"):
        add.add_argument("--" + flag, required=True)
    add.add_argument("--address", default="")
    add.add_argument("--prologue", default="")
    add.add_argument("--db", default="")

    listed = sub.add_parser("evidence-list")
    listed.add_argument("--game", default="")
    listed.add_argument("--limit", type=int, default=50)
    listed.add_argument("--db", default="")

    grun = sub.add_parser("ghidra-run")
    grun.add_argument("--game", required=True)
    grun.add_argument("script")
    grun.add_argument("script_args", nargs="*")
    grun.add_argument("--timeout", type=int, default=600)
    grun.add_argument("--lane", default="")

    gscripts = sub.add_parser("ghidra-scripts")
    gscripts.add_argument("--game", required=True)
    gscripts.add_argument("--filter", default="")

    glanes = sub.add_parser("ghidra-lanes")
    glanes.add_argument("--game", required=True)

    sub.add_parser("ghidra-jobs")
    systems = sub.add_parser("systems")
    systems.add_argument("--game", default="")
    sub.add_parser("games")
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
    except (ValueError, OSError, KeyError) as exc:
        print("%s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 1


def _pair(args: argparse.Namespace) -> tuple[str, dict]:
    command = args.command.replace("-", "_")
    if command == "evidence_add":
        return command, {
            "game": args.game, "build": args.build, "kind": args.kind, "name": args.name,
            "note": args.note, "source": args.source, "address": args.address,
            "prologue": args.prologue, "db": args.db,
        }
    if command == "evidence_list":
        return command, {"game": args.game, "limit": args.limit, "db": args.db}
    if command == "ghidra_run":
        return "ghidra_run", {
            "game": args.game, "script": args.script, "args": args.script_args,
            "timeout_s": args.timeout, "lane": args.lane,
        }
    if command == "ghidra_scripts":
        return command, {"game": args.game, "filter": args.filter}
    if command == "ghidra_lanes":
        return command, {"game": args.game}
    if command == "ghidra_jobs":
        return command, {}
    if command in ("systems", "games", "fingerprint"):
        payload = {}
        if command != "games":
            if getattr(args, "game", ""):
                payload["game"] = args.game
            if getattr(args, "exe", ""):
                payload["exe"] = args.exe
        return command, payload
    if command == "strings":
        return command, {"exe": args.exe, "pattern": args.pattern, "limit": args.limit}
    if command == "hash":
        return command, {"table": args.table, "exe": args.exe, "hashes": args.hashes}
    if command == "addr":
        return command, {"table": args.table, "exe": args.exe, "addresses": args.addresses}
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
