"""Warm MCP call latency through the real stdio server (rows C1-02, C1-03, C1-15 reply sizes).

    python benchmarks/mcp_latency.py --engine <dir> --client <ghidra_session.py> --root <fresh folder> --out <logs> --runs 30

Spawns `python -m hydralysis mcp` against a prepared target (the default fixture is the system whoami.exe; pass a COPY
of the real program with --binary for the owner's figure), discards warm-up calls, then makes at least 30 warm calls
each of `function` (offline PE tool), `ghidra_query` decompile of one pinned function and `ghidra_query` status. Records
median, p95 and maximum in milliseconds, the reply size in bytes, the function address and size, the engine release,
the program SHA-256, the file system and the foreign load. Budgets are report-only.
"""

from __future__ import annotations

import argparse
import json
import shutil

import bench_common as common

WARMUP = 3


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.common_arguments(parser)
    parser.add_argument("--runs", type=int, default=30, help="warm calls per tool (the spec asks for at least 30)")
    parser.add_argument("--function", help="address of the pinned function (default: the largest of the first 200)")
    args = parser.parse_args(argv)
    common.require_engine(args)
    binary = common.default_binary(args.binary)
    root = common.fresh_root(args, "mcplat")
    out = common.output_dir(args.out)
    settings = common.settings_of(args, root)
    scratch = root / "fixture.exe"
    shutil.copy2(binary, scratch)
    report = {"script": "mcp_latency", "rows": ["C1-02", "C1-03", "C1-15"], "engine": common.engine_facts(args),
              "machine": common.machine(), "program_sha256": common.sha256_of(scratch), "program": binary.name,
              "file_system": common.file_system(root), "runs": args.runs, "warmup_discarded": WARMUP,
              "load_before": common.foreign_load(), "tools": {}}
    client = None
    try:
        runner, _ = common.prepare(settings, scratch, "fixture")
        functions = common.sized_functions(runner, "fixture")
        pinned = next((f for f in functions if f["address"] == args.function), None) if args.function else functions[0]
        if pinned is None:
            raise SystemExit("function %s is not in the first 200 functions" % args.function)
        report["pinned_function"] = pinned
        client = common.McpClient(common.write_config(root, settings), settings["root"])
        report["initialize_s"] = round(client.initialize(), 3)
        calls = {
            "function": ("function", {"exe": str(scratch), "address": pinned["address"]}),
            "ghidra_query.decompile": ("ghidra_query", {"target": "fixture", "action": "decompile", "address": pinned["address"]}),
            "ghidra_query.status": ("ghidra_query", {"target": "fixture", "action": "status"}),
        }
        budgets = common.load_budgets()
        for label, (tool, arguments) in calls.items():
            errors = 0
            for _ in range(WARMUP):
                client.tool(tool, arguments)
            times, sizes = [], []
            for _ in range(args.runs):
                reply, seconds, size = client.tool(tool, arguments)
                if (reply.get("result") or {}).get("isError") or "error" in reply:
                    errors += 1
                times.append(seconds * 1000)
                sizes.append(size)
            stats = common.summarize(times)
            report["tools"][label] = {"ms": stats, "reply_bytes": common.summarize(sizes), "errors": errors,
                                      "budget": common.judge("mcp_latency.%s.median_ms" % label, stats["median"], budgets)}
        # C1-03: 20 serial decompiles of the pinned function by one client (the owner's 896 ms had no stated function size).
        serial = []
        for _ in range(20):
            _, seconds, _ = client.tool("ghidra_query", {"target": "fixture", "action": "decompile", "address": pinned["address"]})
            serial.append(seconds * 1000)
        report["serial_20_decompiles"] = {"total_ms": round(sum(serial), 1), "per_call_ms": round(sum(serial) / 20, 2),
                                          "function": pinned}
    finally:
        report["load_after"] = common.foreign_load()
        if client:
            client.close()
        try:
            common.stop_engine(settings)
        except Exception as exc:
            report["stop_error"] = str(exc)[:300]
        path = common.write_report(out, "mcp_latency", report)
        print(json.dumps({"report": str(path), "tools": {k: v["ms"] for k, v in report["tools"].items()}}, indent=2))
        common.cleanup(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
