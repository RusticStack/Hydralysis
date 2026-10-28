"""Cold-start breakdown of the first query (row C2-51: 7.6 s, undecomposed).

    python benchmarks/bench_cold_start.py --engine <dir> --client <ghidra_session.py> --root <fresh folder> --out <logs> --runs 5

Each run starts with no daemon of this measurement's own root (it is stopped first) and times: the MCP server start to
its `initialize` reply, the first tool call that needs the engine (which starts the daemon, opens the project and the
program: `ghidra_query status`), and the first decompile after it. The OS file cache is not dropped (that needs
administrator rights this script will not take); the report says `cold_os_cache: false`, and the first run after a
reboot is the owner's to mark.
"""

from __future__ import annotations

import argparse
import json
import shutil
import time

import mcp_latency as common


def one_run(settings: dict, root, address: str) -> dict:
    common.stop_engine(settings)
    time.sleep(1)
    started = time.perf_counter()
    client = common.McpClient(common.write_config(root, settings), settings["root"])
    try:
        init = client.initialize()
        _, status_s, _ = client.tool("ghidra_query", {"target": "fixture", "action": "status"}, timeout=600)
        _, decompile_s, _ = client.tool("ghidra_query", {"target": "fixture", "action": "decompile", "address": address}, timeout=600)
        _, again_s, _ = client.tool("ghidra_query", {"target": "fixture", "action": "decompile", "address": address}, timeout=600)
        total = time.perf_counter() - started
    finally:
        client.close()
    return {"mcp_start_to_initialize_s": round(init, 3), "first_engine_call_s": round(status_s, 3),
            "first_decompile_s": round(decompile_s, 3), "second_decompile_s": round(again_s, 3), "total_s": round(total, 3)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.common_arguments(parser)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args(argv)
    common.require_engine(args)
    binary = common.default_binary(args.binary)
    root = common.fresh_root(args, "cold")
    out = common.output_dir(args.out)
    settings = common.settings_of(args, root)
    scratch = root / "fixture.exe"
    shutil.copy2(binary, scratch)
    report = {"script": "bench_cold_start", "rows": ["C2-51"], "engine": common.engine_facts(args), "machine": common.machine(),
              "program_sha256": common.sha256_of(scratch), "program": binary.name, "file_system": common.file_system(root),
              "cold_os_cache": False, "load_before": common.foreign_load(), "runs": []}
    try:
        runner, _ = common.prepare(settings, scratch, "fixture")
        address = common.sized_functions(runner, "fixture", 50)[0]["address"]
        for _ in range(args.runs):
            report["runs"].append(one_run(settings, root, address))
        report["summary"] = {key: common.summarize([r[key] for r in report["runs"]])
                             for key in ("mcp_start_to_initialize_s", "first_engine_call_s", "first_decompile_s", "total_s")}
        report["budget"] = common.judge("bench_cold_start.total_s.median", report["summary"]["total_s"]["median"])
    finally:
        report["load_after"] = common.foreign_load()
        try:
            common.stop_engine(settings)
        except Exception as exc:
            report["stop_error"] = str(exc)[:300]
        path = common.write_report(out, "bench_cold_start", report)
        print(json.dumps({"report": str(path), "summary": report.get("summary")}, indent=2))
        common.cleanup(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
