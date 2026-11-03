"""Static read plane against the engine: equality of xrefs answers and time per query, warm daemon and cold start.

Needs a Hydra Engine install (HYDRALYSIS_INTEGRATION_ENGINE / _CLIENT / _JAVA like tests/test_engine_integration.py) and
the native extension on PYTHONPATH. Runs in its own data root, with its own daemon, stopped at the end.

    python benchmarks/static_plane.py --root <scratch dir> [--queries 200] [--out result.json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
FIXTURE = REPOSITORY / "rust" / "crates" / "hy-static" / "tests" / "fixtures"
SHA = "d105b8ad8a5f549a8a2c205e95f71e1b84bcc7ec183f63ea9804442be855179b"


def oracle_targets(count):
    """Addresses with stored references (to), evenly spread, from the Java oracle output."""
    seen = []
    for line in (FIXTURE / "oracle" / "oracleprog-legacy-12.1.4-analysed.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("toref from=") and " to=ram:" in line and "kind=MemReferenceDB" in line:
            address = int(line.split(" to=ram:")[1].split(" ")[0], 16)
            if not seen or seen[-1] != address:
                seen.append(address)
    seen = sorted(set(seen))
    step = max(1, len(seen) // count)
    return seen[::step][:count]


def child(root: Path, mode: str, queries: int, engine: dict) -> dict:
    """One fresh process: build the runner, then time the first query (cold) and the next N (warm)."""
    code = r'''
import json, os, sys, time
sys.path.insert(0, os.environ["HYDRALYSIS_SRC"])
from hydralysis import query
settings = json.loads(os.environ["HYDRALYSIS_SETTINGS"])
addresses = json.loads(os.environ["HYDRALYSIS_ADDRESSES"])
t0 = time.perf_counter()
runner = query.QueryRunner(settings)
def ask(address, action="xrefs"):
    return json.loads(runner.query("flow", action, "va:0x%x" % address, limit=200, options={"view": "shared"}))
first = time.perf_counter(); r0 = ask(addresses[0]); cold = time.perf_counter() - first
times, rows = [], {}
for address in addresses:
    s = time.perf_counter(); r = ask(address); times.append(time.perf_counter() - s)
    rows[hex(address)] = [(x["from"], x["to"], x["type"]) for x in r["references"]]
modes = {ask(addresses[0])["engine"]["mode"]}
fn = []
fentries = json.loads(os.environ["HYDRALYSIS_ENTRIES"])
from hydralysis import staticplane
for address in fentries:
    s = time.perf_counter()
    if os.environ.get("HYDRALYSIS_IMPL") == "rust":
        # the plane's own entry lookup: name and flags only, NOT the engine's `function` row (no signature, no body)
        assert staticplane.call("function_at_entry", settings["targets"]["flow"]["gpr"], "/flow_fixture.exe", address)[0]
    else:
        runner.query("flow", "function", "va:0x%x" % address, options={"view": "shared"})
    fn.append(time.perf_counter() - s)
print(json.dumps({"cold_first_query_s": cold, "times": times, "rows": rows, "mode": sorted(modes), "function_times": fn}))
'''
    env = dict(os.environ)
    env.update(HYDRALYSIS_ROOT=str(root / "data"), HYDRALYSIS_SRC=str(REPOSITORY / "src"),
               HYDRALYSIS_SETTINGS=json.dumps(engine["settings"]), HYDRALYSIS_ADDRESSES=json.dumps(engine["addresses"]),
               HYDRALYSIS_ENTRIES=json.dumps(engine["entries"]))
    if mode == "rust":
        env["HYDRALYSIS_IMPL"] = "rust"
    else:
        env.pop("HYDRALYSIS_IMPL", None)
    done = subprocess.run([sys.executable, "-c", code], env={**env, "PYTHONPATH": env.get("PYTHONPATH", "")},
                          capture_output=True, text=True, timeout=900)
    if done.returncode:
        raise SystemExit("child failed: " + done.stderr[-3000:])
    return json.loads(done.stdout.strip().splitlines()[-1])


def stop_daemon(settings):
    sys.path.insert(0, str(REPOSITORY / "src"))
    from hydralysis import hydra
    engine = hydra.Engine(settings)
    try:
        engine.stop(force=True)
    finally:
        daemon = engine.module().Daemon(str(engine.engine_dir), str(hydra.state_dir(settings)), hydra.INSTANCE)
        if daemon.jvm_alive() or daemon.read_endpoint():
            daemon.kill()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--queries", type=int, default=200)
    parser.add_argument("--out", default="")
    args = parser.parse_args()
    root = Path(args.root)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    project = root / "project"
    shutil.copytree(FIXTURE / "legacy-12.1.4-analysed", project)
    settings = {"root": str(root / "data"), "hydra_dir": os.environ["HYDRALYSIS_INTEGRATION_ENGINE"],
                "hydra_client": os.environ["HYDRALYSIS_INTEGRATION_CLIENT"], "hydra_idle_s": 600,
                "hydra_allow_unpinned": True,
                "targets": {"flow": {"gpr": str(project / "legacy.gpr"), "program": "/flow_fixture.exe", "sha256": SHA}}}
    if os.environ.get("HYDRALYSIS_INTEGRATION_JAVA"):
        settings["java_home"] = os.environ["HYDRALYSIS_INTEGRATION_JAVA"]
    addresses = oracle_targets(args.queries)
    entries = [0x140001030, 0x1400010f0, 0x140001280] * 10
    engine = {"settings": settings, "addresses": addresses, "entries": entries}
    result = {"queries": len(addresses)}
    try:
        # Rust plane first: cold = first query of a fresh process, no daemon exists.
        result["rust"] = child(root, "rust", args.queries, engine)
        # Engine: the first query starts the daemon and opens the program (cold start), the rest are warm.
        result["engine"] = child(root, "engine", args.queries, engine)
        # Engine again with the daemon still running: warm daemon, fresh Python process.
        result["engine_warm_daemon"] = child(root, "engine", args.queries, engine)
    finally:
        stop_daemon(settings)
    same = result["rust"]["rows"] == result["engine"]["rows"]
    result["rows_equal"] = same
    if not same:
        result["differences"] = [k for k in result["rust"]["rows"] if result["rust"]["rows"][k] != result["engine"]["rows"].get(k)][:20]
    summary = {"queries": result["queries"], "rows_equal_engine": same}
    for key in ("rust", "engine", "engine_warm_daemon"):
        t = result[key]["times"]
        summary[key] = {"mode": result[key]["mode"], "cold_first_query_s": round(result[key]["cold_first_query_s"], 4),
                        "total_s": round(sum(t), 4), "median_ms": round(statistics.median(t) * 1000, 3),
                        "p95_ms": round(sorted(t)[int(len(t) * 0.95) - 1] * 1000, 3),
                        "function_action_median_ms": round(statistics.median(result[key]["function_times"]) * 1000, 3)}
    print(json.dumps(summary, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps({**summary, "detail": {k: {kk: vv for kk, vv in v.items() if kk != "rows"} for k, v in result.items() if isinstance(v, dict)}}, indent=2))


if __name__ == "__main__":
    main()
