"""Static read plane against the engine, per action: equality of answers and time per query (cold and warm).

Needs a Hydra Engine install (HYDRALYSIS_INTEGRATION_ENGINE / _CLIENT / _JAVA like tests/test_engine_integration.py) and
the native extension on PYTHONPATH. Runs in its own data root, with its own daemon, stopped at the end.

    python benchmarks/static_plane.py --root <scratch dir> [--queries 200] [--out result.json]

Three fresh processes, in this order: the Rust plane (no daemon exists), the engine (its first query starts the daemon:
the cold start), the engine again (daemon warm). Each runs the same requests: `xrefs` at N addresses, `function` at the
entries the plane answers, `functions` pages (limit 200 and a filtered limit-20 page). Requests the plane declines are
left out of every column (they would go to the engine) and counted.
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

CHILD = r'''
import ctypes, json, os, sys, time
from ctypes import wintypes
sys.path.insert(0, os.environ["HYDRALYSIS_SRC"])
from hydralysis import query, staticplane
settings = json.loads(os.environ["HYDRALYSIS_SETTINGS"])
plan = json.loads(os.environ["HYDRALYSIS_PLAN"])
mode = os.environ["BENCH_MODE"]
runner = query.QueryRunner(settings)
gpr, program = settings["targets"]["flow"]["gpr"], "/flow_fixture.exe"

def request(action, address="", limit=200, cursor="", contains=""):
    return {"id": "b", "action": action, "address": address, "limit": limit, "cursor": cursor, "contains": contains,
            "timeout_s": 30, "options": {}, "expected_sha256": ""}

def ask(action, address="", limit=200, cursor="", contains=""):
    return json.loads(runner.query("flow", action, address, limit=limit, cursor=cursor, contains=contains,
                                   options={"view": "shared"}))

def peak_working_set():
    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("a", ctypes.c_size_t), ("b", ctypes.c_size_t),
                    ("c", ctypes.c_size_t), ("d", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t)]
    kernel32, psapi = ctypes.WinDLL("kernel32"), ctypes.WinDLL("psapi")
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    counters = Counters(); counters.cb = ctypes.sizeof(counters)
    if not psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        raise OSError("GetProcessMemoryInfo failed")
    return counters.PeakWorkingSetSize

result = {"mode": mode}
before = peak_working_set()
# the requests; in rust mode keep only what the plane answers, and report that list so the engine runs the same ones
requests = {}
for name, items in plan.items():
    keep = []
    for item in items:
        if mode == "rust" and staticplane.answer(gpr, program, request(item["action"], **item["args"])) is None:
            continue
        keep.append(item)
    requests[name] = keep
if mode != "rust":
    requests = plan   # the main process passes the filtered plan
result["plan"] = requests
result["declined"] = {name: len(plan[name]) - len(requests[name]) for name in plan}

first = None
for name, items in requests.items():
    times, rows = [], []
    for item in items:
        started = time.perf_counter()
        reply = ask(item["action"], **item["args"])
        elapsed = time.perf_counter() - started
        if first is None:
            first = elapsed   # the very first query of the process: with the engine, the daemon start
        times.append(elapsed)
        for key in ("engine", "id", "query_s", "agent", "base", "target", "view"):
            reply.pop(key, None)
        rows.append(reply)
        result.setdefault("modes", set()).add(item["action"])
    result[name] = {"times": times, "answers": rows}
result["first_query_s"] = first
result["peak_working_set_delta_mb"] = (peak_working_set() - before) / 1e6
result["peak_working_set_mb"] = peak_working_set() / 1e6
result["modes"] = sorted(result.get("modes", []))
print(json.dumps(result))
'''


def plan_for(count: int):
    refs = []
    for line in (FIXTURE / "oracle" / "oracleprog-legacy-12.1.4-analysed.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("toref from=") and " to=ram:" in line and "kind=MemReferenceDB" in line:
            address = int(line.split(" to=ram:")[1].split(" ")[0], 16)
            if not refs or refs[-1] != address:
                refs.append(address)
    refs = sorted(set(refs))
    refs = refs[:: max(1, len(refs) // count)][:count]
    truth = json.loads((FIXTURE / "engine" / "function.json").read_text(encoding="utf-8"))
    entries = list(truth)
    pages = json.loads((FIXTURE / "engine" / "functions.json").read_text(encoding="utf-8"))
    cursors = [""] + [p["next_cursor"] for p in pages if p.get("truncated")]
    return {
        "xrefs": [{"action": "xrefs", "args": {"address": "va:0x%x" % a, "limit": 200}} for a in refs],
        "function": [{"action": "function", "args": {"address": a}} for a in entries],
        "functions_page200": [{"action": "functions", "args": {"limit": 200, "cursor": c}} for c in cursors],
        "functions_filtered20": [{"action": "functions", "args": {"limit": 20, "cursor": c, "contains": "fun"}} for c in cursors],
    }


def child(mode: str, settings: dict, plan: dict, root: Path) -> dict:
    env = dict(os.environ)
    env.update(HYDRALYSIS_ROOT=str(root / "data"), HYDRALYSIS_SRC=str(REPOSITORY / "src"),
               HYDRALYSIS_SETTINGS=json.dumps(settings), HYDRALYSIS_PLAN=json.dumps(plan), BENCH_MODE=mode)
    if mode == "rust":
        env["HYDRALYSIS_IMPL"] = "rust"
    else:
        env.pop("HYDRALYSIS_IMPL", None)
    done = subprocess.run([sys.executable, "-c", CHILD], env=env, capture_output=True, text=True, timeout=1800)
    if done.returncode:
        raise SystemExit("child failed: " + done.stderr[-3000:])
    return json.loads(done.stdout.strip().splitlines()[-1])


def engine_memory_mb(settings) -> dict | None:
    """Working set (now and peak) of this root's daemon JVM, found through the pid in its endpoint file."""
    sys.path.insert(0, str(REPOSITORY / "src"))
    from hydralysis import hydra
    engine = hydra.Engine(settings)
    daemon = engine.module().Daemon(str(engine.engine_dir), str(hydra.state_dir(settings)), hydra.INSTANCE)
    pid = (daemon.read_endpoint() or {}).get("pid")
    if not pid:
        return None
    script = "$p = Get-Process -Id %d; '{0} {1}' -f $p.WorkingSet64, $p.PeakWorkingSet64" % int(pid)
    done = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True, timeout=60)
    try:
        now, peak = done.stdout.split()
        return {"pid": int(pid), "working_set_mb": round(int(now) / 1e6, 1), "peak_working_set_mb": round(int(peak) / 1e6, 1)}
    except ValueError:
        return None


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


def stats(times):
    if not times:
        return None
    ordered = sorted(times)
    return {"n": len(times), "median_ms": round(statistics.median(times) * 1000, 3),
            "p95_ms": round(ordered[max(0, int(len(ordered) * 0.95) - 1)] * 1000, 3), "total_s": round(sum(times), 4)}


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
    plan = plan_for(args.queries)
    runs = {}
    try:
        runs["rust"] = child("rust", settings, plan, root)
        kept = runs["rust"]["plan"]
        runs["engine_cold"] = child("engine", settings, kept, root)
        runs["engine_memory_mb"] = engine_memory_mb(settings)
        runs["engine_warm"] = child("engine", settings, kept, root)
    finally:
        stop_daemon(settings)
    summary = {"declined_by_the_plane": runs["rust"]["declined"], "engine_daemon_memory": runs["engine_memory_mb"],
               "python_peak_working_set_mb": {k: round(runs[k]["peak_working_set_mb"], 1) for k in ("rust", "engine_cold", "engine_warm")},
               "python_working_set_growth_mb": {k: round(runs[k]["peak_working_set_delta_mb"], 1) for k in ("rust", "engine_cold", "engine_warm")},
               "first_query_s": {k: round(runs[k]["first_query_s"], 4) for k in ("rust", "engine_cold", "engine_warm")},
               "equal_to_engine": {}, "actions": {}}
    for name in kept:
        a, b = runs["rust"][name]["answers"], runs["engine_warm"][name]["answers"]
        mismatches = [i for i, (x, y) in enumerate(zip(a, b)) if _strip(x) != _strip(y)]
        summary["equal_to_engine"][name] = {"compared": len(a), "mismatches": len(mismatches)}
        summary["actions"][name] = {k: stats(runs[k][name]["times"]) for k in ("rust", "engine_cold", "engine_warm")}
    print(json.dumps(summary, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2))


def _strip(answer):
    return {k: v for k, v in answer.items() if k not in ("engine", "id", "query_s", "overlays")}


if __name__ == "__main__":
    main()
