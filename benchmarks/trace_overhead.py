"""Overhead of the semantic-trace recorder on the real `frameloop` fixture: capture off versus capture on.

    python benchmarks/trace_overhead.py [--rounds 5] [--out DIR] [--workloads tight,paced] [--fixtures DIR]

Method (follows D:/Projects/global-rules/references/perf-evidence.md):
* The fixture times its own frames (`--times`, QueryPerformanceCounter ticks of every frame), so the numbers are the
  target's, not the harness's. Frame-time percentiles are over all frames of all rounds of a configuration.
* Capture off is a plain process; capture on is the same process spawned paused, armed with the declared baseline profile
  (the nine frameloop hooks) through `capture start {trace}` with the default recorder settings, then resumed. Rounds are
  interleaved (off, on, off, on, ...) so drift in the machine hits both alike; the reported overhead is the median over
  rounds of (on - off) / off, from the per-round median and mean frame time.
* The parts of the cost are reported separately: frame time (steady state), the first frames (first-use pause: probe
  install happens before the first frame, so what remains is first-hit cost), the install time per probe, the Python
  worker's CPU share, and what the recorder did (probe hits, rate, drops, backpressure stalls, lost batches).
* A bare loop (about 5 us a frame) is a stress test, not a game: its overhead is reported but is not the figure for a frame
  that does work. The `paced` workload spins a declared amount of "game work" per frame.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

import trace_live as tl  # noqa: E402

WORKLOADS = {
    "tight": ["--frames=20000"],                       # the bare loop, about 5 us a frame
    "paced": ["--frames=20000", "--spin-us=200"],      # 200 us of game work in every frame
    "frame16": ["--frames=600", "--spin-us=16000"],    # a 60 Hz frame of work
}
FREQ = 10_000_000


def _cpu_seconds(handle, job: bool) -> float:
    """User + kernel CPU of a process (GetProcessTimes) or of every process that ever ran in a job object, in seconds."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not job:
        times = [wintypes.FILETIME() for _ in range(4)]
        k32.GetProcessTimes(wintypes.HANDLE(handle), *[ctypes.byref(t) for t in times])
        return sum(((t.dwHighDateTime << 32) | t.dwLowDateTime) for t in times[2:]) / 1e7

    class Basic(ctypes.Structure):
        _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64), ("ThisPeriodTotalUserTime", ctypes.c_int64),
                    ("ThisPeriodTotalKernelTime", ctypes.c_int64), ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                    ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD)]
    info = Basic()
    k32.QueryInformationJobObject(wintypes.HANDLE(handle), 1, ctypes.byref(info), ctypes.sizeof(info), None)
    return (info.TotalUserTime + info.TotalKernelTime) / 1e7


def read_times(path: Path) -> list[int]:
    data = path.read_bytes()
    return list(struct.unpack("<%dQ" % (len(data) // 8), data[: len(data) // 8 * 8]))


def pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))] if ordered else float("nan")


def summarize(ticks: list[int]) -> dict:
    us = [t * 1e6 / FREQ for t in ticks]
    return {"frames": len(us), "p50_us": pct(us, .5), "p95_us": pct(us, .95), "p99_us": pct(us, .99), "max_us": max(us),
            "mean_us": statistics.fmean(us), "first10_mean_us": statistics.fmean(us[:10]), "total_ms": sum(us) / 1000}


def run_off(exe: Path, args: list[str], work: Path) -> dict:
    times = work / "times.bin"
    started = time.perf_counter()
    proc = subprocess.Popen([str(exe), *args, "--times=" + str(times)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={**os.environ, "HYDRA_FX_LINGER_MS": "0"})
    _, err = proc.communicate(timeout=600)
    wall = time.perf_counter() - started
    assert proc.returncode == 0, err
    return {"wall_s": wall, "frames": summarize(read_times(times)), "tree_cpu_s": _cpu_seconds(int(proc._handle), False)}


def run_on(fixtures: Path, exe_name: str, args: list[str], work: Path, hooks: list[str] | None, trace_options: dict) -> dict:
    times = work / "times.bin"
    specs, _verification = tl.specs_for(fixtures, [exe_name], hooks)
    cpu0, wall0 = time.process_time(), time.perf_counter()
    live = tl.Live(work, fixtures / exe_name, [*args, "--times=" + str(times)], linger_ms=1500)
    try:
        started = live.start(specs, **trace_options)
        cpu_setup = time.process_time() - cpu0
        wall_setup = time.perf_counter() - wall0
        cpu1, wall1 = time.process_time(), time.perf_counter()
        job_cpu1 = _cpu_seconds(int(live.job.handle), True)
        live.resume()
        exited = live.wait_exit(900)
        run_wall = time.perf_counter() - wall1
        run_cpu = time.process_time() - cpu1         # the worker's own CPU while the target ran (includes Frida callbacks)
        target_cpu = _cpu_seconds(int(live.job.handle), True) - job_cpu1     # the target (agent threads included), exited by now
        time.sleep(0.2)
        stopped = live.stop()
    finally:
        live.close()
    assert exited, "the fixture did not exit"
    health = stopped["trace"]["health"]
    producer = health["producer"]
    probes = started["trace"]["probes"]
    return {"wall_s": run_wall, "frames": summarize(read_times(times)), "setup_wall_s": wall_setup, "setup_cpu_s": cpu_setup,
            "worker_cpu_s_during_run": run_cpu, "worker_cpu_share": run_cpu / run_wall if run_wall else None,
            "target_cpu_s": target_cpu, "tree_cpu_s": target_cpu + run_cpu, "sampling": producer.get("sampling"),
            "install_ms": {p["name"]: p["install_ms"] for p in probes},
            "hits": producer["attempted"], "dropped": producer["dropped"], "no_ring": producer["no_ring"],
            "stalls": producer.get("stalls"), "stall_ticks": producer.get("stall_ticks"), "window_waits": producer.get("window_waits"),
            "records_written": health["encoder"]["records"], "batches_missing": health["transport"]["batches_missing"],
            "batches": health["transport"]["batches"], "segment_bytes": health["writer"]["bytes"],
            "verify": health["verify"]["outcome"], "reads_refused": health.get("reads_refused"), "segment_events": health["records"]}


def median(values):
    return statistics.median(values)


def report(workload: str, args: list[str], off_runs: list[dict], on_runs: list[dict]) -> dict:
    rounds = []
    for off, on in zip(off_runs, on_runs):
        o, n = off["frames"], on["frames"]
        rounds.append({"p50_overhead": (n["p50_us"] - o["p50_us"]) / o["p50_us"], "mean_overhead": (n["mean_us"] - o["mean_us"]) / o["mean_us"],
                       "p99_overhead": (n["p99_us"] - o["p99_us"]) / o["p99_us"], "wall_overhead": (n["total_ms"] - o["total_ms"]) / o["total_ms"],
                       "tree_cpu_overhead": (on["tree_cpu_s"] - off["tree_cpu_s"]) / off["tree_cpu_s"] if off.get("tree_cpu_s") else float("nan")})
    hits = [r["hits"] for r in on_runs]
    walls = [r["wall_s"] for r in on_runs]
    return {
        "workload": workload, "args": args, "rounds": len(off_runs),
        "off": {k: median([r["frames"][k] for r in off_runs]) for k in ("p50_us", "p95_us", "p99_us", "max_us", "mean_us", "first10_mean_us")},
        "on": {k: median([r["frames"][k] for r in on_runs]) for k in ("p50_us", "p95_us", "p99_us", "max_us", "mean_us", "first10_mean_us")},
        "overhead_median_of_rounds": {k: median([r[k] for r in rounds]) for k in rounds[0]},
        "overhead_per_round": rounds,
        "recorder": {"hits_median": median(hits), "hit_rate_per_s_median": median([h / w for h, w in zip(hits, walls)]),
                     "hits_per_frame": median([r["hits"] / r["frames"]["frames"] for r in on_runs]),
                     "dropped_total": sum(r["dropped"] for r in on_runs), "no_ring_total": sum(r["no_ring"] for r in on_runs),
                     "stalls_total": sum(r["stalls"] or 0 for r in on_runs), "stall_ticks_total": sum(r["stall_ticks"] or 0 for r in on_runs),
                     "batches_missing_total": sum(r["batches_missing"] or 0 for r in on_runs),
                     "all_segments_clean": all(r["verify"] == "clean" for r in on_runs),
                     "skipped_total": sum((r["sampling"] or {}).get("skipped", 0) for r in on_runs),
                     "tree_cpu_s_off_median": median([r["tree_cpu_s"] for r in off_runs]), "tree_cpu_s_on_median": median([r["tree_cpu_s"] for r in on_runs]),
                     "worker_cpu_share_median": median([r["worker_cpu_share"] for r in on_runs]),
                     "install_ms_median": {k: median([r["install_ms"][k] for r in on_runs]) for k in on_runs[0]["install_ms"]},
                     "segment_bytes_median": median([r["segment_bytes"] for r in on_runs])},
        "runs_off": off_runs, "runs_on": on_runs,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--out", default="E:/Projects/Hydra/_logs/trace-lcap2/overhead")
    parser.add_argument("--workloads", default="tight,paced,frame16")
    parser.add_argument("--fixtures", default="")
    parser.add_argument("--label", default="run")
    parser.add_argument("--hooks", default="", help="comma separated hook ids (default: every frameloop hook of the baseline)")
    parser.add_argument("--sampling", default="", help="sampling policy: adaptive (the default), exact, fixed:N, or a JSON object")
    parser.add_argument("--hooking", default="", help="inline (the default) or interceptor")
    parser.add_argument("--option", action="append", default=[], help="trace option key=value (int/float), e.g. ring_bytes=262144")
    options = parser.parse_args()
    out = Path(options.out)
    out.mkdir(parents=True, exist_ok=True)
    fixtures = Path(options.fixtures) if options.fixtures else out / "fx"
    if not (fixtures / "frameloop.exe").is_file():
        sys.path.insert(0, str(ROOT / "tests" / "fixtures"))
        import trace_fixtures
        trace_fixtures.build_group("frameloop", fixtures.parent if fixtures.name == "x64" else fixtures, ("x64",))
        fixtures = fixtures / "x64" if (fixtures / "x64").is_dir() else fixtures
    trace_options = {}
    for item in options.option:
        key, value = item.split("=", 1)
        trace_options[key] = float(value) if "." in value else int(value)
    if options.sampling:
        raw = options.sampling
        trace_options["sampling"] = json.loads(raw) if raw.startswith("{") else ({"mode": "fixed", "stride": int(raw[6:])} if raw.startswith("fixed:") else raw)
    if options.hooking:
        trace_options["hooking"] = options.hooking
    hooks = [h for h in options.hooks.split(",") if h] or None
    results = {"label": options.label, "machine": {"cpus": os.cpu_count()}, "trace_options": trace_options, "workloads": []}
    for name in [w for w in options.workloads.split(",") if w]:
        args = WORKLOADS[name]
        off_runs, on_runs = [], []
        for index in range(options.rounds):
            work = out / ("work-%s-%s-%d" % (options.label, name, index))
            shutil.rmtree(work, ignore_errors=True)
            work.mkdir(parents=True)
            off_runs.append(run_off(fixtures / "frameloop.exe", args, work))      # interleaved: off, on, off, on, ...
            on_runs.append(run_on(fixtures, "frameloop.exe", args, work, hooks, trace_options))
            shutil.rmtree(work, ignore_errors=True)
            print("%s round %d: off p50 %.2f us  on p50 %.2f us  hits %d dropped %d" % (
                name, index, off_runs[-1]["frames"]["p50_us"], on_runs[-1]["frames"]["p50_us"], on_runs[-1]["hits"], on_runs[-1]["dropped"]), flush=True)
        results["workloads"].append(report(name, args, off_runs, on_runs))
    path = out / ("overhead-%s.json" % options.label)
    path.write_text(json.dumps(results, indent=1, default=str), encoding="utf-8")
    for w in results["workloads"]:
        o, n, ov, r = w["off"], w["on"], w["overhead_median_of_rounds"], w["recorder"]
        print("\n== %s (%d rounds) ==" % (w["workload"], w["rounds"]))
        print("frame p50 %.2f -> %.2f us   p99 %.2f -> %.2f us   mean %.2f -> %.2f us" % (o["p50_us"], n["p50_us"], o["p99_us"], n["p99_us"], o["mean_us"], n["mean_us"]))
        print("overhead (median of rounds): p50 %.1f%%  mean %.1f%%  p99 %.1f%%  wall %.1f%%" % tuple(100 * ov[k] for k in ("p50_overhead", "mean_overhead", "p99_overhead", "wall_overhead")))
        print("hits/frame %.1f  rate %.0f/s  dropped %d  skipped(policy) %d  no_ring %d  stalls %d  missing batches %d  clean %s  worker cpu share %.2f" % (
            r["hits_per_frame"], r["hit_rate_per_s_median"], r["dropped_total"], r["skipped_total"], r["no_ring_total"], r["stalls_total"],
            r["batches_missing_total"], r["all_segments_clean"], r["worker_cpu_share_median"]))
        print("process-tree CPU (target + worker) off %.3f s -> on %.3f s  (median over rounds of per-round overhead %.1f%%)" % (
            r["tree_cpu_s_off_median"], r["tree_cpu_s_on_median"], 100 * median([x["tree_cpu_overhead"] for x in w["overhead_per_round"]])))
    print("\nwrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
