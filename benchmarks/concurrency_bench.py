"""Serial against concurrent decompiles, the speed-up and the lane `everQueued`, native and ghidra_query paths apart.

    python benchmarks/concurrency_bench.py --engine <dir> --client <ghidra_session.py> --root <fresh folder> --out <logs> \
        --clients 2,4,8 --per-client 8 --runs 5

Native path: each client is its own `hydra.Engine` connection (its own lane) calling `decompile` on one shared program.
ghidra_query path: each client is a thread of the Hydralysis query layer (`QueryRunner.query`, action decompile).
For each client count the same set of distinct functions is decompiled by one client (serial) and then split over N
clients (concurrent); the speed-up is serial time over concurrent time. The scheduler's `everQueued` counters (read
from the engine `status`) are printed before and after, per lane, so queueing is visible and not inferred. Medians
over --runs with the spread (min, max). Report-only; a fixture with tiny functions shows little speed-up, and the
report states the function sizes used. Machine dependent: recorded with the foreign load.
"""

from __future__ import annotations

import argparse
import json
import shutil
import threading
import time

import bench_common as common


def lanes(engine) -> dict:
    scheduler = engine.call("status").get("scheduler") or {}
    return {name: {key: lane.get(key) for key in ("slots", "inUse", "everQueued", "admitted")} for name, lane in scheduler.items()}


def delta(before: dict, after: dict) -> dict:
    out = {}
    for name, lane in after.items():
        base = before.get(name, {})
        out[name] = {"everQueued_before": base.get("everQueued"), "everQueued_after": lane.get("everQueued"),
                     "queued_during": (lane.get("everQueued") or 0) - (base.get("everQueued") or 0),
                     "slots": lane.get("slots")}
    return out


def timed(jobs: list) -> float:
    """Run the callables in parallel (one thread each) and return wall seconds; an error is re-raised."""
    errors: list = []

    def guard(job):
        try:
            job()
        except Exception as exc:
            errors.append("%s: %s" % (type(exc).__name__, str(exc)[:300]))

    threads = [threading.Thread(target=guard, args=(job,)) for job in jobs]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise RuntimeError("; ".join(errors[:3]))
    return time.perf_counter() - started


def split(items: list, parts: int) -> list[list]:
    return [items[i::parts] for i in range(parts)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.common_arguments(parser)
    parser.add_argument("--clients", default="2,4,8")
    parser.add_argument("--per-client", type=int, default=8, help="functions each concurrent client decompiles")
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args(argv)
    common.require_engine(args)
    from hydralysis import hydra, query
    binary = common.default_binary(args.binary)
    root = common.fresh_root(args, "conc")
    out = common.output_dir(args.out)
    settings = common.settings_of(args, root)
    scratch = root / "fixture.exe"
    shutil.copy2(binary, scratch)
    report = {"script": "concurrency_bench", "rows": ["C1-03", "9.10 concurrent speed-up"], "engine": common.engine_facts(args),
              "machine": common.machine(), "program_sha256": common.sha256_of(scratch), "program": binary.name,
              "file_system": common.file_system(root), "runs": args.runs, "load_before": common.foreign_load(),
              "native": {}, "ghidra_query": {}}
    try:
        runner, _ = common.prepare(settings, scratch, "fixture")
        target = runner.target("fixture")
        top = common.sized_functions(runner, "fixture", 200)
        counts = [int(x) for x in args.clients.split(",") if x]
        need = max(counts) * args.per_client
        chosen = top[:need]
        report["functions"] = {"count": len(chosen), "wanted": need, "size_bytes": common.summarize([f["size"] for f in chosen]),
                               "note": "fewer than wanted: functions repeat across clients" if len(chosen) < need else ""}
        addresses = [f["address"] for f in chosen] or [top[0]["address"]]
        observer = hydra.Engine(settings, lane="observer")
        # Native clients: one engine connection (lane) each, one shared read-only program.
        connections = []
        for index in range(max(counts)):
            engine = hydra.Engine(settings, lane="bench%d" % index)
            program = query.open_program(engine, target["gpr"], target["program"], target["sha256"])
            connections.append((engine, program["key"]))
        # Warm: a first pass makes the native decompilers and fills the caches; it is not measured.
        for engine, key in connections:
            engine.call("decompile", program=key, address=addresses[0], timeout=120)
        runner.query("fixture", "decompile", addresses[0])

        def native_job(engine, key, mine):
            return lambda: [engine.call("decompile", program=key, address=a, timeout=120) for a in mine]

        def query_job(mine):
            return lambda: [runner.query("fixture", "decompile", a, timeout_s=120) for a in mine]

        for path_name, make in (("native", "native"), ("ghidra_query", "query")):
            for count in counts:
                work = [addresses[i % len(addresses)] for i in range(count * args.per_client)]
                serial_s, concurrent_s = [], []
                before = lanes(observer)
                for _ in range(args.runs):
                    if make == "native":
                        engine, key = connections[0]
                        serial_s.append(timed([native_job(engine, key, work)]))
                        parts = split(work, count)
                        concurrent_s.append(timed([native_job(connections[i][0], connections[i][1], parts[i]) for i in range(count)]))
                    else:
                        serial_s.append(timed([query_job(work)]))
                        concurrent_s.append(timed([query_job(part) for part in split(work, count)]))
                after = lanes(observer)
                s, c = common.summarize(serial_s), common.summarize(concurrent_s)
                report[path_name][str(count)] = {
                    "calls": len(work), "serial_s": s, "concurrent_s": c,
                    "speed_up_median": round(s["median"] / c["median"], 2) if c["median"] else None,
                    "speed_up_range": [round(min(serial_s) / max(concurrent_s), 2), round(max(serial_s) / min(concurrent_s), 2)],
                    "lanes": delta(before, after)}
                print(path_name, count, "serial %.3fs concurrent %.3fs speed-up %s" % (
                    s["median"], c["median"], report[path_name][str(count)]["speed_up_median"]), flush=True)
    finally:
        report["load_after"] = common.foreign_load()
        try:
            common.stop_engine(settings)
        except Exception as exc:
            report["stop_error"] = str(exc)[:300]
        path = common.write_report(out, "concurrency_bench", report)
        print(json.dumps({"report": str(path)}))
        common.cleanup(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
