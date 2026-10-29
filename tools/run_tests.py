"""Run the unit suite in parallel.

    python tools/run_tests.py                 # all cores, test roots under the system temp
    python tools/run_tests.py -j 12 --root C:/dev-overflow/hydralysis-tests
    python tools/run_tests.py --record        # also rewrite tests/timings.json from this run
    python tools/run_tests.py -k views        # only tests whose id contains "views"

The suite is wall-clock bound (many tests start processes and fsync), so it splits into tasks: a class is one task,
and a class that costs more than SPLIT_S seconds in tests/timings.json is cut into one task per slow test plus one
for the rest. Every task is its own `python -m unittest` process with its own HYDRALYSIS_TEST_ROOT and TEMP, the
longest tasks start first, and the pool stays full until the queue is empty.

A test that fails under this load is run again ALONE, with nothing else running (--rerun-alone, default 1). A test
that then passes is listed as "failed under load, passed alone": it is a timing test that needs a quiet machine, and
the run still exits 0 unless --strict is given. A test that fails alone too is a real failure and exits 1. Tests
named in timings.json under "serial" run alone after the parallel phase, because they measure rates or latency.

The test roots must be on a fast local disk: the durable-write tests fsync, and on a hard disk they take minutes.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
TESTS = REPOSITORY / "tests"
TIMINGS = TESTS / "timings.json"
SPLIT_S = 40.0          # a class costing more than this is split
SLOW_S = 12.0           # inside a split class, a test at least this slow gets its own task
DEFAULT_COST_S = 1.5    # a test with no recorded timing
CHUNK = 60              # most test ids on one command line
DURATION = re.compile(r"^\s*([0-9]+\.[0-9]+)s\s+\S+ \(([\w.]+)\)\s*$", re.M)
HEADER = re.compile(r"^(?:FAIL|ERROR): \S+ \(([\w.]+)\)", re.M)
RAN = re.compile(r"^Ran (\d+) tests? in ", re.M)


def list_tests(pattern: str = "") -> list[str]:
    """Every test id in tests/, in discovery order. An import failure stays in the list as its module name."""
    sys.path[:0] = [str(TESTS), str(REPOSITORY / "src")]
    out: list[str] = []

    def walk(suite) -> None:
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                walk(item)
            else:
                ident = item.id()
                if ident.startswith("unittest.loader._FailedTest."):
                    ident = ident.rsplit(".", 1)[-1]
                out.append(ident)

    walk(unittest.TestLoader().discover(str(TESTS), top_level_dir=str(TESTS)))
    return [i for i in out if pattern in i]


def plan(ids: list[str], timings: dict[str, float]) -> list[dict]:
    """Group test ids into tasks, longest first. A task is {"name", "args", "cost"}."""
    classes: dict[str, list[str]] = {}
    for ident in ids:
        classes.setdefault(ident.rsplit(".", 1)[0] if ident.count(".") >= 2 else ident, []).append(ident)
    tasks: list[dict] = []
    for cls, members in classes.items():
        cost = {m: timings.get(m, DEFAULT_COST_S) for m in members}
        total = sum(cost.values())
        if total <= SPLIT_S or len(members) == 1:
            tasks.append({"name": cls, "args": [cls], "cost": total})
            continue
        slow = [m for m in members if cost[m] >= SLOW_S]
        rest = [m for m in members if cost[m] < SLOW_S]
        for m in slow:
            tasks.append({"name": m, "args": [m], "cost": cost[m]})
        for n in range(0, len(rest), CHUNK):
            part = rest[n:n + CHUNK]
            tasks.append({"name": "%s#%d" % (cls, n // CHUNK), "args": part, "cost": sum(cost[m] for m in part)})
    tasks.sort(key=lambda t: -t["cost"])
    return tasks


def run_task(task: dict, root: Path, index: int) -> dict:
    work = root / ("w%03d" % index)
    tmp = work / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    # hermetic like CI: no inherited stock-Ghidra variable is visible to a test (unset is the same as empty)
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GHIDRA")}
    env.update(PYTHONPATH=os.pathsep.join([str(REPOSITORY / "src")] + ([os.environ["PYTHONPATH"]] if os.environ.get("PYTHONPATH") else [])),
               HYDRALYSIS_TEST_ROOT=str(work / "root"), TEMP=str(tmp), TMP=str(tmp), TMPDIR=str(tmp), PYTHONUNBUFFERED="1")
    started = time.monotonic()
    proc = subprocess.run([sys.executable, "-m", "unittest", "--durations", "0", *task["args"]], cwd=TESTS, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    text = proc.stdout or ""
    (root / "logs").mkdir(exist_ok=True)
    (root / "logs" / ("%03d-%s.log" % (index, re.sub(r"[^\w.#-]", "_", task["name"])[:80]))).write_text(text, encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    ran = RAN.search(text)
    return {"task": task, "code": proc.returncode, "seconds": time.monotonic() - started, "text": text,
            "ran": int(ran.group(1)) if ran else 0, "failed": sorted(set(HEADER.findall(text))),
            "durations": {ident: float(sec) for sec, ident in DURATION.findall(text)}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("-j", "--jobs", type=int, default=max(2, (os.cpu_count() or 4) - 2))
    ap.add_argument("--root", default="", help="work root (default: a new directory under the system temp); must be dot-free")
    ap.add_argument("-k", default="", help="only test ids containing this text")
    ap.add_argument("--rerun-alone", type=int, default=1)
    ap.add_argument("--strict", action="store_true", help="a test that failed under load fails the run even if it passes alone")
    ap.add_argument("--record", action="store_true", help="rewrite tests/timings.json from this run")
    ap.add_argument("--keep", action="store_true", help="keep the work root and logs")
    ap.add_argument("--list", action="store_true", help="print the plan and exit")
    args = ap.parse_args()

    started = time.monotonic()
    data = json.loads(TIMINGS.read_text(encoding="utf-8")) if TIMINGS.exists() else {}
    timings: dict[str, float] = data.get("seconds", {})
    serial = set(data.get("serial", []))
    ids = list_tests(args.k)
    parallel_ids = [i for i in ids if i not in serial]
    serial_ids = [i for i in ids if i in serial]
    tasks = plan(parallel_ids, timings)
    if args.list:
        for t in tasks:
            print("%7.1f  %s (%d args)" % (t["cost"], t["name"], len(t["args"])))
        print("serial:", ", ".join(serial_ids) or "-")
        return 0

    root = Path(args.root).resolve() if args.root else Path(tempfile.mkdtemp(prefix="hydralysis-tests-"))
    root.mkdir(parents=True, exist_ok=True)
    print("%d tests, %d tasks on %d workers, %d serial; root %s" % (len(ids), len(tasks), args.jobs, len(serial_ids), root), flush=True)
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        futures = [pool.submit(run_task, t, root, n) for n, t in enumerate(tasks)]
        for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
            r = future.result()
            results.append(r)
            mark = "ok  " if r["code"] == 0 else "FAIL"
            if r["code"] != 0 or r["seconds"] > 60:
                print("[%3d/%d] %s %6.1fs %s" % (done, len(tasks), mark, r["seconds"], r["task"]["name"]), flush=True)
    parallel_wall = time.monotonic() - started

    ran = sum(r["ran"] for r in results)
    failed_ids = sorted({f for r in results for f in r["failed"]})
    crashed = [r for r in results if r["code"] != 0 and not r["failed"]]
    serial_results: list[dict] = []
    for n, ident in enumerate(serial_ids):
        r = run_task({"name": ident, "args": [ident], "cost": 0}, root, 900 + n)
        serial_results.append(r)
        ran += r["ran"]
        if r["code"] != 0:
            failed_ids.append(ident)
    failed_ids = sorted(set(failed_ids))

    under_load: list[str] = []
    real: list[str] = []
    texts = {f: r["text"] for r in results + serial_results for f in r["failed"]}
    for ident in failed_ids:
        verdict = "real"
        if ident not in serial:
            for _ in range(args.rerun_alone):
                r = run_task({"name": ident, "args": [ident], "cost": 0}, root, 950)
                if r["code"] == 0:
                    verdict = "load"
                else:
                    verdict = "real"
                    texts[ident] = r["text"]
                    break
        (under_load if verdict == "load" else real).append(ident)

    if args.record:
        seconds = dict(timings)
        for r in results + serial_results:
            seconds.update(r["durations"])
        TIMINGS.write_text(json.dumps({"serial": sorted(serial), "seconds": {k: round(v, 2) for k, v in sorted(seconds.items())}}, indent=1) + "\n", encoding="utf-8")
        print("timings recorded:", TIMINGS)

    wall = time.monotonic() - started
    print()
    for ident in real:
        print("=" * 70, "\nFAILED ALONE:", ident, "\n" + texts.get(ident, "")[-3000:])
    for r in crashed:
        print("=" * 70, "\nTASK EXITED %s WITHOUT A TEST FAILURE: %s\n%s" % (r["code"], r["task"]["name"], r["text"][-3000:]))
    for ident in under_load:
        print("failed under load, passed alone:", ident)
    print("\nRan %d tests in %.0f s (parallel phase %.0f s), %d failed alone, %d failed only under load, %d tasks crashed" % (
        ran, wall, parallel_wall, len(real), len(under_load), len(crashed)))
    bad = bool(real or crashed or (args.strict and under_load))
    if not bad and not args.keep:
        shutil.rmtree(root, ignore_errors=True)
    else:
        print("logs and work root kept in", root)
    print("FAILED" if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
