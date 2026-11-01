"""Run the unit suite in parallel.

    python tools/run_tests.py                 # all cores, work directories under the system temp
    python tools/run_tests.py -j 12 --root <fast-disk work dir>
    python tools/run_tests.py --record        # also rewrite tests/timings.json from this run
    python tools/run_tests.py -k views        # only tests whose id contains "views"

The suite is wall-clock bound (many tests start processes and fsync), so it splits into tasks: a class is one task,
and a class that costs more than SPLIT_S seconds in tests/timings.json is cut into one task per slow test plus
chunks for the rest. Every task is its own `python -m unittest` process with its own HYDRALYSIS_TEST_ROOT and TEMP
inside a fresh directory made under --root (only that directory is ever deleted); the longest tasks start first and
the pool stays full until the queue is empty.

A task passes only when its process exits 0, prints "Ran N tests" and N is the number of tests planned for it, so a
task that dies early, hangs (--task-timeout) or loses tests fails the run. A task that fails under this load is run
again whole and ALONE, with nothing else running (same grouping, same order, so a failure that depends on the other
tests of its class stays a failure). A test that fails in the parallel phase and passes in that rerun is listed as
"failed under load, passed alone": a timing test that needs a quiet machine. The run still exits 0 for it unless
--strict is given. A test that fails again is a real failure and exits 1. Tests named in timings.json under "serial"
run alone after the parallel phase.

CI runs `python -m unittest discover -s tests` serially and stays the gate: it also catches state that leaks between
classes and modules, which a split into tasks cannot. The work directories must be on a fast local disk: the
durable-write tests fsync, and on a hard disk they take minutes. HYDRALYSIS_INTEGRATION_* variables are removed from
the tests' environment (the engine tests would otherwise run 22 at a time) unless --integration is given.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import signal
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
FAILED_LOADER = "unittest.loader._FailedTest."


def granted_cpus() -> int:
    """The logical processors this process may run on (its affinity mask), not the machine's count: a CI runner or a
    run under ``start /affinity`` has fewer than ``os.cpu_count()`` reports, and on Windows ``os.cpu_count`` and
    ``os.process_cpu_count`` both report the whole machine."""
    if hasattr(os, "sched_getaffinity"):
        return max(1, len(os.sched_getaffinity(0)))
    if os.name == "nt":
        import ctypes
        proc, system = ctypes.c_size_t(), ctypes.c_size_t()
        k32 = ctypes.windll.kernel32
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        if k32.GetProcessAffinityMask(ctypes.c_void_p(k32.GetCurrentProcess()), ctypes.byref(proc), ctypes.byref(system)) and proc.value:
            return bin(proc.value).count("1")
    return os.cpu_count() or 1


#: tasks at once: the granted logical processors less 2 for the runner and the OS, at least 2
DEFAULT_JOBS = max(2, granted_cpus() - 2)


def test_id(ident: str) -> str:
    """The id the planner uses: an import failure is named by its module."""
    return ident[len(FAILED_LOADER):] if ident.startswith(FAILED_LOADER) else ident


def list_tests(pattern: str = "") -> list[str]:
    """Every test id in tests/, in discovery order. An import failure stays in the list as its module name."""
    sys.path[:0] = [str(TESTS), str(REPOSITORY / "src")]
    out: list[str] = []

    def walk(suite) -> None:
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                walk(item)
            else:
                out.append(test_id(item.id()))

    walk(unittest.TestLoader().discover(str(TESTS), top_level_dir=str(TESTS)))
    return [i for i in out if pattern in i]


def plan(ids: list[str], timings: dict[str, float], whole_classes: bool = True) -> list[dict]:
    """Group test ids into tasks, longest first. A task is {"name", "args", "ids", "cost"}: `args` go to unittest and
    `ids` are the tests it must run. `whole_classes` is False when `ids` is a selection (-k): a class then cannot be
    named as a whole, because that would run tests that were not selected."""
    classes: dict[str, list[str]] = {}
    for ident in ids:
        classes.setdefault(ident.rsplit(".", 1)[0] if ident.count(".") >= 2 else ident, []).append(ident)
    tasks: list[dict] = []
    for cls, members in classes.items():
        cost = {m: timings.get(m, DEFAULT_COST_S) for m in members}
        total = sum(cost.values())
        if whole_classes and (total <= SPLIT_S or len(members) == 1):
            tasks.append({"name": cls, "args": [cls], "ids": members, "cost": total})
            continue
        slow = [m for m in members if cost[m] >= SLOW_S]
        rest = [m for m in members if cost[m] < SLOW_S]
        for m in slow:
            tasks.append({"name": m, "args": [m], "ids": [m], "cost": cost[m]})
        for n in range(0, len(rest), CHUNK):
            part = rest[n:n + CHUNK]
            tasks.append({"name": "%s#%d" % (cls, n // CHUNK), "args": part, "ids": part, "cost": sum(cost[m] for m in part)})
    tasks.sort(key=lambda t: -t["cost"])
    return tasks


def judge(task: dict, code, text: str) -> dict:
    """The verdict on one finished task process: which tests failed, and whether the process itself is trustworthy.
    `code` is the exit code, or None when the process was killed after the timeout."""
    ran = RAN.search(text)
    count = int(ran.group(1)) if ran else 0
    failed = sorted({test_id(f) for f in HEADER.findall(text)})
    problem = ""
    if code is None:
        problem = "timed out"
    elif code != 0 and not failed:
        problem = "exited %s without a test failure" % code
    elif code == 0 and not ran:
        problem = "exited 0 without printing 'Ran N tests'"
    elif code == 0 and count != len(task["ids"]):
        problem = "ran %d tests, %d were planned" % (count, len(task["ids"]))
    return {"task": task, "code": code, "ran": count, "failed": failed, "problem": problem, "text": text,
            "ok": code == 0 and not problem,
            "durations": {test_id(i): float(s) for s, i in DURATION.findall(text)}}


def kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()


def run_task(task: dict, root: Path, label: str, integration: bool = False, timeout: float = 1800.0) -> dict:
    work = root / label
    tmp = work / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    # hermetic like CI: no inherited stock-Ghidra variable is visible to a test (unset is the same as empty)
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith("GHIDRA") and (integration or not k.upper().startswith("HYDRALYSIS_INTEGRATION"))}
    env.update(PYTHONPATH=os.pathsep.join([str(REPOSITORY / "src")] + ([os.environ["PYTHONPATH"]] if os.environ.get("PYTHONPATH") else [])),
               HYDRALYSIS_TEST_ROOT=str(work / "root"), TEMP=str(tmp), TMP=str(tmp), TMPDIR=str(tmp), PYTHONUNBUFFERED="1")
    command = [sys.executable, "-m", "unittest"] + (["--durations", "0"]) + task["args"]
    started = time.monotonic()
    proc = subprocess.Popen(command, cwd=TESTS, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", start_new_session=(os.name != "nt"))
    try:
        text, _ = proc.communicate(timeout=timeout)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        text, _ = proc.communicate()
        code = None
    (root / "logs").mkdir(exist_ok=True)
    (root / "logs" / ("%s-%s.log" % (label, re.sub(r"[^\w.#-]", "_", task["name"])[:80]))).write_text(text or "", encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)
    verdict = judge(task, code, text or "")
    verdict["seconds"] = time.monotonic() - started
    return verdict


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("-j", "--jobs", type=int, default=DEFAULT_JOBS, help="tasks at once (default %d)" % DEFAULT_JOBS)
    ap.add_argument("--root", default="", help="parent directory for this run's work directory (default: the system temp); keep it dot-free")
    ap.add_argument("-k", default="", help="only test ids containing this text")
    ap.add_argument("--rerun-alone", type=int, default=1, help="how many times a failed task is run again alone (0: none)")
    ap.add_argument("--strict", action="store_true", help="a test that failed under load fails the run even if it passes alone")
    ap.add_argument("--task-timeout", type=float, default=1800.0, help="seconds before one task is killed and counted as failed")
    ap.add_argument("--integration", action="store_true", help="keep HYDRALYSIS_INTEGRATION_* in the tests' environment")
    ap.add_argument("--record", action="store_true", help="rewrite tests/timings.json from this run")
    ap.add_argument("--keep", action="store_true", help="keep this run's work directory and logs")
    ap.add_argument("--list", action="store_true", help="print the plan and exit")
    args = ap.parse_args()

    started = time.monotonic()
    data = json.loads(TIMINGS.read_text(encoding="utf-8")) if TIMINGS.exists() else {}
    timings: dict[str, float] = data.get("seconds", {})
    serial = set(data.get("serial", []))
    ids = list_tests(args.k)
    tasks = plan([i for i in ids if i not in serial], timings, not args.k)
    serial_tasks = plan([i for i in ids if i in serial], {}, False)
    if args.list:
        for t in tasks:
            print("%7.1f  %s (%d tests)" % (t["cost"], t["name"], len(t["ids"])))
        print("serial:", ", ".join(i for t in serial_tasks for i in t["ids"]) or "-")
        return 0

    parent = Path(args.root).resolve() if args.root else Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    print("%d tests, %d tasks on %d workers, %d serial; work directory %s" % (len(ids), len(tasks), args.jobs, len(serial_tasks), root), flush=True)

    def go(task, label):
        return run_task(task, root, label, args.integration, args.task_timeout)

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        futures = [pool.submit(go, t, "p%03d" % n) for n, t in enumerate(tasks)]
        for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
            r = future.result()
            results.append(r)
            if not r["ok"] or r["seconds"] > 60:
                print("[%3d/%d] %s %6.1fs %s%s" % (done, len(tasks), "ok  " if r["ok"] else "FAIL", r["seconds"], r["task"]["name"],
                                                   " (%s)" % r["problem"] if r["problem"] else ""), flush=True)
    parallel_wall = time.monotonic() - started
    serial_results = [go(t, "s%03d" % n) for n, t in enumerate(serial_tasks)]

    under_load: list[str] = []
    real: list[str] = []
    problems: list[dict] = []
    recovered = 0
    for n, r in enumerate(results + serial_results):
        if r["ok"]:
            continue
        verdict = r
        if n < len(results) and args.rerun_alone > 0:
            for k in range(args.rerun_alone):
                verdict = go(r["task"], "r%03d-%d" % (n, k))
                if verdict["ok"]:
                    break
        if verdict["ok"]:
            recovered += verdict["ran"] - r["ran"]
            under_load.extend(r["failed"] or r["task"]["ids"])
        elif verdict["problem"]:
            problems.append(verdict)
        real.extend(verdict["failed"])
    texts = {}
    for r in results + serial_results:
        for f in r["failed"]:
            texts[f] = r["text"]
    for r in problems:
        for f in r["failed"]:
            texts[f] = r["text"]
    real = sorted(set(real))
    under_load = sorted(set(under_load) - set(real))

    ran = sum(r["ran"] for r in results + serial_results) + recovered
    planned = len(ids)
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
    for r in problems:
        print("=" * 70, "\nTASK PROBLEM (%s): %s\n%s" % (r["problem"], r["task"]["name"], r["text"][-3000:]))
    for ident in under_load:
        print("failed under load, passed alone:", ident)
    missing = planned - ran
    if missing and not problems and not real:
        print("the tasks ran %d tests, %d were planned" % (ran, planned))
    print("\nRan %d of %d tests in %.0f s (parallel phase %.0f s), %d failed alone, %d failed only under load, %d task problems" % (
        ran, planned, wall, parallel_wall, len(real), len(under_load), len(problems)))
    bad = bool(real or problems or missing or (args.strict and under_load))
    if not bad and not args.keep:
        shutil.rmtree(root, ignore_errors=True)
    else:
        print("logs and work directory kept in", root)
    print("FAILED" if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
