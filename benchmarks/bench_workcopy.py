"""CPU time and peak working set of the working-copy, warm-worker and user-script code, Python against Rust.

    python benchmarks/bench_workcopy.py                    # all workloads, 7 runs each, both implementations
    python benchmarks/bench_workcopy.py -n 3 -w edit      # one workload, 3 runs
    python benchmarks/bench_workcopy.py --impl rust       # only HYDRALYSIS_IMPL=rust
    python benchmarks/bench_workcopy.py --impl rust-hosted  # also edit/revert/add_proposals through Rust (opt-in)

Every run is a fresh child process (`--child`), so the numbers are cold-start, per-process ones: user+kernel CPU of the
workload alone (`time.process_time()` around it) and the peak working set of the whole process (`PeakWorkingSetSize`),
plus the working set before the workload started, so the growth is visible. The report prints the median of the runs.

Workloads
  edit      a view with BIG_STORE records: 40 `workcopy.edit`, 10 `workcopy.revert`, `summary` and `changes`. The engine
            (`_sync`, `heal`) is the same stub for both; everything else is the code under test.
  files     `store_archive` + `verify_archive` + `store_corpus` of a 192 MiB file.
  viewpool  200 sequential dispatches of a job to a warm stub worker (the worker is idle for each); CPU is the dispatching
            process's, threads included.
  scripts   `userscripts.list_scripts` over 1500 scripts, 30 times, and 60 `check_options`.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
BIG_STORE = 3000
STUB = r'''
import json, os, sys
PREFIX = b"@hydralysis-viewpool "
def say(**message):
    sys.stdout.buffer.write(PREFIX + json.dumps(message).encode("ascii") + b"\n")
    sys.stdout.buffer.flush()
say(ready=True, pid=os.getpid())
for line in sys.stdin.buffer:
    message = json.loads(line)
    if message.get("stop"):
        break
    say(done=True)
'''


# ---- measuring --------------------------------------------------------------------------------------------------------

class _Counters(ctypes.Structure):
    _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong), ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def memory() -> tuple[int, int]:
    """(working set, peak working set) of this process in bytes."""
    counters = _Counters()
    counters.cb = ctypes.sizeof(counters)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Counters), ctypes.c_ulong]
    psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
    return counters.WorkingSetSize, counters.PeakWorkingSetSize


# ---- the workloads (child side) ---------------------------------------------------------------------------------------

def settings_of(root: Path) -> dict:
    return {"root": str(root)}


def prepare_edit(root: Path) -> None:
    """A view with BIG_STORE records, written by the Python implementation."""
    sys.path.insert(0, str(REPOSITORY / "src"))
    from hydralysis import workcopy
    target = {"key": "bench", "sha256": "ab" * 32, "name": "bench", "program": "bench", "gpr": "x.gpr"}
    settings = settings_of(root)
    store = workcopy.load_store(settings, target)
    edits, journal = [], []
    for number in range(1, BIG_STORE + 1):
        address = "0x%x" % (0x401000 + number * 16)
        edits.append({"id": "%032x" % number, "address": address, "seq": number, "by": {"client": "bench", "harness": "bench"}, "at": 1.5,
                      "options": {"kind": "rename", "source": "bench", "name": "n%d" % number},
                      "effects": [{"subject": "address:" + address, "field": "name", "before": "a", "after": "n%d" % number}]})
        journal.append({"revision": number, "op": "edit", "subjects": ["address:" + address], "by": {"client": "bench"}, "at": 1.5})
    store.update(edits=edits, revision=BIG_STORE, journal=journal[-200:])
    workcopy._save_store(settings, target, store)


def run_edit(root: Path) -> dict:
    from hydralysis import workcopy

    def sync(settings, target, store, timeout_s, extra=None, **kwargs):
        effects = {r["id"]: [{"subject": "address:" + r["address"], "field": "name", "before": "a", "after": r["options"]["name"]}]
                   for r in extra or []}
        return {"fork_gpr": "", "effects": effects, "last_sync": {"n": len(extra or [])}}

    workcopy._sync = sync
    workcopy.heal = lambda settings, target: False
    target = {"key": "bench", "sha256": "ab" * 32, "name": "bench", "program": "bench", "gpr": "x.gpr"}
    settings = settings_of(root)
    started = time.process_time()
    revision = workcopy.load_store(settings, target)["revision"]
    ids = []
    for number in range(40):
        result = workcopy.edit(settings, None, target, "0x%x" % (0x900000 + number * 16),
                               {"kind": "rename", "source": "bench", "name": "fresh%d" % number, "expect_revision": revision}, 30)
        revision = result["revision"]
        ids.append(result["overlay_id"])
    for ident in ids[:10]:
        revision = workcopy.revert(settings, target, [ident], revision)["revision"]
    summary = workcopy.summary(settings, target)
    changes = workcopy.changes(settings, target, since=BIG_STORE - 5)
    return {"cpu": time.process_time() - started, "check": [revision, summary["edits"], len(changes["changes"])],
            "routed": os.environ.get("HYDRALYSIS_ROUTE_HOSTED") == "1" and os.environ.get("HYDRALYSIS_IMPL") == "rust"}


def run_files(root: Path) -> dict:
    from hydralysis import workcopy
    source = root / "big.bin"
    block = bytes(range(256)) * 4096
    with source.open("wb") as handle:
        for _ in range(192):
            handle.write(block)
    settings = settings_of(root / "data")
    started = time.process_time()
    digest, size = workcopy.store_archive(settings, str(source))
    workcopy.verify_archive(workcopy.archive_path(settings, digest), digest, size)
    corpus, _ = workcopy.store_corpus(settings, str(source))
    return {"cpu": time.process_time() - started, "check": [digest[:12], size, corpus[:12]], "routed": hasattr(workcopy.store_archive, "python_function")}


def run_viewpool(root: Path) -> dict:
    from hydralysis import viewpool
    stub = root / "stub.py"
    stub.write_text(STUB, encoding="utf-8")
    viewpool.command = lambda: [sys.executable, str(stub)]
    job = root / "job.json"
    job.write_text("{}", encoding="utf-8")
    env = dict(os.environ)
    started = time.process_time()
    delivered = 0
    for _ in range(200):
        for _ in range(500):
            if viewpool.dispatch(job, env, 1):
                delivered += 1
                break
            time.sleep(0.002)
        time.sleep(0.01)
    cpu = time.process_time() - started
    routed = isinstance(viewpool._POOL, viewpool.NativePool)
    viewpool.close_all()
    time.sleep(0.5)
    return {"cpu": cpu, "check": [delivered], "routed": routed}


def run_scripts(root: Path) -> dict:
    from hydralysis import userscripts, viewnative
    from hydralysis import targets
    folder = root / "scripts"
    folder.mkdir()
    for number in range(1500):
        (folder / ("S%04d.java" % number)).write_text("// header\n// Usage: S%04d <address> [flags]\nclass S {}\n" % number, encoding="utf-8")
    settings = settings_of(root)
    targets.resolve = lambda settings, name: {"name": name, "scripts": str(folder)}
    started = time.process_time()
    text = ""
    for _ in range(30):
        text = userscripts.list_scripts(settings, "t", "S01")
    for _ in range(60):
        userscripts.check_options({"isolation": "private", "readonly": True})
    return {"cpu": time.process_time() - started, "check": [len(text.splitlines())], "routed": os.environ.get("HYDRALYSIS_IMPL") == "rust" and viewnative.native_views() is not None}


WORKLOADS = {"edit": run_edit, "files": run_files, "viewpool": run_viewpool, "scripts": run_scripts}


def child(name: str, root: Path) -> None:
    sys.path.insert(0, str(REPOSITORY / "src"))
    import hydralysis.workcopy  # noqa: F401 - imported before the baseline reading: the import cost is not the workload's
    import hydralysis.userscripts  # noqa: F401
    import hydralysis.viewpool  # noqa: F401
    before, _ = memory()
    result = WORKLOADS[name](root)
    _, peak = memory()
    print(json.dumps({**result, "ws_before_mib": before / 2**20, "peak_mib": peak / 2**20}))


# ---- the driver -------------------------------------------------------------------------------------------------------

def one(name: str, impl: str, template: Path | None, scratch: Path) -> dict:
    root = scratch / ("run-%s-%d" % (impl, time.monotonic_ns()))
    if template is not None:
        shutil.copytree(template, root)
    else:
        root.mkdir(parents=True)
    env = {key: value for key, value in os.environ.items() if not key.startswith("HYDRALYSIS_")}
    env.update(PYTHONPATH=os.pathsep.join([str(REPOSITORY / "src"), str(REPOSITORY / "tests")]), PYTHONIOENCODING="utf-8")
    if impl in ("rust", "rust-hosted"):
        env["HYDRALYSIS_IMPL"] = "rust"
    if impl == "rust-hosted":
        env["HYDRALYSIS_ROUTE_HOSTED"] = "1"  # edit/revert through Rust (opt-in: it measured slower)
    done = subprocess.run([sys.executable, "-I", "-X", "utf8", str(Path(__file__).resolve()), "--child", name, str(root)],
                          env=env, capture_output=True, text=True, timeout=600, cwd=str(scratch))
    shutil.rmtree(root, ignore_errors=True)
    if done.returncode:
        raise SystemExit("child failed (%s %s):\n%s" % (name, impl, done.stderr[-2000:]))
    return json.loads(done.stdout.strip().splitlines()[-1])


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        child(sys.argv[2], Path(sys.argv[3]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-n", type=int, default=7, help="runs per workload and implementation")
    parser.add_argument("-w", action="append", choices=list(WORKLOADS), help="workload (default: all)")
    parser.add_argument("--impl", action="append", choices=["python", "rust", "rust-hosted"], help="implementation (default: python and rust)")
    parser.add_argument("--scratch", default=str(Path(tempfile.gettempdir()) / "bench-workcopy"))
    args = parser.parse_args()
    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    rows = {}
    for name in args.w or list(WORKLOADS):
        template = None
        if name == "edit":
            template = scratch / "template-edit"
            shutil.rmtree(template, ignore_errors=True)
            template.mkdir(parents=True)
            subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r); sys.path.insert(0, %r); "
                            "import benchmarks.bench_workcopy as b; from pathlib import Path; b.prepare_edit(Path(%r))"
                            % (str(REPOSITORY), str(REPOSITORY / "src"), str(template))], check=True, cwd=str(REPOSITORY))
        for impl in args.impl or ["python", "rust"]:
            runs = [one(name, impl, template, scratch) for _ in range(args.n)]
            rows[(name, impl)] = runs
            cpu = statistics.median(run["cpu"] for run in runs)
            peak = statistics.median(run["peak_mib"] for run in runs)
            growth = statistics.median(run["peak_mib"] - run["ws_before_mib"] for run in runs)
            print("%-9s %-6s cpu %8.3f s   peak WS %7.1f MiB   growth %6.1f MiB   routed=%s   check=%s"
                  % (name, impl, cpu, peak, growth, runs[0]["routed"], runs[0]["check"]), flush=True)
    print(json.dumps({"%s/%s" % key: runs for key, runs in rows.items()}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
