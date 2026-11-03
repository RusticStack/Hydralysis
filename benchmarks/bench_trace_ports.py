"""Time and peak memory of the trace ports (`pair_report`, `link_events`): Python versus HYDRALYSIS_IMPL=rust.

Method: each (function, size, implementation) runs in a fresh child process so one run's heap cannot colour the next.
The child builds its input with a fixed seed, calls the function once to warm up, then REPEAT times, and prints the
median wall time, the median process CPU time and the peak working set (Windows `PeakWorkingSetSize`, which includes the
interpreter and the input). The input is built before the timer starts; its size is the same in both children, so the
difference between the two peak working sets is the cost of the implementation. Usage:

    PYTHONPATH=src;tests python benchmarks/bench_trace_ports.py [--repeat 5]
"""

import argparse
import ctypes
import json
import os
import random
import statistics
import subprocess
import sys
import time
from ctypes import wintypes


def peak_working_set() -> int:
    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t)]
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    kernel32, psapi = ctypes.WinDLL("kernel32"), ctypes.WinDLL("psapi")
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    if not psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        raise OSError("GetProcessMemoryInfo failed")
    return counters.PeakWorkingSetSize


def pair_input(size: int):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
    import test_rust_parity_pairing as t
    rng = random.Random(1)
    return t.session(rng, objects=max(2, size // 400), per_object=400, drift=1.0001, markers=8, dropped=0.1, ints=True, gap=True)


def link_input(size: int):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
    import test_rust_parity_bindings as t
    rng = random.Random(1)
    return t.trace(rng, size), t.table(rng)


def child(function: str, size: int, repeat: int) -> None:
    from hydralysis import trace_bindings, trace_pairing
    if function == "pair_report":
        owner, replica = pair_input(size)
        call = lambda: trace_pairing.pair_report(owner, replica, None)  # noqa: E731
    else:
        events, table = link_input(size)
        call = lambda: trace_bindings.link_events(events, table)  # noqa: E731
    answer = call()
    wall, cpu = [], []
    for _ in range(repeat):
        w, c = time.perf_counter(), time.process_time()
        call()
        wall.append(time.perf_counter() - w)
        cpu.append(time.process_time() - c)
    print(json.dumps({"wall_ms": statistics.median(wall) * 1000, "cpu_ms": statistics.median(cpu) * 1000,
                      "peak_mb": peak_working_set() / 2 ** 20, "digest": hash(json.dumps(answer)) & 0xFFFF}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--child", nargs=2, metavar=("FUNCTION", "SIZE"))
    args = parser.parse_args()
    if args.child:
        child(args.child[0], int(args.child[1]), args.repeat)
        return
    print("%-12s %8s %8s %10s %10s %9s  same-answer" % ("function", "size", "impl", "wall ms", "cpu ms", "peak MB"))
    for function, sizes in (("pair_report", (2000, 20000, 100000)), ("link_events", (5000, 50000, 300000))):
        for size in sizes:
            results = {}
            for impl in ("python", "rust"):
                env = dict(os.environ, HYDRALYSIS_IMPL="rust" if impl == "rust" else "python", PYTHONHASHSEED="0")
                out = subprocess.run([sys.executable, __file__, "--child", function, str(size), "--repeat", str(args.repeat)],
                                     env=env, capture_output=True, text=True, check=True).stdout
                results[impl] = json.loads(out.strip().splitlines()[-1])
                r = results[impl]
                print("%-12s %8d %8s %10.1f %10.1f %9.1f" % (function, size, impl, r["wall_ms"], r["cpu_ms"], r["peak_mb"]))
            print("%-12s %8d %8s speed-up x%.2f  same answer: %s" % (function, size, "", results["python"]["wall_ms"] / results["rust"]["wall_ms"],
                                                                  results["python"]["digest"] == results["rust"]["digest"]))


if __name__ == "__main__":
    main()
