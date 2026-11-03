"""The capture writer's cost per agent batch, without Frida: synthetic batches through `TraceSource.on_batch`.

    python benchmarks/trace_pump_bench.py [--batches 60] [--records 2900] [--rounds 3] [--label run]

Reports, per round and as the median over rounds: process CPU and wall per record, the time a callback holds the caller
(the time before the agent's acknowledgement), the share of a concurrent pure-Python spinner's throughput that survives
(GIL availability while batches are written; 1.0 = the callback never blocks other Python threads), and peak working set.
The spinner is the stand-in for Frida's own message thread and the rest of the worker. Set HYDRALYSIS_NATIVE=0 for the
Python twin of the encoder and writer.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hydralysis import trace_wire as tw  # noqa: E402
from hydralysis.trace_capture import TraceSource  # noqa: E402

SITES = {
    1: {"name": "CreateFileW", "kind": "call", "module": "kernel32.dll", "va": 0x7FF800001000, "buf": "id"},
    2: {"name": "frame_tick", "kind": "call", "module": "game.exe", "va": 0x140001000},
    3: {"name": "fx_frame_begin", "kind": "event", "module": "frameloop.exe", "va": 0x140001100, "event": "app.frame", "hook": "frame-begin",
        "fields": [{"name": "frame", "type": "u64", "source": "0"}]},
}


def make_batches(count: int, per: int, gen: int = 1) -> list[bytes]:
    out, seq = [], 0
    for b in range(count):
        records = []
        for i in range(per):
            site = (1, 2, 3, 2)[i % 4]
            rec = {"site": site, "ring": i % 4, "ring_seq": seq // 4 if False else 0, "qpc": 1000 + b * per + i, "tid": 100 + i % 4,
                   "ret_addr": 0x140002000, "qpc_end": 1000 + b * per + i + 30, "retval": i, "flags": tw.F_RET, "args": [i, 2, 3, 4]}
            if site == 1:
                rec["flags"] |= tw.F_WIDE
                rec["buf"] = (r"C:\data\file%d.bin" % (i % 50)).encode("utf-16le") + b"\0\0"
                rec["buf_addr"] = 0x1000
            records.append(rec)
        # per-ring sequence numbers must be contiguous across batches
        for ring in range(4):
            for n, rec in enumerate([r for r in records if r["ring"] == ring]):
                rec["ring_seq"] = b * (per // 4) + n
        out.append(tw.build_batch(gen, b, 2000 + b, (per * (b + 1), 0, 0, 0), records))
    return out


def rss_peak() -> int:
    import ctypes
    from ctypes import wintypes

    class PMC(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("a", ctypes.c_size_t), ("b", ctypes.c_size_t), ("c", ctypes.c_size_t),
                    ("d", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    info = PMC()
    info.cb = ctypes.sizeof(info)
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
    ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(info), info.cb)
    return int(info.PeakWorkingSetSize)


def spin_rate(seconds: float) -> float:
    stop = threading.Event()
    threading.Timer(seconds, stop.set).start()
    n, start = 0, time.perf_counter()
    while not stop.is_set():
        n += 1
    return n / (time.perf_counter() - start)


def _unused_spin_rate(seconds: float) -> float:
    n, end = 0, time.perf_counter() + seconds
    while time.perf_counter() < end:
        n += 1
    return n / seconds


def one_round(batches: list[bytes], work: Path, baseline: float, spin: bool) -> dict:
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    src = TraceSource(work, session="bench", producer_gen=1, process_id=4242, sites=SITES, qpc_freq=10_000_000, key=b"k" * 32)
    src.on_ready({"context": "bench", "installed": []})
    stop, count = threading.Event(), [0]

    def spinner():
        n = 0
        while not stop.is_set():
            n += 1
        count[0] = n
    thread = threading.Thread(target=spinner)
    holds = []
    if spin:
        thread.start()
    cpu0, wall0 = time.process_time(), time.perf_counter()
    for data in batches:
        t0 = time.perf_counter()
        reply = src.on_batch(data)
        holds.append(time.perf_counter() - t0)
        assert reply["ok"], reply
    health = src.finalize()
    wall = time.perf_counter() - wall0
    cpu = time.process_time() - cpu0
    stop.set()
    if spin:
        thread.join()
    verify = src.verify()
    records = health["records"]
    return {"cpu_us_per_record": cpu * 1e6 / records, "wall_us_per_record": wall * 1e6 / records, "records": records,
            "hold_ms_median": statistics.median(holds) * 1e3, "hold_ms_max": max(holds) * 1e3,
            "spinner_share": (count[0] / wall) / baseline if spin else None, "segment_bytes": health["writer"]["bytes"],
            "verify": verify["outcome"], "head": health["head"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batches", type=int, default=60)
    parser.add_argument("--records", type=int, default=2900)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--label", default="run")
    parser.add_argument("--out", default="")
    options = parser.parse_args()
    batches = make_batches(options.batches, options.records)
    baseline = spin_rate(0.5)
    base = Path(options.out or tempfile.mkdtemp(prefix="trace-pump-bench-"))
    rounds = [one_round(batches, base / ("r%d" % i), baseline, False) for i in range(options.rounds)]
    spun = [one_round(batches, base / ("s%d" % i), baseline, True) for i in range(options.rounds)]
    out = {"label": options.label, "native": os.environ.get("HYDRALYSIS_NATIVE", "1") != "0", "rounds": rounds,
           "median": {k: statistics.median(r[k] for r in rounds) for k in rounds[0] if isinstance(rounds[0][k], (int, float))},
           "spinner_share_median": statistics.median(r["spinner_share"] for r in spun),
           "hold_ms_with_spinner_median": statistics.median(r["hold_ms_median"] for r in spun),
           "peak_rss_mb": rss_peak() / 1048576, "heads_equal": len({r["head"] for r in rounds}) == 1,
           "all_clean": all(r["verify"] == "clean" for r in rounds + spun)}
    print(json.dumps(out, indent=1))
    shutil.rmtree(base, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
