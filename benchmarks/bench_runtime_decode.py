"""Time and peak memory of the runtime_decode port: Python versus HYDRALYSIS_IMPL=rust.

Method: as bench_trace_ports.py. Each (function, size, implementation) runs in a fresh child process; the child builds its
input with a fixed seed before the timer, calls the function once to warm up, then REPEAT times and prints the median wall
time, median process CPU time and the peak working set (Windows `PeakWorkingSetSize`, interpreter and input included; the
input is the same in both children). Sizes are the number of events (each carries 3 captures: a utf16 string, a u32 with
names and a 16 byte struct), of layout fields, of normalize calls, or of regions in a snapshot (each 8 fields and 120
characters of bytes, so about 100 rows per 10 regions; a call compares or hashes two snapshots). The digest compares the answers across children.

    PYTHONPATH=src;tests python benchmarks/bench_runtime_decode.py [--repeat 5]
"""

import argparse
import json
import os
import random
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
from bench_trace_ports import peak_working_set  # noqa: E402


def inputs(function: str, size: int):
    from hydralysis import runtime_decode as d
    rng = random.Random(1)
    specs = d._normalize_py([{"arg": 0, "deref": [8], "as": "utf16", "size": 32},
                             {"arg": 1, "as": "u32", "names": {"0x2a": "answer", "7": "seven"}},
                             {"arg": 2, "deref": [0], "as": "struct", "fields": [
                                 {"name": "x", "offset": 0, "type": "float"}, {"name": "id", "offset": 4, "type": "uint32"},
                                 {"name": "p", "offset": 8, "type": "Thing *"}]}])
    if function == "decode_event":
        events = [[{"pointer": hex(rng.randrange(1 << 40)), "hex": ("name%d" % rng.randrange(1000)).encode("utf-16-le").hex() + "0000" * 4},
                   {"pointer": "0x2a", "hex": rng.randrange(60).to_bytes(4, "little").hex()},
                   {"pointer": "0x9", "hex": rng.randbytes(16).hex()}] for _ in range(size)]
        return lambda: [d.decode_event(specs, event) for event in events]
    if function == "layout_values":
        fields = [{"name": "f%d" % i, "offset": (i * 8) % 96, "type": rng.choice(["int", "u64", "float", "Thing *", "u8", "Blob"]),
                   "names": {"0": "zero", "1": "one"}} for i in range(size)]
        data = rng.randbytes(128)
        return lambda: d.layout_values(fields, data)
    if function in ("compare", "stable_sha256"):
        import test_rust_parity_runtime as t
        from hydralysis import runtime_snapshot as snap
        a = t.snapshot_record(rng, scale=1)
        a["regions"] = {"r%d" % i: {"address": hex(i), "range": {"base": hex(i), "size": 64},
                                    "bytes": "".join(rng.choice("0123456789ABCDEF ") for _ in range(120)),
                                    "fields": [{"name": "f%d" % k, "value": rng.randrange(1000), "type": "u32"} for k in range(8)]}
                        for i in range(size)}
        b = t.mutate(rng, a)
        for key in list(b["regions"])[::7]:
            b["regions"][key]["fields"][0]["value"] += 1
        if function == "compare":
            return lambda: snap.compare(a, b)
        return lambda: snap.stable_sha256(a, ("regions/*/bytes",))
    captures = [[{"arg": i % 8, "deref": [8, 16], "as": "utf8", "size": 64, "label": "n%d" % i},
                 {"arg": 1, "as": "u32", "names": {"0x2a": "answer", "7": "seven"}}] for i in range(size)]
    return lambda: [d.normalize(c) for c in captures]


def child(function: str, size: int, repeat: int) -> None:
    call = inputs(function, size)
    answer = call()
    wall, cpu = [], []
    for _ in range(repeat):
        w, c = time.perf_counter(), time.process_time()
        call()
        wall.append(time.perf_counter() - w)
        cpu.append(time.process_time() - c)
    from hydralysis import runtime_decode as d
    print(json.dumps({"wall_ms": statistics.median(wall) * 1000, "cpu_ms": statistics.median(cpu) * 1000,
                      "peak_mb": peak_working_set() / 2 ** 20, "routed": hasattr(d.normalize, "rust_function") or hasattr(__import__("hydralysis.runtime_snapshot", fromlist=["x"]).compare, "rust_function"),
                      "digest": __import__("hashlib").sha256(json.dumps(answer).encode()).hexdigest()[:12]}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--child", nargs=2, metavar=("FUNCTION", "SIZE"))
    args = parser.parse_args()
    if args.child:
        child(args.child[0], int(args.child[1]), args.repeat)
        return
    print("%-14s %8s %8s %10s %10s %9s" % ("function", "size", "impl", "wall ms", "cpu ms", "peak MB"))
    for function, sizes in (("decode_event", (1000, 20000, 200000)), ("layout_values", (100, 2000, 50000)),
                            ("normalize", (1000, 20000, 200000)), ("compare", (10, 200, 5000)), ("stable_sha256", (10, 200, 5000))):
        for size in sizes:
            results = {}
            for impl in ("python", "rust"):
                env = dict(os.environ, HYDRALYSIS_IMPL="rust" if impl == "rust" else "python", HYDRALYSIS_RUNTIME_HELD="1", PYTHONHASHSEED="0")
                out = subprocess.run([sys.executable, __file__, "--child", function, str(size), "--repeat", str(args.repeat)],
                                     env=env, capture_output=True, text=True, check=True).stdout
                results[impl] = json.loads(out.strip().splitlines()[-1])
                r = results[impl]
                print("%-14s %8d %8s %10.1f %10.1f %9.1f%s" % (function, size, impl, r["wall_ms"], r["cpu_ms"], r["peak_mb"],
                                                                 "" if impl == "python" or r["routed"] else "  NOT ROUTED"))
            print("%-14s %8d %8s speed-up x%.2f  same answer: %s" % (function, size, "", results["python"]["wall_ms"] / results["rust"]["wall_ms"],
                                                                   results["python"]["digest"] == results["rust"]["digest"]))


if __name__ == "__main__":
    main()
