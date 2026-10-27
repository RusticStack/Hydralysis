import hashlib
import json
import math
import platform
import statistics
import time
from rusticre.crossbuild import match

N = 50000
REPEATS = 11

def rows(destination):
    result = {}
    for i in range(N):
        rva = hex(0x1000 + i * 32 + (16 if destination else 0))
        # Some byte identities survive, some have common shapes and some lack matches.
        identity = i if not destination or i % 5 else i + N
        result[rva] = {
            "bytes": "bytes-%d" % identity if i % 3 == 0 else "common-%d" % (i % 100),
            "shape": "shape-%d" % (identity if i % 4 == 0 else i % 200),
            "size": 32 + (i % 5) * 8,
            "instructions": 8 + i % 7,
            "strings": ["string-%d" % identity] if i % 7 == 0 else [],
            "imports": ["import-%d" % (i % 30)] if i % 11 == 0 else [],
            "constants": [i, i + 1] if i % 13 == 0 else [],
            "heads": [], "callees": [],
        }
    return result

source, destination = rows(False), rows(True)
times = []
expected = None
for repeat in range(REPEATS + 1):
    start = time.perf_counter()
    pairs = match(source, destination)
    elapsed = time.perf_counter() - start
    digest = hashlib.sha256(json.dumps(sorted(pairs.items()), separators=(",", ":")).encode()).hexdigest()
    if expected is not None and digest != expected:
        raise RuntimeError("unstable match output")
    expected = digest
    if repeat:
        times.append(elapsed)
times.sort()
print(json.dumps({"python": platform.python_version(), "platform": platform.platform(), "source_rows": N,
                  "destination_rows": N, "repeats": REPEATS, "warmup": 1,
                  "p50_s": statistics.median(times), "p95_s": times[math.ceil(.95 * len(times))-1],
                  "samples_s": times, "matches": len(pairs), "output_sha256": expected}, indent=2))
