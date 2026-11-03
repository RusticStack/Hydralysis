"""A sealed or atomic write is never seen empty or torn: writer processes, reader threads, one COMPLETE.json-like path.

Runs under whichever implementation HYDRALYSIS_IMPL selects (the Rust twin is rust/crates/hy-core/tests/atomic_stress.rs).
HYDRALYSIS_STRESS_SECS sets the duration (default 3); the work directory follows HYDRALYSIS_TEST_ROOT, so running it with
the root on D: and on E: compares the disks. The slow-disk cases add threads that write and fsync 4 MiB files beside it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from support import REPOSITORY, workdir

SECONDS = float(os.environ.get("HYDRALYSIS_STRESS_SECS", "3"))
WRITERS = 3
READERS = 4

WRITER = r"""
import os, sys, time
from pathlib import Path
from hydralysis import durable
path, kind, index, stop = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), Path(sys.argv[4])
n = index * 1_000_000
started = time.monotonic()
try:
    while not stop.exists():
        n += 1
        if kind == "sealed":
            durable.write_sealed(path, {"gpr": "E:/work/base-%d/x.gpr" % n, "generation": n, "pad": "p" * (n % 5000)})
        else:
            length = 1 + (n * 2654435761) % 70000
            durable.atomic_write(path, length.to_bytes(4, "little") + bytes([n % 251 + 1]) * (length + 1))
except BaseException as error:
    sys.exit("writer %d: %r after %d writes and %.1f s" % (index, error, n - index * 1_000_000, time.monotonic() - started))
"""


def sealed_record(n: int) -> dict:
    return {"gpr": "E:/work/base-%d/x.gpr" % n, "generation": n, "pad": "p" * (n % 5000)}


def blob_problem(data: bytes) -> str | None:
    if len(data) < 5:
        return "%d bytes" % len(data)
    length = int.from_bytes(data[:4], "little")
    if len(data) != length + 5:
        return "declares %d body bytes, has %d" % (length, len(data) - 5)
    if data[5:].count(data[4:5]) != length:
        return "mixed bytes"
    return None


class Stress(unittest.TestCase):
    maxDiff = None

    def run_case(self, kind: str, noisy: int) -> None:
        from hydralysis import durable
        work = workdir("stress-" + kind)
        self.addCleanup(work.cleanup)
        folder = Path(work.name)
        target = folder / "COMPLETE.json"
        stop = folder / "stop"
        if kind == "sealed":
            durable.write_sealed(target, sealed_record(0))
        else:
            durable.atomic_write(target, (0).to_bytes(4, "little") + b"\x01" * 1)
        env = dict(os.environ, PYTHONPATH=str(REPOSITORY / "src"))
        writers = [subprocess.Popen([sys.executable, "-c", WRITER, str(target), kind, str(index), str(stop)], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) for index in range(1, WRITERS + 1)]
        halt = threading.Event()
        bad: list[str] = []
        counts = {"reads": 0, "transient": 0}

        def read_loop():
            while not halt.is_set():
                counts["reads"] += 1
                try:
                    if kind == "sealed":
                        value, source = durable.read_sealed_info(target)
                        if source != "file":
                            bad.append("the reader needed %r" % (source,))
                        elif value != sealed_record(value["generation"]):
                            bad.append("not any version written: %r" % (str(value)[:80],))
                    else:
                        problem = blob_problem(durable.read_bytes(target))
                        if problem:
                            bad.append("torn atomic_write blob: " + problem)
                except durable.StoreCorrupt as error:
                    bad.append("StoreCorrupt for a reader: %s" % str(error)[:300])
                except PermissionError:
                    counts["transient"] += 1
                except FileNotFoundError as error:
                    bad.append("the file vanished during a replace: %s" % error)

        def noise_loop(index: int):
            block = b"\xa5" * (4 * 1024 * 1024)
            path = folder / ("noise-%d.bin" % index)
            while not halt.is_set():
                with open(path, "wb") as handle:
                    handle.write(block)
                    handle.flush()
                    os.fsync(handle.fileno())

        threads = [threading.Thread(target=read_loop) for _ in range(READERS)]
        threads += [threading.Thread(target=noise_loop, args=(index,)) for index in range(noisy)]
        for thread in threads:
            thread.start()
        time.sleep(SECONDS)
        stop.write_text("x")
        halt.set()
        for thread in threads:
            thread.join(timeout=60)
        errors = []
        for process in writers:
            try:
                _, error = process.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                error = b"writer did not stop"
            if process.returncode:
                errors.append(error.decode(errors="replace")[-400:])
        if not os.environ.get("HYDRALYSIS_IMPL"):
            # The Python reference replaces with MoveFileExW, which Windows refuses (ERROR_ACCESS_DENIED) while a reader holds
            # the file open, so a writer can give up after its 10 s retry budget under readers that always have it open. A
            # refused write is not a torn read; the Rust replace (POSIX-semantics rename) has no such limit and is held to it.
            errors = [error for error in errors if "PermissionError" not in error]
        print("%s noisy=%d impl=%s: %d reads, %d transient read errors, root %s" % (
            kind, noisy, os.environ.get("HYDRALYSIS_IMPL") or "python", counts["reads"], counts["transient"], folder.parent))
        self.assertEqual(bad[:5], [])
        self.assertEqual(errors, [])
        self.assertGreater(counts["reads"], 0)

    def test_write_sealed_is_never_seen_empty_or_torn(self):
        self.run_case("sealed", 0)

    def test_atomic_write_is_never_seen_empty_or_torn(self):
        self.run_case("atomic", 0)

    def test_write_sealed_on_a_slow_disk(self):
        self.run_case("sealed", 3)

    def test_atomic_write_on_a_slow_disk(self):
        self.run_case("atomic", 3)


if __name__ == "__main__":
    unittest.main()
