"""Warm MCP call latency through the real stdio server (rows C1-02, C1-03, C1-15 reply sizes).

    python benchmarks/mcp_latency.py --engine <dir> --client <ghidra_session.py> --root <fresh folder> --out <logs> --runs 30

Spawns `python -m hydralysis mcp` against a prepared target (the default fixture is the system whoami.exe; pass a COPY
of the real program with --binary for the owner's figure), discards warm-up calls, then makes at least 30 warm calls
each of `function` (offline PE tool), `ghidra_query` decompile of one pinned function and `ghidra_query` status. Records
median, p95 and maximum in milliseconds, the reply size in bytes, the function address and size, the engine release,
the program SHA-256, the file system and the foreign load. Budgets are report-only.

This module also holds the helpers the other four benchmark scripts import (they use `import mcp_latency as common`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path

# ---- shared helpers (used by every benchmark script) ----
HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

BUDGETS = HERE / "budgets.json"
BUDGET_FACTOR = 3
# The original KotOR project must never be opened by an engine; a copy goes to a scratch folder first.
FORBIDDEN = ("f:/dev-cache/hydra-projects/kotor",)


def summarize(samples: list[float]) -> dict:
    """Median, p95 and maximum of SAMPLES (any unit), plus the count."""
    if not samples:
        return {"n": 0, "median": None, "p95": None, "max": None, "min": None}
    ordered = sorted(samples)
    return {"n": len(ordered), "median": statistics.median(ordered), "min": ordered[0],
            "p95": ordered[max(0, math.ceil(.95 * len(ordered)) - 1)], "max": ordered[-1]}


def sha256_of(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def file_system(path: str | Path) -> str | None:
    """The file system name of the volume holding PATH (NTFS, ReFS, ...), or None when unknown."""
    if os.name != "nt":
        return None
    import ctypes
    drive = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
    name = ctypes.create_unicode_buffer(64)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(ctypes.c_wchar_p(drive), None, 0, None, None, None, name, 64)
    return name.value if ok else None


def _processes() -> dict:
    """Counts of the processes that matter for foreign load, and the machine's CPU load percentage."""
    counts: dict = {}
    if os.name == "nt":
        try:
            out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, errors="replace", timeout=30).stdout
            for line in out.splitlines():
                name = line.split('","')[0].strip('"').lower()
                if name in ("java.exe", "python.exe", "gradle.exe", "node.exe", "cl.exe", "link.exe", "msbuild.exe"):
                    counts[name] = counts.get(name, 0) + 1
        except (OSError, subprocess.SubprocessError):
            counts = {}
        cpu = None
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average"],
                                 capture_output=True, text=True, errors="replace", timeout=60).stdout.strip()
            cpu = float(out) if out else None
        except (OSError, subprocess.SubprocessError, ValueError):
            cpu = None
        return {"processes": counts, "cpu_load_percent": cpu}
    try:
        return {"processes": counts, "cpu_load_percent": os.getloadavg()[0]}
    except (OSError, AttributeError):
        return {"processes": counts, "cpu_load_percent": None}


def foreign_load() -> dict:
    """A sample of the load that is not ours. Taken before and after a run; compare the two."""
    return {**_processes(), "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "own_pid": os.getpid()}


def machine() -> dict:
    return {"node": platform.node(), "platform": platform.platform(), "python": platform.python_version(),
            "cpu_count": os.cpu_count(), "processor": platform.processor()}


def refuse_original(path: str | Path) -> None:
    text = str(Path(path).resolve()).replace("\\", "/").lower()
    for forbidden in FORBIDDEN:
        if text.startswith(forbidden):
            raise SystemExit("refusing to use %s: copy the original to a scratch folder and pass the copy" % path)


def load_budgets() -> dict:
    try:
        return json.loads(BUDGETS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"factor": BUDGET_FACTOR, "entries": {}}


def judge(key: str, value: float | None, budgets: dict | None = None) -> dict:
    """Compare VALUE with the recorded median and budget of KEY. Report-only: the result never changes an exit code."""
    budgets = budgets if budgets is not None else load_budgets()
    entry = (budgets.get("entries") or {}).get(key)
    if value is None:
        return {"key": key, "value": None, "status": "no-value"}
    if not entry or entry.get("median") is None:
        return {"key": key, "value": value, "status": "unrecorded"}
    budget = entry.get("budget") or entry["median"] * budgets.get("factor", BUDGET_FACTOR)
    return {"key": key, "value": value, "recorded_median": entry["median"], "budget": budget,
            "status": "within" if value <= budget else "over-budget (report-only)"}


def output_dir(arg: str | None) -> Path:
    """`--out`, else $HYDRA_BENCH_OUT, else ./bench-out. The owner passes D:/Projects/Hydra/_logs/<stream>."""
    path = Path(arg or os.environ.get("HYDRA_BENCH_OUT") or "bench-out")
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_report(out: Path, name: str, data: dict) -> Path:
    path = out / ("%s-%s.json" % (name, time.strftime("%Y%m%d-%H%M%S")))
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return path


def common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--out", help="folder for the JSON report (default $HYDRA_BENCH_OUT or ./bench-out)")
    parser.add_argument("--root", help="data root of the measurement (a fresh folder on the file system to measure)")
    parser.add_argument("--engine", default=os.environ.get("HYDRALYSIS_INTEGRATION_ENGINE"), help="engine install dir")
    parser.add_argument("--client", default=os.environ.get("HYDRALYSIS_INTEGRATION_CLIENT"), help="ghidra_session.py")
    parser.add_argument("--java", default=os.environ.get("HYDRALYSIS_INTEGRATION_JAVA"), help="JDK home")
    parser.add_argument("--binary", default=os.environ.get("HYDRALYSIS_INTEGRATION_BINARY"),
                        help="PE to prepare (a copy of KotOR for the real figure; the default is the system whoami.exe)")
    parser.add_argument("--unpinned", action="store_true", default=bool(os.environ.get("HYDRALYSIS_INTEGRATION_UNPINNED")),
                        help="allow an engine that is not the release this Hydralysis pins")


def default_binary(arg: str | None) -> Path:
    if arg:
        refuse_original(arg)
        return Path(arg)
    return Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "whoami.exe"


def require_engine(args) -> None:
    if not (args.engine and args.client):
        raise SystemExit("set --engine and --client (or HYDRALYSIS_INTEGRATION_ENGINE / HYDRALYSIS_INTEGRATION_CLIENT)")


def settings_of(args, root: Path) -> dict:
    settings = {"root": str(root / "data"), "hydra_dir": args.engine, "hydra_client": args.client, "hydra_idle_s": 900}
    if args.java:
        settings["java_home"] = args.java
    if args.unpinned:
        settings["hydra_allow_unpinned"] = True
    return settings


def engine_facts(args) -> dict:
    """The engine release: the folder name, the client, and the version string the engine itself reports when it can."""
    facts = {"engine_dir": args.engine, "client": args.client}
    try:
        text = Path(args.client).parent.name
        facts["client_release"] = text
    except (OSError, TypeError):
        pass
    return facts


def prepare(settings: dict, binary: Path, name: str, timeout_s: int = 900):
    """Prepare BINARY under SETTINGS' root once; returns (runner, status). Mirrors the integration tests."""
    from hydralysis import preparation, query
    os.environ["HYDRALYSIS_ROOT"] = settings["root"]
    query._keys.clear()
    job = preparation.prepare(settings, str(binary), name)
    deadline = time.monotonic() + timeout_s
    while True:
        status = preparation.status(settings, job["job_id"])
        if status["state"] not in preparation.ACTIVE or time.monotonic() > deadline:
            break
        time.sleep(1)
    if status["state"] != "done":
        raise SystemExit("prepare did not finish: %s" % json.dumps(status)[:2000])
    return query.QueryRunner(settings), status


def stop_engine(settings: dict) -> None:
    """Stop the daemon this measurement started (and only it: its state dir is under our root)."""
    from hydralysis import hydra
    engine = hydra.Engine(settings)
    try:
        engine.stop(force=True)
    finally:
        daemon = engine.module().Daemon(str(engine.engine_dir), str(hydra.state_dir(settings)), hydra.INSTANCE)
        if daemon.jvm_alive() or daemon.read_endpoint():
            daemon.kill()


def fresh_root(args, label: str) -> Path:
    base = Path(args.root) if args.root else Path(os.environ.get("HYDRA_BENCH_ROOT", "bench-work"))
    root = (base / ("%s-%s" % (label, uuid.uuid4().hex[:8]))).resolve()
    root.mkdir(parents=True)
    return root


def cleanup(root: Path) -> None:
    shutil.rmtree(root, ignore_errors=True)


def body_size(item: dict) -> int:
    """Bytes of a `functions` listing item, from its body ranges ("[start, end]" inclusive, hex)."""
    total = 0
    for part in item.get("body") or []:
        low, _, high = part.strip("[]").partition(",")
        try:
            total += int(high.strip(), 16) - int(low.strip(), 16) + 1
        except ValueError:
            pass
    return total


def sized_functions(runner, target: str, scan: int = 200) -> list[dict]:
    """Up to SCAN functions as {address, size}, largest first (the listing is paged by the saved analysis)."""
    out: list[dict] = []
    cursor = ""
    while len(out) < scan:
        page = json.loads(runner.query(target, "functions", limit=min(200, scan - len(out)), cursor=cursor))
        out.extend({"address": f["address"], "size": body_size(f), "name": f.get("name")} for f in page.get("functions", []))
        cursor = page.get("next_cursor") or ""
        if not cursor:
            break
    return sorted(out, key=lambda item: -item["size"])


class McpClient:
    """The real stdio MCP server (`python -m hydralysis mcp`) as a child process, one JSON message per line."""

    def __init__(self, config: Path, root: str):
        import queue
        import threading
        env = {**os.environ, "HYDRALYSIS_CONFIG": str(config), "HYDRALYSIS_ROOT": root, "PYTHONPATH": str(SRC)}
        self.started = time.perf_counter()
        self.process = subprocess.Popen([sys.executable, "-m", "hydralysis", "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=env, cwd=str(config.parent))
        self.replies: "queue.Queue" = queue.Queue()
        self._ids = 0
        self._lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for line in self.process.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                continue
            self.replies.put(message)

    def request(self, method: str, params: dict | None = None, timeout: float = 600) -> tuple[dict, float, int]:
        """(reply, seconds, reply bytes). Replies are matched by id from the shared queue."""
        import queue
        with self._lock:
            self._ids += 1
            ident = self._ids
        body = {"jsonrpc": "2.0", "id": ident, "method": method}
        if params is not None:
            body["params"] = params
        begin = time.perf_counter()
        self.process.stdin.write((json.dumps(body) + "\n").encode("utf-8"))
        self.process.stdin.flush()
        stash = []
        deadline = begin + timeout
        while True:
            try:
                message = self.replies.get(timeout=max(0.01, deadline - time.perf_counter()))
            except queue.Empty:
                raise TimeoutError("no reply to %s within %ss" % (method, timeout))
            if message.get("id") == ident:
                for other in stash:
                    self.replies.put(other)
                return message, time.perf_counter() - begin, len(json.dumps(message).encode("utf-8"))
            stash.append(message)

    def notify(self, method: str) -> None:
        self.process.stdin.write((json.dumps({"jsonrpc": "2.0", "method": method}) + "\n").encode("utf-8"))
        self.process.stdin.flush()

    def initialize(self) -> float:
        _, seconds, _ = self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                    "clientInfo": {"name": "bench", "version": "1"}})
        self.notify("notifications/initialized")
        return seconds

    def tool(self, name: str, arguments: dict, timeout: float = 600) -> tuple[dict, float, int]:
        return self.request("tools/call", {"name": name, "arguments": arguments}, timeout)

    def close(self) -> None:
        try:
            self.process.stdin.close()
            self.process.wait(timeout=30)
        except Exception:
            self.process.kill()


def write_config(root: Path, settings: dict) -> Path:
    """A config file naming the engine and root, so a spawned MCP server finds the same prepared target."""
    path = root / "bench-config.json"
    path.write_text(json.dumps({k: v for k, v in settings.items() if k != "root"}), encoding="utf-8")
    return path


# ---- the warm MCP latency script ----
WARMUP = 3


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common_arguments(parser)
    parser.add_argument("--runs", type=int, default=30, help="warm calls per tool (the spec asks for at least 30)")
    parser.add_argument("--function", help="address of the pinned function (default: the largest of the first 200)")
    args = parser.parse_args(argv)
    require_engine(args)
    binary = default_binary(args.binary)
    root = fresh_root(args, "mcplat")
    out = output_dir(args.out)
    settings = settings_of(args, root)
    scratch = root / "fixture.exe"
    shutil.copy2(binary, scratch)
    report = {"script": "mcp_latency", "rows": ["C1-02", "C1-03", "C1-15"], "engine": engine_facts(args),
              "machine": machine(), "program_sha256": sha256_of(scratch), "program": binary.name,
              "file_system": file_system(root), "runs": args.runs, "warmup_discarded": WARMUP,
              "load_before": foreign_load(), "tools": {}}
    client = None
    try:
        runner, _ = prepare(settings, scratch, "fixture")
        functions = sized_functions(runner, "fixture")
        pinned = next((f for f in functions if f["address"] == args.function), None) if args.function else functions[0]
        if pinned is None:
            raise SystemExit("function %s is not in the first 200 functions" % args.function)
        report["pinned_function"] = pinned
        client = McpClient(write_config(root, settings), settings["root"])
        report["initialize_s"] = round(client.initialize(), 3)
        calls = {
            "function": ("function", {"exe": str(scratch), "address": pinned["address"]}),
            "ghidra_query.decompile": ("ghidra_query", {"target": "fixture", "action": "decompile", "address": pinned["address"]}),
            "ghidra_query.status": ("ghidra_query", {"target": "fixture", "action": "status"}),
        }
        budgets = load_budgets()
        for label, (tool, arguments) in calls.items():
            errors = 0
            for _ in range(WARMUP):
                client.tool(tool, arguments)
            times, sizes = [], []
            for _ in range(args.runs):
                reply, seconds, size = client.tool(tool, arguments)
                if (reply.get("result") or {}).get("isError") or "error" in reply:
                    errors += 1
                times.append(seconds * 1000)
                sizes.append(size)
            stats = summarize(times)
            report["tools"][label] = {"ms": stats, "reply_bytes": summarize(sizes), "errors": errors,
                                      "budget": judge("mcp_latency.%s.median_ms" % label, stats["median"], budgets)}
        # C1-03: 20 serial decompiles of the pinned function by one client (the owner's 896 ms had no stated function size).
        serial = []
        for _ in range(20):
            _, seconds, _ = client.tool("ghidra_query", {"target": "fixture", "action": "decompile", "address": pinned["address"]})
            serial.append(seconds * 1000)
        report["serial_20_decompiles"] = {"total_ms": round(sum(serial), 1), "per_call_ms": round(sum(serial) / 20, 2),
                                          "function": pinned}
    finally:
        report["load_after"] = foreign_load()
        if client:
            client.close()
        try:
            stop_engine(settings)
        except Exception as exc:
            report["stop_error"] = str(exc)[:300]
        path = write_report(out, "mcp_latency", report)
        print(json.dumps({"report": str(path), "tools": {k: v["ms"] for k, v in report["tools"].items()}}, indent=2))
        cleanup(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
