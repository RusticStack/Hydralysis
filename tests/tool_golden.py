"""Golden replies of the Hydralysis MCP tools, recorded over the stdio wire (test tooling; no product code).

The request plan is tests/data/tool_golden/requests.json. The harness starts one MCP server process, sends
initialize, notifications/initialized and tools/list, then every step in order: one request at a time, waiting
for each reply (the server answers accepted calls concurrently, so a client that pipelines would see replies in
another order). The replies are written as JSON lines with volatile fields masked, so two runs of the same server
on the same machine agree and a different server (a Rust host) can be diffed against the same requests.

    record   start a server, drive the plan, write one JSON line per step
    compare  diff two recordings; exit 1 on any difference
    selfcheck  record twice (determinism) and compare; exit 1 on a difference

    C:\\Python315\\python.exe tests\\tool_golden.py record --out X.jsonl                 # the Python server
    C:\\Python315\\python.exe tests\\tool_golden.py record --out Y.jsonl -- C:\\path\\hydralysis.exe mcp
    C:\\Python315\\python.exe tests\\tool_golden.py compare X.jsonl Y.jsonl

A run needs an analysis engine (Hydra Engine 12.3-hydra.6, default C:/dev-overflow/hydra-engines/final2b/ghidra_12.3_DEV,
or --engine). It writes its own config (hydra_dir, and hydra_allow_unpinned because the engine is not the pinned
hydra.5) and its own root under --data (default D:/Projects/Hydra/_data/h7-toolgolden/runs/<run id>); the run is removed
afterwards unless --keep. The engine is stopped at the end of the plan (backend stop, not recorded).

Masks (applied to every recorded reply; each one is a fixed token so a recording never holds a volatile value):
  path tokens   the run root <ROOT>, run folder <RUN>, work folder <WORK>, engine <ENGINE>, the corpus fixtures
                <FIXTURES>, the repository <REPO>, the Windows folder <SYSROOT>, the config file <CONFIG>; matched
                case-insensitively, with either slash direction.
  key masks     created_at, started_at, updated_at, finished_at, completed_at, ended_at, startedAt, elapsed_s,
                elapsed_ms, duration_s, worker_pid, worker_started_ms, pid, ppid, owner_token, token_sha256, log_path,
                installId, boot_id, created_ms, started_ms, time, timestamp, mtime, heartbeat_at, last_seen,
                script_s, query_s, engine_s, elapsed_run_s, seconds, import_seconds, analysis_started_at (engine clocks),
                progress_tail (a log tail with clock stamps) -> "<masked>"; the same timings inside an error text that
                carries a JSON object -> "<s>".
  id masks      (prepare|export|decompile|overlay|job)-<hex> -> <kind>-<id>; @<16 hex> (agent names) -> @<boot>;
                rusticre:<pid> -> rusticre:<pid>; any 32-hex token -> <token>.
  time masks    an ISO-8601 stamp -> <time>.
  jdk           the JDK folder (a path with a jdk-<version> name) -> <JDK>.
  version       serverInfo.version, _meta environment version and the "Hydralysis x.y.z" of the instructions text ->
                <version> (a Rust host reports its own version; nothing else about the version is masked).
Tool replies whose text is JSON are recorded as the parsed value (key order and whitespace are not compared); other
texts are recorded verbatim after the masks. tools/list is recorded verbatim with its catalog hash and byte size.

Exit codes: 0 ok; 1 difference (compare) or a failed contract (record: catalog epoch != 5, or the tool table
is not under the 9216-byte budget, or initialize and tools/list disagree); 2 usage or harness error.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
CORPUS = HERE / "data" / "tool_golden"
REQUESTS = CORPUS / "requests.json"
FORMAT = "hydralysis-tool-golden/1"
PROTOCOL = "2025-11-25"
CATALOG_EPOCH = 5
CATALOG_BUDGET = 9216
DEFAULT_ENGINE = "C:/dev-overflow/hydra-engines/final2b/ghidra_12.3_DEV"
DEFAULT_DATA = "D:/Projects/Hydra/_data/h7-toolgolden"
JOB_PREFIXES = ("prepare-", "decompile-", "export-", "overlay-", "job-")
ACTIVE_STATES = ("queued", "running", "cancelling", "starting")
STEP_TIMEOUT_S = 150
JOB_WAIT_S = 170

MASK = "<masked>"
MASK_KEYS = frozenset({
    "created_at", "started_at", "updated_at", "finished_at", "completed_at", "ended_at", "startedAt", "elapsed_s",
    "elapsed_ms", "duration_s", "worker_pid", "worker_started_ms", "pid", "ppid", "owner_token", "token_sha256",
    "log_path", "installId", "boot_id", "created_ms", "started_ms", "time", "timestamp", "mtime", "heartbeat_at",
    "last_seen", "script_s", "query_s", "engine_s", "elapsed_run_s", "seconds", "import_seconds",
    "analysis_started_at", "progress_tail",
})
STRING_MASKS = (
    (re.compile(r"\b(prepare|export|decompile|overlay|job)-[0-9a-f]{8,}\b"), r"\1-<id>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"), "<time>"),
    (re.compile(r"@[0-9a-f]{16}\b"), "@<boot>"),
    (re.compile(r"\b[0-9a-f]{32}\b"), "<token>"),
    (re.compile(r"\brusticre:\d+\b"), "rusticre:<pid>"),
    # the JDK the engine runs on (backend inspect: jdk.path); its version stays in the recording
    (re.compile(r"[A-Za-z]:[\\/][^\"]*?jdk-[0-9][^\"\\/]*"), "<JDK>"),
    # timings inside an error text that carries a JSON object (a RuntimeError of the engine)
    (re.compile(r'"(script_s|query_s|engine_s|elapsed_run_s|seconds|import_seconds)": ?[0-9.eE+-]+'), r'"\1": <s>'),
)
VERSION_TEXT = re.compile(r"Hydralysis \d+\.\d+\.\d+")


class HarnessError(RuntimeError):
    pass


# ---- masks -------------------------------------------------------------------------------------------------------

class Paths:
    """Literal path tokens: longest first, case-insensitive, both slash directions."""

    def __init__(self, tokens: dict[str, str]):
        pairs: dict[str, str] = {}
        for token, raw in tokens.items():
            if not raw:
                continue
            normal = os.path.normpath(raw)
            for variant in (normal, normal.replace("\\", "/"), normal.replace("/", "\\")):
                pairs.setdefault(variant.lower(), token)
        ordered = sorted(pairs, key=len, reverse=True)
        self.lookup = pairs
        self.pattern = re.compile("|".join(re.escape(item) for item in ordered), re.IGNORECASE) if ordered else None

    def apply(self, text: str) -> str:
        if self.pattern is None:
            return text
        return self.pattern.sub(lambda match: self.lookup[match.group(0).lower()], text)


def mask_string(text: str, paths: Paths) -> str:
    text = paths.apply(text)
    for pattern, replacement in STRING_MASKS:
        text = pattern.sub(replacement, text)
    return text


def mask(value, paths: Paths):
    if isinstance(value, dict):
        return {key: (MASK if key in MASK_KEYS else mask(item, paths)) for key, item in value.items()}
    if isinstance(value, list):
        return [mask(item, paths) for item in value]
    if isinstance(value, str):
        return mask_string(value, paths)
    return value


def parsed_json(text: str):
    """The parsed JSON value of TEXT when it is a JSON object or array, else None."""
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, (dict, list)) else None


def text_reply(text: str, paths: Paths) -> dict:
    value = parsed_json(text)
    if value is not None:
        return {"json": mask(value, paths)}
    return {"text": mask_string(text, paths)}


def tool_reply(result: dict, paths: Paths) -> dict:
    out = {"isError": bool(result.get("isError", False)),
           "content": [text_reply(str(item.get("text", "")), paths) for item in result.get("content", [])
                       if isinstance(item, dict)]}
    if "structuredContent" in result:
        out["structuredContent"] = mask(result["structuredContent"], paths)
    return out


def initialize_reply(result: dict, paths: Paths) -> dict:
    out = mask(result, paths)
    out["serverInfo"] = {**out.get("serverInfo", {}), "version": "<version>"}
    out["instructions"] = VERSION_TEXT.sub("Hydralysis <version>", out.get("instructions", ""))
    environment = out.get("_meta", {}).get("hydralysis/environment")
    if isinstance(environment, dict) and "version" in environment:
        environment["version"] = "<version>"
    return out


def catalog_of(tools: list) -> dict:
    canonical = json.dumps(tools, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {"hash": hashlib.sha256(canonical.encode("ascii")).hexdigest(),
            "bytes": len(json.dumps(tools).encode("utf-8"))}


# ---- the wire ---------------------------------------------------------------------------------------------------

class Wire:
    def __init__(self, argv: list[str], env: dict, stderr_path: Path):
        self.stderr = open(stderr_path, "wb")
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, env=env)
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in iter(self.proc.stdout.readline, b""):
            self.lines.put(line)
        self.lines.put(None)

    def _send(self, message: dict) -> None:
        try:
            self.proc.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
            self.proc.stdin.flush()
        except OSError as exc:
            raise HarnessError("server stdin closed (exit %s): %s" % (self.proc.poll(), exc))

    def notify(self, method: str, params: dict | None = None) -> None:
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def call(self, ident: int, method: str, params: dict, timeout: float = STEP_TIMEOUT_S) -> dict:
        self._send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessError("no reply to %s (id %d) within %ds" % (method, ident, timeout))
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                raise HarnessError("no reply to %s (id %d) within %ds" % (method, ident, timeout))
            if line is None:
                raise HarnessError("server exited (code %s) before replying to %s" % (self.proc.poll(), method))
            if not line.strip():
                continue
            try:
                message = json.loads(line.decode("utf-8"))
            except ValueError:
                raise HarnessError("stdout is not JSON: %r" % line[:200])
            if message.get("id") == ident and ("result" in message or "error" in message):
                return message

    def close(self) -> int:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            code = self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise HarnessError("server did not exit after stdin closed; killed")
        self.stderr.close()
        return code


# ---- the plan ---------------------------------------------------------------------------------------------------

def resolve(value, context: dict):
    """Placeholders ({NAME}) and step references ($ref:<step>.<key>) in a declared value."""
    if isinstance(value, dict):
        return {key: resolve(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve(item, context) for item in value]
    if isinstance(value, str):
        if value.startswith("$ref:"):
            step, _, key = value[5:].partition(".")
            refs = context["refs"]
            if step not in refs or key not in refs[step]:
                raise HarnessError("reference %s is not a key of an earlier reply" % value)
            return refs[step][key]
        for name, text in context["placeholders"].items():
            value = value.replace("{%s}" % name, text)
        return value
    return value


def file_matches(path: Path, digest: str) -> tuple[bool, str]:
    if not path.is_file():
        return False, "%s is not present on this machine" % path
    found = hashlib.sha256(path.read_bytes()).hexdigest()
    if found != digest:
        return False, "%s has sha256 %s, the plan expects %s" % (path, found, digest)
    return True, ""


def job_id_of(raw) -> str | None:
    if not isinstance(raw, dict):
        return None
    for key in ("job_id", "id"):
        value = raw.get(key)
        if isinstance(value, str) and value.startswith(JOB_PREFIXES):
            return value
    return None


def await_job(wire: Wire, next_id, job_id: str) -> tuple[str, dict]:
    """Poll the job until it leaves the active states. Returns the last state and the last reply's JSON (raw)."""
    deadline = time.monotonic() + JOB_WAIT_S
    arguments = {"action": "status", "id": job_id}  # `job` follows every job id prefix (prepare, decompile, export, ...)
    while True:
        response = wire.call(next_id(), "tools/call", {"name": "job", "arguments": arguments})
        raw = parsed_json(response.get("result", {}).get("content", [{}])[0].get("text", "")) or {}
        state = str(raw.get("state", ""))
        if state not in ACTIVE_STATES:
            return state, response
        if time.monotonic() > deadline:
            raise HarnessError("job %s still %s after %ds" % (job_id, state, JOB_WAIT_S))
        time.sleep(2)


def build_placeholders(run: Path, engine: str, sysroot: str) -> dict[str, str]:
    return {
        "FIXTURE": str(CORPUS / "fixtures" / "cc_issues_pe.exe"),
        "SYSEXE": str(Path(sysroot) / "System32" / "whoami.exe"),
        "WORK": str(run / "work"),
        "TARGET": "cc_issues",
        "ENGINE": engine,
    }


def path_tokens(run: Path, engine: str, sysroot: str) -> dict[str, str]:
    return {"<RUN>": str(run), "<ROOT>": str(run / "root"), "<WORK>": str(run / "work"), "<ENGINE>": engine,
            "<FIXTURES>": str(CORPUS / "fixtures"), "<REPO>": str(REPO), "<SYSROOT>": sysroot,
            "<CONFIG>": str(run / "config.json")}


def record(out: Path, data: Path, engine: str, keep: bool, server: list[str]) -> int:
    run = data / "runs" / uuid.uuid4().hex[:12]
    (run / "work").mkdir(parents=True)
    (run / "root").mkdir()
    config = run / "config.json"
    config.write_text(json.dumps({"hydra_dir": engine, "hydra_allow_unpinned": True}, indent=2), encoding="utf-8")
    sysroot = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or "C:/Windows"
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("RUSTICRE_", "HYDRALYSIS_")) and key != "GHIDRA_INSTALL_DIR"}
    env["HYDRALYSIS_CONFIG"] = str(config)
    env["HYDRALYSIS_ROOT"] = str(run / "root")
    if not server:
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")
        server = [sys.executable, "-m", "hydralysis", "mcp"]
    plan = json.loads(REQUESTS.read_text(encoding="utf-8"))
    placeholders = build_placeholders(run, engine, sysroot)
    paths = None
    wire = Wire(server, env, run / "server.stderr.log")
    counter = [0]

    def next_id() -> int:
        counter[0] += 1
        return counter[0]

    lines: list[dict] = []
    refs: dict[str, dict] = {}
    failures: list[str] = []
    try:
        ident = next_id()
        init_params = {"protocolVersion": PROTOCOL, "clientInfo": {"name": "tool-golden", "version": "1"},
                       "capabilities": {}}
        response = wire.call(ident, "initialize", init_params)
        if "result" not in response:
            raise HarnessError("initialize failed: %s" % json.dumps(response.get("error")))
        init_result = response["result"]
        meta = init_result.get("_meta", {})
        catalog_meta = meta.get("hydralysis/catalog", {})
        environment = meta.get("hydralysis/environment", {})
        # The root the server reports is the one it was given; it is masked as <ROOT> like the run's own copy.
        paths = Paths({**path_tokens(run, engine, sysroot), "<ROOT>": environment.get("root") or str(run / "root")})
        if catalog_meta.get("epoch") != CATALOG_EPOCH:
            failures.append("catalog epoch %r, expected %d" % (catalog_meta.get("epoch"), CATALOG_EPOCH))
        wire.notify("notifications/initialized")
        tools_response = wire.call(next_id(), "tools/list", {})
        tools = tools_response["result"]["tools"]
        catalog = catalog_of(tools)
        if catalog["hash"] != catalog_meta.get("hash"):
            failures.append("tools/list hash %s differs from initialize catalog %s" % (catalog["hash"], catalog_meta.get("hash")))
        if catalog["bytes"] >= CATALOG_BUDGET:
            failures.append("tool table is %d bytes; the budget is under %d" % (catalog["bytes"], CATALOG_BUDGET))
        if len(tools) != 21:
            failures.append("tools/list has %d tools; expected 21" % len(tools))
        requests_sha = hashlib.sha256(REQUESTS.read_bytes()).hexdigest()
        lines.append({"kind": "header", "format": FORMAT, "requests_sha256": requests_sha,
                      "fixture_sha256": {"cc_issues_pe.exe": hashlib.sha256(
                          (CORPUS / "fixtures" / "cc_issues_pe.exe").read_bytes()).hexdigest()},
                      "protocol": PROTOCOL, "excluded": plan.get("excluded", [])})
        lines.append({"kind": "initialize", "request": {"method": "initialize", "params": init_params},
                      "reply": initialize_reply(init_result, paths)})
        lines.append({"kind": "tools/list", "reply": {"tools": tools, "catalog": catalog}})

        context = {"refs": refs, "placeholders": placeholders}
        for step in plan["steps"]:
            sid = step["id"]
            recorded = step.get("record", True)
            requires = step.get("requires")
            if requires:
                ok, reason = file_matches(Path(resolve(requires["file"], context)), requires["sha256"])
                if not ok:
                    lines.append({"kind": "step", "id": sid, "skipped": reason})
                    continue
            if "method" in step:
                method = step["method"]
                declared = {"method": method, "params": step.get("params", {})}
            else:
                declared_params = {"name": step["tool"]}
                if "arguments" in step:
                    declared_params["arguments"] = step["arguments"]
                method = "tools/call"
                declared = {"method": method, "params": declared_params}
            try:
                params = resolve(declared["params"], context)
            except HarnessError as exc:
                lines.append({"kind": "step", "id": sid, "skipped": str(exc)})
                continue
            response = wire.call(next_id(), method, params)
            if "error" in response:
                reply = {"error": mask(response["error"], paths)}
                raw = None
            else:
                result = response.get("result", {})
                reply = tool_reply(result, paths) if "content" in result else mask(result, paths)
                raw = parsed_json(result.get("content", [{}])[0].get("text", "")) if "content" in result else None
            refs[sid] = raw or {}
            if step.get("await_job"):
                job_id = job_id_of(raw)
                if job_id is None:
                    raise HarnessError("step %s has no job id to await" % sid)
                final, last = await_job(wire, next_id, job_id)
                refs[sid + ".final"] = {"state": final}
                if recorded:
                    # The start reply, then the reply of the status poll that saw the job finish (the job's result).
                    lines.append({"kind": "step", "id": sid, "request": declared, "reply": reply})
                    lines.append({"kind": "step", "id": sid + ".awaited", "request": {"method": "tools/call",
                                  "params": {"name": "job", "arguments": {"action": "status", "id": "<job of %s>" % sid}}},
                                  "reply": tool_reply(last["result"], paths), "state": final})
                continue
            if recorded:
                lines.append({"kind": "step", "id": sid, "request": declared, "reply": reply})

        # Teardown: stop the engine this run started (not recorded; backend stop is excluded from the plan).
        wire.call(next_id(), "tools/call", {"name": "backend", "arguments": {"action": "stop"}}, timeout=120)
    finally:
        code = wire.close()
    if code not in (0, None):
        failures.append("server exited with code %s; see %s" % (code, run / "server.stderr.log"))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as handle:
        for line in lines:
            handle.write(json.dumps(line, sort_keys=True, ensure_ascii=False) + "\n")
    print("recorded %d lines to %s" % (len(lines), out))
    if keep:
        print("kept run folder %s" % run)
    else:
        shutil.rmtree(run, ignore_errors=True)
    for failure in failures:
        print("contract: " + failure, file=sys.stderr)
    return 1 if failures else 0


def compare(baseline: Path, candidate: Path) -> int:
    left = [json.loads(line) for line in baseline.read_text(encoding="utf-8").splitlines() if line.strip()]
    right = [json.loads(line) for line in candidate.read_text(encoding="utf-8").splitlines() if line.strip()]
    differences = 0
    if len(left) != len(right):
        print("line count differs: %s has %d, %s has %d" % (baseline, len(left), candidate, len(right)))
        differences += 1
    for index, (a, b) in enumerate(zip(left, right)):
        if a == b:
            continue
        differences += 1
        label = a.get("id", a.get("kind", "line %d" % index))
        before = json.dumps(a, sort_keys=True, indent=2, ensure_ascii=False).splitlines()
        after = json.dumps(b, sort_keys=True, indent=2, ensure_ascii=False).splitlines()
        print("\n".join(difflib.unified_diff(before, after, "baseline " + str(label), "candidate " + str(label),
                                             lineterm="")))
    if differences:
        print("%d difference(s) between %s and %s" % (differences, baseline, candidate))
        return 1
    print("identical: %d lines, %s and %s" % (len(left), baseline, candidate))
    return 0


def selfcheck(data: Path, engine: str) -> int:
    scratch = data / "selfcheck"
    first, second = scratch / "first.jsonl", scratch / "second.jsonl"
    if record(first, data, engine, False, []) != 0 or record(second, data, engine, False, []) != 0:
        return 1
    return compare(first, second)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    rec = commands.add_parser("record", help="drive the plan against a server and write the JSON lines")
    rec.add_argument("--out", type=Path, required=True)
    rec.add_argument("--data", type=Path, default=Path(os.environ.get("HYDRALYSIS_GOLDEN_DATA", DEFAULT_DATA)))
    rec.add_argument("--engine", default=os.environ.get("HYDRALYSIS_HYDRA_DIR", DEFAULT_ENGINE))
    rec.add_argument("--keep", action="store_true", help="keep the run folder (root, work, server stderr log)")
    rec.add_argument("server", nargs="*", help="server command (default: this Python, -m hydralysis mcp)")
    cmp_ = commands.add_parser("compare", help="diff two recordings; exit 1 on a difference")
    cmp_.add_argument("baseline", type=Path)
    cmp_.add_argument("candidate", type=Path)
    check = commands.add_parser("selfcheck", help="record twice and compare (determinism)")
    check.add_argument("--data", type=Path, default=Path(os.environ.get("HYDRALYSIS_GOLDEN_DATA", DEFAULT_DATA)))
    check.add_argument("--engine", default=os.environ.get("HYDRALYSIS_HYDRA_DIR", DEFAULT_ENGINE))
    args = parser.parse_args(argv)
    try:
        if args.command == "record":
            return record(args.out, args.data, args.engine, args.keep, list(args.server))
        if args.command == "compare":
            return compare(args.baseline, args.candidate)
        return selfcheck(args.data, args.engine)
    except HarnessError as exc:
        print("harness error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
