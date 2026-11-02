"""Profile query modules (spec 8.2, plan WS-F).

Two kinds, both registered by the profile and neither adding a catalog entry:

* **declarative** (`[[queries]]` with kinds / group_by / filter): compiled into the `trace_query` request the engine
  already serves. The profile adds no code and the engine does the work.
* **contained Python** (`[[queries]]` with `module` and `sha256`): a function `query(rows, params) -> dict` that
  post-processes rows the engine already returned (a bounded page, never the trace store). It runs in a separate
  interpreter (`python -I`, empty environment, a scratch working directory, a timeout), receives and returns bounded
  JSON, and only if the file still hashes to the value the profile pinned. The module has no handle on the store, the
  engine connection or the target.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile

from hydralysis import proc
from pathlib import Path

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
TIMEOUT_S = 20

_RUNNER = r"""
import importlib.util, json, sys
path = sys.argv[1]
spec = importlib.util.spec_from_file_location("profile_query_module", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
request = json.loads(open(sys.argv[2], "rb").read().decode("utf-8"))
result = module.query(request["rows"], request.get("params") or {})
sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False))
"""


class QueryModuleError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self)}


def _find(profile, query_id: str) -> dict:
    for query in profile.data["queries"]:
        if query["id"] == query_id:
            return query
    raise QueryModuleError("query_unknown", "profile %s has no query %r" % (profile.id, query_id))


def compile_query(profile, query_id: str, *, session: str, limit: int | None = None, cursor: str | None = None) -> dict:
    """The engine `trace_query` fields for a declarative profile query."""
    query = _find(profile, query_id)
    if "module" in query:
        raise QueryModuleError("query_is_module", "%s is a Python module: run it over rows with run_module" % query_id)
    request = {"session": session, "kinds": list(query["kinds"]), "filter": dict(query["filter"]),
               "group_by": list(query["group_by"]), "limit": min(int(limit or query["limit"]), 200)}
    if cursor:
        request["cursor"] = cursor
    return request


def run_module(profile, query_id: str, rows: list, params: dict | None = None, *, timeout_s: float = TIMEOUT_S) -> dict:
    """Run a pinned Python query module over ROWS (already bounded by the engine) and return its JSON result."""
    query = _find(profile, query_id)
    if "module" not in query or profile.directory is None:
        raise QueryModuleError("query_not_module", "%s is not a Python query module" % query_id)
    path = (profile.directory / query["module"]).resolve()
    try:
        path.relative_to(profile.directory.resolve())
        source = path.read_bytes()
    except (ValueError, OSError) as exc:
        raise QueryModuleError("module_unreadable", "cannot read %s: %s" % (query["module"], exc)) from exc
    if hashlib.sha256(source).hexdigest() != query["sha256"]:
        raise QueryModuleError("module_changed", "%s no longer hashes to the SHA-256 the profile pinned; not run" % query["module"])
    payload = json.dumps({"rows": rows, "params": params or {}}, sort_keys=True).encode("utf-8")
    if len(payload) > MAX_INPUT_BYTES:
        raise QueryModuleError("input_too_large", "the rows are %d bytes; a module receives at most %d" % (len(payload), MAX_INPUT_BYTES))
    env = {key: os.environ[key] for key in ("SystemRoot", "PATH") if key in os.environ}
    with tempfile.TemporaryDirectory(prefix="hydralysis-query-") as scratch:
        request = Path(scratch) / "request.json"
        request.write_bytes(payload)
        try:
            done = proc.run([sys.executable, "-I", "-c", _RUNNER, str(path), str(request)], capture_output=True,
                            timeout=timeout_s, cwd=scratch, env=env)
        except subprocess.TimeoutExpired as exc:
            raise QueryModuleError("module_timeout", "%s ran over %ss and was stopped" % (query["module"], timeout_s)) from exc
    if done.returncode:
        raise QueryModuleError("module_failed", "%s failed: %s" % (query["module"], done.stderr.decode("utf-8", "replace")[-800:]))
    if len(done.stdout) > MAX_OUTPUT_BYTES:
        raise QueryModuleError("output_too_large", "%s returned %d bytes; at most %d" % (query["module"], len(done.stdout), MAX_OUTPUT_BYTES))
    try:
        return json.loads(done.stdout.decode("utf-8"))
    except ValueError as exc:
        raise QueryModuleError("module_output_invalid", "%s did not return JSON: %s" % (query["module"], exc)) from exc
