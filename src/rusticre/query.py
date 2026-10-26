"""Bounded, address-based queries on saved analysis, through Hydra Engine.

The analysed project opens in place through the engine's read-only view: no lock,
no copy, nothing written. Every RusticRE process on the root shares one daemon,
so the program and its decompilers stay warm across harnesses. Each query is one
contained run of RusticQuery.java, which the engine rolls back, so a query can
never change what another client reads. Targets with cited overlays are answered
from their working copy (see workcopy.py).
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from pathlib import Path

from rusticre import hydra, targets, workcopy
from rusticre.analysis import ADVANCED_ACTIONS, BULK_KINDS, validate_options

ACTIONS = {"decompile", "function", "functions", "xrefs", "status", "stop"} | ADVANCED_ACTIONS
ADDRESS_ACTIONS = {"decompile", "function", "xrefs", "variables", "dossier", "blocks", "pcode", "trace", "data", "scan"}
_ADDRESS = re.compile(r"(?:(?:rva|va):)?(?:0x)?[0-9a-fA-F]+")
MAX_CHARS = 16_000_000
# A background save of a large working copy holds its program for up to a few minutes;
# requests wait for it rather than fail.
BUSY_WAIT_MS = 180_000

# Program keys per (root, project, program) for this process. The daemon may
# restart; a stale key is reopened once.
_keys: dict[tuple, dict] = {}
_keys_guard = threading.Lock()


def _public(value):
    """Engine credentials never enter MCP/status/export output."""
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if key not in ("ipc", "token", "secret")}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


def open_program(engine: hydra.Engine, gpr: str, program: str, sha256: str, *, writable: bool = False,
                 upgrade: bool = False, refresh: bool = False) -> dict:
    """Join (or open) one program and check the build before anything is answered from it."""
    cache_key = (engine.key, str(Path(gpr)).lower(), program, writable)
    with _keys_guard:
        known = _keys.get(cache_key)
    if known and not refresh:
        return known
    opened = engine.call("open_project", path=gpr, writable=writable, wait=BUSY_WAIT_MS)
    fields = {"path": program, "project": opened["id"]}
    if writable:
        fields.update(writable=True, share=True, upgrade=upgrade)
    info = engine.call("open_program", wait=BUSY_WAIT_MS, **fields)
    if str(info.get("sha256", "")).lower() != sha256:
        raise ValueError("%s in %s reports SHA-256 %s, not the target build %s; nothing was answered"
                         % (program, opened.get("gpr", gpr), info.get("sha256"), sha256))
    result = {"key": info["key"], "project": opened["id"], "gpr": opened.get("gpr", gpr), "revision": info.get("revision"),
              "project_revision": opened.get("revision"), "image_base": info.get("imageBase"),
              "functions": info.get("functions"), "analyzed": info.get("analyzed"), "mode": info.get("mode")}
    with _keys_guard:
        _keys[cache_key] = result
    return result


def forget(engine: hydra.Engine) -> None:
    with _keys_guard:
        for key in [key for key in _keys if key[0] == engine.key]:
            _keys.pop(key, None)


def run_script(engine: hydra.Engine, program: dict, request: dict, timeout_s: int, request_dir: Path | None = None,
               wait_ms: int = 0) -> tuple[dict, dict]:
    """One RusticQuery run. Large requests travel as a file, not a command argument."""
    body = json.dumps(request, ensure_ascii=False)
    argument = body
    path = None
    if len(body) > 256 * 1024:
        if request_dir is None:
            raise ValueError("request too large to send inline")
        request_dir.mkdir(parents=True, exist_ok=True)
        path = request_dir / ("request-%s.json" % uuid.uuid4().hex)
        path.write_text(body, encoding="utf-8")
        argument = "@" + str(path)
    try:
        result = engine.call("script", script="RusticQuery.java", program=program["key"], args=[argument],
                             maxChars=MAX_CHARS, timeout=timeout_s + 5, wait=wait_ms or BUSY_WAIT_MS)
    finally:
        if path is not None:
            path.unlink(missing_ok=True)
    lines = [line for line in str(result.get("output", "")).splitlines() if line.startswith("{")]
    if not lines or result.get("truncated"):
        raise RuntimeError("RusticQuery returned no complete answer (truncated=%s): %s"
                           % (result.get("truncated"), str(result.get("output", ""))[-2000:]))
    return json.loads(lines[-1]), result


class QueryRunner:
    def __init__(self, settings: dict, engine: hydra.Engine | None = None):
        self.settings = settings
        self.engine = engine or hydra.Engine(settings)
        self.requests = Path(settings["root"]) / "hydra" / "requests"

    def target(self, name: str) -> dict:
        return targets.resolve(self.settings, name)

    def program_for(self, target: dict, *, for_overlays: bool = True) -> dict:
        """The master's read-only view, or the working copy that holds the target's overlays."""
        if for_overlays and workcopy.has_overlays(self.settings, target):
            return workcopy.reader(self.settings, self.engine, target)
        return open_program(self.engine, target["gpr"], target["program"], target["sha256"])

    def query(self, target: str, action: str = "decompile", address: str = "",
              limit: int = 40, cursor: str = "", contains: str = "", timeout_s: int = 30,
              options: dict | None = None) -> str:
        if action not in ACTIONS:
            raise ValueError("unknown saved-analysis query action; use backend help")
        options = validate_options(action, options)
        if not 1 <= limit <= 200 or not 1 <= timeout_s <= 300:
            raise ValueError("limit must be 1..200; timeout_s must be 1..300")
        requires_address = action in ADDRESS_ACTIONS
        requires_address |= action == "type_edit" and options.get("kind") not in ("struct", "batch", "revert", "import_types")
        if requires_address and not address:
            raise ValueError("address is required (a VA such as 0x140001000, or rva:0x1000)")
        if action == "type" and not (address or options.get("path")):
            raise ValueError("type requires options.path or a typed-data address")
        if address and not _ADDRESS.fullmatch(address):
            raise ValueError("use a numeric VA or an rva:/va: prefix, not a symbol name")
        if cursor and not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", cursor):
            raise ValueError("use a numeric VA or hexadecimal row cursor, not a symbol name")
        selected = self.target(target)
        if action == "status":
            return json.dumps(_public(self.status(selected)), ensure_ascii=False)
        if action == "stop":
            return json.dumps(self.stop(selected))
        if action == "type_edit" and options.get("kind") == "revert":
            return json.dumps(workcopy.revert(self.settings, selected, options["ids"], options.get("expect_revision")))
        if action == "type_edit" and options.get("kind") in BULK_KINDS:
            from rusticre import overlayjobs
            return json.dumps(overlayjobs.start(self.settings, selected["name"], "edit", address, options), ensure_ascii=False)
        if action == "type_edit":
            if address.startswith(("rva:", "va:")):
                # Overlay records hold plain VAs, so replay never depends on how an edit was typed.
                base = open_program(self.engine, selected["gpr"], selected["program"], selected["sha256"])["image_base"]
                value = int(address.split(":", 1)[1].removeprefix("0x"), 16)
                address = hex(int(base, 16) + value if address.startswith("rva:") else value)
            return json.dumps(_public(workcopy.edit(self.settings, self.engine, selected, address, options, timeout_s)),
                              ensure_ascii=False)
        request = {"id": uuid.uuid4().hex, "action": action, "address": address, "limit": limit, "cursor": cursor,
                   "contains": contains, "timeout_s": timeout_s, "options": options, "expected_sha256": selected["sha256"]}
        started = time.monotonic()
        response = self._ask(selected, request, timeout_s)
        response.update(target=selected["name"], query_s=round(time.monotonic() - started, 3))
        if not response.get("ok"):
            raise RuntimeError(json.dumps(_public(response), ensure_ascii=False))
        return json.dumps(_public(response), ensure_ascii=False)

    def _ask(self, selected: dict, request: dict, timeout_s: int) -> dict:
        expected_state = workcopy.expected_state(self.settings, selected)
        for attempt in (0, 1):
            program = self.program_for(selected)
            try:
                response, raw = run_script(self.engine, program, request, timeout_s, self.requests)
            except hydra.EngineError as error:
                if attempt == 0 and error.code in ("no_program", "not_found", "no_project", "closed"):
                    forget(self.engine)
                    continue
                raise
            state = response.get("overlay_state") or ""
            if expected_state is not None and state != expected_state:
                if attempt == 0:
                    # The working copy does not hold the store's state (a daemon restart lost
                    # unsaved changes, or another process is mid-edit): replay from the store.
                    if workcopy.heavy(workcopy.load_store(self.settings, selected)):
                        workcopy.rebuilding(self.settings, selected)
                    workcopy.repair(self.settings, self.engine, selected)
                    forget(self.engine)
                    continue
                raise RuntimeError("working copy answers with overlay state %r, expected %r; refused rather than "
                                   "answer from the wrong overlay version" % (state, expected_state))
            response["engine"] = {"program": program["key"], "mode": raw.get("mode"), "script_s": raw.get("seconds")}
            if expected_state is not None:
                response["overlays"] = json.loads(expected_state) if expected_state else None
            return response
        raise RuntimeError("program could not be reopened")

    def status(self, selected: dict) -> dict:
        hello = self.engine.hello()
        info = {key: hello.get(key) for key in ("protocol", "hydraVersion", "ghidraVersion", "installId", "pid", "startedAt")}
        return {"engine": info, "target": {key: selected[key] for key in ("name", "gpr", "program", "sha256")},
                "overlays": workcopy.summary(self.settings, selected), "identity": hydra.identity()}

    def stop(self, selected: dict) -> dict:
        """Release this process's use of the target's programs; the shared daemon keeps serving others."""
        released = []
        with _keys_guard:
            entries = [(key, value) for key, value in _keys.items() if key[0] == self.engine.key]
        for key, value in entries:
            try:
                self.engine.call("close_program", program=value["key"])
                released.append(value["key"])
            except hydra.EngineError:
                pass
        forget(self.engine)
        return {"released": released, "note": "the shared engine keeps warm programs for keepWarm seconds"}
