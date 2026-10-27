"""The Python API: the MCP tools, called in process, with structured answers.

Every method goes through `api.call`, the same dispatch the MCP server and the CLI
use, so a script gets exactly the contract an agent gets: the same names, the same
arguments, the same bounds and the same refusals. Tools that answer JSON come back
parsed; tools that answer text come back as text. A refusal raises `RusticError`.

    from rusticre.client import Client
    re = Client()
    re.fingerprint(exe)["sha256"]
    re.read(exe, "rva:0x5d53a0", 16)
    re.check_prologues(exe, [{"name": "hook", "address": "rva:0x5d53a0", "expect": "48 89 5C 24"}])
    re.query("cp25", "decompile", "rva:0x5d53a0")

From another language, `rusticre call <tool> --args '<json>'` prints one JSON
envelope: {"ok": true, "result": ...} or {"ok": false, "error": ...}.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager

from rusticre import api

TABLE_ROWS = 200


class RusticError(RuntimeError):
    """A tool refused the request; `result` holds a structured answer when it had one."""

    def __init__(self, message: str, result: dict | None = None):
        super().__init__(message)
        self.result = result


def parse(text: str):
    """A tool's answer as data: JSON when it is JSON, else the text."""
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            return json.loads(text)
        except ValueError:
            pass
    return text


class Client:
    """In-process RusticRE. `config` names a config file (as RUSTICRE_CONFIG does) for analysis targets."""

    def __init__(self, config: str | None = None):
        self.config = config

    @contextmanager
    def _environment(self):
        if not self.config:
            yield
            return
        previous = os.environ.get("RUSTICRE_CONFIG")
        os.environ["RUSTICRE_CONFIG"] = self.config
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("RUSTICRE_CONFIG", None)
            else:
                os.environ["RUSTICRE_CONFIG"] = previous

    def call(self, tool: str, **args):
        """Any tool by its MCP name, with its MCP arguments."""
        with self._environment():
            try:
                return parse(api.call(tool, {key: value for key, value in args.items() if value is not None}))
            except (ValueError, OSError, KeyError, RuntimeError) as exc:
                # An engine refusal is its JSON answer (error_kind says not_found, timeout, ...).
                answer = parse(str(exc))
                raise RusticError("%s: %s" % (type(exc).__name__, exc),
                                  answer if isinstance(answer, dict) else None) from exc

    def try_query(self, target: str, action: str, address: str = "", **options) -> dict | None:
        """query, but None when the engine answers not_found (no function there, no such type)."""
        try:
            return self.query(target, action, address, **options)
        except RusticError as exc:
            if (exc.result or {}).get("error_kind") == "not_found":
                return None
            raise

    # Static PE work: no engine, no JVM.

    def fingerprint(self, exe: str) -> dict:
        text = self.call("fingerprint", exe=exe)
        return json.loads(text[text.index("\n{") + 1:])

    def read(self, exe: str, address: str, size: int = 32) -> bytes:
        """File bytes at an rva:/va: address."""
        text = self.call("bytes", exe=exe, address=address, size=size)
        return bytes.fromhex(text.rsplit("\n", 1)[1])

    def check_prologues(self, exe: str, rows: list[dict], sha256: str | None = None) -> dict:
        """Verify [{address, expect (one or a list of alternatives), name?}] in one PE open.

        Returns the table result whether or not every row matched (`matched` says), so a
        report can list the mismatches. More than 200 rows are checked in pages.
        """
        if not rows:
            raise RusticError("ValueError: no rows to check")
        merged = None
        for start in range(0, len(rows), TABLE_ROWS):
            result = self._table(exe, rows[start:start + TABLE_ROWS], sha256)
            if merged is None:
                merged = result
                continue
            merged["rows"] += result["rows"]
            for key in ("checked", "matched", "failed"):
                merged["summary"][key] += result["summary"][key]
            merged["matched"] = merged["matched"] and result["matched"]
        return merged

    def _table(self, exe, rows, sha256):
        try:
            return self.call("prologue", exe=exe, checks=rows, sha256=sha256)
        except RusticError as exc:
            text = str(exc.__cause__ or "")
            marker = "PROLOGUE TABLE MISMATCH\n"
            if text.startswith(marker):
                return json.loads(text[len(marker):])
            raise

    def disasm(self, exe: str, address: str, count: int = 40) -> str:
        return self.call("disasm", exe=exe, address=address, count=count)

    def inspect(self, exe: str, address: str) -> str:
        return self.call("inspect", exe=exe, address=address)

    def sigscan(self, exe: str, pattern: str, limit: int = 20) -> str:
        return self.call("sigscan", exe=exe, pattern=pattern, limit=limit)

    # Analysed targets: the shared engine.

    def query(self, target: str, action: str, address: str = "", **options) -> dict:
        """ghidra_query; limit, cursor, contains and timeout_s are top level, the rest are options."""
        # An export's limit and filters are its own options (the record count, not a page size).
        lifted = ("timeout_s",) if action == "export" else ("limit", "cursor", "contains", "timeout_s")
        top = {key: options.pop(key) for key in lifted if key in options}
        return self.call("ghidra_query", target=target, action=action, address=address,
                         options=options or None, **top)

    def runtime(self, action: str, **options):
        return self.call("runtime", action=action, options=options)

    def evidence(self, **args):
        return self.call("evidence_list", **args)
