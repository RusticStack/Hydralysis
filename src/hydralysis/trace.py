"""The `trace` tool: Hydra semantic traces over the engine (plan WS-D; spec 8.2, 14.10).

One MCP tool with an `action` (start, stop, status, query, diff, explain, mark, export, check, import, resymbolize).
It is a thin, bounded carrier:

* **The engine owns the data.** The store, ingest, query, diff, explain and checks are the engine's (`trace_*` protocol
  commands, served from committed snapshots with no lock). This module builds the request, sends it on the shared engine
  connection and shapes the reply. It never holds trace rows.
* **Capture belongs to `runtime`.** `start` and `stop` open and close the trace session on the engine and delegate the
  target to `runtime` (spawn or attach, then `capture start|stop` pointed at the trace session).
* **Every reply is bounded and cited.** Lists are cut at the page limit and the whole reply at `MAX_REPLY_BYTES`; the
  reply states counts, what was cut, event ids as citations, the committed `revision` it was read at, and the coverage
  revision with the gaps that matter. A reply that does not report coverage says so instead of implying it.
* **Jobs ride the long lane.** `export`, `import` and `resymbolize` (and any diff or check the engine turns into a job)
  are long-lane calls (`mcp.LONG_TRACE_ACTIONS`); the engine answers them with a job id the caller follows with `job`.
* **Offline.** With no daemon, `import`, `verify`, `rebuild` and `export` work on the files: segments are verified and
  JSONL is converted to a chained segment here (`trace_canon`), and the engine install's `hydra-trace.exe` rebuilds the
  index and exports.

The client layer (`TraceClient`) maps each action onto the commands `trace_open`, `trace_append`, `trace_mark`,
`trace_query`, `trace_explain`, `trace_diff`, `trace_check`, `trace_export`, `trace_close`, `trace_list`, `trace_info` and
`trace_resymbolize`, each with JSON fields. The engine advertises the `trace` capability only after its gate passes; until
then every action answers `not_available`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from hydralysis import evidence, proc, trace_canon, trace_schema

ACTIONS = ("start", "stop", "status", "query", "diff", "explain", "mark", "export", "check", "import", "resymbolize",
           "reprocess", "relations", "evict", "bundle")
# Actions that are jobs on the engine and so take the long lane of the MCP server.
LONG_ACTIONS = frozenset({"export", "import", "resymbolize", "reprocess", "relations", "evict"})
COMMANDS = ("trace_open", "trace_append", "trace_mark", "trace_query", "trace_explain", "trace_diff", "trace_check",
            "trace_export", "trace_close", "trace_list", "trace_info", "trace_resymbolize", "trace_reprocess",
            "trace_relations", "trace_artifact", "trace_evict", "trace_bundle")
# Read commands the engine answers the same however often they are sent; a lost reply may be sent again.
IDEMPOTENT_COMMANDS = frozenset({"trace_list", "trace_info", "trace_query", "trace_explain", "trace_diff", "trace_check",
                                 "trace_bundle"})
CAPABILITY = "trace"

DEFAULT_LIMIT, MAX_LIMIT = 25, 200
MAX_REPLY_BYTES = 48 * 1024
MAX_CITATIONS = 50
MAX_IMPORT_EVENTS = 100_000
MAX_IMPORT_BYTES = 64 * 1024 * 1024
BATCH_EVENTS = 500
_SESSION = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$")
_EVENT_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,119}$")
# The list-valued fields of the engine's replies (PROTOCOL-3.md 8.20): query rows and groups, explain nodes, edges and
# boundaries, check results, list sessions, info sources, export files, and the entries of a diff or an aligned diff.
_LIST_KEYS = ("rows", "groups", "nodes", "edges", "boundaries", "results", "sessions", "sources", "files", "entries",
              "unmatched_a", "unmatched_b", "rejected", "events", "items", "counterexamples", "only_a", "only_b",
              "different_under_matched_coverage", "not_comparable", "paths", "unresolved", "assertions", "jobs", "decodings",
              "evicted", "reasons")
_NESTED = ("diff", "aligned", "symbols", "decoded")   # reply members that hold lists of their own
_TOKENS: dict[str, str] = {}      # session -> the writer capability (`cap`) this process was given by trace_open
_LINKS: dict[str, str] = {}       # trace session -> the runtime session capturing into it

# TRACE-1 section 15: the wire codes are hyphenated; evidence stores the same code with underscores.
LIMITATIONS = {code: evidence.LIMITATIONS[code.replace("-", "_")][1] for code in (
    "no-stack", "not-code", "module-unknown", "no-symbol", "producer-lost", "ring-overflow", "read-failure",
    "observer-inactive", "clock-uncalibrated", "lifetime-unresolved", "alignment-ambiguous", "budget-reached",
    "artifact-evicted", "payload-not-authorized", "etw-not-elevated", "optional-hook-refused")}


def to_evidence_code(code: str) -> str:
    """The evidence-ledger spelling of a TRACE-1 limitation code."""
    if code not in LIMITATIONS:
        raise ValueError("unknown trace limitation %r" % (code,))
    return code.replace("-", "_")


class TraceError(RuntimeError):
    """A refusal the caller can act on, with a stable code. It is answered as data, not raised to the transport."""

    def __init__(self, code: str, message: str, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self), **self.detail}


# ---- argument handling ----------------------------------------------------------------------------------------

def _session(value, what: str = "session") -> str:
    if not isinstance(value, str) or not _SESSION.match(value):
        raise ValueError("%s must be a trace session id (letters, digits, `_`, `.`, `-`, at most 80)" % what)
    return value


def _limit(options: dict) -> int:
    value = options.get("limit", DEFAULT_LIMIT)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_LIMIT:
        raise ValueError("limit must be 1..%d" % MAX_LIMIT)
    return value


def _strings(value, what: str, maximum: int = 64) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum or not all(isinstance(item, str) and item for item in value):
        raise ValueError("%s must be a list of at most %d non-empty strings" % (what, maximum))
    return list(value)


def _object(value, what: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("%s must be an object" % what)
    return value


# ---- shaping a reply ------------------------------------------------------------------------------------------

def _collect_ids(value, found: list, depth: int = 0) -> None:
    if depth > 5 or len(found) >= MAX_CITATIONS * 4:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("event_id", "from_event", "to_event", "representative", "first_event", "last_event", "first_a", "first_b", "root") and isinstance(item, str):
                found.append(item)
            elif key in ("event_ids", "counterexamples", "representatives", "events") and isinstance(item, list):
                for entry in item:
                    if isinstance(entry, str):
                        found.append(entry)
                    elif isinstance(entry, dict):
                        _collect_ids(entry, found, depth + 1)
            else:
                _collect_ids(item, found, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _collect_ids(item, found, depth + 1)


def _size(value) -> int:
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))


def shape(reply, *, session: str | None, command: str, limit: int, requested_revision=None) -> dict:
    """Bound REPLY and add the fields every trace answer carries: revision, coverage, citations and what was cut.

    The engine's reply is data and is never trusted for size: every list is cut at LIMIT, and if the whole is still over
    MAX_REPLY_BYTES the largest lists are halved until it fits, saying so in `bounds.truncated`."""
    out = dict(reply) if isinstance(reply, dict) else {"result": reply}
    truncated: dict[str, int] = {}
    for key in _NESTED:
        if isinstance(out.get(key), dict):
            out[key] = dict(out[key])
    for holder, name in [(out, "")] + [(out[key], key + ".") for key in _NESTED if isinstance(out.get(key), dict)]:
        for key in _LIST_KEYS:
            if isinstance(holder.get(key), list) and len(holder[key]) > limit:
                truncated[name + key] = len(holder[key]) - limit
                holder[key] = holder[key][:limit]
    coverage = out.get("coverage") if isinstance(out.get("coverage"), dict) else None
    gaps = (coverage or {}).get("gaps", out.get("gaps"))
    reported = coverage is not None or isinstance(gaps, list)
    nested_gaps = out["diff"] if isinstance(out.get("diff"), dict) and "gaps_a" in out["diff"] else None
    gaps = gaps if isinstance(gaps, list) else []
    if nested_gaps is not None:
        reported = True
    if len(gaps) > limit:
        truncated["gaps"] = len(gaps) - limit
        gaps = gaps[:limit]
    revision = out.get("revision", requested_revision)
    out["coverage"] = {"revision": revision, "gaps": gaps, "reported": reported}
    if nested_gaps is not None:
        out["coverage"].update(gaps_a=nested_gaps.get("gaps_a"), gaps_b=nested_gaps.get("gaps_b"),
                               revision_a=nested_gaps.get("revision_a"), revision_b=nested_gaps.get("revision_b"))
    out.pop("coverage_revision", None)
    out.pop("gaps", None)
    if not out["coverage"]["reported"]:
        out["coverage"]["note"] = "the engine reported no coverage for this answer; absence of events is not evidence of absence"
    if coverage:
        out["coverage"].update({key: value for key, value in coverage.items() if key not in ("revision", "gaps")})
    ids: list = []
    _collect_ids(out, ids)
    unique = list(dict.fromkeys(item for item in ids if _EVENT_ID.match(item)))
    if session is not None:
        out["citations"] = [{"session": session, "event_id": item, "revision": revision} for item in unique[:MAX_CITATIONS]]
    if len(unique) > MAX_CITATIONS:
        truncated["citations"] = len(unique) - MAX_CITATIONS
    out["revision"] = revision
    while _size(out) > MAX_REPLY_BYTES:
        holders = [(out, "")] + [(out[key], key + ".") for key in _NESTED if isinstance(out.get(key), dict)]
        sized = [(holder, name + key, key, len(holder[key])) for holder, name in holders for key in _LIST_KEYS
                 if isinstance(holder.get(key), list) and len(holder[key]) > 1]
        if not sized:
            break
        holder, label, key, _ = max(sized, key=lambda item: (_size(item[0][item[2]]), item[1]))
        keep = max(1, len(holder[key]) // 2)
        truncated[label] = truncated.get(label, 0) + len(holder[key]) - keep
        holder[key] = holder[key][:keep]
    if _size(out) > MAX_REPLY_BYTES:
        out = {"error": "reply_too_large", "message": "the engine's answer to %s does not fit %d bytes even cut to its "
               "heads; narrow the filter" % (command, MAX_REPLY_BYTES), "revision": revision}
        truncated["reply"] = 1
    out["bounds"] = {"limit": limit, "max_reply_bytes": MAX_REPLY_BYTES, "truncated": truncated,
                     "complete": not truncated}
    return out


# ---- the client layer -----------------------------------------------------------------------------------------

class TraceClient:
    """Sends the engine's `trace_*` commands. ENGINE is a `hydra.Engine` (or a stand-in with `call` and `capabilities`)."""

    def __init__(self, engine):
        self.engine = engine

    def available(self) -> bool:
        from hydralysis import hydra
        return hydra.supports(self.engine, CAPABILITY)

    def call(self, command: str, **fields) -> dict:
        if command not in COMMANDS:
            raise ValueError("%s is not a trace command" % command)
        fields = {key: value for key, value in fields.items() if value is not None}
        try:
            reply = self.engine.call(command, **fields)
        except Exception as exc:  # noqa: BLE001 - an engine refusal is an answer the caller can act on
            from hydralysis.hydra import EngineError
            if isinstance(exc, EngineError):
                raise TraceError(str(exc.code), str(exc), command=command,
                                 **({"details": exc.details} if getattr(exc, "details", None) else {})) from exc
            raise
        return reply if isinstance(reply, dict) else {"result": reply}

    def begin(self, **fields) -> dict:
        return self.call("trace_open", **fields)

    def append(self, session: str, events: list, **fields) -> dict:
        return self.call("trace_append", session=session, events=events, **fields)

    def mark(self, session: str, label: str, **fields) -> dict:
        return self.call("trace_mark", session=session, label=label, **fields)

    def query(self, session: str, **fields) -> dict:
        return self.call("trace_query", session=session, **fields)

    def explain(self, session: str, event_id: str, **fields) -> dict:
        return self.call("trace_explain", session=session, event_id=event_id, **fields)

    def diff(self, a: str, b: str, **fields) -> dict:
        return self.call("trace_diff", a=a, b=b, **fields)

    def check(self, session: str, **fields) -> dict:
        return self.call("trace_check", session=session, **fields)

    def export(self, session: str, **fields) -> dict:
        return self.call("trace_export", session=session, **fields)

    def close(self, session: str, **fields) -> dict:
        return self.call("trace_close", session=session, **fields)

    def list(self, **fields) -> dict:
        return self.call("trace_list", **fields)

    def info(self, session: str, **fields) -> dict:
        return self.call("trace_info", session=session, **fields)

    def resymbolize(self, session: str, **fields) -> dict:
        return self.call("trace_resymbolize", session=session, **fields)

    def reprocess(self, session: str, **fields) -> dict:
        return self.call("trace_reprocess", session=session, **fields)

    def relations(self, session: str, **fields) -> dict:
        return self.call("trace_relations", session=session, **fields)

    def artifact(self, session: str, **fields) -> dict:
        return self.call("trace_artifact", session=session, **fields)

    def evict(self, **fields) -> dict:
        return self.call("trace_evict", **fields)

    def bundle(self, path: str, **fields) -> dict:
        return self.call("trace_bundle", path=path, **fields)


def _engine(settings: dict):
    from hydralysis import hydra
    return hydra.Engine(settings)


# ---- reading events from a file (import) ----------------------------------------------------------------------

def read_jsonl(path: Path, *, max_events: int = MAX_IMPORT_EVENTS) -> dict:
    """Read producer events from a JSONL file and keep the outcomes apart: empty, torn tail, corrupt, over the bound.

    The valid prefix is returned in every case. A line is valid when it is a JSON object that satisfies the event
    schema; an invalid line followed by more lines is `corrupt` (the scan stops there), an invalid last line without a
    newline is a `torn_tail`. `lost_producers` counts jumps in `source_seq` that no `core.capture.gap` explains."""
    path = Path(path)
    if not path.is_file():
        return {"outcome": "missing", "events": [], "reason": "%s does not exist" % path}
    size = path.stat().st_size
    if size > MAX_IMPORT_BYTES:
        return {"outcome": "too_large", "events": [], "reason": "%d bytes; an online import takes at most %d (use the offline importer)" % (size, MAX_IMPORT_BYTES)}
    data = path.read_bytes()
    if not data.strip():
        return {"outcome": "empty", "events": [], "lines": 0}
    events, damage = [], None
    lines = data.split(b"\n")
    ends_clean = data.endswith(b"\n")
    if ends_clean:
        lines = lines[:-1]
    for number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        last = number == len(lines)
        problem = None
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            event, problem = None, "not JSON: %s" % exc
        if problem is None:
            reasons = trace_schema.validate_event(event) if isinstance(event, dict) else ["not an object"]
            problem = "; ".join(reasons[:3]) if reasons else None
        if problem is None:
            try:
                trace_canon.canonical_bytes(event)
            except trace_canon.NotCanonical as exc:
                problem = "not canonical: %s" % exc
        if problem is not None:
            kind = "torn_tail" if last and not ends_clean else "corrupt"
            damage = {"kind": kind, "line": number, "reason": problem}
            break
        if len(events) >= max_events:
            damage = {"kind": "over_bound", "line": number, "reason": "more than %d events" % max_events}
            break
        events.append(event)
    lost, last_seq, gap_next = 0, {}, {}
    for event in events:
        key = (event["source_id"], event["producer_gen"])
        if event["kind"] == "core.capture.gap":
            payload = event.get("payload") or {}
            if isinstance(payload.get("last_missing_source_seq"), int):
                gap_next[key] = payload["last_missing_source_seq"] + 1
        if key in last_seq and event["source_seq"] != last_seq[key] + 1 and gap_next.get(key) != event["source_seq"]:
            lost += 1
        last_seq[key] = event["source_seq"]
    outcome = damage["kind"] if damage else "clean"
    return {"outcome": outcome, "events": events, "lines": len(lines), "damage": damage, "lost_producers": lost}


def segment_from_events(events: list[dict], segment_id: str) -> bytes:
    """A chained raw segment (TRACE-1 section 3) for already-valid events of one source."""
    chain = trace_canon.Chain(segment_id)
    return b"".join(chain.push(event) for event in events)


# ---- the offline tool -----------------------------------------------------------------------------------------

# The `hydra-trace` command line (crates/hydra-trace/src/main.rs): `import <root> <session> <file.jsonl|file.dmp>`,
# `rebuild <root> <session>`, `export <root> <session> <outdir> [--overwrite]`, `verify <root> <session>` (a folder
# as the first argument; `verify <segment-file> <segment-id>` checks one segment) and `gen <recipe> <seed> <events>
# <outdir>`.
OFFLINE_VERBS = ("import", "rebuild", "export", "verify")


def find_tool(settings: dict | None = None) -> Path | None:
    """The engine install's `hydra-trace.exe`: HYDRA_TRACE_EXE, else beside the engine."""
    explicit = os.environ.get("HYDRA_TRACE_EXE")
    if explicit:
        return Path(explicit) if Path(explicit).is_file() else None
    base = Path((settings or {}).get("hydra_dir") or "")
    if not str(base):
        return None
    for relative in ("hydra-trace.exe", "bin/hydra-trace.exe", "support/hydra-trace.exe", "lib/hydra-trace.exe"):
        if (base / relative).is_file():
            return base / relative
    return None


def run_tool(settings: dict | None, verb: str, arguments: list[str], *, timeout_s: int = 600) -> dict:
    """Run one verb of `hydra-trace` with bounded output."""
    tool = find_tool(settings)
    if tool is None:
        raise TraceError("tool_missing", "hydra-trace.exe was not found in the engine install; set HYDRA_TRACE_EXE or "
                         "install the engine that ships it", verb=verb)
    try:
        done = proc.run([str(tool), verb, *arguments], capture_output=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        raise TraceError("tool_timeout", "hydra-trace %s ran over %ds and was stopped" % (verb, timeout_s)) from exc
    text = done.stdout.decode("utf-8", "replace")[-8000:]
    return {"verb": verb, "exit_code": done.returncode, "stdout": text, "stderr": done.stderr.decode("utf-8", "replace")[-2000:],
            "ok": done.returncode == 0}


def offline_verify(directory: Path, segments: list[str] | None = None) -> dict:
    """Verify every `*.trace` segment under DIRECTORY (a session's `segments` folder) with the Python twin."""
    directory = Path(directory)
    if not directory.is_dir():
        return {"outcome": "missing", "segments": [], "reason": "%s is not a folder" % directory}
    rows = []
    for path in sorted(directory.glob("*.trace")):
        if segments and path.stem not in segments:
            continue
        result = trace_canon.scan(path.read_bytes(), path.stem)
        rows.append({"segment": path.stem, "outcome": result.outcome, "records": len(result.records), "valid_bytes": result.valid_end,
                     "size": result.size, "head": result.head, "damage": result.damage})
    worst = next((row["outcome"] for kind in ("chain_break", "corrupt", "torn_tail") for row in rows if row["outcome"] == kind), None)
    return {"outcome": worst or ("empty" if rows and all(row["outcome"] == "empty" for row in rows) else "clean" if rows else "missing"),
            "segments": rows}


def _tool_json(result: dict) -> dict:
    """The JSON line the tool printed, when it printed one."""
    for line in reversed(str(result.get("stdout", "")).splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return {}


def _offline(action: str, options: dict, settings: dict) -> dict:
    store = Path(str(options.get("store") or Path(settings.get("root", ".")) / "traces"))
    verb = str(options.get("op") or ("import" if action == "import" else action))
    if verb not in OFFLINE_VERBS:
        raise ValueError("offline op must be one of: " + ", ".join(OFFLINE_VERBS))
    name = _session(options.get("session") or options.get("name") or "", "options.session")
    if verb == "verify":
        python = offline_verify(store / name / "segments", _strings(options.get("segments"), "options.segments"))
        reply = {"offline": True, "op": "verify", **python}
        if options.get("engine") and find_tool(settings):
            reply["engine"] = run_tool(settings, "verify", [str(store), name])
            reply["engine"]["report"] = _tool_json(reply["engine"])
        return reply
    if verb == "import":
        source = Path(str(options.get("input") or options.get("file") or ""))
        if source.suffix.lower() == ".dmp":
            return {"offline": True, "op": "import", **run_tool(settings, "import", [str(store), name, str(source)])}
        too_large = source.is_file() and source.stat().st_size > MAX_IMPORT_BYTES
        if options.get("stream") or too_large:
            # A file past the in-memory bound (or asked for with stream): the tool reads it line by line in chunks, so memory
            # stays flat however large it is, and reports the same distinct outcomes itself. Nothing is parsed here.
            if not find_tool(settings):
                raise TraceError("tool_missing", "a streamed import is done by hydra-trace.exe (HYDRA_TRACE_EXE)", verb="import")
            ran = run_tool(settings, "import", [str(store), name, str(source)], timeout_s=int(options.get("timeout_s", 3600)))
            report = _tool_json(ran)
            return {"offline": True, "op": "import", "streamed": True, "imported": int(report.get("accepted", 0)),
                    "outcome": report.get("outcome", "failed"), "lines": report.get("lines"), "report": report,
                    **({"damage": {"kind": report["outcome"], "line": report.get("damage_line"), "reason": report.get("reason")}}
                       if report.get("outcome") in ("torn_tail", "corrupt") else {}),
                    **{k: ran[k] for k in ("ok", "exit_code", "stderr")}}
        read = read_jsonl(source)
        summary = {key: read[key] for key in ("outcome", "lines", "damage", "lost_producers", "reason") if key in read}
        if not read["events"]:
            return {"offline": True, "op": "import", "imported": 0, **summary}
        if not find_tool(settings):
            raise TraceError("tool_missing", "an offline import is done by hydra-trace.exe (it keeps the batch manifest next to the "
                             "segments); set HYDRA_TRACE_EXE or install the engine that ships it", verb="import")
        # The tool reads a clean JSONL file; the valid prefix of a damaged input is written to a scratch file for it.
        with tempfile.TemporaryDirectory(prefix="hydralysis-trace-import-") as scratch:
            clean = Path(scratch) / "events.jsonl"
            from hydralysis import durable
            durable.atomic_write(clean, b"".join(json.dumps(event, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
                                       for event in read["events"]))
            ran = run_tool(settings, "import", [str(store), name, str(clean)])
        return {"offline": True, "op": "import", "imported": len(read["events"]) if ran["ok"] else 0,
                "report": _tool_json(ran), **summary, **{k: ran[k] for k in ("ok", "exit_code", "stderr")}}
    arguments = [str(store), name]
    if verb == "export":
        output = options.get("output") or options.get("out")
        if not output:
            raise ValueError("options.output (an export folder) is required for an offline export")
        arguments.append(str(output))
        if options.get("overwrite"):
            arguments.append("--overwrite")
    ran = run_tool(settings, verb, arguments)
    return {"offline": True, "op": verb, "report": _tool_json(ran), **ran}


# ---- the actions ----------------------------------------------------------------------------------------------

def _load_profile(options: dict):
    from hydralysis import profiles
    chosen = options.get("profile")
    if chosen in (None, ""):
        return None
    if chosen == "baseline":
        return profiles.load_baseline()
    return profiles.load_file(Path(str(chosen)))


def _verify_profile(profile, options: dict) -> dict:
    """Verify the profile's hooks against the images the caller names; a refusal stops the session before it starts."""
    from hydralysis import profiles
    from hydralysis.pe import Image
    images = options.get("images")
    if not isinstance(images, dict) or not images:
        if not profile.data["hooks"]:
            return {"profile": profile.id, "ok": True, "hooks": [], "limitations": [], "refusals": [], "enabled": [],
                    "counts": {"verified": 0, "refused_required": 0, "refused_optional": 0}}
        raise TraceError("images_required", "a build-bound profile is verified against the exact images: pass options.images "
                         "{module: path} for %s" % ", ".join(profile.data["target"]["modules"]))
    loaded = {str(name): Image(Path(str(path))) for name, path in images.items()}
    result = profiles.verify_profile(profile, loaded)
    profiles.require(result)
    return result


TRACE_CAPTURE_KEYS = ("ring_bytes", "rings", "batch_ms", "batch_bytes", "counter_ms", "bp_ms", "window", "authorize_payload",
                      "authorize_preview", "builtin", "watchdog", "etw", "fault_policy", "producer_gen", "scope", "scope_key")


def _trace_option(session: str, profile, verification, capture_options: dict) -> dict:
    """The `trace` object of `capture start`: which trace session the capture feeds, the owner's lease, the enabled hook ids
    and, resolved from the verified profile, the probes to arm. Recorder settings the caller gives are passed through."""
    from hydralysis import profiles
    unknown = set(capture_options) - set(TRACE_CAPTURE_KEYS)
    if unknown:
        raise ValueError("unknown options.capture_options: %s; accepted: %s" % (", ".join(sorted(unknown)), ", ".join(TRACE_CAPTURE_KEYS)))
    option = {"session": session, "owner": _TOKENS.get(session), "hooks": list((verification or {}).get("enabled", []))}
    if profile is not None and verification is not None:
        option["probes"] = profiles.probe_specs(profile, verification)
        enabled = [h for h in profile.data["hooks"] if h["id"] in option["hooks"]]
        option["fault_policy"] = profiles.host_fault_policy(profile, enabled)
        option["profile"] = {"id": profile.id, "sha256": profile.sha256}
        watch = _watchdog_option(profile, capture_options.get("watchdog"))
        if watch:
            option["watchdog"] = watch
    for key, value in capture_options.items():
        if key != "watchdog":
            option[key] = value
    return option


def _watchdog_option(profile, requested) -> dict | None:
    """The frame-stall watchdog of the declared main loop: the first frame phase of the profile names the hook whose hits are
    the frames. `requested` is {stall_s, hook?}; absent, no watchdog runs."""
    if not requested:
        return None
    if not isinstance(requested, dict):
        raise ValueError("options.capture_options.watchdog is {stall_s, hook?, after_s?}")
    hook = requested.get("hook")
    if hook is None:
        frames = [p for p in profile.data["phases"] if p["kind"] == "frame"]
        hook = frames[0]["open"] if frames else None
    if hook is None or profile.hook(hook) is None:
        raise ValueError("the watchdog needs the hook that marks a frame: the profile declares no frame phase (or %r is not a hook)" % hook)
    return {"hook": hook, "stall_s": float(requested.get("stall_s", 2.0)), "after_s": float(requested.get("after_s", 0.0))}


def _open_program(client: TraceClient, options: dict) -> dict:
    """The program a trace is symbolized against is read through a project this connection has open (read-only: a trace never
    writes into it). Given a project folder or .gpr and a program path, open both and name them as the engine keys them."""
    if not (options.get("program") and options.get("project")):
        return options
    project = client.engine.call("open_project", path=str(options["project"]))
    info = client.engine.call("open_program", path=str(options["program"]), project=project["id"])
    return {**options, "project": project["id"], "program": info["key"]}


def _start(client: TraceClient, session: str | None, options: dict, settings: dict) -> dict:
    from hydralysis import profiles
    profile = _load_profile(options)
    verification = _verify_profile(profile, options) if profile is not None else None
    scope = _object(options.get("scope"), "options.scope")
    if scope.get("add") and not options.get("owner_token"):
        raise TraceError("scope_expansion_needs_owner", "adding processes or services to the scope needs the owner token")
    limitations = list((verification or {}).get("limitations", []))
    # The session metadata (profile id and hash, scope, limitations, target, capture configuration, scenario) is persisted
    # by the engine next to the session, so it survives a reopen and `status` reads it back from `trace_info`.
    options = _open_program(client, options)
    meta = {"profile": verification and {"id": verification.get("profile"), "sha256": verification.get("profile_sha256"),
                                         "counts": verification.get("counts"), "enabled": verification.get("enabled")},
            "scope": scope or {"process_tree": True}, "limitations": limitations,
            "target": options.get("target") or {k: options[k] for k in ("program", "project", "modules") if options.get(k)} or None,
            "capture": _object(options.get("capture_options"), "options.capture_options") or None,
            "scenario": options.get("scenario")}
    shared = _object(options.get("shared_scope"), "options.shared_scope") or None
    if shared is not None and not (isinstance(shared.get("name"), str) and isinstance(shared.get("key"), str)):
        raise ValueError("options.shared_scope is {name, key}: the key is 64 hex digits, provisioned out of band")
    opened = client.begin(
        session=session, create=True, mode="write", max_events=options.get("max_events"), max_bytes=options.get("max_bytes"),
        preview=options.get("preview"), program=options.get("program"), project=options.get("project"),
        modules=_strings(options.get("modules"), "options.modules") or None,
        meta={k: v for k, v in meta.items() if v is not None}, shared_scope=shared)
    name = str(opened.get("session") or session or "")
    cap = (opened.get("lease") or {}).get("cap")
    if cap:
        _TOKENS[name] = str(cap)
    result = {"session": name, "opened": opened, "profile": verification and {k: verification[k] for k in
              ("profile", "profile_sha256", "counts", "limitations", "enabled")},
              "scope": scope or {"process_tree": True}, "limitations": limitations, "cap": cap}
    launch = _object(options.get("launch"), "options.launch")
    if launch:
        from hydralysis.runtime import RuntimeRunner
        runner = RuntimeRunner(settings)
        action = str(launch.get("action") or "spawn")
        if action not in ("spawn", "attach"):
            raise ValueError("options.launch.action must be spawn or attach")
        try:
            started = runner.call(action, {key: value for key, value in launch.items() if key != "action"})
            runtime_session = str(started.get("session") or "")
            capture = runner.call("capture", {"op": "start", "session": runtime_session,
                                              "trace": _trace_option(name, profile, verification,
                                                                     _object(options.get("capture_options"), "options.capture_options"))})
        except Exception as exc:  # noqa: BLE001 - the session was opened; close it so no orphan keeps a writer lease
            try:
                client.close(name, cap=_TOKENS.pop(name, None))
            except Exception:  # noqa: BLE001
                pass
            raise
        _LINKS[name] = runtime_session
        result.update(runtime={"session": runtime_session, "started": started, "capture": capture})
    return result


def _stop(client: TraceClient, session: str, options: dict, settings: dict) -> dict:
    result = {"session": session}
    runtime_session = str(options.get("runtime_session") or _LINKS.get(session) or "")
    if runtime_session:
        from hydralysis.runtime import RuntimeRunner
        runner = RuntimeRunner(settings)
        result["runtime"] = {"session": runtime_session, "capture": runner.call(
            "capture", {"op": "stop", "session": runtime_session})}
        if options.get("detach", True):
            result["runtime"]["detach"] = runner.call("detach", {"session": runtime_session})
    result["closed"] = client.close(session, cap=options.get("cap") or _TOKENS.get(session))
    _TOKENS.pop(session, None)
    _LINKS.pop(session, None)
    return result


_FILTER_KEYS = ("resource_key", "state_key", "corr", "process_gen")


def _query_fields(options: dict, limit: int) -> dict:
    """The `trace_query` request fields (PROTOCOL-3.md 8.20) for the tool's options."""
    flt = _object(options.get("filter"), "options.filter")
    unknown = sorted(set(flt) - set(_FILTER_KEYS))
    if unknown:
        raise ValueError("options.filter takes %s; not %s" % (", ".join(_FILTER_KEYS), ", ".join(unknown)))
    group = options.get("group_by")
    if isinstance(group, list):
        if len(group) > 1:
            raise ValueError("options.group_by is one of kind, resource, state, module, source (one grouping per query)")
        group = group[0] if group else None
    return {"kinds": _strings(options.get("kinds"), "options.kinds") or None, **{k: flt.get(k) for k in _FILTER_KEYS},
            "group_by": group, "after": options.get("cursor", options.get("after")), "up_to": options.get("up_to"),
            "with_symbols": options.get("with_symbols") or None, "decoded": options.get("decoded") or None,
            "decode_interp": options.get("decode_interpretation", options.get("decode_interp")),
            "interp": options.get("interpretation", options.get("interp")), "lifetimes": options.get("lifetimes") or None,
            "limit": limit}


def _query(client: TraceClient, session: str, options: dict, limit: int) -> dict:
    fields = _query_fields(options, limit)
    if options.get("profile_query"):
        from hydralysis import profiles
        profile = _load_profile(options)
        if profile is None:
            raise ValueError("options.profile is required with options.profile_query")
        query = next((q for q in profile.data["queries"] if q["id"] == options["profile_query"]), None)
        if query is None:
            raise ValueError("profile %s has no query %s" % (profile.id, options["profile_query"]))
        if "module" in query:
            rows = client.query(session, **{**fields, "limit": limit})
            module_rows = rows.get("rows") or rows.get("groups") or []
            return {**rows, "module": query["id"], "module_result": profiles.run_module(
                profile, query["id"], module_rows[:limit], _object(options.get("params"), "options.params"))}
        compiled = _query_fields({**profiles.compile_query(profile, query["id"], session=session, limit=limit),
                                  "cursor": options.get("cursor")}, limit)
        fields.update({k: v for k, v in compiled.items() if fields.get(k) is None})
    return client.query(session, **fields)


def _check(client: TraceClient, session: str, options: dict, limit: int) -> dict:
    assertions = options.get("assertions")
    if assertions is None and isinstance(options.get("assertion"), dict):
        assertions = [options["assertion"]]
    if not isinstance(assertions, list) or not assertions or not all(isinstance(a, dict) for a in assertions) or len(assertions) > 64:
        raise ValueError("options.assertions is a list of 1..64 assertion objects ({type, name, ...}: request_completion, cardinality, "
                         "forbidden, ordered_transitions, required_transition, forbidden_transition, only_on_role, "
                         "write_precedes_read_in_frame, at_most_once_per_frame, no_frame_without, round_trip)")
    return client.check(session, assertions=assertions, persist=options.get("persist"),
                        cap=options.get("cap") or _TOKENS.get(session))


def _import(client: TraceClient, session: str | None, options: dict) -> dict:
    source = Path(str(options.get("input") or options.get("file") or ""))
    read = read_jsonl(source)
    summary = {key: read[key] for key in ("outcome", "lines", "damage", "lost_producers", "reason") if key in read}
    if not read["events"]:
        return {"imported": 0, "session": session, **summary}
    opened = client.begin(session=session, create=True, mode="write")
    name = str(opened.get("session") or session or "")
    cap = (opened.get("lease") or {}).get("cap")
    appended = 0
    last = {}
    for start in range(0, len(read["events"]), BATCH_EVENTS):
        batch = read["events"][start:start + BATCH_EVENTS]
        last = client.append(name, batch, cap=cap)
        appended += int(last.get("accepted", len(batch)))
    closed = client.close(name, cap=cap) if not options.get("keep_open") else None
    if options.get("keep_open") and cap:
        _TOKENS[name] = str(cap)
    return {"session": name, "imported": appended, "damaged_input_ignored_after": summary.get("damage"), **summary,
            "last_append": last, "closed": closed}


def ship_artifacts(client: TraceClient, session: str, cap: str, events: list[dict], artifact_dir: Path, *, scope: str,
                   max_bytes: int = 4096) -> tuple[list[dict], dict]:
    """Payload mode, engine side: the exact bytes the recorder kept for an authorized range (`artifact_dir/<sha256>`, named by
    the digest in the event) are stored in the session as private artifacts, and each event that named one then references the
    engine's artifact id. Returns (events with the references rewritten, {stored, missing}). An event whose file is gone keeps
    no reference and is counted under `missing` (limitation `artifact-evicted`); nothing is guessed."""
    stored: dict[str, str] = {}
    missing: list[str] = []

    def rewrite(value):
        if isinstance(value, dict):
            ref = value.get("artifact")
            if isinstance(ref, dict) and isinstance(ref.get("sha256"), str):
                digest = ref["sha256"]
                if digest not in stored:
                    path = Path(artifact_dir) / digest
                    if not path.is_file():
                        missing.append(digest)
                        return {k: rewrite(v) for k, v in value.items() if k != "artifact"} | {"artifact_missing": digest}
                    reply = client.artifact(session, cap=cap, scope=scope, max_bytes=max_bytes, data_hex=path.read_bytes().hex())
                    stored[digest] = str(reply["artifact"])
                return {k: rewrite(v) for k, v in value.items() if k != "artifact"} | {"artifact": stored[digest]}
            return {k: rewrite(v) for k, v in value.items()}
        return value

    out = [{**event, "payload": rewrite(event["payload"])} if isinstance(event.get("payload"), dict) else event for event in events]
    return out, {"stored": len(stored), "missing": sorted(set(missing))}


def handle_action(action: str, session: str | None, options: dict, settings: dict, client: TraceClient | None = None) -> dict:
    """Run one action and return the shaped reply (a dict). `client` is injectable for tests."""
    if action not in ACTIONS:
        raise ValueError("trace action must be one of: " + ", ".join(ACTIONS))
    limit = _limit(options)
    if options.get("offline"):
        return _offline(action, {**options, "session": options.get("session") or session}, settings)
    client = client or TraceClient(_engine(settings))
    if not client.available():
        return {"not_available": CAPABILITY, "message": "this engine does not advertise the trace capability (it needs "
                "12.3-hydra.6 or later). Offline: pass options.offline=true with options.op verify, import, rebuild or export.",
                "offline": {"verify": "Python", "import": "Python (JSONL -> segment)", "rebuild/export": "hydra-trace.exe"
                            if find_tool(settings) else "hydra-trace.exe (not found)"}}
    if session is not None:
        _session(session)
    if action == "start":
        return shape(_start(client, session, options, settings), session=session, command="trace_open", limit=limit)
    if action == "status":
        if session is None:
            return shape(client.list(limit=limit), session=None, command="trace_list", limit=limit)
        info = client.info(session)
        reply = {"session": session, "info": info}
        if _LINKS.get(session):
            try:
                from hydralysis.runtime import RuntimeRunner
                reply["runtime"] = RuntimeRunner(settings).call("status", {"session": _LINKS[session]})
            except Exception as exc:  # noqa: BLE001 - a dead runtime session is part of the status, not a failure of it
                reply["runtime"] = {"error": str(exc)}
        return shape({**info, "session": session, "runtime": reply.get("runtime")} if isinstance(info, dict) else reply,
                     session=session, command="trace_info", limit=limit)
    if action == "import":
        return shape(_import(client, session, options), session=None, command="trace_import", limit=limit)
    if action == "evict":
        if not (session or options.get("to_quota")):
            raise ValueError("trace evict requires session (a closed session) or options.to_quota")
        return shape(client.evict(session=session, to_quota=options.get("to_quota") or None, reason=options.get("reason")),
                     session=None, command="trace_evict", limit=limit)
    if action == "bundle":
        path = options.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("trace bundle requires options.path (an export folder)")
        return shape(client.bundle(path), session=None, command="trace_bundle", limit=limit)
    if session is None:
        raise ValueError("trace %s requires session" % action)
    if action == "stop":
        return shape(_stop(client, session, options, settings), session=session, command="trace_close", limit=limit)
    if action == "query":
        reply = _query(client, session, options, limit)
        return shape(reply, session=session, command="trace_query", limit=limit, requested_revision=options.get("revision"))
    if action == "diff":
        other = _session(options.get("against") or options.get("session_b"), "options.against")
        group = options.get("group_by")
        group = group[0] if isinstance(group, list) and len(group) == 1 else group
        if group is not None and not isinstance(group, str):
            raise ValueError("options.group_by is one of kind, resource, state, module, source")
        reply = client.diff(session, other, group_by=group, kinds=_strings(options.get("kinds"), "options.kinds") or None,
                            align=options.get("align"), background=options.get("background"))
        return shape(reply, session=session, command="trace_diff", limit=limit)
    if action == "explain":
        event_id = options.get("event_id")
        if not isinstance(event_id, str) or not _EVENT_ID.match(event_id):
            raise ValueError("options.event_id must be an event id")
        depth = options.get("depth", options.get("max_depth", 4))
        if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 16:
            raise ValueError("options.depth must be 1..16")
        if options.get("direction") not in (None, "upstream", "downstream"):
            raise ValueError("options.direction must be upstream or downstream")
        reply = client.explain(session, event_id, direction=str(options.get("direction") or "upstream"), max_depth=depth,
                               max_events=min(int(options.get("max_events", 200)), 1000))
        return shape(reply, session=session, command="trace_explain", limit=limit)
    if action == "mark":
        label = options.get("label")
        if not isinstance(label, str) or not label.strip() or len(label) > 200:
            raise ValueError("options.label is required (1..200 characters)")
        reply = client.mark(session, label, phase=options.get("phase"), frame=options.get("frame"),
                            cap=options.get("cap") or _TOKENS.get(session))
        return shape(reply, session=session, command="trace_mark", limit=limit)
    if action == "check":
        return shape(_check(client, session, options, limit), session=session, command="trace_check", limit=limit)
    if action == "export":
        # The engine chooses the folder (<root>/<session>/export/<name>); the caller names only the export.
        reply = client.export(session, name=options.get("name"), overwrite=options.get("overwrite"),
                              authorized_artifacts=_strings(options.get("authorized_artifacts"), "options.authorized_artifacts") or None,
                              exported_at=options.get("exported_at"))
        return shape(reply, session=session, command="trace_export", limit=limit)
    if action == "reprocess":
        codecs = options.get("codecs")
        if not isinstance(codecs, dict) or not codecs:
            raise ValueError("options.codecs is {layout name: {name, fields: [{name, offset, len, type, endian?}]}}")
        reply = client.reprocess(session, codecs=codecs, context=options.get("context"), contexts=options.get("contexts"),
                                 kinds=_strings(options.get("kinds"), "options.kinds") or None,
                                 bytes_field=options.get("bytes_field"), note=options.get("note"),
                                 cap=options.get("cap") or _TOKENS.get(session))
        return shape(reply, session=session, command="trace_reprocess", limit=limit)
    if action == "relations":
        op = options.get("op", "materialize")
        if op not in ("materialize", "status"):
            raise ValueError("options.op is materialize or status")
        reply = client.relations(session, op=op, cap=(options.get("cap") or _TOKENS.get(session)) if op == "materialize" else None)
        return shape(reply, session=session, command="trace_relations", limit=limit)
    options = _open_program(client, options)
    return shape(client.resymbolize(session, program=options.get("program"), project=options.get("project"),
                                    modules=_strings(options.get("modules"), "options.modules") or None,
                                    cap=options.get("cap") or _TOKENS.get(session)),
                 session=session, command="trace_resymbolize", limit=limit)


def call(args: dict, settings: dict) -> str:
    """The `trace` tool: ARGS is {action, session?, options?}; the reply is JSON text."""
    action = args.get("action")
    if not isinstance(action, str):
        raise ValueError("trace requires action: " + ", ".join(ACTIONS))
    options = args.get("options")
    if options is not None and not isinstance(options, dict):
        raise ValueError("options must be an object")
    session = args.get("session")
    try:
        result = handle_action(action, session if session not in (None, "") else None, dict(options or {}), settings)
    except TraceError as error:
        result = error.payload()
    except Exception as error:  # noqa: BLE001
        from hydralysis.profiles import HookRefused, ProfileError
        if isinstance(error, (HookRefused, ProfileError)):
            result = error.payload()
        else:
            raise
    return json.dumps(result, indent=2, ensure_ascii=False)


# ---- citing a trace from evidence (source kind `from_trace`) ---------------------------------------------------

def citation(session: str, events: list[str], revision: int, interpretation: int | None = None) -> dict:
    """The `from_trace` source of an evidence claim: session, event ids and the committed revision they were read at."""
    value = {"session": session, "events": list(events), "revision": revision}
    if interpretation is not None:
        value["interpretation"] = interpretation
    return evidence.check_from_trace(value)


def pin_for(session: str, revision: int, events: list[str], *, interpretation: int | None = None, profile: dict | None = None,
            artifacts: list[dict] | None = None, unauthorized: list[dict] | None = None, coverage: dict | None = None) -> dict:
    """A bundle pin (`traces/<session>.json`): the revision, events and authorized artifact ranges a claim can be re-read
    from. Artifacts without authorization are never pinned; they are listed under `cannot_reproduce`."""
    from hydralysis.evidence_bundle import TRACE_PIN_FORMAT, check_pin
    cannot = [{"what": "artifact %s %s" % (item.get("id", "?"), item.get("range", "")), "reason": item.get("reason", "payload-not-authorized")}
              for item in unauthorized or []]
    pin = {"format": TRACE_PIN_FORMAT, "trace_id": session, "session": session, "revision": revision,
           "interpretation_revision": interpretation, "profile": profile, "events": sorted(set(events)),
           "artifacts": [{"id": a["id"], "sha256": a["sha256"], "range": list(a["range"]), "authorized": True} for a in artifacts or []],
           "coverage": coverage or {"revision": None, "gaps": []}, "reproducible": not cannot, "cannot_reproduce": cannot}
    return check_pin(pin, session)


def pin_digest(pin: dict) -> str:
    return hashlib.sha256(trace_canon.canonical_bytes(pin)).hexdigest()
