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
from pathlib import Path

from hydralysis import evidence, proc, trace_canon, trace_schema

ACTIONS = ("start", "stop", "status", "query", "diff", "explain", "mark", "export", "check", "import", "resymbolize")
# Actions that are jobs on the engine and so take the long lane of the MCP server.
LONG_ACTIONS = frozenset({"export", "import", "resymbolize"})
COMMANDS = ("trace_open", "trace_append", "trace_mark", "trace_query", "trace_explain", "trace_diff", "trace_check",
            "trace_export", "trace_close", "trace_list", "trace_info", "trace_resymbolize")
# Read commands the engine answers the same however often they are sent; a lost reply may be sent again.
IDEMPOTENT_COMMANDS = frozenset({"trace_list", "trace_info", "trace_query", "trace_explain", "trace_diff", "trace_check"})
CAPABILITY = "trace"

DEFAULT_LIMIT, MAX_LIMIT = 25, 200
MAX_REPLY_BYTES = 48 * 1024
MAX_CITATIONS = 50
MAX_IMPORT_EVENTS = 100_000
MAX_IMPORT_BYTES = 64 * 1024 * 1024
BATCH_EVENTS = 500
_SESSION = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$")
_EVENT_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,119}$")
_LIST_KEYS = ("groups", "events", "rows", "items", "results", "counterexamples", "sessions", "only_a", "only_b",
              "different_under_matched_coverage", "not_comparable", "paths", "marks", "unresolved", "assertions", "jobs")
_TOKENS: dict[str, str] = {}      # session -> the owner capability this process was given by trace_open
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
            if key in ("event_id", "from_event", "to_event", "representative", "first_event", "last_event") and isinstance(item, str):
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
    for key in _LIST_KEYS:
        if isinstance(out.get(key), list) and len(out[key]) > limit:
            truncated[key] = len(out[key]) - limit
            out[key] = out[key][:limit]
    coverage = out.get("coverage") if isinstance(out.get("coverage"), dict) else None
    gaps = (coverage or {}).get("gaps", out.get("gaps"))
    gaps = gaps if isinstance(gaps, list) else []
    if len(gaps) > limit:
        truncated["gaps"] = len(gaps) - limit
        gaps = gaps[:limit]
    revision = out.get("revision", requested_revision)
    out["coverage"] = {"revision": (coverage or {}).get("revision", out.get("coverage_revision")), "gaps": gaps,
                       "reported": coverage is not None or "coverage_revision" in out}
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
        sized = [(key, len(out[key])) for key in _LIST_KEYS if isinstance(out.get(key), list) and len(out[key]) > 1]
        if not sized:
            break
        key = max(sized, key=lambda item: (_size(out[item[0]]), item[0]))[0]
        keep = max(1, len(out[key]) // 2)
        truncated[key] = truncated.get(key, 0) + len(out[key]) - keep
        out[key] = out[key][:keep]
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

    def open(self, **fields) -> dict:
        return self.call("trace_open", **fields)

    def append(self, session: str, events: list, **fields) -> dict:
        return self.call("trace_append", session=session, events=events, **fields)

    def mark(self, session: str, label: str, **fields) -> dict:
        return self.call("trace_mark", session=session, label=label, **fields)

    def query(self, session: str, **fields) -> dict:
        return self.call("trace_query", session=session, **fields)

    def explain(self, session: str, event_id: str, **fields) -> dict:
        return self.call("trace_explain", session=session, event_id=event_id, **fields)

    def diff(self, session_a: str, session_b: str, **fields) -> dict:
        return self.call("trace_diff", session_a=session_a, session_b=session_b, **fields)

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

# The `hydra-trace` verbs and their argument order, as this module calls them. `gen` and `verify <segment> <id>` exist
# today; the others are the store lane's (import, rebuild, export) and are not advertised until it ships them.
OFFLINE_VERBS = {"import": ("store", "session", "input"), "rebuild": ("store", "session"),
                 "export": ("store", "session", "output"), "check": ("store", "session")}


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
    """Verify every `*.trace` segment under DIRECTORY with the Python twin; the five outcomes are kept apart."""
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


def _offline(action: str, options: dict, settings: dict) -> dict:
    store = Path(str(options.get("store") or Path(settings.get("root", ".")) / "traces"))
    verb = str(options.get("op") or ("import" if action == "import" else action))
    if verb == "verify":
        session = _session(options.get("session") or options.get("name") or "", "options.session")
        return {"offline": True, "op": "verify", **offline_verify(store / session, _strings(options.get("segments"), "options.segments"))}
    if action == "import" and verb == "import":
        name = _session(options.get("session") or "", "options.session")
        source = Path(str(options.get("input") or options.get("file") or ""))
        read = read_jsonl(source)
        summary = {key: read[key] for key in ("outcome", "lines", "damage", "lost_producers", "reason") if key in read}
        if not read["events"]:
            return {"offline": True, "op": "import", "imported": 0, **summary}
        target = store / name
        target.mkdir(parents=True, exist_ok=True)
        segment_id = _session(options.get("source_id") or read["events"][0]["source_id"], "source_id")
        path = target / (segment_id + ".trace")
        if path.exists():
            raise TraceError("segment_exists", "%s exists; a segment is append-only and is not replaced" % path)
        from hydralysis import durable
        durable.atomic_write(path, segment_from_events(read["events"], segment_id))
        result = {"offline": True, "op": "import", "imported": len(read["events"]), "segment": str(path),
                  "verified": offline_verify(target, [segment_id])["outcome"], **summary}
        if options.get("rebuild", True) and find_tool(settings):
            result["rebuild"] = run_tool(settings, "rebuild", [str(store), name])
        return result
    if verb in OFFLINE_VERBS:
        fields = {"store": str(store), "session": _session(options.get("session") or "", "options.session"),
                  "input": str(options.get("input") or ""), "output": str(options.get("output") or options.get("out") or "")}
        return {"offline": True, "op": verb, **run_tool(settings, verb, [fields[name] for name in OFFLINE_VERBS[verb]])}
    raise ValueError("offline op must be verify, import, rebuild, export or check")


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
                      "authorize_preview", "builtin", "watchdog", "etw", "fault_policy", "producer_gen")


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


def _start(client: TraceClient, session: str | None, options: dict, settings: dict) -> dict:
    from hydralysis import profiles
    profile = _load_profile(options)
    verification = _verify_profile(profile, options) if profile is not None else None
    scope = _object(options.get("scope"), "options.scope")
    if scope.get("add") and not options.get("owner_token"):
        raise TraceError("scope_expansion_needs_owner", "adding processes or services to the scope needs the owner token")
    limitations = list((verification or {}).get("limitations", []))
    opened = client.open(
        session=session, profile=profile.session_record() if profile else None, scenario=str(options.get("scenario") or ""),
        scope=scope or {"process_tree": True}, capture=_object(options.get("capture"), "options.capture") or None,
        watchpoints=options.get("watchpoints"), limitations=limitations or None,
        enabled_hooks=(verification or {}).get("enabled"), label=options.get("label"))
    name = str(opened.get("session") or session or "")
    if opened.get("owner"):
        _TOKENS[name] = str(opened["owner"])
    result = {"session": name, "opened": opened, "profile": verification and {k: verification[k] for k in
              ("profile", "profile_sha256", "counts", "limitations", "enabled")},
              "owner": opened.get("owner")}
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
                client.close(name, reason="launch failed: %s" % exc, owner=_TOKENS.pop(name, None))
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
    result["closed"] = client.close(session, owner=options.get("owner") or _TOKENS.get(session), reason=options.get("reason"))
    _TOKENS.pop(session, None)
    _LINKS.pop(session, None)
    return result


def _query(client: TraceClient, session: str, options: dict, limit: int) -> dict:
    fields = {"kinds": _strings(options.get("kinds"), "options.kinds") or None, "filter": _object(options.get("filter"), "options.filter") or None,
              "group_by": _strings(options.get("group_by"), "options.group_by", 8) or None, "cursor": options.get("cursor"),
              "revision": options.get("revision"), "interpretation": options.get("interpretation"), "limit": limit}
    if options.get("profile_query"):
        from hydralysis import profiles
        profile = _load_profile(options)
        if profile is None:
            raise ValueError("options.profile is required with options.profile_query")
        query = next((q for q in profile.data["queries"] if q["id"] == options["profile_query"]), None)
        if query is None:
            raise ValueError("profile %s has no query %s" % (profile.id, options["profile_query"]))
        if "module" in query:
            rows = client.query(session, **{**fields, "kinds": options.get("kinds"), "limit": limit})
            module_rows = rows.get("events") or rows.get("groups") or rows.get("rows") or []
            return {**rows, "module": query["id"], "module_result": profiles.run_module(
                profile, query["id"], module_rows[:limit], _object(options.get("params"), "options.params"))}
        fields.update({k: v for k, v in profiles.compile_query(profile, query["id"], session=session, limit=limit).items()
                       if k not in ("session",) and fields.get(k) is None})
    return client.query(session, **fields)


def _check(client: TraceClient, session: str, options: dict, limit: int) -> dict:
    assertions = options.get("assertions")
    if assertions is not None and (not isinstance(assertions, list) or not all(isinstance(a, dict) for a in assertions) or len(assertions) > 64):
        raise ValueError("options.assertions is a list of at most 64 assertion objects")
    return client.check(session, assertions=assertions, assertion=options.get("assertion"), revision=options.get("revision"),
                        limit=limit, save=options.get("save"))


def _import(client: TraceClient, session: str | None, options: dict) -> dict:
    source = Path(str(options.get("input") or options.get("file") or ""))
    read = read_jsonl(source)
    summary = {key: read[key] for key in ("outcome", "lines", "damage", "lost_producers", "reason") if key in read}
    if not read["events"]:
        return {"imported": 0, "session": session, **summary}
    opened = client.open(session=session, scenario=str(options.get("scenario") or "import"), imported=True,
                         label=options.get("label"), scope={"process_tree": False, "import": str(source.name)})
    name = str(opened.get("session") or session or "")
    appended = 0
    last = {}
    for start in range(0, len(read["events"]), BATCH_EVENTS):
        batch = read["events"][start:start + BATCH_EVENTS]
        last = client.append(name, batch, owner=opened.get("owner"))
        appended += len(batch)
    closed = client.close(name, owner=opened.get("owner"), reason="import complete") if not options.get("keep_open") else None
    return {"session": name, "imported": appended, "damaged_input_ignored_after": summary.get("damage"), **summary,
            "last_append": last, "closed": closed}


def handle_action(action: str, session: str | None, options: dict, settings: dict, client: TraceClient | None = None) -> dict:
    """Run one action and return the shaped reply (a dict). `client` is injectable for tests."""
    if action not in ACTIONS:
        raise ValueError("trace action must be one of: " + ", ".join(ACTIONS))
    limit = _limit(options)
    if options.get("offline"):
        return _offline(action, options, settings)
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
    if session is None:
        raise ValueError("trace %s requires session" % action)
    if action == "stop":
        return shape(_stop(client, session, options, settings), session=session, command="trace_close", limit=limit)
    if action == "query":
        reply = _query(client, session, options, limit)
        return shape(reply, session=session, command="trace_query", limit=limit, requested_revision=options.get("revision"))
    if action == "diff":
        other = _session(options.get("against") or options.get("session_b"), "options.against")
        reply = client.diff(session, other, group_by=_strings(options.get("group_by"), "options.group_by", 8) or None,
                            limit=limit, align=options.get("align"), cursor=options.get("cursor"),
                            budget=options.get("budget"))
        return shape(reply, session=session, command="trace_diff", limit=limit)
    if action == "explain":
        event_id = options.get("event_id")
        if not isinstance(event_id, str) or not _EVENT_ID.match(event_id):
            raise ValueError("options.event_id must be an event id")
        depth = options.get("depth", 4)
        if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 16:
            raise ValueError("options.depth must be 1..16")
        reply = client.explain(session, event_id, direction=str(options.get("direction") or "upstream"), depth=depth,
                               max_events=min(int(options.get("max_events", 200)), 1000), limit=limit,
                               revision=options.get("revision"))
        return shape(reply, session=session, command="trace_explain", limit=limit)
    if action == "mark":
        label = options.get("label")
        if not isinstance(label, str) or not label.strip() or len(label) > 200:
            raise ValueError("options.label is required (1..200 characters)")
        reply = client.mark(session, label, note=str(options.get("note") or "")[:2000] or None,
                            event_range=options.get("event_range"), owner=options.get("owner") or _TOKENS.get(session))
        return shape(reply, session=session, command="trace_mark", limit=limit)
    if action == "check":
        return shape(_check(client, session, options, limit), session=session, command="trace_check", limit=limit)
    if action == "export":
        reply = client.export(session, out=str(options.get("out") or "") or None, format=str(options.get("format") or "jsonl"),
                              filter=_object(options.get("filter"), "options.filter") or None,
                              include_artifacts=bool(options.get("include_artifacts", False)),
                              artifact_authorization=options.get("artifact_authorization"))
        return shape(reply, session=session, command="trace_export", limit=limit)
    return shape(client.resymbolize(session, program=options.get("program"), symbol_revision=options.get("symbol_revision"),
                                    owner=options.get("owner") or _TOKENS.get(session)),
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
