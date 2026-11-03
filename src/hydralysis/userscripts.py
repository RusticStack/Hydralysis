"""ghidra_run: one of your own Ghidra scripts on a target's saved analysis.

The engine only loads Java scripts from its script path, so the script is copied
into Hydralysis's user-scripts folder first (never over one of Hydralysis's own, and
never over a different script of the same name). Nothing is imported and no project is copied.

How the script is isolated (PROTOCOL-3.md 3.6, 7.4, D20, D47, D64; Y4e):

- An engine without the `scriptIsolation` capability (hydra.2/3): today's contained mode (the engine rolls back an
  outer transaction). Options that ask for a mode are answered `not_available` and the script is not run (7.5).
- A user script never runs `shared` (D47).
- On the sealed master (a program with nothing unsaved): `private`, a throwaway program object from the stored file.
- On a view's working copy, on an engine whose `scriptIsolation` is 2 or more (E7, hydra.4): `worker`, a killable
  child JVM on a disposable clone of the SAVED view. The view's owner takes the per-view lock, saves the fork once and
  only when `info.changed` (a bounded save, D64: the clone of an unsaved view would answer from a stale file, and the
  engine refuses it with `conflict`, `reason:"unsaved"`), passes the saved revision as `basedOn` and submits. A script
  that ignores cancel is killed at its timeout and nothing of the run reaches the view.
- On a view's working copy on an engine without the worker: `private` when it has nothing unsaved, else `exclusive`.

`options.isolation` (`private` or `exclusive`) overrides the choice; `private` is refused on a program with unsaved
edits (it would answer from the stored file). `options.readonly:true` fails the job when the script attempted changes
(`attemptedChanges`). The reply surfaces `isolation`, `attemptedChanges` and `basedOn`.

The `ghidra_run` options reach this module through `api.HANDLER_MODULES["scriptIsolation"]` (Y2's registry, 8.2).
The registry's request carries no target or script, so `handle` cannot run the script itself: it validates the
options, hands them to the `run` that `api.py` calls next in the same context, and returns "" so that the dispatcher
goes on to `run`. `run` takes them first thing, so they never outlive the one call they belong to.
"""

from __future__ import annotations

import contextvars
import json
import re
import time
import uuid
from pathlib import Path

from hydralysis import hydra, targets, viewnative, workcopy
from hydralysis.backends import read_json, write_json
from hydralysis.paths import root_path

_SCRIPT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:java|py)")

# The isolation values a caller may ask for. `shared` never (D47); `worker` is chosen for a view, not asked for (the
# request enum that api.py validates has no `worker`).
ASKABLE = ("private", "exclusive")
OPTION_KEYS = ("isolation", "readonly")
# The engine's `scriptIsolation` version from which `isolation:"worker"` exists (E7 advertises 2).
WORKER_VERSION = 2

# The options `handle` validated, for the `run` that api.py calls next in the same context (see the module docstring).
_PENDING: contextvars.ContextVar = contextvars.ContextVar("hydralysis_ghidra_run_options", default=None)


class NotAvailable(Exception):
    """Options that ask for something the engine has no capability for: answered `not_available`, nothing is run."""

    def __init__(self, capability: str, message: str):
        super().__init__(message)
        self.capability = capability
        self.message = message


def check_options(options) -> dict:
    """The validated `ghidra_run` options: only `isolation` (private, exclusive) and `readonly` (a boolean)."""
    if options is None:
        return {}
    if not isinstance(options, dict):
        raise ValueError("options must be an object")
    unknown = sorted(set(options) - set(OPTION_KEYS))
    if unknown:
        raise ValueError("ghidra_run options take isolation and readonly (and as); not %s" % ", ".join(unknown))
    isolation = options.get("isolation")
    if isolation == "shared":
        raise ValueError("a user ghidra_run never runs shared (its changes would be visible to other readers while it "
                         "runs); omit isolation to get private, worker or exclusive, or ask for private or exclusive")
    if isolation is not None and isolation not in ASKABLE:
        raise ValueError("ghidra_run options.isolation must be private or exclusive")
    if "readonly" in options and not isinstance(options["readonly"], bool):
        raise ValueError("ghidra_run options.readonly must be a boolean")
    return dict(options)


def handle(capability: str, request: dict) -> str:
    """The registered handler of `scriptIsolation` (api.HANDLER_MODULES): validate, hand on to `run`, return ""."""
    _PENDING.set(check_options(request.get("options")))
    return ""


def choose(level: int, on_view: bool, changed: bool, asked: str | None) -> str | None:
    """The isolation of one run (7.4); None is today's contained mode (an engine without the capability).

    LEVEL is the engine's `scriptIsolation` version (0: none), ON_VIEW whether the program is a view's working copy,
    CHANGED whether it has unsaved edits (`info.changed`), ASKED the caller's `options.isolation`."""
    if asked is not None:
        if not level:
            raise NotAvailable("scriptIsolation", "this engine has no script isolation (hydra.2/3); the script was not "
                               "run. Call ghidra_run without options for today's contained mode")
        if asked == "private" and changed:
            raise ValueError("isolation private reads the stored file, and this program has unsaved edits it would not "
                             "see; omit isolation (a view is saved first and the script runs in a worker) or ask for "
                             "exclusive")
        return asked
    if not level:
        return None
    if on_view and level >= WORKER_VERSION:
        return "worker"
    return "exclusive" if changed else "private"


def _level(engine, name: str) -> int:
    """The version of capability NAME the engine advertises; 0 when it does not (or cannot say: a stand-in)."""
    found = getattr(engine, "capabilities", None)
    if not callable(found):
        return 0
    try:
        value = found().get(name, 0)
    except Exception:
        return 0
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _save_view(settings: dict, engine, selected: dict, program: dict) -> dict:
    """The owner's one bounded save before a worker clones the view (D64): under the per-view lock, only if changed.

    Returns {"revision", "saved", "seconds"}; `revision` is the saved revision the worker's clone is based on."""
    from hydralysis.query import forget, open_program
    started = time.monotonic()
    with workcopy.view_lock(settings, selected):
        info = engine.call("info", program=program["key"])
        if not info.get("changed"):
            return {"revision": info.get("revision"), "saved": False, "seconds": round(time.monotonic() - started, 3)}
        writer = workcopy.writer_for(settings, selected)
        try:
            owned = open_program(writer, program["gpr"], selected["program"], selected["sha256"],
                                 writable=True, upgrade=True, refresh=True)
            reply = writer.call("save", program=owned["key"], comment="Hydralysis: view saved before a worker script",
                                wait=int(workcopy.SYNC_LOCK_S * 1000))
        finally:
            writer.reset()
            forget(writer)
    return {"revision": reply.get("revision"), "saved": True, "seconds": round(time.monotonic() - started, 3)}


def _unsaved(error: hydra.EngineError) -> bool:
    return error.code == "conflict" and (error.details or {}).get("reason") == "unsaved"


def _stage(settings: dict, source: Path) -> str:
    own = Path(__file__).with_name("scripts")
    native = viewnative.native_views()
    if native is not None:
        return viewnative.call(native, "userscripts_stage", [{}, str(own), str(hydra.script_dirs(settings)[1]), str(source)])
    if (own / source.name).exists():
        raise ValueError("%s is the name of one of Hydralysis's own scripts; rename yours" % source.name)
    folder = hydra.script_dirs(settings)[1]
    folder.mkdir(parents=True, exist_ok=True)
    staged = folder / source.name
    data = source.read_bytes()
    if staged.is_file() and staged.read_bytes() != data:
        owner = read_json(folder / "owners.json").get(source.name)
        if owner and owner != str(source.resolve()):
            raise ValueError("a different %s from %s is staged already; rename one of them" % (source.name, owner))
    if not staged.is_file() or staged.read_bytes() != data:
        temporary = staged.with_name(staged.name + ".tmp")
        temporary.write_bytes(data)
        temporary.replace(staged)
    owners = read_json(folder / "owners.json")
    owners[source.name] = str(source.resolve())
    write_json(folder / "owners.json", owners)
    return source.name


def run(settings: dict, target: str, script: str, args: list[str], timeout_s: int = 600, view: str = "", who: dict | None = None,
        options: dict | None = None) -> str:
    # The options `handle` validated belong to this call alone: taken first, before anything here can raise.
    pending = _PENDING.get()
    _PENDING.set(None)
    options = check_options(options if options is not None else pending)
    from hydralysis.query import QueryRunner
    resolved = targets.resolve(settings, target)
    # No view named: the caller's own view when it has one (`who`, from `options.as` or the process default), else the sealed
    # master (D43). It never reads a view the caller does not hold.
    master = False
    if not view and who is not None:
        view = "shared" if who["shared"] else who["name"]
        master = not who["shared"] and not workcopy.view_exists(settings, workcopy.with_view(resolved, view))
    selected = workcopy.master_target(resolved) if master else workcopy.with_view(resolved, view)
    name = script if script.endswith((".java", ".py")) else script + ".java"
    if not _SCRIPT.fullmatch(name):
        raise ValueError("script must be a simple .java or .py file name")
    folder = Path(selected.get("scripts") or "")
    if not selected.get("scripts") or not (folder / name).is_file():
        raise ValueError("script %s is not in target %s's scripts directory (%s)" % (name, target, folder or "not set"))
    if not 1 <= timeout_s <= 14400:
        raise ValueError("timeout_s must be 1..14400")
    if len(args) > 64 or any(not isinstance(item, str) or len(item) > 32768 for item in args):
        raise ValueError("script arguments must be at most 64 strings")
    runner = QueryRunner(settings)
    engine = runner.engine
    level = _level(engine, "scriptIsolation")
    readonly = bool(options.get("readonly"))
    try:
        if options.get("readonly") is not None and not _level(engine, "attemptedChanges"):
            raise NotAvailable("attemptedChanges", "this engine does not report attemptedChanges (hydra.2/3), so a "
                               "readonly run cannot be checked; the script was not run")
        # Checked before anything is staged or opened: a refused option changes nothing.
        if options.get("isolation") is not None and not level:
            choose(level, False, False, options["isolation"])
    except NotAvailable as missing:
        from hydralysis import api
        return api.not_available(missing.capability, missing.message, tool="ghidra_run", options=sorted(options))
    staged = _stage(settings, folder / name)
    program = runner.program_for(selected)
    on_view = not selected.get("master_read") and workcopy.has_overlays(settings, selected)
    changed = bool(engine.call("info", program=program["key"]).get("changed")) if level else False
    isolation = choose(level, on_view, changed, options.get("isolation"))
    job_id = "job-%s" % uuid.uuid4().hex[:12]
    started = time.time()
    record = {"job_id": job_id, "kind": "script", "target": target, "view": selected["view"], "script": name, "args": args,
              "started_at": started, "created_at": started, "program": program["key"], "state": "running"}
    if isolation:
        record["isolation"] = isolation
    jobs = root_path(settings) / "jobs"
    write_json(jobs / (job_id + ".json"), record)
    fields = {"script": staged, "program": program["key"], "args": args, "timeout": timeout_s, "maxChars": 1_000_000,
              "wait": 30000}
    if isolation:
        fields["isolation"] = isolation
    saves = []
    try:
        for attempt in (1, 2):
            if isolation == "worker":
                based = _save_view(settings, engine, selected, program)
                saves.append(based)
                fields["basedOn"] = {"saved": True, "programRevision": based["revision"]}
            try:
                result = engine.call("script", **fields)
                break
            except hydra.EngineError as error:
                # An edit that landed between the owner's save and the clone: saved once more, then submitted again.
                if isolation != "worker" or attempt == 2 or not _unsaved(error):
                    raise
        record.update(state="done", output=result.get("output", ""), truncated=result.get("truncated"),
                      mode=result.get("mode"), changed=result.get("changed"))
        if isolation:
            record.update(isolation=result.get("isolation", isolation), attempted_changes=result.get("attemptedChanges"),
                          attempted_changes_count=result.get("attemptedChangesCount"), based_on=result.get("basedOn"),
                          unsaved_ignored=result.get("unsavedIgnored"))
            if isinstance(result.get("worker"), dict):
                record["worker"] = {key: result["worker"].get(key) for key in ("pid", "totalMs", "startMs", "cloneMs", "killed")}
        if readonly and result.get("attemptedChanges"):
            record.update(state="failed", error="readonly run: the script attempted %s change(s); nothing of it was kept"
                          % result.get("attemptedChangesCount", "some"))
    except hydra.EngineError as error:
        record.update(state="failed", error=str(error))
    if isolation == "worker":
        record["view_saves"] = [item for item in saves if item["saved"]]
    record.update(finished_at=time.time(), duration_s=round(time.time() - started, 2))
    write_json(jobs / (job_id + ".json"), record)
    if record["state"] != "done":
        raise RuntimeError("script job %s failed: %s" % (job_id, record["error"]))
    isolated = ""
    if isolation:
        based_on = record.get("based_on") or {}
        isolated = ("\nisolation=%s attemptedChanges=%s (%s) basedOn=%s view_saved=%s"
                    % (record["isolation"], json.dumps(record.get("attempted_changes")), record.get("attempted_changes_count"),
                       based_on.get("programRevision") if based_on else "-",
                       "yes" if record.get("view_saves") else "no"))
        if record.get("unsaved_ignored"):
            isolated += " unsavedIgnored=%s" % record["unsaved_ignored"]
    return ("job=%s target=%s view=%s script=%s mode=%s state=done duration=%ss%s%s\n--- script output ---\n%s"
            % (job_id, target, selected["view"], name, record["mode"], record["duration_s"],
               " (output truncated)" if record.get("truncated") else "", isolated, record["output"] or "(no script output)"))


def list_scripts(settings: dict, target: str, name_filter: str = "") -> str:
    selected = targets.resolve(settings, target)
    folder = Path(selected.get("scripts") or "")
    native = viewnative.native_views()
    if native is not None:
        return viewnative.call(native, "userscripts_list_scripts", [{}, target, selected.get("scripts") or None, str(folder), name_filter])
    if not selected.get("scripts") or not folder.is_dir():
        raise ValueError("target %s has no scripts directory" % target)
    rows = []
    for path in sorted(folder.iterdir()):
        if path.suffix in (".java", ".py") and (not name_filter or name_filter.lower() in path.name.lower()):
            usage = ""
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:40]:
                stripped = line.strip().lstrip("/# ").strip()
                if stripped.lower().startswith("usage"):
                    usage = stripped
                    break
            rows.append("%s  %s" % (path.name, usage))
    return "\n".join(rows) if rows else "no scripts in %s" % folder


# ---- optional Rust implementation of the option rules (HYDRALYSIS_IMPL=rust) -------------------------------------------


def _chosen(reply: dict):
    """The native `choose` answers `{"isolation": ...}`, or `{"not_available": {...}}` for the refusal the original raises."""
    if "not_available" in reply:
        raise NotAvailable(reply["not_available"]["capability"], reply["not_available"]["message"])
    return reply["isolation"]


check_options = viewnative.routed("userscripts_check_options", check_options, prepare=lambda values: [{}] + values)
choose = viewnative.routed("userscripts_choose", choose, prepare=lambda values: [{}] + values, finish=_chosen)
