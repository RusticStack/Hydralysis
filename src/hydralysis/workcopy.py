"""Cited overlays, materialized in a working copy of the analysed project.

The overlay store (overlays/<target key>.json) is the record: every edit carries
its cited source, who made it (client and harness) and when, and the store has a
revision that only moves forward. The canonical project is never written.

To answer from the overlays, the engine forks the shared base of the master
(the master in the engine's database format, built once per master revision,
generation and engine release by whichever caller gets there first) into a
working copy (a block clone on ReFS, a bounded copy elsewhere) and applies
every pending record in one owner transaction. The program then records the
overlay state it holds; a reader compares that with the store and refreshes
before it would answer from another version. A changed master, a reverted
record or a missing copy means a new fork and a full replay; otherwise new
records are applied incrementally.

A working copy is a cache and nothing else (D61): no second process saves it,
the store is the record, and what the daemon loses with a restart is replayed
from the store because the program's marker shows what it holds. One writer at a
time per view holds an OS lock for at most SYNC_LOCK_S (then a structured
`busy`); a sync uses a writer connection of its own, so two views never close
each other's projects; an editor that read an older revision gets a conflict
instead of overwriting.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from hydralysis import durable, hydra, integrity, lineage, revisions
from hydralysis.analysis import MAX_CORPUS_BYTES, MAX_HISTORY_BYTES, MAX_OVERLAYS, _edit, _overlay_path
from hydralysis.backends import read_json, write_json
from hydralysis.locks import LaneLock, LockBusy, locked
from hydralysis.paths import root_path

# The per-view lock bound (D44) and the bound on waiting for another caller's build of the shared base (4.10).
# Both are unmeasured starting values; past them the caller gets the structured `busy`, never a silent wait.
SYNC_LOCK_S = 30
BASE_WAIT_S = 30


@contextmanager
def view_lock(settings: dict, target: dict, wait_s: float | None = None):
    """The per-view lock (replaces the per-target `.sync.lock`): bounded, OS-held, so a killed holder frees it.

    A wait that runs out (WAIT_S, default SYNC_LOCK_S) is a `LockBusy`; here it reaches the caller as the structured `busy`
    error (a RuntimeError carrying the JSON payload, like the conflict payloads of `revisions`)."""
    try:
        with locked(_directory(settings, target) / ".view.lock", SYNC_LOCK_S if wait_s is None else wait_s, "working copy"):
            yield
    except LockBusy as busy:
        raise RuntimeError(json.dumps(busy.payload())) from busy


def _origin(target: dict) -> dict:
    origin = target.get("origin_key") or target.get("key")
    return {"origin_key": origin} if origin else {}


def with_view(target: dict, view: str = "") -> dict:
    """Select a durable annotation namespace without changing the analysed target."""
    if not isinstance(view, str) or (view and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", view)):
        raise ValueError("view must be a name of 1..64 letters, digits, dots, dashes or underscores")
    if not view or view == "shared":
        return {**target, "view": "shared", **_origin(target)}
    key = hashlib.sha256((target["key"] + "\nview:" + view).encode()).hexdigest()[:16]
    # `origin_key` is the key of the master the view forks from: every view of it shares one base.
    return {**target, "key": key, "view": view, **_origin(target)}


def master_target(target: dict) -> dict:
    """The sealed master as a read target: no overlays, no working copy, no store (D43: an agent without a view reads it).

    `key` stays the target's key, so a reply names the same build; `master_read` tells `program_for` and `_ask` to skip
    the store of that key (which belongs to the `shared` view)."""
    return {**target, "view": "master", "master_read": True, **_origin(target)}


def view_exists(settings: dict, target: dict) -> bool:
    """Does the view of TARGET have a store? A view is created lazily, by its first edit; before that it has nothing."""
    return durable.exists(_store_path(settings, target))


def release(engine: hydra.Engine, settings: dict, target: dict) -> list[str]:
    """Close this process's open programs of the view's working copy, discarding what the daemon holds unsaved, and keep
    the folder (eviction, 3.11, D61): every record is in the store, so the next use replays what the program lost.

    Only the view's own forks are closed (the ones a reader of this process opened and the one its writer connection left
    open in the daemon): never the master, a generation or the shared base. Returns the project ids closed.

    A reader's `close_project` only makes that reader leave: the edits a sync left in a shared-mode program stay in the
    daemon as orphaned work, kept for ever (`orphanKeepS` 0) and counted as a view. The discard is therefore done by the
    view's writer lane, which joins each fork as a writer and closes it with discard (`discard_forks`)."""
    from hydralysis import query, viewgov
    ending = viewgov.session_ending()
    if ending and not getattr(engine, "connected", lambda: True)():
        return []   # the process is ending without a connection: there is no daemon of ours to close anything in
    folders = [folder.resolve() for folder in view_folders(settings, target)]
    with query._keys_guard:
        mine = [(key, value) for key, value in query._keys.items()
                if key[0] == engine.key and any(Path(key[1]).resolve().is_relative_to(folder) for folder in folders)]
    projects = {value["project"] for _, value in mine}
    state = _state(settings, target)
    forks = [item for item in [state.get("fork_gpr"), *(state.get("retired") or [])] if item]
    forks += [str(path) for path in _forks_on_disk(settings, target) if str(path) not in forks]
    closed = []
    for project in sorted(projects):
        try:
            engine.call("close_project", project=project, discard=True)
            closed.append(project)
        except hydra.EngineError as error:
            if error.code not in _GONE:
                raise
    with query._keys_guard:
        for key, value in mine:
            if query._keys.get(key) is value:
                query._keys.pop(key, None)
    if forks:
        try:
            with locked(_directory(settings, target) / ".view.lock", DISCARD_LOCK_S, "working copy"):
                writer = writer_for(settings, target, start=not ending)
                try:
                    done = discard_forks(settings, target, forks, writer)
                    # a copy the daemon let go of is the saved fork again, and the next use replays into it (D61); one it
                    # still holds for another reader is not reused
                    _forget_current(settings, target, _still_open(writer, done["closed"]))
                finally:
                    writer.reset()
                    query.forget(writer)
        except LockBusy:
            # A sync of the view is running (in this process or another): it owns the working copy now, and whatever
            # it supersedes it discards itself.
            return closed
        if done["failed"]:
            raise RuntimeError(json.dumps({"error": "release_failed", "failed": done["failed"]}))
        closed += [item for item in done["projects"] if item not in closed]
    return closed


# ---- closing working copies nothing will read again (9.17: the view leak) --------------------------------------
#
# A sync leaves its working copy open in the daemon in shared mode with the replayed records unsaved (D61): the
# writer connection leaves, the daemon keeps the work as an orphan (`orphanKeepS` 0: for ever) and counts the program
# as a view against `maxViews`. That is the working copy's warm cache while the view uses it. A copy the view no
# longer uses (superseded by a rebuild after a publish or a revert, rebased away, built by a failed operation, or
# left behind by a process that ended) would stay an orphan for ever, so every such copy is closed here with discard:
# its records are in the store, and nothing reads the copy again.

_GONE = ("not_found", "no_project", "closed", "no_program")
DISCARD_WAIT_MS = 30_000   # the engine's wait for the program while a running request finishes with it
DISCARD_LOCK_S = 5         # an eviction or a session end waits this long for the view lock, then leaves it to the sync


def _norm(gpr) -> str:
    return str(Path(gpr).resolve()).lower()


def view_folders(settings: dict, target: dict) -> list[Path]:
    """The folders that hold the view's working copies: its own and the one its rebases build in (`views._shadow`)."""
    own = _directory(settings, target)
    return [own, own.with_name(own.name + "r")]


def _still_open(engine: hydra.Engine, gprs: list[str]) -> list[str]:
    """The GPRS whose program the daemon still holds after a discard: used by a connection (another process's reader) or
    with unsaved work. A program nobody holds is the saved fork again. Unknown counts as held."""
    if not gprs:
        return []
    try:
        status = engine.call("status")
    except (hydra.EngineError, OSError, RuntimeError):
        return list(gprs)
    if not isinstance(status.get("programs"), list):
        return list(gprs)
    by_id = {item.get("id"): _norm(item["gpr"]) for item in status.get("projects", []) if item.get("gpr")}
    held = {by_id.get(row.get("project")) for row in status["programs"]
            if row.get("users") or row.get("writers") or (row.get("unsavedEdits") or 0) > 0}
    return [gpr for gpr in gprs if _norm(gpr) in held]


def _forget_current(settings: dict, target: dict, discarded: list[str], retired: list[str] | None = None) -> None:
    """After a discard: the state file stops naming a copy that was discarded as the view's current one, so the next use
    forks a new copy instead of reusing it. A discarded program is not a clean fork: while another connection still reads
    it the daemon keeps the edits it shows that reader, and its overlay marker no longer says what it holds (gate 9.17
    soak: K8 and "overlay state ''"). RETIRED, when given, replaces the state's retired list. The caller holds the view lock."""
    state = _state(settings, target)
    if not state:
        return
    gone = {_norm(gpr) for gpr in discarded if gpr}
    current = state.get("fork_gpr")
    changed = dict(state)
    if retired is not None:
        changed["retired"] = list(retired)
    if current and _norm(current) in gone:
        changed.pop("fork_gpr", None)
        changed.pop("state", None)
        if current not in changed.get("retired", []) and Path(current).exists():
            changed["retired"] = [*changed.get("retired", []), current]
    if changed != state:
        write_json(_directory(settings, target) / "state.json", changed)


def _forks_on_disk(settings: dict, target: dict) -> list[Path]:
    """Every working copy of the view that is on disk (`w-*/<name>.gpr` in the view's folders), referenced or not: a state
    file that was lost (K15 removes it) or never written (a sync that failed) no longer names the copies it made."""
    found = []
    for folder in view_folders(settings, target):
        if folder.is_dir():
            found += sorted(path for path in folder.glob("w-*/*.gpr") if path.is_file())
    return found


def superseded_forks(settings: dict, target: dict, keep: list[str], also: list[str] = ()) -> list[str]:
    """The view's working copies other than KEEP: the ones its state names (current and retired), ALSO, and every other
    copy on disk in the view's folders. The view lock must be held (no other sync of the view is making one)."""
    kept = {_norm(item) for item in keep if item}
    state = _state(settings, target)
    seen, out = set(), []
    for gpr in [state.get("fork_gpr"), *(state.get("retired") or []), *also, *map(str, _forks_on_disk(settings, target))]:
        if gpr and _norm(gpr) not in kept and _norm(gpr) not in seen:
            seen.add(_norm(gpr))
            out.append(gpr)
    return out


def retire_copies(settings: dict, target: dict, keep: list[str] = ()) -> dict:
    """Close every working copy of the view except KEEP with discard, remove the folders the daemon let go of, and record
    the rest as retired in the state file (a later sync tries again). For a view whose copy nothing will read again: its
    records were all published, or its base moved and the next use rebuilds it. The caller holds the view lock."""
    gone = superseded_forks(settings, target, keep=list(keep))
    if not gone:
        return {"closed": [], "projects": [], "failed": []}
    writer = writer_for(settings, target)
    try:
        done = discard_forks(settings, target, gone, writer)
        retired = _retire(writer, gone)
    finally:
        from hydralysis.query import forget
        writer.reset()
        forget(writer)
    _forget_current(settings, target, gone, retired)
    return done


def _reader_rows(gprs: set[str]) -> list[tuple[str, list[tuple], str]]:
    """This process's cached read-only rows of the programs in GPRS: (connection key, rows, daemon program key)."""
    from hydralysis import query
    groups: dict[tuple[str, str], list[tuple]] = {}
    with query._keys_guard:
        for key, value in query._keys.items():
            if not key[3] and _norm(key[1]) in gprs:
                groups.setdefault((key[0], value["key"]), []).append(key)
    return [(connection, rows, program) for (connection, program), rows in groups.items()]


def _close_reader_rows(settings: dict, gprs: set[str]) -> None:
    """Close this process's read-only uses of GPRS on the shared reader connection, the one `QueryRunner` reads through, so
    that a closed copy has no reader of ours left and the per-connection view cap (`maxViewsPerClient`) is given back.
    Best effort: a row of another connection (a pool entry, on hydra.2/3) is dropped from the cache only, as `forget` does."""
    from hydralysis import query
    reader = hydra.Engine(settings)
    # A connection that is gone took its uses with it: its rows are only dropped (a call would connect, and could start a daemon).
    live = getattr(reader, "connected", lambda: True)()
    for connection, rows, program in _reader_rows(gprs):
        if connection == reader.key and live:
            try:
                reader.call("close_program", program=program)
            except hydra.EngineError as error:
                if error.code not in _GONE:
                    continue   # still open: the cache keeps it, and the LRU close of the cap can still find it
            except OSError:
                continue
        with query._keys_guard:
            for key in rows:
                query._keys.pop(key, None)


def close_superseded_readers(settings: dict, target: dict) -> dict:
    """Close this process's read-only uses of the view's working copies that are not its current one, and discard what the
    daemon still holds of them. Called before each use of the view.

    A copy is retired by whichever process finalizes the view's publish: usually the publish worker, which can discard the
    copy's work but not end another connection's reading of it. While this process's reader still uses the copy the daemon
    keeps the edits; once the reader leaves, the copy stays read-only with the edits and no user (K7). So the process that
    reads the copy closes its rows and repeats the writer's discard, which then disposes of the program. Cheap when there is
    nothing to do: a look at this process's row cache and the state file. Best effort (a busy view is left to its next use)."""
    from hydralysis import query
    folders = [_norm(folder) for folder in view_folders(settings, target)]
    with query._keys_guard:
        cached = {_norm(key[1]) for key in query._keys if not key[3]}
    cached = {gpr for gpr in cached if any(gpr.startswith(folder + os.sep) for folder in folders)}
    if not cached:
        return {"closed": [], "projects": [], "failed": []}
    state = _state(settings, target)
    retired = {_norm(gpr) for gpr in state.get("retired") or [] if gpr}
    current = _norm(state["fork_gpr"]) if state.get("fork_gpr") and Path(state["fork_gpr"]).is_file() else None
    stale = sorted(gpr for gpr in cached if gpr != current or gpr in retired)
    if not stale:
        return {"closed": [], "projects": [], "failed": []}
    try:
        with locked(_directory(settings, target) / ".view.lock", DISCARD_LOCK_S, "working copy"):
            done = discard_forks(settings, target, stale)
            _forget_current(settings, target, _still_open(hydra.Engine(settings), done["closed"]))
            return done
    except LockBusy:
        return {"closed": [], "projects": [], "failed": []}   # a sync of the view owns its copies now; it sweeps them


def discard_forks(settings: dict, target: dict, gprs: list[str], writer: hydra.Engine | None = None) -> dict:
    """Close each working copy in GPRS in the daemon and discard the edits it holds unsaved (they are in the store).

    A reader's close only makes it leave: the work a sync left in a shared-mode program stays as an orphan. So the view's
    writer lane joins the copy as a shared writer (which adopts the orphaned work) and closes its project with discard:
    the program goes back to the saved fork for any other user, and is disposed when nobody uses it. A copy the daemon
    does not have open needs nothing. The caller holds the view lock. Returns {"closed": [gpr], "projects": [id],
    "failed": [{"gpr", "error", "message"}]}; nothing is raised for a copy that is already gone."""
    wanted = {_norm(gpr): gpr for gpr in gprs if gpr}
    result: dict = {"closed": [], "projects": [], "failed": []}
    if not wanted:
        return result
    _close_reader_rows(settings, set(wanted))
    own = writer is None
    writer = writer if writer is not None else writer_for(settings, target)
    try:
        try:
            status = writer.call("status")
            listed = status.get("projects", [])
        except (hydra.EngineError, OSError, RuntimeError) as error:
            result["failed"] = [{"gpr": gpr, "error": getattr(error, "code", type(error).__name__), "message": str(error)[:300]}
                                for gpr in wanted.values()]
            return result
        open_now = {_norm(item["gpr"]): item["id"] for item in listed if item.get("gpr") and item.get("id")}
        # An engine that lists its programs (every hydra release does) says which projects hold unsaved work; one that holds
        # none has nothing to discard, and joining it as a writer would only make the daemon reopen it for its readers.
        unsaved = None
        if isinstance(status.get("programs"), list):
            unsaved = {item.get("project") for item in status["programs"] if (item.get("unsavedEdits") or 0) > 0}
        for norm, gpr in wanted.items():
            if norm not in open_now or (unsaved is not None and open_now[norm] not in unsaved):
                continue
            try:
                opened = writer.call("open_project", path=gpr, writable=True, wait=DISCARD_WAIT_MS)
            except hydra.EngineError as error:
                if error.code not in _GONE:
                    result["failed"].append({"gpr": gpr, "error": error.code, "message": str(error)[:300]})
                continue
            joined = None
            try:
                writer.call("open_program", project=opened["id"], path=target["program"], writable=True, share=True,
                            upgrade=True, wait=DISCARD_WAIT_MS)
                joined = True
            except hydra.EngineError as error:
                joined = error.code in _GONE   # the program is not in it any more: leaving the project is all there is
                if not joined:
                    result["failed"].append({"gpr": gpr, "error": error.code, "message": str(error)[:300]})
            try:
                writer.call("close_project", project=opened["id"], discard=True, wait=DISCARD_WAIT_MS)
            except hydra.EngineError as error:
                if error.code not in _GONE:
                    if joined:
                        result["failed"].append({"gpr": gpr, "error": error.code, "message": str(error)[:300]})
                    continue
            if joined:
                result["closed"].append(gpr)
                result["projects"].append(opened["id"])
    finally:
        if own:
            from hydralysis.query import forget
            writer.reset()
            forget(writer)
    return result


def _store_path(settings: dict, target: dict) -> Path:
    return _overlay_path(root_path(settings), target["key"])


STORE_VERSION = 3
DEFAULT_BASE = {"lineage": "", "generation": 0}


def _store_record(path: Path) -> dict | None:
    """The sealed store record, or None when no store was ever written.

    A version-3 file is read with require_seal=True: one whose seal was stripped is `store_corrupt`, not a
    "pre-seal" record. A version-1 or -2 file may still be unsealed; its first write seals it.
    """
    limit = MAX_HISTORY_BYTES + 4096
    kind, value, _ = durable.inspect_file(path, limit)
    if kind == "sealed":
        return value
    if kind == "unsealed":
        if value.get("version") in (1, 2):
            return value
        # Not the previous version either: a stripped seal is tampering or truncation, and must not be answered
        # from an older sealed copy as if nothing happened.
        backup = durable.backup_path(path)
        raise durable.StoreCorrupt(path, backup, {path.name: "no seal (a version-3 store is always sealed)",
                                                  backup.name: "not tried"})
    # Missing, zero-length, torn or mis-sealed: the previous version (.bak), else store_corrupt (or None: never written).
    return durable.read_sealed(path, default=None, max_bytes=limit)


def _clean_record(item: dict, position: int, previous_seq: int) -> dict:
    """One stored record as a v3 record. A record without effects (v1, v2) keeps `effects: null` and `before_unknown`."""
    if not isinstance(item, dict):
        raise ValueError("overlay history holds a record that is not an object")
    clean = _edit({key: item[key] for key in ("id", "address", "options") if key in item})
    clean.update({key: item[key] for key in ("by", "at", "batch") if key in item})
    seq = item.get("seq", position + 1)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= previous_seq:
        raise ValueError("overlay record %s has a sequence number out of order" % clean["id"])
    clean["seq"] = seq
    effects = revisions.clean_effects(item.get("effects"))
    clean["effects"] = effects
    if effects is None or item.get("before_unknown"):
        clean["before_unknown"] = True
    for key in ("imported_from", "merged_from"):
        if key in item:
            clean[key] = item[key]
    return clean


def _clean_commits(raw) -> list[dict]:
    """The committed-id set (D32): one entry per cid, `ids` authoritative, `ids_sha256` over the sorted ids."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("overlay commits must be a list")
    seen, clean = set(), []
    for entry in raw:
        if (not isinstance(entry, dict) or not isinstance(entry.get("cid"), str) or not isinstance(entry.get("ids"), list)
                or any(not isinstance(item, str) for item in entry["ids"])):
            raise ValueError("an overlay commit entry needs a cid and a list of ids")
        if entry["cid"] in seen:
            raise ValueError("overlay commits repeat cid %s" % entry["cid"])
        seen.add(entry["cid"])
        digest = _digest_of(sorted(entry["ids"]))
        if "ids_sha256" in entry and entry["ids_sha256"] != digest:
            raise ValueError("overlay commit %s does not match its ids_sha256" % entry["cid"])
        clean.append({**entry, "ids_sha256": digest, "reverted": bool(entry.get("reverted", False))})
    return clean


def lineage_binding(target: dict) -> dict | None:
    """The base binding the head generation gives a view: {lineage, generation}, or None for a target with no lineage."""
    link = target.get("lineage")
    return {"lineage": link["id"], "generation": link["generation"]} if link else None


def stale_reason(store: dict, target: dict) -> str | None:
    """`master_generation_changed` when the view holds records on a generation that is no longer the head (4.7).

    Reads keep answering from the view's working copy, built from the view's own base generation (`base_master_gpr`); a
    mutation is refused with `stale_view` until the view is rebased."""
    binding = lineage_binding(target)
    if binding and (store["edits"] or store["commits"]) and (store.get("base") or {}).get("generation", 0) != binding["generation"]:
        return "master_generation_changed"
    return None


def refuse_stale(store: dict, target: dict, what: str, settings: dict | None = None) -> None:
    """A mutation of a view behind the head is refused with `stale_view`, naming the generations (and views) that moved
    the head and the `rebase` call that settles it (4.7, 4.10)."""
    if stale_reason(store, target):
        payload = {"error": "stale_view", "stale": "master_generation_changed", "what": what,
                   "view": target.get("view", "shared"), "base": store.get("base"), "head": lineage_binding(target),
                   "next": _rebase_next(store), "retried": False,
                   "suggest": "another view published a new generation, and this view holds records on the older one; nothing was "
                              "recorded and Hydralysis does not retry the %s. Rebase the view with ghidra_query action=type_edit "
                              "options.kind=rebase (the call in `next`; resolve any conflicts it lists with take_mine or keep), "
                              "then send the %s again with the view_revision the rebase answers" % (what, what)}
        if settings is not None:
            from hydralysis import views
            payload["editors"] = views.editors_since(settings, target["lineage"]["id"], (store.get("base") or {}).get("generation", 0))
        raise RuntimeError(json.dumps(payload))


def _rebase_next(store: dict) -> dict:
    return {"tool": "ghidra_query", "action": "type_edit", "options": {"kind": "rebase", "expect_revision": store["revision"]}}


def base_master_gpr(settings: dict, target: dict, store: dict) -> str:
    """The project of the generation STORE is based on: the content a working copy of the view is built from and a view
    without pending records is read from (gate 9.17 H).

    The head (`target["gpr"]`) only for a view on the head generation. A view behind it is built from its own generation's
    sealed project (the CURRENT.log line of that generation), so it never moves without a rebase. A generation whose
    project is gone (removed, or no longer the sealed folder its log line names) is refused with `base_unavailable`, naming
    the rebase: the head is never substituted."""
    binding = lineage_binding(target)
    base = store.get("base") or DEFAULT_BASE
    generation = base.get("generation") or 0
    if binding is None or generation == binding["generation"]:
        return target["gpr"]
    lineage_id = base.get("lineage") or binding["lineage"]
    problem = None
    try:
        rows = [row for row in lineage.history(settings, lineage_id) if row.get("gen") == generation and row.get("gpr")]
    except (OSError, ValueError) as error:
        rows, problem = [], "the lineage log could not be read: %s" % error
    gpr = rows[-1]["gpr"] if rows else None
    if generation == 0 and gpr is None and problem is None:
        try:
            gpr = lineage.load(settings, lineage_id).get("origin_gpr")
        except (OSError, ValueError):
            gpr = None
    if problem is None and not gpr:
        problem = "the lineage log names no project for generation %d" % generation
    elif problem is None and not Path(gpr).is_file():
        problem = "the project of generation %d is gone (%s)" % (generation, gpr)
    elif problem is None and generation > 0:
        # A published generation is a sealed folder: its manifest must still be the one its log line names.
        named = next((row.get("manifestSha256") for row in rows if row.get("manifestSha256")), None)
        folder = lineage.project_folder_of(gpr)
        if lineage.read_manifest(folder) is None:
            problem = "the folder of generation %d has no manifest" % generation
        elif named and lineage.manifest_file_sha256(folder) != named:
            problem = "the folder of generation %d is not the sealed one its log line names" % generation
    if problem is None:
        return gpr
    raise RuntimeError(json.dumps({
        "error": "base_unavailable", "view": target.get("view", "shared"), "base": base, "head": binding, "detail": problem,
        "next": _rebase_next(store),
        "suggest": "the generation this view is based on is no longer available, so its working copy cannot be rebuilt and "
                   "Hydralysis does not answer from the head instead. Rebase the view onto the head with ghidra_query "
                   "action=type_edit options.kind=rebase (the call in `next`); its records are kept in the store"}))


def read_gpr(settings: dict, target: dict) -> str:
    """The project a read of a view without pending records opens: its base generation (`base_master_gpr`). A view that has
    no store, or none behind the head, reads the head."""
    if not target.get("lineage") or not durable.exists(_store_path(settings, target)):
        return target["gpr"]
    store = load_store(settings, target)
    return base_master_gpr(settings, target, store) if stale_reason(store, target) else target["gpr"]


def heal(settings: dict, target: dict) -> None:
    """Settle a commit or revert that died between its CURRENT.log line and its store write, and a publish whose view
    was not finalized by the leader, before the view is used."""
    if target.get("lineage"):
        from hydralysis import commits, views
        views.settle(settings, target)
        commits.heal(settings, target)


def _empty_store(sha256: str) -> dict:
    return {"version": STORE_VERSION, "sha256": sha256, "revision": 0, "base": dict(DEFAULT_BASE), "edits": [],
            "reverted": [], "journal": [], "commits": [], "archived": [], "stale": None,
            "published_through": {}, "changesets": []}


def load_store(settings: dict, target: dict) -> dict:
    """The store in its version-3 shape. A v1 or v2 file upgrades in memory (its `version` still says what was read)
    and on disk at its first write, which keeps the old file once as `.v1.bak` or `.v2.bak`."""
    path = _store_path(settings, target)
    if path.is_file() and path.stat().st_size > MAX_HISTORY_BYTES:
        raise ValueError("overlay history exceeds 20 MiB; preserved for review")
    # Sealed record: the file, else its previous version (.bak). A store that exists but has no valid
    # version raises store_corrupt; only a store that was never written reads as "no edits".
    record = _store_record(path)
    if record is None:
        fresh = _empty_store(target["sha256"])
        binding = lineage_binding(target)
        if binding:
            fresh["base"] = binding  # a view created after a commit starts on the head generation
        return fresh
    if record.get("version") not in (1, 2, STORE_VERSION) or record.get("sha256") != target["sha256"]:
        raise ValueError("overlays at %s belong to another build or format; preserve them and use a new target" % path)
    edits = record.get("edits")
    if not isinstance(edits, list) or len(edits) > MAX_OVERLAYS:
        raise ValueError("overlay history must contain at most %d records" % MAX_OVERLAYS)
    clean, previous = [], 0
    for position, item in enumerate(edits):
        clean.append(_clean_record(item, position, previous))
        previous = clean[-1]["seq"]
    if len({edit["id"] for edit in clean}) != len(clean):
        raise ValueError("overlay history has duplicate edit identities")
    base = record.get("base") if isinstance(record.get("base"), dict) else dict(DEFAULT_BASE)
    binding = lineage_binding(target)
    if binding and not clean and not record.get("commits") and base.get("generation") != binding["generation"]:
        base = binding  # a view with no records follows the head (it has nothing to rebase)
    archived = record.get("archived")
    stale = record.get("stale")
    return {"version": record["version"], "sha256": target["sha256"], "revision": int(record.get("revision", len(clean))),
            "base": base, "edits": clean, "reverted": record.get("reverted", []),
            "journal": revisions.clean_journal(record.get("journal")), "commits": _clean_commits(record.get("commits")),
            "archived": archived if isinstance(archived, list) else [], "stale": stale if isinstance(stale, str) else None,
            "published_through": _clean_through(record.get("published_through")), "changesets": _clean_changesets(record.get("changesets"))}


MAX_CHANGESETS = 200


def _clean_through(raw) -> dict:
    """`published_through` (4.8): destination view -> the highest `seq` of this view's records already merged there."""
    if not isinstance(raw, dict):
        return {}
    return {str(name): int(seq) for name, seq in raw.items() if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0}


def _clean_changesets(raw) -> list[dict]:
    """The publish queue's bookkeeping in this view (4.10): one entry per changeset settled here, so a settle is idempotent."""
    kept = []
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, dict) and isinstance(item.get("csid"), str):
            kept.append(item)
    return kept[-MAX_CHANGESETS:]


def _stored_version(path: Path) -> int | None:
    """The `version` of the file at PATH without parsing it all (it is the first key of every writer)."""
    try:
        with path.open("rb") as handle:
            head = handle.read(8192)
    except OSError:
        return None
    found = re.search(rb'"version"\s*:\s*(\d+)', head)
    if found:
        return int(found.group(1))
    _, value, _ = durable.inspect_file(path, MAX_HISTORY_BYTES + 4096)
    return value.get("version") if value else None


def _keep_old_format(path: Path) -> None:
    """Migration: the first write over a v1 or v2 file keeps it, once, as `<file>.v<N>.bak`."""
    if not path.is_file():
        return
    old = _stored_version(path)
    if old in (1, 2):
        backup = path.with_name("%s.v%d.bak" % (path.name, old))
        if not backup.exists():
            durable.atomic_write(backup, path.read_bytes(), point="v%d_backup" % old)


def _v3(store: dict, target: dict) -> dict:
    """The record to write: the store in its v3 form, whatever shape the caller holds (a v2 dict upgrades)."""
    edits, previous = [], 0
    for position, item in enumerate(store.get("edits", [])):
        edit = _clean_record(item, position, previous)
        previous = edit["seq"]
        edits.append(edit)
    base = store.get("base") if isinstance(store.get("base"), dict) else dict(DEFAULT_BASE)
    return {"version": STORE_VERSION, "sha256": store.get("sha256", target["sha256"]), "revision": store["revision"],
            "base": base, "edits": edits, "reverted": store.get("reverted") or [], "journal": store.get("journal") or [],
            "commits": _clean_commits(store.get("commits")), "archived": store.get("archived") or [],
            "stale": store.get("stale"), "published_through": _clean_through(store.get("published_through")),
            "changesets": _clean_changesets(store.get("changesets"))}


def _save_store(settings: dict, target: dict, store: dict) -> None:
    # Version 3, sealed, previous version kept as .bak, atomic and fsynced (durable.write_sealed); a v1 or v2
    # file is kept once as .v1.bak or .v2.bak before it is replaced.
    path = _store_path(settings, target)
    record = _v3(store, target)
    _keep_old_format(path)
    durable.write_sealed(path, record, max_bytes=MAX_HISTORY_BYTES,
                         too_large="overlay history would exceed 20 MiB; existing history preserved")


def committed_ids(store: dict) -> set[str]:
    """Ids of the records in a live commit (D32). Reverted commits do not count: their records are pending again."""
    found: set[str] = set()
    for entry in store.get("commits") or []:
        if not entry.get("reverted"):
            found.update(entry["ids"])
    return found


def pending_of(store: dict) -> list[dict]:
    """The records the working copy replays: every record not in a live commit, in `seq` (store) order."""
    committed = committed_ids(store)
    return [edit for edit in store["edits"] if edit["id"] not in committed]


def _digest_of(ids) -> str:
    return hashlib.sha256("\n".join(ids).encode()).hexdigest()


def state_of(store: dict) -> dict:
    """The overlay marker of 4.2: the pending list plus the base and the committed set it was built on."""
    ids = [edit["id"] for edit in pending_of(store)]
    base = store.get("base") or DEFAULT_BASE
    return {"revision": store["revision"], "edits": len(ids), "ids_sha256": _digest_of(ids),
            "base": {"lineage": base.get("lineage", ""), "generation": base.get("generation", 0)},
            "committed_sha256": _digest_of(sorted(committed_ids(store)))}


def state_text(state: dict) -> str:
    # Byte-identical to Gson's rendering of the same object in RusticQuery.java.
    return json.dumps(state, separators=(",", ":"))


def has_overlays(settings: dict, target: dict) -> bool:
    # durable.exists: a store whose main file is gone but whose .bak is intact still has overlays.
    return durable.exists(_store_path(settings, target)) and bool(pending_of(load_store(settings, target)))


def expected_state(settings: dict, target: dict) -> str | None:
    if not durable.exists(_store_path(settings, target)):
        return None
    store = load_store(settings, target)
    return state_text(state_of(store)) if pending_of(store) else None


def _directory(settings: dict, target: dict) -> Path:
    return root_path(settings) / "working" / target["key"]


def _state(settings: dict, target: dict) -> dict:
    return read_json(_directory(settings, target) / "state.json")


def summary(settings: dict, target: dict) -> dict:
    store = load_store(settings, target)
    state = _state(settings, target)
    latest = max(store["journal"], key=lambda entry: entry["revision"], default=None)
    pending = pending_of(store)
    return {"revision": store["revision"], "view_revision": store["revision"], "edits": len(store["edits"]),
            "pending": len(pending), "committed": len(store["edits"]) - len(pending),
            "latest_editor": {"by": latest["by"], "at": latest["at"]} if latest else None, "reverted": len(store["reverted"]),
            "working_copy": state.get("fork_gpr"), "working_state": state.get("state"),
            "in_sync": bool(state) and state.get("state") == state_text(state_of(store)),
            "last_sync": state.get("last_sync"),
            "recent": [{"id": edit["id"], "address": edit["address"], "kind": edit["options"].get("kind"),
                        "by": edit.get("by"), "at": edit.get("at")} for edit in store["edits"][-10:]]}


def changes(settings: dict, target: dict, since: int = 0, state: str = "all", limit: int = 40) -> dict:
    """The view's records after revision SINCE (by `seq`), each with its effects and whether a live commit holds it."""
    store = load_store(settings, target)
    committed = committed_ids(store)
    rows = []
    for edit in store["edits"]:
        mine = "committed" if edit["id"] in committed else "pending"
        if edit["seq"] <= since or state not in ("all", mine):
            continue
        rows.append({"seq": edit["seq"], "id": edit["id"], "address": edit["address"], "kind": edit["options"].get("kind"),
                     "source": edit["options"].get("source"), "by": edit.get("by"), "at": edit.get("at"), "state": mine,
                     "effects": edit["effects"], **({"before_unknown": True} if edit.get("before_unknown") else {})})
    page = rows[:limit]
    return {"view_revision": store["revision"], "since": since, "state": state, "changes": page,
            "truncated": len(rows) > len(page), **({"next_since": page[-1]["seq"]} if len(rows) > len(page) else {}),
            "archived_commits": len(store.get("archived") or [])}


def _attribution() -> dict:
    who = hydra.identity()
    return {"client": who["client"], "harness": who["harness"]}


def corpus_path(settings: dict, digest: str) -> Path:
    return root_path(settings) / "corpora" / (digest + ".jsonl")


def store_corpus(settings: dict, source: str) -> tuple[str, int]:
    """Copy a corpus under its SHA-256 once; overlay replay never rereads the caller's file."""
    source_path = Path(source)
    digest = hashlib.sha256()
    with source_path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 22), b""):
            digest.update(block)
    value = digest.hexdigest()
    destination = corpus_path(settings, value)
    if not destination.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + "." + uuid.uuid4().hex + ".tmp")
        shutil.copyfile(source_path, temporary)
        temporary.replace(destination)
    return value, destination.stat().st_size


def archive_path(settings: dict, digest: str) -> Path:
    return root_path(settings) / "archives" / (digest + ".gdt")


def verify_archive(path: Path, digest: str, size: int) -> None:
    if path.stat().st_size != size:
        raise ValueError("stored type archive has the wrong size: %s" % path)
    actual = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 22), b""):
            actual.update(block)
    if actual.hexdigest() != digest:
        raise ValueError("stored type archive does not match its SHA-256: %s" % path)


def store_archive(settings: dict, source: str) -> tuple[str, int]:
    """Snapshot exactly the hashed bytes, bounded and independent of the original file."""
    source_path = Path(source)
    before = source_path.stat()
    directory = root_path(settings) / "archives"
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / (uuid.uuid4().hex + ".tmp")
    digest, size = hashlib.sha256(), 0
    try:
        with source_path.open("rb") as input_file, temporary.open("xb") as output_file:
            for block in iter(lambda: input_file.read(1 << 22), b""):
                size += len(block)
                if size > MAX_CORPUS_BYTES:
                    raise ValueError("archive exceeds 1 GiB")
                digest.update(block)
                output_file.write(block)
        after = source_path.stat()
        if size < 1 or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("archive changed while copying or is empty")
        value = digest.hexdigest()
        destination = archive_path(settings, value)
        with locked(destination.with_suffix(".lock"), what="type archive"):
            if destination.exists():
                verify_archive(destination, value, size)
            else:
                temporary.replace(destination)
        return value, size
    finally:
        temporary.unlink(missing_ok=True)


def _replayable(settings: dict, target: dict, record: dict) -> dict:
    """What RusticQuery needs to replay one record: bulk records get their files."""
    options = dict(record["options"])
    if options.get("kind") == "import_types":
        corpus = corpus_path(settings, options["corpus_sha256"])
        if not corpus.is_file():
            raise ValueError("corpus %s of overlay %s is missing from %s; preserved overlays cannot be replayed"
                             % (options["corpus_sha256"][:12], record["id"], corpus.parent))
        options["corpus_file"] = str(corpus)
        options["report_file"] = str(_directory(settings, target) / ("import-%s.json" % record["id"]))
    if options.get("kind") == "import_archive":
        archive = archive_path(settings, options["archive_sha256"])
        verify_archive(archive, options["archive_sha256"], options["archive_bytes"])
        options["archive_file"] = str(archive)
        options["report_file"] = str(_directory(settings, target) / ("import-%s.json" % record["id"]))
    return {"id": record["id"], "address": record["address"], "options": options}


class VerifyMismatch(ValueError):
    """`verify_before` found a value other than the one a record saw; the whole transaction was rolled back.

    `detail` names the effect: {id, subject, field, expected, found}."""

    def __init__(self, message: str, detail: dict):
        super().__init__(message)
        self.detail = detail


def _apply(settings: dict, writer: hydra.Engine, program: dict, records: list[dict], state: dict | None, timeout_s: int,
           target: dict | None = None, verify_before: bool = False) -> dict:
    """Apply RECORDS to the working copy in one owner transaction and set its marker to STATE (None clears it).

    With `verify_before` the engine first checks, record by record, that the first effect of each (subject, field)
    finds the value the record saw (its `before`); a mismatch rolls the whole call back and raises VerifyMismatch.
    """
    from hydralysis.query import run_script
    directory = root_path(settings) / "hydra" / "requests"
    directory.mkdir(parents=True, exist_ok=True)
    batch = directory / ("overlays-%s.json" % uuid.uuid4().hex)
    sent = []
    for record in records:
        item = _replayable(settings, target, record) if target else {key: record[key] for key in ("id", "address", "options")}
        if verify_before and record.get("effects"):
            item["effects"] = record["effects"]
        sent.append(item)
    batch.write_text(json.dumps({"edits": sent, "state": state, **({"verify_before": True} if verify_before else {})}),
                     encoding="utf-8")
    try:
        request = {"id": uuid.uuid4().hex, "action": "apply_overlays", "address": "", "limit": 1, "cursor": "",
                   "contains": "", "timeout_s": timeout_s, "options": {}, "edits_file": str(batch)}
        # A background save holds the program for about 35 s on a large project.
        response, raw = run_script(writer, program, request, timeout_s, wait_ms=300000)
    finally:
        batch.unlink(missing_ok=True)
    if raw.get("mode") != "owner":
        raise RuntimeError("overlay apply ran %s, not as the working copy's writer; nothing recorded" % raw.get("mode"))
    if not response.get("ok"):
        if response.get("verify_mismatch"):
            raise VerifyMismatch("overlay apply refused: %s" % response.get("error"), response["verify_mismatch"])
        raise ValueError("overlay apply refused: %s" % response.get("error"))
    return response


def probe(engine: hydra.Engine, program: dict, probes: list[tuple[str, str]], timeout_s: int = 60) -> dict:
    """The current value of each (subject, field) in PROGRAM, read-only (RusticQuery `annotation_probe`, contained).

    Values are in the text an effect uses (`absent` for none); a pair the engine cannot probe (a bulk report)
    maps to None. This is what a bundle import and a commit's drift check compare a record's `before` with.
    """
    from hydralysis.query import run_script
    found: dict[tuple[str, str], str | None] = {}
    for start in range(0, len(probes), 2000):
        chunk = probes[start:start + 2000]
        request = {"id": uuid.uuid4().hex, "action": "annotation_probe", "address": "", "limit": 1, "cursor": "",
                   "contains": "", "timeout_s": timeout_s,
                   "options": {"probes": [{"subject": subject, "field": field} for subject, field in chunk]}}
        response, _ = run_script(engine, program, request, timeout_s)
        if not response.get("ok"):
            raise ValueError("annotation probe refused: %s" % response.get("error"))
        for row in response.get("values", []):
            found[(row["subject"], row["field"])] = row.get("value")
    return found


PHASES = ("master_open", "fork", "copy", "base_upgrade", "open", "replay")


class _Phases:
    """Wall-clock milliseconds per phase of one sync (see `last_sync.phases_ms`)."""

    def __init__(self):
        self.ms = dict.fromkeys(PHASES, 0.0)

    def add(self, name: str, started: float) -> None:
        self.ms[name] += (time.monotonic() - started) * 1000

    def report(self, total_s: float) -> dict:
        out = {name: int(round(value)) for name, value in self.ms.items()}
        out["total"] = int(round(total_s * 1000))
        return out


def _fork(settings: dict, writer: hydra.Engine, target: dict, source: str, prefix: str,
          phases: _Phases | None = None, parent: Path | None = None) -> dict:
    directory = parent if parent is not None else _directory(settings, target)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / (prefix + uuid.uuid4().hex[:10])
    # On one ReFS volume this is a block clone; across volumes (a master on another drive) a full
    # copy, allowed up to fork_max_copy_mb and reported in the sync's fork details.
    started = time.monotonic()
    forked = writer.call("fork_project", project=source, path=str(destination), writable=True,
                         mode=str(settings.get("fork_mode", "auto")), maxCopyMb=int(settings.get("fork_max_copy_mb", 8192)))
    if phases is not None:
        phases.add("fork", started)
        phases.ms["copy"] += float(forked.get("copyMs") or 0)
    return forked


def engine_release(engine: hydra.Engine) -> dict | None:
    """The engine release a database was written or upgraded by, as far as the engine reports it.

    `hello` carries hydraVersion and ghidraVersion; neither `hello` nor `open_project` reports a
    database format number (protocol 2), so the release pair stands in for it: one release writes
    one format. If the engine reports neither, the key has no release part and a base is judged by
    the master revision alone, as before.
    """
    try:
        hello = engine.hello()
    except (hydra.EngineError, OSError, AttributeError):
        return None
    release = {key: hello.get(key) for key in ("hydraVersion", "ghidraVersion") if hello.get(key)}
    return release or None


# ---- the shared base (PROTOCOL-3.md 4.10, D44) -----------------------------------------------------------------

def base_key(target: dict, binding: dict | None, master: dict, release: dict | None) -> str:
    """One key per (master origin, lineage generation, master revision, engine release): the identity of a base.

    The analysis identity and the database format of the spec are not reported by a protocol-2 engine; the master
    revision and the release pair stand in for them (see `engine_release`)."""
    binding = binding or DEFAULT_BASE
    material = json.dumps({"origin": target.get("origin_key", target["key"]), "lineage": binding.get("lineage", ""),
                           "generation": binding.get("generation", 0), "master_revision": master.get("revision"),
                           "release": release}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode()).hexdigest()[:20]


def bases_root(settings: dict, target: dict | None = None) -> Path:
    """`bases/` (every master) or, with a target, `bases/<origin key>/` (the bases of that master's generations)."""
    root = root_path(settings) / "bases"
    return root / (target.get("origin_key") or target["key"]) if target else root


def _base_ready(folder: Path) -> dict | None:
    """The base built in FOLDER, or None while it has no completion marker (a folder without one is invisible)."""
    record = read_json(folder / "COMPLETE.json")
    if record.get("gpr") and Path(record["gpr"]).is_file() and integrity.newest_valid(record["gpr"]):
        return record  # published to every view, so it is only ever read here, never repaired (K1)
    return None


def _build_base(settings: dict, writer: hydra.Engine, target: dict, master: dict, release: dict | None, key: str,
                folder: Path, phases: _Phases | None, binding: dict | None = None) -> dict:
    """Fork the master into FOLDER, bring it to the engine's current format, clear a stale marker, write the marker."""
    from hydralysis.query import open_program
    # A crashed builder left a partial fork here; nothing reads it (no marker), and this builder holds the lock.
    for partial in folder.glob("base-*") if folder.is_dir() else ():
        shutil.rmtree(partial, ignore_errors=True)
    started = time.monotonic()
    forked = _fork(settings, writer, target, master["id"], "base-", phases, parent=folder)
    upgrading = time.monotonic()
    try:
        program = open_program(writer, forked["gpr"], target["program"], target["sha256"], writable=True, upgrade=True, refresh=True)
        upgraded = bool(writer.call("info", program=program["key"]).get("changed"))
        # A generation is a published fork: it carries no overlay_state (commit step 5 cleared it). One that does is
        # stale, a claim about records this base does not hold, so it is cleared before any view forks from it.
        cleared = False
        if _marker(writer, program):
            _apply(settings, writer, program, [], None, 120)
            cleared = upgraded = True
        if upgraded:
            writer.call("save", program=program["key"], comment="RusticRE base: current database format", wait=600000)
        writer.call("close_project", project=forked["project"])
        if phases is not None:
            phases.add("base_upgrade", upgrading)
    except BaseException:
        try:
            writer.call("close_project", project=forked["project"], discard=True)
        except Exception:
            pass
        shutil.rmtree(Path(forked["gpr"]).parent, ignore_errors=True)
        raise
    binding = binding or DEFAULT_BASE
    record = {"gpr": forked["gpr"], "key": key, "lineage": binding.get("lineage", ""), "generation": binding.get("generation", 0),
              "master_revision": master.get("revision"), "engine": release,
              "upgraded": upgraded, "marker_cleared": cleared, "seconds": round(time.monotonic() - started, 3),
              "fork": {name: forked.get(name) for name in ("method", "cloned", "bytes", "copyMs")}, "built_at": time.time()}
    write_json(folder / "COMPLETE.json", record)  # the completion marker: written last, so a base is whole or invisible
    return record


def _base(settings: dict, writer: hydra.Engine, target: dict, master: dict, store: dict,
          phases: _Phases | None = None) -> dict:
    """The master in the engine's current database format, once per base key for every view and every process.

    A project saved by an older Ghidra is upgraded only in a copy (never in place), and working copies are forked
    from this one, so a rebuild after a revert pays a block clone and a replay, not another upgrade.

    The first caller takes the OS lock `bases/<key>.lock` and builds; the others poll the completion marker for at
    most BASE_WAIT_S and then get a structured `busy` (a LockBusy). Nobody who only reads waits here: a reader of a
    view without records answers from the master.
    """
    release = engine_release(writer)
    key = base_key(target, store.get("base"), master, release)
    folder = bases_root(settings, target) / key
    ready = _base_ready(folder)
    if ready:
        return ready
    folder.parent.mkdir(parents=True, exist_ok=True)
    lease = LaneLock(str(bases_root(settings, target) / (key + ".lock")))
    started = time.monotonic()
    while True:
        if lease.acquire():
            try:
                ready = _base_ready(folder)  # another caller finished while this one waited for the lock
                return ready or _build_base(settings, writer, target, master, release, key, folder, phases, store.get("base"))
            finally:
                lease.release()
        time.sleep(0.05)
        ready = _base_ready(folder)
        if ready:
            return ready
        if time.monotonic() - started >= BASE_WAIT_S:
            raise LockBusy("shared base", bases_root(settings, target) / (key + ".lock"), time.monotonic() - started, 2000)


def _marker(engine: hydra.Engine, program: dict) -> dict | None:
    """The overlay state the program object holds now (saved or not)."""
    from hydralysis.query import run_script
    response, _ = run_script(engine, program, {"id": uuid.uuid4().hex, "action": "overlay_state", "address": "",
                                               "limit": 1, "cursor": "", "contains": "", "timeout_s": 10,
                                               "options": {}}, 10)
    text = response.get("overlay_state") or ""
    return json.loads(text) if text else None


def _prefix_matches(records: list[dict], marker: dict | None, wanted: dict | None = None) -> int | None:
    """How many leading PENDING records the program already holds, or None if it diverged.

    `wanted` is the marker the store asks for (state_of): the program must also have been built on the same base
    (lineage, generation) and the same committed set, so a program built before a commit never matches after it
    (its records would be applied twice). A marker without `base` is a v2 marker: it matches only generation 0
    with an empty committed set.
    """
    if not marker:
        return 0
    if wanted is not None:
        base = marker.get("base")
        if base is None:
            if wanted["base"] != DEFAULT_BASE or wanted["committed_sha256"] != _digest_of([]):
                return None
        elif base != wanted["base"]:
            return None
        if marker.get("committed_sha256", _digest_of([])) != wanted["committed_sha256"]:
            return None
    count = marker.get("edits", -1)
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= len(records):
        return None
    ids = [record["id"] for record in records[:count]]
    return count if _digest_of(ids) == marker.get("ids_sha256") else None


def _same_base(record: dict | None, wanted: dict) -> bool:
    """Was the base record of a state file (`_base`) built on the (lineage, generation) WANTED names?"""
    record = record or {}
    return (record.get("lineage") or "", record.get("generation") or 0) == (wanted.get("lineage") or "", wanted.get("generation") or 0)


def writer_for(settings: dict, target: dict, start: bool = True) -> hydra.Engine:
    """The writer connection of one view: private to it, so closing it never touches another view's programs.
    `start=False` joins a running daemon only (the end of a session must not launch one)."""
    if start:
        return hydra.Engine(settings, role="writer", lane=target["key"])
    return hydra.Engine(settings, role="writer", lane=target["key"], start=False)


def _sync(settings: dict, target: dict, store: dict, timeout_s: int, extra: list[dict] | None = None,
          sweep: bool = True) -> dict:
    """Bring the working copy to the store (plus `extra`, the record being added). Lock held by caller.

    Changes are committed in the engine's shared-write mode and stay in the daemon after this
    connection leaves. Nothing saves them (D61): a working copy is a cache, the store is the record, and if the
    daemon stops first the program's marker shows what it lost and the next sync replays it from the store.

    Every other working copy of the view (the one this sync replaced, earlier retired ones, copies on disk that no state
    file names) is closed in the daemon with discard (`discard_forks`), so it does not stay there as an orphan for ever.
    A rebase builds its copy with `sweep=False` (the view's current copy keeps serving reads until the switch) and the
    switch sweeps (`views._adopt_copy`). A copy this sync made and could not finish is discarded too.
    """
    from hydralysis.query import forget, open_program
    writer = writer_for(settings, target)
    records = pending_of(store) + (extra or [])
    wanted = state_of({**store, "revision": store["revision"] + len(extra or []),
                       "edits": store["edits"] + (extra or [])})
    current = _state(settings, target)
    started = time.monotonic()
    phases = _Phases()
    created = None
    try:
        opening = time.monotonic()
        # The generation the store is based on, not the head: a view behind the head is rebuilt on its own base and moves only
        # by a rebase, whose store is based on the head (gate 9.17 H).
        master = writer.call("open_project", path=base_master_gpr(settings, target, store))
        phases.add("master_open", opening)
        how = {"rebuilt": False}
        program = None
        applied = None
        reusable = Path(current.get("fork_gpr", "")).is_file() and current.get("master_revision") == master.get("revision")
        if reusable:
            try:
                # The fork is ours and disposable: a newest version with no valid header (a kill between the rename and
                # the header write) is moved aside before the engine is asked to open it (integrity.py, D42).
                checked = integrity.check_fork(current["fork_gpr"], disposable=True)
                if checked["moved"]:
                    how["integrity"] = checked
            except integrity.CorruptNewest as damaged:
                # Nothing usable is left in it: it is a cache, so it is rebuilt from the base and the store.
                how["integrity"] = {"ok": False, "dropped": current["fork_gpr"], "report": damaged.report["newest_invalid"]}
                reusable = False
        if reusable:
            opening = time.monotonic()
            program = open_program(writer, current["fork_gpr"], target["program"], target["sha256"],
                                   writable=True, upgrade=True, refresh=True)
            phases.add("open", opening)
            opening = time.monotonic()
            marker = _marker(writer, program)
            held = _prefix_matches(records, marker, wanted)
            if held is not None and not marker and not _same_base(current.get("base"), wanted["base"]):
                # A program without a marker holds the fork as it was made (a fresh fork, or one whose unsaved replay was
                # discarded): it is reused only on the base it was forked from.
                held = None
            phases.add("replay", opening)
            if held is None:
                program = None
            else:
                pending = records[held:]
                gpr = current["fork_gpr"]
        base = current.get("base") or {}
        if program is None:
            base = _base(settings, writer, target, master, store, phases)
            forked = _fork(settings, writer, target, base["gpr"], "w-", phases)
            gpr = created = forked["gpr"]
            how = {**how, "rebuilt": True, "fork": {key: forked.get(key) for key in ("method", "cloned", "bytes", "copyMs")}}
            opening = time.monotonic()
            program = open_program(writer, gpr, target["program"], target["sha256"], writable=True, upgrade=True, refresh=True)
            phases.add("open", opening)
            pending = records
        if pending or state_text(wanted) != current.get("state"):
            opening = time.monotonic()
            applied = _apply(settings, writer, program, pending, wanted, timeout_s, target)
            phases.add("replay", opening)
        retired = list(current.get("retired", []))
        # Only this view's own forks are retired; the shared base belongs to every view.
        if current.get("fork_gpr") and current["fork_gpr"] != gpr and current["fork_gpr"] not in retired:
            retired.append(current["fork_gpr"])
        if sweep:
            retired = superseded_forks(settings, target, keep=[gpr], also=retired)
        if retired:
            discarded = discard_forks(settings, target, retired, writer)
            if discarded["closed"] or discarded["failed"]:
                how["discarded"] = {"closed": len(discarded["closed"]), **({"failed": discarded["failed"][:5]}
                                                                           if discarded["failed"] else {})}
        report = (applied or {}).get("import_report") if pending else None
        state = {"fork_gpr": gpr, "master_revision": master.get("revision"), "state": state_text(wanted),
                 "base": base, "edits": len(records), "updated_at": time.time(),
                 "retired": _retire(writer, retired),
                 "last_sync": {**how, "applied_now": len(pending), "seconds": round(time.monotonic() - started, 3),
                               "phases_ms": phases.report(time.monotonic() - started),
                               **({"import_report": report} if report else {})}}
        write_json(_directory(settings, target) / "state.json", state)
        created = None
        if extra:
            # What each record changed and what was there before, as the engine saw it (store v3 `effects`).
            # Only the added records': a replay of up to MAX_OVERLAYS pending ones must not inflate the response.
            added = {item["id"] for item in extra}
            return {**state, "effects": {item["id"]: [{"before": None, "after": None, **effect} for effect in item["effects"]]
                                         if item.get("effects") is not None else None
                                         for item in (applied or {}).get("effects") or [] if item.get("id") in added}}
        return state
    except BaseException:
        if created is not None:
            # The copy this sync forked is named by no state file and holds a partial replay: nothing will read it.
            try:
                discard_forks(settings, target, [created], writer)
                _retire(writer, [created])
            except Exception:  # noqa: BLE001 - the error under way is the one the caller gets; a later sweep finds the copy
                pass
        raise
    finally:
        # Disconnecting keeps the committed changes in the daemon (shared mode); readers keep (or refresh) their
        # views. This connection is this view's own, so only this view's programs are released.
        writer.reset()
        forget(writer)


def _retire(engine: hydra.Engine, gprs: list[str]) -> list[str]:
    """Remove old working copies the engine no longer has open; keep the rest for a later sync."""
    try:
        open_now = {str(Path(item.get("gpr", "")).resolve()).lower() for item in engine.call("status").get("projects", [])}
    except (hydra.EngineError, OSError):
        return gprs
    kept = []
    for gpr in gprs:
        if str(Path(gpr).resolve()).lower() in open_now:
            kept.append(gpr)
            continue
        shutil.rmtree(Path(gpr).parent, ignore_errors=True)
        if Path(gpr).parent.exists():
            kept.append(gpr)
    return kept


def reader(settings: dict, engine: hydra.Engine, target: dict) -> dict:
    """The working copy, synchronized with the store, opened read-only for queries.

    A view behind the head is read like any other (gate 9.17 G): a copy that is gone or out of step is rebuilt from the view's
    own base generation (`_sync`, `base_master_gpr`), never from the head, and a read is never refused with `stale_view`
    (only a mutation is). A base generation that is no longer available is refused with `base_unavailable`, naming the rebase."""
    from hydralysis.query import open_program
    heal(settings, target)
    store = load_store(settings, target)
    wanted = state_text(state_of(store))
    state = _state(settings, target)
    if state.get("state") != wanted or not Path(state.get("fork_gpr", "")).is_file():
        if heavy(store):
            rebuilding(settings, target)
        with view_lock(settings, target):
            store = load_store(settings, target)
            state = _sync(settings, target, store, 300)
    return open_program(engine, state["fork_gpr"], target["program"], target["sha256"])


def repair(settings: dict, engine: hydra.Engine, target: dict, timeout_s: int = 300) -> dict:
    """Re-sync the working copy from the store, whatever its program holds now."""
    heal(settings, target)
    with view_lock(settings, target):
        return _sync(settings, target, load_store(settings, target), timeout_s)


def heavy(store: dict) -> bool:
    from hydralysis.analysis import BULK_KINDS
    return any(edit["options"].get("kind") in BULK_KINDS for edit in pending_of(store))


def rebuilding(settings: dict, target: dict) -> dict:
    """A replay of bulk overlays runs as a job; the reader is told which one."""
    from hydralysis import overlayjobs
    job = overlayjobs.start(settings, target["name"], "sync", view=target.get("view", ""))
    raise RuntimeError(json.dumps({"working_copy": "synchronizing", "job": job["id"], "state": job["state"],
                                   "suggest": "job status %s; queries answer once it is done" % job["id"]}))


def refresh(settings: dict, engine: hydra.Engine, target: dict) -> None:
    state = _state(settings, target)
    if state.get("fork_gpr"):
        opened = engine.call("open_project", path=state["fork_gpr"])
        try:
            engine.call("refresh", project=opened["id"], force=True)
        except hydra.EngineError:
            pass


def require_revision(settings: dict, target: dict, expect: int | None, what: str) -> int:
    """expect_revision is mandatory for every mutation on every view; the error carries the current one."""
    if expect is None:
        current = load_store(settings, target)["revision"]
        raise RuntimeError(json.dumps(revisions.missing_payload(current, target.get("view", "shared"), what)))
    return expect


def reconcile(store: dict, expect: int, subjects: list[str]) -> dict:
    """Current, rebased (the stale edit's subjects were untouched since), or a conflict error."""
    decision = revisions.reconcile(expect, store["revision"], store["journal"], subjects)
    if decision["outcome"] == "conflict":
        raise RuntimeError(json.dumps(revisions.conflict_payload(expect, decision, subjects)))
    return decision


def _rebase_report(expect: int, decision: dict) -> dict:
    rebased = decision["outcome"] == "rebased"
    return {"rebased": rebased, **({"rebased_from": expect, "subjects_changed_since": decision["subjects_changed_since"]}
                                   if rebased else {})}


def edit(settings: dict, engine: hydra.Engine, target: dict, address: str, options: dict, timeout_s: int) -> dict:
    """Validate, apply and record one cited edit (or batch) with an optimistic revision check."""
    expect = options.pop("expect_revision", None)
    heal(settings, target)
    require_revision(settings, target, expect, "type_edit")
    if options.get("kind") == "import_types":
        digest, size = store_corpus(settings, options.pop("corpus"))
        options.update(corpus_sha256=digest, corpus_bytes=size)
    if options.get("kind") == "import_archive":
        digest, size = store_archive(settings, options.pop("archive"))
        options.update(archive_sha256=digest, archive_bytes=size)
    record = {"id": uuid.uuid4().hex, "address": address, "options": options}
    clean = {**_edit(record), "by": _attribution(), "at": time.time()}
    with view_lock(settings, target):
        store = load_store(settings, target)
        refuse_stale(store, target, "type_edit", settings)
        subjects = revisions.subjects_of(address, clean["options"])
        decision = reconcile(store, expect, subjects)
        if len(store["edits"]) >= MAX_OVERLAYS:
            raise ValueError("overlay history limit reached; export/review it before adding more edits")
        state = _sync(settings, target, store, timeout_s, extra=[clean])
        # The subject record: what this edit changed and what was there before. An engine whose script does not
        # report effects leaves the record without them (`before_unknown`): it still replays, it cannot be drift-checked.
        effects = (state.get("effects") or {}).get(clean["id"])
        clean["effects"] = revisions.clean_effects(effects)
        if clean["effects"] is None:
            clean["before_unknown"] = True
        store["revision"] += 1
        clean["seq"] = max(store["revision"], max((item["seq"] for item in store["edits"]), default=0) + 1)
        store["edits"].append(clean)
        store["journal"] = revisions.append(store["journal"], revisions.journal_entry(
            store["revision"], "edit", subjects, clean["by"], clean["at"]))
        _save_store(settings, target, store)
    import_report = (state.get("last_sync") or {}).get("import_report")
    return {"ok": True, "overlay_id": clean["id"], "revision": store["revision"], "view_revision": store["revision"],
            **_rebase_report(expect, decision), "by": clean["by"],
            **({"import_report": _summary(import_report)} if import_report else {}),
            "edits_applied": len(options.get("edits", [])) if options.get("kind") == "batch" else 1,
            "working_copy": state["fork_gpr"], "sync": state.get("last_sync"), "seq": clean["seq"],
            **({"effects": clean["effects"]} if clean["effects"] is not None else {"before_unknown": True}),
            "persistence": "cited, build-bound overlay applied to the working copy; the canonical project is unchanged"}


def add_proposals(settings: dict, engine: hydra.Engine, target: dict, records: list[dict], expect: int | None,
                  timeout_s: int, imported_from: dict) -> dict:
    """Add RECORDS (id, address, options, optional effects) to a view as pending proposals, atomically.

    The engine applies them all in one owner transaction first (a record it refuses leaves the view unchanged),
    then the store takes them, one revision and one journal entry each, with the effects of THIS view's program
    (what the engine reports here, not what the author saw). Each carries `imported_from` (the bundle and the
    record it came from). Used by bundle import; the same locking, rebase and cap rules as `edit`.
    """
    heal(settings, target)
    require_revision(settings, target, expect, "import_bundle")
    clean = []
    for record in records:
        item = _edit({key: record[key] for key in ("id", "address", "options") if key in record})
        clean.append({**item, "by": _attribution(), "at": time.time(),
                      "imported_from": {**imported_from, "id": record.get("source_id", record["id"]),
                                        "by": record.get("source_by"), "at": record.get("source_at")}})
    subjects = sorted({subject for item in clean for subject in revisions.subjects_of(item["address"], item["options"])})
    with view_lock(settings, target):
        store = load_store(settings, target)
        refuse_stale(store, target, "import_bundle", settings)
        decision = reconcile(store, expect, subjects)
        if len(store["edits"]) + len(clean) > MAX_OVERLAYS:
            raise ValueError("overlay history limit reached; export/review it before adding more edits")
        state = _sync(settings, target, store, timeout_s, extra=clean)
        effects = state.get("effects") or {}
        for item in clean:
            item["effects"] = revisions.clean_effects(effects.get(item["id"]))
            if item["effects"] is None:
                item["before_unknown"] = True
            store["revision"] += 1
            item["seq"] = max(store["revision"], max((edit["seq"] for edit in store["edits"]), default=0) + 1)
            store["edits"].append(item)
            store["journal"] = revisions.append(store["journal"], revisions.journal_entry(
                store["revision"], "edit", revisions.subjects_of(item["address"], item["options"]), item["by"], item["at"]))
        _save_store(settings, target, store)
    return {"ok": True, "added": [item["id"] for item in clean], "revision": store["revision"],
            "view_revision": store["revision"], **_rebase_report(expect, decision), "working_copy": state["fork_gpr"],
            "sync": state.get("last_sync")}


def _summary(report: dict) -> dict:
    """The import report's counts; the full report stays in its file."""
    return {key: report.get(key) for key in ("records", "archive_types", "already_present", "archive_sha256", "by_kind", "fields", "embedded_parents", "flattened_parents", "inherited_fields", "functions_typed_this", "functions_thiscall_kept",
                                             "functions_renamed", "unresolved_type_names", "conflicts_total",
                                             "failures_total", "category")} | {"unresolved_top": report.get("unresolved", [])[:10]}


def _selected(store: dict, ids: list[str]) -> list[dict]:
    wanted = set(ids)
    return [edit for edit in store["edits"] if edit["id"] in wanted or edit.get("batch") in wanted]


def revert(settings: dict, target: dict, ids: list[str], expect: int | None = None, cascade: bool = False) -> dict:
    """Undo records in one step. The working copy is rebuilt from the master on next use.

    A record that a live commit holds is refused (`already_committed`): undo it with a new inverse edit or a
    commit revert. A record whose removal would leave a later pending record on the same (subject, field) with a
    stale `before` is refused (`has_dependents`, the later ids named); `cascade` removes those as well.
    """
    heal(settings, target)
    require_revision(settings, target, expect, "revert")
    with view_lock(settings, target):
        store = load_store(settings, target)
        refuse_stale(store, target, "revert", settings)
        dropped = _selected(store, ids)
        if not dropped:
            raise ValueError("no overlay record or batch matches %s" % ", ".join(ids))
        committed = committed_ids(store)
        held = [edit["id"] for edit in dropped if edit["id"] in committed]
        if held:
            raise RuntimeError(json.dumps({"error": "already_committed", "ids": held, "current_revision": store["revision"],
                                           "suggest": "a committed record is history: undo it with a new inverse edit, or revert the commit"}))
        later = revisions.dependents(store["edits"], {edit["id"] for edit in dropped}, committed)
        if later and not cascade:
            raise RuntimeError(json.dumps({"error": "has_dependents", "ids": later, "reverting": [edit["id"] for edit in dropped],
                                           "current_revision": store["revision"],
                                           "suggest": "later records of the same subject and field rest on these; revert them "
                                                      "first, or pass cascade:true to revert the whole chain"}))
        if later:
            dropped = dropped + [edit for edit in store["edits"] if edit["id"] in set(later)]
            # A batch always goes whole.
            dropped = dropped + [edit for edit in _selected(store, [edit["batch"] for edit in dropped if edit.get("batch")])
                                 if edit not in dropped]
        dropped_ids = {edit["id"] for edit in dropped}
        # A commit that has written its PREPARE line still needs its selected records in the store when it finalizes.
        from hydralysis import commits
        flying = commits.in_flight_ids(settings, target)
        busy = sorted(ident for ident in dropped_ids if ident in flying)
        if busy:
            raise RuntimeError(json.dumps({"error": "commit_in_flight", "ids": busy, "cid": flying[busy[0]],
                                           "current_revision": store["revision"], "retryAfterMs": 2000,
                                           "suggest": "a commit is working on these records; retry when it finishes, or "
                                                      "commit_abort it first"}))
        kept = [edit for edit in store["edits"] if edit["id"] not in dropped_ids]
        removed = [edit["id"] for edit in store["edits"] if edit["id"] in dropped_ids]
        subjects = sorted({subject for edit in dropped for subject in revisions.subjects_of(edit["address"], edit["options"])})
        decision = reconcile(store, expect, subjects)
        who, now = _attribution(), time.time()
        store["edits"] = kept
        store["revision"] += 1
        store["reverted"] = (store.get("reverted") or []) + [{"ids": removed, "by": who, "at": now}]
        store["journal"] = revisions.append(store["journal"], revisions.journal_entry(
            store["revision"], "revert", subjects, who, now))
        _save_store(settings, target, store)
    return {"ok": True, "reverted": len(removed), "revision": store["revision"], "view_revision": store["revision"],
            **({"cascaded": [ident for ident in removed if ident in set(later)]} if later else {}),
            **_rebase_report(expect, decision),
            "note": "the working copy is rebuilt from the unchanged master on the next query"}
