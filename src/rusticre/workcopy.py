"""Cited overlays, materialized in a working copy of the analysed project.

The overlay store (overlays/<target key>.json) is the record: every edit carries
its cited source, who made it (client and harness) and when, and the store has a
revision that only moves forward. The canonical project is never written.

To answer from the overlays, the engine forks the project into a working copy
(a block clone on ReFS, a bounded copy elsewhere), applies every record in one
owner transaction and saves it. The program then records the overlay state it
holds; a reader compares that with the store and refreshes before it would
answer from another version. A changed master, a reverted record or a missing
copy means a new fork and a full replay; otherwise new records are applied
incrementally. One writer at a time per target holds an OS lock; an editor that
read an older revision gets a conflict instead of overwriting.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import time
import uuid
from pathlib import Path

from rusticre import hydra
from rusticre.analysis import MAX_HISTORY_BYTES, MAX_OVERLAYS, _edit, _overlay_path
from rusticre.backends import read_json, write_json
from rusticre.locks import locked
from rusticre.paths import root_path

SYNC_LOCK_S = 900


def _store_path(settings: dict, target: dict) -> Path:
    return _overlay_path(root_path(settings), target["key"])


def load_store(settings: dict, target: dict) -> dict:
    path = _store_path(settings, target)
    if not path.is_file():
        return {"version": 2, "sha256": target["sha256"], "revision": 0, "edits": [], "reverted": []}
    if path.stat().st_size > MAX_HISTORY_BYTES:
        raise ValueError("overlay history exceeds 20 MiB; preserved for review")
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("version") not in (1, 2) or record.get("sha256") != target["sha256"]:
        raise ValueError("overlays at %s belong to another build or format; preserve them and use a new target" % path)
    edits = record.get("edits")
    if not isinstance(edits, list) or len(edits) > MAX_OVERLAYS:
        raise ValueError("overlay history must contain at most %d records" % MAX_OVERLAYS)
    clean = []
    for item in edits:
        meta = {key: item[key] for key in ("by", "at", "batch") if key in item}
        clean.append({**_edit({key: item[key] for key in ("id", "address", "options") if key in item}), **meta})
    if len({edit["id"] for edit in clean}) != len(clean):
        raise ValueError("overlay history has duplicate edit identities")
    return {"version": 2, "sha256": target["sha256"], "revision": int(record.get("revision", len(clean))),
            "edits": clean, "reverted": record.get("reverted", [])}


def _save_store(settings: dict, target: dict, store: dict) -> None:
    payload = json.dumps(store, indent=2).encode("utf-8")
    if len(payload) > MAX_HISTORY_BYTES:
        raise ValueError("overlay history would exceed 20 MiB; existing history preserved")
    path = _store_path(settings, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def state_of(store: dict) -> dict:
    ids = [edit["id"] for edit in store["edits"]]
    return {"revision": store["revision"], "edits": len(ids),
            "ids_sha256": hashlib.sha256("\n".join(ids).encode()).hexdigest()}


def state_text(state: dict) -> str:
    # Byte-identical to Gson's rendering of the same object in RusticQuery.java.
    return json.dumps(state, separators=(",", ":"))


def has_overlays(settings: dict, target: dict) -> bool:
    return _store_path(settings, target).is_file() and bool(load_store(settings, target)["edits"])


def expected_state(settings: dict, target: dict) -> str | None:
    if not _store_path(settings, target).is_file():
        return None
    store = load_store(settings, target)
    return state_text(state_of(store)) if store["edits"] else None


def _directory(settings: dict, target: dict) -> Path:
    return root_path(settings) / "working" / target["key"]


def _state(settings: dict, target: dict) -> dict:
    return read_json(_directory(settings, target) / "state.json")


def summary(settings: dict, target: dict) -> dict:
    store = load_store(settings, target)
    state = _state(settings, target)
    return {"revision": store["revision"], "edits": len(store["edits"]), "reverted": len(store["reverted"]),
            "working_copy": state.get("fork_gpr"), "working_state": state.get("state"),
            "in_sync": bool(state) and state.get("state") == state_text(state_of(store)),
            "saved": bool(state.get("saved_at")) and state.get("saved_at", 0) >= state.get("updated_at", 0),
            "last_sync": state.get("last_sync"),
            "recent": [{"id": edit["id"], "address": edit["address"], "kind": edit["options"].get("kind"),
                        "by": edit.get("by"), "at": edit.get("at")} for edit in store["edits"][-10:]]}


def _attribution() -> dict:
    who = hydra.identity()
    return {"client": who["client"], "harness": who["harness"]}


def _apply(settings: dict, writer: hydra.Engine, program: dict, records: list[dict], state: dict, timeout_s: int) -> dict:
    from rusticre.query import run_script
    directory = root_path(settings) / "hydra" / "requests"
    directory.mkdir(parents=True, exist_ok=True)
    batch = directory / ("overlays-%s.json" % uuid.uuid4().hex)
    batch.write_text(json.dumps({"edits": [{key: record[key] for key in ("id", "address", "options")} for record in records],
                                 "state": state}), encoding="utf-8")
    try:
        request = {"id": uuid.uuid4().hex, "action": "apply_overlays", "address": "", "limit": 1, "cursor": "",
                   "contains": "", "timeout_s": timeout_s, "options": {}, "edits_file": str(batch)}
        # A background save holds the program for about 35 s on a large project.
        response, raw = run_script(writer, program, request, timeout_s, wait_ms=120000)
    finally:
        batch.unlink(missing_ok=True)
    if raw.get("mode") != "owner":
        raise RuntimeError("overlay apply ran %s, not as the working copy's writer; nothing recorded" % raw.get("mode"))
    if not response.get("ok"):
        raise ValueError("overlay apply refused: %s" % response.get("error"))
    return response


def _fork(settings: dict, writer: hydra.Engine, target: dict, source: str, prefix: str) -> dict:
    directory = _directory(settings, target)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / (prefix + uuid.uuid4().hex[:10])
    return writer.call("fork_project", project=source, path=str(destination), writable=True,
                       mode=str(settings.get("fork_mode", "auto")))


def _base(settings: dict, writer: hydra.Engine, target: dict, master: dict, current: dict) -> dict:
    """The master in the engine's current database format, once per master revision.

    A project saved by an older Ghidra is upgraded only in a copy (never in place), and
    working copies are forked from this one, so a rebuild after a revert pays a block
    clone and a replay, not another upgrade of the whole program.
    """
    from rusticre.query import open_program
    base = current.get("base") or {}
    if base.get("master_revision") == master.get("revision") and Path(base.get("gpr", "")).is_file():
        return base
    started = time.monotonic()
    forked = _fork(settings, writer, target, master["id"], "base-")
    try:
        program = open_program(writer, forked["gpr"], target["program"], target["sha256"], writable=True, upgrade=True, refresh=True)
        upgraded = bool(writer.call("info", program=program["key"]).get("changed"))
        if upgraded:
            writer.call("save", program=program["key"], comment="RusticRE base: current database format", wait=600000)
        writer.call("close_project", project=forked["project"])
    except BaseException:
        try:
            writer.call("close_project", project=forked["project"], discard=True)
        except Exception:
            pass
        shutil.rmtree(Path(forked["gpr"]).parent, ignore_errors=True)
        raise
    return {"gpr": forked["gpr"], "master_revision": master.get("revision"), "upgraded": upgraded,
            "seconds": round(time.monotonic() - started, 3),
            "fork": {key: forked.get(key) for key in ("method", "cloned", "bytes", "copyMs")}}


def _marker(engine: hydra.Engine, program: dict) -> dict | None:
    """The overlay state the program object holds now (saved or not)."""
    from rusticre.query import run_script
    response, _ = run_script(engine, program, {"id": uuid.uuid4().hex, "action": "overlay_state", "address": "",
                                               "limit": 1, "cursor": "", "contains": "", "timeout_s": 10,
                                               "options": {}}, 10)
    text = response.get("overlay_state") or ""
    return json.loads(text) if text else None


def _prefix_matches(records: list[dict], marker: dict | None) -> int | None:
    """How many leading records the program already holds, or None if it diverged."""
    if not marker:
        return 0
    count = int(marker.get("edits", -1))
    if not 0 <= count <= len(records):
        return None
    ids = [record["id"] for record in records[:count]]
    return count if hashlib.sha256("\n".join(ids).encode()).hexdigest() == marker.get("ids_sha256") else None


def _sync(settings: dict, target: dict, store: dict, timeout_s: int, extra: list[dict] | None = None) -> dict:
    """Bring the working copy to the store (plus `extra`, the record being added). Lock held by caller.

    Changes are committed in the engine's shared-write mode and stay in the daemon after this
    connection leaves; a background saver persists them (saving 1.5 GB takes about 35 s, so it
    is never on the edit path). If the daemon stops first, the program's marker shows what it
    lost and the next sync replays it from the store.
    """
    from rusticre.query import forget, open_program
    writer = hydra.Engine(settings, role="writer")
    records = store["edits"] + (extra or [])
    wanted = state_of({"revision": store["revision"] + (1 if extra else 0), "edits": records})
    current = _state(settings, target)
    started = time.monotonic()
    try:
        master = writer.call("open_project", path=target["gpr"])
        how = {"rebuilt": False}
        program = None
        if Path(current.get("fork_gpr", "")).is_file() and current.get("master_revision") == master.get("revision"):
            program = open_program(writer, current["fork_gpr"], target["program"], target["sha256"],
                                   writable=True, upgrade=True, refresh=True)
            held = _prefix_matches(records, _marker(writer, program))
            if held is None:
                program = None
            else:
                pending = records[held:]
                gpr = current["fork_gpr"]
        base = current.get("base") or {}
        if program is None:
            base = _base(settings, writer, target, master, current)
            forked = _fork(settings, writer, target, base["gpr"], "w-")
            gpr = forked["gpr"]
            how = {"rebuilt": True, "fork": {key: forked.get(key) for key in ("method", "cloned", "bytes", "copyMs")}}
            program = open_program(writer, gpr, target["program"], target["sha256"], writable=True, upgrade=True, refresh=True)
            pending = records
        if pending or state_text(wanted) != current.get("state"):
            _apply(settings, writer, program, pending, wanted, timeout_s)
        retired = list(current.get("retired", []))
        for old in (current.get("fork_gpr"), (current.get("base") or {}).get("gpr")):
            if old and old not in (gpr, base.get("gpr")) and old not in retired:
                retired.append(old)
        state = {"fork_gpr": gpr, "master_revision": master.get("revision"), "state": state_text(wanted),
                 "base": base, "edits": len(records), "updated_at": time.time(),
                 "saved_at": current.get("saved_at") if not how["rebuilt"] else None,
                 "retired": _retire(writer, retired),
                 "last_sync": {**how, "applied_now": len(pending), "seconds": round(time.monotonic() - started, 3)}}
        write_json(_directory(settings, target) / "state.json", state)
        _start_saver(settings, target)
        return state
    finally:
        # Disconnecting keeps the committed changes in the daemon (shared mode);
        # readers keep (or refresh) their views.
        writer.reset()
        forget(writer)


def _start_saver(settings: dict, target: dict) -> None:
    from rusticre import proc
    from rusticre.locks import held
    import os
    import sys
    directory = _directory(settings, target)
    if held(str(directory / ".saver.lock")):
        return
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    env["RUSTICRE_HARNESS"] = hydra.identity()["harness"]
    keys = ("root", "hydra_dir", "hydra_client", "java_home", "hydra_idle_s", "hydra_keep_warm_s", "hydra_max_heap",
            "hydra_allow_unpinned", "hydra", "fork_mode", "forbidden_drives", "overlay_save_debounce_s")
    write_json(directory / "saver-settings.json", {**{key: settings[key] for key in keys if key in settings},
                                                   "targets": {target["name"]: targets_entry(settings, target)}})
    with (directory / "saver.log").open("ab") as log:
        proc.popen([sys.executable, "-m", "rusticre.workcopy_saver", str(directory), target["name"]],
                   env=env, stdout=log, stderr=log, **({} if os.name == "nt" else {"start_new_session": True}))


def targets_entry(settings: dict, target: dict) -> dict:
    from rusticre import targets
    return targets.configured(settings)[target["name"]]


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
    """The working copy, synchronized with the store, opened read-only for queries."""
    from rusticre.query import open_program
    store = load_store(settings, target)
    wanted = state_text(state_of(store))
    state = _state(settings, target)
    if state.get("state") != wanted or not Path(state.get("fork_gpr", "")).is_file():
        with locked(_directory(settings, target) / ".sync.lock", SYNC_LOCK_S, "working copy"):
            store = load_store(settings, target)
            state = _sync(settings, target, store, 300)
    return open_program(engine, state["fork_gpr"], target["program"], target["sha256"])


def repair(settings: dict, engine: hydra.Engine, target: dict) -> dict:
    """Re-sync the working copy from the store, whatever its program holds now."""
    with locked(_directory(settings, target) / ".sync.lock", SYNC_LOCK_S, "working copy"):
        return _sync(settings, target, load_store(settings, target), 300)


def refresh(settings: dict, engine: hydra.Engine, target: dict) -> None:
    state = _state(settings, target)
    if state.get("fork_gpr"):
        opened = engine.call("open_project", path=state["fork_gpr"])
        try:
            engine.call("refresh", project=opened["id"], force=True)
        except hydra.EngineError:
            pass


def edit(settings: dict, engine: hydra.Engine, target: dict, address: str, options: dict, timeout_s: int) -> dict:
    """Validate, apply and record one cited edit (or batch) with an optimistic revision check."""
    expect = options.pop("expect_revision", None)
    record = {"id": uuid.uuid4().hex, "address": address, "options": options}
    clean = {**_edit(record), "by": _attribution(), "at": time.time()}
    with locked(_directory(settings, target) / ".sync.lock", SYNC_LOCK_S, "working copy"):
        store = load_store(settings, target)
        if expect is not None and expect != store["revision"]:
            last = store["edits"][-1] if store["edits"] else {}
            raise RuntimeError(json.dumps({"conflict": "overlay revision changed", "expected_revision": expect,
                                           "current_revision": store["revision"], "last_edit_by": last.get("by"),
                                           "suggest": "re-read the target (ghidra_query status), then edit again"}))
        if len(store["edits"]) >= MAX_OVERLAYS:
            raise ValueError("overlay history limit reached; export/review it before adding more edits")
        state = _sync(settings, target, store, timeout_s, extra=[clean])
        store["edits"].append(clean)
        store["revision"] += 1
        _save_store(settings, target, store)
    return {"ok": True, "overlay_id": clean["id"], "revision": store["revision"], "by": clean["by"],
            "edits_applied": len(options.get("edits", [])) if options.get("kind") == "batch" else 1,
            "working_copy": state["fork_gpr"], "sync": state.get("last_sync"),
            "persistence": "cited, build-bound overlay applied to the working copy; the canonical project is unchanged"}


def revert(settings: dict, target: dict, ids: list[str], expect: int | None = None) -> dict:
    """Undo records in one step. The working copy is rebuilt from the master on next use."""
    with locked(_directory(settings, target) / ".sync.lock", SYNC_LOCK_S, "working copy"):
        store = load_store(settings, target)
        if expect is not None and expect != store["revision"]:
            raise RuntimeError(json.dumps({"conflict": "overlay revision changed", "expected_revision": expect,
                                           "current_revision": store["revision"]}))
        wanted = set(ids)
        kept = [edit for edit in store["edits"] if edit["id"] not in wanted and edit.get("batch") not in wanted]
        removed = [edit["id"] for edit in store["edits"] if edit not in kept]
        if not removed:
            raise ValueError("no overlay record or batch matches %s" % ", ".join(ids))
        store["edits"] = kept
        store["revision"] += 1
        store["reverted"] = (store.get("reverted") or []) + [{"ids": removed, "by": _attribution(), "at": time.time()}]
        _save_store(settings, target, store)
    return {"ok": True, "reverted": len(removed), "revision": store["revision"],
            "note": "the working copy is rebuilt from the unchanged master on the next query"}
