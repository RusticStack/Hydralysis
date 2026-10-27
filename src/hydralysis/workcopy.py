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
import re
import shutil
import time
import uuid
from pathlib import Path

from hydralysis import durable, hydra, revisions
from hydralysis.analysis import MAX_CORPUS_BYTES, MAX_HISTORY_BYTES, MAX_OVERLAYS, _edit, _overlay_path
from hydralysis.backends import read_json, write_json
from hydralysis.locks import locked
from hydralysis.paths import root_path

SYNC_LOCK_S = 900


def with_view(target: dict, view: str = "") -> dict:
    """Select a durable annotation namespace without changing the analysed target."""
    if not isinstance(view, str) or (view and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", view)):
        raise ValueError("view must be a name of 1..64 letters, digits, dots, dashes or underscores")
    if not view or view == "shared":
        return {**target, "view": "shared"}
    key = hashlib.sha256((target["key"] + "\nview:" + view).encode()).hexdigest()[:16]
    return {**target, "key": key, "view": view}


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


def _empty_store(sha256: str) -> dict:
    return {"version": STORE_VERSION, "sha256": sha256, "revision": 0, "base": dict(DEFAULT_BASE), "edits": [],
            "reverted": [], "journal": [], "commits": [], "archived": [], "stale": None}


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
        return _empty_store(target["sha256"])
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
    archived = record.get("archived")
    stale = record.get("stale")
    return {"version": record["version"], "sha256": target["sha256"], "revision": int(record.get("revision", len(clean))),
            "base": base, "edits": clean, "reverted": record.get("reverted", []),
            "journal": revisions.clean_journal(record.get("journal")), "commits": _clean_commits(record.get("commits")),
            "archived": archived if isinstance(archived, list) else [], "stale": stale if isinstance(stale, str) else None}


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
            "stale": store.get("stale")}


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
            "saved": bool(state.get("saved_at")) and state.get("saved_at", 0) >= state.get("updated_at", 0),
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
          phases: _Phases | None = None) -> dict:
    directory = _directory(settings, target)
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


def _base(settings: dict, writer: hydra.Engine, target: dict, master: dict, current: dict,
          phases: _Phases | None = None) -> dict:
    """The master in the engine's current database format, once per master revision.

    A project saved by an older Ghidra is upgraded only in a copy (never in place), and
    working copies are forked from this one, so a rebuild after a revert pays a block
    clone and a replay, not another upgrade of the whole program.

    The base is keyed by the master revision and the engine release (hydraVersion and
    ghidraVersion from hello): another release may write another database format, so a base
    built by a different release (or by one that did not record it) is rebuilt once.
    """
    from hydralysis.query import open_program
    release = engine_release(writer)
    base = current.get("base") or {}
    if (base.get("master_revision") == master.get("revision") and base.get("engine") == release
            and Path(base.get("gpr", "")).is_file()):
        return base
    started = time.monotonic()
    forked = _fork(settings, writer, target, master["id"], "base-", phases)
    upgrading = time.monotonic()
    try:
        program = open_program(writer, forked["gpr"], target["program"], target["sha256"], writable=True, upgrade=True, refresh=True)
        upgraded = bool(writer.call("info", program=program["key"]).get("changed"))
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
    return {"gpr": forked["gpr"], "master_revision": master.get("revision"), "engine": release, "upgraded": upgraded,
            "seconds": round(time.monotonic() - started, 3),
            "fork": {key: forked.get(key) for key in ("method", "cloned", "bytes", "copyMs")}}


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


def _sync(settings: dict, target: dict, store: dict, timeout_s: int, extra: list[dict] | None = None) -> dict:
    """Bring the working copy to the store (plus `extra`, the record being added). Lock held by caller.

    Changes are committed in the engine's shared-write mode and stay in the daemon after this
    connection leaves; a background saver persists them (saving 1.5 GB takes about 35 s, so it
    is never on the edit path). If the daemon stops first, the program's marker shows what it
    lost and the next sync replays it from the store.
    """
    from hydralysis.query import forget, open_program
    writer = hydra.Engine(settings, role="writer")
    records = pending_of(store) + (extra or [])
    wanted = state_of({**store, "revision": store["revision"] + len(extra or []),
                       "edits": store["edits"] + (extra or [])})
    current = _state(settings, target)
    started = time.monotonic()
    phases = _Phases()
    try:
        opening = time.monotonic()
        master = writer.call("open_project", path=target["gpr"])
        phases.add("master_open", opening)
        how = {"rebuilt": False}
        program = None
        applied = None
        if Path(current.get("fork_gpr", "")).is_file() and current.get("master_revision") == master.get("revision"):
            opening = time.monotonic()
            program = open_program(writer, current["fork_gpr"], target["program"], target["sha256"],
                                   writable=True, upgrade=True, refresh=True)
            phases.add("open", opening)
            opening = time.monotonic()
            held = _prefix_matches(records, _marker(writer, program), wanted)
            phases.add("replay", opening)
            if held is None:
                program = None
            else:
                pending = records[held:]
                gpr = current["fork_gpr"]
        base = current.get("base") or {}
        if program is None:
            base = _base(settings, writer, target, master, current, phases)
            forked = _fork(settings, writer, target, base["gpr"], "w-", phases)
            gpr = forked["gpr"]
            how = {"rebuilt": True, "fork": {key: forked.get(key) for key in ("method", "cloned", "bytes", "copyMs")}}
            opening = time.monotonic()
            program = open_program(writer, gpr, target["program"], target["sha256"], writable=True, upgrade=True, refresh=True)
            phases.add("open", opening)
            pending = records
        if pending or state_text(wanted) != current.get("state"):
            opening = time.monotonic()
            applied = _apply(settings, writer, program, pending, wanted, timeout_s, target)
            phases.add("replay", opening)
        retired = list(current.get("retired", []))
        for old in (current.get("fork_gpr"), (current.get("base") or {}).get("gpr")):
            if old and old not in (gpr, base.get("gpr")) and old not in retired:
                retired.append(old)
        report = (applied or {}).get("import_report") if pending else None
        state = {"fork_gpr": gpr, "master_revision": master.get("revision"), "state": state_text(wanted),
                 "base": base, "edits": len(records), "updated_at": time.time(),
                 "saved_at": current.get("saved_at") if not how["rebuilt"] else None,
                 "retired": _retire(writer, retired),
                 "last_sync": {**how, "applied_now": len(pending), "seconds": round(time.monotonic() - started, 3),
                               "phases_ms": phases.report(time.monotonic() - started),
                               **({"import_report": report} if report else {})}}
        write_json(_directory(settings, target) / "state.json", state)
        _start_saver(settings, target)
        if extra:
            # What each record changed and what was there before, as the engine saw it (store v3 `effects`).
            return {**state, "effects": {item["id"]: [{"before": None, "after": None, **effect} for effect in item["effects"]]
                                         if item.get("effects") is not None else None
                                         for item in (applied or {}).get("effects") or []}}
        return state
    finally:
        # Disconnecting keeps the committed changes in the daemon (shared mode);
        # readers keep (or refresh) their views.
        writer.reset()
        forget(writer)


def _start_saver(settings: dict, target: dict) -> None:
    from hydralysis import proc
    from hydralysis.locks import held
    import os
    import sys
    directory = _directory(settings, target)
    if held(str(directory / ".saver.lock")):
        return
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    env["HYDRALYSIS_HARNESS"] = hydra.identity()["harness"]
    keys = ("root", "hydra_dir", "hydra_client", "java_home", "hydra_idle_s", "hydra_keep_warm_s", "hydra_max_heap",
            "hydra_allow_unpinned", "hydra", "fork_mode", "fork_max_copy_mb", "forbidden_drives", "overlay_save_debounce_s")
    write_json(directory / "saver-settings.json", {**{key: settings[key] for key in keys if key in settings},
                                                   "targets": {target["name"]: targets_entry(settings, target)}})
    with (directory / "saver.log").open("ab") as log:
        proc.popen([sys.executable, "-m", "hydralysis.workcopy_saver", str(directory), target["name"]],
                   env=env, stdout=log, stderr=log, **({} if os.name == "nt" else {"start_new_session": True}))


def targets_entry(settings: dict, target: dict) -> dict:
    from hydralysis import targets
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
    from hydralysis.query import open_program
    store = load_store(settings, target)
    wanted = state_text(state_of(store))
    state = _state(settings, target)
    if state.get("state") != wanted or not Path(state.get("fork_gpr", "")).is_file():
        if heavy(store):
            rebuilding(settings, target)
        with locked(_directory(settings, target) / ".sync.lock", SYNC_LOCK_S, "working copy"):
            store = load_store(settings, target)
            state = _sync(settings, target, store, 300)
    return open_program(engine, state["fork_gpr"], target["program"], target["sha256"])


def repair(settings: dict, engine: hydra.Engine, target: dict, timeout_s: int = 300) -> dict:
    """Re-sync the working copy from the store, whatever its program holds now."""
    with locked(_directory(settings, target) / ".sync.lock", SYNC_LOCK_S, "working copy"):
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
    require_revision(settings, target, expect, "type_edit")
    if options.get("kind") == "import_types":
        digest, size = store_corpus(settings, options.pop("corpus"))
        options.update(corpus_sha256=digest, corpus_bytes=size)
    if options.get("kind") == "import_archive":
        digest, size = store_archive(settings, options.pop("archive"))
        options.update(archive_sha256=digest, archive_bytes=size)
    record = {"id": uuid.uuid4().hex, "address": address, "options": options}
    clean = {**_edit(record), "by": _attribution(), "at": time.time()}
    with locked(_directory(settings, target) / ".sync.lock", SYNC_LOCK_S, "working copy"):
        store = load_store(settings, target)
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
    require_revision(settings, target, expect, "import_bundle")
    clean = []
    for record in records:
        item = _edit({key: record[key] for key in ("id", "address", "options") if key in record})
        clean.append({**item, "by": _attribution(), "at": time.time(),
                      "imported_from": {**imported_from, "id": record.get("source_id", record["id"]),
                                        "by": record.get("source_by"), "at": record.get("source_at")}})
    subjects = sorted({subject for item in clean for subject in revisions.subjects_of(item["address"], item["options"])})
    with locked(_directory(settings, target) / ".sync.lock", SYNC_LOCK_S, "working copy"):
        store = load_store(settings, target)
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
    require_revision(settings, target, expect, "revert")
    with locked(_directory(settings, target) / ".sync.lock", SYNC_LOCK_S, "working copy"):
        store = load_store(settings, target)
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
