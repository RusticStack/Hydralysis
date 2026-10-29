"""Commit as a new generation, its revert, and the `job` filters (PROTOCOL-3.md 4.2, 4.6, 7.3).

A commit never writes the analysed project. It makes a candidate: a fork of the head generation into
`lineages/<id>/gen/000N`, opened writable by the job alone, with the selected records replayed in one transaction after a
drift check, saved, forced to disk, hashed into `MANIFEST.json`, verified on a disposable clone, sealed, and only then
published with one fsynced `CURRENT.log` line (the commit point). Every step writes a CRC-framed line to
`commits/<cid>.intent.log` first or last, so a crash at any point is resolved by `recover` to the old state or the new
one and never to something between. The oracle after every fault: O1 (the master and the previous generation are
byte-identical), O2 (every acknowledged record is in the store, nothing is committed twice or lost), O3 (the head names
an old or a new generation whose manifest verifies), O4 (no folder without a verifying manifest is offered), O5 (the same
`cid` yields one published line and one commit entry) and O6 (a recovery that is killed recovers again to the same state).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path

from hydralysis import backups, durable, hydra, integrity, lineage, revisions, workcopy
from hydralysis.locks import LaneLock

SAMPLE_PER_KIND = 25
SPOT_CHECK = 25
SNAPSHOT_BUDGET_S = 20
VOLATILE = {"id", "overlay_state", "seconds", "query_s", "engine", "mode", "target", "view", "timeout_s"}
STEPS = ("PREPARE", "BACKUP_DONE", "CANDIDATE_RESERVED", "FORKED", "APPLIED", "FILES_FORCED", "MANIFEST", "VERIFIED", "SEALED",
         "PUBLISHED", "FINALIZED", "ABORTED")
CONFIRMATION = ("After this commit only engines whose program database version is at least this engine's can open the new "
                "generation (the original project is never changed, and a revert returns to it). Repeat with "
                "confirm_one_way_upgrade:true to go on.")


class CommitError(ValueError):
    """A commit refusal or abort with a stable `code`; `payload()` is what the caller receives."""

    def __init__(self, code: str, message: str, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self), **self.detail}


class Crash(BaseException):
    """What a simulated kill raises in tests (durable._die is replaced); never caught by the commit's own handlers."""


def new_cid() -> str:
    return "c-" + uuid.uuid4().hex[:8]


def _point(name: str) -> None:
    """A fault point (`HYDRALYSIS_TEST_FAULT=commit.<name>:exit|raise`); a no-op unless the test mode asks for it."""
    durable.fault("commit." + name)


# ---- options ---------------------------------------------------------------------------------------------------

COMMIT_KEYS = {"kind", "cid", "expect_revision", "confirm_one_way_upgrade", "on_drift", "only", "include_dependencies",
               "dry_run", "backup", "confirm_large", "allow_unverified_before", "resume_verified", "source", "snapshot_budget_s"}


def validate(options: dict) -> dict:
    """The commit options, checked. Unknown keys are refused, so a typo never silently changes a one-way operation."""
    if not isinstance(options, dict):
        raise ValueError("options must be an object")
    kind = options.get("kind")
    if kind not in ("commit", "commit_revert", "commit_abort"):
        raise ValueError("kind must be commit, commit_revert or commit_abort")
    extra = set(options) - COMMIT_KEYS
    if extra:
        raise ValueError("options do not belong to %s: %s" % (kind, ", ".join(sorted(extra))))
    out = dict(options)
    if kind != "commit_abort":
        revision = out.get("expect_revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise ValueError("expect_revision (the store revision you read) is required")
    if "cid" in out and not (isinstance(out["cid"], str) and re.fullmatch(r"c-[0-9a-f]{4,16}", out["cid"])):
        raise ValueError("cid must look like c-1a2b3c4d")
    if kind == "commit_abort" and "cid" not in out:
        raise ValueError("commit_abort needs the cid")
    for name in ("confirm_one_way_upgrade", "include_dependencies", "dry_run", "confirm_large", "allow_unverified_before", "resume_verified"):
        if name in out and not isinstance(out[name], bool):
            raise ValueError("%s must be a boolean" % name)
    if out.get("on_drift", "refuse") not in ("refuse", "skip"):
        raise ValueError("on_drift must be refuse or skip")
    only = out.get("only")
    if only is not None:
        if not isinstance(only, dict) or set(only) - {"ids", "authors"}:
            raise ValueError("only is {ids, authors}")
        for name in ("ids", "authors"):
            value = only.get(name)
            if value is not None and (not isinstance(value, list) or any(not isinstance(item, str) for item in value)):
                raise ValueError("only.%s must be a list of text or null" % name)
    if out.get("backup", "auto") != "auto" and not isinstance(out["backup"], str):
        raise ValueError("backup must be auto or the id of a verified backup")
    budget = out.get("snapshot_budget_s", SNAPSHOT_BUDGET_S)
    if isinstance(budget, bool) or not isinstance(budget, (int, float)) or not 1 <= budget <= 600:
        raise ValueError("snapshot_budget_s must be 1..600")
    return out


# ---- selection (4.2) -------------------------------------------------------------------------------------------

def _depends(records: list[dict]) -> dict[str, set[str]]:
    """record id -> ids of the EARLIER pending records it depends on (a shared coarse subject; `*` shares with all)."""
    subjects = {record["id"]: set(revisions.subjects_of(record["address"], record["options"])) for record in records}
    found: dict[str, set[str]] = {}
    for index, record in enumerate(records):
        mine = subjects[record["id"]]
        found[record["id"]] = {earlier["id"] for earlier in records[:index]
                               if (mine & subjects[earlier["id"]]) or revisions.WILDCARD in mine or revisions.WILDCARD in subjects[earlier["id"]]}
    return found


def select(store: dict, only: dict | None, include_dependencies: bool) -> tuple[list[dict], list[str]]:
    """The records S of a commit in `seq` order, closed under dependency and batch (or `selection_not_closed`).

    Returns (S, added): `added` are the ids the closure added because include_dependencies was set."""
    pending = sorted(workcopy.pending_of(store), key=lambda record: record["seq"])
    if not only or (only.get("ids") is None and only.get("authors") is None):
        return pending, []
    wanted = set(only.get("ids") or [])
    authors = set(only.get("authors") or [])
    known = {record["id"] for record in pending} | {record.get("batch") for record in pending if record.get("batch")}
    unknown = sorted(item for item in wanted if item not in known)
    if unknown:
        raise CommitError("unknown_records", "these ids are not pending records or batches of this view: %s" % ", ".join(unknown), ids=unknown)
    chosen = {record["id"] for record in pending
              if record["id"] in wanted or (record.get("batch") and record["batch"] in wanted)
              or (authors and ((record.get("by") or {}).get("harness") in authors or (record.get("by") or {}).get("client") in authors))}
    depends = _depends(pending)
    batches: dict[str, set[str]] = {}
    for record in pending:
        if record.get("batch"):
            batches.setdefault(record["batch"], set()).add(record["id"])
    closed = set(chosen)
    changed = True
    while changed:
        changed = False
        for ident in list(closed):
            needed = set(depends[ident])
            record = next(item for item in pending if item["id"] == ident)
            if record.get("batch"):
                needed |= batches[record["batch"]]
            if needed - closed:
                closed |= needed
                changed = True
    missing = sorted(closed - chosen, key=lambda ident: next(item["seq"] for item in pending if item["id"] == ident))
    if missing and not include_dependencies:
        raise CommitError("selection_not_closed", "the selection depends on %d pending record(s) it does not name; name them or pass "
                          "include_dependencies:true" % len(missing), missing=missing)
    return [record for record in pending if record["id"] in closed], missing


def _later_dependents(records: list[dict], drifted: set[str]) -> set[str]:
    """Every later record of RECORDS that depends, directly or through others, on a drifted one."""
    depends = _depends(records)
    taken = set(drifted)
    changed = True
    while changed:
        changed = False
        for record in records:
            if record["id"] not in taken and depends[record["id"]] & taken:
                taken.add(record["id"])
                changed = True
    return taken


# ---- drift (step 5) --------------------------------------------------------------------------------------------

def drift_check(engine, program: dict, records: list[dict]) -> list[dict]:
    """The records whose first effect on a (subject, field) no longer finds its `before` in PROGRAM, or whose chain breaks.

    The first effect of each (subject, field) in `seq` order is compared with a read-only probe of the live value; every
    later effect on the same pair is chain-checked offline (its `before` must equal the previous effect's `after`).
    Bulk reports (`*`) are checked by input hash elsewhere and are not probed."""
    first: dict[tuple[str, str], tuple[dict, dict]] = {}
    drifted: dict[str, dict] = {}
    last_after: dict[tuple[str, str], str | None] = {}
    for record in records:
        for effect in record.get("effects") or []:
            pair = (effect["subject"], effect["field"])
            if effect["subject"] == revisions.WILDCARD:
                continue
            if pair not in first:
                first[pair] = (record, effect)
            elif effect["before"] != last_after.get(pair) and record["id"] not in drifted:
                drifted[record["id"]] = {"id": record["id"], "subject": pair[0], "field": pair[1], "reason": "chain",
                                         "expected": effect["before"], "found": last_after.get(pair)}
            last_after[pair] = effect["after"]
    if first:
        live = workcopy.probe(engine, program, list(first))
        for pair, (record, effect) in first.items():
            found = live.get(pair)
            expected = "absent" if effect["before"] is None else effect["before"]
            if found is not None and found != expected and record["id"] not in drifted:
                drifted[record["id"]] = {"id": record["id"], "subject": pair[0], "field": pair[1], "reason": "drift",
                                         "expected": effect["before"], "found": found}
    return [drifted[record["id"]] for record in records if record["id"] in drifted]


# ---- intent log ------------------------------------------------------------------------------------------------

class Intent:
    """One commit's intent log: forced, CRC-framed lines, each with the attempt number and the step."""

    def __init__(self, settings: dict, lineage_id: str, cid: str, attempt: int):
        self.log = lineage.intent_log(settings, lineage_id, cid)
        self.cid, self.attempt = cid, attempt

    def write(self, step: str, **data) -> None:
        line = {"cid": self.cid, "attempt": self.attempt, "step": step, "at": lineage.now_iso(), **data}
        torn = durable.fault("commit.intent_torn")
        if torn is not None:
            self.log.path.parent.mkdir(parents=True, exist_ok=True)
            with durable.file_lock(self.log.lock_path, self.log.lock_timeout_s, what="log " + self.log.path.name):
                self.log.repair(lock_held=True)
                durable.AppendLog._raw_append(self.log.path, durable.frame(line)[:torn], faults=False)
            durable._die()
        self.log.append(line)


def next_attempt(settings: dict, lineage_id: str, cid: str) -> int:
    rows = lineage.intent_log(settings, lineage_id, cid).scan().records
    return max((row.get("attempt", 0) for row in rows), default=0) + 1


def last_steps(settings: dict, lineage_id: str, cid: str) -> dict:
    """The newest attempt of a commit: its number, last step and the data of the steps it passed."""
    rows = lineage.intent_log(settings, lineage_id, cid).scan().records
    if not rows:
        return {"attempt": 0, "step": None, "data": {}}
    attempt = max(row.get("attempt", 0) for row in rows)
    mine = [row for row in rows if row.get("attempt") == attempt]
    data: dict = {}
    for row in mine:
        data.update({key: value for key, value in row.items() if key not in ("cid", "attempt", "step", "at")})
    return {"attempt": attempt, "step": mine[-1]["step"], "data": data, "rows": mine}


def intent_cids(settings: dict, lineage_id: str) -> list[str]:
    folder = lineage.lineage_dir(settings, lineage_id) / "commits"
    return sorted(path.name[: -len(".intent.log")] for path in folder.glob("c-*.intent.log")) if folder.is_dir() else []


# ---- helpers on the engine -------------------------------------------------------------------------------------

def _capabilities(engine) -> dict:
    try:
        return engine.capabilities()
    except Exception:  # an engine that cannot say is a hydra.2/3 engine
        return {}


def _program_of(engine, gpr: str, target: dict, writable: bool = False, **fields) -> dict:
    from hydralysis.query import open_program
    return open_program(engine, gpr, target["program"], target["sha256"], writable=writable, **fields)


def _decompile(engine, program: dict, address: str, sha256: str) -> str:
    from hydralysis.query import run_script
    request = {"id": uuid.uuid4().hex, "action": "decompile", "address": address, "limit": 40, "cursor": "", "contains": "",
               "timeout_s": 60, "options": {}, "expected_sha256": sha256}
    response, _ = run_script(engine, program, request, 60)
    if not response.get("ok"):
        raise CommitError("verify_failed", "the decompile of %s failed: %s" % (address, response.get("error")))
    return lineage.canonical({key: value for key, value in response.items() if key not in VOLATILE}).decode("utf-8")


def _touched(records: list[dict]) -> dict[str, set[str]]:
    """field kind -> function addresses that the records touched (subjects `address:0x...`)."""
    found: dict[str, set[str]] = {}
    for record in records:
        if record.get("effects"):
            for effect in record["effects"]:
                if effect["subject"].startswith("address:"):
                    found.setdefault(revisions.field_kind(effect["field"]), set()).add(effect["subject"].removeprefix("address:"))
        else:  # a record without a subject record: the subjects of the record itself say which function it touches
            for subject in revisions.subjects_of(record["address"], record["options"]):
                if subject.startswith("address:"):
                    found.setdefault(str(record["options"].get("kind")), set()).add(subject.removeprefix("address:"))
    return found


def _sample(records: list[dict]) -> list[str]:
    chosen: list[str] = []
    for kind, addresses in sorted(_touched(records).items()):
        chosen.extend(sorted(addresses)[:SAMPLE_PER_KIND])
    return sorted(set(chosen))


def _excluded(pending_outside: list[dict]) -> set[str]:
    """Addresses of functions that a pending record outside S also touches: the working copy differs there by design."""
    found: set[str] = set()
    for record in pending_outside:
        for subject in revisions.subjects_of(record["address"], record["options"]):
            if subject.startswith("address:"):
                found.add(subject.removeprefix("address:"))
            elif subject == revisions.WILDCARD or subject.startswith(("structure:", "type:")):
                found.add(revisions.WILDCARD)
    return found


def _force_files(folder: Path) -> dict:
    """Ghidra's save does not promise an fsync (whether it does is not verified): flush every file unconditionally."""
    forced = skipped = 0
    for path in sorted(item for item in Path(folder).rglob("*") if item.is_file()):
        try:
            # Opened for flushing only: no byte of the file is written (not a record write, so not a durable.* site).
            descriptor = os.open(os.fspath(path), os.O_RDWR | getattr(os, "O_BINARY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            forced += 1
        except OSError:
            skipped += 1  # a read-only file was fsynced by whoever wrote it; counted, never silent
    return {"forced": forced, "not_forced": skipped}


# ---- the commit ------------------------------------------------------------------------------------------------

def _plan_confirmation(options: dict, engine=None, source_gpr: str | None = None) -> None:
    if options.get("confirm_one_way_upgrade"):
        return
    # `open_project.format.upgradeRequired` is unknown on hydra.2/3 (no `format`), and unknown needs the confirmation (4.6).
    # An engine with the `format` capability says it: the confirmation is skipped only for an explicit `false`, and the
    # refusal carries what the engine reported.
    info = None
    if engine is not None and source_gpr and "format" in _capabilities(engine):
        try:
            info = (engine.call("open_project", path=source_gpr) or {}).get("format")
        except hydra.EngineError:
            info = None
    if isinstance(info, dict) and info.get("upgradeRequired") is False:
        return
    detail = {"format": info} if isinstance(info, dict) else {}
    raise CommitError("confirmation_required", CONFIRMATION, confirm="confirm_one_way_upgrade", **detail)


def _head_for(settings: dict, selected: dict) -> tuple[str | None, dict]:
    """(lineage id or None, the head the commit starts from). A target with no lineage starts at generation 0."""
    link = selected.get("lineage")
    if not link:
        return None, {"gen": 0, "gpr": selected["gpr"], "seq": 0, "cid": None, "torn_tail": None, "corrupt": None}
    top = lineage.head(settings, link["id"])
    if top["corrupt"]:
        raise CommitError("lineage_corrupt", "CURRENT.log has a damaged line in the middle (offset %s); reads use the last good "
                          "line and commits are refused until the owner repairs it" % top["corrupt"].get("offset"), corrupt=top["corrupt"])
    return link["id"], top


def preconditions(settings: dict, selected: dict, options: dict, engine) -> dict:
    """Checked first and in order; a failure creates nothing. Returns the facts the later steps use."""
    store = workcopy.load_store(settings, selected)
    lineage_id, top = _head_for(settings, selected)
    if lineage_id is not None:
        bad = lineage.tampered(settings, lineage_id)
        if bad:
            raise CommitError("tampered", "a published generation no longer matches its manifest; commits are refused until the "
                              "owner re-adopts", tampered=bad)
    if store["revision"] != options["expect_revision"]:
        raise CommitError("revision_changed", "the store is at revision %d, not %d" % (store["revision"], options["expect_revision"]),
                          current_revision=store["revision"])
    binding = store.get("base") or {}
    if lineage_id is not None and binding.get("generation", 0) != top["gen"]:
        raise CommitError("master_drifted", "this view is based on generation %s and the head is generation %d; rebase it first"
                          % (binding.get("generation", 0), top["gen"]), base=binding, head=top["gen"])
    chosen, added = select(store, options.get("only"), options.get("include_dependencies", False))
    if not chosen:
        raise CommitError("nothing_to_commit", "no pending record to commit")
    unknown = [record["id"] for record in chosen if record.get("before_unknown")]
    if unknown and not options.get("allow_unverified_before"):
        raise CommitError("before_unknown", "%d record(s) predate the subject record and cannot be drift-checked; pass "
                          "allow_unverified_before:true to commit them" % len(unknown), ids=unknown)
    return {"store": store, "lineage_id": lineage_id, "head": top, "chosen": chosen, "added": added}


def plan(settings: dict, selected: dict, options: dict, engine) -> dict:
    """`dry_run`: preconditions, closure and the drift pre-pass against a read-only probe; no side effects at all."""
    facts = preconditions(settings, selected, options, engine)
    chosen = facts["chosen"]
    program = _program_of(engine, facts["head"]["gpr"], selected)
    drifted = drift_check(engine, program, chosen)
    dropped = _later_dependents(chosen, {item["id"] for item in drifted}) if options.get("on_drift") == "skip" else set()
    committing = [record["id"] for record in chosen if record["id"] not in dropped]
    skipped = [{"id": ident, "reason": next((item["reason"] for item in drifted if item["id"] == ident), "depends_on_drifted")}
               for ident in sorted(dropped, key=lambda i: next(r["seq"] for r in chosen if r["id"] == i))]
    pending_outside = [record for record in workcopy.pending_of(facts["store"]) if record["id"] not in {r["id"] for r in chosen}]
    source = facts["head"]["gpr"]
    return {"dry_run": True, "ok": not drifted or options.get("on_drift") == "skip", "ids": committing, "skipped": skipped,
            "drift": drifted, "closure_added": facts["added"], "excluded_functions": sorted(_excluded(pending_outside) & set(_sample(chosen))),
            "generation_from": facts["head"]["gen"], "backup_cost": backups.preview(settings, facts["lineage_id"] or "L-00000000", source),
            "confirmation": CONFIRMATION, "revision": facts["store"]["revision"]}


def run_commit(settings: dict, selected: dict, options: dict, engine=None, timeout_s: int = 600, progress=None) -> dict:
    """Make generation N from the pending records of SELECTED's view. Returns the report; raises CommitError on a refusal
    or an abort (the intent log then ends in ABORTED and nothing was published)."""
    options = validate(options)
    engine = engine or hydra.Engine(settings)
    if options.get("dry_run"):
        return plan(settings, selected, options, engine)
    link = selected.get("lineage")
    if link:
        # What an earlier commit left between its CURRENT.log line and its store write is settled first, and a resubmission
        # of a published cid is answered (O5) before the caller's stale revision is held against it.
        workcopy.heal(settings, selected)
        if options.get("cid"):
            prior = already_committed(settings, selected, link["id"], options["cid"])
            if prior is not None:
                return prior
    facts = preconditions(settings, selected, options, engine)
    _plan_confirmation(options, engine, facts["head"]["gpr"])
    # A commit is a lineage: create it now, at the first commit, recording the current key (4.4).
    link = lineage.ensure(settings, {**selected, "origin_key": selected.get("origin_key") or selected["key"]})
    lineage_id = link["id"]
    cid = options.get("cid") or new_cid()
    lock = LaneLock(str(lineage.commit_lock_path(settings, lineage_id)))
    lineage.lineage_dir(settings, lineage_id).mkdir(parents=True, exist_ok=True)
    if not lock.acquire():
        raise CommitError("commit_busy", "another commit holds this lineage's commit lock; retry when it finishes", retryAfterMs=5000)
    try:
        # Every acquisition repairs a torn tail before any append (4.1), then settles what an earlier commit left half done.
        lineage.current_log(settings, lineage_id).repair(lock_held=False)
        recover(settings, selected, lineage_id)
        already = already_committed(settings, selected, lineage_id, cid)
        if already is not None:
            return already
        facts = preconditions(settings, selected, options, engine)
        return _commit(settings, selected, options, engine, lineage_id, cid, facts, timeout_s, progress)
    finally:
        lock.release()


def already_committed(settings: dict, selected: dict, lineage_id: str, cid: str) -> dict | None:
    """O5: a resubmission of a published cid is answered, not repeated."""
    published = [row for row in lineage.history(settings, lineage_id) if row.get("cid") == cid and row.get("reason") == "commit"]
    if not published:
        return None
    store = workcopy.load_store(settings, selected)
    entry = next((item for item in store["commits"] + store["archived"] if item.get("cid") == cid), None)
    return {"ok": True, "reused": True, "cid": cid, "generation": published[-1]["gen"], "committed": bool(entry),
            "ids": (entry or {}).get("ids"), "note": "this cid was already published; nothing was repeated"}


def _commit(settings: dict, selected: dict, options: dict, engine, lineage_id: str, cid: str, facts: dict, timeout_s: int,
            progress) -> dict:
    attempt = next_attempt(settings, lineage_id, cid)
    intent = Intent(settings, lineage_id, cid, attempt)
    started = time.monotonic()
    state = {"cid": cid, "attempt": attempt, "lineage": lineage_id}
    source_gpr = facts["head"]["gpr"]
    job = hydra.Engine(settings, role="commit", lane=cid)
    candidate_folder: Path | None = None
    clone_folder: Path | None = None

    def note(step: str) -> None:
        if progress:
            progress(step)
        flag = lineage.lineage_dir(settings, lineage_id) / "commits" / (cid + ".abort")
        if flag.exists() and step in STEPS[:10]:
            raise CommitError("aborted", "commit_abort was requested", cid=cid)

    try:
        # 1. PREPARE: the only moment edits are held up (the committing view's lock), bounded by snapshot_budget_s.
        note("PREPARE")
        with workcopy.view_lock(settings, selected):
            store = workcopy.load_store(settings, selected)
            if store["revision"] != options["expect_revision"]:
                raise CommitError("revision_changed", "the store moved to revision %d" % store["revision"], current_revision=store["revision"])
            chosen, added = select(store, options.get("only"), options.get("include_dependencies", False))
            up_to = store["revision"]
            ids_sha = workcopy._digest_of(sorted(record["id"] for record in chosen))
            sync = workcopy._sync(settings, selected, store, timeout_s)
            reference, marker = _capture_reference(settings, engine, selected, sync, chosen, store, float(options.get("snapshot_budget_s", SNAPSHOT_BUDGET_S)))
            excluded_all = _excluded([record for record in workcopy.pending_of(store) if record["id"] not in {r["id"] for r in chosen}])
            # Written while the view lock is held: from this line on, a revert of a selected record is refused (in_flight_ids),
            # so the records the manifest will name are still in the store when FINALIZED reads them.
            intent.write("PREPARE", upTo=up_to, ids=[record["id"] for record in chosen], ids_sha256=ids_sha, marker=marker,
                         reference_functions=sorted(reference), excluded=sorted(excluded_all), view=selected.get("view", "shared"),
                         expect_revision=options["expect_revision"], from_generation=facts["head"]["gen"])
        _point("after_prepare")

        reuse = _resumable(settings, lineage_id, cid, attempt, chosen) if options.get("resume_verified") else None
        if reuse is not None:
            # Opt-in: re-hash the verified candidate of the earlier attempt (done above), seal it if it is not sealed yet, publish it
            # without rebuilding. Nothing is applied, saved or forked again.
            note("SEALED")
            if not (reuse["folder"] / lineage.SEAL_MARKER).is_file():
                backups.seal(reuse["folder"], reuse["manifest_sha"])
            intent.write("CANDIDATE_RESERVED", gen=reuse["generation"], resumed=True)
            intent.write("SEALED", manifest_sha256=reuse["manifest_sha"], resumed=True)
            note("PUBLISHED")
            finalized = _publish(settings, selected, lineage_id, cid, reuse["generation"], reuse["gpr"], reuse["manifest_sha"],
                                 reuse["manifest"].get("engine") or {}, intent)
            facts = reuse["manifest"]["store"]
            return {"ok": True, "cid": cid, "attempt": attempt, "generation": reuse["generation"], "gpr": reuse["gpr"],
                    "ids": facts["ids"], "skipped": [{"id": ident, "reason": "left_pending"} for ident in facts.get("skipped", [])],
                    "closure_added": added, "resumed": True, "manifestSha256": reuse["manifest_sha"], "revision": finalized["revision"],
                    "seconds": round(time.monotonic() - started, 3)}

        # 2. BACKUP_DONE: a fresh, re-hashed backup of the current generation, per policy.
        note("BACKUP_DONE")
        master = engine.call("open_project", path=source_gpr)
        made = _backup(settings, engine, selected, lineage_id, source_gpr, master.get("revision") or "", facts["head"]["gen"], options)
        intent.write("BACKUP_DONE", backup=made["backup"]["id"], backup_manifest_sha256=made["backup"]["manifestSha256"],
                     backup_folder=made["backup"]["folder"])
        _point("after_backup")

        # 3. CANDIDATE_RESERVED: the number is reserved in the log before the folder exists.
        note("CANDIDATE_RESERVED")
        generation = lineage.next_generation(settings, lineage_id)
        intent.write("CANDIDATE_RESERVED", gen=generation)
        _point("after_reserve")

        # 4. Fork the current generation into the candidate folder and open it writable, owned by this job alone.
        note("FORKED")
        candidate_folder = lineage.generation_dir(settings, lineage_id, generation)
        candidate_folder.parent.mkdir(parents=True, exist_ok=True)
        forked = job.call("fork_project", project=source_gpr, path=str(candidate_folder), writable=True,
                          mode=str(settings.get("fork_mode", "auto")), maxCopyMb=int(settings.get("fork_max_copy_mb", 8192)),
                          **({"purpose": "generation"} if backups.ENGINE_BACKUP_CAPABILITY in _capabilities(engine) else {}))
        candidate_gpr = forked["gpr"]
        # hydra.2/3 has no purpose: the job rewrites the sidecar so that a later engine does not take the generation for a
        # disposable fork (D12) nor for a sealed one (D38). It happens before step 7 hashes the folder.
        backups._rewrite_sidecar(candidate_folder, disposable=False, purpose="generation", state="candidate")
        integrity.check_fork(candidate_gpr, disposable=True)
        gate = {"backup": str(Path(made["backup"]["folder"]) / "backup.json")} if "upgradeGate" in _capabilities(engine) else {}
        program = _program_of(job, candidate_gpr, selected, writable=True, upgrade=True, refresh=True, share=False, **gate)
        intent.write("FORKED", gen=generation, gpr=candidate_gpr)
        _point("after_fork")

        # 5. APPLIED: drift pre-pass (read-only), then one transaction with verify_before.
        note("APPLIED")
        drifted = drift_check(job, program, chosen)
        skipped: list[dict] = []
        committing = chosen
        if drifted:
            if options.get("on_drift", "refuse") == "refuse":
                raise CommitError("drift", "%d record(s) no longer find the value they saw; nothing was published. Rebase, or "
                                  "commit with on_drift:skip" % len(drifted), drift=drifted)
            dropped = _later_dependents(chosen, {item["id"] for item in drifted})
            reasons = {item["id"]: item["reason"] for item in drifted}
            skipped = [{"id": record["id"], "reason": reasons.get(record["id"], "depends_on_drifted"),
                        **({"subject": next(i for i in drifted if i["id"] == record["id"])["subject"],
                            "field": next(i for i in drifted if i["id"] == record["id"])["field"]} if record["id"] in reasons else {})}
                       for record in chosen if record["id"] in dropped]
            committing = [record for record in chosen if record["id"] not in dropped]
            if not committing:
                raise CommitError("nothing_to_commit", "every selected record drifted or depends on one that did", drift=drifted)
            # What a skipped record touches stays pending, so the working copy differs from the candidate there by design.
            excluded_all = excluded_all | _excluded([record for record in chosen if record["id"] not in {r["id"] for r in committing}])
        _point("mid_apply")
        try:
            workcopy._apply(settings, job, program, committing, None, timeout_s, target=selected, verify_before=True)
        except workcopy.VerifyMismatch as mismatch:
            raise CommitError("verify_before", "the candidate refused a record: %s" % mismatch, effect=mismatch.detail) from mismatch
        except (ValueError, RuntimeError) as refused:
            raise CommitError("apply_refused", "the engine refused the replay, so nothing was published: %s" % refused) from refused
        final_ids = [record["id"] for record in committing]
        job.call("save", program=program["key"], comment="Hydralysis commit %s" % cid, wait=600000)
        intent.write("APPLIED", ids_sha256=workcopy._digest_of(sorted(final_ids)), n=len(final_ids), skipped=skipped)
        _point("after_save")
        job.call("close_project", project=program["project"])
        job.reset()

        # 6. FILES_FORCED
        note("FILES_FORCED")
        forced = _force_files(candidate_folder)
        intent.write("FILES_FORCED", **forced)
        _point("after_force")

        # 7. MANIFEST, then VERIFIED on a disposable clone (the candidate itself is never opened again).
        note("MANIFEST")
        bundle_sha = lineage.sha256_hex(lineage.canonical([{key: record.get(key) for key in ("id", "address", "options", "effects")}
                                                           for record in committing]))
        hello = engine.hello()
        body = {"cid": cid, "base": {"generation": facts["head"]["gen"], "revision": master.get("revision")},
                "engine": {key: hello.get(key) for key in ("hydraVersion", "ghidraVersion") if hello.get(key)},
                "dbVersions": hello.get("dbVersions") or (hello.get("analysisIdentity") or {}).get("dbVersions"),
                "backups": [made["backup"]["manifestSha256"]],
                "store": {"view": selected.get("view", "shared"), "revision": up_to, "snapshot": up_to, "ids": final_ids,
                          "skipped": [item["id"] for item in skipped], "ids_sha256": workcopy._digest_of(sorted(final_ids)),
                          "bundle_sha256": bundle_sha},
                "hydralysis_commit": {"cid": cid, "lineage": lineage_id, "base_generation": facts["head"]["gen"], "snapshot": up_to,
                                      "ids_sha256": workcopy._digest_of(sorted(final_ids)), "bundle_sha256": bundle_sha}}
        manifest = lineage.write_manifest(candidate_folder, body)
        manifest_sha = lineage.manifest_file_sha256(candidate_folder)
        intent.write("MANIFEST", manifest_sha256=manifest_sha, filesetSha256=manifest["filesetSha256"])
        _point("after_manifest")
        clone_folder = Path(settings.get("tmp_dir") or workcopy.root_path(settings)) / "commit-verify" / (cid + "-" + uuid.uuid4().hex[:6])
        _verify_candidate(settings, engine, job, selected, candidate_gpr, clone_folder, source_gpr, committing, reference, excluded_all)
        intent.write("VERIFIED", manifest_sha256=manifest_sha)
        _point("after_verify")

        # 7b. SEALED: from here a writable open, save, analyze or owner script on the candidate is refused.
        note("SEALED")
        if "sealProject" in _capabilities(engine):
            engine.call("seal_project", project=candidate_gpr)
        backups.seal(candidate_folder, manifest_sha)
        intent.write("SEALED", manifest_sha256=manifest_sha)
        _point("after_seal")

        note("PUBLISHED")
        finalized = _publish(settings, selected, lineage_id, cid, generation, candidate_gpr, manifest_sha, body["engine"], intent)
        return {"ok": True, "cid": cid, "attempt": attempt, "generation": generation, "gpr": candidate_gpr, "ids": final_ids,
                "skipped": skipped, "closure_added": added, "backup": made["backup"]["id"], "manifestSha256": manifest_sha,
                "excluded_functions": sorted(set(reference) & excluded_all), "revision": finalized["revision"],
                "stale_views": "other views of this target are behind the new generation; each must rebase before it edits",
                "seconds": round(time.monotonic() - started, 3)}
    except durable.FaultInjected:
        raise  # a simulated kill: nothing is written, recovery decides
    except Crash:
        raise
    except CommitError as error:
        if _published(settings, lineage_id, cid):
            raise _finalize_pending(error, cid, lineage_id) from error
        if error.code == "aborted":
            # The request is consumed: a resubmission of the same cid must not be aborted again at PREPARE.
            (lineage.lineage_dir(settings, lineage_id) / "commits" / (cid + ".abort")).unlink(missing_ok=True)
        _abort(intent, error, candidate_folder)
        raise
    except hydra.EngineError as error:
        refusal = CommitError("engine_refused", "the engine refused %s: %s" % (error.command or "a call", error), engine_error=error.code)
        if _published(settings, lineage_id, cid):
            raise _finalize_pending(refusal, cid, lineage_id) from error
        _abort(intent, refusal, candidate_folder)
        raise refusal from error
    except Exception as error:
        if _published(settings, lineage_id, cid):
            raise _finalize_pending(error, cid, lineage_id) from error
        _abort(intent, CommitError("failed", "%s: %s" % (type(error).__name__, error)), candidate_folder)
        raise
    finally:
        try:
            job.reset()
        except Exception:
            pass
        if clone_folder is not None:
            shutil.rmtree(clone_folder, ignore_errors=True)


def _publish(settings: dict, selected: dict, lineage_id: str, cid: str, generation: int, candidate_gpr: str, manifest_sha: str,
             engine_summary: dict, intent: Intent) -> dict:
    """Steps 8 and 9: the CURRENT.log line (the commit point of the publish), then FINALIZED."""
    _point("before_publish")
    intent.write("PUBLISHED", gen=generation, manifest_sha256=manifest_sha)
    _append_published(settings, lineage_id, {"gen": generation, "cid": cid, "reason": "commit", "gpr": candidate_gpr,
                                             "manifestSha256": manifest_sha, "engine": engine_summary})
    _point("after_publish")
    return finalize(settings, selected, lineage_id, cid, generation, intent, point=True)


def _resumable(settings: dict, lineage_id: str, cid: str, attempt: int, chosen: list[dict]) -> dict | None:
    """`resume_verified`: an earlier attempt of this cid ended with a verified (or sealed), unpublished candidate that still
    verifies against its manifest and was built for exactly this selection. Returns its generation and manifest facts."""
    rows = lineage.intent_log(settings, lineage_id, cid).scan().records
    for earlier in sorted({row.get("attempt", 0) for row in rows if row.get("attempt", 0) < attempt}, reverse=True):
        mine = [row for row in rows if row.get("attempt") == earlier]
        steps = {row["step"] for row in mine}
        reserved = next((row["gen"] for row in mine if row["step"] == "CANDIDATE_RESERVED"), None)
        if not ({"VERIFIED"} & steps) or reserved is None:
            continue
        folder = lineage.generation_dir(settings, lineage_id, reserved)
        check = lineage.verify_manifest(folder)
        manifest = check["manifest"]
        if not check["ok"] or manifest.get("cid") != cid or any(row.get("reason") == "commit" and row.get("gen") == reserved
                                                                  for row in lineage.history(settings, lineage_id)):
            continue
        store = manifest.get("store") or {}
        if sorted(store.get("ids", []) + store.get("skipped", [])) != sorted(record["id"] for record in chosen):
            continue
        gpr = next((str(path) for path in sorted(folder.glob("*.gpr"))), None)
        if gpr:
            return {"generation": reserved, "folder": folder, "gpr": gpr, "manifest": manifest,
                    "manifest_sha": lineage.manifest_file_sha256(folder)}
    return None


def _published(settings: dict, lineage_id: str, cid: str) -> bool:
    """Whether CURRENT.log has this commit's line: from then on the commit is the truth and is never marked ABORTED."""
    try:
        return any(row.get("cid") == cid and row.get("reason") == "commit" for row in lineage.history(settings, lineage_id))
    except Exception:
        return True  # unreadable: unknown counts as published, so ABORTED is never written; recovery reads the log again under the lock


def _finalize_pending(error: Exception, cid: str, lineage_id: str) -> "CommitError":
    """The line is written and the store write failed: the intent log stays at PUBLISHED so recovery rolls forward."""
    if isinstance(error, CommitError) and error.code == "finalize_pending":
        return error
    return CommitError("finalize_pending", "the generation of %s is published; finalizing the store failed (%s: %s). The next use of "
                       "this view completes it" % (cid, getattr(error, "code", type(error).__name__), error), cid=cid, lineage=lineage_id)


def _abort(intent: Intent, error: CommitError, candidate_folder: Path | None) -> None:
    try:
        intent.write("ABORTED", code=error.code, message=str(error)[:500],
                     candidate=str(candidate_folder) if candidate_folder else None)
    except Exception:
        pass  # the intent log is repaired and read by recovery; a lost ABORTED costs only a recovery pass


def _append_published(settings: dict, lineage_id: str, line: dict) -> None:
    """The CURRENT.log line of the commit; under `publish_torn` only its first n bytes reach the disk, then the process ends."""
    torn = durable.fault("commit.publish_torn")
    if torn is None:
        lineage.append_current(settings, lineage_id, line)
        return
    log = lineage.current_log(settings, lineage_id)
    with durable.file_lock(log.lock_path, log.lock_timeout_s, what="log CURRENT.log"):
        log.repair(lock_held=True)
        previous = log.last(strict=True)
        full = durable.frame({"seq": previous["seq"] + 1, **line, "at": lineage.now_iso(),
                              "prevHash": lineage.sha256_hex(lineage.canonical(previous))})
        durable.AppendLog._raw_append(log.path, full[:torn], faults=False)
    durable._die()


def _backup(settings: dict, engine, selected: dict, lineage_id: str, source_gpr: str, revision: str, generation: int, options: dict) -> dict:
    wanted = options.get("backup", "auto")
    if wanted != "auto":
        found = backups.usable(settings, lineage_id, wanted)
        if found is None:
            raise CommitError("backup_unusable", "backup %s is missing or does not verify" % wanted)
        return {"backup": {"id": wanted, "folder": found["folder"], "manifestSha256": found["manifestSha256"]}}
    try:
        return backups.make(settings, engine, lineage_id, source_gpr, "pre-commit", revision, generation,
                            confirm_large=bool(options.get("confirm_large")))
    except backups.BackupError as error:
        raise CommitError(error.code, str(error), **error.detail) from error


def _capture_reference(settings: dict, engine, selected: dict, sync: dict, chosen: list[dict], store: dict, budget_s: float) -> tuple[dict, dict | None]:
    """The decompile text of the sampled functions, from the working copy at `upTo`, and its marker as the proof (step 1)."""
    deadline = time.monotonic() + budget_s
    reader = _program_of(engine, sync["fork_gpr"], selected, refresh=True)
    marker = workcopy._marker(engine, reader)
    wanted = workcopy.state_of(store)
    if marker != wanted:
        raise CommitError("working_copy_out_of_sync", "the working copy does not hold the store's state at the snapshot", marker=marker, wanted=wanted)
    reference: dict[str, str] = {}
    addresses = _sample(chosen)
    for index, address in enumerate(addresses):
        if time.monotonic() > deadline and index:
            break  # the sample shrinks once the budget is spent
        reference[address] = _decompile(engine, reader, address, selected["sha256"])
    return reference, marker


def _verify_candidate(settings: dict, engine, job, selected: dict, candidate_gpr: str, clone_folder: Path, source_gpr: str,
                      committing: list[dict], reference: dict, excluded: set[str]) -> None:
    """K2, K3 on the candidate's files and on a disposable clone of it (the candidate is never opened again)."""
    report = integrity.scan(candidate_gpr)
    if not report["ok"]:
        raise CommitError("verify_failed", "the candidate has a database version without a valid header", report=report)
    clone_folder.parent.mkdir(parents=True, exist_ok=True)
    clone = job.call("fork_project", project=candidate_gpr, path=str(clone_folder), writable=True,
                     mode=str(settings.get("fork_mode", "auto")), maxCopyMb=int(settings.get("fork_max_copy_mb", 8192)),
                     **({"purpose": "fork"} if backups.ENGINE_BACKUP_CAPABILITY in _capabilities(engine) else {}))
    try:
        master = _program_of(engine, source_gpr, selected)
        read_only = _program_of(engine, clone["gpr"], selected, refresh=True)
        if (read_only.get("functions"), read_only.get("analyzed")) != (master.get("functions"), master.get("analyzed")):
            raise CommitError("verify_failed", "the candidate's function count or analysed flag differs from its parent's",
                              candidate={"functions": read_only.get("functions"), "analyzed": read_only.get("analyzed")},
                              parent={"functions": master.get("functions"), "analyzed": master.get("analyzed")})
        # The effects the candidate reports: after == actual, with the same normaliser (annotation_probe).
        last: dict[tuple[str, str], str | None] = {}
        for record in committing:
            for effect in record.get("effects") or []:
                if effect["subject"] != revisions.WILDCARD:
                    last[(effect["subject"], effect["field"])] = effect["after"]
        if last:
            live = workcopy.probe(engine, read_only, list(last))
            wrong = [{"subject": pair[0], "field": pair[1], "expected": after, "found": live.get(pair)}
                     for pair, after in last.items() if live.get(pair) is not None and live.get(pair) != ("absent" if after is None else after)]
            if wrong:
                raise CommitError("verify_failed", "%d applied effect(s) are not what the candidate holds" % len(wrong), mismatches=wrong[:20])
        everything = revisions.WILDCARD in excluded
        for address, expected in sorted(reference.items()):
            if address in excluded or everything:
                continue
            actual = _decompile(engine, read_only, address, selected["sha256"])
            if actual != expected:
                raise CommitError("verify_failed", "the decompile of %s differs from the reference taken at the snapshot" % address,
                                  address=address)
        # Regression guard for the engine upgrade: functions the commit did not touch decompile as in the parent.
        touched = {address for addresses in _touched(committing).values() for address in addresses}
        from hydralysis.query import run_script
        listing, _ = run_script(engine, master, {"id": uuid.uuid4().hex, "action": "functions", "address": "", "limit": 200,
                                                 "cursor": "", "contains": "", "timeout_s": 60, "options": {}}, 60)
        spot = [row["address"] for row in listing.get("functions", []) if row.get("address") not in touched][:SPOT_CHECK]
        for address in spot:
            if _decompile(engine, master, address, selected["sha256"]) != _decompile(engine, read_only, address, selected["sha256"]):
                raise CommitError("verify_failed", "untouched function %s decompiles differently in the candidate" % address, address=address)
        # K3: a disposable clone of a candidate opens writable too (discarded; the clone is deleted below).
        writable = _program_of(job, clone["gpr"], selected, writable=True, upgrade=False, refresh=True)
        job.call("close_project", project=writable["project"], discard=True)
        job.reset()
    finally:
        try:
            engine.call("close_project", project=clone.get("project"), discard=True)
        except Exception:
            pass


# ---- step 9 ----------------------------------------------------------------------------------------------------

def finalize(settings: dict, selected: dict, lineage_id: str, cid: str, generation: int, intent: Intent | None = None,
             point: bool = False) -> dict:
    """FINALIZED: in one atomic store write, append the commit entry (ids and skipped read from the generation's manifest),
    set the base to the new generation and archive the previous live commit's records. Idempotent by `cid`."""
    folder = lineage.generation_dir(settings, lineage_id, generation)
    manifest = lineage.read_manifest(folder)
    if manifest is None or manifest.get("cid") != cid:
        raise CommitError("finalize_failed", "generation %d has no manifest for %s" % (generation, cid))
    with workcopy.view_lock(settings, selected):
        store = workcopy.load_store(settings, selected)
        settled = None
        if any(entry.get("cid") == cid for entry in store["commits"] + store["archived"]):
            settled = {"revision": store["revision"], "already": True}
    if settled is not None:
        # The store write happened (a crash or a failure between it and the intent line): close the intent log now, or the
        # commit stays "in flight" forever and revert refuses its records.
        if intent is not None:
            intent.write("FINALIZED", gen=generation, revision=settled["revision"])
        return settled
    with workcopy.view_lock(settings, selected):
        store = workcopy.load_store(settings, selected)
        if any(entry.get("cid") == cid for entry in store["commits"] + store["archived"]):
            return {"revision": store["revision"], "already": True}
        facts = manifest["store"]
        by_id = {record["id"]: record for record in store["edits"]}
        missing = [ident for ident in facts["ids"] if ident not in by_id]
        if missing:
            raise CommitError("finalize_failed", "records of the commit are not in the store: %s" % ", ".join(missing[:5]), ids=missing)
        live = [entry for entry in store["commits"] if not entry.get("reverted")]
        previous = live[-1] if live else None
        if previous is not None:
            _archive(settings, selected, store, previous)
            store["commits"] = [entry for entry in store["commits"] if entry["cid"] != previous["cid"]]
        skipped_records = [{"id": ident, "reason": "left_pending"} for ident in facts.get("skipped", [])]
        store["commits"] = store["commits"] + [{"cid": cid, "generation": generation, "snapshot": facts.get("snapshot"),
                                                "ids": list(facts["ids"]), "skipped": skipped_records, "ids_sha256": facts["ids_sha256"],
                                                "bundle_sha256": facts.get("bundle_sha256"), "at": time.time(), "reverted": False}]
        store["base"] = {"lineage": lineage_id, "generation": generation}
        store["stale"] = None
        if point:
            _point("finalize_mid")
        store["revision"] += 1
        store["journal"] = revisions.append(store["journal"], revisions.journal_entry(store["revision"], "commit", [revisions.WILDCARD],
                                                                                       workcopy._attribution(), time.time()))
        workcopy._save_store(settings, selected, store)
    if intent is not None:
        intent.write("FINALIZED", gen=generation, revision=store["revision"])
    return {"revision": store["revision"], "already": False}


def _archive(settings: dict, selected: dict, store: dict, entry: dict) -> None:
    """Move the previous live commit's records out of `edits[]` into a sealed archive file (4.2); never deleted."""
    from hydralysis import annotations
    ids = set(entry["ids"])
    records = [record for record in store["edits"] if record["id"] in ids]
    path = annotations._archive_path(settings, selected, entry["cid"])
    path.parent.mkdir(parents=True, exist_ok=True)
    from hydralysis.backends import write_json
    write_json(path, {"cid": entry["cid"], "ids_sha256": entry["ids_sha256"], "records": records})
    store["edits"] = [record for record in store["edits"] if record["id"] not in ids]
    store["archived"] = (store.get("archived") or []) + [{"cid": entry["cid"], "generation": entry["generation"], "count": len(records),
                                                         "ids_sha256": entry["ids_sha256"], "archive": str(path)}]


# ---- recovery (4.6) --------------------------------------------------------------------------------------------

def recover(settings: dict, selected: dict, lineage_id: str) -> list[dict]:
    """The recovery table, run when a lineage is opened and by a resubmission, under `.commit.lock`.

    Every row ends in the old state or the new one. It is idempotent, and killing it half way leaves a state that the
    next run completes the same way (O6)."""
    done = []
    published = {row["cid"]: row for row in lineage.history(settings, lineage_id) if row.get("reason") == "commit" and row.get("cid")}
    for cid in intent_cids(settings, lineage_id):
        steps = last_steps(settings, lineage_id, cid)
        step = steps["step"]
        if step in ("ABORTED", "FINALIZED") or step is None:
            continue
        intent = Intent(settings, lineage_id, cid, steps["attempt"])
        line = published.get(cid)
        if line is not None:
            folder = lineage.project_folder_of(line["gpr"])
            check = lineage.verify_manifest(folder)
            if check["ok"] and lineage.manifest_file_sha256(folder) == line.get("manifestSha256"):
                # CURRENT.log has the line, FINALIZED is missing: roll forward from the manifest, wherever it died.
                view = (check["manifest"].get("store") or {}).get("view", "shared")
                finalize(settings, workcopy.with_view(_base_target(selected), "" if view == "shared" else view), lineage_id, cid, line["gen"],
                         intent, point=True)
                done.append({"cid": cid, "action": "rolled_forward", "gen": line["gen"]})
            else:
                previous = (check["manifest"] or {}).get("base", {}).get("generation", 0)
                back = next((row for row in reversed(lineage.history(settings, lineage_id)) if row.get("gen") == previous), None)
                if back is not None:
                    lineage.append_current(settings, lineage_id, {"gen": previous, "cid": cid, "reason": "rollback", "gpr": back["gpr"],
                                                                  "manifestSha256": back.get("manifestSha256"), "detail": "candidate_failed_reverify"})
                intent.write("ABORTED", code="candidate_failed_reverify", message="; ".join(check["problems"])[:300])
                done.append({"cid": cid, "action": "rolled_back", "problems": check["problems"]})
            continue
        # Not published. Before the commit point there is nothing to undo: partial folders have no valid manifest (invisible),
        # a verified backup is kept (never deleted), a verified or sealed candidate stays unpublished.
        reason = {"PREPARE": "aborted_after_prepare", "BACKUP_DONE": "aborted_backup_kept", "VERIFIED": "unpublished_candidate",
                  "SEALED": "unpublished_candidate", "PUBLISHED": "aborted_before_commit_point"}.get(step, "aborted_partial_candidate")
        intent.write("ABORTED", code=reason, message="recovered: no CURRENT.log line for this commit")
        done.append({"cid": cid, "action": "aborted", "reason": reason, "last_step": step})
    return done


def in_flight_ids(settings: dict, selected: dict) -> dict[str, str]:
    """Record id -> commit id for every record a commit of this view's lineage is still working on.

    A commit is in flight from its PREPARE line until FINALIZED or ABORTED. A commit whose process is gone and that was not
    published has nothing to protect (recovery aborts it), so it is skipped; one that is published but not finalized still
    needs its records and counts, whether or not its process is alive. Called with the view lock held."""
    lineage_id = lineage.find(settings, selected.get("origin_key") or selected["key"])
    if lineage_id is None:
        return {}
    found: dict[str, str] = {}
    store = workcopy.load_store(settings, selected)
    settled = {entry.get("cid") for entry in store["commits"] + store["archived"]}
    for cid in intent_cids(settings, lineage_id):
        steps = last_steps(settings, lineage_id, cid)
        if steps["step"] in ("ABORTED", "FINALIZED", None):
            continue
        ids = steps["data"].get("ids") or []
        if not ids:
            continue
        if cid in settled:
            continue  # the store already holds the commit: nothing is in flight, whatever the intent log still says
        if not _published(settings, lineage_id, cid):
            probe = LaneLock(str(lineage.commit_lock_path(settings, lineage_id)))
            if probe.acquire():
                probe.release()
                continue  # nobody holds the commit lock and nothing was published: a dead commit
        found.update({ident: cid for ident in ids})
    return found


def _base_target(selected: dict) -> dict:
    """The target without its view: `with_view` derives the committing view's key from the origin key."""
    plain = {key: value for key, value in selected.items() if key not in ("view",)}
    plain["key"] = selected.get("origin_key") or selected["key"]
    return plain


# ---- revert (4.6) ----------------------------------------------------------------------------------------------

def revert(settings: dict, selected: dict, options: dict, engine=None) -> dict:
    """`commit_revert`: only the latest live commit. The previous generation's manifest must still verify; a `rollback`
    line is appended; the entry is marked reverted and its ids are pending again (rehydrated from the archive when the
    commit became the latest only after a later revert)."""
    options = validate(options)
    link = selected.get("lineage")
    if not link:
        raise CommitError("no_lineage", "this target has no commit to revert")
    lineage_id = link["id"]
    lock = LaneLock(str(lineage.commit_lock_path(settings, lineage_id)))
    if not lock.acquire():
        raise CommitError("commit_busy", "another commit or revert holds this lineage's commit lock", retryAfterMs=5000)
    try:
        lineage.current_log(settings, lineage_id).repair(lock_held=False)
        recover(settings, selected, lineage_id)
        top = lineage.head(settings, lineage_id)
        if top["corrupt"]:
            raise CommitError("lineage_corrupt", "CURRENT.log has a damaged line in the middle; reverts are refused until it is repaired")
        with workcopy.view_lock(settings, selected):
            store = workcopy.load_store(settings, selected)
            if store["revision"] != options["expect_revision"]:
                raise CommitError("revision_changed", "the store is at revision %d" % store["revision"], current_revision=store["revision"])
            live = [entry for entry in store["commits"] if not entry.get("reverted")]
            rehydrate = None
            if live:
                entry = live[-1]
            elif store.get("archived"):
                rehydrate = store["archived"][-1]
                entry = rehydrate
            else:
                raise CommitError("nothing_to_revert", "this view has no live commit")
            if top["gen"] != entry["generation"]:
                raise CommitError("not_latest", "only the latest live commit can be reverted; the head is generation %d, this commit "
                                  "is generation %d" % (top["gen"], entry["generation"]))
            folder = lineage.generation_dir(settings, lineage_id, entry["generation"])
            manifest = lineage.read_manifest(folder)
            if manifest is None or (manifest.get("store") or {}).get("view", "shared") != selected.get("view", "shared"):
                raise CommitError("wrong_view", "the commit %s was made in view %s; revert it there" % (
                    entry["cid"], ((manifest or {}).get("store") or {}).get("view", "?")))
            previous = (manifest.get("base") or {}).get("generation", 0)
            back = next((row for row in reversed(lineage.history(settings, lineage_id)) if row.get("gen") == previous and row.get("reason") != "rollback"), None) \
                or next((row for row in reversed(lineage.history(settings, lineage_id)) if row.get("gen") == previous), None)
            if back is None:
                raise CommitError("revert_failed", "generation %d is not in CURRENT.log" % previous)
            if previous:
                check = lineage.verify_manifest(lineage.project_folder_of(back["gpr"]))
                if not check["ok"]:
                    raise CommitError("revert_failed", "generation %d no longer verifies: %s" % (previous, "; ".join(check["problems"][:3])))
            elif not Path(back["gpr"]).is_file():
                raise CommitError("revert_failed", "the adopted project %s is gone" % back["gpr"])
            # Validate the whole store change first (a rehydration that would not fit changes nothing), then the commit
            # point of the revert, the rollback line, then the one atomic store write.
            if rehydrate is not None:
                _check_rehydrate(settings, selected, store, rehydrate)
            lineage.append_current(settings, lineage_id, {"gen": previous, "cid": entry["cid"], "reason": "rollback", "gpr": back["gpr"],
                                                          "manifestSha256": back.get("manifestSha256"), "engine": back.get("engine")})
            _point("revert_after_rollback")
            restored = _finish_revert(settings, selected, store, lineage_id, entry, rehydrate is not None, previous)
        return {"ok": True, "reverted": entry["cid"], "generation": previous, "pending_again": restored["pending_again"],
                "rehydrated": restored["rehydrated"], "revision": store["revision"]}
    finally:
        lock.release()


def _finish_revert(settings: dict, selected: dict, store: dict, lineage_id: str, entry: dict, archived: bool, previous: int) -> dict:
    """The store half of a revert, idempotent: the commit entry is reverted, its ids are pending, the base is the previous
    generation. Caller holds the view lock and has appended (or found) the rollback line."""
    rehydrated = 0
    if archived:
        if any(item["cid"] == entry["cid"] for item in store["archived"]):
            restored = _rehydrate(settings, selected, store, next(item for item in store["archived"] if item["cid"] == entry["cid"]))
            rehydrated, pending_again = len(restored), len(restored)
        else:
            pending_again = len(next(item for item in store["commits"] if item["cid"] == entry["cid"])["ids"])
    else:
        live = next(item for item in store["commits"] if item["cid"] == entry["cid"])
        live["reverted"] = True
        pending_again = len(live["ids"])
    store["base"] = {"lineage": lineage_id, "generation": previous}
    store["revision"] += 1
    store["journal"] = revisions.append(store["journal"], revisions.journal_entry(store["revision"], "commit_revert", [revisions.WILDCARD],
                                                                                   workcopy._attribution(), time.time()))
    workcopy._save_store(settings, selected, store)
    return {"pending_again": pending_again, "rehydrated": rehydrated}


def _check_rehydrate(settings: dict, selected: dict, store: dict, entry: dict) -> None:
    """Refuse with `archive_unreadable` or `store_full` before anything changes (the real move happens in `_rehydrate`)."""
    scratch = {**store, "edits": list(store["edits"]), "archived": list(store["archived"]), "commits": list(store["commits"])}
    _rehydrate(settings, selected, scratch, entry)


def heal(settings: dict, selected: dict) -> bool:
    """Complete what a dead commit or revert left between its CURRENT.log line and its store write (the line is the truth).

    Called before a view is read or edited. A live commit that is mid-finalize holds `.commit.lock`: the caller then gets a
    structured `busy` and retries; it never reads a store that disagrees with the head. Returns whether anything was done."""
    link = selected.get("lineage")
    if not link or link.get("reason") not in ("commit", "rollback") or not link.get("cid"):
        return False
    store = workcopy.load_store(settings, selected)
    cid = link["cid"]
    known = {entry["cid"]: entry for entry in store["commits"] + store["archived"]}
    if link["reason"] == "commit":
        if cid in known:
            return _close_intent(settings, selected, link["id"], cid)
    else:
        entry = known.get(cid)
        if entry is None or (cid in {item["cid"] for item in store["commits"]} and entry.get("reverted")) or                 store.get("base", {}).get("generation") == link["generation"]:
            return False
    manifest = lineage.read_manifest(lineage.generation_dir(settings, link["id"], link["generation"] if link["reason"] == "commit" else known[cid]["generation"]))
    if manifest is None or (manifest.get("store") or {}).get("view", "shared") != selected.get("view", "shared"):
        return False  # another view's commit: that view settles it; this one is stale until it rebases
    lock = LaneLock(str(lineage.commit_lock_path(settings, link["id"])))
    if not lock.acquire():
        raise RuntimeError(json.dumps({"error": "busy", "what": "commit finalizing", "retryAfterMs": 1000,
                                       "suggest": "a commit or revert is finishing; retry"}))
    try:
        if link["reason"] == "commit":
            recover(settings, selected, link["id"])
        else:
            with workcopy.view_lock(settings, selected):
                store = workcopy.load_store(settings, selected)
                entry = next((item for item in store["commits"] if item["cid"] == cid and not item.get("reverted")), None)
                archived = entry is None
                _finish_revert(settings, selected, store, link["id"], entry or {"cid": cid}, archived, link["generation"])
        return True
    finally:
        lock.release()


def _close_intent(settings: dict, selected: dict, lineage_id: str, cid: str) -> bool:
    """The store holds the commit but its intent log never got FINALIZED (a crash between the two): close it under the commit
    lock. A busy lock means a live commit or revert is working; it closes the log itself, so this returns without waiting."""
    if last_steps(settings, lineage_id, cid)["step"] in ("FINALIZED", "ABORTED", None):
        return False
    lock = LaneLock(str(lineage.commit_lock_path(settings, lineage_id)))
    if not lock.acquire():
        return False
    try:
        return bool(recover(settings, selected, lineage_id))
    finally:
        lock.release()


def _rehydrate(settings: dict, selected: dict, store: dict, entry: dict) -> list[dict]:
    """Move an archived commit's records back into `edits[]` as pending, in `seq` order, in the caller's atomic store write."""
    from hydralysis import annotations
    path = annotations._archive_path(settings, selected, entry["cid"])
    try:
        record = durable.read_sealed(path, default=None, max_bytes=workcopy.MAX_HISTORY_BYTES + 4096)
    except durable.StoreCorrupt as error:
        raise CommitError("archive_unreadable", str(error)) from error
    if record is None or not isinstance(record.get("records"), list):
        raise CommitError("archive_unreadable", "%s is missing or holds no records" % path)
    items, previous = [], 0
    for position, item in enumerate(record["records"]):
        items.append(workcopy._clean_record(item, position, previous))
        previous = items[-1]["seq"]
    if workcopy._digest_of(sorted(item["id"] for item in items)) != entry.get("ids_sha256"):
        raise CommitError("archive_unreadable", "%s does not match its ids_sha256" % path)
    if len(store["edits"]) + len(items) > workcopy.MAX_OVERLAYS:
        raise CommitError("store_full", "rehydrating %d records would exceed the %d-record cap; commit or export first" % (len(items), workcopy.MAX_OVERLAYS))
    merged = sorted(store["edits"] + items, key=lambda edit: edit["seq"])
    store["edits"] = merged
    store["archived"] = [item for item in store["archived"] if item["cid"] != entry["cid"]]
    store["commits"] = store["commits"] + [{"cid": entry["cid"], "generation": entry["generation"], "snapshot": None,
                                            "ids": sorted(item["id"] for item in items), "skipped": [], "ids_sha256": entry["ids_sha256"],
                                            "at": time.time(), "reverted": True}]
    return items


def request_abort(settings: dict, selected: dict, cid: str) -> dict:
    """`commit_abort`: honoured before the publish; after it the answer is `cancel_too_late`."""
    link = selected.get("lineage")
    if not link:
        raise CommitError("no_lineage", "this target has no commit in flight")
    if any(row.get("cid") == cid and row.get("reason") == "commit" for row in lineage.history(settings, link["id"])):
        raise CommitError("cancel_too_late", "commit %s is already published" % cid)
    flag = lineage.lineage_dir(settings, link["id"]) / "commits" / (cid + ".abort")
    flag.parent.mkdir(parents=True, exist_ok=True)
    durable.atomic_write(flag, b"abort\n")
    return {"ok": True, "cid": cid, "requested": True}


# ---- `job` options filters (kind, cid) -------------------------------------------------------------------------

def handle(capability: str, request: dict) -> str:
    """`job options.{kind, cid}`: the overlay jobs (commits among them) filtered by kind and by commit id."""
    from hydralysis import api
    options = request.get("options") or {}
    unknown = set(options) - {"kind", "cid"}
    if unknown:
        raise ValueError("job options are kind and cid, not %s" % ", ".join(sorted(unknown)))
    for name in ("kind", "cid"):
        if name in options and not isinstance(options[name], str):
            raise ValueError("job options.%s must be text" % name)
    settings = request.get("settings") or api._settings()
    from hydralysis.backends import read_json
    from hydralysis.overlayjobs import status
    limit = int((request.get("args") or {}).get("limit", 20))
    rows = []
    directory = Path(settings["root"]) / "overlay-jobs"
    for path in sorted(directory.glob("overlay-*/job.json"), key=lambda item: item.stat().st_mtime_ns, reverse=True) if directory.is_dir() else ():
        record = status(settings, path.parent.name)
        if options.get("kind") and record.get("kind") != options["kind"]:
            continue
        if options.get("cid") and (record.get("options") or {}).get("cid") != options["cid"]:
            continue
        rows.append({key: record.get(key) for key in ("id", "kind", "state", "target", "view", "created_at", "elapsed_s", "error")
                     if key in record} | {"cid": (record.get("options") or {}).get("cid")})
    return json.dumps({"jobs": rows[:limit], "filters": {key: options[key] for key in ("kind", "cid") if key in options}}, indent=2)
