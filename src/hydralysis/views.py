"""Rebase, publish and merge between views, and the publish queue (PROTOCOL-3.md 4.7, 4.8, 4.10, D45).

A view is a store of cited records on top of a base generation. Three things move records between a view and the rest:

* `rebase` (4.7): a view behind the head moves its base to the head. Per pending record: dropped when it is already in the
  master (its id, or the id it was merged from, is in the `store.ids` of a generation manifest after the view's base),
  dropped as `converged` when the master already holds its `after`, kept when the master still holds its `before`,
  otherwise a conflict that is listed, never resolved on its own. The base binding moves only when no conflict is left;
  the outcome is one atomic store write.
* `merge` / `publish to a view` (4.8): the records of a source view after its `published_through` are compared, effect by
  effect, with the destination's current values; all match: they are appended to the destination with new ids and
  `merged_from`; otherwise the conflicts are returned and `resolve` decides. Idempotent through `published_through` and
  through `merged_from`. The two view locks are taken in the lexicographic order of the view keys.
* `publish` to the master (4.10, D45): the view's pending records are sealed as a changeset in `pending/<csid>.json` and
  the caller gets a job with its position. Whoever holds the non-blocking OS lock `publish.lock` is the leader and
  drains the queue in id order, `publish_batch_max` (1) changesets per generation: it classifies the records against the
  head (applied, rebased, converged, conflict, skipped), forks the head into a candidate, replays with `verify_before`,
  verifies the candidate on a disposable clone, seals it, and appends ONE `CURRENT.log` line (the commit point) that names
  the changesets. The manifest of the generation lists the ids it applied, so a leader that died after the append and
  before `done/<csid>.json` is resolved by reading the manifest: a changeset is applied exactly once. A follower never
  waits on the leader inside a call; it polls its job (`publish_pending{position, etaMs}`) and tries the lock on each poll.

The generations of `CURRENT.log` stay consecutive: a candidate that never became head is moved aside and its number is used again,
unless the OS or the engine will not let go of the folder (an open handle on Windows): then the number is skipped and the log has a gap.

The queue's order is the order of the changeset ids (allocated when a changeset is sealed); two sealers on different views can
write their files in the reverse order of their ids, so a leader may decide a later id first. That costs order only: every
changeset is still decided once, against the head it finds.

Nothing here writes the master or a published generation. A conflict is never resolved silently: the changeset is
refused whole, its records stay pending in the view, and the conflict names the other editors.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import secrets
import shutil
import statistics
import subprocess
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

from hydralysis import backups, commits, durable, hydra, integrity, lineage, revisions, targets, workcopy
from hydralysis.locks import LaneLock, LockBusy, held, locked

FORMAT = 1
PUBLISH_BATCH_MAX = 1            # `publishBatchMax`: changesets per generation; more only if SP7 shows it is needed
PUBLISH_WAIT_S = 3600            # how long one publish job waits for its changeset before it gives up (it stays queued)
COMMIT_WAIT_S = 120              # how long a leader waits for a running commit (`.commit.lock`) before it yields
POLL_S = 0.1
MAX_ATTEMPTS = 3                 # counted candidate failures of one changeset before it ends as `candidate_failed`
MAX_QUEUE = 1000
RESOLUTIONS = ("take_mine", "keep")
_CSID = re.compile(r"c-[0-9a-f]{4,16}")
_VIEW = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class ViewError(ValueError):
    """A refusal or a terminal outcome with a stable `code`; `payload()` is what the caller receives."""

    def __init__(self, code: str, message: str, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self), **self.detail}


class PublishFailure(Exception):
    """A build that did not produce a generation. `counted` failures (the candidate was refused or failed verification)
    count against the changeset that caused them; the others (the engine was away, a commit was running) never do."""

    def __init__(self, code: str, message: str, counted: bool = False, csid: str | None = None, **detail):
        super().__init__(message)
        self.code, self.counted, self.csid, self.detail = code, counted, csid, detail

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self), "counted": self.counted, "csid": self.csid, **self.detail}


def _point(name: str) -> None:
    """A fault point (`HYDRALYSIS_TEST_FAULT=publish.<name>:exit|raise`); a no-op unless the test mode asks for it."""
    durable.fault("publish." + name)


def _text(value) -> str:
    return revisions.ABSENT if value is None else value


# ---- options -----------------------------------------------------------------------------------------------------

_COMMON = {"kind", "expect_revision", "resolve"}
KEYS = {"rebase": _COMMON,
        "merge": _COMMON | {"from", "allow_unverified_before"},
        "publish": _COMMON | {"to", "confirm_one_way_upgrade", "allow_unverified_before", "backup", "confirm_large"}}


def validate(options: dict) -> dict:
    """The options of `type_edit kind=rebase|merge|publish`, checked. Unknown keys are refused."""
    if not isinstance(options, dict):
        raise ValueError("options must be an object")
    kind = options.get("kind")
    if kind not in KEYS:
        raise ValueError("kind must be rebase, merge or publish")
    extra = set(options) - KEYS[kind]
    if extra:
        raise ValueError("options do not belong to %s: %s" % (kind, ", ".join(sorted(extra))))
    out = dict(options)
    revision = out.get("expect_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("expect_revision is required (the revision of the %s you read)"
                         % ("destination view" if kind == "merge" or out.get("to") else "view"))
    if kind == "merge" and not out.get("from"):
        raise ValueError("merge needs from: the view whose records are merged into this one")
    for name in ("from", "to"):
        if name in out and not (isinstance(out[name], str) and (out[name] == "shared" or _VIEW.fullmatch(out[name]))):
            raise ValueError("%s must be a view name" % name)
    for name in ("confirm_one_way_upgrade", "allow_unverified_before", "confirm_large"):
        if name in out and not isinstance(out[name], bool):
            raise ValueError("%s must be a boolean" % name)
    resolve = out.get("resolve")
    if resolve is not None:
        if not isinstance(resolve, dict) or any(not isinstance(key, str) or value not in RESOLUTIONS for key, value in resolve.items()):
            raise ValueError("resolve is {<subject>: take_mine | keep}")
    if "backup" in out and not isinstance(out["backup"], str):
        raise ValueError("backup must be auto or the id of a verified backup")
    return out


# ---- what the master already holds (the manifests) ---------------------------------------------------------------

def live_generations(settings: dict, lineage_id: str) -> list[dict]:
    """The CURRENT.log lines of the generations that make up the master now, oldest first (a rollback removes the later ones)."""
    chain: list[dict] = []
    for row in lineage.history(settings, lineage_id):
        if not isinstance(row.get("gen"), int):
            continue
        if row.get("reason") == "commit" and row["gen"] > 0:
            chain = [item for item in chain if item["gen"] < row["gen"]] + [row]
        elif row.get("reason") == "rollback":
            chain = [item for item in chain if item["gen"] <= row["gen"]]
    return chain


def _manifest_of(row: dict) -> dict:
    return lineage.read_manifest(lineage.project_folder_of(row["gpr"])) or {}


def master_ids(settings: dict, lineage_id: str, after_generation: int = 0) -> set[str]:
    """Ids of the records the master holds because of a generation after AFTER_GENERATION: the `store.ids` of its manifest and
    the ids the records were merged from (a record published from another view matches by `merged_from`)."""
    found: set[str] = set()
    for row in live_generations(settings, lineage_id):
        if row["gen"] > after_generation:
            store = _manifest_of(row).get("store") or {}
            found.update(store.get("ids") or [])
            found.update(store.get("merged_from_ids") or [])
    return found


def in_master(record: dict, ids: set[str]) -> bool:
    return record["id"] in ids or ((record.get("merged_from") or {}).get("id") in ids)


def editors_since(settings: dict, lineage_id: str, base_generation: int, subjects: set[str] | None = None) -> list[dict]:
    """Who moved the head after BASE_GENERATION: the generation, its cid, the view(s) and the changesets. With SUBJECTS, only
    the generations that touched one (`certain:true`, from the manifest's subject list) or that cannot say (`certain:false`)."""
    rows = []
    for row in live_generations(settings, lineage_id):
        if row["gen"] <= base_generation:
            continue
        store = _manifest_of(row).get("store") or {}
        touched = store.get("subjects")
        certain = touched is not None
        if subjects is not None and certain and not (set(touched) & subjects) and revisions.WILDCARD not in touched:
            continue
        rows.append({"generation": row["gen"], "cid": row.get("cid"), "view": store.get("view"),
                     "views": sorted({item.get("view") for item in row.get("changesets") or [] if item.get("view")}) or None,
                     "at": row.get("at"), "certain": certain})
    return rows


# ---- classification: the one rule of rebase, merge and publish ---------------------------------------------------

def probe_pairs(records: list[dict]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen = set()
    for record in records:
        for effect in record.get("effects") or []:
            pair = (effect["subject"], effect["field"])
            if effect["subject"] != revisions.WILDCARD and pair not in seen:
                seen.add(pair)
                found.append(pair)
    return found


def probe_live(engine, program: dict, records: list[dict]) -> dict:
    """The current value of each (subject, field) the records touch, read-only in PROGRAM (None: the engine cannot probe it)."""
    pairs = probe_pairs(records)
    return workcopy.probe(engine, program, pairs) if pairs else {}


def classify(records: list[dict], live: dict, chain: dict | None = None) -> tuple[list[dict], dict]:
    """Decide each record against the values LIVE (a probe of the program the records are going into).

    Records are taken in `seq` order. The first effect of a (subject, field) compares `before` with the live value:
    equal is `apply`; the live value already equal to `after` is `converged`; anything else is a `conflict`
    `{subject, field, before, now, after}`. A later effect on the same pair is chain-checked (its `before` is the earlier
    effect's `after`), and a record that touches a pair a conflicting record holds is a conflict too (`depends_on_conflict`:
    it rests on a value that was not accepted). A record with no subject record (`before_unknown`) and a bulk report
    cannot be checked and are `unchecked`: they are applied, and said so. Returns (verdicts, the chain after the accepted records).
    """
    chain = dict(chain or {})
    blocked: set[tuple[str, str]] = set()
    verdicts = []
    for record in records:
        effects = record.get("effects")
        if not effects:
            verdicts.append({"id": record["id"], "outcome": "unchecked", "reason": "before_unknown"})
            continue
        states, found_conflict = [], None
        updates: dict[tuple[str, str], str] = {}
        for index, effect in enumerate(effects):
            pair = (effect["subject"], effect["field"])
            before, after = _text(effect["before"]), _text(effect["after"])
            if effect["subject"] == revisions.WILDCARD:
                states.append("unchecked")
                continue
            if pair in blocked:
                found_conflict = {"subject": pair[0], "field": pair[1], "reason": "depends_on_conflict", "before": effect["before"],
                                  "after": effect["after"], "effect": index}
                break
            if pair in chain or pair in updates:
                expected = updates.get(pair, chain.get(pair))
                if before != expected:
                    found_conflict = {"subject": pair[0], "field": pair[1], "reason": "chain", "before": effect["before"],
                                      "now": expected, "after": effect["after"], "effect": index}
                    break
                states.append("apply")
            else:
                now = live.get(pair)
                if now is None:
                    states.append("unchecked")
                elif now == before:
                    states.append("apply")
                elif now == after:
                    states.append("converged")
                else:
                    found_conflict = {"subject": pair[0], "field": pair[1], "reason": "drift", "before": effect["before"],
                                      "now": now, "after": effect["after"], "effect": index}
                    break
            updates[pair] = after
        if found_conflict is None and "converged" in states and any(state != "converged" for state in states):
            at = next(index for index, state in enumerate(states) if state == "converged")
            first = effects[at]
            found_conflict = {"subject": first["subject"], "field": first["field"], "reason": "partially_converged",
                              "before": first["before"], "now": first["after"], "after": first["after"], "effect": at}
        if found_conflict is not None:
            blocked.update((effect["subject"], effect["field"]) for effect in effects if effect["subject"] != revisions.WILDCARD)
            verdicts.append({"id": record["id"], "outcome": "conflict", **found_conflict})
            continue
        chain.update(updates)
        verdicts.append({"id": record["id"], "outcome": "converged" if states and all(state == "converged" for state in states)
                         else ("unchecked" if states and all(state == "unchecked" for state in states) else "apply")})
    return verdicts, chain


def _conflict_row(verdict: dict, record: dict, editors: list[dict] | None = None) -> dict:
    """The conflict as an agent reads it: {subject, field, theirs, mine, ...}; `theirs` is what the other side holds now."""
    row = {"id": record["id"], "subject": verdict["subject"], "field": verdict["field"], "reason": verdict["reason"],
           "theirs": verdict.get("now"), "mine": verdict.get("after"), "before": verdict.get("before"),
           "master_now": verdict.get("now"), "after": verdict.get("after"), "by": record.get("by")}
    if editors:
        row["editors"] = editors
    return row


def _resolution(resolve: dict | None, conflict: dict) -> str | None:
    resolve = resolve or {}
    return resolve.get(conflict["subject"]) or resolve.get("%s|%s" % (conflict["subject"], conflict["field"]))


# ---- rebase (4.7) ------------------------------------------------------------------------------------------------

def rebase(settings: dict, engine, selected: dict, options: dict, timeout_s: int = 300) -> dict:
    """`type_edit kind=rebase`: move a view that is behind the head onto it. See the module text for the per-record rule.

    The new working copy is built first, in a directory of its own, and verified (the last `after` of the kept records is
    read back from it); only then does one atomic store write move the base. A crash before that write changes nothing the
    view can see; a crash after it leaves a store whose working copy is rebuilt from the base and the store (K15)."""
    options = validate({**options, "kind": "rebase"})
    workcopy.heal(settings, selected)
    binding = workcopy.lineage_binding(selected)
    with workcopy.view_lock(settings, selected):
        store = workcopy.load_store(settings, selected)
        decision = workcopy.reconcile(store, options["expect_revision"], [revisions.WILDCARD])
        base_generation = (store.get("base") or {}).get("generation", 0)
        pending = workcopy.pending_of(store)
        current = binding is not None and base_generation == binding["generation"]
        if binding is None or (current and not pending):
            return _up_to_date(selected, store)
        lineage_id = binding["lineage"]
        known = master_ids(settings, lineage_id, base_generation)
        in_the_master = [record for record in pending if in_master(record, known)]
        rest = [record for record in pending if not in_master(record, known)]
        verdicts: list[dict] = []
        if rest:
            from hydralysis.query import open_program
            program = open_program(engine, selected["gpr"], selected["program"], selected["sha256"])
            verdicts, _ = classify(rest, probe_live(engine, program, rest))
        by_id = {record["id"]: record for record in rest}
        conflicts = [verdict for verdict in verdicts if verdict["outcome"] == "conflict"]
        if current and not conflicts and not in_the_master and not any(item["outcome"] == "converged" for item in verdicts):
            return _up_to_date(selected, store)
        editors = editors_since(settings, lineage_id, base_generation, {item["subject"] for item in conflicts}) if conflicts else []
        unresolved = [item for item in conflicts if _resolution(options.get("resolve"), item) is None]
        if unresolved:
            return {"ok": False, "rebased": False, "outcome": "conflict", "view": selected.get("view", "shared"),
                    "conflicts": [_conflict_row(item, by_id[item["id"]], editors) for item in unresolved],
                    "from_generation": base_generation, "to_generation": binding["generation"],
                    "revision": store["revision"], "view_revision": store["revision"],
                    "next": {"tool": "ghidra_query", "action": "type_edit",
                             "options": {"kind": "rebase", "expect_revision": store["revision"],
                                         "resolve": {item["subject"]: "take_mine | keep" for item in unresolved}}},
                    "suggest": "nothing was changed: the master holds another value where this view's record rests on an older "
                               "one. take_mine keeps your record and re-anchors it to the master's value; keep drops it (and "
                               "the records that rest on it)"}
        converged = [item["id"] for item in verdicts if item["outcome"] == "converged"]
        # keep: the record goes, with every later record that rests on it and the rest of its batch.
        dropped_keep: set[str] = set()
        for item in conflicts:
            if _resolution(options.get("resolve"), item) == "keep":
                dropped_keep.add(item["id"])
        if dropped_keep:
            dropped_keep |= set(revisions.dependents(store["edits"], dropped_keep, workcopy.committed_ids(store)))
            batches = {by_id[ident].get("batch") for ident in dropped_keep if ident in by_id and by_id[ident].get("batch")}
            dropped_keep |= {record["id"] for record in pending if record.get("batch") in batches}
        # take_mine: the record stays; the `before` that disagrees (with the master for a drift, with the value already there
        # for a partial convergence, with the record before it for a chain) becomes the value the record will replace, so
        # the next publish finds nothing to dispute. A record that only rests on a conflicting one is kept unchanged.
        reanchored: dict[str, list[dict]] = {}
        for item in conflicts:
            if (_resolution(options.get("resolve"), item) == "take_mine" and item["reason"] in ("drift", "partially_converged", "chain")
                    and item["id"] not in dropped_keep):
                record = by_id[item["id"]]
                effects = [dict(effect) for effect in record["effects"]]
                at = item.get("effect")
                if isinstance(at, int) and 0 <= at < len(effects):
                    effects[at]["before"] = None if item["now"] == revisions.ABSENT else item["now"]
                reanchored[item["id"]] = effects
        removed = ({record["id"] for record in in_the_master} | set(converged) | dropped_keep)
        kept_ids = [record["id"] for record in rest if record["id"] not in removed]
        edits = []
        for record in store["edits"]:
            if record["id"] in removed:
                continue
            edits.append({**record, "effects": reanchored[record["id"]]} if record["id"] in reanchored else record)
        who, now = workcopy._attribution(), time.time()
        subjects = sorted({subject for record in pending if record["id"] in removed or record["id"] in reanchored
                           for subject in revisions.subjects_of(record["address"], record["options"])}) or [revisions.WILDCARD]
        new_store = {**store, "edits": edits, "base": dict(binding), "stale": None, "revision": store["revision"] + 1,
                     "reverted": (store.get("reverted") or []) + ([{"ids": sorted(removed), "by": who, "at": now, "reason": "rebase"}]
                                                                  if removed else []),
                     "journal": revisions.append(store["journal"], revisions.journal_entry(store["revision"] + 1, "rebase", subjects, who, now))}
        # 1. the new working copy, beside the old one, verified; the old one keeps serving reads until the switch below.
        verified = _build_rebased_copy(settings, engine, selected, new_store, kept_ids, timeout_s)
        # 2. the switch: one atomic store write.
        try:
            workcopy._save_store(settings, selected, new_store)
        except Exception:
            _abandon_copy(settings, selected, verified.get("state"))
            raise
        _point("after_rebase_store")
        # 3. the cache pointer follows (a crash before it is harmless: the marker mismatch rebuilds the copy).
        _adopt_copy(settings, selected, verified)
    return {"ok": True, "rebased": True, "outcome": "clean" if not conflicts and not removed else
            ("resolved" if conflicts else ("dropped" if removed else "clean")),
            "view": selected.get("view", "shared"), "from_generation": base_generation, "to_generation": binding["generation"],
            "kept": kept_ids, "dropped_in_master": [record["id"] for record in in_the_master], "converged": converged,
            "dropped_keep": sorted(dropped_keep), "reanchored": sorted(reanchored),
            "unverified": [item["id"] for item in verdicts if item["outcome"] == "unchecked"],
            "revision": new_store["revision"], "view_revision": new_store["revision"], "verified": verified["verified"],
            "outcomes_checked": verified.get("checked", 0)}


def _up_to_date(selected: dict, store: dict) -> dict:
    return {"ok": True, "rebased": False, "outcome": "up_to_date", "view": selected.get("view", "shared"),
            "revision": store["revision"], "view_revision": store["revision"], "base": store.get("base"),
            "note": "this view is already on the head generation and none of its records conflicts with it"}


def _shadow(target: dict) -> dict:
    """The directory (and so the state file and writer lane) a rebase builds its new working copy in."""
    return {**target, "key": target["key"] + "r"}


def _build_rebased_copy(settings: dict, engine, selected: dict, new_store: dict, kept_ids: list[str], timeout_s: int) -> dict:
    """Build and verify the working copy of NEW_STORE in the rebase directory. Returns {"verified", "state", "checked"}."""
    if not workcopy.pending_of(new_store):
        return {"verified": "nothing_to_replay", "state": None}
    if workcopy.heavy(new_store):
        return {"verified": "deferred_bulk_replay", "state": None}  # a bulk replay is a job of its own; the reader starts it
    shadow = _shadow(selected)
    folder = workcopy._directory(settings, shadow)
    (folder / "state.json").unlink(missing_ok=True)
    # sweep=False: the view's current copy may live in this folder (an earlier rebase built it here) and serves reads until
    # the switch; `_adopt_copy` closes it once the store names the new one.
    state = workcopy._sync(settings, shadow, new_store, timeout_s, sweep=False)
    try:
        from hydralysis.query import open_program
        program = open_program(engine, state["fork_gpr"], selected["program"], selected["sha256"], refresh=True)
        expected: dict[tuple[str, str], str] = {}
        for record in workcopy.pending_of(new_store):
            for effect in record.get("effects") or []:
                if effect["subject"] != revisions.WILDCARD:
                    expected[(effect["subject"], effect["field"])] = _text(effect["after"])
        pairs = list(expected)[:commits.SAMPLE_PER_KIND * 4]
        live = workcopy.probe(engine, program, pairs) if pairs else {}
        wrong = [{"subject": pair[0], "field": pair[1], "expected": expected[pair], "found": live.get(pair)}
                 for pair in pairs if live.get(pair) is not None and live.get(pair) != expected[pair]]
        if wrong:
            raise ViewError("rebase_verify_failed", "the rebuilt working copy does not hold the values of the kept records; the view "
                            "was not changed", mismatches=wrong[:20])
    except BaseException:
        _abandon_copy(settings, selected, state)
        raise
    return {"verified": True, "state": state, "checked": len(pairs)}


def _abandon_copy(settings: dict, selected: dict, state: dict | None) -> None:
    """A rebase that does not switch (its copy failed verification, or the store write failed): the copy it built is named by
    no store and is closed with discard, so it does not stay in the daemon as an orphan. Best effort: a later sync of the view
    finds it on disk and closes it then."""
    if not state or not state.get("fork_gpr"):
        return
    try:
        writer = workcopy.writer_for(settings, selected)
        try:
            workcopy.discard_forks(settings, selected, [state["fork_gpr"]], writer)
            workcopy._retire(writer, [state["fork_gpr"]])
        finally:
            writer.reset()
            from hydralysis.query import forget
            forget(writer)
    except Exception:  # noqa: BLE001 - the error under way is the one the caller gets
        pass


def _adopt_copy(settings: dict, selected: dict, built: dict) -> None:
    """The switch to the rebased copy: the state file names it, and every other copy of the view (the one it replaces, the
    earlier retired ones) is closed with discard (`workcopy.discard_forks`) and its folder removed once the daemon let go."""
    state = built.get("state")
    if not state:
        # Nothing to replay (every record was in the head) or a bulk replay the reader starts: the old copy holds records the
        # store no longer has pending on this base, so nothing reads it again.
        try:
            workcopy.retire_copies(settings, selected)
        except Exception:  # noqa: BLE001 - the store already switched; the next sync of the view sweeps what is left
            pass
        return
    from hydralysis.backends import write_json
    writer = workcopy.writer_for(settings, selected)
    try:
        retired = workcopy.superseded_forks(settings, selected, keep=[state["fork_gpr"]], also=list(state.get("retired", [])))
        if retired:
            workcopy.discard_forks(settings, selected, retired, writer)
        retired = workcopy._retire(writer, retired)
    finally:
        writer.reset()
        from hydralysis.query import forget
        forget(writer)
    write_json(workcopy._directory(settings, selected) / "state.json", {**state, "retired": retired})


# ---- merge and publish to a view (4.8) ---------------------------------------------------------------------------

def merge(settings: dict, engine, source: dict, destination: dict, options: dict, timeout_s: int = 300) -> dict:
    """Append SOURCE's records after its `published_through` to DESTINATION when their `before` values match what the
    destination holds now. OPTIONS are already validated (`validate`); `expect_revision` is the destination's. Conflicts
    are returned, never resolved on their own."""
    if source["key"] == destination["key"]:
        raise ViewError("same_view", "the source and the destination are the same view")
    for target in (source, destination):
        workcopy.heal(settings, target)
    ordered = sorted((source, destination), key=lambda target: target["key"])  # lexicographic order of the keys (4.8)
    with ExitStack() as stack:
        for target in ordered:
            stack.enter_context(workcopy.view_lock(settings, target))
        mine = workcopy.load_store(settings, source)
        theirs = workcopy.load_store(settings, destination)
        workcopy.refuse_stale(mine, source, "merge", settings)
        workcopy.refuse_stale(theirs, destination, "merge", settings)
        name = destination["view"]
        through = mine.get("published_through", {}).get(name, 0)
        merged_already = {(item.get("merged_from") or {}).get("id") for item in theirs["edits"]
                          if (item.get("merged_from") or {}).get("view") == source["view"]}
        candidates = [record for record in workcopy.pending_of(mine) if record["seq"] > through and record["id"] not in merged_already]
        # What a crash between the destination's write and the source's mark left behind: those are already there.
        already_there = [record for record in workcopy.pending_of(mine) if record["id"] in merged_already and record["seq"] > through]
        if not candidates:
            if already_there:
                mine["published_through"] = {**mine.get("published_through", {}), name: max(r["seq"] for r in already_there)}
                workcopy._save_store(settings, source, mine)
            return {"ok": True, "outcome": "merged", "merged": 0, "view": name, "from": source["view"],
                    "revision": theirs["revision"], "view_revision": theirs["revision"],
                    "note": "nothing after published_through", "published_through": mine.get("published_through", {}).get(name, 0)}
        unknown = [record["id"] for record in candidates if record.get("before_unknown")]
        if unknown and not options.get("allow_unverified_before"):
            raise ViewError("before_unknown", "%d record(s) predate the subject record and cannot be compared with the destination; "
                            "pass allow_unverified_before:true to merge them" % len(unknown), ids=unknown)
        subjects = sorted({subject for record in candidates for subject in revisions.subjects_of(record["address"], record["options"])})
        decision = workcopy.reconcile(theirs, options["expect_revision"], subjects)
        from hydralysis.query import open_program
        if workcopy.pending_of(theirs):
            state = workcopy._sync(settings, destination, theirs, timeout_s)
            program = open_program(engine, state["fork_gpr"], destination["program"], destination["sha256"], refresh=True)
        else:
            program = open_program(engine, destination["gpr"], destination["program"], destination["sha256"])
        verdicts, _ = classify(candidates, probe_live(engine, program, candidates))
        by_id = {record["id"]: record for record in candidates}
        conflicts = [item for item in verdicts if item["outcome"] == "conflict"]
        unresolved = [item for item in conflicts if _resolution(options.get("resolve"), item) is None]
        if unresolved:
            return {"ok": False, "outcome": "conflict", "merged": 0, "view": name, "from": source["view"],
                    "conflicts": [_conflict_row(item, by_id[item["id"]]) for item in unresolved],
                    "revision": theirs["revision"], "view_revision": theirs["revision"],
                    "next": {"tool": "ghidra_query", "action": "type_edit",
                             "options": {"kind": "merge", "from": source["view"], "view": name, "expect_revision": theirs["revision"],
                                         "resolve": {item["subject"]: "take_mine | keep" for item in unresolved}}},
                    "suggest": "nothing was merged: the destination holds another value where these records rest on an older "
                               "one. take_mine applies the record over it; keep leaves the destination's value"}
        accepted, kept, converged = [], [], []
        for verdict in verdicts:
            record = by_id[verdict["id"]]
            if verdict["outcome"] == "converged":
                converged.append(record["id"])
            elif verdict["outcome"] == "conflict" and _resolution(options.get("resolve"), verdict) == "keep":
                kept.append(record["id"])
            else:
                accepted.append(record)
        who, now = workcopy._attribution(), time.time()
        added = [{**workcopy._edit({key: record[key] for key in ("id", "address", "options")}), "id": uuid.uuid4().hex, "by": who, "at": now,
                  "merged_from": {"view": source["view"], "id": record["id"], "seq": record["seq"]}} for record in accepted]
        sync = None
        if added:
            if len(theirs["edits"]) + len(added) > workcopy.MAX_OVERLAYS:
                raise ValueError("overlay history limit reached; export/review it before adding more edits")
            sync = workcopy._sync(settings, destination, theirs, timeout_s, extra=added)
            effects = sync.get("effects") or {}
            for item in added:
                item["effects"] = revisions.clean_effects(effects.get(item["id"]))
                if item["effects"] is None:
                    item["before_unknown"] = True
                theirs["revision"] += 1
                item["seq"] = max(theirs["revision"], max((edit["seq"] for edit in theirs["edits"]), default=0) + 1)
                theirs["edits"].append(item)
                theirs["journal"] = revisions.append(theirs["journal"], revisions.journal_entry(
                    theirs["revision"], "merge", revisions.subjects_of(item["address"], item["options"]), who, now))
            workcopy._save_store(settings, destination, theirs)
            _point("after_merge_destination")
        mine["published_through"] = {**mine.get("published_through", {}), name: max(record["seq"] for record in candidates)}
        workcopy._save_store(settings, source, mine)
    return {"ok": True, "outcome": "merged", "merged": len(added), "ids": [item["id"] for item in added], "converged": converged,
            "kept_destination": kept, "view": name, "from": source["view"], "revision": theirs["revision"],
            "view_revision": theirs["revision"], "published_through": mine["published_through"][name],
            **workcopy._rebase_report(options["expect_revision"], decision),
            **({"sync": sync.get("last_sync")} if sync else {})}


# ---- the publish queue: files ------------------------------------------------------------------------------------

def _dir(settings: dict, lineage_id: str, name: str) -> Path:
    return lineage.lineage_dir(settings, lineage_id) / name


def pending_path(settings: dict, lineage_id: str, csid: str) -> Path:
    if not _CSID.fullmatch(csid or ""):
        raise ValueError("invalid changeset id")
    return _dir(settings, lineage_id, "pending") / (csid + ".json")


def done_path(settings: dict, lineage_id: str, csid: str) -> Path:
    if not _CSID.fullmatch(csid or ""):
        raise ValueError("invalid changeset id")
    return _dir(settings, lineage_id, "done") / (csid + ".json")


def declined_path(settings: dict, lineage_id: str, csid: str) -> Path:
    """The result of a changeset that made no generation (a conflict, values already there, records already in the master, a
    failed candidate). `done/` holds only what the log names, which is what the K12 oracle checks."""
    if not _CSID.fullmatch(csid or ""):
        raise ValueError("invalid changeset id")
    return _dir(settings, lineage_id, "declined") / (csid + ".json")


def failure_path(settings: dict, lineage_id: str, csid: str) -> Path:
    return _dir(settings, lineage_id, "failures") / (csid + ".json")


def publish_lock_path(settings: dict, lineage_id: str) -> Path:
    return lineage.lineage_dir(settings, lineage_id) / "publish.lock"


def new_csid() -> str:
    """Sorts in the order changesets were sealed: microseconds since the epoch, then twelve random bits for a tie."""
    return "c-%013x%03x" % (int(time.time() * 1_000_000), random.getrandbits(12))


def _ids_in(folder: Path) -> list[str]:
    if not folder.is_dir():
        return []
    return sorted(item.name[:-5] for item in folder.iterdir() if item.name.endswith(".json") and _CSID.fullmatch(item.name[:-5]))


def read_changeset(settings: dict, lineage_id: str, csid: str) -> dict:
    record = durable.read_sealed(pending_path(settings, lineage_id, csid), max_bytes=workcopy.MAX_HISTORY_BYTES + 4096)
    if record.get("csid") != csid or record.get("format", FORMAT) > FORMAT:
        raise durable.StoreCorrupt(pending_path(settings, lineage_id, csid), pending_path(settings, lineage_id, csid), {"csid": "mismatch"})
    return record


def read_done(settings: dict, lineage_id: str, csid: str) -> dict | None:
    """The result of a decided changeset: `done/` (published) or `declined/` (no generation was made), else None."""
    found = durable.read_sealed(done_path(settings, lineage_id, csid), default=None)
    return found if found is not None else durable.read_sealed(declined_path(settings, lineage_id, csid), default=None)


def write_done(settings: dict, lineage_id: str, csid: str, record: dict) -> dict:
    """The per-changeset result. Idempotent: an existing result is kept (the first one written is the outcome). A changeset
    that made a generation is written to `done/` after the `CURRENT.log` line; any other result goes to `declined/`."""
    existing = read_done(settings, lineage_id, csid)
    if existing is not None:
        return existing
    body = {"format": FORMAT, "csid": csid, "lineage": lineage_id, "at": lineage.now_iso(), "leader": {"pid": os.getpid()}, **record}
    path = done_path(settings, lineage_id, csid) if record.get("generation") is not None else declined_path(settings, lineage_id, csid)
    durable.write_sealed(path, body)
    return body


def outstanding(settings: dict, lineage_id: str) -> list[str]:
    """The changesets sealed and not yet decided, in the order of their ids (the FIFO of D45). The id is allocated before the file
    is written under the view's lock, so two sealers on different views can write in the reverse order of their ids: FIFO is
    nominal at that grain, and costs only the order in which two near-simultaneous changesets are decided."""
    finished = set(_ids_in(_dir(settings, lineage_id, "done"))) | set(_ids_in(_dir(settings, lineage_id, "declined")))
    return [csid for csid in _ids_in(_dir(settings, lineage_id, "pending")) if csid not in finished]


def _eta_ms(settings: dict, lineage_id: str, position: int) -> int | None:
    """Observed, never promised: the median build time of this lineage's last five builds times the changesets ahead. None until
    one was measured (no latency figure is stated before SP7, D45)."""
    folder = _dir(settings, lineage_id, "done")
    if not folder.is_dir():
        return None
    files = sorted((item for item in folder.iterdir() if item.name.endswith(".json")), key=lambda item: item.stat().st_mtime_ns)[-5:]
    samples = []
    for path in files:
        try:
            record = durable.read_sealed(path, default=None)
        except (durable.StoreCorrupt, OSError):
            continue
        if record and isinstance(record.get("build_ms"), (int, float)):
            samples.append(record["build_ms"])
    return int(statistics.median(samples) * position) if samples else None


def position_of(settings: dict, lineage_id: str, csid: str) -> int | None:
    queue = outstanding(settings, lineage_id)
    return queue.index(csid) + 1 if csid in queue else None


def pending_info(settings: dict, lineage_id: str, csid: str) -> dict:
    """`publish_pending{position, etaMs}`, or the result when the changeset is decided."""
    result = read_done(settings, lineage_id, csid)
    position = None if result is not None else position_of(settings, lineage_id, csid)
    if position is None and result is None:
        # The result may have been written between the two reads: it is read again before the changeset is called unknown.
        result = read_done(settings, lineage_id, csid)
    if result is not None:
        return {"state": "done", "outcome": result.get("outcome"), "generation": result.get("generation"), "csid": csid}
    if position is None:
        return {"state": "unknown", "csid": csid}
    return {"state": "publish_pending", "csid": csid, "position": position, "etaMs": _eta_ms(settings, lineage_id, position),
            "leader": held(str(publish_lock_path(settings, lineage_id)))}


def queue_status(settings: dict, lineage_id: str, csid: str | None = None) -> dict:
    """`status show=queue`: who is waiting, whether a leader is running, the recent results."""
    queue = outstanding(settings, lineage_id)
    rows = []
    for position, name in enumerate(queue[:50], start=1):
        try:
            record = read_changeset(settings, lineage_id, name)
            rows.append({"csid": name, "position": position, "view": record.get("view"), "records": len(record.get("records", [])),
                         "sealed_at": record.get("sealed_at"), "agent": record.get("agent")})
        except (durable.StoreCorrupt, OSError, ValueError):
            rows.append({"csid": name, "position": position, "error": "unreadable"})
    recent = []
    for name in sorted(set(_ids_in(_dir(settings, lineage_id, "done"))) | set(_ids_in(_dir(settings, lineage_id, "declined"))),
                       reverse=True)[:10]:
        result = read_done(settings, lineage_id, name) or {}
        recent.append({key: result.get(key) for key in ("csid", "outcome", "generation", "build_ms", "at")})
    leading = held(str(publish_lock_path(settings, lineage_id)))
    who = None
    if leading:
        try:
            who = json.loads((lineage.lineage_dir(settings, lineage_id) / "publish.leader.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            who = None
    return {"lineage": lineage_id, "queue": {"length": len(queue), "leader": leading, "leader_info": who,
                                              "changesets": rows, "batch_max": PUBLISH_BATCH_MAX},
            "recent": recent, **({"changeset": pending_info(settings, lineage_id, csid)} if csid else {})}


# ---- sealing a changeset (the caller's half) ---------------------------------------------------------------------

def ensure_lineage(settings: dict, selected: dict) -> dict:
    """The lineage of SELECTED, created at the first publish. Creation is serialised: 24 first publishers make one lineage."""
    from hydralysis.locks import locked
    lineages = lineage.lineages_root(settings)
    with locked(lineages / ".ensure.lock", 60, what="lineage creation"):
        return lineage.ensure(settings, {**selected, "origin_key": selected.get("origin_key") or selected["key"]})


def seal_changeset(settings: dict, selected: dict, options: dict) -> dict:
    """Step 1 of 4.10: seal `pending/<csid>.json` (the view's pending records, their base, the agent) and return at once.

    No engine call, no other view and no reader is involved. A second publish of the same pending records while the first
    waits returns the first (`reused`)."""
    options = validate({**options, "kind": "publish"})
    commits._plan_confirmation(options)
    link = ensure_lineage(settings, selected)
    lineage_id = link["id"]
    selected = workcopy.with_view(targets.resolve(settings, selected["name"]), selected.get("view", ""))
    workcopy.heal(settings, selected)
    head = lineage.head(settings, lineage_id)
    if head["corrupt"]:
        raise commits.CommitError("lineage_corrupt", "CURRENT.log has a damaged line in the middle; publishes are refused until the "
                                  "owner repairs it", corrupt=head["corrupt"])
    with workcopy.view_lock(settings, selected):
        store = workcopy.load_store(settings, selected)
        if store["revision"] != options["expect_revision"]:
            raise commits.CommitError("revision_changed", "the store is at revision %d, not %d" % (store["revision"], options["expect_revision"]),
                                      current_revision=store["revision"])
        pending = workcopy.pending_of(store)
        if not pending:
            raise commits.CommitError("nothing_to_commit", "no pending record to publish")
        unknown = [record["id"] for record in pending if record.get("before_unknown")]
        if unknown and not options.get("allow_unverified_before"):
            raise commits.CommitError("before_unknown", "%d record(s) predate the subject record and cannot be checked against the "
                                      "master; pass allow_unverified_before:true to publish them" % len(unknown), ids=unknown)
        ids_sha = workcopy._digest_of(sorted(record["id"] for record in pending))
        for name in outstanding(settings, lineage_id):
            try:
                earlier = read_changeset(settings, lineage_id, name)
            except (durable.StoreCorrupt, OSError):
                continue
            if earlier.get("view_key") == selected["key"] and earlier.get("ids_sha256") == ids_sha:
                return {"csid": name, "reused": True, "lineage": lineage_id, "records": len(pending), "ids_sha256": ids_sha,
                        **pending_info(settings, lineage_id, name)}
        csid = new_csid()
        body = {"format": FORMAT, "csid": csid, "lineage": lineage_id, "view": selected.get("view", "shared"), "view_key": selected["key"],
                "target": {"name": selected["name"], "program": selected["program"], "sha256": selected["sha256"],
                           "origin_key": selected.get("origin_key") or selected["key"]},
                "agent": workcopy._attribution(), "base": store.get("base"), "store_revision": store["revision"],
                "head_generation": head["gen"], "ids": [record["id"] for record in pending], "ids_sha256": ids_sha, "records": pending,
                "options": {key: options[key] for key in ("allow_unverified_before", "backup", "confirm_large") if key in options},
                "sealed_at": lineage.now_iso()}
        durable.write_sealed(pending_path(settings, lineage_id, csid), body, max_bytes=workcopy.MAX_HISTORY_BYTES,
                             too_large="the changeset would exceed 20 MiB; publish fewer records")
    _point("after_seal_changeset")
    return {"csid": csid, "reused": False, "lineage": lineage_id, "records": len(pending), "ids_sha256": ids_sha,
            "base_generation": (store.get("base") or {}).get("generation", 0), "head_generation": head["gen"],
            **pending_info(settings, lineage_id, csid)}


# ---- the leader --------------------------------------------------------------------------------------------------

def _batch_max(settings: dict) -> int:
    value = settings.get("publish_batch_max", PUBLISH_BATCH_MAX)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else PUBLISH_BATCH_MAX


def drain(settings: dict, lineage_id: str, engine=None, stop_after: str | None = None, timeout_s: int = 600) -> dict:
    """Try to become the leader and drain the queue in id order, until it is empty or STOP_AFTER is decided.

    Non-blocking: when another process holds `publish.lock` this returns `{"led": False}` at once. The lock is held for the
    drain only, and is released by the OS if the leader dies. Returns {"led", "built": [generation ...], "failure"}."""
    lineage.lineage_dir(settings, lineage_id).mkdir(parents=True, exist_ok=True)
    lock = LaneLock(str(publish_lock_path(settings, lineage_id)))
    if not lock.acquire():
        return {"led": False, "built": [], "failure": None}
    engine = engine or hydra.Engine(settings)
    built: list[int] = []
    failure = None
    try:
        # Who leads, for `status` and the doctor (the OS lock is the truth; this file is only a label and may be stale).
        durable.atomic_write(lineage.lineage_dir(settings, lineage_id) / "publish.leader.json",
                             json.dumps({"pid": os.getpid(), "at": lineage.now_iso()}).encode("utf-8"), point="leader")
        _point("after_lock")
        # Every acquisition repairs a torn CURRENT.log tail before any append (4.1), then settles what a dead leader left.
        lineage.current_log(settings, lineage_id).repair(lock_held=False)
        reconcile(settings, lineage_id)
        while True:
            queue = outstanding(settings, lineage_id)
            if not queue or (stop_after and stop_after not in queue):
                break
            try:
                step = _build(settings, lineage_id, engine, queue[:_batch_max(settings)], timeout_s)
            except PublishFailure as error:
                failure = error.payload()
                _count_failure(settings, lineage_id, error)
                break
            if step.get("generation"):
                built.append(step["generation"])
        return {"led": True, "built": built, "failure": failure}
    finally:
        lock.release()


def _count_failure(settings: dict, lineage_id: str, error: PublishFailure) -> None:
    """A counted failure is held against the changeset that caused it; at MAX_ATTEMPTS it ends as `candidate_failed`, so one
    poisoned changeset cannot hold the queue for ever. The view's records stay pending: nothing is ever dropped."""
    if not error.counted or not error.csid:
        return
    path = failure_path(settings, lineage_id, error.csid)
    record = durable.read_sealed(path, default=None) or {"csid": error.csid, "attempts": 0, "history": []}
    record["attempts"] += 1
    record["history"] = (record["history"] + [{"at": lineage.now_iso(), "code": error.code, "message": str(error)[:300],
                                              "candidate": error.detail.get("candidate")}])[-10:]
    durable.write_sealed(path, record)
    if record["attempts"] >= MAX_ATTEMPTS:
        write_done(settings, lineage_id, error.csid, {"outcome": "candidate_failed", "generation": None, "record_outcomes": {},
                                                      "attempts": record["attempts"], "failure": record["history"][-1],
                                                      "candidates": [item["candidate"] for item in record["history"] if item.get("candidate")]})


def reconcile(settings: dict, lineage_id: str) -> list[dict]:
    """Under `publish.lock`: settle what a dead leader left. A changeset the live history names, whose result file is missing,
    is resolved from the manifest of its generation: the manifest still verifies, so the result is written (exactly once); if it
    does not verify, a `rollback` line returns the head to the previous generation and the changesets stay in the queue."""
    done = []
    chain = live_generations(settings, lineage_id)
    for row in chain:
        names = [item["csid"] for item in row.get("changesets") or [] if item.get("csid")]
        missing = [name for name in names if read_done(settings, lineage_id, name) is None]
        if not missing:
            continue
        folder = lineage.project_folder_of(row["gpr"])
        check = lineage.verify_manifest(folder)
        if check["ok"] and lineage.manifest_file_sha256(folder) == row.get("manifestSha256"):
            store = check["manifest"].get("store") or {}
            for name in missing:
                info = (store.get("by_changeset") or {}).get(name) or {}
                write_done(settings, lineage_id, name, {"outcome": info.get("outcome", "applied"), "generation": row["gen"],
                                                        "gpr": row["gpr"], "manifestSha256": row.get("manifestSha256"),
                                                        "record_outcomes": info.get("records") or {}, "resolved_from": "manifest"})
                done.append({"csid": name, "action": "resolved_from_manifest", "generation": row["gen"]})
        else:
            previous = (check["manifest"] or {}).get("base", {}).get("generation", 0)
            back = next((item for item in reversed(lineage.history(settings, lineage_id)) if item.get("gen") == previous
                         and item.get("reason") != "rollback"), None)
            if back is not None:
                lineage.append_current(settings, lineage_id, {"gen": previous, "cid": row.get("cid"), "reason": "rollback", "gpr": back["gpr"],
                                                              "manifestSha256": back.get("manifestSha256"),
                                                              "detail": "candidate_failed_reverify"})
            done.append({"csid": missing, "action": "rolled_back", "problems": check["problems"]})
    return done


def _leader_target(first: dict, head: dict) -> dict:
    origin = first["target"]["origin_key"]
    return {"name": first["target"]["name"], "program": first["target"]["program"], "sha256": first["target"]["sha256"], "key": origin,
            "origin_key": origin, "gpr": head["gpr"], "view": "shared"}


def _verify_candidate(settings: dict, engine, job, target: dict, candidate_gpr: str, clone_folder: Path, source_gpr: str,
                      applied: list[dict]) -> None:
    """4.10 step 4: K2 and K3 on the candidate's files and on a disposable clone (the candidate itself is never opened again):
    the header of its newest version, the clone opening read-only and writable, the function count and analysed flag equal to the
    parent's, every applied effect read back (`after` equals the live value), K sampled decompiles that succeed and carry the
    current names, and a spot check of functions the changeset did not touch."""
    report = integrity.scan(candidate_gpr)
    if not report["ok"]:
        raise PublishFailure("candidate_failed", "the candidate has a database version without a valid header", counted=True, report=report)
    clone_folder.parent.mkdir(parents=True, exist_ok=True)
    clone = job.call("fork_project", project=candidate_gpr, path=str(clone_folder), writable=True,
                     mode=str(settings.get("fork_mode", "auto")), maxCopyMb=int(settings.get("fork_max_copy_mb", 8192)),
                     **({"purpose": "fork"} if "forkPurposes" in commits._capabilities(engine) else {}))
    try:
        parent = commits._program_of(engine, source_gpr, target)
        read_only = commits._program_of(engine, clone["gpr"], target, refresh=True)
        if (read_only.get("functions"), read_only.get("analyzed")) != (parent.get("functions"), parent.get("analyzed")):
            raise PublishFailure("candidate_failed", "the candidate's function count or analysed flag differs from its parent's", counted=True)
        last: dict[tuple[str, str], str | None] = {}
        for record in applied:
            for effect in record.get("effects") or []:
                if effect["subject"] != revisions.WILDCARD:
                    last[(effect["subject"], effect["field"])] = effect["after"]
        if last:
            live = workcopy.probe(engine, read_only, list(last))
            # A pair the probe could not read (None) is not a mismatch: None means "could not probe", never "holds a wrong value".
            wrong = [{"subject": pair[0], "field": pair[1], "expected": after, "found": live.get(pair)}
                     for pair, after in last.items() if live.get(pair) is not None and live.get(pair) != _text(after)]
            if wrong:
                raise PublishFailure("candidate_failed", "%d applied effect(s) are not what the candidate holds" % len(wrong),
                                     counted=True, mismatches=wrong[:20])
        names = {}
        for record in applied:
            for effect in record.get("effects") or []:
                if effect["field"] == "name" and effect["subject"].startswith("address:") and effect["after"]:
                    names[effect["subject"].removeprefix("address:")] = effect["after"]
        for address in commits._sample(applied):
            try:
                text = commits._decompile(engine, read_only, address, target["sha256"])
            except commits.CommitError as error:
                raise PublishFailure("candidate_failed", str(error), counted=True, address=address) from error
            if address in names and names[address] not in text:
                raise PublishFailure("candidate_failed", "the decompile of %s does not carry the current name %s" % (address, names[address]),
                                     counted=True, address=address)
        touched = {address for addresses in commits._touched(applied).values() for address in addresses}
        from hydralysis.query import run_script
        listing, _ = run_script(engine, parent, {"id": uuid.uuid4().hex, "action": "functions", "address": "", "limit": 200, "cursor": "",
                                                 "contains": "", "timeout_s": 60, "options": {}}, 60)
        # A caller of a function the changeset renamed prints the new name: that difference is explained by the records and
        # passes; any other difference fails the candidate (commits.spot_check).
        spot = commits.spot_check(engine, parent, read_only, target["sha256"], applied, listing.get("functions", []), touched)
        if spot["diverged"]:
            raise PublishFailure("candidate_failed", "untouched function %s decompiles differently in the candidate, and the "
                                 "changeset's renames do not explain the difference" % spot["diverged"], counted=True,
                                 address=spot["diverged"], spot_check={key: value for key, value in spot.items() if key != "diverged"})
        try:
            writable = commits._program_of(job, clone["gpr"], target, writable=True, upgrade=False, refresh=True)
        except hydra.EngineError as error:
            if error.code in ("closed", "busy"):
                raise  # the engine is away or occupied: that says nothing about the candidate
            raise PublishFailure("candidate_failed", "the candidate's clone does not open writable: %s" % error, counted=True,
                                 engine_error=error.code) from error
        job.call("close_project", project=writable["project"], discard=True)
        job.reset()
        return {key: value for key, value in spot.items() if key != "diverged"}
    finally:
        # The clone's programs on the caller's connection are closed by the keys that connection got, and their rows dropped,
        # so they neither count against maxViewsPerClient nor stay in the cache (as in commits._verify_candidate).
        try:
            commits._release(engine, {key: value for key, value in commits._rows(engine).items()
                                      if key[1] == str(Path(clone["gpr"])).lower()})
        except Exception:
            pass
        try:
            engine.call("close_project", project=clone.get("project"), discard=True)
        except Exception:
            pass


def _append_line(settings: dict, lineage_id: str, line: dict) -> dict:
    """The CURRENT.log line of the publish (the commit point). Under `append_torn` only its first n bytes reach the disk."""
    torn = durable.fault("publish.append_torn")
    if torn is None:
        return lineage.append_current(settings, lineage_id, line)
    log = lineage.current_log(settings, lineage_id)
    with durable.file_lock(log.lock_path, log.lock_timeout_s, what="log CURRENT.log"):
        log.repair(lock_held=True)
        previous = log.last(strict=True)
        full = durable.frame({"seq": previous["seq"] + 1, **line, "at": lineage.now_iso(),
                              "prevHash": lineage.sha256_hex(lineage.canonical(previous))})
        durable.AppendLog._raw_append(log.path, full[:torn], faults=False)
    durable._die()


def _acquire_commit_lock(settings: dict, lineage_id: str) -> LaneLock:
    """A publish and a Y2 commit both append generations: they take turns on `.commit.lock`. The wait is bounded, and a
    wait that runs out is not a failure of the changeset."""
    lock = LaneLock(str(lineage.commit_lock_path(settings, lineage_id)))
    deadline = time.monotonic() + COMMIT_WAIT_S
    while not lock.acquire():
        if time.monotonic() >= deadline:
            raise PublishFailure("commit_busy", "a commit holds this lineage's commit lock; the changesets stay queued")
        time.sleep(0.05)
    return lock


def _build(settings: dict, lineage_id: str, engine, batch_ids: list[str], timeout_s: int) -> dict:
    """Steps 3 to 5 of 4.10 for one batch. Returns {"generation": n|None, "csids": [...]}."""
    started = time.monotonic()
    commit_lock = _acquire_commit_lock(settings, lineage_id)
    try:
        # A commit that ran while this leader waited may have moved the head: everything below reads it afresh.
        return _build_locked(settings, lineage_id, engine, batch_ids, timeout_s, started)
    finally:
        commit_lock.release()


def _build_locked(settings: dict, lineage_id: str, engine, batch_ids: list[str], timeout_s: int, started: float) -> dict:
    head = lineage.head(settings, lineage_id)
    if head["corrupt"]:
        raise PublishFailure("lineage_corrupt", "CURRENT.log has a damaged line in the middle (offset %s); publishes are refused until "
                             "the owner repairs it" % head["corrupt"].get("offset"))
    bad = lineage.tampered(settings, lineage_id)
    if bad:
        raise PublishFailure("tampered", "a published generation no longer matches its manifest; publishes are refused until the "
                             "owner re-adopts", tampered=bad)
    batch = []
    for name in batch_ids:
        if read_done(settings, lineage_id, name) is not None:
            continue
        try:
            batch.append(read_changeset(settings, lineage_id, name))
        except (durable.StoreCorrupt, OSError, ValueError) as error:
            write_done(settings, lineage_id, name, {"outcome": "corrupt_changeset", "generation": None, "record_outcomes": {},
                                                    "message": str(error)[:300]})
    if not batch:
        return {"generation": None, "csids": []}
    target = _leader_target(batch[0], head)
    known = master_ids(settings, lineage_id)
    program = commits._program_of(engine, head["gpr"], target)
    everything = [record for cs in batch for record in cs["records"] if not in_master(record, known)]
    live = probe_live(engine, program, everything)
    chain: dict = {}
    results = []
    for cs in batch:
        skipped = [record for record in cs["records"] if in_master(record, known)]
        mine = [record for record in cs["records"] if not in_master(record, known)]
        unverified = [record["id"] for record in mine if record.get("before_unknown")]
        verdicts, after = classify(mine, live, chain)
        by_id = {record["id"]: record for record in mine}
        conflicts = [item for item in verdicts if item["outcome"] == "conflict"]
        outcomes = {record["id"]: "skipped" for record in skipped}
        for item in verdicts:
            outcomes[item["id"]] = {"apply": "applied", "unchecked": "applied", "converged": "converged", "conflict": "conflict"}[item["outcome"]]
        apply = [by_id[item["id"]] for item in verdicts if item["outcome"] in ("apply", "unchecked")]
        if conflicts:
            editors = editors_since(settings, lineage_id, (cs.get("base") or {}).get("generation", 0), {item["subject"] for item in conflicts})
            outcome = "conflict"
        else:
            editors = []
            moved = (cs.get("base") or {}).get("generation", 0) != head["gen"]
            outcome = (("rebased" if moved else "applied") if apply else ("converged" if any(v["outcome"] == "converged" for v in verdicts) else "skipped"))
            chain = after
            if moved and apply:
                for ident in (record["id"] for record in apply):
                    outcomes[ident] = "rebased"
        results.append({"cs": cs, "outcome": outcome, "apply": apply, "records": outcomes, "unverified": unverified,
                        "converged": [item["id"] for item in verdicts if item["outcome"] == "converged"],
                        "in_master": [record["id"] for record in skipped],
                        "conflicts": [_conflict_row(item, by_id[item["id"]], editors) for item in conflicts]})
    # Decided without a new generation: a conflict, records the master already holds, values it already has.
    accepted = [item for item in results if item["apply"]]
    accepted_ids = {item["cs"]["csid"] for item in accepted}
    for item in results:
        if item["cs"]["csid"] in accepted_ids:
            continue
        write_done(settings, lineage_id, item["cs"]["csid"],
                   {"outcome": item["outcome"], "generation": None, "record_outcomes": item["records"], "conflicts": item["conflicts"],
                    "base_generation": head["gen"], "settled": sorted(item["converged"] + item["in_master"]),
                    "converged": item["converged"], "in_master": item["in_master"], "unverified": item["unverified"],
                    "build_ms": int((time.monotonic() - started) * 1000)})
        if item["outcome"] != "conflict":
            settle_one(settings, lineage_id, item["cs"], None, sorted(item["converged"] + item["in_master"]))
    if not accepted:
        return {"generation": None, "csids": [item["cs"]["csid"] for item in results]}
    return _publish_candidate(settings, lineage_id, engine, head, target, accepted, timeout_s, started)


def reserve_generation(settings: dict, lineage_id: str) -> int:
    """The number of the next candidate: one more than the highest generation the log ever named, so the generations of
    `CURRENT.log` are consecutive (K12) however many candidates were abandoned, unless the OS or the engine will not let go of an
    abandoned folder (see below), which makes a gap. Only the leader (it holds `publish.lock` and
    `.commit.lock`) gets here, so a folder at that number that the log never named is an abandoned candidate: it was never head,
    and it is moved aside, not deleted, for manual removal (D28). If the OS or the engine will not let go of it the number is
    skipped instead, which costs a gap and nothing else."""
    logged = {row["gen"] for row in lineage.history(settings, lineage_id) if isinstance(row.get("gen"), int)}
    number = max(logged | {0}) + 1
    folder = lineage.generation_dir(settings, lineage_id, number)
    if folder.exists():
        try:
            durable.replace_file(folder, folder.with_name("%04d.abandoned-%s" % (number, uuid.uuid4().hex[:8])))
        except OSError:
            return lineage.next_generation(settings, lineage_id)
    return number


def _publish_candidate(settings: dict, lineage_id: str, engine, head: dict, target: dict, accepted: list[dict], timeout_s: int,
                       started: float) -> dict:
    first = accepted[0]["cs"]["csid"]
    generation = reserve_generation(settings, lineage_id)
    candidate_folder = lineage.generation_dir(settings, lineage_id, generation)
    leader_target = {**target, "key": "publish-" + first.removeprefix("c-")[:10]}
    workcopy._directory(settings, leader_target).mkdir(parents=True, exist_ok=True)
    job = hydra.Engine(settings, role="publish", lane=first)
    clone_folder: Path | None = None
    culprit = first
    try:
        options = {"backup": accepted[0]["cs"].get("options", {}).get("backup", "auto"),
                   "confirm_large": any(item["cs"].get("options", {}).get("confirm_large") for item in accepted)}
        master = engine.call("open_project", path=head["gpr"])
        made = commits._backup(settings, engine, target, lineage_id, head["gpr"], master.get("revision") or "", head["gen"], options)
        _point("after_backup")
        candidate_folder.parent.mkdir(parents=True, exist_ok=True)
        forked = job.call("fork_project", project=head["gpr"], path=str(candidate_folder), writable=True,
                          mode=str(settings.get("fork_mode", "auto")), maxCopyMb=int(settings.get("fork_max_copy_mb", 8192)),
                          **({"purpose": "generation"} if "forkPurposes" in commits._capabilities(engine) else {}))
        candidate_gpr = forked["gpr"]
        # hydra.2/3 has no `purpose`: the sidecar is rewritten so a later engine takes the generation for neither a disposable
        # fork (D12) nor a sealed one (D38). The candidate is writable on purpose until it is verified (D38, revision 7).
        backups._rewrite_sidecar(candidate_folder, disposable=False, purpose="generation", state="candidate")
        integrity.check_fork(candidate_gpr, disposable=True)
        gate = {"backup": str(Path(made["backup"]["folder"]) / "backup.json")} if "upgradeGate" in commits._capabilities(engine) else {}
        program = commits._program_of(job, candidate_gpr, target, writable=True, upgrade=True, refresh=True, share=False, **gate)
        _point("after_fork")
        applied: list[dict] = []
        for item in accepted:
            culprit = item["cs"]["csid"]
            _point("mid_apply")
            try:
                workcopy._apply(settings, job, program, item["apply"], None, timeout_s, target=leader_target, verify_before=True)
            except workcopy.VerifyMismatch as mismatch:
                raise PublishFailure("candidate_failed", "the candidate refused a record: %s" % mismatch, counted=True, csid=culprit,
                                     effect=mismatch.detail, candidate=str(candidate_folder)) from mismatch
            except (ValueError, RuntimeError) as refused:
                raise PublishFailure("candidate_failed", "the engine refused the replay: %s" % refused, counted=True, csid=culprit,
                                     candidate=str(candidate_folder)) from refused
            applied.extend(item["apply"])
        culprit = first
        job.call("save", program=program["key"], comment="Hydralysis publish %s" % first, wait=600000)
        _point("after_save")
        job.call("close_project", project=program["project"])
        job.reset()
        commits._force_files(candidate_folder)
        _point("after_force")
        # The manifest: the ids the generation applied, per changeset, so an acknowledged publish is resolved by reading it.
        settled_all: list[str] = []
        by_changeset = {}
        for item in accepted:
            ids = sorted(set(item["records"]) - {ident for ident, kind in item["records"].items() if kind == "conflict"})
            settled_all.extend(ids)
            by_changeset[item["cs"]["csid"]] = {"outcome": item["outcome"], "ids": ids, "records": item["records"],
                                                "view": item["cs"]["view"], "view_key": item["cs"]["view_key"],
                                                "snapshot": item["cs"]["store_revision"]}
        merged_from = sorted({record["merged_from"]["id"] for record in applied if (record.get("merged_from") or {}).get("id")})
        subjects = sorted({subject for record in applied for subject in revisions.subjects_of(record["address"], record["options"])})
        bundle_sha = lineage.sha256_hex(lineage.canonical([{key: record.get(key) for key in ("id", "address", "options", "effects")}
                                                           for record in applied]))
        hello = engine.hello()
        ids_sha = workcopy._digest_of(sorted(settled_all))
        body = {"cid": first, "via": "publish", "changesets": [item["cs"]["csid"] for item in accepted],
                "base": {"generation": head["gen"], "revision": master.get("revision")},
                "engine": {key: hello.get(key) for key in ("hydraVersion", "ghidraVersion") if hello.get(key)},
                "dbVersions": hello.get("dbVersions") or (hello.get("analysisIdentity") or {}).get("dbVersions"),
                "backups": [made["backup"]["manifestSha256"]],
                "store": {"view": accepted[0]["cs"]["view"], "revision": accepted[0]["cs"]["store_revision"],
                          "snapshot": accepted[0]["cs"]["store_revision"], "ids": sorted(settled_all),
                          "applied": sorted(record["id"] for record in applied), "skipped": [], "ids_sha256": ids_sha,
                          "bundle_sha256": bundle_sha, "by_changeset": by_changeset, "subjects": subjects, "merged_from_ids": merged_from},
                "hydralysis_commit": {"cid": first, "lineage": lineage_id, "base_generation": head["gen"], "ids_sha256": ids_sha,
                                      "bundle_sha256": bundle_sha}}
        manifest = lineage.write_manifest(candidate_folder, body)
        manifest_sha = lineage.manifest_file_sha256(candidate_folder)
        _point("after_manifest")
        clone_folder = Path(settings.get("tmp_dir") or workcopy.root_path(settings)) / "publish-verify" / (first + "-" + uuid.uuid4().hex[:6])
        try:
            spot = _verify_candidate(settings, engine, job, target, candidate_gpr, clone_folder, head["gpr"], applied) or {}
        except PublishFailure as error:
            error.csid = error.csid or first
            error.detail.setdefault("candidate", str(candidate_folder))
            raise
        _point("after_verify")
        # Sealed before it can be head: from here every writable path on the candidate is refused (D38).
        if "sealProject" in commits._capabilities(engine):
            engine.call("seal_project", project=candidate_gpr)
        backups.seal(candidate_folder, manifest_sha)
        _point("after_seal")
        # Commit point: one CURRENT.log line that names the changesets, then the results.
        _point("before_append")
        line = _append_line(settings, lineage_id, {"gen": generation, "cid": first, "reason": "commit", "via": "publish",
                                                    "csids": [item["cs"]["csid"] for item in accepted], "changesets": [{"csid": item["cs"]["csid"], "view": item["cs"]["view"],
                                                                    "view_key": item["cs"]["view_key"]} for item in accepted],
                                                    "gpr": candidate_gpr, "manifestSha256": manifest_sha, "engine": body["engine"]})
        _point("after_append")
        build_ms = int((time.monotonic() - started) * 1000)
        for item in accepted:
            write_done(settings, lineage_id, item["cs"]["csid"],
                       {"outcome": item["outcome"], "generation": generation, "gpr": candidate_gpr, "manifestSha256": manifest_sha,
                        "record_outcomes": item["records"], "seq": line["seq"], "base_generation": head["gen"], "build_ms": build_ms,
                        "unverified": item["unverified"], "converged": item["converged"], "in_master": item["in_master"],
                        "spot_check": spot})
            _point("after_done")
        for item in accepted:
            settle_one(settings, lineage_id, item["cs"], generation, by_changeset[item["cs"]["csid"]]["ids"])
        return {"generation": generation, "csids": [item["cs"]["csid"] for item in accepted], "manifestSha256": manifest_sha}
    except (durable.FaultInjected, commits.Crash):
        raise  # a simulated kill: nothing more is written, the next leader decides from the files
    except PublishFailure:
        raise
    except hydra.EngineError as error:
        raise PublishFailure("engine_refused", "the engine refused %s: %s" % (error.command or "a call", error), engine_error=error.code) from error
    except commits.CommitError as error:
        raise PublishFailure(error.code, str(error), counted=False, csid=culprit) from error
    finally:
        try:
            job.reset()
        except Exception:
            pass
        if clone_folder is not None:
            shutil.rmtree(clone_folder, ignore_errors=True)


# ---- settling a view ---------------------------------------------------------------------------------------------


def settle_one(settings: dict, lineage_id: str, cs: dict, generation: int | None, ids: list[str]) -> bool:
    """Finalize one decided changeset in the view that sealed it (best effort: a view that is busy settles at its next call)."""
    try:
        target = workcopy.with_view(targets.resolve(settings, cs["target"]["name"]), "" if cs["view"] == "shared" else cs["view"])
        return finalize_changeset(settings, target, lineage_id, cs["csid"], generation, ids, cs.get("store_revision"))
    except (RuntimeError, LockBusy, OSError, ValueError, durable.StoreCorrupt):
        return False


def finalize_changeset(settings: dict, selected: dict, lineage_id: str, csid: str, generation: int | None, ids: list[str],
                       snapshot: int | None) -> bool:
    """In one atomic store write of the sealing view: the decided records become a commit entry of the new generation (the
    previous live entry is archived, as in 4.2) and the base moves to it; with no generation (the values were already there)
    they are dropped. Idempotent by `csid`. Returns whether anything was written.

    The base moves to GENERATION only when that is safe for what stays in the view. Records the view still holds (added while the
    changeset waited) were written over the head the view had, and the generations between its old base and GENERATION (other
    views' publishes the leader decided first) were never classified against them. When such records remain and the jump crosses
    another generation, the base stays: the view is then stale, `rebase` classifies the remainder against the head (a conflict is
    listed and resolvable), and until then it answers from the working copy it has."""
    with workcopy.view_lock(settings, selected):
        store = workcopy.load_store(settings, selected)
        if any(item.get("csid") == csid for item in store["changesets"]):
            return False
        present = [record["id"] for record in store["edits"] if record["id"] in set(ids)]
        committed = workcopy.committed_ids(store)
        present = [ident for ident in present if ident not in committed]
        remaining = [record["id"] for record in workcopy.pending_of(store) if record["id"] not in set(present)]
        base_before = (store.get("base") or {}).get("generation", 0)
        who, now = workcopy._attribution(), time.time()
        if generation is not None:
            live = [entry for entry in store["commits"] if not entry.get("reverted")]
            if present:
                if live:
                    commits._archive(settings, selected, store, live[-1])
                    store["commits"] = [entry for entry in store["commits"] if entry["cid"] != live[-1]["cid"]]
                store["commits"] = store["commits"] + [{"cid": csid, "generation": generation, "snapshot": snapshot, "ids": sorted(present),
                                                        "skipped": [], "ids_sha256": workcopy._digest_of(sorted(present)),
                                                        "bundle_sha256": None, "at": now, "reverted": False}]
            old_base = (store.get("base") or {}).get("generation", 0)
            crosses_others = generation > old_base + 1
            if generation >= old_base and not (remaining and crosses_others):
                store["base"] = {"lineage": lineage_id, "generation": generation}
                store["stale"] = None
            op = "commit"
        else:
            store["edits"] = [record for record in store["edits"] if record["id"] not in set(present)]
            store["reverted"] = (store.get("reverted") or []) + ([{"ids": present, "by": who, "at": now, "reason": "published:already_in_master"}]
                                                                if present else [])
            op = "publish"
        moved = (store.get("base") or {}).get("generation", 0) != base_before
        store["changesets"] = store["changesets"] + [{"csid": csid, "generation": generation, "ids": sorted(present), "at": now}]
        store["revision"] += 1
        store["journal"] = revisions.append(store["journal"], revisions.journal_entry(store["revision"], op, [revisions.WILDCARD], who, now))
        workcopy._save_store(settings, selected, store)
        if moved or not workcopy.pending_of(store):
            # The view's working copy holds the published records unsaved on the old base: with nothing pending the view reads
            # the head, and with its base moved its next use rebuilds the copy, so nothing reads it again. Closed now (9.17)
            # rather than left in the daemon as an orphan until that next use, which may never come.
            try:
                workcopy.retire_copies(settings, selected)
            except Exception:  # noqa: BLE001 - the changeset is final; the next sync of the view sweeps what is left
                pass
        return True


def settle(settings: dict, selected: dict) -> bool:
    """Called before a view is read or edited: finalize the publishes of this view that the leader did not (it died between the
    `CURRENT.log` line and the store write, or the view was busy). Never waits for a publish in progress."""
    link = selected.get("lineage")
    if not link:
        return False
    rows = [row for row in live_generations(settings, link["id"]) if row.get("via") == "publish"]
    mine = [(row, item) for row in rows for item in row.get("changesets") or [] if item.get("view_key") == selected["key"]]
    if not mine:
        return False
    known = {item["csid"] for item in workcopy.load_store(settings, selected)["changesets"]}
    todo = [(row, item) for row, item in mine if item["csid"] not in known]
    changed = False
    for row, item in todo:
        manifest = _manifest_of(row)
        info = ((manifest.get("store") or {}).get("by_changeset") or {}).get(item["csid"])
        if not info:
            continue
        try:
            changed |= finalize_changeset(settings, selected, link["id"], item["csid"], row["gen"], info["ids"], info.get("snapshot"))
        except (RuntimeError, LockBusy):
            return changed  # busy: the next call settles it
    return changed


# ---- the publish job ---------------------------------------------------------------------------------------------

def run_publish_job(settings: dict, selected: dict, options: dict, engine=None, timeout_s: int = 600, progress=None) -> dict:
    """The worker of a publish job (`overlayjobs` kind `publish`): wait for the changeset's result, and lead the queue whenever
    the lock is free. Raises ViewError for a conflict or a failed candidate (the records stay pending in the view)."""
    csid, lineage_id = options["csid"], options["lineage"]
    engine = engine or hydra.Engine(settings)
    deadline = time.monotonic() + float(settings.get("publish_wait_s", PUBLISH_WAIT_S))
    while True:
        result = read_done(settings, lineage_id, csid)
        if result is None:
            led = drain(settings, lineage_id, engine, stop_after=csid, timeout_s=timeout_s)
            result = read_done(settings, lineage_id, csid)
            if result is None and led["failure"] and not led["failure"].get("counted") and led["failure"]["error"] != "commit_busy":
                failure = led["failure"]
                raise ViewError(failure["error"], failure["message"], csid=csid,
                                retained="the changeset stays queued and its records stay pending; this job ends, and no job drives the "
                                         "changeset now: it is published when any later publish on this lineage (from any view) leads "
                                         "the queue, so publish again once the cause is gone")
        if result is not None:
            return outcome_of(result, _revision_of(settings, selected))
        info = pending_info(settings, lineage_id, csid)
        if info["state"] == "done":
            continue
        if info["state"] == "unknown":
            raise ViewError("unknown_changeset", "changeset %s is not in the queue" % csid)
        if progress:
            progress(info)
        if time.monotonic() >= deadline:
            raise ViewError("publish_wait_expired", "the changeset was not decided within publish_wait_s; it stays queued and is "
                            "published when a leader reaches it", csid=csid, **pending_info(settings, lineage_id, csid))
        time.sleep(POLL_S)


def _revision_of(settings: dict, selected: dict) -> int | None:
    try:
        return workcopy.load_store(settings, selected)["revision"]
    except (OSError, ValueError, durable.StoreCorrupt, RuntimeError):
        return None


def outcome_of(result: dict, revision: int | None = None) -> dict:
    """The result of a decided changeset as the job reports it. With REVISION (the sealing view's store revision) the conflict
    carries the exact `rebase` call that settles it."""
    outcome = result.get("outcome")
    if outcome == "conflict":
        options = {"kind": "rebase"}
        if revision is not None:
            options["expect_revision"] = revision
        options["resolve"] = {item["subject"]: "take_mine | keep" for item in result.get("conflicts", []) if item.get("subject")}
        raise ViewError("publish_conflict", "the master holds other values where this changeset rests on older ones; nothing was "
                        "published and the records stay pending in the view", csid=result["csid"], conflicts=result.get("conflicts", []),
                        next={"tool": "ghidra_query", "action": "type_edit", "options": options},
                        suggest="rebase this view: it lists each conflict, and resolve decides it (take_mine re-anchors your record to "
                                "the master's value, keep drops it); then publish again")
    if outcome in ("candidate_failed", "corrupt_changeset"):
        raise ViewError(outcome, "the changeset was not published; its records stay pending in the view", csid=result["csid"],
                        failure=result.get("failure"), candidates=result.get("candidates"))
    return {"ok": True, "generation": result.get("generation"),
            **{key: result.get(key) for key in ("csid", "outcome", "gpr", "record_outcomes", "base_generation", "seq", "build_ms",
                                                "manifestSha256", "converged", "in_master", "unverified") if result.get(key) is not None}}


# ---- per-agent views: identity and the view records of 4.10 (Y5) -----------------------------------------------------
#
# The view of a call is (lineage, agent id). The agent id is `options.as`, else the process default
# `<MCP clientInfo name>@<boot id>` (D59); `HYDRALYSIS_AGENT_ID`, read when the server starts, replaces the default with an id
# that survives a restart. A process id is never part of an id. The view's store is keyed by the view NAME, a plain name
# derived from the id (`view_name`), so every job, lock and file that already carries a view name works unchanged.
#
# `views/<view name>.json` in the lineage folder says who holds the view: the agent id, its kind, the agent's name, the boot
# id, the pid with its start time, a lease refreshed by the holder's calls, the base generation and the state. A holder is
# live while its lease holds and its process exists; a view with no live holder is `orphaned`, and the `adoptable` list of
# a new process names the orphans of the same agent name that still have pending records.

BOOT_ID = secrets.token_hex(8)       # 16 random hex digits, new at every start of this server process (D59, revision 8)
RESERVED_VIEWS = ("shared", "master")  # `shared` is the collaboration view (named explicitly); `master` labels reads of the sealed master
LEASE_S = 600                        # `viewLeaseS`: a holder that makes no call for this long no longer owns the view
LEASE_REFRESH_S = 60                 # the lease is rewritten when this much of it is gone, not on every call
RECORD_FORMAT = 1
RECORD_LOCK_S = 10
_AGENT_MAX = 128
_STARTED_MS: list[int] = []


def process_started_ms() -> int:
    if not _STARTED_MS:
        from hydralysis.preparation import process_start_ms
        _STARTED_MS.append(process_start_ms(os.getpid()))
    return _STARTED_MS[0]


def agent_name() -> str:
    """The MCP client's name (`clientInfo.name`, set at `initialize`), `cli` outside a server."""
    return hydra.identity()["harness"]


def clean_agent_id(value, what: str = "options.as") -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _AGENT_MAX or any(ord(char) < 32 for char in value):
        raise ValueError("%s must be a string of 1..%d printable characters" % (what, _AGENT_MAX))
    return value.strip()


def default_agent_id() -> tuple[str, str]:
    """(id, kind) of a call that carries no `as`: `HYDRALYSIS_AGENT_ID` (stable across restarts), else `<client name>@<boot id>`."""
    from hydralysis import compat
    fixed = compat.env("AGENT_ID")
    if fixed:
        return clean_agent_id(fixed, "HYDRALYSIS_AGENT_ID"), "stable"
    return "%s@%s" % (agent_name(), BOOT_ID), "default"


def view_name(agent_id: str) -> str:
    """The name of the view of AGENT_ID: the id itself when it is already a view name, else a slug with a short digest
    (`claude-code@1f2e...` becomes `claude-code.at.1f2e....<digest>`), so two different ids never share a name.
    The name is also the file name `views/<name>.json`, and Windows file names ignore case: an id that has an upper-case letter
    always gets the lower-cased slug plus the digest of its exact spelling, so `Alice` and `alice` never share a file."""
    if _VIEW.fullmatch(agent_id) and agent_id not in RESERVED_VIEWS and agent_id == agent_id.lower():
        return agent_id
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", agent_id.replace("@", ".at.")).strip("-._")[:48].lower() or "agent"
    return "%s.%s" % (slug, hashlib.sha256(agent_id.encode("utf-8")).hexdigest()[:10])


def identify(options: dict) -> dict:
    """Who a call is. Pops `as` from OPTIONS. `{agent, kind, name, shared}`; `shared` is True for the collaboration view."""
    given = options.pop("as", None)
    if given is None:
        agent, kind = default_agent_id()
    else:
        agent, kind = clean_agent_id(given), "explicit"
    if agent == "shared":
        return {"agent": agent, "kind": kind, "name": "shared", "shared": True}
    if agent == "master":
        raise ValueError("options.as 'master' is reserved: it labels reads of the sealed master")
    return {"agent": agent, "kind": kind, "name": view_name(agent), "shared": False}


def views_dir(settings: dict, lineage_id: str) -> Path:
    return lineage.lineage_dir(settings, lineage_id) / "views"


def record_path(settings: dict, lineage_id: str, name: str) -> Path:
    if not _VIEW.fullmatch(name or ""):
        raise ValueError("invalid view name")
    return views_dir(settings, lineage_id) / (name + ".json")


def _record_lock(settings: dict, lineage_id: str, name: str):
    return locked(views_dir(settings, lineage_id) / (name + ".lock"), RECORD_LOCK_S, "view record")


def read_record(settings: dict, lineage_id: str, name: str) -> dict | None:
    """The view's record, or None when there is none or it cannot be read (a record is metadata: the store is the truth)."""
    try:
        return durable.read_sealed(record_path(settings, lineage_id, name), default=None, max_bytes=65536)
    except (durable.StoreCorrupt, OSError, ValueError):
        return None


def list_records(settings: dict, lineage_id: str) -> list[dict]:
    folder = views_dir(settings, lineage_id)
    if not folder.is_dir():
        return []
    rows = []
    for path in sorted(folder.glob("*.json")):
        record = read_record(settings, lineage_id, path.stem)
        if record and record.get("view") == path.stem:
            rows.append(record)
    return rows


def _holder_live(holder: dict, now: float) -> bool:
    from hydralysis import proc
    if float(holder.get("lease_until", 0)) < now:
        return False
    try:
        return proc.identity(int(holder.get("pid", 0)), int(holder.get("pid_started_ms", 0)))
    except (OSError, ValueError):
        return False


def live_holders(record: dict, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    return {boot: holder for boot, holder in (record.get("holders") or {}).items() if _holder_live(holder, now)}


def holder_state(record: dict, now: float | None = None) -> str:
    """`mine` (this process holds it), `live` (another process does) or `orphaned` (no holder is alive)."""
    holders = live_holders(record, now)
    if BOOT_ID in holders:
        return "mine"
    return "live" if holders else "orphaned"


def claim(settings: dict, selected: dict, who: dict, lineage_id: str, lease_s: float = LEASE_S, create: bool = True) -> dict | None:
    """Take (create, refresh or adopt) the record of the view WHO names, under the record's lock.

    A process default id (`kind` default) belongs to the process that made it: another process that names it with `as`
    while a holder is live is refused with `view_in_use` (it may adopt once the holder's lease ended or its process is
    gone). Explicit and stable ids are shared by every caller that presents them (D59); the record keeps every live holder.
    With CREATE False a missing record is not made."""
    name = who["name"]
    path = record_path(settings, lineage_id, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    with _record_lock(settings, lineage_id, name):
        record = read_record(settings, lineage_id, name)
        if record is None and not create:
            return None
        holders = {}
        if record:
            holders = {boot: item for boot, item in (record.get("holders") or {}).items() if _holder_live(item, now)}
            others = [boot for boot in holders if boot != BOOT_ID]
            if others and record.get("id_kind") == "default" and who["kind"] != "default":
                owner = holders[others[0]]
                raise ViewError("view_in_use", "view %s is held by a live process of the same agent (%s, pid %s); it can be "
                                "adopted when its lease ends or its process exits" % (who["agent"], owner.get("agent_name"), owner.get("pid")),
                                view=name, agent=who["agent"],
                                owner={"boot_id": others[0], "pid": owner.get("pid"), "agent_name": owner.get("agent_name"),
                                       "lease_until": owner.get("lease_until")})
        mine = holders.get(BOOT_ID)
        if mine and record and mine["lease_until"] - now > lease_s - LEASE_REFRESH_S:
            return record
        holders[BOOT_ID] = {"pid": os.getpid(), "pid_started_ms": process_started_ms(), "lease_until": now + lease_s,
                            "agent_name": agent_name()}
        adopted = None
        if record and record.get("boot_id") != BOOT_ID and BOOT_ID not in (record.get("holders") or {}):
            adopted = {"boot_id": record.get("boot_id"), "pid": record.get("pid"), "agent_name": record.get("agent_name"), "at": now}
        previous = (record or {}).get("adopted_from")
        body = {"format": RECORD_FORMAT, "view": name, "agent": who["agent"], "id_kind": (record or {}).get("id_kind") or who["kind"],
                "agent_name": agent_name(), "boot_id": BOOT_ID, "pid": os.getpid(), "pid_started_ms": process_started_ms(),
                "lease_until": now + lease_s, "holders": holders, "key": selected["key"], "target": selected["name"],
                "base": (record or {}).get("base") or workcopy.lineage_binding(selected), "state": "open",
                "created": (record or {}).get("created", now), "last_seen": now,
                **({"adopted_from": adopted or previous} if (adopted or previous) else {})}
        durable.write_sealed(path, body, max_bytes=65536)
        return body


def mark_state(settings: dict, lineage_id: str, name: str, state: str, **fields) -> None:
    """Record that the view's fork is `evicted` (closed, folder kept), `deleted` or `open` again. Best effort."""
    try:
        with _record_lock(settings, lineage_id, name):
            record = read_record(settings, lineage_id, name)
            if record:
                durable.write_sealed(record_path(settings, lineage_id, name), {**record, "state": state, **fields},
                                     max_bytes=65536)
    except (OSError, LockBusy, durable.StoreCorrupt, ValueError):
        pass


def describe(settings: dict, template: dict, record: dict, now: float | None = None) -> dict:
    """One row of `status show=views`: the record, its holder state and what the store holds for it."""
    now = time.time() if now is None else now
    pending, base = None, record.get("base")
    try:
        store = workcopy.load_store(settings, {**template, "key": record["key"], "view": record["view"]})
        pending, base = len(workcopy.pending_of(store)), store.get("base")
    except (ValueError, OSError, durable.StoreCorrupt):
        pass
    return {"view": record["view"], "agent": record["agent"], "id_kind": record.get("id_kind"), "agent_name": record.get("agent_name"),
            "state": holder_state(record, now), "fork": record.get("state"), "pending": pending, "base": base,
            "boot_id": record.get("boot_id"), "pid": record.get("pid"), "lease_until": record.get("lease_until"),
            "idle_s": round(now - record.get("last_seen", now), 1),
            **({"adopted_from": record["adopted_from"]} if record.get("adopted_from") else {})}


def adoptable(settings: dict, template: dict, lineage_id: str, name: str | None = None) -> list[dict]:
    """The orphaned views of this lineage with the same agent name that still hold pending records (4.10 b)."""
    name = agent_name() if name is None else name
    found = []
    for record in list_records(settings, lineage_id):
        if record.get("agent_name") != name or holder_state(record) != "orphaned":
            continue
        row = describe(settings, template, record)
        if row["pending"]:
            found.append({"agent": row["agent"], "view": row["view"], "pending": row["pending"],
                          "orphaned_since": record.get("lease_until"), "use": {"options": {"as": row["agent"]}}})
    return found


def views_status(settings: dict, template: dict, lineage_id: str | None, me: dict | None = None) -> dict:
    """`status show=views`: every view of the lineage with its holder state, the adoptable orphans and this process's identity."""
    default_id, kind = default_agent_id()
    out = {"boot_id": BOOT_ID, "agent_name": agent_name(), "default_agent": default_id, "default_kind": kind, "pid": os.getpid(),
           "lineage": lineage_id, "views": [], "adoptable": []}
    if me:
        out["you"] = {"agent": me["agent"], "view": me["name"]}
    if lineage_id:
        out["views"] = [describe(settings, template, record) for record in list_records(settings, lineage_id)]
        out["adoptable"] = adoptable(settings, template, lineage_id)
    return out


# ---- the publish job's own worker ---------------------------------------------------------------------------------
# A publish job is an overlay job record (`overlay-jobs/<id>/job.json`, read by `overlayjobs.status` and the `job` tool like
# any other) whose worker process is `python -m hydralysis.views <job.json>`. `overlayjobs.py` belongs to Y0a and Y2 (8.1) and
# is left as it was: this module starts and runs its own worker rather than adding a job kind there.

def start_job(settings: dict, target: str, options: dict, view: str = "") -> dict:
    """Start the worker of a publish job for the sealed changeset in OPTIONS ({csid, lineage}). Returns the job as
    `overlayjobs.status` shows it, plus `owner_token`."""
    import sys
    from hydralysis import jobowner, overlayjobs, proc
    from hydralysis.backends import read_json, write_json
    from hydralysis.locks import locked
    from hydralysis.paths import root_path
    root = root_path(settings)
    with locked(root / "overlay-jobs" / ".start.lock", what="overlay jobs"):
        view = "" if view == "shared" else view
        job_id = "overlay-" + uuid.uuid4().hex[:12]
        path = overlayjobs.job_path(settings, job_id)
        path.parent.mkdir(parents=True)
        record = {"id": job_id, "kind": "publish", "target": target, "view": view, "address": "", "options": dict(options),
                  "state": "queued", "created_at": time.time(), "by": hydra.identity()}
        token = jobowner.issue(record)
        write_json(path, record)
        keys = ("root", "hydra_dir", "hydra_client", "java_home", "hydra_idle_s", "hydra_keep_warm_s", "hydra_max_heap",
                "hydra_allow_unpinned", "hydra", "fork_mode", "fork_max_copy_mb", "forbidden_drives", "targets", "expected_agents",
                "publish_wait_s", "publish_batch_max", "tmp_dir", "backup_roots")
        write_json(path.parent / "settings.json", {key: settings[key] for key in keys if key in settings})
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent), HYDRALYSIS_HARNESS=hydra.identity()["harness"])
        # No log file: a raw file write outside `durable` is a site `test_durable` counts. What the worker has to say goes into the
        # job record (`error`), which `overlayjobs.status` shows; `main` below puts any uncaught exception there too.
        child = proc.popen([sys.executable, "-m", "hydralysis.views", str(path)], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, **({} if os.name == "nt" else {"start_new_session": True}))
        with locked(path.with_suffix(".lock"), what="overlay job"):
            current = read_json(path)
            if current.get("state") == "queued" and not current.get("worker_pid"):
                current.update(worker_pid=child.pid, worker_started_ms=overlayjobs.proc_start(child.pid), updated_at=time.time())
                write_json(path, current)
        return {**overlayjobs.status(settings, job_id), "owner_token": token}


def run_job(path: Path, engine=None, watch: bool = True) -> None:
    """The worker body of a publish job: lead or follow until the changeset is decided, and record the result in the job."""
    import threading
    from hydralysis import overlayjobs
    from hydralysis.backends import read_json
    record = read_json(path)
    settings = read_json(path.parent / "settings.json")
    cancel_file = path.parent / "cancel.request"

    def watcher():
        while True:
            if cancel_file.exists():
                overlayjobs._update(path, state="cancelled", finished_at=time.time(),
                                    error="cancelled; the changeset stays queued and is published when a leader reaches it")
                os._exit(3)
            time.sleep(0.5)

    if watch:
        threading.Thread(target=watcher, daemon=True).start()
    overlayjobs._update(path, state="running", worker_pid=os.getpid(), worker_started_ms=overlayjobs.proc_start(os.getpid()),
                        started_at=time.time())
    try:
        selected = workcopy.with_view(targets.resolve(settings, record["target"]), record.get("view", ""))
        result = run_publish_job(settings, selected, dict(record["options"]), engine, overlayjobs.TIMEOUT_S,
                                 progress=lambda info: overlayjobs._update(path, publish_pending=info))
    except ViewError as error:
        overlayjobs._update(path, state="failed", error="%s: %s" % (error.code, error), error_payload=error.payload(),
                            finished_at=time.time())
        return
    except (commits.CommitError, lineage.LineageError) as error:
        overlayjobs._update(path, state="failed", error="%s: %s" % (error.code, error), error_payload=error.payload(),
                            finished_at=time.time())
        return
    except Exception as exc:
        overlayjobs._update(path, state="failed", error="%s: %s" % (type(exc).__name__, exc), finished_at=time.time())
        return
    overlayjobs._update(path, state="done", result=result, finished_at=time.time())


def main(argv: list[str]) -> None:
    from hydralysis import overlayjobs
    path = Path(argv[0]).resolve()
    try:
        run_job(path)
    except BaseException as exc:  # run_job records its own failures; this is what happens before or around it
        try:
            overlayjobs._update(path, state="failed", error="%s: %s" % (type(exc).__name__, exc), finished_at=time.time())
        except Exception:
            pass
        raise


if __name__ == "__main__":
    import sys
    main(sys.argv[1:])
