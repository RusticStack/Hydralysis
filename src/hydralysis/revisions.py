"""Subject-aware optimistic concurrency for the overlay store.

Every edit and revert moves the store's revision by one and appends one journal
entry: {revision, op, subjects, by, at}. A subject names what a change touches
("address:0x140001000", "type:/game/Thing", "structure:functions", or "*" for a
change that may touch anything, such as a type import). An editor that read an
older revision is rebased onto the current one only when the journal proves that
no edit after that revision touched its subjects; otherwise it gets a conflict
that names what changed and who changed it.

Granularity is the address or the type path. Dependencies between subjects (an
`apply` of a structure that another editor has since redefined, a function body
that moves across a neighbour) are not tracked, except that two function
structure edits (create/body/delete) always overlap.
"""

from __future__ import annotations

WILDCARD = "*"
MAX_JOURNAL = 1024
MAX_SUBJECTS = 256
_STRUCTURE_KINDS = ("function_create", "function_body", "function_delete")
_BULK_KINDS = ("import_types", "import_archive")


def _address(text: str) -> str:
    return "address:" + hex(int(str(text).removeprefix("0x"), 16))


def subjects_of(address: str, options: dict) -> list[str]:
    """What one edit record (address plus options) touches, as sorted subject strings."""
    found: set[str] = set()
    kind = options.get("kind")
    if kind in _BULK_KINDS:
        found.add(WILDCARD)
    elif kind == "batch":
        for child in options.get("edits", []):
            found.update(subjects_of(child.get("address", ""), child.get("options", {})))
    else:
        if kind == "struct" and options.get("path"):
            found.add("type:" + options["path"])
        if address:
            found.add(_address(address))
        if kind in _STRUCTURE_KINDS:
            found.add("structure:functions")
    if not found or len(found) > MAX_SUBJECTS:
        return [WILDCARD]
    return sorted(found)


def journal_entry(revision: int, op: str, subjects: list[str], by: dict | None, at: float) -> dict:
    return {"revision": revision, "op": op, "subjects": subjects if 0 < len(subjects) <= MAX_SUBJECTS else [WILDCARD],
            "by": by, "at": at}


def append(journal: list[dict], entry: dict) -> list[dict]:
    return (list(journal) + [entry])[-MAX_JOURNAL:]


def clean_journal(raw) -> list[dict]:
    """A stored journal as entries; anything malformed is dropped, which only makes history incomplete."""
    kept = []
    for item in raw if isinstance(raw, list) else []:
        if (isinstance(item, dict) and isinstance(item.get("revision"), int) and not isinstance(item["revision"], bool)
                and isinstance(item.get("subjects"), list) and all(isinstance(s, str) for s in item["subjects"])):
            kept.append({"revision": item["revision"], "op": str(item.get("op", "")), "subjects": item["subjects"],
                         "by": item.get("by") if isinstance(item.get("by"), dict) else None, "at": item.get("at")})
    return kept[-MAX_JOURNAL:]


def overlaps(left, right) -> set[str]:
    """Subjects of `left` that `right` also touches; a wildcard on either side overlaps everything."""
    left, right = set(left), set(right)
    if WILDCARD in left:
        return right or {WILDCARD}
    if WILDCARD in right:
        return left
    return left & right


def reconcile(expected: int | None, revision: int, journal: list[dict], subjects: list[str]) -> dict:
    """Decide what a stale (or current) expected revision means for an edit touching `subjects`.

    Returns {"outcome": "current"|"rebased"|"conflict", "current_revision", "view_revision",
    "latest_editor": {"by", "at"}|None, "subjects_changed_since": [...], "history_complete": bool,
    "overlapping": [...]}. `expected` of None is the caller's error to report; here it is a conflict.
    """
    later = [entry for entry in journal if expected is not None and entry["revision"] > expected]
    latest = max(journal, key=lambda entry: entry["revision"], default=None)
    result = {"current_revision": revision, "view_revision": revision,
              "latest_editor": {"by": latest["by"], "at": latest["at"]} if latest else None,
              "subjects_changed_since": [], "history_complete": True, "overlapping": []}
    if expected is not None and expected == revision:
        return {**result, "outcome": "current"}
    if expected is None or expected > revision:
        return {**result, "outcome": "conflict", "history_complete": False}
    have = {entry["revision"] for entry in later}
    result["history_complete"] = all(number in have for number in range(expected + 1, revision + 1))
    changed: set[str] = set()
    for entry in later:
        changed.update(entry["subjects"])
    result["subjects_changed_since"] = sorted(changed)
    if later:
        last = max(later, key=lambda entry: entry["revision"])
        result["latest_editor"] = {"by": last["by"], "at": last["at"]}
    result["overlapping"] = sorted(overlaps(subjects, changed)) if changed else []
    if result["history_complete"] and not result["overlapping"]:
        return {**result, "outcome": "rebased"}
    return {**result, "outcome": "conflict"}


def conflict_payload(expected: int | None, decision: dict, subjects: list[str]) -> dict:
    """The error body an agent receives: enough to decide whether to re-read or simply retry."""
    if expected is None or expected > decision["current_revision"]:
        reason = "expect_revision is not a revision of this view's store"
    elif not decision["history_complete"]:
        reason = "history after your revision is incomplete; the edit cannot be proven independent"
    else:
        reason = "an edit after your revision touched the same subject"
    return {"conflict": "overlay revision changed", "reason": reason, "expected_revision": expected,
            "current_revision": decision["current_revision"], "view_revision": decision["view_revision"],
            "latest_editor": decision["latest_editor"], "last_edit_by": (decision["latest_editor"] or {}).get("by"),
            "subjects_changed_since": decision["subjects_changed_since"], "history_complete": decision["history_complete"],
            "edit_subjects": subjects, "overlapping": decision["overlapping"],
            "suggest": "re-read the affected subjects (ghidra_query status shows the revision), then edit again with expect_revision=%d"
                       % decision["current_revision"]}


def missing_payload(revision: int, view: str, what: str) -> dict:
    return {"error": "expect_revision_required", "view": view, "current_revision": revision, "view_revision": revision,
            "message": "%s requires expect_revision on every view, including the shared one" % what,
            "suggest": "retry with expect_revision=%d (the view's current revision), or read it with ghidra_query status" % revision}
