"""Persistent-store footprint: what a run (or an intervention) changed on disk, and whether undoing it round-trips.

A footprint is a snapshot of files under chosen roots (path, size, content hash). ``diff`` compares two snapshots;
``classify`` separates changes the intervention caused from changes an ordinary (control) run makes anyway;
``round_trip`` checks that reverting the intervention restored the original state, and says
``did not round-trip`` with the differing paths when it did not.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

NOT_ROUND_TRIP = "did not round-trip"


def _hash(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


def snapshot(roots: list[Path], ignore: tuple[str, ...] = ()) -> dict[str, dict]:
    """``{normalized path: {size, sha256}}``; a file that cannot be read is recorded as unreadable, not skipped."""
    snap: dict[str, dict] = {}
    for root in roots:
        root = Path(root)
        files = [root] if root.is_file() else (p for p in root.rglob("*") if p.is_file()) if root.exists() else []
        for p in files:
            key = os.path.normcase(str(p))
            if any(part in key for part in ignore):
                continue
            digest = _hash(p)
            try:
                size = p.stat().st_size
            except OSError:
                size = None
            snap[key] = {"size": size, "sha256": digest, "readable": digest is not None}
    return snap


def diff(before: dict, after: dict) -> dict:
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(k for k in set(before) & set(after) if before[k]["sha256"] != after[k]["sha256"])
    unreadable = sorted(k for k in set(before) | set(after) if not (before.get(k) or after.get(k) or {"readable": True})["readable"])
    return {"added": added, "removed": removed, "changed": changed, "unreadable": unreadable,
            "empty": not (added or removed or changed)}


def _paths(d: dict) -> set[str]:
    return set(d["added"]) | set(d["removed"]) | set(d["changed"])


def classify(intervention: dict, control: dict) -> dict:
    """Changes in the intervened run's diff that the control run did not make are attributed to the intervention.

    With no control run the answer is ``unknown``: an ordinary change cannot be told from a caused one.
    """
    if control is None:
        return {"verdict": "unknown", "reason": "no control run", "caused": [], "ordinary": []}
    ordinary = _paths(intervention) & _paths(control)
    caused = _paths(intervention) - _paths(control)
    return {"verdict": "caused" if caused else "none", "caused": sorted(caused), "ordinary": sorted(ordinary)}


def round_trip(original: dict, restored: dict, ordinary: set[str] | None = None) -> dict:
    """Whether the state after reverting equals the original, ignoring paths the control run changes anyway."""
    d = diff(original, restored)
    left = sorted(_paths(d) - (ordinary or set()))
    if left:
        return {"verdict": NOT_ROUND_TRIP, "paths": left}
    return {"verdict": "round-trips", "ignored_ordinary": sorted(_paths(d) & (ordinary or set()))}
