"""Persistent-store footprint: what a run (or an intervention) changed on disk, and whether undoing it round-trips.

A footprint is a snapshot of files under chosen roots (path, size, content hash) and, on Windows, of the declared
HKEY_CURRENT_USER keys (every value: name, type, size, hash of the data; the data itself is never copied, so a secret value is
not leaked into a snapshot). ``diff`` compares two snapshots;
``classify`` separates changes the intervention caused from changes an ordinary (control) run makes anyway;
``round_trip`` checks that reverting the intervention restored the original state, and says
``did not round-trip`` with the differing paths when it did not.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

NOT_ROUND_TRIP = "did not round-trip"
MAX_REGISTRY_VALUES = 20000
_HKCU_PREFIXES = ("hkcu\\", "hkey_current_user\\", "hkcu:\\")


def registry_subkey(path: str) -> str:
    """The sub key path of a declared HKCU key; any other hive is refused (a footprint never reads machine-wide keys)."""
    text = str(path).replace("/", "\\").strip("\\")
    lowered = text.lower() + "\\"
    for prefix in _HKCU_PREFIXES:
        if lowered.startswith(prefix):
            sub = text[len(prefix) - 1:].strip("\\")
            if not sub:
                raise ValueError("a declared registry key is below HKCU, not the hive itself")
            return sub
    raise ValueError("only HKCU keys can be declared in a footprint, got %r" % path)


def snapshot_registry(keys: list[str]) -> dict[str, dict]:
    """``{reg:<key>/<value>: {size, sha256, readable, type}}`` for each declared HKCU key and everything below it.

    A key that does not exist contributes nothing (so its creation is an `added` entry and its removal a `removed` one); an empty
    existing key is recorded as ``reg:<key>/`` so that creating or deleting it is seen too."""
    import winreg
    snap: dict[str, dict] = {}
    budget = [MAX_REGISTRY_VALUES]

    def walk(sub: str) -> None:
        try:
            handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            return
        except OSError:
            snap["reg:" + sub.lower() + "\\"] = {"size": None, "sha256": None, "readable": False, "type": "key"}
            return
        with handle:
            snap["reg:" + sub.lower() + "\\"] = {"size": 0, "sha256": hashlib.sha256(b"key").hexdigest(), "readable": True, "type": "key"}
            index = 0
            while budget[0] > 0:
                try:
                    name, data, kind = winreg.EnumValue(handle, index)
                except OSError:
                    break
                index += 1
                budget[0] -= 1
                raw = data if isinstance(data, bytes) else repr(data).encode("utf-8", "replace")
                snap["reg:" + (sub + "\\" + name).lower()] = {
                    "size": len(raw), "sha256": hashlib.sha256(str(kind).encode() + b"\0" + raw).hexdigest(), "readable": True,
                    "type": kind}
            index = 0
            children = []
            while True:
                try:
                    children.append(winreg.EnumKey(handle, index))
                except OSError:
                    break
                index += 1
        for child in children:
            walk(sub + "\\" + child)

    for key in keys:
        walk(registry_subkey(key))
    if budget[0] <= 0:
        snap["reg:<truncated>"] = {"size": None, "sha256": None, "readable": False, "type": "limit"}
    return snap


def stores_of(profile, base: Path) -> tuple[list[Path], list[str]]:
    """The files (relative paths resolve under BASE) and HKCU keys a profile declares as persistent stores."""
    files, keys = [], []
    for store in profile.data.get("stores", []):
        if store["kind"] == "registry":
            keys.append(store["path"])
        else:
            path = Path(store["path"])
            files.append(path if path.is_absolute() else Path(base) / path)
    return files, keys


def _hash(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


def snapshot(roots: list[Path], ignore: tuple[str, ...] = (), registry: list[str] | tuple = ()) -> dict[str, dict]:
    """``{normalized path: {size, sha256}}``; a file that cannot be read is recorded as unreadable, not skipped. REGISTRY lists
    declared HKCU keys, snapshotted with their values and sub keys under `reg:` names."""
    snap: dict[str, dict] = {}
    if registry:
        snap.update(snapshot_registry(list(registry)))
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
