"""Header-magic check and quarantine of Hydralysis-owned forks, before the engine opens them (PROTOCOL-3.md D42, D44, K2).

A Ghidra project keeps each database in `<name>.rep/idata/<xx>/~<id>.db/` as versioned files `db.<N>.gbf`. A save that
was killed between the final-named rename and the header write leaves a full-size newest version whose first eight
bytes are zero (measurement C: 12 of 363 kills). Such a file cannot be opened; the version before it can. hydra.4's
engine repairs this on open (E8); on hydra.2/3 this module does the same for the forks Hydralysis owns.

What it will and will not do:

* `scan` only reads eight bytes per version file. It opens no program and starts no engine, so it is safe on the
  master, on a published generation and on a backup (K1: those are never written, not even to check).
* `quarantine` writes, and therefore refuses anything that is not a writable disposable fork of ours: a folder with a
  `SEALED.json` marker, a sidecar with `state:"complete"`, or one that the caller did not declare disposable. It never
  deletes: the damaged version is moved to `<name>.quarantine/`, beside the `.rep` folder, with a record of the move,
  and the previous version is the newest again.
* `check_fork` is the call the sync makes before it opens a view's fork: scan, repair if the fork is ours and
  disposable, otherwise raise `corrupt_newest` with the repair hint.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from hydralysis import durable

GBF_MAGIC = bytes.fromhex("2f30312c34292c2a")
_VERSION = re.compile(r"db\.(\d+)\.gbf")


class CorruptNewest(ValueError):
    """The newest version of a database has no valid header and nothing may repair it here (`corrupt_newest`)."""

    def __init__(self, message: str, report: dict):
        super().__init__(message)
        self.report = report

    def payload(self) -> dict:
        return {"error": "corrupt_newest", "message": str(self), **self.report,
                "suggest": "the fork is a cache: delete it and the next query rebuilds it from the store; a sealed or "
                           "published project is never repaired in place, restore it from a backup"}


def project_folder(path) -> Path:
    """The folder of the project that PATH names (its .gpr, its .rep or the folder itself)."""
    path = Path(path)
    if path.suffix == ".gpr":
        return path.parent
    if path.suffix == ".rep":
        return path.parent
    return path


def _reps(folder: Path) -> list[Path]:
    return sorted(item for item in folder.glob("*.rep") if item.is_dir())


def _databases(folder: Path) -> list[Path]:
    found: list[Path] = []
    for rep in _reps(folder):
        found.extend(sorted(rep.glob("idata/*/~*.db")))
        found.extend(sorted(rep.glob("user/*/~*.db")))
    return [item for item in found if item.is_dir()]


def _versions(database: Path) -> list[tuple[int, Path]]:
    versions = []
    for item in database.iterdir():
        match = _VERSION.fullmatch(item.name)
        if match and item.is_file():
            versions.append((int(match.group(1)), item))
    return sorted(versions)


def _valid_header(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(GBF_MAGIC)) == GBF_MAGIC
    except OSError:
        return False


def scan(path) -> dict:
    """Read-only: per database, its versions and whether each has the magic; `newest_invalid` lists the damaged ones.

    A database with no version file at all is reported under `empty`, never as damaged (a project being created)."""
    folder = project_folder(path)
    report: dict = {"project": str(folder), "databases": 0, "versions": 0, "newest_invalid": [], "empty": [],
                    "usable": True}
    for database in _databases(folder):
        report["databases"] += 1
        versions = _versions(database)
        report["versions"] += len(versions)
        if not versions:
            report["empty"].append(str(database))
            continue
        number, newest = versions[-1]
        if not _valid_header(newest):
            fallback = next((item for item in reversed(versions[:-1]) if _valid_header(item[1])), None)
            report["newest_invalid"].append({"database": str(database), "file": newest.name, "version": number,
                                             "previous_valid": fallback[1].name if fallback else None})
            if fallback is None:
                report["usable"] = False
    report["ok"] = not report["newest_invalid"]
    return report


def is_sealed(path) -> bool:
    """Whether the folder carries a seal Hydralysis or the engine wrote (`SEALED.json`, or a sidecar `state:"complete"`)."""
    folder = project_folder(path)
    if (folder / "SEALED.json").is_file():
        return True
    for sidecar in folder.glob("*.fork.json"):
        try:
            record = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(record, dict) and record.get("state") == "complete":
            return True
    return False


def quarantine(path, disposable: bool = False) -> dict:
    """Move every invalid newest version of a disposable, unsealed fork aside; the previous version is newest again.

    Nothing is deleted. Returns the scan taken before the move plus `moved` (one record per file) and the scan after.
    Raises CorruptNewest when the project is not ours to repair, or when a database has no valid version left."""
    before = scan(path)
    if before["ok"]:
        return {**before, "moved": [], "after": before}
    folder = project_folder(path)
    if not disposable or is_sealed(folder):
        raise CorruptNewest("%d database(s) of %s have a newest version without a valid header; this project is %s, so "
                            "it was not touched" % (len(before["newest_invalid"]), folder,
                                                    "sealed or published" if is_sealed(folder) else "not a disposable fork"),
                            before)
    if not before["usable"]:
        raise CorruptNewest("a database of %s has no version with a valid header; nothing was moved" % folder, before)
    target = folder / (folder.name + ".quarantine")
    moved = []
    for item in before["newest_invalid"]:
        source = Path(item["database"]) / item["file"]
        destination = target / Path(item["database"]).name / item["file"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            destination = destination.with_name("%s.%d" % (destination.name, int(time.time() * 1000)))
        durable.replace_file(source, destination)  # same volume: a write-through rename, nothing is deleted
        moved.append({"file": item["file"], "database": item["database"], "to": str(destination),
                      "restored": item["previous_valid"]})
    durable.atomic_write(target / ("quarantine-%d.json" % int(time.time() * 1000)),
                         json.dumps({"at": time.time(), "moved": moved}, indent=2).encode("utf-8"))
    after = scan(path)
    return {**before, "moved": moved, "after": after}


def check_fork(path, disposable: bool = True) -> dict:
    """Before a fork is opened: its report; a damaged newest version of a disposable fork is quarantined first."""
    found = scan(path)
    if found["ok"]:
        return {"ok": True, "moved": []}
    repaired = quarantine(path, disposable=disposable)
    return {"ok": repaired["after"]["ok"], "moved": repaired["moved"]}


def newest_valid(path) -> bool:
    """A cheap yes/no for a project that must not be written (a base, a generation, a backup): every newest header is valid."""
    return scan(path)["ok"]

# --- HYDRALYSIS_IMPL=rust ----------------------------------------------------------------------------------------
# The Rust twin (rust/crates/hy-engine, bound in native/src/hyapi.rs) answers what it models exactly; see _rust_engine.py.
import os as _os  # noqa: E402
if _os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() == "rust":
    from hydralysis import _rust_engine
    _rust_engine.install()
