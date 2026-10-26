"""Named analysis targets: a saved project, one program in it, and its build hash.

A target is registered by prepare (a fresh analysis) or adopt (an analysed
project that already exists). Adopting opens the project in place through the
engine's read-only view: nothing is copied, imported or written, and the
program's recorded SHA-256 must match the expected build before it is named.
Older configuration entries ({dir, name, program}) keep working.
"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path

from rusticre.backends import read_json, sha256, write_json
from rusticre.locks import locked
from rusticre.paths import root_path, validate_project_path

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA = re.compile(r"[0-9a-f]{64}")


def registry_path(settings: dict) -> Path:
    return root_path(settings) / "targets.json"


def registry(settings: dict) -> dict:
    return read_json(registry_path(settings)).get("targets", {})


def configured(settings: dict) -> dict:
    """Registered targets, overridden by explicit configuration."""
    return {**registry(settings), **(settings.get("targets") or settings.get("projects") or {})}


def register(settings: dict, names: list[str], record: dict) -> None:
    root = root_path(settings)
    with locked(root / ".targets.lock", what="target registry"):
        data = read_json(registry_path(settings)) or {"version": 2, "targets": {}}
        for name in names:
            if not _NAME.fullmatch(name):
                raise ValueError("target must be a simple 1..64 character name")
            existing = data["targets"].get(name)
            if existing and existing.get("sha256") and existing.get("sha256") != record["sha256"]:
                raise ValueError("target %s already names another build (%s); choose a new target"
                                 % (name, existing["sha256"][:12]))
        for name in names:
            data["targets"][name] = record
        data["version"] = 2
        write_json(registry_path(settings), data)


def exe_sha256(settings: dict, exe: str | Path) -> str:
    """Hash a build once per (path, size, mtime); queries do not re-read 66 MB each time."""
    path = Path(exe).expanduser().resolve()
    stat = path.stat()
    key = "%s|%d|%d" % (str(path).lower(), stat.st_size, stat.st_mtime_ns)
    cache_path = root_path(settings) / "hash-cache.json"
    cache = read_json(cache_path)
    if cache.get(key):
        return cache[key]
    digest = sha256(path)
    after = path.stat()
    if (after.st_size, after.st_mtime_ns) != (stat.st_size, stat.st_mtime_ns):
        raise ValueError("binary changed while hashing; use a stable build: %s" % path)
    try:
        with locked(cache_path.with_suffix(".lock"), what="hash cache"):
            cache = read_json(cache_path)
            cache[key] = digest
            if len(cache) > 512:
                cache = dict(list(cache.items())[-512:])
            write_json(cache_path, cache)
    except ValueError:
        pass
    return digest


def gpr_of(item: dict) -> str:
    if item.get("gpr"):
        return str(item["gpr"])
    if item.get("dir") and item.get("name"):
        return str(Path(item["dir"]) / (item["name"] + ".gpr"))
    if item.get("dir"):
        return str(item["dir"])
    raise ValueError("target has no project: set gpr (the .gpr, its folder or a parent)")


def resolve(settings: dict, name: str) -> dict:
    targets = configured(settings)
    if name not in targets:
        known = ", ".join(sorted(targets)) or "(none)"
        raise ValueError("no analysis target %r; known: %s. Register one with prepare action=adopt (an analysed "
                         "project) or prepare action=start (a fresh executable)" % (name, known))
    item = targets[name]
    expected = str(item.get("sha256") or "").lower()
    if item.get("exe"):
        actual = exe_sha256(settings, item["exe"])
        if expected and expected != actual:
            raise ValueError("target %s: the configured sha256 does not match %s; verify the build" % (name, item["exe"]))
        expected = actual
    if not _SHA.fullmatch(expected):
        raise ValueError("target %s needs exe or a full sha256 to verify the analysed program" % name)
    program = str(item.get("program") or "")
    if not program:
        raise ValueError("target %s has no program" % name)
    gpr = gpr_of(item)
    validate_project_path(gpr)
    return {"name": name, "gpr": gpr, "program": program, "sha256": expected, "exe": item.get("exe", ""),
            "key": target_key(gpr, program), "scripts": item.get("scripts", "")}


def target_key(gpr: str, program: str) -> str:
    """A stable identity for one program of one project, for overlays and working copies."""
    normal = str(Path(gpr).expanduser().resolve()).lower()
    return hashlib.sha256((normal + "\n" + program.lstrip("/")).encode()).hexdigest()[:16]


def default_name(stem: str, digest: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", stem).strip("-._")[:45] + "-" + digest[:12]


def adopt(settings: dict, engine, path: str, exe: str = "", expected: str = "", program: str = "",
          target: str = "") -> dict:
    """Register an analysed project without importing, copying or writing it."""
    if not path:
        raise ValueError("adopt requires path: the .gpr, its folder, or a parent folder with one project")
    source = Path(path).expanduser()
    if not source.exists():
        raise ValueError("adopt path does not exist: %s" % source)
    validate_project_path(source)
    expected = expected.lower()
    if expected and not _SHA.fullmatch(expected):
        raise ValueError("sha256 must be the full 64-hex build hash")
    if exe:
        actual = exe_sha256(settings, exe)
        if expected and actual != expected:
            raise ValueError("sha256 does not match exe %s (%s)" % (exe, actual))
        expected = actual
    opened = engine.call("open_project", path=str(source.resolve()))
    listing = engine.call("list", project=opened["id"], programsOnly=True, limit=200,
                          **({"sha256": expected} if expected else {}))
    programs = [entry for entry in listing.get("entries", []) if entry.get("program")]
    if program:
        programs = [entry for entry in programs if entry.get("path") in (program, "/" + program.lstrip("/"))
                    or entry.get("name") == program]
    candidates = [{"program": entry["path"], "sha256": entry.get("sha256"), "format": entry.get("format"),
                   "language": entry.get("language")} for entry in programs]
    if not expected:
        return {"kind": "adopt", "state": "needs_build_hash", "registered": False, "project": opened["gpr"],
                "candidates": candidates,
                "reason": "pass exe (the executable you own) or its sha256; adopt names a target only after the "
                          "program's recorded hash matches the build"}
    if len(programs) != 1:
        return {"kind": "adopt", "state": "no_match" if not programs else "ambiguous", "registered": False,
                "project": opened["gpr"], "sha256": expected, "candidates": candidates,
                "reason": "no program with this SHA-256 in the project" if not programs
                else "several programs match; pass program"}
    chosen = programs[0]
    info = engine.call("open_program", path=chosen["path"], project=opened["id"])
    if str(info.get("sha256", "")).lower() != expected:
        raise ValueError("opened program reports SHA-256 %s, not %s; nothing registered" % (info.get("sha256"), expected))
    if not info.get("analyzed"):
        raise ValueError("%s in %s is not analysed; prepare a fresh analysis instead" % (chosen["path"], opened["gpr"]))
    name = target or default_name(Path(chosen["path"]).stem, expected)
    record = {"gpr": opened["gpr"], "program": chosen["path"], "sha256": expected, "exe": str(Path(exe).resolve()) if exe else "",
              "adopted_at": time.time(), "functions": info.get("functions"), "image_base": info.get("imageBase"),
              "project_revision": opened.get("revision"), "engine": "hydra"}
    register(settings, [name], record)
    return {"kind": "adopt", "state": "registered", "registered": True, "target": name, **record,
            "copied": False, "imported": False,
            "note": "opened in place through a read-only view: no lock, no copy, no write"}
