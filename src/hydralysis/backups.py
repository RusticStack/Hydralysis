"""Backups of a lineage's head generation, on hydra.2 and hydra.3 (PROTOCOL-3.md 4.5, 3.4, D28, D66).

The engine of those releases has no `backup` command and no fork purposes, so the client makes the backup: a fork of the
source with `writable:false` into the backup folder, then Python re-hashes every file, writes `backup.json` last (the
folder is invisible without one that verifies) and seals the copy. A block clone protects against a bad commit, not
against loss of the volume: `independent` is true only for a copy on another volume, and the listing says how many
there are. Nothing here deletes a backup unless the owner runs `options.op=remove` with `confirm:true`.

`backend action=backups options.op=list|verify|remove` is registered in `api.HANDLER_MODULES` and reaches `handle`.
"""

from __future__ import annotations

import json
import shutil
import stat
import time
from pathlib import Path

from hydralysis import durable, hydra, lineage
from hydralysis.paths import root_path

FORMAT = 1
KIND = "ghidra-session-backup"
DEFAULTS = {"backup_min_verified": 1, "backup_min_independent": 0, "backup_confirm_gb": 50, "backup_root_warn_gb": 200}
GIB = 1024 ** 3


class BackupError(ValueError):
    """A backup refusal with a stable code (confirm_large_backup, backup_failed, backup_verify_failed, ...)."""

    def __init__(self, code: str, message: str, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self), **self.detail}


# ---- policy ----------------------------------------------------------------------------------------------------

def policy(settings: dict) -> dict:
    roots = settings.get("backup_roots")
    if not roots:
        roots = [{"path": str(root_path(settings) / "backups"), "mode": "auto", "required": True}]
    clean = []
    for index, item in enumerate(roots):
        if isinstance(item, str):
            item = {"path": item}
        if not isinstance(item, dict) or not item.get("path"):
            raise ValueError("backup_roots entries need a path")
        mode = item.get("mode", "auto")
        if mode not in ("auto", "copy"):
            raise ValueError("backup_roots mode must be auto or copy")
        # The first root is the primary; a secondary root is always a full copy (a clone shares blocks with its source).
        clean.append({"path": str(item["path"]), "mode": mode if index == 0 else "copy",
                      "required": bool(item.get("required", index == 0))})
    result = {key: settings.get(key, default) for key, default in DEFAULTS.items()}
    for key in DEFAULTS:
        if isinstance(result[key], bool) or not isinstance(result[key], (int, float)) or result[key] < 0:
            raise ValueError("%s must be a non-negative number" % key)
    return {"roots": clean, **result}


def size_of(folder: Path) -> int:
    return sum(item.stat().st_size for item in Path(folder).rglob("*") if item.is_file())


def backup_id(revision: str, purpose: str, when: float | None = None) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(when if when is not None else time.time()))
    return "%s-%s-%s" % (stamp, (revision or "unknown")[:8], purpose)


def _volume(path: Path) -> int | None:
    probe = Path(path)
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        return probe.stat().st_dev
    except OSError:
        return None


def _readonly(folder: Path) -> None:
    """Best effort: backup.json and the data files are not touched after writing."""
    for item in Path(folder).rglob("*"):
        if item.is_file():
            try:
                item.chmod(item.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            except OSError:
                pass


def _writable_tree(folder: Path) -> None:
    for item in [Path(folder), *Path(folder).rglob("*")]:
        try:
            item.chmod(item.stat().st_mode | stat.S_IWUSR)
        except OSError:
            pass


# ---- the log ---------------------------------------------------------------------------------------------------

def logged(settings: dict, lineage_id: str) -> list[dict]:
    return lineage.backups_log(settings, lineage_id).scan().records


def cumulative(settings: dict, lineage_id: str, root: str) -> int:
    """Logical bytes of the lineage's verified backups under ROOT, from backups.log."""
    return sum(int(row.get("bytes") or 0) for row in logged(settings, lineage_id) if row.get("root") == root and not row.get("removed"))


def preview(settings: dict, lineage_id: str, source_gpr: str) -> dict:
    """What a backup would cost, with the cumulative figures the confirmation text must state (4.5)."""
    wanted = policy(settings)
    size = size_of(Path(source_gpr).parent)
    rows = []
    for root in wanted["roots"]:
        base = Path(root["path"])
        probe = base if base.exists() else base.parent
        try:
            free = shutil.disk_usage(probe).free
        except OSError:
            free = None
        before = cumulative(settings, lineage_id, root["path"])
        rows.append({"root": root["path"], "mode": root["mode"], "required": root["required"], "this_backup_bytes": size,
                     "cumulative_bytes_before": before, "cumulative_bytes_after": before + size, "free_bytes": free,
                     "warn": (before + size) > wanted["backup_root_warn_gb"] * GIB,
                     "note": "a block clone's logical size overstates the physical blocks it adds"
                             if root["mode"] == "auto" else "a full copy"})
    return {"bytes": size, "confirm_gb": wanted["backup_confirm_gb"], "needs_confirmation": size > wanted["backup_confirm_gb"] * GIB,
            "roots": rows}


# ---- making one ------------------------------------------------------------------------------------------------

def _fork_into(settings: dict, engine: hydra.Engine, source_gpr: str, destination: Path, mode: str) -> dict:
    """A fork of the source that holds nothing open for writing (`writable:false`: the field defaults to true)."""
    fields = {"project": source_gpr, "path": str(destination), "writable": False,
              "mode": mode if mode in ("auto", "copy") else "auto", "maxCopyMb": int(settings.get("fork_max_copy_mb", 8192))}
    forked = engine.call("fork_project", **fields)
    try:
        engine.call("close_project", project=forked["project"])
    except hydra.EngineError:
        pass
    return forked


def project_dir(folder: Path) -> Path:
    """Where the project files of a backup live: `<folder>/project` for the Python writer, the folder itself for the engine's."""
    nested = Path(folder) / "project"
    return nested if nested.is_dir() else Path(folder)


def _engine_backup(engine) -> bool:
    try:
        return "forkPurposes" in engine.capabilities()
    except Exception:  # an engine that cannot say is a hydra.2/3 engine
        return False


def _make_engine(settings: dict, engine: hydra.Engine, lineage_id: str, source_gpr: str, folder: Path, identifier: str,
                 purpose: str, revision: str, generation: int, root: dict) -> dict:
    """hydra.4: `fork_project purpose:"backup"` copies, hashes both sides, writes backup.json (writer "engine") and seals.

    The client does not trust the reply: it re-reads and re-hashes every file against the manifest with hashlib, checks the
    self-hash, and compares the copy with the source it hashed before (4.5)."""
    if folder.exists():
        raise BackupError("backup_failed", "%s exists; a backup never overwrites" % folder)
    folder.parent.mkdir(parents=True, exist_ok=True)
    expected = {row["path"]: row for row in lineage.tree_files(Path(source_gpr).parent)}
    try:
        forked = engine.call("fork_project", project=source_gpr, path=str(folder), purpose="backup", open=False, verify="hash",
                             mode=root["mode"] if root["mode"] in ("auto", "copy") else "auto",
                             maxCopyMb=int(settings.get("fork_max_copy_mb", 8192)))
    except hydra.EngineError as error:
        raise BackupError("backup_failed", "the engine could not make the backup: %s" % error, folder=str(folder)) from error
    checked = verify(folder)
    if not checked["ok"]:
        raise BackupError("backup_verify_failed", "the engine's backup does not verify: %s; the folder stays invisible and is listed "
                          "for manual removal" % "; ".join(checked["problems"][:5]), folder=str(folder))
    manifest = checked["manifest"]
    mismatches = [{"path": row["path"], "expected": expected[row["path"]]["sha256"], "actual": row["sha256"]}
                  for row in manifest.get("files") or [] if row["path"] in expected and expected[row["path"]]["sha256"] != row["sha256"]
                  and not row["path"].endswith(".fork.json")]
    if mismatches:
        raise BackupError("backup_verify_failed", "the backup does not match its source", mismatches=mismatches[:20], folder=str(folder))
    digest = lineage.sha256_hex((folder / "backup.json").read_bytes())
    lineage.backups_log(settings, lineage_id).append({
        "id": identifier, "manifestSha256": digest, "root": root["path"], "verifiedAt": lineage.now_iso(), "bytes": size_of(folder),
        "independent": bool((manifest.get("copy") or {}).get("independent")), "purpose": purpose, "generation": generation})
    return {"id": identifier, "folder": str(folder), "project": str(project_dir(folder)), "gpr": forked.get("gpr") or "",
            "manifest": manifest, "manifestSha256": digest, "root": root["path"], "writer": manifest.get("writer")}


def _sidecar_path(folder: Path) -> Path | None:
    found = sorted(Path(folder).glob("*.fork.json"))
    return found[0] if found else None


def _rewrite_sidecar(folder: Path, **changes) -> dict:
    path = _sidecar_path(folder)
    record = {"format": 1}
    if path is not None:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    else:
        path = Path(folder) / "backup.fork.json"
    record.update(changes)
    durable.atomic_write(path, json.dumps(record, indent=2).encode("utf-8"), point="sidecar")
    return record


def seal(folder: Path, manifest_sha256: str) -> None:
    """On hydra.2/3 the client seals: SEALED.json and the sidecar's `state:"complete"` (a hydra.4 engine reads either)."""
    durable.atomic_write(Path(folder) / lineage.SEAL_MARKER,
                         json.dumps({"manifestSha256": manifest_sha256, "sealedAt": lineage.now_iso(), "by": "hydralysis"},
                                    indent=2).encode("utf-8"), point="seal")
    _rewrite_sidecar(folder, state="complete")


def make(settings: dict, engine: hydra.Engine, lineage_id: str, source_gpr: str, purpose: str, revision: str,
         generation: int, confirm_large: bool = False, by: dict | None = None) -> dict:
    """Back up SOURCE_GPR into every configured root and re-hash each copy. Returns the primary backup and the others.

    The primary must verify (a failure aborts); a secondary that fails aborts when the policy needs it
    (`backup_min_verified`, a `required` root) and otherwise only warns. Raises BackupError."""
    wanted = policy(settings)
    plan = preview(settings, lineage_id, source_gpr)
    if plan["needs_confirmation"] and not confirm_large:
        raise BackupError("confirm_large_backup", "this backup is %.1f GB, above backup_confirm_gb (%s); the cumulative cost and "
                          "the free space are in `plan`. Repeat with confirm_large:true" % (plan["bytes"] / GIB, wanted["backup_confirm_gb"]),
                          plan=plan)
    stamp = time.time()
    identifier = backup_id(revision, purpose, stamp)
    unique, number = identifier, 1
    while any((Path(root["path"]) / lineage_id / unique).exists() for root in wanted["roots"]):
        number += 1  # a retry in the same second must not meet the earlier backup: a backup never overwrites
        unique = "%s-%d" % (identifier, number)
    identifier = unique
    made, warnings = [], []
    for index, root in enumerate(wanted["roots"]):
        folder = Path(root["path"]) / lineage_id / identifier
        try:
            made.append(_make_one(settings, engine, lineage_id, source_gpr, folder, identifier, purpose, revision, generation,
                                  root, by or hydra.identity()))
        except (BackupError, hydra.EngineError, OSError, RuntimeError) as error:
            if index == 0 or root["required"]:
                raise BackupError("backup_failed", "the %s backup into %s failed: %s" % ("primary" if index == 0 else "required",
                                                                                         root["path"], error)) from error
            warnings.append({"root": root["path"], "error": str(error)})
    if len(made) < wanted["backup_min_verified"]:
        raise BackupError("backup_failed", "%d verified backup(s), the policy needs backup_min_verified=%d"
                          % (len(made), wanted["backup_min_verified"]), warnings=warnings)
    independent = sum(1 for item in made if item["manifest"]["copy"]["independent"])
    if independent < wanted["backup_min_independent"]:
        raise BackupError("backup_failed", "%d independent verified backup(s), the policy needs backup_min_independent=%d"
                          % (independent, wanted["backup_min_independent"]), warnings=warnings)
    return {"backup": made[0], "all": made, "warnings": warnings, "plan": plan}


def _make_one(settings: dict, engine: hydra.Engine, lineage_id: str, source_gpr: str, folder: Path, identifier: str, purpose: str,
              revision: str, generation: int, root: dict, by: dict) -> dict:
    started = time.monotonic()
    source_folder = Path(source_gpr).parent
    if _engine_backup(engine):
        return _make_engine(settings, engine, lineage_id, source_gpr, folder, identifier, purpose, revision, generation, root)
    if folder.exists():
        raise BackupError("backup_failed", "%s exists; a backup never overwrites" % folder)
    project = folder / "project"
    folder.parent.mkdir(parents=True, exist_ok=True)
    # The copy is verified against the SOURCE as well: a source that changed during the copy makes a bad backup.
    expected = {row["path"]: row for row in lineage.tree_files(source_folder)}
    forked = _fork_into(settings, engine, source_gpr, project, root["mode"])
    _rewrite_sidecar(project, purpose="backup", disposable=False, state="candidate")
    files = lineage.tree_files(folder)
    mismatches = []
    for row in files:
        if not row["path"].startswith("project/"):
            continue
        source = expected.get(row["path"].removeprefix("project/"))
        if source is not None and (source["sha256"] != row["sha256"] or source["size"] != row["size"]):
            if not row["path"].endswith(".fork.json"):
                mismatches.append({"path": row["path"], "expected": source["sha256"], "actual": row["sha256"]})
    if mismatches:
        raise BackupError("backup_verify_failed", "the backup does not match its source; no backup.json was written, the folder "
                          "stays invisible and is listed for manual removal", mismatches=mismatches[:20], folder=str(folder))
    same_volume = _volume(folder) == _volume(source_folder)
    after = lineage.tree_files(source_folder)
    manifest = {
        "format": FORMAT, "kind": KIND, "writer": "hydralysis", "id": identifier, "purpose": purpose, "createdAt": lineage.now_iso(),
        "createdBy": by,
        "source": {"gpr": source_gpr, "name": Path(source_gpr).stem, "revision": revision, "lineage": lineage_id, "generation": generation},
        "engine": {key: value for key, value in (engine.hello() or {}).items() if key in ("hydraVersion", "ghidraVersion")},
        "files": files, "filesetSha256": lineage.fileset_sha256(files),
        "copy": {"method": forked.get("method") or ("clone" if forked.get("cloned") else "copy"), "sameVolume": same_volume,
                 "independent": not same_volume and root["mode"] == "copy", "ms": int((time.monotonic() - started) * 1000)},
        "verify": {"level": "hash", "ok": True, "at": lineage.now_iso(), "sourceUnchanged": lineage.fileset_sha256(after) == lineage.fileset_sha256(list(expected.values()))},
    }
    if not manifest["verify"]["sourceUnchanged"]:
        raise BackupError("backup_verify_failed", "the source changed while it was copied; no backup.json was written", folder=str(folder))
    manifest["selfSha256"] = lineage.self_hash(manifest)
    durable.atomic_write(folder / "backup.json", lineage.canonical(manifest), point="backup_manifest")
    digest = lineage.sha256_hex((folder / "backup.json").read_bytes())
    seal(project, digest)
    row = {"id": identifier, "manifestSha256": digest, "root": root["path"], "verifiedAt": lineage.now_iso(), "bytes": size_of(folder),
           "independent": manifest["copy"]["independent"], "purpose": purpose, "generation": generation}
    lineage.backups_log(settings, lineage_id).append(row)
    return {"id": identifier, "folder": str(folder), "project": str(project), "gpr": forked["gpr"], "manifest": manifest,
            "manifestSha256": digest, "root": root["path"]}


# ---- reading, verifying ----------------------------------------------------------------------------------------

def read_backup(folder: Path) -> dict | None:
    try:
        manifest = json.loads((Path(folder) / "backup.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return manifest if isinstance(manifest, dict) and manifest.get("kind") == KIND else None


def verify(folder: Path) -> dict:
    """Re-read and re-hash every file against backup.json with hashlib, and check the self-hash (4.5)."""
    manifest = read_backup(folder)
    if manifest is None:
        return {"ok": False, "problems": ["no valid backup.json"], "manifest": None}
    problems = []
    if manifest.get("format", FORMAT) > FORMAT:
        problems.append("backup.json format %s is newer than %d (format_unreadable)" % (manifest["format"], FORMAT))
    if manifest.get("selfSha256") != lineage.self_hash(manifest):
        problems.append("selfSha256 does not match")
    if manifest.get("filesetSha256") != lineage.fileset_sha256(manifest.get("files") or []):
        problems.append("filesetSha256 does not match the files list")
    if not (manifest.get("verify") or {}).get("ok"):
        problems.append("backup.json does not say verify.ok")
    listed = {row["path"]: row for row in manifest.get("files") or []}
    actual = {row["path"]: row for row in lineage.tree_files(folder)}
    for path, row in listed.items():
        found = actual.get(path)
        if found is None:
            problems.append("missing file %s" % path)
        elif found["sha256"] != row["sha256"] or found["size"] != row["size"]:
            problems.append("changed file %s" % path)
    for path in actual:
        if path not in listed:
            problems.append("unlisted file %s" % path)
    return {"ok": not problems, "problems": problems[:20], "manifest": manifest}


def scan_roots(settings: dict, lineage_id: str) -> dict:
    """Every folder under the backup roots for this lineage: verified (visible), or without a valid backup.json (invisible)."""
    visible, invisible = [], []
    for root in policy(settings)["roots"]:
        base = Path(root["path"]) / lineage_id
        for folder in sorted(base.iterdir()) if base.is_dir() else ():
            if not folder.is_dir():
                continue
            if read_backup(folder) is not None:
                visible.append({"folder": folder, "root": root["path"]})
            else:
                invisible.append({"folder": str(folder), "root": root["path"], "note": "no valid backup.json; invisible, never used "
                                  "as a restore source, listed for manual removal (D28)"})
    return {"visible": visible, "invisible": invisible}


def usable(settings: dict, lineage_id: str, identifier: str, manifest_sha256: str | None = None) -> dict | None:
    """A backup that may be relied on (commit, upgrade gate): present, verifies, and (when given) the one backups.log names."""
    for found in scan_roots(settings, lineage_id)["visible"]:
        if found["folder"].name == identifier:
            result = verify(found["folder"])
            digest = lineage.sha256_hex((found["folder"] / "backup.json").read_bytes())
            if result["ok"] and (manifest_sha256 is None or manifest_sha256 == digest):
                return {"folder": str(found["folder"]), "manifestSha256": digest, "manifest": result["manifest"]}
    return None


def listing(settings: dict, lineage_id: str, verify_all: bool = False) -> dict:
    scan = scan_roots(settings, lineage_id)
    rows_logged = {row["id"] + "|" + row["root"]: row for row in logged(settings, lineage_id)}
    rows, independent = [], 0
    for found in scan["visible"]:
        folder = found["folder"]
        manifest = read_backup(folder)
        digest = lineage.sha256_hex((folder / "backup.json").read_bytes())
        entry = rows_logged.get(folder.name + "|" + found["root"])
        row = {"id": folder.name, "root": found["root"], "purpose": manifest.get("purpose"), "createdAt": manifest.get("createdAt"),
               "generation": (manifest.get("source") or {}).get("generation"), "writer": manifest.get("writer"),
               "independent": bool((manifest.get("copy") or {}).get("independent")), "sealed": (project_dir(folder) / lineage.SEAL_MARKER).is_file(),
               "manifestSha256": digest, "logged": entry is not None, "replaced": bool(entry and entry["manifestSha256"] != digest)}
        if not row["sealed"]:
            row["note"] = "legacy: not sealed; protected by client discipline only until `op=verify` adopts it"
        if verify_all:
            checked = verify(folder)
            row["verified"] = checked["ok"]
            if not checked["ok"]:
                row["problems"] = checked["problems"]
        independent += row["independent"] and (row.get("verified", True))
        rows.append(row)
    missing = [row for key, row in rows_logged.items() if not row.get("removed") and not any(r["id"] == row["id"] and r["root"] == row["root"] for r in rows)]
    return {"lineage": lineage_id, "backups": rows, "invisible": scan["invisible"], "independent_verified": independent,
            "logged_but_missing": [{"id": row["id"], "root": row["root"]} for row in missing],
            "policy": {key: item for key, item in policy(settings).items() if key != "roots"}, "roots": policy(settings)["roots"]}


# ---- retention (OD8): remove is a dry run unless confirm:true --------------------------------------------------

def protected_generations(settings: dict, lineage_id: str, selected_stores: list[dict] | None = None) -> dict[int, str]:
    """Generations that `remove` refuses: generation 0, the head, every generation the revert chain can reach and the base
    of a live view.

    `commit_revert` undoes the latest live commit and the commit before it becomes the latest (its archived records come
    back), so after reverting c3 the next target is the generation before it, and so on down to generation 0. Every
    published generation at or below the head is therefore a revert target. What stays removable is a generation above the
    head (a rolled-back or unpublished candidate) and a folder that CURRENT.log never published."""
    rows = lineage.history(settings, lineage_id)
    top = rows[-1]["gen"] if rows else 0
    keep = {0: "generation 0 is the adopted project and is never removed", top: "the head generation"}
    published = sorted({row["gen"] for row in rows if row.get("gen", 0) < top and row.get("reason") in ("commit", "recover", "rollback")})
    for number in published:
        keep.setdefault(number, "the revert target (the generation before the head)" if number == published[-1]
                        else "a generation the revert chain can reach (commit_revert walks back to generation 0)")
    bases = Path(root_path(settings)) / "bases"
    for marker in bases.glob("*/*/COMPLETE.json") if bases.is_dir() else ():
        try:
            record = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(record.get("generation"), int) and record.get("lineage") == lineage_id:
            keep.setdefault(record["generation"], "the base of a live view")
    return keep


def remove(settings: dict, lineage_id: str, options: dict) -> dict:
    confirm = options.get("confirm", False)
    if not isinstance(confirm, bool):
        raise ValueError("confirm must be a boolean")
    identifier, generation = options.get("id"), options.get("generation")
    if (identifier is None) == (generation is None):
        raise ValueError("backups remove needs exactly one of id (a backup) or generation (a generation folder)")
    plan: dict = {"dry_run": not confirm}
    if identifier is not None:
        matches = [found for found in scan_roots(settings, lineage_id)["visible"] + [{"folder": Path(item["folder"]), "root": item["root"]}
                                                                                 for item in scan_roots(settings, lineage_id)["invisible"]]
                   if found["folder"].name == identifier]
        if not matches:
            raise ValueError("no backup %s under the configured roots of %s" % (identifier, lineage_id))
        verified = [found for found in scan_roots(settings, lineage_id)["visible"] if verify(found["folder"])["ok"]]
        wanted = policy(settings)["backup_min_verified"]
        target_ok = any(found["folder"] == matches[0]["folder"] for found in verified)
        if target_ok and len(verified) - 1 < wanted:
            return {**plan, "removed": False, "refused": "backup_min_verified",
                    "message": "removing it would leave %d verified backup(s), the policy needs %d" % (len(verified) - 1, wanted)}
        plan.update(what="backup", folders=[str(item["folder"]) for item in matches])
        victims = [item["folder"] for item in matches]
    else:
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise ValueError("generation must be an integer")
        keep = protected_generations(settings, lineage_id)
        if generation in keep:
            return {**plan, "removed": False, "refused": "protected_generation", "generation": generation, "message": keep[generation]}
        folder = lineage.generation_dir(settings, lineage_id, generation)
        if not folder.is_dir():
            raise ValueError("generation %d has no folder" % generation)
        plan.update(what="generation", folders=[str(folder)])
        victims = [folder]
    plan["bytes"] = sum(size_of(item) for item in victims)
    if not confirm:
        return {**plan, "removed": False, "message": "dry run: nothing was removed; repeat with confirm:true"}
    for item in victims:
        _writable_tree(item)
        shutil.rmtree(item)
    if identifier is not None:
        for found in matches:
            lineage.backups_log(settings, lineage_id).append({"id": identifier, "root": found["root"], "removed": True,
                                                              "removedAt": lineage.now_iso()})
    return {**plan, "removed": True}


def adopt_legacy(folder: Path, engine=None, lineage_id: str | None = None) -> dict:
    """`op=verify` on a backup without a seal: re-hash against backup.json, then seal it (a failed one is `legacy_unverified`).

    On an engine with `seal_project` the engine's registry is told as well (a best effort: the client's SEALED.json and the
    sidecar are already a witness of the union, D66)."""
    result = verify(folder)
    if not result["ok"]:
        return {"ok": False, "label": "legacy_unverified", "problems": result["problems"]}
    project = project_dir(folder)
    if (project / lineage.SEAL_MARKER).is_file():
        return {"ok": True, "adopted": False}
    seal(project, lineage.sha256_hex((Path(folder) / "backup.json").read_bytes()))
    outcome: dict = {"ok": True, "adopted": True}
    if engine is not None and _engine_backup(engine):
        gpr = next(iter(sorted(project.glob("*.gpr"))), None)
        try:
            if gpr is None:
                raise hydra.EngineError("not_found", "no .gpr in the backup")
            fields = {"project": str(gpr)}
            if lineage_id:
                fields["lineage"] = lineage_id
            engine.call("seal_project", **fields)
            outcome["engine_sealed"] = True
        except hydra.EngineError as error:
            outcome.update(engine_sealed=False, engine_seal_error=str(error))
    return outcome


# ---- the handler `backend action=backups` ----------------------------------------------------------------------

def _target_lineage(settings: dict, options: dict) -> str:
    from hydralysis import targets
    if options.get("lineage"):
        lineage.lineage_dir(settings, str(options["lineage"]))
        return str(options["lineage"])
    name = options.get("target")
    if not name:
        raise ValueError("backups needs options.target (a target name) or options.lineage")
    resolved = targets.resolve(settings, str(name))
    if not resolved.get("lineage"):
        raise BackupError("no_lineage", "target %s has no lineage yet: backups are made by a commit" % name)
    return resolved["lineage"]["id"]


def handle(capability: str, request: dict) -> str:
    from hydralysis import api
    options = request.get("options") or {}
    settings = request.get("settings") or api._settings()
    op = options.get("op", "list")
    try:
        lineage_id = _target_lineage(settings, options)
        if op == "list":
            result = listing(settings, lineage_id, verify_all=bool(options.get("verify_all")))
        elif op == "verify":
            result = {"lineage": lineage_id, "results": []}
            try:
                adopter = hydra.Engine(settings) if any(not (project_dir(f["folder"]) / lineage.SEAL_MARKER).is_file()
                                                         for f in scan_roots(settings, lineage_id)["visible"]) else None
            except Exception:  # no engine: the client's seal alone
                adopter = None
            for found in scan_roots(settings, lineage_id)["visible"]:
                if options.get("id") and found["folder"].name != options["id"]:
                    continue
                outcome = adopt_legacy(found["folder"], adopter, lineage_id)
                result["results"].append({"id": found["folder"].name, "root": found["root"], **outcome})
            if options.get("id") and not result["results"]:
                raise ValueError("no backup %s under the configured roots" % options["id"])
        else:
            result = {"lineage": lineage_id, **remove(settings, lineage_id, options)}
    except (BackupError, lineage.LineageError) as error:
        return json.dumps(error.payload(), indent=2)
    return json.dumps({"op": op, **result}, indent=2, default=str)
