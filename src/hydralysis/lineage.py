"""Lineage and generations (PROTOCOL-3.md 4.4): the analysed project in place is generation 0, never written; a commit
makes generation N as a new, verified, sealed project folder, and one append-only log, `CURRENT.log`, says which
generation is the head.

Layout, under the Hydralysis root (`generations_root` overrides it):

    lineages/<id>/lineage.json            {format, id, origin_key, origin_gpr, program, sha256, createdAt}
    lineages/<id>/CURRENT.log             CRC-framed lines (durable.AppendLog), the head is the last valid line
    lineages/<id>/commits/<cid>.intent.log
    lineages/<id>/backups.log
    lineages/<id>/gen/0002/<project>/...  a generation, invisible until its MANIFEST.json verifies
    lineages/<id>/.commit.lock            OS lock: one commit per lineage

`targets.json` keeps `lineage: {id, origin_key}` as a cache; this log is the truth (a crash between the append and any
registry write is harmless). Nothing here writes into generation 0 or into a published generation.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path

from hydralysis import durable
from hydralysis.backends import read_json, write_json
from hydralysis.paths import root_path

FORMAT = 1
MANIFEST = "MANIFEST.json"
SEAL_MARKER = "SEALED.json"
# Files that are state of the engine or of the lock, not content of a project: never part of a manifest hash.
_EXCLUDED_NAMES = {MANIFEST, SEAL_MARKER, "projectState", "backup.json"}
_EXCLUDED_SUFFIXES = (".lock", ".lock~")
_LINEAGE_ID = re.compile(r"L-[0-9a-f]{8}")


class LineageError(ValueError):
    """A lineage refusal with a stable `code` (lineage_corrupt, tampered, no_lineage, ...)."""

    def __init__(self, code: str, message: str, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self), **self.detail}


# ---- canonical form (4.1, 3.4: both writers produce these bytes) -----------------------------------------------

def canonical(value) -> bytes:
    """UTF-8, no whitespace, sorted keys, integers only in a manifest, nothing escaped beyond quote, backslash and C0.

    `json.dumps(..., ensure_ascii=False)` escapes exactly those, writes U+2028 and U+2029 literally, and the strict
    UTF-8 encode refuses an unpaired surrogate, as a manifest verified by two languages must."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fileset_sha256(files: list[dict]) -> str:
    return sha256_hex(canonical(files))


def self_hash(manifest: dict) -> str:
    return sha256_hex(canonical({key: item for key, item in manifest.items() if key != "selfSha256"}))


# ---- layout ----------------------------------------------------------------------------------------------------

def lineages_root(settings: dict) -> Path:
    base = Path(settings["generations_root"]) if settings.get("generations_root") else root_path(settings)
    return base / "lineages"


def lineage_dir(settings: dict, lineage_id: str) -> Path:
    if not _LINEAGE_ID.fullmatch(lineage_id or ""):
        raise ValueError("invalid lineage id")
    return lineages_root(settings) / lineage_id


def generation_dir(settings: dict, lineage_id: str, number: int) -> Path:
    return lineage_dir(settings, lineage_id) / "gen" / ("%04d" % number)


def current_log(settings: dict, lineage_id: str) -> durable.AppendLog:
    return durable.AppendLog(lineage_dir(settings, lineage_id) / "CURRENT.log", by="lineage")


def intent_log(settings: dict, lineage_id: str, cid: str) -> durable.AppendLog:
    if not re.fullmatch(r"c-[0-9a-f]{4,16}", cid or ""):
        raise ValueError("invalid commit id")
    return durable.AppendLog(lineage_dir(settings, lineage_id) / "commits" / (cid + ".intent.log"), by="commit")


def backups_log(settings: dict, lineage_id: str) -> durable.AppendLog:
    return durable.AppendLog(lineage_dir(settings, lineage_id) / "backups.log", by="backups")


def commit_lock_path(settings: dict, lineage_id: str) -> Path:
    return lineage_dir(settings, lineage_id) / ".commit.lock"


# ---- creation and lookup ---------------------------------------------------------------------------------------

def find(settings: dict, origin_key: str) -> str | None:
    """The lineage of an origin key, from the lineage folders themselves (the registry is only a cache)."""
    root = lineages_root(settings)
    if not root.is_dir():
        return None
    for folder in sorted(root.iterdir()):
        if _LINEAGE_ID.fullmatch(folder.name):
            record = read_json(folder / "lineage.json")
            if record.get("origin_key") == origin_key:
                return folder.name
    return None


def load(settings: dict, lineage_id: str) -> dict:
    record = read_json(lineage_dir(settings, lineage_id) / "lineage.json")
    if not record:
        raise LineageError("no_lineage", "lineage %s has no lineage.json" % lineage_id)
    if record.get("format", FORMAT) > FORMAT:
        raise LineageError("format_unreadable", "lineage.json has format %s; this Hydralysis reads %d" % (record["format"], FORMAT))
    return record


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def ensure(settings: dict, target: dict) -> dict:
    """The lineage of TARGET (a resolved target), created at the first commit with generation 0 registered.

    The creation records the current key (`origin_key`), so overlay stores and working directories keep their names
    across every later flip. Idempotent: a second call returns the same lineage (also after a crash between the
    folder and the registry write)."""
    origin = target.get("origin_key") or target["key"]
    # Find and create are one step per origin key: the commit lock lives inside the lineage folder, so it cannot order two
    # first commits. This lock sits beside the lineages and is keyed by the origin, across threads and processes.
    root = lineages_root(settings)
    root.mkdir(parents=True, exist_ok=True)
    with durable.file_lock(root / (".create.%s.lock" % sha256_hex(origin.encode("utf-8"))[:24]), what="lineage creation"):
        lineage_id = find(settings, origin)
        if lineage_id is None:
            lineage_id = "L-" + uuid.uuid4().hex[:8]
            folder = lineage_dir(settings, lineage_id)
            folder.mkdir(parents=True, exist_ok=False)
            write_json(folder / "lineage.json", {"format": FORMAT, "id": lineage_id, "origin_key": origin, "origin_gpr": target["gpr"],
                                                 "program": target["program"], "sha256": target["sha256"], "createdAt": now_iso()})
        if current_log(settings, lineage_id).last() is None:
            append_current(settings, lineage_id, {"gen": 0, "cid": None, "reason": "register", "gpr": load(settings, lineage_id)["origin_gpr"],
                                                  "manifestSha256": None, "engine": None})
    register(settings, target, lineage_id, origin)
    return load(settings, lineage_id)


def register(settings: dict, target: dict, lineage_id: str, origin: str) -> None:
    """Mirror the lineage into targets.json (a cache; a crash before this is harmless)."""
    from hydralysis import targets
    registered = targets.registry(settings).get(target["name"])
    if registered is None or (registered.get("lineage") or {}).get("id") == lineage_id:
        return  # a target defined only by configuration has no registry row to extend; or it is already mirrored
    targets.register(settings, [target["name"]], {**registered, "lineage": {"id": lineage_id, "origin_key": origin}})


# ---- CURRENT.log -----------------------------------------------------------------------------------------------

def append_current(settings: dict, lineage_id: str, record: dict, lock_held: bool = False) -> dict:
    """Append one CURRENT.log line (the commit point of a publish). Fills `seq`, `at` and `prevHash`."""
    log = current_log(settings, lineage_id)

    def build() -> dict:
        previous = log.last(strict=True)
        line = {"seq": (previous["seq"] + 1) if previous else 1, **record, "at": now_iso(),
                "prevHash": sha256_hex(canonical(previous)) if previous else None}
        log.append(line, lock_held=True)
        return line

    if lock_held:
        return build()
    with durable.file_lock(log.lock_path, log.lock_timeout_s, what="log CURRENT.log"):
        # The writer's tail check runs inside append(); read the previous line only after it, under the same hold.
        log.repair(lock_held=True)
        return build()


def head(settings: dict, lineage_id: str) -> dict:
    """The head: the last valid CURRENT.log line, with what the reader saw (`torn_tail`, `corrupt`).

    A reader never repairs. A torn tail shows an older, consistent state; a mid-log gap resolves to the last good
    line before it and says so (`corrupt`), and commits and reverts are refused until the owner repairs it."""
    scan = current_log(settings, lineage_id).scan()
    if not scan.records:
        raise LineageError("no_lineage", "lineage %s has no valid CURRENT.log line" % lineage_id, torn_tail=scan.torn_tail,
                           corrupt=scan.corrupt)
    last = scan.records[-1]
    for field in ("seq", "gen", "gpr"):
        if field not in last:
            raise LineageError("lineage_corrupt", "a CURRENT.log line has no %s" % field)
    return {**last, "torn_tail": scan.torn_tail, "corrupt": scan.corrupt, "lines": len(scan.records)}


def history(settings: dict, lineage_id: str) -> list[dict]:
    return current_log(settings, lineage_id).scan().records


def resolve(settings: dict, item: dict, key: str) -> dict:
    """What `targets.resolve` changes for a target with a lineage: `gpr` is the head, `key` the stored origin key."""
    link = item.get("lineage")
    if not link:
        return {}
    try:
        top = head(settings, link["id"])
    except LineageError:
        return {}
    return {"gpr": top["gpr"], "key": link["origin_key"], "lineage": {"id": link["id"], "origin_key": link["origin_key"],
                                                                      "generation": top["gen"], "cid": top.get("cid"),
                                                                      "reason": top.get("reason")},
            "adopted_gpr": item.get("gpr", "")}


# ---- generations: files, manifests -----------------------------------------------------------------------------

def _excluded(path: Path) -> bool:
    return path.name in _EXCLUDED_NAMES or path.name.endswith(_EXCLUDED_SUFFIXES)


def _file_hash(path: Path) -> tuple[int, str]:
    """(size, sha256) of what the manifest records for PATH."""
    if path.name.endswith(".fork.json"):
        # The sidecar's lifecycle `state` changes at seal time, so size and hash are taken without it (4.6 step 7).
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            record = None
        if isinstance(record, dict):
            body = canonical({key: item for key, item in record.items() if key != "state"})
            return len(body), sha256_hex(body)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return path.stat().st_size, digest.hexdigest()


def tree_files(folder: Path) -> list[dict]:
    """[{path, size, sha256}] for every content file under FOLDER, sorted by path (forward slashes)."""
    rows = []
    for path in sorted(item for item in Path(folder).rglob("*") if item.is_file() and not _excluded(item)):
        size, digest = _file_hash(path)
        rows.append({"path": path.relative_to(folder).as_posix(), "size": size, "sha256": digest})
    return sorted(rows, key=lambda row: row["path"])


def tree_hash(folder: Path) -> str:
    """The oracle's tree hash (O1): the fileset hash of the folder, excluding projectState, locks and manifests."""
    return fileset_sha256(tree_files(folder))


def project_folder_of(gpr: str) -> Path:
    return Path(gpr).parent


def write_manifest(folder: Path, body: dict) -> dict:
    """Write MANIFEST.json (forced, write-through replace) with its fileset and self hashes. Returns the manifest."""
    files = tree_files(folder)
    manifest = {"format": FORMAT, **body, "files": files, "filesetSha256": fileset_sha256(files)}
    manifest["selfSha256"] = self_hash(manifest)
    durable.atomic_write(Path(folder) / MANIFEST, canonical(manifest), point="manifest")
    return manifest


def read_manifest(folder: Path) -> dict | None:
    path = Path(folder) / MANIFEST
    try:
        data = path.read_bytes()
        manifest = json.loads(data.decode("utf-8"))
    except (OSError, ValueError):
        return None
    return manifest if isinstance(manifest, dict) else None


def manifest_file_sha256(folder: Path) -> str | None:
    try:
        return sha256_hex((Path(folder) / MANIFEST).read_bytes())
    except OSError:
        return None


def verify_manifest(folder: Path) -> dict:
    """Re-hash every file against MANIFEST.json. `ok` is false when the manifest is missing or invalid, a file
    differs, a file is missing, or an unlisted file appeared (`tampered`)."""
    manifest = read_manifest(folder)
    if manifest is None:
        return {"ok": False, "problems": ["no valid MANIFEST.json"], "manifest": None}
    problems = []
    if manifest.get("format", FORMAT) > FORMAT:
        problems.append("manifest format %s is newer than %d (format_unreadable)" % (manifest.get("format"), FORMAT))
    if manifest.get("selfSha256") != self_hash(manifest):
        problems.append("selfSha256 does not match")
    if manifest.get("filesetSha256") != fileset_sha256(manifest.get("files") or []):
        problems.append("filesetSha256 does not match the files list")
    listed = {row["path"]: row for row in manifest.get("files") or []}
    actual = {row["path"]: row for row in tree_files(folder)}
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


def reserved_generations(settings: dict, lineage_id: str) -> set[int]:
    """Every generation number that must never be reused: the log, the intent logs' reservations, and any folder."""
    taken = {record.get("gen") for record in history(settings, lineage_id) if isinstance(record.get("gen"), int)}
    commits = lineage_dir(settings, lineage_id) / "commits"
    for path in commits.glob("*.intent.log") if commits.is_dir() else ():
        for record in durable.AppendLog(path).scan().records:
            if isinstance(record.get("gen"), int):
                taken.add(record["gen"])
    gen = lineage_dir(settings, lineage_id) / "gen"
    for path in gen.iterdir() if gen.is_dir() else ():
        if path.name.isdigit():
            taken.add(int(path.name))
    return taken


def next_generation(settings: dict, lineage_id: str) -> int:
    return max(reserved_generations(settings, lineage_id) | {0}) + 1


def verify_head(settings: dict, lineage_id: str) -> dict:
    """The head generation's manifest verifies (generation 0 has none: it is the adopted project, never written)."""
    top = head(settings, lineage_id)
    if top["gen"] == 0:
        return {"ok": True, "generation": 0, "problems": []}
    folder = project_folder_of(top["gpr"])
    result = verify_manifest(folder)
    named = result["manifest"] and manifest_file_sha256(folder)
    if result["ok"] and top.get("manifestSha256") and named != top["manifestSha256"]:
        result = {**result, "ok": False, "problems": ["the manifest is not the one CURRENT.log names"]}
    return {"ok": result["ok"], "generation": top["gen"], "problems": result["problems"]}


def tampered(settings: dict, lineage_id: str) -> list[dict]:
    """Published generations whose folder no longer matches its manifest (4.7: a process wrote into one)."""
    found = []
    seen = set()
    for record in history(settings, lineage_id):
        if record.get("gen") and record["gen"] not in seen and record.get("reason") in ("commit", "recover"):
            seen.add(record["gen"])
            folder = project_folder_of(record["gpr"])
            if folder.is_dir():
                check = verify_manifest(folder)
                if not check["ok"]:
                    found.append({"generation": record["gen"], "problems": check["problems"]})
    return found


def status(settings: dict, target: dict) -> dict:
    """`ghidra_query action=status options.show=lineage`: where the head is and what is wrong with it."""
    link = target.get("lineage")
    if not link:
        return {"lineage": None, "generation": 0, "gpr": target["gpr"],
                "note": "no commit has been made on this target; generation 0 is the adopted project, never written"}
    try:
        top = head(settings, link["id"])
    except LineageError as error:
        return {"lineage": link["id"], "error": error.payload()}
    rows = history(settings, link["id"])
    report = {"lineage": link["id"], "origin_key": link["origin_key"], "generation": top["gen"], "gpr": top["gpr"],
              "cid": top.get("cid"), "reason": top.get("reason"), "seq": top["seq"], "engine": top.get("engine"),
              "generations": [{"generation": row["gen"], "reason": row["reason"], "cid": row.get("cid"), "at": row.get("at")}
                              for row in rows[-20:]],
              "torn_tail": top["torn_tail"], "corrupt": top["corrupt"]}
    if top["corrupt"]:
        report["error"] = "lineage_corrupt"
    problems = tampered(settings, link["id"])
    if problems:
        report["tampered"] = problems
    return report
