"""Exportable evidence bundles: export, verify, compare, import (PROTOCOL-3.md Z9, audit C1-42, C2-28).

A bundle is a folder. Everything in it is a file that `manifest.json` lists with its size and SHA-256, and a folder
with a file the manifest does not list is refused.

    manifest.json     format, bundle_id, the filter, the file table, and the volatile fields (exported_at, exporter)
    evidence.jsonl    one line per claim, sorted by evidence_id: {evidence_id, content, meta}
    subjects.json     the games, builds and subject hashes the claims are about, with counts
    captures/<id>.json  bounded captures that claims cite through `from_capture`
    replay.json       the claims that came from a replay or a capture, with their sources
    environment.json  the exporting environment (volatile)
    limitations.md    the limitation codes in use, in words, and which claim carries which

`bundle_id` = `eb_` + SHA-256 of the canonical JSON of what the bundle says, not of how it was written: the
evidence ids, the subjects, the capture file hashes, the replay table and the limitation codes. `meta` (time,
client, harness, provenance), `environment.json` and the manifest's volatile fields are left out. Two independent
exports of the same claims therefore have the same bundle_id, and `compare` says so while naming what differed in
the volatile part.

No game payload bytes: every string is bounded (16 KiB), hex and base64 runs longer than 8 KiB are refused, and a
capture is at most 1 MiB. Nothing here reads or writes a game folder.

CLI: `python -m hydralysis.evidence_bundle export|verify|compare|import ...`. The `evidenceBundle` capability name
is registered in `api.HANDLER_MODULES`; `handle(capability, request)` answers `options.op` the same way.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import sys
import uuid
from pathlib import Path

from hydralysis import durable, evidence
from hydralysis.evidence import EvidenceIntegrityError, canonical_digest, canonical_json

FORMAT = "hydralysis.evidence-bundle/1"
MAX_STRING = 16384
MAX_ENCODED_RUN = 8192
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_CAPTURES = 256
_ENCODED = re.compile(r"^[0-9A-Fa-f\s]+$|^[A-Za-z0-9+/=\s_-]+$")
_NAME = re.compile(r"^(?:manifest\.json|evidence\.jsonl|subjects\.json|replay\.json|environment\.json|limitations\.md|"
                   r"captures/[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}\.json)$")
# Files whose bytes may differ between two exports of the same claims.
VOLATILE_FILES = ("manifest.json", "environment.json", "evidence.jsonl")

# The REA reference bundle (f196ebf, src/domain/evidenceBundle.ts) top-level fields and the file that carries each.
REA_BUNDLE_MAP = {
    "records": "evidence.jsonl",
    "artifacts": "subjects.json",
    "providers": "evidence.jsonl (meta.client, meta.harness: attribution, not identity)",
    "environments": "environment.json (volatile)",
    "scenarios": "replay.json",
    "captures": "captures/",
}
REA_BUNDLE_GAPS = {
    "unknowns": "not modeled: Hydralysis has no residual-unknown records; a gap is a partial or unknown coverage",
}


class BundleError(ValueError):
    """A bundle that cannot be written, read or trusted, with a stable code."""

    def __init__(self, code: str, message: str, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self), **self.detail}


# ---- the payload guard ----------------------------------------------------------------------------------------

def guard_payload(value, where: str = "value") -> None:
    """Refuse strings that look like game bytes or game text: too long, or a long run of hex or base64."""
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise BundleError("payload_refused", "%s is a string of %d characters; a bundle carries at most %d"
                              % (where, len(value), MAX_STRING))
        if len(value) > MAX_ENCODED_RUN and _ENCODED.match(value):
            raise BundleError("payload_refused", "%s looks like encoded bytes (%d characters of hex or base64); a "
                              "bundle carries bounded captured hex, not payloads" % (where, len(value)))
    elif isinstance(value, dict):
        for key, item in value.items():
            guard_payload(key, where + ".<key>")
            guard_payload(item, "%s.%s" % (where, key))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            guard_payload(item, "%s[%d]" % (where, index))


# ---- building ------------------------------------------------------------------------------------------------

def _jsonl(records: list[dict]) -> bytes:
    return b"".join(canonical_json(record).encode("utf-8") + b"\n" for record in records)


def _json_bytes(value) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _subjects(records: list[dict]) -> dict:
    counts: dict[tuple, int] = {}
    for record in records:
        content = record["content"]
        key = (content["game"], content["build"], (content["subject"] or {}).get("sha256", ""))
        counts[key] = counts.get(key, 0) + 1
    return {"subjects": [{"game": game, "build": build, "subject_sha256": digest or None, "records": count}
                         for (game, build, digest), count in sorted(counts.items())]}


def _replay(records: list[dict], captured: set[str]) -> dict:
    scenarios = []
    missing = set()
    for record in records:
        content = record["content"]
        if content["authority"] == "controlled-replay" or content["from_capture"]:
            capture = content["from_capture"]
            scenarios.append({"evidence_id": record["evidence_id"], "authority": content["authority"],
                              "name": content["name"], "source": content["source"], "from_capture": capture})
            if capture and capture not in captured:
                missing.add(capture)
    return {"scenarios": scenarios, "missing_captures": sorted(missing)}


def _limitations(records: list[dict]) -> dict:
    by_code: dict[str, list[str]] = {}
    for record in records:
        for code in record["content"]["limitations"]:
            by_code.setdefault(code, []).append(record["evidence_id"])
    return {code: sorted(ids) for code, ids in sorted(by_code.items())}


def _limitations_md(table: dict) -> bytes:
    lines = ["# Limitations", "",
             "Each code below is stored with the claims that carry it. A code that bounds coverage means the claim "
             "does not cover the whole subject.", ""]
    if not table:
        lines.append("No claim in this bundle states a limitation.")
    for code, ids in table.items():
        entry = evidence.LIMITATIONS.get(code)
        meaning = entry[1] if entry else "A code of the writer's own (no catalog text)."
        lines += ["## `%s`%s" % (code, " (bounds coverage)" if evidence.bounds_coverage(code) else ""), "", meaning, ""]
        lines += ["- %s" % evidence_id for evidence_id in ids] + [""]
    return ("\n".join(lines) + "\n").encode("utf-8")


def bundle_id_of(records: list[dict], subjects: dict, capture_hashes: dict, replay: dict, limitations: dict) -> str:
    """The identity of what a bundle says; volatile fields never enter it."""
    return "eb_" + canonical_digest({
        "format": FORMAT, "records": [record["evidence_id"] for record in records], "subjects": subjects,
        "captures": capture_hashes, "replay": replay, "limitations": sorted(limitations),
    })


def _load_captures(captures_dir: Path | None, wanted: set[str]) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    if captures_dir is None:
        return found
    for capture_id in sorted(wanted):
        file = Path(captures_dir) / (capture_id + ".json")
        if not file.is_file():
            continue
        data = file.read_bytes()
        if len(data) > MAX_CAPTURE_BYTES:
            raise BundleError("payload_refused", "capture %s is %d bytes; a bundle carries at most %d per capture"
                              % (capture_id, len(data), MAX_CAPTURE_BYTES))
        try:
            parsed = json.loads(data.decode("utf-8"))
        except ValueError as exc:
            raise BundleError("capture_invalid", "capture %s is not JSON: %s" % (capture_id, exc)) from exc
        if not isinstance(parsed, dict) or parsed.get("capture_id") != capture_id:
            raise BundleError("capture_invalid", "capture %s must be a JSON object whose capture_id is %s"
                              % (capture_id, capture_id))
        guard_payload(parsed, "capture %s" % capture_id)
        found[capture_id] = _json_bytes(parsed)  # canonical bytes: the same capture hashes the same everywhere
    return found


def export_bundle(db_path: Path, out: Path, *, game: str = "", subsystem: str = "", build: str = "",
                  captures_dir: Path | None = None, overwrite: bool = False) -> dict:
    """Write the selected claims (superseded ones too) as a bundle folder, atomically."""
    out = Path(out)
    if out.exists() and not overwrite:
        raise BundleError("bundle_exists", "%s exists; pass overwrite to replace a bundle" % out)
    if out.exists() and not (out / "manifest.json").is_file():
        raise BundleError("not_a_bundle", "%s exists and is not a bundle folder; it is not replaced" % out)
    records = evidence.records_for_bundle(Path(db_path), game, subsystem, build)
    if not records:
        raise BundleError("empty_selection", "no claims match game=%r subsystem=%r build=%r" % (game, subsystem, build))
    for record in records:
        guard_payload(record["content"], "claim %s" % record["evidence_id"])
        guard_payload(record["meta"], "claim %s meta" % record["evidence_id"])
    cited = {record["content"]["from_capture"] for record in records if record["content"]["from_capture"]}
    captures = _load_captures(captures_dir, cited)
    if len(captures) > MAX_CAPTURES:
        raise BundleError("payload_refused", "too many captures (%d, at most %d)" % (len(captures), MAX_CAPTURES))
    subjects = _subjects(records)
    replay = _replay(records, set(captures))
    limitations = _limitations(records)
    capture_hashes = {key: hashlib.sha256(data).hexdigest() for key, data in sorted(captures.items())}
    bundle_id = bundle_id_of(records, subjects, capture_hashes, replay, limitations)
    from hydralysis import __version__
    exported_at = evidence._now()
    environment = {"hydralysis": __version__, "python": platform.python_version(), "platform": sys.platform,
                   "exported_at": exported_at, "exported_by": evidence._who()[1]}
    files = {"evidence.jsonl": _jsonl(records), "subjects.json": _json_bytes(subjects), "replay.json": _json_bytes(replay),
             "environment.json": _json_bytes(environment), "limitations.md": _limitations_md(limitations)}
    for key, data in captures.items():
        files["captures/%s.json" % key] = data
    manifest = {"format": FORMAT, "bundle_id": bundle_id, "records": len(records),
                "filter": {"game": game, "subsystem": subsystem, "build": build},
                "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                          for name, data in sorted(files.items())},
                "volatile": {"exported_at": exported_at, "files": [name for name in VOLATILE_FILES if name != "manifest.json"]}}
    files["manifest.json"] = _json_bytes(manifest)
    stage = out.parent / (out.name + "." + uuid.uuid4().hex[:12] + ".staging")
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        for name, data in files.items():
            durable.atomic_write(stage / name, data)
        aside = None
        if out.exists():
            aside = out.parent / (out.name + "." + uuid.uuid4().hex[:12] + ".old")
            durable.replace_file(out, aside)  # a move to a name that is free: no folder is overwritten
        try:
            durable.replace_file(stage, out)
        except OSError:
            if aside is not None:
                durable.replace_file(aside, out)
            raise
        if aside is not None:
            shutil.rmtree(aside, ignore_errors=True)
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
    return {"bundle": str(out), "bundle_id": bundle_id, "records": len(records), "captures": len(captures),
            "missing_captures": replay["missing_captures"], "limitations": sorted(limitations)}


# ---- reading and verifying -----------------------------------------------------------------------------------

def _read_file(folder: Path, name: str, expected: dict | None = None) -> bytes:
    if not _NAME.match(name):
        raise BundleError("bundle_path_refused", "%r is not a file a bundle may hold" % name)
    file = folder / name
    if file.is_symlink() or not file.is_file():
        raise BundleError("bundle_file_missing", "%s is missing from the bundle" % name, file=name)
    size = file.stat().st_size
    if size > MAX_FILE_BYTES:
        raise BundleError("bundle_file_too_large", "%s is %d bytes; at most %d" % (name, size, MAX_FILE_BYTES), file=name)
    data = file.read_bytes()
    if expected is not None and (len(data) != expected.get("bytes") or hashlib.sha256(data).hexdigest() != expected.get("sha256")):
        raise BundleError("bundle_file_changed", "%s does not match the hash in the manifest" % name, file=name)
    return data


def load_bundle(folder: Path) -> dict:
    """Read a bundle and prove it: file hashes, every evidence id, the derived files and the bundle id."""
    folder = Path(folder)
    if not folder.is_dir():
        raise BundleError("bundle_missing", "%s is not a bundle folder" % folder)
    try:
        manifest = json.loads(_read_file(folder, "manifest.json").decode("utf-8"))
    except ValueError as exc:
        raise BundleError("bundle_manifest_invalid", "manifest.json is not JSON: %s" % exc) from exc
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or not isinstance(manifest.get("files"), dict):
        raise BundleError("bundle_manifest_invalid", "manifest.json is not a %s manifest" % FORMAT)
    listed = set(manifest["files"])
    for name in listed:
        if not _NAME.match(name) or name == "manifest.json":
            raise BundleError("bundle_path_refused", "the manifest lists %r, which a bundle may not hold" % name)
    for required in ("evidence.jsonl", "subjects.json", "replay.json", "environment.json", "limitations.md"):
        if required not in listed:
            raise BundleError("bundle_manifest_invalid", "the manifest does not list %s" % required)
    present = {str(path.relative_to(folder)).replace("\\", "/") for path in folder.rglob("*") if path.is_file()}
    extra = sorted(present - listed - {"manifest.json"})
    if extra:
        raise BundleError("bundle_unlisted_file", "the bundle holds files the manifest does not list: %s"
                          % ", ".join(extra), files=extra)
    blobs = {name: _read_file(folder, name, manifest["files"][name]) for name in sorted(listed)}
    records = []
    seen = set()
    for number, line in enumerate(blobs["evidence.jsonl"].decode("utf-8").splitlines(), 1):
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise BundleError("bundle_record_invalid", "evidence.jsonl line %d is not JSON: %s" % (number, exc)) from exc
        if not isinstance(record, dict) or set(record) != {"evidence_id", "content", "meta"} or not isinstance(record["content"], dict):
            raise BundleError("bundle_record_invalid", "evidence.jsonl line %d is not {evidence_id, content, meta}" % number)
        if set(record["content"]) != set(evidence.CONTENT_KEYS):
            raise BundleError("bundle_record_invalid", "evidence.jsonl line %d has content fields that are not those of "
                              "the evidence model" % number)
        try:
            evidence.verify_content(record["content"], record["evidence_id"])
        except EvidenceIntegrityError as exc:
            raise BundleError(exc.code, "evidence.jsonl line %d: %s" % (number, exc), evidence_id=exc.evidence_id) from exc
        if record["evidence_id"] in seen:
            raise BundleError("bundle_duplicate_record", "evidence.jsonl repeats %s" % record["evidence_id"])
        seen.add(record["evidence_id"])
        guard_payload(record["content"], "claim %s" % record["evidence_id"])
        guard_payload(record["meta"], "claim %s meta" % record["evidence_id"])
        records.append(record)
    if [record["evidence_id"] for record in records] != sorted(seen):
        raise BundleError("bundle_not_canonical", "evidence.jsonl is not sorted by evidence_id")
    if len(records) != manifest.get("records"):
        raise BundleError("bundle_manifest_invalid", "the manifest says %s records, evidence.jsonl has %d"
                          % (manifest.get("records"), len(records)))
    captures = {name[len("captures/"):-len(".json")]: blobs[name] for name in blobs if name.startswith("captures/")}
    for capture_id, data in captures.items():
        try:
            parsed = json.loads(data.decode("utf-8"))
        except ValueError as exc:
            raise BundleError("capture_invalid", "capture %s is not JSON: %s" % (capture_id, exc)) from exc
        if not isinstance(parsed, dict) or parsed.get("capture_id") != capture_id:
            raise BundleError("capture_invalid", "capture %s does not carry its own capture_id" % capture_id)
        guard_payload(parsed, "capture %s" % capture_id)
    subjects = _subjects(records)
    replay = _replay(records, set(captures))
    limitations = _limitations(records)
    for name, expected in (("subjects.json", _json_bytes(subjects)), ("replay.json", _json_bytes(replay)),
                           ("limitations.md", _limitations_md(limitations))):
        if blobs[name] != expected:
            raise BundleError("bundle_derived_mismatch", "%s does not say what the records say" % name, file=name)
    capture_hashes = {key: hashlib.sha256(data).hexdigest() for key, data in sorted(captures.items())}
    bundle_id = bundle_id_of(records, subjects, capture_hashes, replay, limitations)
    if bundle_id != manifest.get("bundle_id"):
        raise BundleError("bundle_id_mismatch", "bundle_id is %s but the contents hash to %s"
                          % (manifest.get("bundle_id"), bundle_id))
    known = {record["evidence_id"] for record in records}
    dangling = sorted({link for record in records for link in record["content"]["evidence_links"] if link not in known})
    return {"bundle_id": bundle_id, "manifest": manifest, "records": records, "subjects": subjects, "replay": replay,
            "limitations": limitations, "captures": capture_hashes, "files": manifest["files"],
            "environment": json.loads(blobs["environment.json"].decode("utf-8")), "dangling_links": dangling,
            "capture_blobs": captures}


def verify_bundle(folder: Path) -> dict:
    """The verdict as data: `ok` and, when not, the stable code and the message."""
    try:
        loaded = load_bundle(folder)
    except BundleError as exc:
        return {"ok": False, **exc.payload()}
    return {"ok": True, "bundle_id": loaded["bundle_id"], "records": len(loaded["records"]),
            "captures": len(loaded["captures"]), "missing_captures": loaded["replay"]["missing_captures"],
            "dangling_links": loaded["dangling_links"], "limitations": sorted(loaded["limitations"])}


# ---- comparing -----------------------------------------------------------------------------------------------

def _logical_key(content: dict) -> str:
    return "|".join((content["game"], content["build"], content["kind"], content["name"], content["address"],
                     content["subsystem"]))


def compare_bundles(left: Path, right: Path) -> dict:
    """Classify the differences between two verified bundles; volatile fields are named, not compared."""
    one, two = load_bundle(left), load_bundle(right)
    left_ids = {record["evidence_id"]: record for record in one["records"]}
    right_ids = {record["evidence_id"]: record for record in two["records"]}
    unchanged = sorted(set(left_ids) & set(right_ids))
    only_left = sorted(set(left_ids) - set(right_ids))
    only_right = sorted(set(right_ids) - set(left_ids))
    keys_left: dict[str, list[str]] = {}
    keys_right: dict[str, list[str]] = {}
    for evidence_id in only_left:
        keys_left.setdefault(_logical_key(left_ids[evidence_id]["content"]), []).append(evidence_id)
    for evidence_id in only_right:
        keys_right.setdefault(_logical_key(right_ids[evidence_id]["content"]), []).append(evidence_id)
    changes = []
    for key in sorted(set(keys_left) | set(keys_right)):
        classification = "changed" if key in keys_left and key in keys_right else ("removed" if key in keys_left else "added")
        changes.append({"entity": "evidence", "key": key, "classification": classification,
                        "left_evidence_ids": keys_left.get(key, []), "right_evidence_ids": keys_right.get(key, [])})
    for capture_id in sorted(set(one["captures"]) | set(two["captures"])):
        left_hash, right_hash = one["captures"].get(capture_id), two["captures"].get(capture_id)
        if left_hash != right_hash:
            changes.append({"entity": "capture", "key": capture_id,
                            "classification": "added" if left_hash is None else "removed" if right_hash is None else "changed",
                            "left_digest": left_hash, "right_digest": right_hash})
    for code in sorted(set(one["limitations"]) ^ set(two["limitations"])):
        changes.append({"entity": "limitation", "key": code,
                        "classification": "added" if code in two["limitations"] else "removed"})
    volatile = sorted(name for name in set(one["files"]) | set(two["files"])
                      if name in VOLATILE_FILES and one["files"].get(name) != two["files"].get(name))
    equal = one["bundle_id"] == two["bundle_id"]
    return {
        "status": "equal" if equal else "different",
        "left_bundle_id": one["bundle_id"], "right_bundle_id": two["bundle_id"],
        "summary": {"records_unchanged": len(unchanged), "records_added": len(only_right),
                    "records_removed": len(only_left), "records_changed": sum(1 for c in changes
                                                                                if c["entity"] == "evidence" and c["classification"] == "changed")},
        "changes": changes,
        "volatile_ignored": {"fields": ["manifest.volatile", "meta.created", "meta.client", "meta.harness",
                                        "meta.provenance", "environment.json"],
                             "files_differing": volatile},
    }


# ---- importing -----------------------------------------------------------------------------------------------

def import_bundle(folder: Path, db_path: Path) -> dict:
    """Verify the bundle, then store its records in the ledger. Records already there are skipped."""
    loaded = load_bundle(folder)
    summary = evidence.import_records(Path(db_path), loaded["records"])
    return {"bundle_id": loaded["bundle_id"], "records": len(loaded["records"]), **summary,
            "missing_captures": loaded["replay"]["missing_captures"]}


# ---- the capability handler and the CLI ----------------------------------------------------------------------

def _absolute(value, what: str) -> Path:
    path = Path(str(value or ""))
    if not value or not path.is_absolute():
        raise BundleError("path_not_absolute", "%s must be an absolute path" % what)
    return path


def handle(capability: str, request: dict) -> str:
    """`options.op` = export | verify | compare | import; reached through `api.HANDLER_MODULES['evidenceBundle']`."""
    from hydralysis.config import evidence_path
    options = request.get("options") or {}
    args = request.get("args") or {}
    op = options.get("op", "verify")
    try:
        db = evidence_path(str(options.get("db") or args.get("db") or ""))
        if op == "export":
            result = export_bundle(db, _absolute(options.get("out"), "options.out"),
                                   game=str(options.get("target") or options.get("game") or ""),
                                   subsystem=str(options.get("subsystem") or ""), build=str(options.get("build") or ""),
                                   captures_dir=_absolute(options["captures"], "options.captures") if options.get("captures") else None,
                                   overwrite=bool(options.get("overwrite")))
        elif op == "verify":
            result = verify_bundle(_absolute(options.get("bundle"), "options.bundle"))
        elif op == "compare":
            result = compare_bundles(_absolute(options.get("left"), "options.left"), _absolute(options.get("right"), "options.right"))
        elif op == "import":
            result = import_bundle(_absolute(options.get("bundle"), "options.bundle"), db)
        else:
            raise BundleError("unknown_op", "options.op must be export, verify, compare or import")
    except (BundleError, EvidenceIntegrityError) as error:
        payload = error.payload() if isinstance(error, BundleError) else {"error": error.code, "message": str(error)}
        return json.dumps(payload, indent=2)
    return json.dumps({"op": op, **result}, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hydralysis.evidence_bundle", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export", help="write the ledger's claims as a bundle folder")
    export.add_argument("out")
    export.add_argument("--db", default="")
    export.add_argument("--target", "--game", dest="game", default="")
    export.add_argument("--subsystem", default="")
    export.add_argument("--build", default="")
    export.add_argument("--captures", default="", help="folder with <capture_id>.json files to include")
    export.add_argument("--overwrite", action="store_true")
    verify = sub.add_parser("verify", help="prove a bundle: file hashes, every evidence id, bundle_id")
    verify.add_argument("bundle")
    compare = sub.add_parser("compare", help="classify the differences between two bundles")
    compare.add_argument("left")
    compare.add_argument("right")
    imported = sub.add_parser("import", help="verify a bundle and store its claims in the ledger")
    imported.add_argument("bundle")
    imported.add_argument("--db", default="")
    arguments = parser.parse_args(argv)
    from hydralysis.config import evidence_path
    try:
        if arguments.command == "export":
            result = export_bundle(evidence_path(arguments.db), Path(arguments.out), game=arguments.game,
                                   subsystem=arguments.subsystem, build=arguments.build,
                                   captures_dir=Path(arguments.captures) if arguments.captures else None,
                                   overwrite=arguments.overwrite)
        elif arguments.command == "verify":
            result = verify_bundle(Path(arguments.bundle))
        elif arguments.command == "compare":
            result = compare_bundles(Path(arguments.left), Path(arguments.right))
        else:
            result = import_bundle(Path(arguments.bundle), evidence_path(arguments.db))
    except (BundleError, EvidenceIntegrityError) as error:
        payload = error.payload() if isinstance(error, BundleError) else {"error": error.code, "message": str(error)}
        print(json.dumps(payload, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    if arguments.command == "verify":
        return 0 if result["ok"] else 1
    if arguments.command == "compare":
        return 0 if result["status"] == "equal" else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
