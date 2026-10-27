"""Source-cited name/hash to RVA maps, scoped to an exact executable build."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from rusticre.backends import read_json, write_json
from rusticre.locks import locked
from rusticre.paths import root_path

_SHA = re.compile(r"[0-9a-f]{64}")
_HASH = re.compile(r"0x[0-9a-fA-F]{1,32}")
_RVA = re.compile(r"(?:rva:)?0x[0-9a-fA-F]{1,8}")
MAX_BYTES = 16 * 1024 * 1024
MAX_ROWS = 100000
MAX_MAPS = 32


def _record_hash(record: dict) -> str:
    data = {key: value for key, value in record.items() if key != "record_sha256"}
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def _directory(settings: dict, digest: str) -> Path:
    if not _SHA.fullmatch(digest):
        raise ValueError("address map requires the full build SHA-256")
    return root_path(settings) / "address-maps" / digest


def import_map(settings: dict, digest: str, path: str) -> dict:
    directory = _directory(settings, digest)
    source_path = Path(path)
    if not source_path.is_absolute():
        raise ValueError("address map path must be absolute")
    with source_path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("address map exceeds 16 MiB")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("address map must be UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) - {"sha256", "source", "entries"}:
        raise ValueError("address map takes sha256, source and entries")
    if str(value.get("sha256", "")).lower() != digest:
        raise ValueError("address map build SHA-256 mismatch")
    source = value.get("source")
    entries = value.get("entries")
    if not isinstance(source, str) or not source.strip() or len(source) > 4096:
        raise ValueError("address map requires a cited source")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_ROWS:
        raise ValueError("address map requires 1..100000 entries")
    cleaned = []
    for row in entries:
        if not isinstance(row, dict) or set(row) - {"name", "hash", "rva", "source"}:
            raise ValueError("address map entries take name, hash, rva and optional source")
        name, hashed, rva = row.get("name", ""), row.get("hash", ""), row.get("rva")
        if not isinstance(name, str) or len(name) > 512 or "\0" in name:
            raise ValueError("address map name must be text of at most 512 characters")
        if not isinstance(hashed, str) or (hashed and not _HASH.fullmatch(hashed)):
            raise ValueError("address map hash must be hexadecimal, e.g. 0x1234")
        if not name and not hashed:
            raise ValueError("address map entry needs a name or hash")
        if not isinstance(rva, str) or not _RVA.fullmatch(rva):
            raise ValueError("address map rva must be hexadecimal, e.g. 0x1234")
        row_source = row.get("source", source)
        if not isinstance(row_source, str) or not row_source.strip() or len(row_source) > 4096:
            raise ValueError("address map entry requires a cited source")
        cleaned.append({"name": name, "hash": hex(int(hashed, 16)) if hashed else "",
                        "rva": hex(int(rva.removeprefix("rva:"), 16)), "source": row_source})
    content_hash = hashlib.sha256(raw).hexdigest()
    record = {"sha256": digest, "map_sha256": content_hash, "file": str(source_path.resolve()),
              "source": source, "entries": cleaned}
    record["record_sha256"] = _record_hash(record)
    if len(json.dumps(record, ensure_ascii=True, indent=2).encode("utf-8")) > 32 * 1024 * 1024:
        raise ValueError("normalized address map exceeds 32 MiB")
    with locked(directory / ".lock", what="address map import"):
        output = directory / (content_hash + ".json")
        if not output.exists():
            if len(list(directory.glob("*.json"))) >= MAX_MAPS:
                raise ValueError("address map limit reached for this build")
            write_json(output, record)
    return {"sha256": digest, "map_sha256": content_hash, "entries": len(cleaned), "path": str(output)}


def resolve(settings: dict, digest: str, selector: str) -> dict:
    directory = _directory(settings, digest)
    kind, sep, value = selector.partition(":")
    if not sep or kind not in ("name", "hash") or not value:
        raise ValueError("address selector must be name:<name> or hash:0x<hex>")
    if kind == "hash":
        if not _HASH.fullmatch(value):
            raise ValueError("address hash must be hexadecimal")
        value = hex(int(value, 16))
    matches = []
    for path in sorted(directory.glob("*.json")):
        record = read_json(path)
        if (record.get("sha256") != digest or record.get("map_sha256") != path.stem
                or record.get("record_sha256") != _record_hash(record)):
            raise ValueError("address map provenance does not match its build or filename")
        for row in record.get("entries", []):
            if row.get(kind) == value:
                matches.append({"rva": row["rva"], "source": row["source"],
                                "map_sha256": record["map_sha256"], "map_file": record["file"]})
    if not matches:
        raise ValueError("no address map entry for %s in build %s" % (selector, digest))
    if len({row["rva"] for row in matches}) != 1:
        raise ValueError("ambiguous address map entry for %s; conflicting cited RVAs" % selector)
    return {"selector": selector, "sha256": digest, "rva": matches[0]["rva"], "evidence": matches}
