"""Budgets and durable, build-bound type overlays for saved Ghidra analysis.

Overlays are user assertions with cited sources. They are replayed in a worker's
memory, never saved into a canonical project. QueryRunner owns the request lock.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path

ADVANCED_ACTIONS = frozenset(("types", "type", "variables", "dossier", "blocks", "pcode", "trace", "type_edit", "data", "scan"))
_TYPE_KINDS = frozenset(("struct", "signature", "variable", "apply", "rename", "comment",
                         "function_create", "function_body", "function_delete", "batch"))
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_ADDRESS = re.compile(r"(?:0x)?[0-9a-fA-F]+")
MAX_OVERLAYS = 4096
MAX_HISTORY_BYTES = 20 * 1024 * 1024
MAX_BATCH_BYTES = 256 * 1024
MAX_BATCH_EDITS = 200
_BATCH_PROVENANCE = {"input_file", "input_file_sha256", "input_file_bytes"}


def _text(value, name: str, maximum: int, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise ValueError("%s must be text of at most %d characters" % (name, maximum))
    if required and not value.strip():
        raise ValueError("%s is required" % name)
    return value


def _integer(value, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError("%s must be an integer in %d..%d" % (name, low, high))
    return value


def validate_options(action: str, options: dict | None, *, _record: bool = False) -> dict:
    """Validate the compact advanced-query options before a worker is started."""
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise ValueError("options must be an object")
    allowed = {
        "decompile": {"max_characters"}, "data": {"table"}, "scan": {"end", "mnemonic", "operand"},
        "types": set(), "type": {"path"}, "variables": set(), "dossier": set(),
        "blocks": set(), "pcode": {"nodes"},
        "trace": {"seed", "direction", "depth", "nodes", "functions", "argument", "brief"},
        "type_edit": {"kind", "source", "path", "size", "fields", "prototype", "variable", "type", "name", "comment", "expect", "ranges", "edits", "file", "expect_revision", "ids"} | (_BATCH_PROVENANCE if _record else set()),
    }
    if action not in allowed:
        if options:
            raise ValueError("options are not supported for %s" % action)
        return {}
    unknown = set(options) - allowed[action]
    if unknown:
        raise ValueError("unknown %s options: %s" % (action, ", ".join(sorted(unknown))))
    out = dict(options)
    if action == "decompile":
        out["max_characters"] = _integer(out.get("max_characters", 32000), "max_characters", 1, 2097152)
    elif action == "data":
        if "table" in out and not isinstance(out["table"], bool):
            raise ValueError("data table must be a boolean")
    elif action == "scan":
        if "end" in out:
            value = _text(out["end"], "scan end", 128, True)
            if not _ADDRESS.fullmatch(value):
                raise ValueError("scan end must be a numeric Ghidra VA")
        for name in ("mnemonic", "operand"):
            if name in out:
                out[name] = _text(out[name], "scan " + name, 256)
    elif action == "type":
        if "path" in out:
            out["path"] = _text(out["path"], "path", 512, True)
    elif action in ("pcode", "trace"):
        out["nodes"] = _integer(out.get("nodes", 80), "nodes", 1, 200)
        if action == "trace":
            out["seed"] = _text(out.get("seed", ""), "seed", 512)
            direction = out.get("direction", "backward")
            if direction not in ("backward", "forward"):
                raise ValueError("direction must be backward or forward")
            out["direction"] = direction
            out["depth"] = _integer(out.get("depth", 5), "depth", 1, 12)
            out["functions"] = _integer(out.get("functions", 1), "functions", 1, 4)
            if "argument" in out:
                out["argument"] = _integer(out["argument"], "argument", 0, 15)
            if "brief" in out and not isinstance(out["brief"], bool):
                raise ValueError("brief must be a boolean")
    elif action == "type_edit":
        kind = out.get("kind")
        if "expect_revision" in out:
            _integer(out["expect_revision"], "expect_revision", 0, 2**31)
        if kind == "revert":
            if set(out) - {"kind", "ids", "expect_revision", "source"}:
                raise ValueError("revert takes ids (overlay or batch ids) and optional expect_revision")
            ids = out.get("ids")
            if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_OVERLAYS or any(
                    not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{32}", item) for item in ids):
                raise ValueError("revert ids must be 1..%d overlay or batch ids" % MAX_OVERLAYS)
            return json.loads(json.dumps(out))
        if kind not in _TYPE_KINDS:
            raise ValueError("unknown type_edit kind")
        kind_fields = {
            "struct": {"path", "size", "fields"}, "signature": {"prototype"},
            "variable": {"variable", "type", "name"}, "apply": {"type"},
            "rename": {"name"}, "comment": {"comment"},
            "function_create": {"expect", "ranges", "name"},
            "function_body": {"expect", "ranges", "name"},
            "function_delete": {"expect"},
            "batch": {"edits", "file"} | (_BATCH_PROVENANCE if _record else set()),
        }[kind]
        if set(out) - {"kind", "source", "expect_revision"} - kind_fields:
            raise ValueError("options do not belong to type_edit kind %s" % kind)
        out["source"] = _text(out.get("source", ""), "source", 4096, True)
        if kind == "batch":
            return _batch(out, _record)
        required = {
            "struct": ("path",), "signature": ("prototype",), "variable": ("variable", "type"),
            "apply": ("type",), "rename": ("name",), "comment": ("comment",),
            "function_create": (), "function_body": (), "function_delete": (),
        }[kind]
        for name in ("path", "prototype", "variable", "type", "name", "comment"):
            if name in out or name in required:
                out[name] = _text(out.get(name, ""), name, 8192 if name in ("prototype", "comment") else 512, name in required)
        if kind == "struct":
            if not out["path"].startswith("/") or out["path"].endswith("/"):
                raise ValueError("struct path must be an absolute category/type path")
            out["size"] = _integer(out.get("size"), "size", 1, 1024 * 1024)
            fields = out.get("fields", [])
            if not isinstance(fields, list) or len(fields) > 64:
                raise ValueError("fields must be an array of at most 64 components")
            clean_fields = []
            names = set()
            for field in fields:
                if not isinstance(field, dict) or set(field) - {"offset", "type", "name", "length"}:
                    raise ValueError("each field accepts offset, type, name and optional length")
                clean = {"offset": _integer(field.get("offset"), "field offset", 0, out["size"] - 1),
                         "type": _text(field.get("type", ""), "field type", 512, True),
                         "name": _text(field.get("name", ""), "field name", 512, True)}
                if "length" in field:
                    clean["length"] = _integer(field["length"], "field length", 1, out["size"] - clean["offset"])
                if clean["name"] in names:
                    raise ValueError("structure fields must have unique names")
                names.add(clean["name"])
                clean_fields.append(clean)
            out["fields"] = clean_fields
        if kind.startswith("function_"):
            expected = _text(out.get("expect", ""), "expect", 192, True).split()
            if not 1 <= len(expected) <= 64 or any(not re.fullmatch(r"[0-9a-fA-F]{2}", byte) for byte in expected):
                raise ValueError("function edits require 1..64 exact expected bytes; wildcards are refused")
            out["expect"] = " ".join(byte.upper() for byte in expected)
            if kind != "function_delete":
                ranges = out.get("ranges")
                if not isinstance(ranges, list) or not 1 <= len(ranges) <= 64:
                    raise ValueError("function ranges must contain 1..64 inclusive VA ranges")
                clean_ranges, occupied = [], []
                for item in ranges:
                    if not isinstance(item, dict) or set(item) != {"start", "end"}:
                        raise ValueError("each function range requires start and end VAs")
                    parsed = []
                    for key in ("start", "end"):
                        value = _text(item[key], "range " + key, 128, True)
                        if not _ADDRESS.fullmatch(value):
                            raise ValueError("range addresses must be numeric Ghidra VAs")
                        parsed.append(int(value.removeprefix("0x"), 16))
                    start, end = parsed
                    if end < start or any(start <= previous_end and end >= previous_start for previous_start, previous_end in occupied):
                        raise ValueError("function ranges must be ordered and non-overlapping")
                    occupied.append((start, end))
                    clean_ranges.append({"start": hex(start), "end": hex(end)})
                out["ranges"] = clean_ranges
    # Round-trip ensures callers cannot mutate a validated record through nested aliases.
    return json.loads(json.dumps(out))


def _overlay_path(root: str | Path, target_key: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", target_key):
        raise ValueError("invalid overlay target key")
    return Path(root) / "overlays" / (target_key + ".json")


def _digest(value: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("overlay requires a full SHA-256")
    return value.lower()


def _batch(value: dict, recorded: bool) -> dict:
    """Snapshot a caller's bounded JSON batch; replay never rereads its file."""
    if ("edits" in value) == ("file" in value):
        raise ValueError("batch requires exactly one of edits or file")
    result = {"kind": "batch", "source": value["source"]}
    if "file" in value:
        if set(value) & _BATCH_PROVENANCE:
            raise ValueError("input file provenance is computed, not supplied")
        path = Path(_text(value["file"], "batch file", 32768, True)).expanduser().resolve()
        with path.open("rb") as handle:
            data = handle.read(MAX_BATCH_BYTES + 1)
        if len(data) > MAX_BATCH_BYTES:
            raise ValueError("batch input exceeds 256 KiB")
        edits = json.loads(data.decode("utf-8-sig"))
        result.update(input_file=str(path), input_file_sha256=hashlib.sha256(data).hexdigest(), input_file_bytes=len(data))
    else:
        edits = value["edits"]
        if not recorded and len(json.dumps(edits, ensure_ascii=False).encode("utf-8")) > MAX_BATCH_BYTES:
            raise ValueError("batch input exceeds 256 KiB")
        provenance = set(value) & _BATCH_PROVENANCE
        if provenance:
            if not recorded or provenance != _BATCH_PROVENANCE:
                raise ValueError("batch provenance must be a complete normalized record")
            result.update(input_file=_text(value["input_file"], "input_file", 32768, True),
                          input_file_sha256=_digest(value["input_file_sha256"]),
                          input_file_bytes=_integer(value["input_file_bytes"], "input_file_bytes", 1, MAX_BATCH_BYTES))
    if not isinstance(edits, list) or not 1 <= len(edits) <= MAX_BATCH_EDITS:
        raise ValueError("batch must contain 1..200 edits")
    clean = []
    for index, item in enumerate(edits):
        if not isinstance(item, dict) or set(item) - {"address", "options"} or "options" not in item:
            raise ValueError("batch edit %d requires address and options" % index)
        child = item["options"]
        if not isinstance(child, dict) or child.get("kind") == "batch":
            raise ValueError("nested batches are refused")
        child = validate_options("type_edit", {"source": result["source"], **child}, _record=recorded)
        address = _text(item.get("address", ""), "batch address", 128)
        if address and not _ADDRESS.fullmatch(address):
            raise ValueError("batch addresses must be numeric Ghidra VAs")
        if child["kind"] != "struct" and not address:
            raise ValueError("batch edit %d requires a Ghidra VA" % index)
        clean.append({"address": address, "options": child})
    result["edits"] = clean
    return result


def _edit(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) - {"id", "address", "options"}:
        raise ValueError("overlay edit accepts id, address and options")
    options = validate_options("type_edit", value.get("options"), _record=True)
    address = _text(value.get("address", ""), "overlay address", 128)
    if address and not _ADDRESS.fullmatch(address):
        raise ValueError("overlay address must be a numeric Ghidra VA")
    if options["kind"] not in ("struct", "batch") and not address:
        raise ValueError("this type edit requires a Ghidra VA")
    edit_id = value.get("id") or uuid.uuid4().hex
    if not isinstance(edit_id, str) or not re.fullmatch(r"[0-9a-f]{32}", edit_id):
        raise ValueError("overlay id must be 32 lowercase hexadecimal characters")
    return {"id": edit_id, "address": address, "options": options}


def load_overlays(root: str | Path, target_key: str, sha256: str) -> list[dict]:
    """Read saved assertions. A changed build must never inherit stale types."""
    expected = _digest(sha256)
    path = _overlay_path(root, target_key)
    if not path.is_file():
        return []
    with path.open("rb") as handle:
        data = handle.read(MAX_HISTORY_BYTES + 1)
    if len(data) > MAX_HISTORY_BYTES:
        raise ValueError("overlay history exceeds 20 MiB; preserved for review")
    record = json.loads(data.decode("utf-8"))
    if not isinstance(record, dict) or record.get("version") != 1 or record.get("sha256") != expected:
        raise ValueError("type overlays belong to another build or format; preserve them and use a new target")
    edits = record.get("edits")
    if not isinstance(edits, list) or len(edits) > MAX_OVERLAYS:
        raise ValueError("overlay history must contain at most 4096 records")
    clean = [_edit(edit) for edit in edits]
    if len({edit["id"] for edit in clean}) != len(clean):
        raise ValueError("overlay history has duplicate edit identities")
    return clean


def save_overlay(root: str | Path, target_key: str, sha256: str, edit: dict) -> dict:
    """Append only AFTER the Java edit succeeded, while holding the target lock."""
    expected = _digest(sha256)
    clean = _edit(edit)
    edits = load_overlays(root, target_key, expected)
    if any(item["id"] == clean["id"] for item in edits):
        if next(item for item in edits if item["id"] == clean["id"]) != clean:
            raise ValueError("overlay id already records a different edit")
        return clean
    if len(edits) >= MAX_OVERLAYS:
        raise ValueError("overlay history limit reached; export/review it before adding more edits")
    payload = json.dumps({"version": 1, "sha256": expected, "edits": edits + [clean]}, indent=2).encode("utf-8")
    if len(payload) > MAX_HISTORY_BYTES:
        raise ValueError("overlay history would exceed 20 MiB; existing history preserved")
    path = _overlay_path(root, target_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)
    return clean
