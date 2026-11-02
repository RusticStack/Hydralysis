"""The vendored TRACE-1 JSON Schemas and a validator for the subset they use (stdlib only).

The schemas are owned by the engine (`Ghidra/Features/HeadlessSession/trace-schema/`); `hydralysis/trace_schema/` holds
byte-identical copies and `tests/test_trace_schema.py` fails when they differ from the engine's. The validator
supports exactly the keywords the schemas use: type, enum, const, pattern, minimum, maximum, minLength, maxLength,
required, properties, additionalProperties, items, minItems, maxItems, oneOf, anyOf. A schema that uses another keyword is
refused rather than half-checked.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

DIRECTORY = Path(__file__).resolve().parent / "trace_schema"
_IGNORED = {"$schema", "$id", "title", "description", "$comment", "examples", "default"}
_KNOWN = {"type", "enum", "const", "pattern", "minimum", "maximum", "minLength", "maxLength", "required", "properties",
          "additionalProperties", "items", "minItems", "maxItems", "oneOf", "anyOf"}
_TYPES = {"object": dict, "array": list, "string": str, "null": type(None), "boolean": bool}


def names() -> list[str]:
    return sorted(path.name for path in DIRECTORY.glob("*.json"))


@lru_cache(maxsize=None)
def load(name: str) -> dict:
    return json.loads((DIRECTORY / name).read_text("utf-8"))


def digest(name: str) -> str:
    """SHA-256 of the schema file's bytes with LF line ends (a checkout may convert them), as recorded with a session or an interpretation."""
    return hashlib.sha256((DIRECTORY / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _is(kind: str, value) -> bool:
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[kind]) and not (kind != "boolean" and isinstance(value, bool))


def errors(instance, schema: dict, path: str = "$") -> list[str]:
    unknown = set(schema) - _KNOWN - _IGNORED
    if unknown:
        raise ValueError("schema keyword not supported by the validator: %s" % ", ".join(sorted(unknown)))
    found: list[str] = []
    kinds = schema.get("type")
    if kinds is not None:
        kinds = [kinds] if isinstance(kinds, str) else kinds
        if not any(_is(kind, instance) for kind in kinds):
            return ["%s: expected %s" % (path, "/".join(kinds))]
    if "const" in schema and instance != schema["const"]:
        found.append("%s: must be %r" % (path, schema["const"]))
    if "enum" in schema and instance not in schema["enum"]:
        found.append("%s: must be one of %s" % (path, ", ".join(map(repr, schema["enum"]))))
    if isinstance(instance, str):
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            found.append("%s: does not match %s" % (path, schema["pattern"]))
        if len(instance) < schema.get("minLength", 0):
            found.append("%s: shorter than %d" % (path, schema["minLength"]))
        if len(instance) > schema.get("maxLength", len(instance)):
            found.append("%s: longer than %d" % (path, schema["maxLength"]))
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            found.append("%s: below %s" % (path, schema["minimum"]))
        if "maximum" in schema and instance > schema["maximum"]:
            found.append("%s: above %s" % (path, schema["maximum"]))
    if isinstance(instance, dict):
        for key in schema.get("required", ()):
            if key not in instance:
                found.append("%s: missing %s" % (path, key))
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                found += errors(value, properties[key], "%s.%s" % (path, key))
            elif schema.get("additionalProperties") is False:
                found.append("%s: unknown field %s" % (path, key))
            elif isinstance(schema.get("additionalProperties"), dict):
                found += errors(value, schema["additionalProperties"], "%s.%s" % (path, key))
    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            found.append("%s: fewer than %d items" % (path, schema["minItems"]))
        if len(instance) > schema.get("maxItems", len(instance)):
            found.append("%s: more than %d items" % (path, schema["maxItems"]))
        if "items" in schema:
            for index, item in enumerate(instance):
                found += errors(item, schema["items"], "%s[%d]" % (path, index))
    if "anyOf" in schema and not any(not errors(instance, option, path) for option in schema["anyOf"]):
        found.append("%s: matches none of the alternatives" % path)
    if "oneOf" in schema and sum(not errors(instance, option, path) for option in schema["oneOf"]) != 1:
        found.append("%s: must match exactly one alternative" % path)
    return found


def validate_event(event: dict) -> list[str]:
    """The reasons EVENT is not a valid producer event (empty when it is)."""
    return errors(event, load("event.schema.json"))
