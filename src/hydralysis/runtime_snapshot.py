"""Runtime snapshots and their comparison: pure functions over plain JSON, shared by the worker and the host.

A snapshot is a record of one moment of a session's target: its modules (name, base, size, file SHA-256), a thread
count, named memory regions (bytes and/or a typed decoding), the event counters and the log position. `compare`
flattens two snapshots to `path -> scalar` rows and reports the rows that differ after the volatile masks.

Volatile means "differs from run to run for reasons that are not the behavior under test": process ids, creation
times, load addresses, hook ids, sequence numbers. The default masks cover those; a caller adds its own. A mask
hides a difference from `equal`; it never deletes the row (`masked` counts them and predicates can still read them).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re

SNAPSHOT_ID = re.compile(r"^snap_[0-9a-f]{64}$")
SNAPSHOT_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,39}$")
VERSION = 1

# Paths (see `flatten`) that change between runs without the behavior changing.
DEFAULT_VOLATILE = (
    "snapshot", "session", "taken_at_ms", "sequence", "log_head", "counters/*", "hooks/*/hook_id", "hooks/*/address",
    "target/pid", "target/created_ms", "modules/*/base", "modules/*/path", "threads/*", "regions/*/address",
    "regions/*/range/base",
)
PREDICATE_OPS = ("unchanged", "changed", "increased", "decreased", "eq", "ne", "lt", "le", "gt", "ge", "between",
                 "present", "absent")
_NUMBER = (int, float)
MAX_MASKS = 64
MAX_PREDICATES = 64
SHOWN = 96


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def snapshot_id(record: dict) -> str:
    """`snap_` + SHA-256 of the record's canonical JSON without its own id."""
    body = {key: value for key, value in record.items() if key != "snapshot"}
    return "snap_" + hashlib.sha256(canonical(body)).hexdigest()


def _key(value) -> str:
    return str(value).replace("/", "_")


def flatten(record: dict) -> dict[str, object]:
    """`path -> scalar`. Lists of named rows are keyed by name (a module by lower-case name; a hook by module, export
    or RVA and kind), so two snapshots line up whatever the order they were taken in."""
    rows: dict[str, object] = {}

    def row_key(path: str, index: int, item) -> str:
        if isinstance(item, dict):
            if path == "hooks":
                where = item.get("export") or item.get("rva") or index
                return "%s:%s:%s" % (item.get("module", ""), where, item.get("kind", ""))
            name = item.get("name")
            if name is not None:
                return str(name).lower() if path == "modules" else str(name)
        return str(index)

    def walk(path: str, value) -> None:
        if isinstance(value, dict):
            for key in sorted(value):
                walk(path + "/" + _key(key) if path else _key(key), value[key])
        elif isinstance(value, list):
            seen: dict[str, int] = {}
            for index, item in enumerate(value):
                key = _key(row_key(path.rsplit("/", 1)[-1] if "/" in path else path, index, item))
                seen[key] = seen.get(key, 0) + 1
                walk("%s/%s" % (path, key if seen[key] == 1 else "%s#%d" % (key, seen[key])), item)
        else:
            rows[path] = value

    walk("", record)
    return rows


def _masked(path: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def stable_sha256(record: dict, mask=()) -> str:
    """SHA-256 of the record's rows without the default-volatile ones and `mask`: equal for two runs that agree."""
    patterns = DEFAULT_VOLATILE + tuple(mask)
    rows = {path: value for path, value in flatten(record).items() if not _masked(path, patterns)}
    return hashlib.sha256(canonical(rows)).hexdigest()


def _shown(value):
    if isinstance(value, str) and len(value) > SHOWN:
        return value[:SHOWN] + "...[%d chars, sha256 %s]" % (len(value), hashlib.sha256(value.encode()).hexdigest()[:16])
    return value


def check_mask(mask) -> list[str]:
    if mask is None:
        return []
    if not isinstance(mask, list) or len(mask) > MAX_MASKS or any(
            not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:*?/ #-]{1,200}", item) for item in mask):
        raise ValueError("mask is a list of at most %d path patterns (letters, digits, `_.:-/#`, `*` and `?`)" % MAX_MASKS)
    return list(mask)


def check_predicates(predicates) -> list[dict]:
    """The closed grammar: a list of {path, op, value?}. Anything else is refused, never evaluated."""
    if predicates is None:
        return []
    if not isinstance(predicates, list) or len(predicates) > MAX_PREDICATES:
        raise ValueError("predicates is a list of at most %d {path, op, value?}" % MAX_PREDICATES)
    clean = []
    for item in predicates:
        if not isinstance(item, dict) or set(item) - {"path", "op", "value"}:
            raise ValueError("a predicate is {path, op, value?} and nothing else")
        path, op = item.get("path"), item.get("op")
        if not isinstance(path, str) or not path or len(path) > 300:
            raise ValueError("a predicate's path is a snapshot path such as regions/config/fields/limit/value")
        if op not in PREDICATE_OPS:
            raise ValueError("predicate op must be one of %s" % ", ".join(PREDICATE_OPS))
        if op in ("eq", "ne", "lt", "le", "gt", "ge"):
            if "value" not in item or isinstance(item["value"], (dict, list)):
                raise ValueError("predicate %s needs a scalar value" % op)
            if op in ("lt", "le", "gt", "ge") and (isinstance(item["value"], bool) or not isinstance(item["value"], _NUMBER)):
                raise ValueError("predicate %s needs a number" % op)
        elif op == "between":
            value = item.get("value")
            if not (isinstance(value, list) and len(value) == 2 and all(
                    isinstance(x, _NUMBER) and not isinstance(x, bool) for x in value) and value[0] <= value[1]):
                raise ValueError("predicate between needs value [low, high]")
        elif "value" in item:
            raise ValueError("predicate %s takes no value" % op)
        clean.append({"path": path, "op": op, **({"value": item["value"]} if "value" in item else {})})
    return clean


def _number(value) -> bool:
    return isinstance(value, _NUMBER) and not isinstance(value, bool)


def _evaluate(predicate: dict, a_rows: dict, b_rows: dict) -> dict:
    path, op = predicate["path"], predicate["op"]
    has_a, has_b = path in a_rows, path in b_rows
    a, b = a_rows.get(path), b_rows.get(path)
    result = {**predicate, "a": _shown(a), "b": _shown(b)}
    if op == "present":
        ok = has_b
    elif op == "absent":
        ok = not has_b
    elif not (has_a and has_b):
        return {**result, "ok": False, "reason": "the path is not in %s" % ("both snapshots" if not (has_a or has_b) else
                                                                           "snapshot b" if has_a else "snapshot a")}
    elif op == "unchanged":
        ok = a == b
    elif op == "changed":
        ok = a != b
    elif op in ("increased", "decreased"):
        if not (_number(a) and _number(b)):
            return {**result, "ok": False, "reason": "not numbers"}
        ok = b > a if op == "increased" else b < a
    else:
        value = predicate["value"]
        if op in ("eq", "ne"):
            ok = (b == value) if op == "eq" else (b != value)
        elif not _number(b):
            return {**result, "ok": False, "reason": "snapshot b's value is not a number"}
        elif op == "between":
            ok = value[0] <= b <= value[1]
        else:
            ok = {"lt": b < value, "le": b <= value, "gt": b > value, "ge": b >= value}[op]
    return {**result, "ok": bool(ok)}


def compare(a: dict, b: dict, mask=(), predicates=(), use_default_mask: bool = True, limit: int = 200) -> dict:
    """What differs between two snapshots, and whether the predicates hold.

    `equal`: no unmasked row differs (a row only in one of them differs). `ok`: the predicates hold when there are
    any, else `equal`. `masked_differences` counts the differing rows a mask hid, so a mask is visible.
    """
    mask = check_mask(list(mask) if isinstance(mask, tuple) else mask)
    predicates = check_predicates(list(predicates) if isinstance(predicates, tuple) else predicates)
    patterns = (DEFAULT_VOLATILE if use_default_mask else ()) + tuple(mask)
    rows_a, rows_b = flatten(a), flatten(b)
    differences, masked, only_a, only_b = [], 0, [], []
    for path in sorted(set(rows_a) | set(rows_b)):
        in_a, in_b = path in rows_a, path in rows_b
        if in_a and in_b and rows_a[path] == rows_b[path]:
            continue
        if _masked(path, patterns):
            masked += 1
            continue
        differences.append({"path": path, "a": _shown(rows_a.get(path)), "b": _shown(rows_b.get(path)),
                            **({"only_in": "a"} if in_a and not in_b else {"only_in": "b"} if in_b and not in_a else {})})
        (only_a if in_a and not in_b else only_b if in_b and not in_a else []).append(path)
    verdicts = [_evaluate(predicate, rows_a, rows_b) for predicate in predicates]
    equal = not differences
    predicates_ok = all(item["ok"] for item in verdicts)
    return {"equal": equal, "ok": predicates_ok if predicates else equal, "differences": differences[:limit],
            "difference_count": len(differences), "truncated": len(differences) > limit,
            "masked_differences": masked, "mask": list(patterns), "only_in_a": only_a[:20], "only_in_b": only_b[:20],
            "predicates": verdicts, "rows_compared": len(set(rows_a) | set(rows_b)),
            "a": {"snapshot": a.get("snapshot"), "stable_sha256": stable_sha256(a, mask)},
            "b": {"snapshot": b.get("snapshot"), "stable_sha256": stable_sha256(b, mask)}}
