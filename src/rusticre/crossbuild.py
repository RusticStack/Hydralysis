"""Whole-program diff between two analysed builds, and transfer of what is known.

Each build is fingerprinted once (one script pass, cached by program SHA-256 and
the fingerprint code): per function its raw-byte hash, its instruction shape
with addresses masked, the strings, imports and constants it references, its
direct callees and its prologue. Matching then runs in phases, each accepting
only one-to-one candidates:

  exact      the same bytes (moved if the RVA differs)
  shape      the same instruction shape and size
  anchors    the same referenced strings, imports or constants, similar size
  callgraph  the k-th callee of a matched pair, where both sides agree

Every pair names its method and confidence; what stays unmatched is new (only
in the destination) or gone (only in the source). The job writes the full report
as JSONL, a summary, a type corpus of names to transfer (applied as one
import_types overlay: revertible in one step), and, given a prologue table for
the source, the same table re-addressed for the destination.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path

from rusticre import targets
from rusticre.paths import root_path

CONFIDENCE = {"exact": 1.0, "shape": 0.9, "anchors": 0.8, "callees": 0.8, "callgraph": 0.7, "callers": 0.6}
_DEFAULT_NAME = ("FUN_", "LAB_", "thunk_FUN_", "SUB_")


def fingerprint_code() -> str:
    """The fingerprint method's own source: other edits to the script keep the cache."""
    text = Path(__file__).with_name("scripts").joinpath("RusticQuery.java").read_text(encoding="utf-8")
    start = text.index("// ---- per-function fingerprints")
    end = text.index("// ---- bulk types from a corpus", start)
    return hashlib.sha256(text[start:end].encode("utf-8")).hexdigest()[:16]


def fingerprints(settings: dict, name: str, engine=None) -> Path:
    """The target's fingerprint file, computed once per build and fingerprint code."""
    from rusticre import hydra
    from rusticre.query import QueryRunner, run_script
    selected = targets.resolve(settings, name)
    directory = root_path(settings) / "fingerprints"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ("%s-%s-%s.jsonl" % (selected["sha256"][:16], selected["key"], fingerprint_code()))
    if path.is_file():
        return path
    runner = QueryRunner(settings, engine or hydra.Engine(settings))
    program = runner.program_for(selected)
    request = {"id": "fp", "action": "fingerprints", "address": "", "limit": 1, "cursor": "", "contains": "",
               "timeout_s": 4 * 3600, "options": {"artifact": str(path)}, "expected_sha256": selected["sha256"]}
    response, _ = run_script(runner.engine, program, request, 4 * 3600)
    if not response.get("ok") or not path.is_file():
        raise RuntimeError("fingerprints for %s failed: %s" % (name, response.get("error")))
    return path


def load(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            rows[row["rva"]] = row
    return rows


def _unique(rows: dict[str, dict], key) -> dict:
    groups = defaultdict(list)
    for rva, row in rows.items():
        value = key(row)
        if value:
            groups[value].append(rva)
    return {value: items[0] for value, items in groups.items() if len(items) == 1}


def _similar(a: dict, b: dict, ratio: float = 0.3) -> bool:
    small, large = sorted((a["size"], b["size"]))
    return large == 0 or (large - small) / large <= ratio


def match(source: dict[str, dict], destination: dict[str, dict]) -> dict[str, tuple[str, str]]:
    """source RVA -> (destination RVA, method)."""
    pairs: dict[str, tuple[str, str]] = {}
    taken: set[str] = set()

    def phase(method, key, check=None, right_key=None):
        left = {rva: row for rva, row in source.items() if rva not in pairs}
        right = {rva: row for rva, row in destination.items() if rva not in taken}
        a, b = _unique(left, key), _unique(right, right_key or key)
        for value, rva in a.items():
            other = b.get(value)
            if other and (check is None or check(source[rva], destination[other])):
                pairs[rva] = (other, method)
                taken.add(other)

    # Tiny functions (a ret, a jump, a refcount release) collide across a whole program: identical
    # bytes alone are trusted only for bodies large enough to be distinctive.
    phase("exact", lambda row: row["bytes"] if row["size"] >= 24 else None)
    phase("exact", lambda row: (row["bytes"], tuple(row["strings"]), tuple(row["imports"])) if row["size"] >= 8 and (row["strings"] or row["imports"]) else None)
    phase("shape", lambda row: (row["shape"], row["size"]) if row["instructions"] >= 6 else None)
    phase("anchors", lambda row: (tuple(row["strings"]), tuple(row["imports"])) if row["strings"] or len(row["imports"]) >= 2 else None, _similar)
    phase("anchors", lambda row: (tuple(row["constants"]), row["instructions"] // 4) if len(row["constants"]) >= 2 else None, _similar)
    phase("shape", lambda row: row["shape"] if row["instructions"] >= 12 else None, _similar)
    # Call graph: the k-th callee of a matched pair, when both are unmatched and alike.
    for _ in range(8):
        added = 0
        for rva, (other, _method) in list(pairs.items()):
            left, right = source[rva]["callees"], destination[other]["callees"]
            if len(left) != len(right):
                continue
            for callee, counterpart in zip(left, right):
                if callee in pairs or counterpart in taken or callee not in source or counterpart not in destination:
                    continue
                if _similar(source[callee], destination[counterpart], 0.25):
                    pairs[callee] = (counterpart, "callgraph")
                    taken.add(counterpart)
                    added += 1
        if not added:
            break
    # Callees: two or more direct callees, all matched, map to exactly the callees of one
    # unmatched destination function.
    for _ in range(4):
        before = len(pairs)
        translated = lambda row: (tuple(sorted(pairs[callee][0] for callee in set(row["callees"])))
                                  if len(set(row["callees"])) >= 2 and all(callee in pairs for callee in row["callees"]) else None)
        own = lambda row: tuple(sorted(set(row["callees"]))) if len(set(row["callees"])) >= 2 else None
        phase("callees", translated, lambda a, b: _similar(a, b, 0.5), own)
        if len(pairs) == before:
            break
    # Callers: a function's matched callers narrow its candidates to their unmatched callees;
    # exactly one alike candidate is a match.
    callers_of = defaultdict(set)
    for rva, row in source.items():
        for callee in row["callees"]:
            callers_of[callee].add(rva)
    for _ in range(4):
        added = 0
        for rva, row in source.items():
            if rva in pairs:
                continue
            known = [pairs[caller][0] for caller in callers_of.get(rva, ()) if caller in pairs]
            if not known:
                continue
            candidates = None
            for caller in known:
                options = {callee for callee in destination[caller]["callees"]
                           if callee in destination and callee not in taken and _similar(row, destination[callee], 0.35)}
                candidates = options if candidates is None else candidates & options
            if candidates and len(candidates) == 1:
                other = candidates.pop()
                pairs[rva] = (other, "callers")
                taken.add(other)
                added += 1
        if not added:
            break
    return pairs


def confidence(method: str, row: dict) -> float:
    """Identical bytes of a small body can be another function's (template copies)."""
    value = CONFIDENCE[method]
    return min(value, 0.85) if method == "exact" and row["size"] < 64 else value


def _named(row: dict) -> bool:
    return row["source"] in ("USER_DEFINED", "IMPORTED") and not row["name"].startswith(_DEFAULT_NAME)


def run(settings: dict, record: dict, output: Path) -> dict:
    """Diff source -> destination; record holds source, destination and options."""
    started = time.monotonic()
    source_name, destination_name = record["options"]["against"], record["target"]
    source = load(fingerprints(settings, source_name))
    destination = load(fingerprints(settings, destination_name))
    pairs = match(source, destination)
    output.mkdir(parents=True, exist_ok=True)
    counts = defaultdict(int)
    names = []
    with (output / "diff.jsonl").open("w", encoding="utf-8", newline="\n") as report:
        for rva, row in source.items():
            if rva in pairs:
                other, method = pairs[rva]
                same = row["bytes"] == destination[other]["bytes"]
                status = ("same" if rva == other else "moved") if same else "changed"
                counts[status] += 1
                counts["by_" + method] += 1
                report.write(json.dumps({"source": rva, "destination": other, "status": status, "method": method,
                                         "confidence": confidence(method, row), "name": row["name"],
                                         "destination_name": destination[other]["name"]}) + "\n")
                if _named(row) and not _named(destination[other]):
                    names.append({"kind": "function", "address": "rva:" + other, "name": row["name"].replace("::", "_"),
                                  "comment": "from %s %s (%s, confidence %.1f)" % (source_name, rva, method, CONFIDENCE[method])})
            else:
                counts["gone"] += 1
                report.write(json.dumps({"source": rva, "status": "gone", "name": row["name"]}) + "\n")
        matched = {other for other, _ in pairs.values()}
        for rva, row in destination.items():
            if rva not in matched:
                counts["new"] += 1
                report.write(json.dumps({"destination": rva, "status": "new", "name": row["name"]}) + "\n")
    with (output / "names.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for item in names:
            handle.write(json.dumps(item) + "\n")
    summary = {"source": source_name, "destination": destination_name, "source_functions": len(source),
               "destination_functions": len(destination), "matched": len(pairs), **dict(counts),
               "names_to_transfer": len(names), "seconds": round(time.monotonic() - started, 1),
               "files": {"diff": str(output / "diff.jsonl"), "names_corpus": str(output / "names.jsonl")}}
    checks = record["options"].get("checks")
    if checks:
        summary["checks"] = transfer_checks(checks, pairs, destination, output / "checks-destination.json")
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def transfer_checks(path: str, pairs: dict, destination: dict, out: Path) -> dict:
    """A source prologue table, re-addressed for the destination with its current prologues."""
    rows = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    rows = rows.get("checks", rows) if isinstance(rows, dict) else rows
    placed, missing = [], []
    for row in rows:
        address = str(row.get("address", ""))
        rva = "0x%x" % int(address.split(":", 1)[1] if ":" in address else address, 16)
        if rva in pairs:
            other, method = pairs[rva]
            placed.append({"name": row.get("name", ""), "address": "rva:" + other, "expect": destination[other]["prologue"],
                           "source_address": "rva:" + rva, "method": method, "confidence": CONFIDENCE[method]})
        else:
            missing.append({"name": row.get("name", ""), "source_address": "rva:" + rva})
    out.write_text(json.dumps({"checks": placed, "unplaced": missing}, indent=2), encoding="utf-8")
    return {"rows": len(rows), "placed": len(placed), "unplaced": len(missing), "file": str(out)}
