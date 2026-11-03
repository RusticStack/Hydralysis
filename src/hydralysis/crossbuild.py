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
the source, review-required destination candidates with their provenance.
A candidate is not evidence that it is the same function or a hook-ready check.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from pathlib import Path

from hydralysis import targets
from hydralysis.pe import Image
from hydralysis.prologue import format_bytes, matches, parse_expect
from hydralysis.paths import root_path

CONFIDENCE = {"exact": 1.0, "shape": 0.9, "anchors": 0.8, "callees": 0.8, "strings": 0.75, "callgraph": 0.7, "callers": 0.6}
_DEFAULT_NAME = ("FUN_", "LAB_", "thunk_FUN_", "SUB_")
# RusticQuery stops after seeing instruction 20,001; only the first 20,000
# are hashed. A matching prefix does not establish full-body equivalence.
FINGERPRINT_INSTRUCTION_LIMIT = 20000


def fingerprint_complete(row: dict) -> bool:
    return row["instructions"] <= FINGERPRINT_INSTRUCTION_LIMIT


def fingerprint_code() -> str:
    """The fingerprint method's own source: other edits to the script keep the cache."""
    text = Path(__file__).with_name("scripts").joinpath("RusticQuery.java").read_text(encoding="utf-8")
    start = text.index("// ---- per-function fingerprints")
    end = text.index("// ---- bulk types from a corpus", start)
    return hashlib.sha256(text[start:end].encode("utf-8")).hexdigest()[:16]


def fingerprints(settings: dict, name: str, engine=None, view: str = "") -> Path:
    """The target's fingerprint file, computed once per build and fingerprint code."""
    from hydralysis import hydra, workcopy
    from hydralysis.locks import locked
    from hydralysis.query import QueryRunner, run_script
    selected = workcopy.with_view(targets.resolve(settings, name), view)
    state = workcopy.state_of(workcopy.load_store(settings, selected))
    directory = root_path(settings) / "fingerprints"
    directory.mkdir(parents=True, exist_ok=True)
    state_key = "%s-%s" % (state["revision"], state["ids_sha256"][:16])
    path = directory / ("%s-%s-%s-%s.jsonl" %
                        (selected["sha256"][:16], selected["key"], fingerprint_code(), state_key))
    with locked(path.with_suffix(".lock"), timeout_s=5, what="fingerprint"):
        if workcopy.state_of(workcopy.load_store(settings, selected)) != state:
            raise RuntimeError("overlays changed before fingerprinting; retry the diff")
        if not path.is_file():
            runner = QueryRunner(settings, engine or hydra.Engine(settings))
            program = runner.program_for(selected)
            request = {"id": "fp", "action": "fingerprints", "address": "", "limit": 1, "cursor": "", "contains": "",
                       "timeout_s": 4 * 3600, "options": {"artifact": str(path)}, "expected_sha256": selected["sha256"]}
            response, _ = run_script(runner.engine, program, request, 4 * 3600)
            if not response.get("ok") or not path.is_file():
                raise RuntimeError("fingerprints for %s failed: %s" % (name, response.get("error")))
        if workcopy.state_of(workcopy.load_store(settings, selected)) != state:
            raise RuntimeError("overlays changed during fingerprinting; retry the diff")
    return path


def load(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            rows[row["rva"]] = row
    return rows


def _unique(rows: dict[str, dict], key, excluded=()) -> dict:
    # One RVA is enough until a second row makes a key ambiguous. Avoid a
    # list per fingerprint and a full filtered copy of both programs per phase.
    unique = {}
    for rva, row in rows.items():
        if rva in excluded:
            continue
        value = key(row)
        if value:
            if value in unique:
                unique[value] = None
            else:
                unique[value] = rva
    return {value: rva for value, rva in unique.items() if rva is not None}


def identical_code(a: dict, b: dict) -> bool:
    """The same code, wherever it sits: equal bytes, or the same instruction shape (addresses
    masked) with the same size, strings, imports and constants. A call displacement or a
    RIP-relative offset that only moved with the layout is not a change."""
    if not fingerprint_complete(a) or not fingerprint_complete(b):
        return False
    if a["bytes"] == b["bytes"]:
        return True
    return (a["shape"] == b["shape"] and a["size"] == b["size"] and a["strings"] == b["strings"]
            and a["imports"] == b["imports"] and a["constants"] == b["constants"])


def _string_prefixes(row: dict) -> tuple | None:
    """A changed function usually keeps nearly the same strings ("build one" -> "build two"):
    the digests of the first 12 characters of each string of at least 12 (fingerprint heads)."""
    heads = row.get("heads") or []
    return tuple(heads) if heads else None


def _similar(a: dict, b: dict, ratio: float = 0.3) -> bool:
    small, large = sorted((a["size"], b["size"]))
    return large == 0 or (large - small) / large <= ratio


def match(source: dict[str, dict], destination: dict[str, dict]) -> dict[str, tuple[str, str]]:
    """source RVA -> (destination RVA, method)."""
    pairs: dict[str, tuple[str, str]] = {}
    taken: set[str] = set()

    def phase(method, key, check=None, right_key=None):
        a = _unique(source, key, pairs)
        b = _unique(destination, right_key or key, taken)
        for value, rva in a.items():
            other = b.get(value)
            if other and (check is None or check(source[rva], destination[other])):
                pairs[rva] = (other, method)
                taken.add(other)

    # Tiny functions (a ret, a jump, a refcount release) collide across a whole program: identical
    # bytes alone are trusted only for bodies large enough to be distinctive.
    phase("exact", lambda row: row["bytes"] if row["size"] >= 24 and fingerprint_complete(row) else None)
    phase("exact", lambda row: (row["bytes"], tuple(row["strings"]), tuple(row["imports"])) if row["size"] >= 8 and fingerprint_complete(row) and (row["strings"] or row["imports"]) else None)
    phase("shape", lambda row: (row["shape"], row["size"]) if row["instructions"] >= 6 and fingerprint_complete(row) else None)
    phase("anchors", lambda row: (tuple(row["strings"]), tuple(row["imports"])) if row["strings"] or len(row["imports"]) >= 2 else None, _similar)
    phase("anchors", lambda row: (tuple(row["constants"]), row["instructions"] // 4) if len(row["constants"]) >= 2 else None, _similar)
    phase("shape", lambda row: row["shape"] if row["instructions"] >= 12 and fingerprint_complete(row) else None, _similar)
    phase("strings", _string_prefixes, lambda a, b: _similar(a, b, 0.9))
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
        # Proposals first: a destination function claimed by two unmatched source functions is
        # nobody's (a removed function must not take the place of a changed one).
        proposals: dict[str, list[str]] = defaultdict(list)
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
                proposals[candidates.pop()].append(rva)
        added = 0
        for other, claimants in proposals.items():
            if len(claimants) == 1:
                pairs[claimants[0]] = (other, "callers")
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
    checks = record["options"].get("checks")
    prepared = source_image = destination_image = None
    from hydralysis import workcopy
    source_target = workcopy.with_view(targets.resolve(settings, source_name), record["options"].get("against_view", ""))
    destination_target = workcopy.with_view(targets.resolve(settings, destination_name), record.get("view", ""))
    if checks:
        source_image = _target_image(source_target)
        destination_image = _target_image(destination_target)
        prepared = _prepare_checks(checks, source_image)
    source_state = workcopy.state_of(workcopy.load_store(settings, source_target))
    destination_state = workcopy.state_of(workcopy.load_store(settings, destination_target))
    source = load(fingerprints(settings, source_name, view=source_target["view"]))
    destination = load(fingerprints(settings, destination_name, view=destination_target["view"]))
    if (workcopy.state_of(workcopy.load_store(settings, source_target)) != source_state or
            workcopy.state_of(workcopy.load_store(settings, destination_target)) != destination_state):
        raise RuntimeError("overlays changed during diff; retry with stable overlays")
    pairs = match(source, destination)
    output.mkdir(parents=True, exist_ok=True)
    counts = defaultdict(int)
    names = []
    with (output / "diff.jsonl").open("w", encoding="utf-8", newline="\n") as report:
        for rva, row in source.items():
            if rva in pairs:
                other, method = pairs[rva]
                complete = fingerprint_complete(row) and fingerprint_complete(destination[other])
                same = identical_code(row, destination[other])
                status = ("same" if rva == other else "moved") if same else "changed" if complete else "incomplete"
                counts[status] += 1
                counts["by_" + method] += 1
                report.write(json.dumps({"source": rva, "destination": other, "status": status, "method": method,
                                         "confidence": confidence(method, row), "name": row["name"],
                                         "destination_name": destination[other]["name"], "fingerprint_complete": complete}) + "\n")
                if _named(row) and not _named(destination[other]):
                    names.append({"kind": "function", "address": "rva:" + other, "name": row["name"].replace("::", "_"),
                                  "comment": "REVIEW candidate from %s sha256:%s rva:%s (%s, confidence %.2f); verify correspondence"
                                             % (source_name, source_target["sha256"], rva, method, confidence(method, row))})
            else:
                counts["gone"] += 1
                report.write(json.dumps({"source": rva, "status": "gone", "name": row["name"],
                                         "fingerprint_complete": fingerprint_complete(row)}) + "\n")
        matched = {other for other, _ in pairs.values()}
        for rva, row in destination.items():
            if rva not in matched:
                counts["new"] += 1
                report.write(json.dumps({"destination": rva, "status": "new", "name": row["name"],
                                         "fingerprint_complete": fingerprint_complete(row)}) + "\n")
    with (output / "names.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for item in names:
            handle.write(json.dumps(item) + "\n")
    summary = {"source": source_name, "destination": destination_name,
               "source_view": source_target["view"], "destination_view": destination_target["view"],
               "source_overlay_state": source_state, "destination_overlay_state": destination_state,
               "source_functions": len(source),
               "destination_functions": len(destination), "matched": len(pairs), **dict(counts),
               "names_to_transfer": len(names), "seconds": round(time.monotonic() - started, 1),
               "files": {"diff": str(output / "diff.jsonl"), "names_corpus": str(output / "names.jsonl")}}
    overlay_report = _export_overlay_candidates(settings, source_target, destination_target, pairs, source, source_image, output)
    if overlay_report:
        summary["overlays"] = overlay_report
    if checks:
        summary["checks"] = transfer_checks(prepared, pairs, source, destination, source_image, destination_image,
                                            output / "checks-destination.json")
    if (workcopy.state_of(workcopy.load_store(settings, source_target)) != source_state or
            workcopy.state_of(workcopy.load_store(settings, destination_target)) != destination_state):
        raise RuntimeError("overlays changed during diff; retry with stable overlays")
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _export_overlay_candidates(settings: dict, source_target: dict, destination_target: dict,
                               pairs: dict, source: dict, source_image: Image | None, output: Path) -> dict | None:
    """Export the cited source records for review, never apply them to another build."""
    from hydralysis import workcopy
    store = workcopy.load_store(settings, source_target)
    if not store["edits"] and not store["reverted"]:
        return None
    if source_image is None and source_target.get("exe"):
        source_image = _target_image(source_target)
    exported = []
    for edit in store["edits"]:
        item = {"source_record": edit, "review_required": True}
        address = edit.get("address")
        if address and source_image:
            try:
                rva = int(address, 16) - source_image.base
            except ValueError:
                rva = -1
            key = "0x%x" % rva if rva >= 0 else ""
            if key in pairs and key in source:
                other, method = pairs[key]
                item["candidate"] = {"source_address": "rva:" + key, "destination_address": "rva:" + other,
                                     "method": method, "confidence": confidence(method, source[key])}
        exported.append(item)
    report = {"kind": "crossbuild-overlay-review", "review_required": True,
              "source_sha256": source_target["sha256"], "destination_sha256": destination_target["sha256"],
              "source_view": source_target.get("view", "shared"), "source_revision": store["revision"],
              "edits": exported, "reverted": store["reverted"],
              "instructions": "Original cited records are source-build evidence only. Independently verify "
                              "destination correspondence and type layouts before creating destination edits. "
                              "Reverted entries contain audit metadata, not the removed record bodies."}
    path = output / "overlays-source-review.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {"file": str(path), "active": len(exported), "reverted_events": len(store["reverted"]),
            "review_required": True}


def _target_image(target: dict) -> Image:
    """Require the actual executable when accepting a hook table, not just a project hash."""
    if not target.get("exe"):
        raise ValueError("cross-build checks need the registered executable for %s" % target["name"])
    image = Image(Path(target["exe"]))
    if image.fingerprint()["sha256"].lower() != target["sha256"].lower():
        raise ValueError("target %s executable does not match its registered build hash" % target["name"])
    return image


def _number(value, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError("%s must be a non-negative number" % label)
    try:
        result = value if isinstance(value, int) else int(value, 0)
    except (TypeError, ValueError):
        raise ValueError("%s must be a non-negative number" % label) from None
    if result < 0:
        raise ValueError("%s must be a non-negative number" % label)
    return result


def _source_rva(value, image: Image, kind: str | None) -> int:
    if isinstance(value, str) and ":" in value:
        prefix, value = value.split(":", 1)
        prefix = prefix.lower()
        if prefix not in ("rva", "va"):
            raise ValueError("address must use rva: or va:")
        if kind and kind != prefix:
            raise ValueError("address prefix conflicts with offset_kind")
        kind = prefix
    number = _number(value, "source address")
    if kind not in (None, "rva", "va"):
        raise ValueError("offset_kind must be rva or va")
    if kind == "rva":
        return number
    if kind == "va":
        if number < image.base:
            raise ValueError("source VA is below the image base")
        return number - image.base
    # An unqualified legacy offset is usable only when precisely one interpretation
    # is file-backed. Both can be valid in unusually large or low-base images.
    candidates = {rva for rva in (number, number - image.base) if rva >= 0 and image.rva_to_offset(rva) is not None}
    if len(candidates) != 1:
        raise ValueError("source address is ambiguous or outside file-backed sections; specify rva: or va:")
    return next(iter(candidates))


def _prepare_checks(path: str, image: Image) -> list[dict]:
    """Validate the whole source table against its selected immutable build first."""
    filename = Path(path)
    if filename.stat().st_size > 1024 * 1024:
        raise ValueError("checks file must be at most 1 MiB")
    value = json.loads(filename.read_text(encoding="utf-8-sig"))
    envelope = value if isinstance(value, dict) else {}
    rows = envelope.get("checks", envelope.get("hooks")) if envelope else value
    if not isinstance(rows, list) or not 1 <= len(rows) <= 200:
        raise ValueError("cross-build checks need 1..200 rows in checks[] or hooks[]")
    declared = envelope.get("build_sha256", envelope.get("sha256"))
    if declared is not None:
        if not isinstance(declared, str) or len(declared) != 64 or any(c not in "0123456789abcdefABCDEF" for c in declared):
            raise ValueError("declared build hash must be the full 64-hex SHA-256")
        if declared.lower() != image.fingerprint()["sha256"].lower():
            raise ValueError("source table build hash does not match the registered executable")
    if "image_base" in envelope and _number(envelope["image_base"], "image_base") != image.base:
        raise ValueError("source table image_base does not match the registered executable")
    kind = envelope.get("offset_kind")
    prepared = []
    total = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError("source check %d must be an object" % index)
        if ("address" in row) == ("offset" in row):
            raise ValueError("source check %d needs exactly one address or offset" % index)
        rva = _source_rva(row.get("address", row.get("offset")), image, kind)
        expected = row.get("expect", row.get("prologues", row.get("prologue")))
        alternatives = expected if isinstance(expected, list) else [expected]
        if not 1 <= len(alternatives) <= 16:
            raise ValueError("source check %d needs 1..16 expected prologues" % index)
        patterns = [parse_expect(item) for item in alternatives]
        if max(map(len, patterns)) > 4096:
            raise ValueError("source check %d exceeds 4096 bytes" % index)
        total += sum(map(len, patterns))
        if total > 65536:
            raise ValueError("source checks exceed 65536 total bytes")
        actual = image.read_rva(rva, max(map(len, patterns)))
        match = next((pattern for pattern in patterns if matches(actual, pattern)), None)
        if match is None:
            raise ValueError("source check %d prologue mismatch at rva:%#x" % (index, rva))
        names = row.get("names", row.get("name", ""))
        if isinstance(names, str):
            names = [names] if names else []
        if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
            raise ValueError("source check %d names must be strings" % index)
        prepared.append({"rva": "0x%x" % rva, "names": names, "record": row,
                         "source_prologue": format_bytes(actual[:len(match)]),
                         "source_pattern_has_wildcards": any(byte is None for byte in match)})
    return prepared


def transfer_checks(prepared: list[dict], pairs: dict, source: dict, destination: dict,
                    source_image: Image, destination_image: Image, out: Path) -> dict:
    """Write evidence-bearing candidates, never a hook-ready prologue table.

    Destination bytes describe the candidate and cannot prove the correspondence.
    A reviewer must independently establish it and create a separate checks table.
    """
    candidates, missing = [], []
    for item in prepared:
        rva = item["rva"]
        common = {"name": item["names"][0] if item["names"] else "", "names": item["names"],
                  "source_address": "rva:" + rva, "source_record": item["record"],
                  "source_prologue": item["source_prologue"],
                  "source_pattern_has_wildcards": item["source_pattern_has_wildcards"]}
        if rva not in pairs:
            missing.append(common)
            continue
        other, method = pairs[rva]
        try:
            length = min(24, destination_image._available(int(other, 16)))
            if length <= 0:
                raise ValueError("no file-backed destination bytes")
            actual = destination_image.read_rva(int(other, 16), length)
        except ValueError:
            missing.append({**common, "proposed_destination": "rva:" + other,
                            "method": method, "reason": "destination has no file-backed prologue"})
            continue
        candidates.append({**common, "address": "rva:" + other,
                           "observed_destination_prologue": format_bytes(actual),
                           "method": method, "confidence": confidence(method, source[rva]),
                           "review_required": True})
    document = {"kind": "crossbuild-hook-candidates", "review_required": True,
                "source_build": source_image.fingerprint(), "destination_build": destination_image.fingerprint(),
                "candidates": candidates, "unplaced": missing,
                "instructions": "Independently verify each correspondence and its destination bytes, cite the evidence, "
                                "then create a separate prologue checks table. These candidates are not hook-ready."}
    out.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return {"rows": len(prepared), "candidates": len(candidates), "unplaced": len(missing),
            "review_required": True, "file": str(out)}


# --- HYDRALYSIS_IMPL=rust ----------------------------------------------------------------------------------------
def _delegating_match(python_impl):
    def match_(source, destination):
        import os
        if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() == "rust":
            try:
                import hydralysis_native as native
                text = native.crossbuild_match_rs(json.dumps(source), json.dumps(destination))
            except (ImportError, AttributeError, TypeError, ValueError):
                text = None
            if text is not None:
                return {rva: (other, method) for rva, other, method in json.loads(text)}
        return python_impl(source, destination)
    match_.__name__ = python_impl.__name__
    match_.__doc__ = python_impl.__doc__
    return match_


match = _delegating_match(match)
