#!/usr/bin/env python3
"""Golden decompile diff harness (docs/golden-harness.md).

Captures what a decompiler says about every function of an analysed program, and compares two
captures. It exists to gate changes to the decompiler or the type system (an upstream Ghidra
merge, an engine release) with evidence instead of a hunch.

  capture      engine + project + program -> a capture directory (rows.jsonl, c.jsonl.gz)
  capture-set  capture every program of a set file
  diff         two capture directories -> report.json + pass/fail gate (exit 1 on fail)
  timing       size-bucketed decompile timing table of a capture
  treehash     sha256 of every file of a tree (proves a source project was never written)
  project-copy copy a project and prove the copy is byte-identical
  prepare      import + analyse executables through RusticRE's own preparation path

Everything a capture holds is derived from the analysed binary. It stays local: never commit a
capture, never attach one to an issue. The normaliser and the diff themselves are pure and are
tested on synthetic captures (tests/test_golden.py).
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import gzip
import hashlib
import json
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SCHEMA = 1

# ---------------------------------------------------------------------------------------------
# Normaliser
#
# Two decompiler runs can differ without differing in meaning: whitespace, the numbering the
# decompiler gives its temporaries, the stack offsets it names locals by, the addresses inside
# its warning comments. "identical after normalisation" must never hide a real change, so the
# normaliser is conservative and every rule is an alpha-renaming or a formatting rule:
#
#   whitespace  line endings, trailing blanks, runs of blank lines, leading/trailing blank lines
#   standard    + standalone comment lines/blocks other than "/* WARNING ..." (banners)
#               + hex addresses inside the kept WARNING comments
#               + temporaries (iVar3, pcVar2, ...) and stack names (local_10, uStack_8,
#                 in_stack_ffffffc8, local_res4) renumbered by first appearance, per family,
#                 outside string and character literals
#
# NOT normalised, so a change shows as `changed`: DAT_/FUN_/LAB_/PTR_ names and every other
# address, types, casts, operators, statement order, parameter names (param_1), function names,
# end-of-line comments, the text of WARNING comments.
# ---------------------------------------------------------------------------------------------

LEVELS = ("raw", "whitespace", "standard")
_TEMP = r"(?P<tp>[A-Za-z]{0,8}Var)(?P<tn>\d+)"
_STACK = r"(?P<sp>local_res|local_|in_stack_|[A-Za-z]{1,6}Stack_)(?P<sn>[0-9a-fA-F]+)"
_LITERAL = r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'"
_NAMES = re.compile(r"(?P<lit>%s)|\b(?:%s|%s)\b" % (_LITERAL, _TEMP, _STACK))
_HEX = re.compile(r"0x[0-9a-fA-F]+")
_BLOCK_START = re.compile(r"^\s*/\*")


def _whitespace(text: str) -> str:
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    out: list[str] = []
    for line in lines:
        if not line and (not out or not out[-1]):
            continue
        out.append(line)
    while out and not out[-1]:
        out.pop()
    return "\n".join(out)


def _strip_banners(text: str) -> str:
    """Drop standalone comment lines and blocks, keep (address-masked) WARNING comments."""
    out: list[str] = []
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if stripped.startswith("//"):
            index += 1
            continue
        if _BLOCK_START.match(line):
            end = index
            while "*/" not in lines[end] and end + 1 < len(lines):
                end += 1
            tail = lines[end].split("*/", 1)[1].strip() if "*/" in lines[end] else "x"
            if tail == "":  # a comment and nothing else on its last line: standalone
                block = lines[index:end + 1]
                if stripped.startswith("/* WARNING") or stripped.startswith("/*WARNING"):
                    out.extend(_HEX.sub("0xADDR", item) for item in block)
                index = end + 1
                continue
        out.append(line)
        index += 1
    return "\n".join(out)


def _rename(text: str) -> str:
    """Alpha-rename temporaries and stack names by first appearance within each family."""
    seen: dict[str, dict[str, int]] = {}

    def take(match: re.Match) -> str:
        if match.group("lit") is not None:
            return match.group(0)
        if match.group("tp") is not None:
            family, label = "T:" + match.group("tp"), match.group("tp")
        else:
            family, label = "S:" + match.group("sp"), match.group("sp")
        names = seen.setdefault(family, {})
        name = match.group(0)
        if name not in names:
            names[name] = len(names) + 1
        return "%s<%d>" % (label, names[name])

    return _NAMES.sub(take, text)


def normalise(text: str, level: str = "standard") -> str:
    if level not in LEVELS:
        raise ValueError("level must be one of %s" % ", ".join(LEVELS))
    if level == "raw":
        return text
    text = _whitespace(text)
    if level == "whitespace":
        return text
    text = _strip_banners(text)
    text = _rename(text)
    return _whitespace(text)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_entry(value) -> str:
    text = str(value).strip().lower()
    if ":" in text:
        text = text.rsplit(":", 1)[1]
    return "0x%x" % int(text.removeprefix("0x"), 16)


# ---------------------------------------------------------------------------------------------
# Capture directories
#
#   rows.jsonl    line 1: {"type": "header", ...}; then one {"type": "function", ...} per function:
#                 entry, name, size, status (ok|failed|timeout|error), ms, c_sha256,
#                 normalized_c_sha256 (level in the header), error
#   c.jsonl.gz    {"entry", "c"} per function that decompiled (local data, see module docstring)
# ---------------------------------------------------------------------------------------------

def size_bucket(size) -> str:
    if size is None:
        return "unknown"
    if size <= 1:
        return "1-byte"
    if size <= 64:
        return "small (2-64 B)"
    if size <= 512:
        return "medium (65-512 B)"
    return "large (>512 B)"


BUCKETS = ("1-byte", "small (2-64 B)", "medium (65-512 B)", "large (>512 B)", "unknown")


class CaptureWriter:
    """Streams rows and C text; the capture only appears under its final names when it is complete."""

    def __init__(self, out: Path, header: dict, level: str = "standard"):
        self.out = Path(out)
        self.out.mkdir(parents=True, exist_ok=True)
        self.level = level
        self.header = {"type": "header", "schema": SCHEMA, "normaliser_level": level, **header}
        self.rows_path = self.out / "rows.jsonl.part"
        self.text_path = self.out / "c.jsonl.gz.part"
        self._rows = self.rows_path.open("w", encoding="utf-8", newline="\n")
        self._texts = gzip.open(self.text_path, "wt", encoding="utf-8", newline="\n")
        self.count = 0
        self.statuses: dict[str, int] = {}

    def add(self, entry, name, size, status, ms, c: str | None = None, error: str | None = None, **extra) -> None:
        row = {"type": "function", "entry": canonical_entry(entry), "name": name, "size": size, "status": status,
               "ms": None if ms is None else round(float(ms), 3)}
        row.update({key: value for key, value in extra.items() if value is not None})
        if c is not None:
            row["c_sha256"] = sha256_text(c)
            row["normalized_c_sha256"] = sha256_text(normalise(c, self.level))
            self._texts.write(json.dumps({"entry": row["entry"], "c": c}, ensure_ascii=False) + "\n")
        if error:
            row["error"] = str(error)[:2000]
        self._rows.write(json.dumps(row, ensure_ascii=False) + "\n")
        self.count += 1
        self.statuses[status] = self.statuses.get(status, 0) + 1

    def close(self, footer: dict | None = None) -> dict:
        self._rows.close()
        self._texts.close()
        header = {**self.header, "function_rows": self.count, "status_counts": self.statuses, **(footer or {})}
        with self.rows_path.open("r", encoding="utf-8") as handle:
            body = handle.read()
        final = self.out / "rows.jsonl"
        final.write_text(json.dumps(header, ensure_ascii=False) + "\n" + body, encoding="utf-8", newline="\n")
        self.rows_path.unlink()
        self.text_path.replace(self.out / "c.jsonl.gz")
        (self.out / "header.json").write_text(json.dumps(header, indent=1, ensure_ascii=False), encoding="utf-8")
        return header


def read_capture(directory: str | Path, with_text: bool = False) -> tuple[dict, dict[str, dict], dict[str, str]]:
    directory = Path(directory)
    header: dict = {}
    rows: dict[str, dict] = {}
    with (directory / "rows.jsonl").open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if item.get("type") == "header":
                header = item
            elif item.get("type") == "function":
                if item["entry"] in rows:
                    raise ValueError("%s: duplicate entry %s" % (directory, item["entry"]))
                rows[item["entry"]] = item
    texts: dict[str, str] = {}
    packed = directory / "c.jsonl.gz"
    if with_text and packed.is_file():
        with gzip.open(packed, "rt", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    item = json.loads(line)
                    texts[item["entry"]] = item["c"]
    return header, rows, texts


# ---------------------------------------------------------------------------------------------
# Diff and gate
# ---------------------------------------------------------------------------------------------

CLASSES = ("identical", "identical_after_normalisation", "changed", "failed_only_in_B", "failed_only_in_A",
           "failed_in_both", "missing_in_B", "missing_in_A")
PROFILES = {"corpus": {"min_match_pct": 98.0, "max_failed_only_in_B": 0},
            "fixtures": {"min_match_pct": 100.0, "max_failed_only_in_B": 0}}


def classify(a: dict | None, b: dict | None) -> str:
    if a is None:
        return "missing_in_A"
    if b is None:
        return "missing_in_B"
    a_ok, b_ok = a.get("status") == "ok", b.get("status") == "ok"
    if a_ok and b_ok:
        if a.get("c_sha256") == b.get("c_sha256"):
            return "identical"
        if a.get("normalized_c_sha256") == b.get("normalized_c_sha256"):
            return "identical_after_normalisation"
        return "changed"
    if a_ok:
        return "failed_only_in_B"
    if b_ok:
        return "failed_only_in_A"
    return "failed_in_both"


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    rank = (len(ordered) - 1) * fraction
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def timing_table(rows: dict[str, dict], field: str = "ms") -> list[dict]:
    groups: dict[str, list[float]] = {name: [] for name in BUCKETS}
    for row in rows.values():
        if row.get(field) is not None and row.get("status") == "ok":
            groups[size_bucket(row.get("size"))].append(float(row[field]))
    table = []
    for name in BUCKETS:
        values = groups[name]
        if not values:
            continue
        table.append({"bucket": name, "n": len(values), "min_ms": round(min(values), 3),
                      "median_ms": round(statistics.median(values), 3), "p95_ms": round(percentile(values, 0.95), 3),
                      "max_ms": round(max(values), 3)})
    everything = [float(row[field]) for row in rows.values() if row.get(field) is not None and row.get("status") == "ok"]
    if everything:
        table.append({"bucket": "all", "n": len(everything), "min_ms": round(min(everything), 3),
                      "median_ms": round(statistics.median(everything), 3), "p95_ms": round(percentile(everything, 0.95), 3),
                      "max_ms": round(max(everything), 3)})
    return table


def render_timing(table: list[dict], title: str = "") -> str:
    lines = [title] if title else []
    lines.append("| bucket | n | min ms | median ms | p95 ms | max ms |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for row in table:
        lines.append("| %s | %d | %.3f | %.3f | %.3f | %.3f |" % (row["bucket"], row["n"], row["min_ms"], row["median_ms"],
                                                               row["p95_ms"], row["max_ms"]))
    return "\n".join(lines)


def _excerpt(a_text: str | None, b_text: str | None, level: str, lines: int) -> list[str]:
    left = normalise(a_text or "", level).split("\n")
    right = normalise(b_text or "", level).split("\n")
    diff = list(difflib.unified_diff(left, right, "A", "B", lineterm="", n=1))
    return diff[:lines] + (["... (%d more diff lines)" % (len(diff) - lines)] if len(diff) > lines else [])


def diff_captures(dir_a, dir_b, *, level: str = "standard", examples: int = 5, excerpt_lines: int = 40,
                  with_text: bool = True, profile: str = "corpus", min_match_pct: float | None = None,
                  max_failed_only_in_B: int | None = None, allow_mismatch: bool = False) -> dict:
    head_a, rows_a, text_a = read_capture(dir_a, with_text=with_text)
    head_b, rows_b, text_b = read_capture(dir_b, with_text=with_text)
    if level not in LEVELS:
        raise ValueError("level must be one of %s" % ", ".join(LEVELS))
    # The normalised hashes in a capture were made at the capture's level; recompute from the
    # text when a different level is asked for and the text is there.
    recompute = with_text and (level != head_a.get("normaliser_level") or level != head_b.get("normaliser_level"))
    counts = {name: 0 for name in CLASSES}
    found: dict[str, list[dict]] = {name: [] for name in CLASSES}
    names_differ = 0
    for entry in sorted(set(rows_a) | set(rows_b), key=lambda value: int(value, 16)):
        a, b = rows_a.get(entry), rows_b.get(entry)
        if recompute and a and b and entry in text_a and entry in text_b:
            a = {**a, "normalized_c_sha256": sha256_text(normalise(text_a[entry], level))}
            b = {**b, "normalized_c_sha256": sha256_text(normalise(text_b[entry], level))}
        kind = classify(a, b)
        counts[kind] += 1
        if a and b and a.get("name") != b.get("name"):
            names_differ += 1
        if len(found[kind]) < examples and kind != "identical":
            item = {"entry": entry, "name_A": (a or {}).get("name"), "name_B": (b or {}).get("name"),
                    "size": (a or b or {}).get("size")}
            for tag, row in (("A", a), ("B", b)):
                if row and row.get("status") != "ok":
                    item["status_" + tag] = row.get("status")
                    item["error_" + tag] = row.get("error")
            if kind in ("changed", "identical_after_normalisation") and with_text and entry in text_a and entry in text_b:
                item["diff"] = _excerpt(text_a[entry], text_b[entry], "raw" if kind == "identical_after_normalisation" else level,
                                        excerpt_lines)
            found[kind].append(item)
    base = sum(1 for row in rows_a.values() if row.get("status") == "ok")
    matched = counts["identical"] + counts["identical_after_normalisation"]
    pct = 100.0 * matched / base if base else 0.0
    wanted = dict(PROFILES[profile])
    if min_match_pct is not None:
        wanted["min_match_pct"] = min_match_pct
    if max_failed_only_in_B is not None:
        wanted["max_failed_only_in_B"] = max_failed_only_in_B
    problems = []
    if counts["failed_only_in_B"] > wanted["max_failed_only_in_B"]:
        problems.append("failed_only_in_B %d > %d" % (counts["failed_only_in_B"], wanted["max_failed_only_in_B"]))
    if pct < wanted["min_match_pct"]:
        problems.append("identical-or-normalised %.2f%% < %.2f%%" % (pct, wanted["min_match_pct"]))
    warnings = []
    for key, label in (("path", "decompile path"), ("program_sha256", "program SHA-256")):
        if head_a.get(key) != head_b.get(key):
            message = "%s differs: A=%s B=%s" % (label, head_a.get(key), head_b.get(key))
            (warnings if allow_mismatch else problems).append(message)
    if head_a.get("options_sha256") != head_b.get("options_sha256"):
        warnings.append("decompiler options differ: A=%s B=%s" % (head_a.get("options_sha256"), head_b.get("options_sha256")))
    if head_a.get("sample") != head_b.get("sample"):
        warnings.append("captures cover different samples")
    report = {
        "schema": SCHEMA, "level": level, "profile": profile, "thresholds": wanted,
        "A": _brief(head_a, dir_a), "B": _brief(head_b, dir_b),
        "counts": counts, "compared_base_ok_in_A": base, "matched": matched, "match_pct": round(pct, 4),
        "names_differ": names_differ, "examples": found, "warnings": warnings,
        "timing_A": timing_table(rows_a), "timing_B": timing_table(rows_b),
        "gate": {"passed": not problems, "problems": problems},
    }
    return report


def _brief(header: dict, path) -> dict:
    return {"dir": str(path), "label": header.get("label"), "path": header.get("path"), "date": header.get("date"),
            "engine": header.get("engine"), "decompiler_binary_sha256": header.get("decompiler_binary_sha256"),
            "program_sha256": header.get("program_sha256"), "function_rows": header.get("function_rows"),
            "options_sha256": header.get("options_sha256"), "options_mode": header.get("options_mode"),
            "sample": header.get("sample")}


def render_report(report: dict) -> str:
    out = ["golden diff  A=%s  B=%s" % (report["A"].get("label"), report["B"].get("label")),
           "  level=%s profile=%s  A: %s %s  B: %s %s" % (
               report["level"], report["profile"], report["A"].get("path"), (report["A"].get("engine") or {}).get("ghidra_version"),
               report["B"].get("path"), (report["B"].get("engine") or {}).get("ghidra_version"))]
    for name in CLASSES:
        out.append("  %-32s %d" % (name, report["counts"][name]))
    out.append("  matched (identical + normalised) %d of %d ok in A = %.2f%%" % (report["matched"], report["compared_base_ok_in_A"],
                                                                              report["match_pct"]))
    for warning in report["warnings"]:
        out.append("  warning: " + warning)
    out.append("  gate: " + ("PASS" if report["gate"]["passed"] else "FAIL: " + "; ".join(report["gate"]["problems"])))
    return "\n".join(out)


# ---------------------------------------------------------------------------------------------
# Trees
# ---------------------------------------------------------------------------------------------

def tree_hash(root: str | Path) -> dict:
    """Sorted (relative path, size, sha256) of every file, and one digest over that list."""
    root = Path(root)
    rows = []
    for directory, _names, files in os.walk(root):
        for name in files:
            path = Path(directory, name)
            rows.append((path.relative_to(root).as_posix(), path.stat().st_size, sha256_file(path)))
    rows.sort()
    digest = hashlib.sha256("\n".join("%s\t%d\t%s" % row for row in rows).encode()).hexdigest()
    return {"root": str(root), "files": len(rows), "bytes": sum(row[1] for row in rows), "tree_sha256": digest,
            "entries": [list(row) for row in rows]}


def project_copy(source: Path, destination: Path) -> dict:
    before = tree_hash(source)
    if destination.exists():
        raise SystemExit("%s exists; refusing to overwrite" % destination)
    shutil.copytree(source, destination)
    copy = tree_hash(destination)
    after = tree_hash(source)
    if copy["tree_sha256"] != before["tree_sha256"]:
        raise SystemExit("copy differs from the source")
    if after["tree_sha256"] != before["tree_sha256"]:
        raise SystemExit("the source changed while it was copied")
    return {"source": str(source), "destination": str(destination), "files": before["files"], "bytes": before["bytes"],
            "tree_sha256": before["tree_sha256"], "source_unchanged": True}


# ---------------------------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------------------------

def read_properties(path: Path) -> dict:
    result = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                result[key.strip()] = value.strip()
    return result


def engine_identity(engine_dir: Path) -> dict:
    """Which decompiler this is: versions and the hash of the native binary that does the work."""
    engine_dir = Path(engine_dir)
    properties = read_properties(engine_dir / "Ghidra" / "application.properties")
    decompiler = engine_dir / "Ghidra" / "Features" / "Decompiler"
    binary = next(iter(sorted(decompiler.glob("os/win_x86_64/decompile.exe"))), None) or \
        next(iter(sorted(decompiler.glob("os/*/decompile*"))), None)
    jar = decompiler / "lib" / "Decompiler.jar"
    release = None
    session_jar = engine_dir / "Ghidra" / "Features" / "HeadlessSession" / "lib" / "HeadlessSession.jar"
    if session_jar.is_file():
        import zipfile
        try:
            with zipfile.ZipFile(session_jar) as archive:
                match = re.search(r"^hydra\.version=(\S+)", archive.read("hydra.properties").decode("utf-8", "replace"), re.M)
                release = match.group(1) if match else None
        except (KeyError, OSError, zipfile.BadZipFile):
            release = None
    return {"kind": "hydra" if release else "stock", "dir": str(engine_dir),
            "ghidra_version": properties.get("application.version"), "release_name": properties.get("application.release.name"),
            "build_date": properties.get("application.build.date"),
            "revision": properties.get("application.revision.hydra-engine") or properties.get("application.revision.ghidra"),
            "hydra_release": release,
            "decompiler_binary": str(binary) if binary else None,
            "_binary": binary, "_jar": jar if jar.is_file() else None}


def _public_identity(identity: dict) -> tuple[dict, str | None, str | None]:
    binary, jar = identity.get("_binary"), identity.get("_jar")
    shown = {key: value for key, value in identity.items() if not key.startswith("_")}
    return shown, sha256_file(binary) if binary else None, sha256_file(jar) if jar else None


def options_digest(options: dict | None) -> str | None:
    return None if not options else sha256_text(json.dumps(options, sort_keys=True))


def _today() -> str:
    return datetime.date.today().isoformat()


def _parse_size(body: list[str] | None) -> int | None:
    if not body:
        return None
    total = 0
    for item in body:
        match = re.search(r"^\[?\s*(?:\w+:)?([0-9A-Fa-f]+)\s*(?:,|-)\s*(?:\w+:)?([0-9A-Fa-f]+)\s*\]?$", str(item).strip())
        if not match:
            return None
        total += int(match.group(2), 16) - int(match.group(1), 16) + 1
    return total


def stratified_sample(rows: list[dict], count: int, seed: int) -> list[dict]:
    """A deterministic sample, proportional per size bucket with at least a few from each."""
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(size_bucket(row.get("size")), []).append(row)
    total = len(rows)
    if count >= total:
        return list(rows)
    chosen: list[dict] = []
    generator = random.Random(seed)
    for name in sorted(groups):
        members = sorted(groups[name], key=lambda item: int(item["entry"], 16))
        take = min(len(members), max(min(10, len(members)), round(count * len(members) / total)))
        chosen.extend(generator.sample(members, take))
    chosen.sort(key=lambda item: int(item["entry"], 16))
    return chosen[:count] if len(chosen) > count else chosen


def _log(message: str) -> None:
    print(time.strftime("%H:%M:%S ") + message, file=sys.stderr, flush=True)


def _hydra_modules():
    sys.path.insert(0, str(REPO / "src"))
    from rusticre import hydra, query  # noqa: PLC0415
    return hydra, query


def _java_home(args) -> str | None:
    return args.java_home or os.environ.get("JAVA_HOME") or None


def _settings(args, engine_dir: Path, state_root: Path) -> dict:
    client = Path(args.client or os.environ.get("GOLDEN_CLIENT") or engine_dir / "support" / "ghidra_session.py")
    settings = {"root": str(state_root), "hydra_dir": str(engine_dir), "hydra_client": str(client),
                "hydra_idle_s": 3600, "hydra_allow_unpinned": True}
    if _java_home(args):
        settings["java_home"] = _java_home(args)
    return settings


def _state_root(args, label: str) -> Path:
    base = Path(args.state_root) if args.state_root else Path(os.environ.get("GOLDEN_STATE", "D:/Projects/Hydra/_golden/state"))
    root = base / ("%s-%s" % (label, time.strftime("%Y%m%d-%H%M%S")))
    root.mkdir(parents=True, exist_ok=False)
    return root


def _stop_daemon(engine, hydra) -> None:
    try:
        engine.stop(force=True)
    except Exception as error:
        _log("daemon stop: %r" % (error,))
    try:
        daemon = engine.module().Daemon(str(engine.engine_dir), str(hydra.state_dir(engine.settings)), hydra.INSTANCE)
        if daemon.jvm_alive() or daemon.read_endpoint():
            daemon.kill()
    except Exception as error:
        _log("daemon kill: %r" % (error,))


def _program_entry(listing: dict, wanted: str | None) -> dict:
    items = [item for item in (listing.get("entries") or []) if item.get("program")]
    if wanted:
        items = [item for item in items if wanted in (item.get("path"), item.get("name"), "/" + str(item.get("name")))] or items
    if len(items) != 1:
        raise SystemExit("choose --program; the project lists: %s" % [item.get("path") or item.get("name") for item in items])
    return items[0]


def capture_hydra(args) -> Path:
    """Hydra Engine: the production RusticQuery path (one decompile request per function) or the explicit path."""
    hydra, query = _hydra_modules()
    engine_dir = Path(args.engine).resolve()
    identity = engine_identity(engine_dir)
    if identity["kind"] != "hydra":
        raise SystemExit("%s is not a Hydra Engine install; use --stock for stock Ghidra" % engine_dir)
    state_root = _state_root(args, args.label)
    settings = _settings(args, engine_dir, state_root)
    if not args.upgrade_cache:
        os.environ["GHIDRA_SESSION_UPGRADE_CACHE"] = "off"
    scripts = hydra.script_dirs(settings)
    for directory in scripts:
        directory.mkdir(parents=True, exist_ok=True)
    shutil.copy2(HERE / "golden" / "GoldenExport.java", scripts[1] / "GoldenExport.java")
    out = Path(args.out)
    engine = hydra.Engine(settings)
    started = time.monotonic()
    try:
        gpr = str(Path(args.project).resolve())
        opened = engine.call("open_project", path=gpr, writable=False)
        listing = engine.call("list", project=opened["id"], programsOnly=True)
        entry = _program_entry(listing, args.program)
        program_name = entry.get("path") or "/" + entry["name"]
        sha = str(entry.get("sha256") or "").lower()
        program = query.open_program(engine, gpr, program_name, sha)
        info = engine.call("info", program=program["key"])
        _log("program %s sha256 %s info.functions=%s analyzed=%s mode=%s" % (program_name, sha, info.get("functions"),
                                                                              info.get("analyzed"), info.get("mode")))
        hello = engine.hello()
        shown, binary_sha, jar_sha = _public_identity(identity)
        shown["session"] = {key: hello.get(key) for key in ("protocol", "hydraVersion", "ghidraVersion", "installId")}
        header = {"label": args.label, "date": args.date or _today(), "path": args.path, "engine": shown,
                  "decompiler_binary_sha256": binary_sha, "decompiler_jar_sha256": jar_sha,
                  "program": program_name, "program_sha256": sha, "program_info": {key: info.get(key) for key in (
                      "functions", "analyzed", "language", "compiler", "imageBase", "format", "md5", "mode", "cachedUpgrade")},
                  "project": gpr, "code": {"golden.py": sha256_file(Path(__file__)),
                                           "GoldenExport.java": sha256_file(HERE / "golden" / "GoldenExport.java"),
                                           "RusticQuery.java": sha256_file(REPO / "src" / "rusticre" / "scripts" / "RusticQuery.java")},
                  "upgrade_cache": bool(args.upgrade_cache), "sample": None}
        entries_file = None
        selected = None
        if args.sample:
            listed = _enumerate(engine, query, program, sha)
            selected = stratified_sample(listed, args.sample, args.seed)
            header["sample"] = {"requested": args.sample, "seed": args.seed, "selected": len(selected), "of": len(listed),
                                "method": "deterministic stratified by size bucket"}
            entries_file = out / "sample-entries.txt"
            out.mkdir(parents=True, exist_ok=True)
            entries_file.write_text("\n".join(item["entry"] for item in selected) + "\n", encoding="utf-8")
        if args.path == "production":
            header = _capture_production(engine, query, program, sha, header, out, args, selected)
        else:
            header = _capture_explicit(engine, program, header, out, args, entries_file)
        header_path = out / "header.json"
        _log("capture complete: %s rows in %.1f s -> %s" % (header.get("function_rows"), time.monotonic() - started, out))
        return header_path
    finally:
        _stop_daemon(engine, hydra)


def _enumerate(engine, query, program: dict, sha: str) -> list[dict]:
    """Every function through RusticQuery's `functions` action, as the export job pages them."""
    rows: list[dict] = []
    cursor = ""
    while True:
        request = {"id": "enumerate", "action": "functions", "address": "", "limit": 200, "cursor": cursor, "contains": "",
                   "timeout_s": 60, "options": {}, "expected_sha256": sha}
        response, _raw = query.run_script(engine, program, request, 60, Path(engine.settings["root"]) / "hydra" / "requests")
        if not response.get("ok"):
            raise SystemExit("enumeration failed: %s" % json.dumps(response)[:500])
        for item in response["functions"]:
            rows.append({"entry": canonical_entry(item["address"]), "name": item["name"], "size": _parse_size(item.get("body")),
                         "size_truncated": bool(item.get("body_truncated"))})
        if not response.get("truncated"):
            return rows
        nxt = str(response.get("next_cursor") or "")
        if not nxt or nxt == cursor:
            raise SystemExit("enumeration made no cursor progress")
        cursor = nxt


def _capture_production(engine, query, program, sha, header, out: Path, args, selected) -> dict:
    listed = selected if selected is not None else _enumerate(engine, query, program, sha)
    _log("production path: %d functions, one RusticQuery decompile request each" % len(listed))
    requests = Path(engine.settings["root"]) / "hydra" / "requests"
    writer = CaptureWriter(out, {**header, "options": None, "options_sha256": None,
                                 "options_note": "RusticQuery.java opens DecompInterface without setOptions: native defaults",
                                 "timeout_s": args.timeout}, args.level)
    began = time.monotonic()
    for index, item in enumerate(listed):
        request = {"id": "golden", "action": "decompile", "address": item["entry"], "limit": 40, "cursor": "", "contains": "",
                   "timeout_s": args.timeout, "options": {"max_characters": 2097152}, "expected_sha256": sha}
        tick = time.perf_counter()
        c = None
        error = None
        status = "ok"
        engine_ms = None
        try:
            response, raw = query.run_script(engine, program, request, args.timeout, requests)
            engine_ms = float(raw.get("seconds") or 0) * 1000.0
            if response.get("ok"):
                c = response.get("c")
                if response.get("truncated"):
                    status, error = "failed", "truncated at %s characters" % response.get("max_characters")
                    c = None
            else:
                message = json.dumps(response)[:2000]
                status = "timeout" if "timed out" in message.lower() or "timeout" in message.lower() else "failed"
                error = message
        except Exception as caught:  # noqa: BLE001 - a per-function engine error is a result, not a crash
            status, error = "error", "%s: %s" % (type(caught).__name__, caught)
        ms = (time.perf_counter() - tick) * 1000.0
        writer.add(item["entry"], item["name"], item["size"], status if c is not None or status != "ok" else "failed", ms, c, error,
                   engine_ms=None if engine_ms is None else round(engine_ms, 3), size_truncated=item.get("size_truncated") or None)
        if (index + 1) % 250 == 0:
            _log("%d/%d  %.1f s" % (index + 1, len(listed), time.monotonic() - began))
    return writer.close({"seconds": round(time.monotonic() - began, 1)})


def _capture_explicit(engine, program, header, out: Path, args, entries_file) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    raw_path = out / "explicit.raw.jsonl"
    raw_path.unlink(missing_ok=True)
    argv = [str(raw_path), str(args.timeout), str(entries_file) if entries_file else "-", args.options_mode]
    _log("explicit path: GoldenExport.java in the engine, args %s" % argv)
    request = engine.send("script", script="GoldenExport.java", program=program["key"], args=argv, timeout=args.script_timeout,
                          maxChars=20000, artifact=str(raw_path))
    began = time.monotonic()
    result = engine.wait(request, "script")
    _log("script answered in %.1f s: %s" % (time.monotonic() - began, str(result.get("output", ""))[-300:]))
    return finalise_raw(raw_path, header, out, args.level, began)


def finalise_raw(raw_path: Path, header: dict, out: Path, level: str, began: float | None = None) -> dict:
    """Turn GoldenExport's raw JSONL into a capture directory and delete the raw file."""
    script_header: dict = {}
    writer = None
    footer: dict = {}
    with raw_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if item["type"] == "header":
                script_header = item
                merged = {**header, "path": "explicit", "options": item.get("options"), "options_mode": item.get("options_mode"),
                          "options_sha256": options_digest(item.get("options")), "timeout_s": item.get("timeout_s"),
                          "function_counts": {"total": item.get("function_count_total"), "internal": item.get("function_count_internal"),
                                              "thunks": item.get("function_count_thunks")},
                          "script_reports": {key: item.get(key) for key in ("application_version", "application_release", "language",
                                                                             "compiler_spec", "image_base")}}
                if header.get("program_sha256") and item.get("program_sha256") and header["program_sha256"] != item["program_sha256"]:
                    raise SystemExit("program SHA-256 differs between the project listing and the script")
                merged["program_sha256"] = item.get("program_sha256") or header.get("program_sha256")
                writer = CaptureWriter(out, merged, level)
            elif item["type"] == "function":
                writer.add(item["entry"], item["name"], item.get("size"), item["status"], item.get("ms"), item.get("c"),
                           item.get("error"), thunk=item.get("thunk") or None)
            elif item["type"] == "footer":
                footer = item
    if writer is None or not footer:
        raise SystemExit("%s is incomplete (no header or footer)" % raw_path)
    done = writer.close({"seconds": footer.get("seconds")})
    raw_path.unlink()
    return done


def capture_stock(args) -> Path:
    """Stock Ghidra: analyzeHeadless -process -noanalysis -readOnly with the same GoldenExport.java."""
    install = Path(args.stock).resolve()
    identity = engine_identity(install)
    if identity["kind"] == "hydra":
        raise SystemExit("%s has Hydra's HeadlessSession; use --engine" % install)
    if not args.program_name:
        raise SystemExit("--program-name (the program's name in the project) is required for stock Ghidra")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    gpr = Path(args.project).resolve()
    state = _state_root(args, args.label)
    raw_path = out / "explicit.raw.jsonl"
    raw_path.unlink(missing_ok=True)
    settings_dir, cache_dir = state / "ghidra-settings", state / "ghidra-cache"
    settings_dir.mkdir(parents=True)
    cache_dir.mkdir(parents=True)
    script = install / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    entries_file = None
    if args.sample:
        raise SystemExit("--sample needs an entry list from a Hydra capture; pass --entries FILE instead")
    if args.entries:
        entries_file = Path(args.entries).resolve()
    command = [str(script), str(gpr.parent), gpr.stem, "-process", args.program_name, "-noanalysis", "-readOnly",
               "-scriptPath", str(HERE / "golden"), "-log", str(out / "analyzeHeadless.log"),
               "-postScript", "GoldenExport.java", str(raw_path), str(args.timeout), str(entries_file) if entries_file else "-",
               args.options_mode]
    env = dict(os.environ)
    if _java_home(args):
        env["JAVA_HOME"] = _java_home(args)
    env["JAVA_TOOL_OPTIONS"] = "-Dapplication.settingsdir=%s -Dapplication.cachedir=%s" % (
        str(settings_dir).replace("\\", "/"), str(cache_dir).replace("\\", "/"))
    _log("stock Ghidra %s: %s" % (identity["ghidra_version"], " ".join(command)))
    began = time.monotonic()
    log_path = out / "analyzeHeadless.console.log"
    with log_path.open("w", encoding="utf-8") as log:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env)
    if result.returncode != 0 or not raw_path.is_file():
        raise SystemExit("analyzeHeadless exited %s and %s; see %s" % (result.returncode, "wrote no export" if not raw_path.is_file()
                                                                      else "wrote one", log_path))
    shown, binary_sha, jar_sha = _public_identity(identity)
    header = {"label": args.label, "date": args.date or _today(), "path": "explicit", "engine": shown,
              "decompiler_binary_sha256": binary_sha, "decompiler_jar_sha256": jar_sha, "program": args.program_name,
              "project": str(gpr), "code": {"golden.py": sha256_file(Path(__file__)),
                                            "GoldenExport.java": sha256_file(HERE / "golden" / "GoldenExport.java")},
              "sample": ({"entries_file": str(entries_file)} if entries_file else None)}
    done = finalise_raw(raw_path, header, out, args.level, began)
    _log("capture complete: %s rows in %.1f s -> %s" % (done.get("function_rows"), time.monotonic() - began, out))
    return out / "header.json"


# ---------------------------------------------------------------------------------------------
# Sets (a list of programs to capture the same way) and preparation of fixtures
# ---------------------------------------------------------------------------------------------

def capture_set(args) -> int:
    entries = json.loads(Path(args.set).read_text(encoding="utf-8"))
    base = Path(args.out_base)
    failures = 0
    for entry in entries["programs"]:
        for path in args.paths.split(","):
            namespace = argparse.Namespace(**{**vars(args), "project": entry["gpr"], "program": entry.get("program"),
                                              "path": path, "out": str(base / entry["name"] / path),
                                              "sample": entry.get("sample") or args.sample, "label": args.label})
            _log("== %s / %s" % (entry["name"], path))
            try:
                capture_hydra(namespace)
            except SystemExit as error:
                failures += 1
                _log("capture failed: %s" % (error,))
    return 1 if failures else 0


def prepare(args) -> int:
    """Import and analyse executables through RusticRE's preparation worker; write a set file."""
    hydra, _query = _hydra_modules()
    from rusticre import preparation  # noqa: PLC0415
    engine_dir = Path(args.engine).resolve()
    state_root = _state_root(args, "prepare")
    settings = _settings(args, engine_dir, state_root)
    os.environ["RUSTICRE_ROOT"] = str(state_root)
    os.environ["PYTHONPATH"] = str(REPO / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")
    from rusticre import query  # noqa: PLC0415
    query._keys.clear()
    jobs = {}
    for spec in args.exe:
        name, _, path = spec.partition("=")
        started = preparation.prepare(settings, path, name)
        jobs[name] = (path, started["job_id"])
        _log("prepare %s job %s" % (name, started["job_id"]))
    programs = []
    failed = 0
    try:
        for name, (path, job) in jobs.items():
            deadline = time.monotonic() + args.timeout
            while True:
                status = preparation.status(settings, job)
                if status["state"] not in preparation.ACTIVE or time.monotonic() > deadline:
                    break
                time.sleep(2)
            if status["state"] != "done":
                failed += 1
                _log("%s: %s" % (name, json.dumps(status)[:1500]))
                continue
            project = status["project"]
            source = Path(project["gpr"]).parent
            destination = Path(args.dest) / name
            copy = project_copy(source, destination)
            programs.append({"name": name, "gpr": str(destination / Path(project["gpr"]).name), "program": project["program"],
                             "exe": path, "exe_sha256": project["sha256"], "functions": project.get("functions"),
                             "project_tree_sha256": copy["tree_sha256"], "prepared_with": hydra.RELEASE})
    finally:
        _stop_daemon(hydra.Engine(settings), hydra)
    Path(args.set).write_text(json.dumps({"programs": programs}, indent=1), encoding="utf-8")
    _log("wrote %s (%d programs, %d failed)" % (args.set, len(programs), failed))
    return 1 if failed else 0


# ---------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------

def _add_capture_options(sub, hydra_only=False) -> None:
    sub.add_argument("--label", required=True, help="a name for this capture, e.g. hydra-2")
    sub.add_argument("--date", help="date to record (default: today, ISO)")
    sub.add_argument("--timeout", type=int, default=120, help="per-function decompile timeout in seconds")
    sub.add_argument("--level", choices=LEVELS[1:], default="standard", help="normaliser level for normalized_c_sha256")
    sub.add_argument("--java-home", help="JDK home (default: JAVA_HOME)")
    sub.add_argument("--state-root", help="parent of this run's fresh daemon state (default D:/Projects/Hydra/_golden/state)")
    sub.add_argument("--client", help="ghidra_session.py (default: the engine's support/ghidra_session.py)")
    sub.add_argument("--upgrade-cache", action="store_true", help="leave Hydra's upgrade cache on (default off for stable timing)")
    sub.add_argument("--script-timeout", type=int, default=6 * 3600, help="timeout of the whole explicit-path script, seconds")
    sub.add_argument("--options-mode", choices=("fixed", "program"), default="fixed",
                     help="explicit path: fixed DecompileOptions, or also grabFromProgram (what the Ghidra window uses)")
    sub.add_argument("--sample", type=int, default=0, help="decompile a deterministic stratified sample of N functions")
    sub.add_argument("--seed", type=int, default=1)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="golden.py", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)

    cap = commands.add_parser("capture", help="capture one program")
    group = cap.add_mutually_exclusive_group(required=True)
    group.add_argument("--engine", help="Hydra Engine install directory")
    group.add_argument("--stock", help="stock Ghidra install directory (analyzeHeadless; explicit path only)")
    cap.add_argument("--project", required=True, help="the .gpr of a COPY of the analysed project")
    cap.add_argument("--program", help="program path in the project (Hydra; default: the only one)")
    cap.add_argument("--program-name", help="program name in the project (stock Ghidra)")
    cap.add_argument("--path", choices=("production", "explicit"), default="explicit",
                     help="production: RusticQuery decompile requests; explicit: GoldenExport.java with fixed DecompileOptions")
    cap.add_argument("--entries", help="stock only: file of entry addresses to decompile")
    cap.add_argument("--out", required=True)
    _add_capture_options(cap)

    many = commands.add_parser("capture-set", help="capture every program of a set file (Hydra)")
    many.add_argument("--engine", required=True)
    many.add_argument("--set", required=True)
    many.add_argument("--out-base", required=True)
    many.add_argument("--paths", default="production,explicit")
    _add_capture_options(many)

    diff = commands.add_parser("diff", help="compare two captures and apply the gate")
    diff.add_argument("a")
    diff.add_argument("b")
    diff.add_argument("--report", help="write the full report here (JSON; includes C excerpts unless --no-text)")
    diff.add_argument("--level", choices=LEVELS, default="standard")
    diff.add_argument("--profile", choices=sorted(PROFILES), default="corpus")
    diff.add_argument("--min-match-pct", type=float)
    diff.add_argument("--max-failed-only-in-b", type=int)
    diff.add_argument("--examples", type=int, default=5, help="examples kept per class")
    diff.add_argument("--excerpt-lines", type=int, default=40)
    diff.add_argument("--no-text", action="store_true", help="hashes only: no C text in the report")
    diff.add_argument("--allow-mismatch", action="store_true", help="warn, do not fail, when path or program SHA-256 differ")

    timing = commands.add_parser("timing", help="size-bucketed decompile timing of a capture")
    timing.add_argument("capture")
    timing.add_argument("--field", default="ms", choices=("ms", "engine_ms"))
    timing.add_argument("--json", action="store_true")

    tree = commands.add_parser("treehash", help="sha256 of every file of a tree")
    tree.add_argument("root")
    tree.add_argument("--out", help="write the full listing here")

    copy = commands.add_parser("project-copy", help="copy a project; prove the copy identical and the source untouched")
    copy.add_argument("src")
    copy.add_argument("dst")
    copy.add_argument("--out")

    prep = commands.add_parser("prepare", help="import+analyse executables with RusticRE's preparation; write a set file")
    prep.add_argument("--engine", required=True)
    prep.add_argument("--exe", action="append", required=True, help="NAME=PATH, repeatable")
    prep.add_argument("--dest", required=True, help="directory that receives a stable copy of each prepared project")
    prep.add_argument("--set", required=True)
    prep.add_argument("--timeout", type=int, default=1800)
    prep.add_argument("--java-home")
    prep.add_argument("--state-root")
    prep.add_argument("--client")

    args = parser.parse_args(argv)
    if args.command == "capture":
        if args.engine:
            capture_hydra(args)
        else:
            if args.path == "production":
                parser.error("the production path is Hydra's RusticQuery; stock Ghidra has only the explicit path")
            capture_stock(args)
        return 0
    if args.command == "capture-set":
        return capture_set(args)
    if args.command == "diff":
        report = diff_captures(args.a, args.b, level=args.level, examples=args.examples, excerpt_lines=args.excerpt_lines,
                               with_text=not args.no_text, profile=args.profile, min_match_pct=args.min_match_pct,
                               max_failed_only_in_B=args.max_failed_only_in_b, allow_mismatch=args.allow_mismatch)
        if args.report:
            Path(args.report).write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
        print(render_report(report))
        return 0 if report["gate"]["passed"] else 1
    if args.command == "timing":
        _head, rows, _ = read_capture(args.capture)
        table = timing_table(rows, args.field)
        print(json.dumps(table, indent=1) if args.json else render_timing(table))
        return 0
    if args.command == "treehash":
        result = tree_hash(args.root)
        if args.out:
            Path(args.out).write_text(json.dumps(result, indent=1), encoding="utf-8")
        print("%d files, %d bytes, tree sha256 %s" % (result["files"], result["bytes"], result["tree_sha256"]))
        return 0
    if args.command == "project-copy":
        result = project_copy(Path(args.src), Path(args.dst))
        if args.out:
            Path(args.out).write_text(json.dumps(result, indent=1), encoding="utf-8")
        print(json.dumps(result, indent=1))
        return 0
    if args.command == "prepare":
        return prepare(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
