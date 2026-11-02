"""Helpers for the semantic-trace fixtures: build them, load their expected answers, run them and check what can be
checked without tracing (docs/trace-fixtures.md). Used by tests/test_trace_fixtures.py and by the acceptance tests of
the other lanes (import it with tests/fixtures on sys.path).

    built = build_group("frameloop", out_dir)            # {"x64": {"manifest": ..., "dir": Path}, "x86": ...}
    expected = load_expected("frameloop")
    for run in runs_of(expected):
        problems = execute(run, built["x64"]["dir"], work_dir)   # [] when the program matched its expected answers
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_fixtures  # noqa: E402

EXPECTED = HERE / "expected"


def msvc_available() -> bool:
    return build_fixtures.msvc_available()


def load_expected(name: str) -> dict:
    return json.loads((EXPECTED / (name + ".json")).read_text(encoding="utf-8"))


def runs_of(expected: dict) -> list[dict]:
    return expected.get("runs") or expected.get("sequence") or []


def build_group(name: str, out_dir: Path, arches: tuple[str, ...] = ("x64", "x86")) -> dict:
    """Build the outputs of one fixture group for the given architectures. Returns {arch: {"dir": Path, "manifest": {exe: entry}}}."""
    rows = [row for row in build_fixtures.TRACE_BUILDS + build_fixtures.BUILDS if row[0] in build_fixtures.TRACE_GROUPS[name]]
    wanted = tuple(a for a in build_fixtures.ARCHES if a[0] in arches)
    manifest = build_fixtures.build(Path(out_dir), rows, wanted)
    return {arch: {"dir": Path(out_dir) / arch,
                   "manifest": {key.split("/", 1)[1]: entry for key, entry in manifest.items() if key.startswith(arch + "/")}}
            for arch, _host in wanted}


def functions_of(built_arch: dict) -> tuple[set, set]:
    """(function names, data names) over every output of a built group on one architecture."""
    functions, data = set(), set()
    for entry in built_arch["manifest"].values():
        functions |= set(entry["functions"])
        data |= set(entry["globals"])
    return functions, data


def substitute(argument: str, work: Path, tag: str) -> str:
    return argument.replace("{work}", str(work)).replace("{tag}", tag)


def match_lines(actual: list[str], wanted: list[str]) -> list[str]:
    """Compare stdout lines with an expected list. Plain entries are exact, "<regex>..." entries are regular expressions
    that must match the whole line, "<optional>..." entries are regular expressions of lines that may be absent."""
    problems, position = [], 0
    for entry in wanted:
        optional = entry.startswith("<optional>")
        pattern = entry[len("<optional>"):] if optional else entry[len("<regex>"):] if entry.startswith("<regex>") else None
        line = actual[position] if position < len(actual) else None
        ok = line is not None and ((re.fullmatch(pattern, line) is not None) if pattern is not None else line == entry)
        if ok:
            position += 1
        elif not optional:
            problems.append("line %d: expected %r, got %r" % (position, entry, line))
            position += 1
    if position < len(actual):
        problems.append("unexpected extra lines: %r" % actual[position:position + 3])
    return problems


def check_files(files: dict, work: Path) -> list[str]:
    problems = []
    for name, spec in files.items():
        path = work / name
        if not path.exists():
            problems.append("missing file " + name)
            continue
        content = path.read_bytes()
        if "text" in spec and content.decode("utf-8", "replace") != spec["text"]:
            problems.append("%s: %r != %r" % (name, content[:60], spec["text"][:60]))
        if "hex" in spec and content.hex() != spec["hex"]:
            problems.append("%s: bytes differ from the expected %d" % (name, len(spec["hex"]) // 2))
        if "prefix_hex" in spec and not content.hex().startswith(spec["prefix_hex"]):
            problems.append("%s: does not start with %s" % (name, spec["prefix_hex"]))
    return problems


def execute(run: dict, exe_dir: Path, work: Path, tag: str | None = None) -> list[str]:
    """Run one entry of an expected file and return the list of mismatches (empty when it matched).

    The companion of a run (the owner of the replica pair) is started first and checked too."""
    tag = tag or uuid.uuid4().hex[:8]
    work.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    companion = None
    if "companion" in run:
        spec = run["companion"]
        companion = subprocess.Popen([str(exe_dir / spec["program"])] + [substitute(a, work, tag) for a in spec["args"]],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True, cwd=work)
    try:
        completed = subprocess.run([str(exe_dir / run["program"])] + [substitute(a, work, tag) for a in run["args"]],
                                   capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=work, timeout=run["max_seconds"])
    except subprocess.TimeoutExpired:
        if companion:
            companion.kill()
        return ["%s timed out after %ss" % (run["id"], run["max_seconds"])]
    label = run["id"]
    if completed.returncode != run["exit_code"]:
        problems.append("%s: exit code %d, expected %d (stderr %r)" % (label, completed.returncode, run["exit_code"], completed.stderr[-200:]))
    problems += ["%s: %s" % (label, p) for p in match_lines(completed.stdout.splitlines(), run["stdout_lines"])]
    problems += ["%s: %s" % (label, p) for p in check_files(run.get("files", {}), work)]
    for name, pattern in run.get("state_file_regex", {}).items():
        text = (work / name).read_text().strip() if (work / name).exists() else ""
        if not re.fullmatch(pattern, text):
            problems.append("%s: %s is %r, expected /%s/" % (label, name, text, pattern))
    if companion:
        try:
            out, err = companion.communicate(timeout=run["max_seconds"])
        except subprocess.TimeoutExpired:
            companion.kill()
            return problems + ["%s: companion timed out" % label]
        spec = run["companion"]
        if companion.returncode != spec["exit_code"]:
            problems.append("%s: companion exit code %d (stderr %r)" % (label, companion.returncode, err[-200:]))
        problems += ["%s companion: %s" % (label, p) for p in match_lines(out.splitlines(), spec["stdout_lines"])]
    return problems


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
