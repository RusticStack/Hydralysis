#!/usr/bin/env python3
"""Classify the functions that decompile differently between two golden captures, by cause.

Z7 of the PROTOCOL-3 plan: the 12.1.4 against 12.3 comparison is REPORTED, NEVER GATED (owner
decision). This tool only reads captures made by `tools/golden.py` (which stays frozen) and prints
or writes COUNTS. It never writes C text, function names or addresses, so its output can be
committed (no game-derived data in the repository).

    python tools/golden_classify.py classify A B [--unpinned B2] [--json OUT] [--markdown OUT]
    python tools/golden_classify.py fixtures ROOT_A ROOT_B [--json OUT] [--markdown OUT]

A is the older engine (stock 12.1.4), B the newer one (12.3, with the decompiler option
`maxBadData` pinned so the comparison holds the options equal), B2 the same newer engine with its
own default (`maxBadData` 4). Giving B2 measures how much of the difference the option explains.

The exit status is 0 whenever the report was produced; a match percentage below any threshold does
not change it. Usage errors and unreadable captures exit 2.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import golden  # noqa: E402  (the shared, frozen harness: imported, never edited)

# The option that 12.3 added and 12.1.4 does not have. It is listed apart from the options hash.
PINNED_OPTION = "maxBadData"

# Causes, most specific first. A changed function gets ONE primary cause (the first that matches
# its changed lines) and every cause that matches is counted as a signal.
CAUSES = (
    ("bad-data-limit", "bad instruction handling: control flow cut short at bad data"),
    ("unimplemented-instruction", "unimplemented instruction handling"),
    ("switch-jump-table", "switch or jump table recovery"),
    ("warning-comment", "only WARNING comment text differs"),
    ("calling-convention", "calling convention or unaffected-register notation"),
    ("block-reorder", "the same statements in a different order"),
    ("condition-inversion", "the same conditions with flipped polarity or swapped operands"),
    ("control-flow", "different number of branches, loops or gotos"),
    ("stack-layout", "stack variables split, merged or resized"),
    ("local-types", "different declared types of locals"),
    ("types-casts", "different types or pointer casts"),
    ("constants-data", "different constants or data references"),
    ("variable-names", "only variable naming or numbering differs"),
    ("other", "no rule matched"),
)

# Accepted-difference policy. "accepted" means: the mechanism is named, the difference is reported
# and no action is required. "open" means: not explained, so a person has to look. Nothing here is
# a gate: the tool exits 0 either way.
POLICY = {
    "bad-data-limit": ("accepted", "12.3 counts bad-data exceptions (GP-6945, option maxBadData, default 4); 12.1.4 has no limit"),
    "unimplemented-instruction": ("open", "not attributed to an upstream change"),
    "switch-jump-table": ("open", "not attributed to an upstream change"),
    "warning-comment": ("accepted", "comment text only; the code is identical once the comment lines are removed"),
    "calling-convention": ("open", "not attributed to an upstream change"),
    "block-reorder": ("accepted", "presentation: identical statements, different order; not checked for equivalence one by one"),
    "condition-inversion": ("accepted", "presentation: only conditions with the same operands and a negated or mirrored operator changed; not checked for equivalence one by one"),
    "control-flow": ("open", "not attributed to an upstream change"),
    "stack-layout": ("open", "not attributed to an upstream change"),
    "local-types": ("open", "not attributed to an upstream change"),
    "types-casts": ("open", "not attributed to an upstream change"),
    "constants-data": ("open", "not attributed to an upstream change"),
    "variable-names": ("accepted", "naming only; no structural difference"),
    "other": ("open", "no rule matched"),
}

_BAD = re.compile(r"halt_baddata|Bad instruction|Truncating control flow|Bad instruction count")
_UNIMPL = re.compile(r"halt_unimplemented|[Uu]nimplemented instruction")
_SWITCH = re.compile(r"\bswitch\b|\bcase\b|\bdefault:|switchD_|switchdata|caseD_|[Jj]ump ?table|computed jump")
_CONV = re.compile(r"__(?:cdecl|stdcall|thiscall|fastcall)|\b(?:in|unaff)_[A-Z]{2,4}\b|\bthis\b")
_FLOW = re.compile(r"\b(?:if|else|while|for|do|goto|break|continue)\b")
_TYPE = re.compile(r"\(\s*(?:char|byte|short|int|uint|ushort|void|undefined\d?|code|float|double)\s*\**\s*\)|\bundefined\d?\b")
_CONST = re.compile(r"\b(?:DAT|PTR|s|u|FUN|LAB)_[0-9a-fA-F]{6,8}\b|\b0x[0-9a-fA-F]+\b|\b\d+\b")
_NAME = re.compile(r"\b(?:[A-Za-z]{0,8}Var\d+|param_\d+|local_(?:res)?[0-9a-fA-F]+|in_stack_[0-9a-fA-F]+|[A-Za-z]{1,6}Stack_[0-9a-fA-F]+)\b")
_STACK = re.compile(r"\bstack0x[0-9a-fA-F]+|\b[A-Za-z]{1,6}Stack_|\bin_stack_|\blocal_res")
_DECL = re.compile(r"^\s*(?:unsigned\s+)?[A-Za-z_][A-Za-z_0-9]*(?:\s*\*+)?\s+\**[A-Za-z]+[A-Za-z_]*<?\d*>?\s*(?:\[\d+\])?;\s*$")
_BRACE = re.compile(r"^\s*(?:\}|\{|\}?\s*else\s*\{?|\})\s*$")
_OPS = re.compile(r"==|!=|<=|>=|(?<![-<>])[<>](?![<>=])|!(?!=)")
_COND = re.compile(r"\b(?:if|while)\b")
_NUMBERED = re.compile(r"<(\d+)>")
# Relational operators: the negation (a < b is false exactly when a >= b) and the mirror (a < b is b > a).
_NEG = {"<": ">=", ">=": "<", ">": "<=", "<=": ">"}
_MIRROR = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}
_SYMMETRIC = ("==", "!=")


def strip_comments(text: str) -> str:
    """Drop the lines that are only comment: `//` lines, `/*` lines and every line up to the closing `*/`.

    A continuation line such as ` * text` counts as comment only inside an open `/*`. A line that starts
    with `*` outside a comment is code (a pointer store such as `*p = 1;`) and is kept.
    """
    kept: list[str] = []
    inside = False
    for line in text.split("\n"):
        stripped = line.strip()
        if inside:
            inside = "*/" not in stripped
            continue
        if stripped.startswith("//"):
            continue
        if stripped.startswith("/*"):
            inside = "*/" not in stripped
            continue
        kept.append(line)
    return "\n".join(kept)


def _changed_lines(a: str, b: str) -> tuple[list[str], list[str]]:
    return _diff(golden.normalise(a), golden.normalise(b))


def _diff(norm_a: str, norm_b: str) -> tuple[list[str], list[str]]:
    la, lb = norm_a.split("\n"), norm_b.split("\n")
    minus: list[str] = []
    plus: list[str] = []
    for line in difflib.unified_diff(la, lb, lineterm="", n=0):
        if line.startswith(("---", "+++", "@@")):
            continue
        (minus if line.startswith("-") else plus).append(line[1:])
    return minus, plus


def _keywords(lines: list[str]) -> Counter:
    return Counter(word for line in lines for word in _FLOW.findall(line))


def _count(pattern: re.Pattern, lines: list[str]) -> int:
    return sum(len(pattern.findall(line)) for line in lines)


def _sides(line: str):
    """The two operands of a line holding one condition with one comparison, or None."""
    inner = re.sub(r"^\s*(?:\}\s*)?(?:else\s+)?(?:if|while)\s*\(|\)\s*\{?\s*$", "", line)
    parts = _OPS.split(inner)
    return (parts[0].strip(), parts[1].strip()) if len(parts) == 2 else None


def _flipped(line_a: str, line_b: str) -> bool:
    """The same operands with the condition negated or mirrored. The operators are compared, not ignored:
    `x == 0` against `x < 0` is a different test, `x < 0` against `x >= 0` or `0 > x` is not."""
    line_a, line_b = _NUMBERED.sub(r"\1", line_a), _NUMBERED.sub(r"\1", line_b)  # iVar<1> is one name, not operators
    words_a, words_b = re.findall(r"\w+", _OPS.sub(" ", line_a)), re.findall(r"\w+", _OPS.sub(" ", line_b))
    if Counter(words_a) != Counter(words_b):
        return False
    ops_a, ops_b = _OPS.findall(line_a), _OPS.findall(line_b)
    if len(ops_a) != len(ops_b) or "!" in ops_a or "!" in ops_b:
        return False
    if len(ops_a) > 1:  # De Morgan: every connective must swap, otherwise this is not the negation
        swap = {"&&": "||", "||": "&&"}
        conn_a, conn_b = re.findall(r"&&|\|\|", line_a), re.findall(r"&&|\|\|", line_b)
        if not conn_a or [swap[c] for c in conn_a] != conn_b:
            return False
    same_order = words_a == words_b
    sides_a, sides_b = _sides(line_a), _sides(line_b)
    reversed_order = len(ops_a) == 1 and sides_a is not None and sides_b is not None and sides_a == sides_b[::-1]
    for first, second in zip(ops_a, ops_b):
        if first in _SYMMETRIC:
            if second not in _SYMMETRIC:
                return False
        elif same_order:
            if second != _NEG.get(first):
                return False
        elif reversed_order:
            if second not in (_MIRROR.get(first), _NEG.get(_MIRROR.get(first, ""))):
                return False
        else:
            return False
    return True


def _mirrored(line_a: str, line_b: str) -> bool:
    """Only the operands swapped sides with the operator mirrored: the same test, no change of polarity."""
    line_a, line_b = _NUMBERED.sub(r"", line_a), _NUMBERED.sub(r"", line_b)
    ops_a, ops_b = _OPS.findall(line_a), _OPS.findall(line_b)
    sides_a, sides_b = _sides(line_a), _sides(line_b)
    if len(ops_a) != 1 or len(ops_b) != 1 or sides_a is None or sides_b is None or sides_a != sides_b[::-1]:
        return False
    return ops_b[0] == ops_a[0] if ops_a[0] in _SYMMETRIC else ops_b[0] == _MIRROR.get(ops_a[0])


def _pure_condition_change(minus: list[str], plus: list[str]) -> bool:
    """Every changed line is a condition that is flipped or mirrored, or a statement that only moved
    (the same multiset of statements on both sides). Anything else changed is not a condition inversion."""
    cond_a = [x for x in minus if _COND.search(x)]
    cond_b = [x for x in plus if _COND.search(x)]
    if not cond_a or len(cond_a) != len(cond_b) or cond_a == cond_b:
        return False
    if not all(_flipped(x, y) for x, y in zip(cond_a, cond_b)):
        return False
    rest_a = Counter(x.strip() for x in minus if not _COND.search(x) and not _BRACE.match(x))
    rest_b = Counter(x.strip() for x in plus if not _COND.search(x) and not _BRACE.match(x))
    if rest_a != rest_b:
        return False
    # a polarity change is only a presentation difference when statements moved with it (branches swapped);
    # on its own it is a changed behaviour. A pure operand mirror has no polarity change and needs no move.
    return bool(rest_a) or all(_mirrored(x, y) for x, y in zip(cond_a, cond_b))


def signals(a: str, b: str) -> list[str]:
    """Every cause whose pattern shows up in the changed lines, in CAUSES order. Never empty."""
    # comments come off the raw text first, so that the renumbering of the machine-made names sees code only
    code_a, code_b = golden.normalise(strip_comments(a)), golden.normalise(strip_comments(b))
    raw_minus, raw_plus = _changed_lines(a, b)
    if code_a == code_b and golden.normalise(a) != golden.normalise(b):
        return ["warning-comment"]
    # the bad-data and unimplemented-instruction notes are comments, so they are looked for in the raw
    # lines; every other rule reads the lines with the comments removed
    minus, plus = _diff(code_a, code_b)
    both = minus + plus
    found: set[str] = set()
    if any(_BAD.search(line) for line in raw_minus + raw_plus):
        found.add("bad-data-limit")
    if any(_UNIMPL.search(line) for line in raw_minus + raw_plus):
        found.add("unimplemented-instruction")
    if _count(_SWITCH, minus) != _count(_SWITCH, plus) or any("jumptable" in line.lower() for line in both):
        found.add("switch-jump-table")
    if _count(_CONV, minus) != _count(_CONV, plus):
        found.add("calling-convention")
    body_a = Counter(x.strip() for x in minus if not _BRACE.match(x))
    body_b = Counter(x.strip() for x in plus if not _BRACE.match(x))
    if body_a and body_a == body_b:
        found.add("block-reorder")
    if _pure_condition_change(minus, plus):
        found.add("condition-inversion")
    if _keywords(minus) != _keywords(plus):
        found.add("control-flow")
    if _count(_STACK, minus) != _count(_STACK, plus) or any(_STACK.search(x) and re.search(r"\[\d+\]", x) for x in both):
        found.add("stack-layout")
    if any(_DECL.match(x) for x in both) and Counter(x.strip() for x in minus if _DECL.match(x)) != Counter(x.strip() for x in plus if _DECL.match(x)):
        found.add("local-types")
    if _count(_TYPE, minus) != _count(_TYPE, plus):
        found.add("types-casts")
    if Counter(c for line in minus for c in _CONST.findall(line)) != Counter(c for line in plus for c in _CONST.findall(line)):
        found.add("constants-data")
    # names only: after masking the machine-made names the changed lines are the same
    if len(minus) == len(plus) and [_NAME.sub("N", x) for x in minus] == [_NAME.sub("N", x) for x in plus]:
        found.add("variable-names")
    result = [name for name, _ in CAUSES if name in found]
    return result or ["other"]


def primary(signal_list: list[str]) -> str:
    # warning-comment is only primary when nothing about the code matched; the order of CAUSES decides the rest
    return signal_list[0]


def is_accepted(signal_list: list[str]) -> bool:
    """Accepted only when the primary cause is an accepted class AND no open-class cause matches the same
    function. A function whose condition is flipped and whose constants also changed stays open."""
    if POLICY[primary(signal_list)][0] != "accepted":
        return False
    return all(POLICY[name][0] == "accepted" for name in signal_list)


def option_differences(header_a: dict, header_b: dict) -> dict:
    """Option names whose values differ, with the pinned option reported separately. Names and values are not game data."""
    options_a, options_b = header_a.get("options") or {}, header_b.get("options") or {}
    differing = sorted(key for key in set(options_a) | set(options_b)
                       if key != PINNED_OPTION and options_a.get(key) != options_b.get(key))
    return {"differing_other_than_pinned": differing,
            "pinned_option": PINNED_OPTION,
            "pinned_in_A": options_a.get(PINNED_OPTION),
            "pinned_in_B": options_b.get(PINNED_OPTION),
            "equal_apart_from_pinned": not differing}


def _identity(header: dict) -> dict:
    engine = header.get("engine") or {}
    return {"label": header.get("label"), "ghidra_version": engine.get("ghidra_version"),
            "hydra_release": engine.get("hydra_release"), "program_sha256": header.get("program_sha256"),
            "function_rows": header.get("function_rows"), "path": header.get("path"),
            "options_mode": header.get("options_mode")}


def compare(dir_a, dir_b, dir_unpinned=None) -> dict:
    """Counts only. Raises ValueError when the two captures are not of the same program and path."""
    header_a, rows_a, text_a = golden.read_capture(dir_a, with_text=True)
    header_b, rows_b, text_b = golden.read_capture(dir_b, with_text=True)
    if header_a.get("program_sha256") != header_b.get("program_sha256"):
        raise ValueError("the captures are of different programs (program SHA-256 differs)")
    if header_a.get("path") != header_b.get("path"):
        raise ValueError("the captures use different decompile paths (%s against %s)" % (header_a.get("path"), header_b.get("path")))
    counts: Counter = Counter()
    primary_counts: Counter = Counter()
    signal_counts: Counter = Counter()
    changed_entries: set[str] = set()
    pure_counts: Counter = Counter()
    pure_accepted = 0
    for entry in sorted(set(rows_a) | set(rows_b)):
        kind = golden.classify(rows_a.get(entry), rows_b.get(entry))
        counts[kind] += 1
        if kind != "changed":
            continue
        changed_entries.add(entry)
        found = signals(text_a[entry], text_b[entry])
        first = primary(found)
        primary_counts[first] += 1
        if is_accepted(found):
            pure_counts[first] += 1
            pure_accepted += 1
        for name in found:
            signal_counts[name] += 1
    compared = sum(counts.values())
    identical = counts["identical"] + counts["identical_after_normalisation"]
    report = {
        "schema": 1,
        "kind": "golden-classification",
        "contains_c_text": False,
        "A": _identity(header_a),
        "B": _identity(header_b),
        "options": option_differences(header_a, header_b),
        "counts": {name: counts.get(name, 0) for name in golden.CLASSES},
        "functions_compared": compared,
        "functions_with_bad_data_text": {"A": sum(1 for t in text_a.values() if _BAD.search(t)),
                                         "B": sum(1 for t in text_b.values() if _BAD.search(t))},
        "identical_or_normalised": identical,
        "match_pct": round(100.0 * identical / compared, 3) if compared else None,
        "changed": counts["changed"],
        "by_primary_cause": {name: primary_counts.get(name, 0) for name, _ in CAUSES},
        "by_signal": {name: signal_counts.get(name, 0) for name, _ in CAUSES},
        "policy": {name: {"status": POLICY[name][0], "reason": POLICY[name][1], "functions": primary_counts.get(name, 0)}
                   for name, _ in CAUSES},
        "reported_not_gated": True,
    }
    candidate = sum(primary_counts[name] for name, _ in CAUSES if POLICY[name][0] == "accepted")
    report["candidate_accepted_functions"] = candidate
    report["accepted_functions"] = pure_accepted
    report["accepted_by_cause"] = {name: pure_counts.get(name, 0) for name, _ in CAUSES if POLICY[name][0] == "accepted"}
    report["open_functions"] = counts["changed"] - pure_accepted
    if dir_unpinned:
        report["maxBadData_effect"] = _effect(dir_a, dir_unpinned, rows_a, rows_b, changed_entries)
    return report


def _effect(dir_a, dir_unpinned, rows_a, rows_b, changed_pinned: set[str]) -> dict:
    """How the newer engine's own default for the pinned option changes the comparison."""
    header_u, rows_u, text_u = golden.read_capture(dir_unpinned, with_text=True)
    header_a, _, _ = golden.read_capture(dir_a)
    if header_u.get("program_sha256") != header_a.get("program_sha256"):
        raise ValueError("the unpinned capture is of a different program")
    changed_unpinned = {entry for entry in rows_a if golden.classify(rows_a.get(entry), rows_u.get(entry)) == "changed"}
    differ_b_u = {entry for entry in rows_b if golden.classify(rows_b.get(entry), rows_u.get(entry)) != "identical"
                  and golden.classify(rows_b.get(entry), rows_u.get(entry)) != "identical_after_normalisation"}
    return {"unpinned": _identity(header_u),
            "pinned_option_value_in_unpinned": (header_u.get("options") or {}).get(PINNED_OPTION),
            "functions_with_bad_data_text_unpinned": sum(1 for t in text_u.values() if _BAD.search(t)),
            "changed_vs_A_unpinned": len(changed_unpinned),
            "changed_vs_A_pinned": len(changed_pinned),
            "changed_only_when_unpinned": len(changed_unpinned - changed_pinned),
            "changed_only_when_pinned": len(changed_pinned - changed_unpinned),
            "changed_in_both": len(changed_unpinned & changed_pinned),
            "functions_where_pinned_and_unpinned_B_differ": len(differ_b_u)}


def compare_fixtures(root_a, root_b) -> dict:
    """One compare() per fixture directory name present in both roots (each holds <name>/explicit)."""
    root_a, root_b = Path(root_a), Path(root_b)
    names = sorted(p.name for p in root_a.iterdir() if p.is_dir() and (p / "explicit" / "rows.jsonl").is_file()
                   and (root_b / p.name / "explicit" / "rows.jsonl").is_file())
    per = {}
    for name in names:
        try:
            per[name] = compare(root_a / name / "explicit", root_b / name / "explicit")
        except ValueError as error:
            per[name] = {"error": str(error)}
    totals: Counter = Counter()
    for item in per.values():
        if "counts" in item:
            totals["compared"] += item["functions_compared"]
            totals["identical"] += item["identical_or_normalised"]
            totals["changed"] += item["changed"]
    return {"schema": 1, "kind": "golden-classification-fixtures", "contains_c_text": False, "reported_not_gated": True,
            "fixtures": per, "totals": dict(totals)}


def render_markdown(report: dict) -> str:
    """Counts-only Markdown. Numbers, cause names and engine labels only."""
    if report.get("kind") == "golden-classification-fixtures":
        lines = ["| fixture | compared | identical | changed | match % |", "| --- | ---: | ---: | ---: | ---: |"]
        for name, item in report["fixtures"].items():
            if "counts" in item:
                lines.append("| %s | %d | %d | %d | %s |" % (name, item["functions_compared"], item["identical_or_normalised"],
                                                             item["changed"], item["match_pct"]))
            else:
                lines.append("| %s | error | | | |" % name)
        return "\n".join(lines) + "\n"
    out = ["| | A | B |", "| --- | --- | --- |"]
    for key in ("label", "ghidra_version", "hydra_release", "function_rows", "options_mode"):
        out.append("| %s | %s | %s |" % (key, report["A"].get(key), report["B"].get(key)))
    out += ["", "Functions compared %d; identical or identical after normalisation %d (%s%%); changed %d."
            % (report["functions_compared"], report["identical_or_normalised"], report["match_pct"], report["changed"]), "",
            "| cause | functions | policy | reason |", "| --- | ---: | --- | --- |"]
    for name, description in CAUSES:
        item = report["policy"][name]
        out.append("| %s (%s) | %d | %s | %s |" % (name, description, item["functions"], item["status"], item["reason"]))
    out += ["", "Candidate accepted (primary cause is an accepted class): %d. Accepted with no open-class signal alongside: %d. Open: %d. Reported, never gated."
            % (report["candidate_accepted_functions"], report["accepted_functions"], report["open_functions"])]
    effect = report.get("maxBadData_effect")
    if effect:
        out += ["", "Effect of the %s option (the newer engine's default %s against the pinned value):" % (
            PINNED_OPTION, effect["pinned_option_value_in_unpinned"]), "",
            "| | functions |", "| --- | ---: |"]
        for key in ("functions_with_bad_data_text_unpinned", "changed_vs_A_unpinned", "changed_vs_A_pinned", "changed_only_when_unpinned", "changed_only_when_pinned",
                    "changed_in_both", "functions_where_pinned_and_unpinned_B_differ"):
            out.append("| %s | %d |" % (key, effect[key]))
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    one = commands.add_parser("classify", help="classify the changed functions of two captures")
    one.add_argument("a")
    one.add_argument("b")
    one.add_argument("--unpinned", help="a capture of B's engine with its own default of the pinned option")
    many = commands.add_parser("fixtures", help="classify every fixture present under two roots")
    many.add_argument("root_a")
    many.add_argument("root_b")
    for sub in (one, many):
        sub.add_argument("--json", help="write the counts-only report here")
        sub.add_argument("--markdown", help="write the counts-only Markdown here")
    args = parser.parse_args(argv)
    try:
        report = compare(args.a, args.b, args.unpinned) if args.command == "classify" else compare_fixtures(args.root_a, args.root_b)
    except (OSError, ValueError) as error:
        print("golden_classify: %s" % error, file=sys.stderr)
        return 2
    text = json.dumps(report, indent=1, sort_keys=False)
    if args.json:
        Path(args.json).write_text(text + "\n", encoding="utf-8", newline="\n")
    if args.markdown:
        Path(args.markdown).write_text(render_markdown(report), encoding="utf-8", newline="\n")
    if not args.json and not args.markdown:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
