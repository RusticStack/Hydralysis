"""Match a function's first bytes against an expect prologue.

`??` or `?` is a wildcard byte. A mismatch means the function moved or the
build changed, so a stored name must not be applied.
"""

from __future__ import annotations

import re


def parse_expect(text: str) -> list[int | None]:
    if not isinstance(text, str):
        raise ValueError("expect prologue must be a hexadecimal string")
    parts = text.replace(",", " ").replace("\\x", " ").replace("\\X", " ").split()
    if not parts:
        raise ValueError("expect prologue is empty")
    out: list[int | None] = []
    for part in parts:
        if part in ("?", "??"):
            out.append(None)
            continue
        part = re.sub(r"^0[xX]", "", part)
        if len(part) <= 2 and re.fullmatch(r"[0-9a-fA-F]{1,2}", part):
            out.append(int(part, 16))
            continue
        if not part or len(part) % 2 or not re.fullmatch(r"(?:[0-9a-fA-F]{2}|\?\?)+", part):
            raise ValueError("prologue requires whole hexadecimal bytes or ?? wildcards: %s" % part)
        out.extend(None if part[index:index + 2] == "??" else int(part[index:index + 2], 16)
                   for index in range(0, len(part), 2))
    if all(value is None for value in out):
        raise ValueError("expect prologue must contain at least one concrete byte")
    return out


def compare_table(image, rows: list[dict], resolve_address) -> dict:
    """Verify bounded rows against one already-open PE; never modify its bytes.

    `expect` is one prologue or a list of accepted alternatives (a table that knows
    several prologues for one function); a row matches when any alternative does, and
    the result names which. The address resolver shares the caller's RVA/VA policy.
    Validate the entire request before reading any prologue, so a malformed last row
    cannot produce a misleading partial verification result.
    """
    if not isinstance(rows, list) or not 1 <= len(rows) <= 200:
        raise ValueError("prologue table needs 1..200 rows")
    prepared = []
    total = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) - {"address", "expect", "name"}:
            raise ValueError("prologue row %d accepts address, expect and optional name only" % index)
        address, expect, name = row.get("address"), row.get("expect"), row.get("name", "")
        if not isinstance(address, str) or not address.strip() or len(address) > 128:
            raise ValueError("prologue row %d needs an address string" % index)
        alternatives = expect if isinstance(expect, list) else [expect]
        if not 1 <= len(alternatives) <= 16 or any(not isinstance(item, str) or len(item) > 32768 for item in alternatives):
            raise ValueError("prologue row %d needs an expect string or a list of 1..16 accepted alternatives" % index)
        if not isinstance(name, str) or len(name) > 256:
            raise ValueError("prologue row %d name must be at most 256 characters" % index)
        patterns = [parse_expect(item) for item in alternatives]
        if max(len(pattern) for pattern in patterns) > 4096:
            raise ValueError("prologue row %d exceeds 4096 bytes" % index)
        total += sum(len(pattern) for pattern in patterns)
        if total > 65536:
            raise ValueError("prologue table exceeds 65536 total bytes")
        rva = resolve_address(address)
        if not isinstance(rva, int) or isinstance(rva, bool) or rva < 0:
            raise ValueError("prologue row %d resolved to an invalid RVA" % index)
        if image.rva_to_offset(rva) is None or max(len(pattern) for pattern in patterns) > image._available(rva):
            raise ValueError("prologue row %d is outside a file-backed section" % index)
        prepared.append((name, address, rva, patterns))
    fingerprint = image.fingerprint()
    results = []
    matched = 0
    for name, address, rva, patterns in prepared:
        actual = image.read_rva(rva, max(len(pattern) for pattern in patterns))
        which = next((index for index, pattern in enumerate(patterns) if matches(actual, pattern)), None)
        matched += int(which is not None)
        row = {"name": name, "input_address": address, "rva": "rva:%#x" % rva, "va": "va:%#x" % (image.base + rva),
               "expect": [" ".join("??" if value is None else "%02X" % value for value in pattern) for pattern in patterns]
               if len(patterns) > 1 else " ".join("??" if value is None else "%02X" % value for value in patterns[0]),
               "actual": format_bytes(actual), "match": which is not None}
        if len(patterns) > 1:
            row["matched_alternative"] = which
        results.append(row)
    return {"fingerprint": fingerprint, "rows": results,
            "summary": {"checked": len(results), "matched": matched, "failed": len(results) - matched},
            "matched": matched == len(results)}


def format_bytes(data: bytes) -> str:
    return " ".join("%02X" % b for b in data)


def matches(data: bytes, expect: list[int | None]) -> bool:
    if not expect or all(value is None for value in expect) or len(data) < len(expect):
        return False
    return all(want is None or data[index] == want for index, want in enumerate(expect))


def find_pattern(haystack: bytes, pattern: list[int | None], limit: int) -> list[int]:
    """Find a literal anchor in C, then check only the candidate windows."""
    if not pattern or limit <= 0:
        return []
    if all(value is None for value in pattern):
        raise ValueError("signature must contain at least one concrete byte")
    anchor_start, anchor = 0, b""
    run_start, run = 0, bytearray()
    for index, value in enumerate(pattern + [None]):
        if value is None:
            if len(run) > len(anchor):
                anchor_start, anchor = run_start, bytes(run)
            run.clear()
        else:
            if not run:
                run_start = index
            run.append(value)
    hits = []
    start = anchor_start
    stop = len(haystack) - len(pattern) + anchor_start + len(anchor)
    concrete = [(index, value) for index, value in enumerate(pattern) if value is not None]
    while start <= stop - len(anchor):
        found = haystack.find(anchor, start, stop)
        if found < 0:
            break
        index = found - anchor_start
        if all(haystack[index + offset] == value for offset, value in concrete):
            hits.append(index)
            if len(hits) >= limit:
                break
        start = found + 1
    return hits


def compare(data: bytes, expect_text: str) -> str:
    expect = parse_expect(expect_text)
    got = data[: len(expect)]
    if matches(got, expect):
        return "PROLOGUE MATCH %s" % format_bytes(got)
    return "PROLOGUE MISMATCH expect %s got %s" % (expect_text, format_bytes(got))
