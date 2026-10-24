"""Match a function's first bytes against an expect prologue.

`??` or `?` is a wildcard byte. A mismatch means the function moved or the
build changed, so a stored name must not be applied.
"""

from __future__ import annotations


def parse_expect(text: str) -> list[int | None]:
    parts = text.replace(",", " ").split()
    if not parts:
        raise ValueError("expect prologue is empty")
    out: list[int | None] = []
    for part in parts:
        if part in ("?", "??"):
            out.append(None)
            continue
        value = int(part, 16)
        if not 0 <= value <= 0xFF:
            raise ValueError("prologue byte out of range: %s" % part)
        out.append(value)
    if all(value is None for value in out):
        raise ValueError("expect prologue must contain at least one concrete byte")
    return out


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
