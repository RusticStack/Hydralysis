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
    return out


def format_bytes(data: bytes) -> str:
    return " ".join("%02X" % b for b in data)


def matches(data: bytes, expect: list[int | None]) -> bool:
    if len(data) < len(expect):
        return False
    return all(want is None or data[index] == want for index, want in enumerate(expect))


def find_pattern(haystack: bytes, pattern: list[int | None], limit: int) -> list[int]:
    if not pattern or limit <= 0:
        return []
    hits = []
    last = len(haystack) - len(pattern) + 1
    for index in range(max(0, last)):
        if matches(haystack[index : index + len(pattern)], pattern):
            hits.append(index)
            if len(hits) >= limit:
                break
    return hits


def find_pattern(haystack: bytes, pattern: list[int | None], limit: int) -> list[int]:
    """Offsets where `pattern` matches. `None` is a wildcard byte."""
    if not pattern or limit <= 0:
        return []
    hits = []
    last = len(haystack) - len(pattern) + 1
    width = len(pattern)
    for index in range(max(0, last)):
        if matches(haystack[index : index + width], pattern):
            hits.append(index)
            if len(hits) >= limit:
                break
    return hits


def compare(data: bytes, expect_text: str) -> str:
    expect = parse_expect(expect_text)
    got = data[: len(expect)]
    if matches(got, expect):
        return "PROLOGUE MATCH %s" % format_bytes(got)
    return "PROLOGUE MISMATCH expect %s got %s" % (expect_text, format_bytes(got))
