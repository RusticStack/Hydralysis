"""RED4ext address-table lookup.

The game ships `cyberpunk2077_addresses.json` beside the exe. It is about
150 MB. Rows are scanned as text and never loaded as one JSON value.

Only segment 0001 is converted to an RVA, by adding the file's
"Code constant offset" (0x1000 on the builds this was written against).
Other segments are reported as seg:offset.
"""

from __future__ import annotations

import re
from pathlib import Path

_ENTRY = re.compile(
    rb'\{"hash":\s*"(\d+)"(?:,\s*"secondary hash":\s*"[0-9a-f]+")?'
    rb'(?:,\s*"symbol":\s*"([^"]*)")?,\s*"offset":\s*"([0-9A-Fa-f]{4}):([0-9A-Fa-f]+)"\}'
)
_CCO = re.compile(rb'"Code constant offset":\s*"([0-9A-Fa-f]+)"')


def code_constant_offset(path: Path) -> int:
    with path.open("rb") as handle:
        head = handle.read(600)
    match = _CCO.search(head)
    if match:
        return int(match.group(1), 16)
    return 0x1000


def iter_entries(path: Path, chunk_size: int = 4 * 1024 * 1024, overlap: int = 4096):
    """Yield (hash, symbol, segment, offset) for every row.

    Reads the file in chunks. A row split across two reads stays in the
    buffer until it is complete. `overlap` is accepted and unused; the
    unfinished tail is kept exactly.
    """
    del overlap
    pending = b""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            pending += chunk
            matches = list(_ENTRY.finditer(pending))
            if not chunk:
                for match in matches:
                    yield _row(match)
                break
            if not matches:
                start = pending.rfind(b'{"hash":')
                pending = pending[start:] if start >= 0 else pending[-2048:]
                continue
            for match in matches:
                yield _row(match)
            pending = pending[matches[-1].end():]


def _row(match: re.Match) -> tuple[int, str, str, int]:
    symbol = (match.group(2) or b"").decode("utf-8", "replace")
    return (
        int(match.group(1)),
        symbol,
        match.group(3).decode("ascii"),
        int(match.group(4), 16),
    )


def format_hit(hash_value: int, symbol: str, segment: str, offset: int, cco: int) -> str:
    if segment == "0001":
        where = hex(offset + cco)
    else:
        where = "%s:%x (not an RVA)" % (segment, offset)
    return "%d %s %s %s %s" % (hash_value, hex(hash_value), segment, where, symbol)


def lookup_hashes(path: Path, wanted: set[int], chunk_size: int = 4 * 1024 * 1024, overlap: int = 4096) -> list[str]:
    cco = code_constant_offset(path)
    found = []
    for row in iter_entries(path, chunk_size=chunk_size, overlap=overlap):
        if row[0] in wanted:
            found.append(format_hit(*row, cco))
    return found


def lookup_rvas(path: Path, rvas: set[int], chunk_size: int = 4 * 1024 * 1024) -> list[str]:
    """Match segment 0001 rows whose offset + code constant offset is in `rvas`."""
    cco = code_constant_offset(path)
    found = []
    for hash_value, symbol, segment, offset in iter_entries(path, chunk_size=chunk_size):
        if segment == "0001" and (offset + cco) in rvas:
            found.append(format_hit(hash_value, symbol, segment, offset, cco))
    return found
