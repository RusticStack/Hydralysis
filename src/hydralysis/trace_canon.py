"""The Python twin of the TRACE-1 canonical JSON, record hash and segment framing (TRACE-1 sections 3 and 4).

The Rust reference is `hydra-trace` (`canon.rs`, `raw.rs`). Both must write the same bytes, so this module carries the
same rules and `tests/test_trace_canon.py` pins them to fixed vectors (`tests/fixtures/trace_canon_vectors.json`)
that the Rust tests can read too:

* keys sorted (ASCII keys), separators `,` and `:` with no spaces;
* strings escape `"` `\\` `\\n` `\\r` `\\t` `\\b` `\\f`, and every other character below 0x20 or above 0x7e (so also
  0x7f) as lowercase `\\uXXXX`, with UTF-16 surrogate pairs above the BMP. `json.dumps(ensure_ascii=True)` is NOT
  enough: it leaves 0x7f alone;
* no floating point numbers, no NaN: times are integer nanoseconds, ratios are integer parts per million;
* a record is chained: `n`, `prev` and `hash`, where `hash` is SHA-256 of the canonical JSON without `hash`;
* a line is `crc SP json LF`, `crc` being 8 lowercase hex digits of CRC-32 (IEEE, `zlib.crc32`) of the JSON bytes;
* the genesis hash is SHA-256 of `"hydra.trace.segment/1\\n" + segment_id`.

`scan` keeps the outcomes a reader must keep apart: empty (no records, clean), torn tail, corrupt, chain break.
"""

from __future__ import annotations

import hashlib
import json
import re
import zlib
from dataclasses import dataclass, field

GENESIS = "hydra.trace.segment/1\n"
_INT_MIN, _INT_MAX = -(2 ** 63), 2 ** 64 - 1
_SIMPLE = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f"}


class NotCanonical(ValueError):
    """A value TRACE-1 does not allow in a chained record."""


_PLAIN = re.compile(r'[ !#-\[\]-~]*')    # 0x20..0x7e without " and \: written as they are


def _string(text: str, out: list) -> None:
    if _PLAIN.fullmatch(text):
        out.append('"' + text + '"')
        return
    out.append('"')
    for char in text:
        simple = _SIMPLE.get(char)
        if simple is not None:
            out.append(simple)
            continue
        code = ord(char)
        if code < 0x20 or code > 0x7e:
            if 0xD800 <= code <= 0xDFFF:
                raise NotCanonical("unpaired surrogate")
            if code > 0xFFFF:
                code -= 0x10000
                out.append("\\u%04x\\u%04x" % (0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)))
            else:
                out.append("\\u%04x" % code)
        else:
            out.append(char)
    out.append('"')


def _write(value, out: list) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if not _INT_MIN <= value <= _INT_MAX:
            raise NotCanonical("integer out of the 64-bit range")
        out.append(str(value))
    elif isinstance(value, float):
        raise NotCanonical("floating point number")
    elif isinstance(value, str):
        _string(value, out)
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for index, key in enumerate(sorted(value)):
            if not isinstance(key, str):
                raise NotCanonical("object key is not a string")
            if index:
                out.append(",")
            _string(key, out)
            out.append(":")
            _write(value[key], out)
        out.append("}")
    else:
        raise NotCanonical("%s is not a JSON value" % type(value).__name__)


def canonical_text(value) -> str:
    out: list = []
    _write(value, out)
    return "".join(out)


def canonical_bytes(value) -> bytes:
    """The canonical bytes of VALUE (ASCII). Raises NotCanonical for a float, a key that is not a string, ..."""
    return canonical_text(value).encode("ascii")


def genesis_hash(segment_id: str) -> str:
    return hashlib.sha256((GENESIS + segment_id).encode("utf-8")).hexdigest()


def record_hash(record: dict) -> str:
    """SHA-256 hex of the canonical JSON of RECORD without its `hash` member."""
    return hashlib.sha256(canonical_bytes({key: item for key, item in record.items() if key != "hash"})).hexdigest()


def body_hash_matches(body: bytes, record: dict) -> bool:
    """Whether RECORD's `hash` is the SHA-256 of BODY (the segment line's canonical JSON) without its `hash` member.

    The same answer as `record_hash(record) == record["hash"]` for a body that is the record's canonical JSON, found by
    cutting the member out of the bytes instead of canonicalising the parsed record again. It answers False, never
    "wrong", for any other body (not canonical, the digest also appearing elsewhere): the caller then asks
    `record_hash`, so what is accepted does not change."""
    claimed = record.get("hash")
    if not isinstance(claimed, str) or len(claimed) != 64:
        return False
    member = b'"hash":"' + claimed.encode("ascii") + b'"'
    if body.count(member) != 1:
        return False
    at = body.find(member)
    if body[at - 1:at] == b",":
        cut = body[:at - 1] + body[at + len(member):]
    elif body[at - 1:at] == b"{" and body[at + len(member):at + len(member) + 1] == b",":
        cut = body[:at] + body[at + len(member) + 1:]
    else:
        return False
    return hashlib.sha256(cut).hexdigest() == claimed


def frame(record: dict) -> bytes:
    """One segment line for RECORD, which already has n, prev and hash."""
    body = canonical_bytes(record)
    return b"%08x " % (zlib.crc32(body) & 0xFFFFFFFF) + body + b"\n"


class Chain:
    """The writer side: chains records from the genesis of one segment and returns their framed lines."""

    def __init__(self, segment_id: str):
        self.head = genesis_hash(segment_id)
        self.count = 0

    def push(self, record: dict) -> bytes:
        chained = dict(record)
        chained["n"] = self.count
        chained["prev"] = self.head
        chained["hash"] = record_hash(chained)
        line = frame(chained)
        self.head = chained["hash"]
        self.count += 1
        return line


@dataclass
class Scan:
    records: list = field(default_factory=list)
    valid_end: int = 0
    size: int = 0
    head: str = ""
    damage: dict | None = None  # {"kind": "torn_tail"|"corrupt"|"chain_break", "offset": int, ...}

    @property
    def clean(self) -> bool:
        return self.damage is None and self.valid_end == self.size

    @property
    def outcome(self) -> str:
        """empty, clean, torn_tail, corrupt or chain_break: five outcomes a reader keeps distinct."""
        if self.damage is not None:
            return self.damage["kind"]
        return "empty" if self.size == 0 else "clean"


def _parse_line(line: bytes):
    if len(line) < 10 or line[8:9] != b" ":
        return None
    try:
        crc = int(line[:8].decode("ascii"), 16)
        text = line[:8].decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return None
    if text != text.lower() or zlib.crc32(line[9:]) & 0xFFFFFFFF != crc:
        return None
    try:
        value = json.loads(line[9:].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def scan(data: bytes, segment_id: str) -> Scan:
    """Read and verify a whole segment: the valid chained prefix, and why the scan stopped early if it did."""
    out = Scan(size=len(data), head=genesis_hash(segment_id))
    cursor, line_no = 0, 0
    while cursor < len(data):
        end = data.find(b"\n", cursor)
        if end < 0:
            out.damage = {"kind": "torn_tail", "offset": cursor, "bytes": len(data) - cursor}
            return out
        line_no += 1
        record = _parse_line(data[cursor:end])
        if record is None:
            if end + 1 >= len(data):
                out.damage = {"kind": "torn_tail", "offset": cursor, "bytes": len(data) - cursor}
            else:
                out.damage = {"kind": "corrupt", "offset": cursor, "line": line_no}
            return out
        number = record.get("n")
        if isinstance(number, bool) or number != len(out.records):
            out.damage = {"kind": "chain_break", "offset": cursor, "reason": "numbering"}
            return out
        if record.get("prev") != out.head:
            out.damage = {"kind": "chain_break", "offset": cursor, "n": number, "reason": "prev"}
            return out
        try:
            expected = record_hash(record)
        except NotCanonical:
            expected = None
        if expected != record.get("hash"):
            out.damage = {"kind": "chain_break", "offset": cursor, "n": number, "reason": "hash"}
            return out
        out.head = expected
        out.records.append(record)
        cursor = end + 1
        out.valid_end = cursor
    return out
