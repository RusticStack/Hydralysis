"""The semantic trace's wire layer: canonical JSON, the chained raw segment, keyed ids and the agent's binary batch.

This module is the pure-Python twin of the Rust helpers in `native/src/trace.rs` (`hydralysis_native`). Both give
byte-identical results (tests/test_trace_wire.py runs the same inputs through both). The worker uses the native
encoder when it is built; nothing here depends on it.

Agent batch (little endian), sent by the in-process agent as `send(message, data)`:

    header, 64 bytes
        0 u32 magic 0x31425448 ("HTB1")    4 u16 version (1)       6 u16 header length (64)
        8 u32 producer_gen                 12 u32 batch_seq        16 u64 qpc at flush
        24 u32 record count                28 u32 record bytes
        32 u64 attempted (cumulative)      40 u64 dropped (cumulative, ring full)
        48 u64 read_failed (cumulative)    56 u64 no_ring (cumulative, threads past the ring budget)
    records, back to back, each 8-byte aligned
        0 u16 size   2 u8 kind (low nibble 1 = call; high nibble = extra call-stack addresses, 0..15)   3 u8 flags
        4 u16 site   6 u16 ring
        8 u64 qpc    16 u32 thread id     20 u32 ring_seq (every attempted record takes one, dropped or not)
        24 u64 return address   32 u64 qpc at return   40 u64 return value   48 u32 last error
        52 u16 argument count   54 u16 buffer length   56 u64 buffer address   64 u64 args[count]
        then u64 stack[kind >> 4] (the caller chain, the return address first)   then the buffer bytes

    flags: 1 has return, 2 buffer read failed, 4 buffer truncated, 8 buffer is a wide string, 16 buffer present

A record's text never leaves the encoder: a buffer becomes a keyed id (HMAC-SHA256 under the scope key, 128 bits) and
its length. Only a site armed for payload mode, with an authorization, yields a content-addressed artifact.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import zlib

GENESIS = "hydra.trace.segment/1\n"
MAGIC = 0x31425448
HEADER = struct.Struct("<IHHIIQIIQQQQ")
HEADER_BYTES = 64
RECORD = struct.Struct("<HBBHHQIIQQQIHHQ")
RECORD_BYTES = 64
F_RET, F_READ_FAILED, F_TRUNCATED, F_WIDE, F_BUF = 1, 2, 4, 8, 16
INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF
DEVICE_PREFIXES = ("\\\\.\\", "\\\\?\\")


class WireError(ValueError):
    """A batch or a value the contract does not allow."""


# ---- canonical JSON (TRACE-1 section 4) ---------------------------------------------------------------------------
def _string(text: str) -> str:
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif code < 0x20 or code > 0x7E:
            if code > 0xFFFF:
                code -= 0x10000
                out.append("\\u%04x\\u%04x" % (0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)))
            else:
                out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _write(value, out: list) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(int(value)))
    elif isinstance(value, float):
        raise WireError("not canonical: floating point number")
    elif isinstance(value, str):
        out.append(_string(value))
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
            if index:
                out.append(",")
            out.append(_string(str(key)))
            out.append(":")
            _write(value[key], out)
        out.append("}")
    else:
        raise WireError("not canonical: %s" % type(value).__name__)


def canon(value) -> bytes:
    """The canonical bytes of a JSON value: sorted keys, minimal separators, ASCII only (DEL and above escaped), no floats."""
    out: list = []
    _write(value, out)
    return "".join(out).encode("ascii")


def genesis_hash(segment: str) -> str:
    return hashlib.sha256((GENESIS + segment).encode("utf-8")).hexdigest()


def frame(record: dict) -> bytes:
    body = canon(record)
    return b"%08x %s\n" % (zlib.crc32(body) & 0xFFFFFFFF, body)


def record_hash(record: dict) -> str:
    return hashlib.sha256(canon({k: v for k, v in record.items() if k != "hash"})).hexdigest()


def keyed_id(key: bytes, data: bytes) -> str:
    """The correlation id of some bytes: HMAC-SHA256 under the scope key, truncated to 128 bits, hex."""
    return hmac.new(key, data, hashlib.sha256).digest()[:16].hex()


def normalize_path(units: bytes) -> bytes:
    """A wide path with ASCII letters lower-cased and `/` as `\\` (the same rule in Rust: no Unicode tables)."""
    out = bytearray(units)
    for index in range(0, len(out) - 1, 2):
        low, high = out[index], out[index + 1]
        if high == 0:
            if 0x41 <= low <= 0x5A:
                out[index] = low + 32
            elif low == 0x2F:
                out[index] = 0x5C
    return bytes(out)


def wide_text(units: bytes) -> str:
    """Wide-string bytes up to the first NUL unit, as a str (for classification only; lone surrogates are replaced)."""
    end = len(units) - len(units) % 2
    for index in range(0, end, 2):
        if units[index] == 0 and units[index + 1] == 0:
            end = index
            break
    return units[:end].decode("utf-16le", "replace")


def is_device_path(units: bytes) -> bool:
    """`\\\\.\\X` or `\\\\?\\X` where X is not a drive letter followed by a colon (that is a file path)."""
    text = bytearray()
    for index in range(0, min(len(units), 16) - 1, 2):
        if units[index + 1] != 0:
            break
        text.append(units[index])
    head = bytes(text)
    if not (head.startswith(b"\\\\.\\") or head.startswith(b"\\\\?\\")):
        return False
    rest = head[4:]
    return not (len(rest) >= 2 and rest[1:2] == b":" and rest[:1].isalpha())


# ---- redacted previews (spec 14.12; at most 256 bytes; only for a probe the capture request authorizes) -----------------
PREVIEW_MAX = 256
SECRET_WORDS = ("password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "api-key", "authorization", "credential",
                "private_key", "private-key", "cookie", "session", "signature", "auth", "bearer", "basic")
_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_.-")
_DELIMITERS = frozenset(" &;,\"'	")


def _printable(raw: bytes, wide: bool) -> str:
    """ASCII text for a preview: printable ASCII stays, everything else becomes '.', up to the first NUL."""
    out = []
    if wide:
        for index in range(0, len(raw) - 1, 2):
            unit = raw[index] | (raw[index + 1] << 8)
            if unit == 0:
                break
            out.append(chr(unit) if 0x20 <= unit < 0x7F else ".")
    else:
        for byte in raw:
            if byte == 0:
                break
            out.append(chr(byte) if 0x20 <= byte < 0x7F else ".")
    return "".join(out)


def redact_preview(raw: bytes, wide: bool = False, limit: int = PREVIEW_MAX) -> tuple:
    """(preview text, masked span count). Secret-like text never survives:

    1. a secret word (password, token, api key, authorization, bearer, ...), optionally continued by the rest of its name,
       followed by `:` or `=` (quotes and spaces allowed between), or by a space for `bearer`/`basic`, masks the value up to the next delimiter;
    2. any run of 20 or more token characters (letters, digits, + / _ . -) that holds a letter and a digit is masked
       (hex and base64 keys, JWTs, access keys);
    3. spans merge into one `***`, and the text is cut at `limit` bytes (never more than 256).
    The scanner is hand-written (no regex) so that the Rust twin gives the same bytes."""
    text = _printable(raw, wide)
    lower = text.lower()
    masked = [False] * len(text)
    for word in SECRET_WORDS:
        start = lower.find(word)
        while start >= 0:
            i = start + len(word)
            while i < len(text) and (text[i].isalnum() or text[i] in "_-"):      # the rest of the name: sessionid, token_value
                i += 1
            while i < len(text) and text[i] in "\"' ":
                i += 1
            if i < len(text) and (text[i] in ":=" or (word in ("bearer", "basic") and start + len(word) < len(text)
                                                       and text[start + len(word)] == " ")):
                if text[i] in ":=":
                    i += 1
                while i < len(text) and text[i] in "\"' ":
                    i += 1
                end = i
                while end < len(text) and text[end] not in _DELIMITERS:
                    end += 1
                for k in range(i, end):
                    masked[k] = True
            start = lower.find(word, start + 1)
    i = 0
    while i < len(text):
        if text[i] in _TOKEN_CHARS:
            j = i
            while j < len(text) and text[j] in _TOKEN_CHARS:
                j += 1
            run = text[i:j]
            if j - i >= 20 and any(c.isdigit() for c in run) and any(c.isalpha() for c in run):
                for k in range(i, j):
                    masked[k] = True
            i = j
        else:
            i += 1
    out, spans, k = [], 0, 0
    while k < len(text):
        if masked[k]:
            while k < len(text) and masked[k]:
                k += 1
            out.append("***")
            spans += 1
        else:
            out.append(text[k])
            k += 1
    return "".join(out)[:min(limit, PREVIEW_MAX)], spans


# ---- the raw segment -----------------------------------------------------------------------------------------------
class Chain:
    """Chain records into one segment: sets `n`, `prev` and `hash`, returns the framed line."""

    def __init__(self, segment: str, head: str | None = None, n: int = 0):
        self.head = head or genesis_hash(segment)
        self.n = n

    def push(self, record: dict) -> bytes:
        record = dict(record)
        record["n"], record["prev"] = self.n, self.head
        record["hash"] = record_hash(record)
        line = frame(record)
        self.head = record["hash"]
        self.n += 1
        return line


# ---- the agent's batch ----------------------------------------------------------------------------------------------
def build_batch(producer_gen: int, batch_seq: int, qpc: int, counters: tuple, records: list) -> bytes:
    """A batch as the agent would send it (tests and the replay of captured traffic). `records` are dicts with the
    record fields; `args` and `buf` are lists / bytes."""
    body = bytearray()
    for r in records:
        args = list(r.get("args", ()))
        buf = bytes(r.get("buf", b""))
        stack = list(r.get("stack", ()))[:15]
        size = RECORD_BYTES + 8 * len(args) + 8 * len(stack) + (len(buf) + 7) // 8 * 8
        flags = r.get("flags", 0) | (F_BUF if (buf or r.get("flags", 0) & F_READ_FAILED) else 0)
        body += RECORD.pack(size, 1 | (len(stack) << 4), flags, r["site"], r["ring"], r["qpc"], r["tid"], r["ring_seq"], r.get("ret_addr", 0),
                            r.get("qpc_end", 0), r.get("retval", 0), r.get("last_error", 0), len(args), len(buf),
                            r.get("buf_addr", 0))
        for a in args:
            body += struct.pack("<Q", a)
        for a in stack:
            body += struct.pack("<Q", a)
        body += buf + b"\0" * ((-len(buf)) % 8)
    attempted, dropped, read_failed, no_ring = counters
    return HEADER.pack(MAGIC, 1, HEADER_BYTES, producer_gen, batch_seq, qpc, len(records), len(body), attempted, dropped,
                       read_failed, no_ring) + bytes(body)


def decode_batch(data: bytes) -> tuple:
    """(header dict, records list). Raises WireError on anything that is not a whole, consistent batch."""
    if len(data) < HEADER_BYTES:
        raise WireError("batch shorter than its header")
    (magic, version, hlen, gen, seq, qpc, count, plen, attempted, dropped, failed, no_ring) = HEADER.unpack_from(data, 0)
    if magic != MAGIC or version != 1 or hlen != HEADER_BYTES:
        raise WireError("not an HTB1 batch")
    if HEADER_BYTES + plen != len(data):
        raise WireError("batch length does not match its header")
    header = {"producer_gen": gen, "batch_seq": seq, "qpc": qpc, "count": count, "attempted": attempted,
              "dropped": dropped, "read_failed": failed, "no_ring": no_ring}
    records, cursor = [], HEADER_BYTES
    for _ in range(count):
        if cursor + RECORD_BYTES > len(data):
            raise WireError("record runs past the batch")
        (size, kind, flags, site, ring, rqpc, tid, rseq, ret_addr, qpc_end, retval, last_error, nargs, buflen,
         buf_addr) = RECORD.unpack_from(data, cursor)
        depth = kind >> 4
        if kind & 15 != 1 or size != RECORD_BYTES + 8 * nargs + 8 * depth + (buflen + 7) // 8 * 8 or cursor + size > len(data):
            raise WireError("record size is inconsistent")
        args = list(struct.unpack_from("<%dQ" % nargs, data, cursor + RECORD_BYTES)) if nargs else []
        stack = list(struct.unpack_from("<%dQ" % depth, data, cursor + RECORD_BYTES + 8 * nargs)) if depth else []
        start = cursor + RECORD_BYTES + 8 * nargs + 8 * depth
        records.append({"kind": kind & 15, "stack": stack, "flags": flags, "site": site, "ring": ring, "qpc": rqpc, "tid": tid, "ring_seq": rseq,
                        "ret_addr": ret_addr, "qpc_end": qpc_end, "retval": retval, "last_error": last_error,
                        "args": args, "buf": bytes(data[start:start + buflen]), "buf_addr": buf_addr})
        cursor += size
    if cursor != len(data):
        raise WireError("bytes after the last record")
    return header, records


# ---- the encoder ----------------------------------------------------------------------------------------------------
def _tick_ns(ticks: int, freq: int) -> int:
    return ticks * 1_000_000_000 // freq


class SegmentEncoder:
    """Turns agent batches into chained TRACE-1 events. The Python twin of `hydralysis_native.SegmentEncoder`.

    `sites` maps a site id to {name, kind ("call" | "open" | "ioctl" | "devquery" | "close" | "event"), module, va,
    buf: "id" | "payload" | None, preview: bytes of redacted preview (0: none), wide: the buffer is UTF-16, buf_arg: the
    argument holding the buffer pointer, event: the event kind a profile hook produces, fields: [{name, type, source}]}.
    Outputs are lines to append to the segment; `artifacts` (payload mode only) must be durable before the lines are.
    """

    def __init__(self, segment_id: str, source_id: str, producer_gen: int, process_id: int, sites: dict, key: bytes,
                 qpc_freq: int, payload_authorized: bool = False, max_payload: int = 4096):
        if qpc_freq <= 0:
            raise WireError("qpc_freq must be positive")
        self.segment_id, self.source_id, self.producer_gen, self.process_id = segment_id, source_id, producer_gen, process_id
        self.sites = {int(k): v for k, v in sites.items()}
        self.key, self.freq = bytes(key), qpc_freq
        self.payload_ok, self.max_payload = payload_authorized, max_payload
        self.chain = Chain(segment_id)
        self.source_seq = 0
        self.ring_next: dict = {}
        self.batch_next = None
        self.dropped_seen = 0
        self.dropped_attributed = 0
        self.handles: dict = {}
        self.hits: dict = {}
        self.stats = {"batches": 0, "records": 0, "events": 0, "gaps": 0, "ring_gaps": 0, "transport_gaps": 0,
                      "dropped_in_band": 0, "read_failures": 0, "payload_refused": 0, "previews": 0, "redactions": 0, "close_unknown": 0, "last_attempted": 0, "last_dropped": 0,
                      "last_read_failed": 0, "last_no_ring": 0, "bad_batches": 0}

    @property
    def head(self) -> str:
        return self.chain.head

    def site_hits(self) -> dict:
        """Records seen per site id (a frame counter for the stall watchdog needs only this)."""
        return dict(self.hits)

    @property
    def count(self) -> int:
        return self.chain.n

    # -- one event ---------------------------------------------------------------------------------------------------
    def _event(self, kind: str, t_ns: int, tid, payload: dict, va=None, callstack=None, module=None) -> bytes:
        event = {"kind": kind, "source_id": self.source_id, "source_seq": self.source_seq, "producer_gen": self.producer_gen,
                 "clock_domain": "qpc-10mhz", "t_mono_ns": t_ns, "process_id": self.process_id, "confidence": "exact",
                 "acquisition": "atomic", "payload": payload}
        if tid is not None:
            event["thread_id"] = tid
        if va:
            event["va"] = va
        if callstack:
            event["callstack"] = callstack
        if module:
            event["module"] = module
        self.source_seq += 1
        self.stats["events"] += 1
        return self.chain.push(event)

    def encode_event(self, kind: str, t_ns: int, payload: dict, tid=None, skip: int = 0) -> bytes:
        """A control event (`core.capture.source`, `core.capture.gap`, `core.marker`): framed, chained, numbered."""
        if skip:
            self.source_seq += skip
        if kind == "core.capture.gap":
            self.stats["gaps"] += 1
        return self._event(kind, t_ns, tid, payload)

    # -- a batch -----------------------------------------------------------------------------------------------------
    def encode_batch(self, data: bytes) -> tuple:
        """(lines, artifacts, info). Raises WireError (and changes nothing) for a batch that does not decode."""
        try:
            header, records = decode_batch(data)
        except WireError:
            self.stats["bad_batches"] += 1
            raise
        stats = self.stats
        out = bytearray()
        artifacts: dict = {}
        t_flush = _tick_ns(header["qpc"], self.freq)
        if header["producer_gen"] != self.producer_gen:
            raise WireError("batch is from producer generation %d, this encoder is generation %d"
                            % (header["producer_gen"], self.producer_gen))
        if self.batch_next is not None and header["batch_seq"] != self.batch_next:
            lost = (header["batch_seq"] - self.batch_next) & 0xFFFFFFFF
            stats["transport_gaps"] += 1
            out += self.encode_event("core.capture.gap", t_flush, {"reason": "producer-lost", "hop": "transport",
                                     "batches_missing": lost, "first_missing_batch": self.batch_next, "out_of_band": False})
        self.batch_next = (header["batch_seq"] + 1) & 0xFFFFFFFF
        stats["batches"] += 1
        stats["records"] += len(records)
        # Per ring, in ring_seq order: how many records are missing before this one.
        before: dict = {}
        for index, r in sorted(enumerate(records), key=lambda p: (p[1]["ring"], (p[1]["ring_seq"] - self.ring_next.get(p[1]["ring"], 0)) & 0xFFFFFFFF)):
            expect = self.ring_next.get(r["ring"], 0)
            missing = (r["ring_seq"] - expect) & 0xFFFFFFFF
            if missing:
                before[index] = missing
            self.ring_next[r["ring"]] = (r["ring_seq"] + 1) & 0xFFFFFFFF
        new_drops = max(0, header["dropped"] - self.dropped_seen)
        self.dropped_seen = max(self.dropped_seen, header["dropped"])
        explained = new_drops
        order = sorted(range(len(records)), key=lambda i: (records[i]["qpc"], records[i]["ring"], records[i]["ring_seq"]))
        for index in order:
            r = records[index]
            missing = before.get(index, 0)
            if missing:
                ring_part = min(missing, explained)
                explained -= ring_part
                stats["dropped_in_band"] += ring_part
                stats["ring_gaps"] += 1
                first = self.source_seq
                self.source_seq += missing
                reason = "ring-overflow" if ring_part == missing else "producer-lost"
                out += self.encode_event("core.capture.gap", _tick_ns(r["qpc"], self.freq),
                                         {"reason": reason, "dropped": missing, "ring": r["ring"], "out_of_band": False,
                                          "first_missing_source_seq": first, "last_missing_source_seq": first + missing - 1,
                                          "attributed_to_overflow": ring_part}, tid=r["tid"])
            out += self._call(r, artifacts)
        stats["last_attempted"], stats["last_dropped"] = header["attempted"], header["dropped"]
        stats["last_read_failed"], stats["last_no_ring"] = header["read_failed"], header["no_ring"]
        return bytes(out), artifacts, {"records": len(records), "batch_seq": header["batch_seq"]}

    def finalize(self, rings: list, t_ns: int, no_ring: int = 0) -> bytes:
        """The loss no later record could reveal, from the agent's out-of-band per-ring counters at the end.

        `rings` is [{ring, attempted, dropped}]. A ring whose attempted count is past what was received gets a gap
        marked out_of_band; so does any thread that never got a ring."""
        out = bytearray()
        for row in sorted(rings, key=lambda x: x["ring"]):
            expect = self.ring_next.get(row["ring"], 0)
            missing = (row["attempted"] - expect) & 0xFFFFFFFF
            if row["attempted"] >= expect and missing:
                first = self.source_seq
                self.source_seq += missing
                self.ring_next[row["ring"]] = row["attempted"] & 0xFFFFFFFF
                self.stats["ring_gaps"] += 1
                out += self.encode_event("core.capture.gap", t_ns, {
                    "reason": "ring-overflow" if row.get("dropped", 0) >= missing else "producer-lost", "dropped": missing,
                    "ring": row["ring"], "out_of_band": True, "first_missing_source_seq": first,
                    "last_missing_source_seq": first + missing - 1})
        if no_ring:
            out += self.encode_event("core.capture.gap", t_ns, {"reason": "budget", "dropped": no_ring, "out_of_band": True,
                                                                 "detail": "threads past the agent's ring budget"})
        return bytes(out)

    # -- a call record -----------------------------------------------------------------------------------------------
    def _buffer(self, site: dict, r: dict, artifacts: dict):
        """The payload entry for a record's buffer: a keyed id and length, an artifact only in authorized payload mode."""
        if not r["flags"] & F_BUF:
            return None
        entry = {"addr": r["buf_addr"]}
        if r["flags"] & F_READ_FAILED:
            self.stats["read_failures"] += 1
            entry.update(read_failed=True, len=0)
            return entry
        raw = r["buf"]
        if r["flags"] & F_WIDE:
            for index in range(0, len(raw) - 1, 2):
                if raw[index] == 0 and raw[index + 1] == 0:
                    raw = raw[:index]
                    break
        entry.update(id=keyed_id(self.key, raw), len=len(raw), truncated=bool(r["flags"] & F_TRUNCATED))
        if site.get("preview"):
            text, spans = redact_preview(raw, bool(r["flags"] & F_WIDE), int(site["preview"]))
            entry.update(preview=text, redacted=spans)
            self.stats["previews"] += 1
            self.stats["redactions"] += spans
        if site.get("buf") == "payload":
            if self.payload_ok:
                digest = hashlib.sha256(raw[:self.max_payload]).hexdigest()
                artifacts[digest] = bytes(raw[:self.max_payload])
                entry["artifact"] = {"sha256": digest, "len": min(len(raw), self.max_payload), "export": False}
            else:
                self.stats["payload_refused"] += 1
                entry["payload"] = "payload-not-authorized"
        return entry

    def _field(self, field: dict, r: dict, site: dict, buf):
        """One declared field of a profile event, from an argument or the return value. A buffer is never stored as
        text: it is a keyed id and a length (and a redacted preview only when the capture authorized one)."""
        source = field["source"]
        if source == "ret":
            if not r["flags"] & F_RET:
                return None
            value = r["retval"]
        else:
            index = int(source)
            if index >= len(r["args"]):
                return None
            value = r["args"][index]
        kind = field["type"]
        is_buf = source != "ret" and site.get("buf_arg") == int(source)
        if kind in ("string", "bytes"):
            return buf if is_buf and buf is not None else None
        if kind == "key":
            if is_buf and buf is not None:
                return buf.get("id")                # None when the read failed: an id of nothing would link unrelated reads
            return keyed_id(self.key, struct.pack("<Q", value))
        if kind == "bool":
            return (value & 0xFFFFFFFF) != 0
        if kind in ("u8", "u16", "u32"):
            return value & ((1 << {"u8": 8, "u16": 16, "u32": 32}[kind]) - 1)
        if kind == "i32":
            value &= 0xFFFFFFFF
            return value - (1 << 32) if value >> 31 else value
        if kind == "i64":
            return value - (1 << 64) if value >> 63 else value
        if kind == "hex":
            return "0x%x" % value
        return value

    def _call(self, r: dict, artifacts: dict) -> bytes:
        site = self.sites.get(r["site"])
        t0 = _tick_ns(r["qpc"], self.freq)
        if site is None:
            return self._event("core.error", t0, r["tid"], {"error": "unknown-site", "site": r["site"]})
        name, kind = site["name"], site["kind"]
        self.hits[r["site"]] = self.hits.get(r["site"], 0) + 1
        call = "%d:%d" % (r["ring"], r["ring_seq"])
        va, module = site.get("va"), site.get("module")
        stack = list(r.get("stack") or ([r["ret_addr"]] if r["ret_addr"] else []))
        args, has_ret = r["args"], bool(r["flags"] & F_RET)
        buf = self._buffer(site, r, artifacts)
        out = bytearray()

        def emit(event_kind, t, payload):
            payload = {**payload, "call": call}
            return self._event(event_kind, t, r["tid"], payload, va=va, callstack=stack, module=module)

        if kind == "open":
            path = r["buf"] if not r["flags"] & F_READ_FAILED else b""
            norm = normalize_path(path[:(len(path) // 2) * 2])
            for index in range(0, len(norm) - 1, 2):
                if norm[index] == 0 and norm[index + 1] == 0:
                    norm = norm[:index]
                    break
            device = is_device_path(path)
            handle = r["retval"]
            ok = has_ret and handle not in (INVALID_HANDLE, 0)
            rid = None if r["flags"] & F_READ_FAILED else keyed_id(self.key, norm)
            payload = {"api": name, "resource_kind": "device" if device else "file", "resource_id": rid,
                       "path_len": len(norm), "truncated": bool(r["flags"] & F_TRUNCATED),
                       "access": args[1] & 0xFFFFFFFF if len(args) > 1 else None,
                       "share": args[2] & 0xFFFFFFFF if len(args) > 2 else None,
                       "disposition": args[4] & 0xFFFFFFFF if len(args) > 4 else None,
                       "handle": handle if has_ret else None, "ok": bool(ok), "last_error": r["last_error"],
                       "read_failed": bool(r["flags"] & F_READ_FAILED), "buf_addr": r["buf_addr"]}
            if buf is not None and "preview" in buf:
                payload["preview"], payload["redacted"] = buf["preview"], buf["redacted"]
            if ok:
                self.handles[handle] = (rid, device)
            out += emit("core.resource.open", _tick_ns(r["qpc_end"] or r["qpc"], self.freq), payload)
            if device:
                out += emit("driver.device_open", _tick_ns(r["qpc_end"] or r["qpc"], self.freq),
                            {"api": name, "resource_id": rid, "handle": handle if has_ret else None, "ok": bool(ok)})
        elif kind == "ioctl":
            handle = args[0] if args else 0
            code = (args[1] & 0xFFFFFFFF) if len(args) > 1 else 0
            known = self.handles.get(handle)
            ok = has_ret and (r["retval"] & 0xFFFFFFFF) != 0
            base = {"api": name, "handle": handle, "resource_id": known[0] if known else None,
                    "resource_unresolved": None if known else "lifetime-unresolved"}
            sizes = {"in_size": (args[3] & 0xFFFFFFFF) if len(args) > 3 else 0, "out_size": (args[5] & 0xFFFFFFFF) if len(args) > 5 else 0}
            t_end = _tick_ns(r["qpc_end"] or r["qpc"], self.freq)
            out += emit("core.resource.write", t0, {**base, "op": "ioctl", "bytes_in": sizes["in_size"],
                                                     "bytes_out": sizes["out_size"], "ok": bool(ok) if has_ret else None})
            ioctl = {**base, **sizes, "code": code, "device_type": code >> 16, "access": (code >> 14) & 3,
                     "function": (code >> 2) & 0xFFF, "method": code & 3, "ok": bool(ok) if has_ret else None,
                     "last_error": r["last_error"], "end_ns": t_end}
            if buf is not None:
                ioctl["in_buffer"] = buf
            out += emit("driver.ioctl", t0, ioctl)
        elif kind == "close":
            handle = args[0] if args else 0
            known = self.handles.pop(handle, None)
            if known is None:
                self.stats["close_unknown"] += 1        # a handle this capture never saw opened: not an event of ours
            else:
                ok = has_ret and (r["retval"] & 0xFFFFFFFF) != 0
                out += emit("core.resource.close", _tick_ns(r["qpc_end"] or r["qpc"], self.freq),
                            {"api": name, "handle": handle, "resource_id": known[0], "device": known[1],
                             "ok": bool(ok) if has_ret else None, "last_error": r["last_error"]})
        elif kind == "event":
            payload = {"site": name, "hook": site.get("hook", name)}
            for field in site.get("fields", ()):
                payload[field["name"]] = self._field(field, r, site, buf)
            if has_ret:
                payload["end_ns"] = _tick_ns(r["qpc_end"] or r["qpc"], self.freq)
                payload["last_error"] = r["last_error"]
            out += emit(site.get("event") or "core.function.enter", t0, payload)
        elif kind == "devquery":
            family = "driver.cfgmgr" if name.lower().startswith("cm_") else "driver.setupapi"
            payload = {"api": name, "resource_kind": "device-enum", "ret": r["retval"] if has_ret else None,
                       "last_error": r["last_error"], "args": args}
            if buf is not None:
                payload["query"] = buf
                payload["resource_id"] = buf.get("id")
            out += emit("core.resource.open", t0, payload)
            out += emit(family, t0, {"api": name, "ret": r["retval"] if has_ret else None, "last_error": r["last_error"],
                                     "query_id": buf.get("id") if buf else None})
        else:
            payload = {"site": name, "args": args}
            if buf is not None:
                payload["buf"] = buf
            out += emit("core.function.enter", t0, payload)
            if has_ret:
                out += emit("core.function.exit", _tick_ns(r["qpc_end"] or r["qpc"], self.freq),
                            {"site": name, "ret": r["retval"], "last_error": r["last_error"]})
        return bytes(out)


def make_encoder(*args, **kwargs):
    """The native encoder when `hydralysis_native` has one, else the Python twin. Same arguments, same bytes."""
    try:
        import hydralysis_native as native  # type: ignore[import-not-found]
        cls = getattr(native, "SegmentEncoder", None)
    except ImportError:
        cls = None
    return (cls or SegmentEncoder)(*args, **kwargs)


def as_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
