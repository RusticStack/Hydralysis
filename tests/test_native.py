"""The optional Rust helper (native/, hydralysis_native) and its pure-Python twin give identical results; the log scan
built on them gives what the line-by-line `_parse` scan gave."""

from __future__ import annotations

import os
import random
import unittest
from unittest.mock import patch

from hydralysis import durable


def reference_scan(data: bytes):
    """The scan before frame_lines: `_parse` on every complete line."""
    records, bad, cursor, line_no = [], None, 0, 0
    while True:
        end = data.find(b"\n", cursor)
        if end < 0:
            break
        line_no += 1
        parsed = durable._parse(data[cursor:end])
        if parsed is None:
            if bad is None:
                bad = (cursor, line_no)
        elif bad is not None:
            return records, ("corrupt", bad[0], bad[1])
        else:
            records.append(parsed[0])
        cursor = end + 1
    if cursor < len(data) and bad is None:
        bad = (cursor, line_no + 1)
    return records, (None if bad is None else ("torn", bad[0]))


def corpus(seed: int) -> list[bytes]:
    rng = random.Random(seed)
    cases = [b"", b"\n", b"x\n", durable.frame({"a": 1}), durable.frame({"a": 1})[:-1],
             durable.frame({"a": 1}).upper(), b"0000000z {}\n", b"00000000 \n", durable.frame("é")]
    for _ in range(300):
        lines = []
        for _ in range(rng.randrange(0, 12)):
            line = bytearray(durable.frame({"n": rng.randrange(10 ** 6), "s": "x" * rng.randrange(40), "u": "é中"}))
            roll = rng.random()
            if roll < 0.08:
                line[rng.randrange(len(line) - 1)] ^= 1 << rng.randrange(8)  # a flipped bit anywhere but the LF
            elif roll < 0.12:
                line = line[:rng.randrange(len(line))]  # a torn line
            elif roll < 0.15:
                line = bytearray(b"%08x not json\n" % (__import__("zlib").crc32(b"not json") & 0xFFFFFFFF))
            lines.append(bytes(line))
        cases.append(b"".join(lines))
    return cases


class Twin(unittest.TestCase):
    def test_python_twin_matches_the_reference_scan(self):
        with patch.object(durable, "_native", None):
            for data in corpus(7):
                scan = durable.scan_bytes(data)
                records, state = reference_scan(data)
                self.assertEqual(scan.records[:len(records)], records)
                if state is None:
                    self.assertEqual((scan.corrupt, scan.torn_tail, scan.valid_end), (None, None, len(data)), data)
                elif state[0] == "corrupt":
                    self.assertEqual((scan.corrupt["offset"], scan.corrupt["line"]), state[1:], data)
                else:
                    self.assertEqual((scan.corrupt, scan.torn_tail["offset"]), (None, state[1]), data)

    @unittest.skipIf(durable._native is None, "hydralysis_native is not installed (the pure-Python twin is used)")
    def test_the_native_helper_matches_the_python_twin(self):
        for data in corpus(11):
            self.assertEqual(durable._native.frame_lines(data, 0), durable._frame_lines_py(data), data)
            native = durable.scan_bytes(data)
            with patch.dict(os.environ, {"HYDRALYSIS_NATIVE": "0"}):
                python = durable.scan_bytes(data)
            self.assertEqual(native.as_status(), python.as_status())
            self.assertEqual(native.records, python.records)


if __name__ == "__main__":
    unittest.main()
