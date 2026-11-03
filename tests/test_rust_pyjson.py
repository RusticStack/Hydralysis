"""An unreadable record file is reported as `unparseable (<Python's own words>)` by both implementations.

`durable._classify` words the reason with `str(exc)[:80]` of the UnicodeDecodeError or json.JSONDecodeError Python raises;
hy-core's `pyjson` module reproduces those words for the bytes serde_json refuses, and callers (test_exporting among them)
match on them. Differential: Python's `_classify` against `hydralysis_rs.classify_bytes`. Skipped when the extension is not
built; Python is the reference, so HYDRALYSIS_IMPL must not be `rust` for this file."""

from __future__ import annotations

import json
import os
import random
import unittest

from hydralysis import durable

try:
    import hydralysis_rs as rs
except ImportError:  # pragma: no cover
    rs = None

SEED = int(os.environ.get("HYDRALYSIS_PARITY_SEED", "20261102"))

DOCUMENTS = [
    b"{broken", b"{", b"[", b"", b"  ", b'{"a"', b'{"a":', b'{"a": 1', b'{"a": 1,', b'{"a": 1,}', b"[1,]", b"[1 2]",
    b"[1,, 2]", b'{"a" 1}', b"{'a': 1}", b'{"a": tru}', b'{"a": 01}', b'{"a": -}', b'{"a": 1.}', b'{"a": .5}', b'{"a": 1e}',
    b'"abc', b'"a\nb"', b'"a\x01b"', b'"\\q"', b'"\\u12"', b'"\\ud800\\u12"', b'"\\ud800\\udc00', b'{"a": "x\ty"}',
    b"[1] x", b"{} {}", b'\xef\xbb\xbf{"a": 1}', b'{"a": 1}\n\n  x', b'{\n  "a": [1,\n  2,\n  oops]\n}',
    b'{"a": 1} // c', b"\xff", b'{"a": "\xe2\x82"}', b"\xe2\x82", b"a\xc3",
    b'{"\xc3\xa9": \xc0}', b'{"a": "\xed\xa0\x80"}', b'{"\\u00e9": nul}', b'{"k": "\\"}', b'["\\ud83d\\ude00", ?]',
    '{"é": 1,\n "ø": ?}'.encode(), b'["\\\xe2\x80\xa8"]', b'{"a": "\\\x7f"}', b"[1, 2,\n\n\n   ]", b'"\\\x00"', b'{"a":\n\n\n  ]',
]


@unittest.skipIf(rs is None or os.environ.get("HYDRALYSIS_IMPL") == "rust", "needs hydralysis_rs and the Python reference")
class DecodeText(unittest.TestCase):
    def check(self, raw):
        expected = durable._classify(raw)
        kind, value, reason = rs.classify_bytes(raw)
        self.assertEqual((kind, None if value is None else json.loads(value), reason), expected, raw)

    def test_the_known_refusals_read_as_python_words(self):
        for raw in DOCUMENTS:
            with self.subTest(raw=raw):
                self.check(raw)

    def test_the_wording_names_the_reason_and_the_position(self):
        _, _, reason = rs.classify_bytes(b"{broken")
        self.assertEqual(reason, "unparseable (Expecting property name enclosed in double quotes: line 1 column 2 (char 1))")
        _, _, reason = rs.classify_bytes(b"\xff")
        self.assertEqual(reason, "unparseable ('utf-8' codec can't decode byte 0xff in position 0: invalid start byte)")

    def test_mutated_documents_read_the_same(self):
        rng = random.Random(SEED + 11)
        pieces = [b"", b"{", b"}", b"[", b"]", b",", b":", b'"', b"\\", b"\n", b"\x01", b"\xc3", b"\xff", b"1", b"-", b"tr", b"\\u"]
        shapes = [{"a": 1, "b": [1, 2, {"c": "é"}], "d": None}, [1, "x", True, 2.5], {"k": "line\nbreak\t\"q\" \\  "},
                  {"nested": {"deeper": {"deepest": [[], {}, ""]}}}]
        seeds = [json.dumps(shape, ensure_ascii=ascii_only, indent=indent).encode()
                 for shape in shapes for ascii_only in (True, False) for indent in (None, 1, 2)]
        for seed in seeds:
            for _ in range(60):
                data = bytearray(seed)
                for _ in range(rng.randint(1, 3)):
                    at = rng.randint(0, len(data))
                    kind = rng.choice(["insert", "delete", "cut"])
                    if kind == "insert":
                        data[at:at] = rng.choice(pieces)
                    elif kind == "delete" and data:
                        del data[min(at, len(data) - 1)]
                    else:
                        del data[at:]
                self.check(bytes(data))


if __name__ == "__main__":
    unittest.main()
