"""The Python twin of TRACE-1 canonical JSON, record hashes and segment framing, against fixed vectors."""

import hashlib
import json
import os
import re
import subprocess
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import workdir

from hydralysis import trace_canon as canon

VECTORS = json.loads((Path(__file__).resolve().parent / "fixtures" / "trace_canon_vectors.json").read_text("utf-8"))


def reference(value) -> str:
    """An independent encoding: the stdlib's, plus the one rule it lacks (0x7f is escaped too)."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return text.replace("\x7f", "\\u007f")


class CanonicalJson(unittest.TestCase):
    def test_vectors(self):
        for vector in VECTORS["canonical"]:
            self.assertEqual(canon.canonical_text(vector["value"]), vector["canonical"])
            self.assertEqual(canon.canonical_text(vector["value"]), reference(vector["value"]))

    def test_delete_is_escaped_and_ascii_only(self):
        self.assertEqual(canon.canonical_text("\x7f~"), '"\\u007f~"')
        text = canon.canonical_text({"k": "é\U0001F600\x00"})
        text.encode("ascii")
        self.assertEqual(text, '{"k":"\\u00e9\\ud83d\\ude00\\u0000"}')

    def test_floats_and_foreign_values_are_refused(self):
        for bad in (1.5, float("nan"), {"t": 0.0}, [1, 2.5], {1: "x"}, {"s": {1, 2}}, 2 ** 64, -(2 ** 63) - 1, "\ud800"):
            with self.assertRaises(canon.NotCanonical, msg=repr(bad)):
                canon.canonical_text(bad)

    def test_booleans_are_not_integers(self):
        self.assertEqual(canon.canonical_text([True, False, 1, 0]), "[true,false,1,0]")

    def test_key_order_does_not_matter(self):
        self.assertEqual(canon.canonical_text({"b": 1, "a": 2}), canon.canonical_text({"a": 2, "b": 1}))


class Chaining(unittest.TestCase):
    def test_genesis(self):
        for segment, expected in VECTORS["genesis"].items():
            self.assertEqual(canon.genesis_hash(segment), expected)
            self.assertEqual(hashlib.sha256(b"hydra.trace.segment/1\n" + segment.encode()).hexdigest(), expected)

    def test_segment_vector(self):
        vector = VECTORS["segment"]
        chain = canon.Chain(vector["id"])
        lines = [chain.push(record) for record in vector["records"]]
        self.assertEqual([line.decode("ascii") for line in lines], vector["lines"])
        self.assertEqual(chain.head, vector["head"])
        for line in lines:
            crc, body = line[:8], line[9:-1]
            self.assertTrue(re.fullmatch(rb"[0-9a-f]{8}", crc))
            self.assertEqual(int(crc, 16), zlib.crc32(body))
            self.assertEqual(line[-1:], b"\n")

    def test_hash_is_over_the_record_without_hash(self):
        record = {"kind": "core.marker", "n": 0, "prev": "0" * 64}
        digest = canon.record_hash(record)
        self.assertEqual(digest, hashlib.sha256(canon.canonical_bytes(record)).hexdigest())
        self.assertEqual(canon.record_hash({**record, "hash": "f" * 64}), digest)

    def segment(self, count=4, name="s1"):
        chain = canon.Chain(name)
        return b"".join(chain.push({"kind": "core.marker", "t": index}) for index in range(count))

    def test_clean_empty_torn_corrupt_and_chain_break_stay_distinct(self):
        data = self.segment()
        clean = canon.scan(data, "s1")
        self.assertEqual((clean.outcome, len(clean.records), clean.valid_end), ("clean", 4, len(data)))
        empty = canon.scan(b"", "s1")
        self.assertEqual((empty.outcome, empty.records), ("empty", []))
        torn = canon.scan(data + b"deadbeef {\"n\":4", "s1")
        self.assertEqual((torn.outcome, len(torn.records), torn.valid_end), ("torn_tail", 4, len(data)))
        self.assertFalse(torn.clean)
        bad_crc_last = canon.scan(data[:-3] + b"zz\n", "s1")
        self.assertEqual((bad_crc_last.outcome, len(bad_crc_last.records)), ("torn_tail", 3))
        flipped = bytearray(data)
        flipped[20] ^= 1
        corrupt = canon.scan(bytes(flipped), "s1")
        self.assertEqual((corrupt.outcome, corrupt.damage["offset"], corrupt.records), ("corrupt", 0, []))
        wrong = canon.scan(data, "other")
        self.assertEqual((wrong.outcome, wrong.damage["reason"]), ("chain_break", "prev"))

    def test_a_dropped_record_breaks_the_numbering_and_a_forged_hash_the_hash(self):
        lines = self.segment().splitlines(keepends=True)
        gap = canon.scan(b"".join(lines[:1] + lines[2:]), "s1")
        self.assertEqual((gap.outcome, gap.damage["reason"], len(gap.records)), ("chain_break", "numbering", 1))
        forged = json.loads(lines[1][9:])
        forged["t"] = 99  # the line is re-framed with a good CRC, so only the chain can catch it
        forged_line = canon.frame(forged)
        broken = canon.scan(lines[0] + forged_line + b"".join(lines[2:]), "s1")
        self.assertEqual((broken.outcome, broken.damage["reason"], len(broken.records)), ("chain_break", "hash", 1))

    def test_a_float_in_a_chained_record_is_a_hash_break_not_a_crash(self):
        chain = canon.Chain("s1")
        first = chain.push({"kind": "core.marker"})
        record = json.loads(first[9:])
        text = json.dumps({**record, "ratio": 0.5}, sort_keys=True, separators=(",", ":")).encode()
        line = b"%08x " % (zlib.crc32(text) & 0xFFFFFFFF) + text + b"\n"
        self.assertEqual(canon.scan(line, "s1").damage["reason"], "hash")

    def test_the_engines_generator_output_verifies_when_the_binary_is_present(self):
        exe = os.environ.get("HYDRA_TRACE_EXE", "")
        if not exe or not Path(exe).is_file():
            self.skipTest("set HYDRA_TRACE_EXE to the engine's hydra-trace.exe to cross-check the Rust twin")
        with workdir("canon-gen") as folder:
            produced = subprocess.run([exe, "gen", "baseline", "7", "200", folder], capture_output=True, text=True,
                                      timeout=60, check=True).stdout.split()
            self.assertTrue(produced)
            for path in produced:
                segment = Path(path)
                result = canon.scan(segment.read_bytes(), segment.stem)
                self.assertTrue(result.clean, (path, result.damage))


if __name__ == "__main__":
    unittest.main()
