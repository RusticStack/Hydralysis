"""Decoding what probes capture, and typed live reads."""

import struct
import unittest

from rusticre import runtime_decode as decode


class Decoding(unittest.TestCase):
    def test_text_numbers_structs_and_names(self):
        specs = decode.normalize([{"arg": 0, "deref": [8], "as": "utf16", "size": 16},
                                  {"arg": 1, "as": "u32", "names": {"0x2a": "answer"}},
                                  {"arg": 2, "deref": [0], "as": "struct", "fields": [
                                      {"name": "x", "offset": 0, "type": "float"}, {"name": "id", "offset": 4, "type": "uint32"}]}])
        captured = [{"pointer": "0x1", "hex": "a:b".encode("utf-16-le").hex() + "0000" * 5},
                    {"pointer": "0x2a", "hex": struct.pack("<I", 42).hex()},
                    {"pointer": "0x3", "hex": struct.pack("<fI", 1.5, 7).hex()}]
        rows = decode.decode_event(specs, captured)
        self.assertEqual(rows[0]["value"], "a:b")
        self.assertEqual(rows[1]["value"], {"value": 42, "name": "answer"})
        self.assertEqual(rows[2]["value"], {"x": 1.5, "id": 7})
        self.assertTrue(specs[1]["value_only"])

    def test_unreadable_capture_is_reported_not_raised(self):
        specs = decode.normalize([{"arg": 0, "deref": [0], "as": "utf8"}])
        self.assertEqual(decode.decode_event(specs, [{"error": "unreadable pointer at 0x10"}])[0]["error"], "unreadable pointer at 0x10")

    def test_bad_specs_are_refused(self):
        for bad in ([{"arg": 9}], [{"arg": 0, "as": "elf"}], [{"arg": 0, "deref": [1, 2, 3, 4, 5]}],
                    [{"arg": 0, "as": "struct"}], [{"arg": 0}] * 5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                decode.normalize(bad)

    def test_layout_values_from_a_type(self):
        data = struct.pack("<iQf", -3, 0x140000000, 2.0)
        rows = decode.layout_values([{"name": "count", "offset": 0, "type": "int"},
                                     {"name": "owner", "offset": 4, "type": "Thing *"},
                                     {"name": "speed", "offset": 12, "type": "float"},
                                     {"name": "blob", "offset": 0, "type": "SomeStruct", "size": 4}], data)
        self.assertEqual([row.get("value") for row in rows[:3]], [-3, "0x140000000", 2.0])
        self.assertEqual(rows[3]["bytes"], "FD FF FF FF")


if __name__ == "__main__":
    unittest.main()
