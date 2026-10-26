import unittest
from unittest.mock import Mock

from rusticre.prologue import compare_table, parse_expect


def fixture_image(size=32):
    image = Mock()
    image.base = 0x400000
    image.rva_to_offset.side_effect = lambda rva: rva - 0x1000 if 0x1000 <= rva < 0x1000 + size else None
    image._available.side_effect = lambda rva: max(0, 0x1000 + size - rva)
    image.read_rva.side_effect = lambda rva, count: b"\x90" * count
    image.fingerprint.return_value = {"sha256": "a" * 64, "image_base": "0x400000", "bits": 32}
    return image


class PrologueNormalization(unittest.TestCase):
    def test_common_hook_table_forms_normalize_to_the_same_bytes(self):
        expected = list(bytes.fromhex("488bc448894808565741544156415748"))
        for text in ("488bc448894808565741544156415748", "0x488bc448894808565741544156415748",
                     "48 8B C4 48 89 48 08 56 57 41 54 41 56 41 57 48",
                     ",".join("0x%02x" % value for value in expected),
                     "".join("\\x%02x" % value for value in expected)):
            with self.subTest(text=text):
                self.assertEqual(parse_expect(text), expected)

    def test_wildcards_are_whole_bytes_and_need_a_literal(self):
        self.assertEqual(parse_expect("48??C4 ? 0x08"), [0x48, None, 0xC4, None, 8])
        for text in ("488", "4?", "48?C", "?? ??", "", "0x", "gg", "-1"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_expect(text)


class PrologueTables(unittest.TestCase):
    def test_twenty_one_rows_share_one_build_fingerprint(self):
        image = fixture_image()
        rows = [{"name": "site%d" % index, "address": "rva:0x1000", "expect": "9090"} for index in range(21)]
        result = compare_table(image, rows, lambda value: int(value.split(":")[1], 16))
        image.fingerprint.assert_called_once_with()
        self.assertEqual(image.read_rva.call_count, 21)
        self.assertTrue(result["matched"])
        self.assertEqual(result["summary"], {"checked": 21, "matched": 21, "failed": 0})
        self.assertEqual(result["rows"][0]["va"], "va:0x401000")
        self.assertEqual(result["rows"][0]["rva"], "rva:0x1000")
        self.assertEqual(result["fingerprint"]["sha256"], "a" * 64)

    def test_mismatch_is_retained_among_all_results(self):
        image = fixture_image()
        result = compare_table(image, [{"address": "x", "expect": "90"},
                                       {"address": "x", "expect": "91"},
                                       {"address": "x", "expect": "??90"}], lambda value: 0x1000)
        self.assertFalse(result["matched"])
        self.assertEqual([row["match"] for row in result["rows"]], [True, False, True])
        self.assertEqual(result["summary"], {"checked": 3, "matched": 2, "failed": 1})
        self.assertEqual(result["rows"][1]["actual"], "90")

    def test_a_row_may_accept_several_prologues_and_names_the_one_that_matched(self):
        image = fixture_image()
        result = compare_table(image, [{"address": "x", "expect": ["48 8B", "90 90"]},
                                       {"address": "x", "expect": ["48", "49"]}], lambda value: 0x1000)
        self.assertEqual([row["match"] for row in result["rows"]], [True, False])
        self.assertEqual(result["rows"][0]["matched_alternative"], 1)
        self.assertIsNone(result["rows"][1]["matched_alternative"])
        with self.assertRaises(ValueError):
            compare_table(image, [{"address": "x", "expect": []}], lambda value: 0x1000)

    def test_envelope_image_base_makes_legacy_offsets_unambiguous(self):
        import json
        from rusticre.cli import _checks_file
        from support import workdir
        with workdir() as folder:
            path = __import__("pathlib").Path(folder) / "table.json"
            path.write_text(json.dumps({"image_base": "0x140000000", "build_sha256": "a" * 64,
                                        "hooks": [{"offset": "0x43cf20", "prologue": "48 8B", "names": ["router"]},
                                                  {"offset": "0x14043cf20", "prologues": ["48", "49"]}]}))
            rows = _checks_file(str(path), None)["checks"]
        self.assertEqual([row["address"] for row in rows], ["rva:0x43cf20", "va:0x14043cf20"])
        self.assertEqual(rows[1]["expect"], ["48", "49"])

    def test_all_rows_validate_before_any_bytes_are_read(self):
        for bad in ({"address": "x", "expect": "??"},
                    {"address": "x", "expect": "90", "guess": True},
                    {"address": "x", "expect": "90" * 4097},
                    {"address": "x", "expect": "90", "name": 7}):
            image = fixture_image()
            with self.subTest(bad=str(bad)[:100]), self.assertRaises(ValueError):
                compare_table(image, [{"address": "x", "expect": "90"}, bad], lambda value: 0x1000)
            image.read_rva.assert_not_called()

    def test_file_backed_boundary_is_checked_before_reads(self):
        image = fixture_image()
        with self.assertRaisesRegex(ValueError, "file-backed"):
            compare_table(image, [{"address": "first", "expect": "90"},
                                  {"address": "last", "expect": "9090"}],
                          lambda value: 0x1000 if value == "first" else 0x101f)
        image.read_rva.assert_not_called()

    def test_total_byte_budget_and_row_budget(self):
        image = fixture_image(100000)
        row = {"address": "x", "expect": "90" * 4096}
        with self.assertRaisesRegex(ValueError, "65536"):
            compare_table(image, [row] * 17, lambda value: 0x1000)
        image.read_rva.assert_not_called()
        for rows in ([], [row] * 201, {}, None):
            with self.subTest(rows=type(rows).__name__), self.assertRaisesRegex(ValueError, "1..200"):
                compare_table(image, rows, lambda value: 0x1000)


if __name__ == "__main__":
    unittest.main()
