"""Address intent must survive PE32 RVA/VA overlap through every interface."""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from rusticre.api import call
from rusticre.cli import main
from rusticre.mcp import Server
from rusticre.pe import parse_rva


class MappedImage:
    base = 0x400000

    def __init__(self, mapped=(0x1000, 0x11D5A2, 0x51D5A2)):
        self.mapped = set(mapped)
        self.inspect = Mock(side_effect=lambda rva: "inspected RVA %#x" % rva)

    def rva_to_offset(self, rva):
        return 0x200 + rva if rva in self.mapped else None


class ExplicitAddressTests(unittest.TestCase):
    def test_explicit_rva_above_image_base_is_not_reinterpreted(self):
        self.assertEqual(parse_rva("rva:0x51d5a2", 0x400000), 0x51D5A2)
        self.assertEqual(parse_rva("va:0x91d5a2", 0x400000), 0x51D5A2)
        self.assertEqual(parse_rva("va:0x51d5a2", 0x400000), 0x11D5A2)

    def test_invalid_prefix_or_negative_address_is_refused(self):
        for address in ("rva:-1", "va:-1", "va:0x1000", "file:0x1000", "offset:0x200", "-1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                parse_rva(address, 0x400000)

    def test_ambiguous_plain_pe32_entry_address_refuses_before_inspection(self):
        image = MappedImage()
        with patch("rusticre.api._image", return_value=image):
            with self.assertRaisesRegex(ValueError, "(?i)ambiguous"):
                call("inspect", {"address": "0x51d5a2"})
        image.inspect.assert_not_called()

    def test_explicit_entry_rva_and_equivalent_va_reach_same_bytes(self):
        image = MappedImage()
        with patch("rusticre.api._image", return_value=image):
            by_rva = call("inspect", {"address": "rva:0x51d5a2"})
            by_va = call("inspect", {"address": "va:0x91d5a2"})
        self.assertEqual(by_rva, "inspected RVA 0x51d5a2")
        self.assertEqual(by_rva, by_va)
        self.assertEqual([args.args[0] for args in image.inspect.call_args_list], [0x51D5A2, 0x51D5A2])

    def test_plain_low_rva_and_unambiguous_va_remain_compatible(self):
        image = MappedImage(mapped=(0x1000,))
        with patch("rusticre.api._image", return_value=image):
            self.assertEqual(call("inspect", {"address": "0x1000"}), "inspected RVA 0x1000")
            self.assertEqual(call("inspect", {"address": "0x401000"}), "inspected RVA 0x1000")

    def test_plain_high_rva_with_no_valid_va_interpretation_stays_rva(self):
        image = MappedImage(mapped=(0x51D5A2,))
        with patch("rusticre.api._image", return_value=image):
            self.assertEqual(call("inspect", {"address": "0x51d5a2"}), "inspected RVA 0x51d5a2")

    def test_cli_and_mcp_share_ambiguity_refusal_and_explicit_address(self):
        image = MappedImage()
        server = Server()
        with patch("rusticre.api._image", return_value=image):
            error_text = io.StringIO()
            with redirect_stderr(error_text):
                self.assertEqual(main(["inspect", "--exe", "unused", "0x51d5a2"]), 1)
            self.assertIn("ambiguous", error_text.getvalue().lower())
            response = server.handle({"id": 1, "method": "tools/call", "params": {
                "name": "inspect", "arguments": {"exe": "unused", "address": "0x51d5a2"}
            }})
            self.assertTrue(response["result"]["isError"])
            self.assertIn("ambiguous", response["result"]["content"][0]["text"].lower())
            image.inspect.assert_not_called()

            cli_text = io.StringIO()
            with redirect_stdout(cli_text):
                self.assertEqual(main(["inspect", "--exe", "unused", "rva:0x51d5a2"]), 0)
            response = server.handle({"id": 2, "method": "tools/call", "params": {
                "name": "inspect", "arguments": {"exe": "unused", "address": "rva:0x51d5a2"}
            }})
            self.assertFalse(response["result"]["isError"])
            self.assertEqual(cli_text.getvalue().strip(), response["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
