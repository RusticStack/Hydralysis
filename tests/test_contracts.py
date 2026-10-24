import io
import json
import unittest
from contextlib import redirect_stderr
from unittest.mock import Mock, patch

from rusticre.api import call, tool_table
from rusticre.cli import main
from rusticre.mcp import Server


class AgentContracts(unittest.TestCase):
    def test_catalog_stays_small_in_bytes_as_well_as_count(self):
        catalog = tool_table()
        self.assertEqual(len(catalog), 20)
        self.assertLess(len(json.dumps(catalog).encode("utf-8")), 8192)
        for tool in catalog:
            self.assertLess(len(json.dumps(tool["inputSchema"]).encode("utf-8")), 1024, tool["name"])
        self.assertIn("ghidra_query", [tool["name"] for tool in catalog])

    def test_long_prologue_reads_all_expected_bytes_and_mismatch_fails_clients(self):
        image = Mock()
        image.header.return_value = "# sha256 build"
        image.base = 0x140000000
        image.read_rva.return_value = b"\x90" * 79 + b"\xc3"
        expect = " ".join(["90"] * 79 + ["C3"])
        with patch("rusticre.api._image", return_value=image):
            self.assertIn("PROLOGUE MATCH", call("prologue", {"address": "0x1000", "expect": expect}))
            image.read_rva.assert_called_with(0x1000, 80)
            args = {"exe": "unused", "address": "0x1000", "expect": "CC"}
            reply = Server().handle({"id": 1, "method": "tools/call",
                                     "params": {"name": "prologue", "arguments": args}})
            self.assertTrue(reply["result"]["isError"])
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["prologue", "--exe", "unused", "0x1000", "--expect", "CC"]), 1)

    def test_invalid_limits_refuse_before_binary_read(self):
        with patch("rusticre.api._image") as image:
            for args in ({"limit": -1}, {"size": 65537}, {"count": 0}, {"limit": True}):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    call("bytes", args)
            image.assert_not_called()


if __name__ == "__main__":
    unittest.main()
