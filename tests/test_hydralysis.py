import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from hydralysis.api import REJECTED, TOOL_NAMES, call, tool_table
from hydralysis.cli import main
from hydralysis.evidence import add_claim
from hydralysis.mcp import Server
from hydralysis.prologue import compare, find_pattern, matches, parse_expect
from hydralysis.red4ext import iter_entries, lookup_hashes

from support import workdir


class PrologueTests(unittest.TestCase):
    def test_wildcard_and_mismatch(self):
        expect = parse_expect("48 89 ?? 24 08")
        self.assertTrue(matches(bytes.fromhex("48 89 5C 24 08"), expect))
        self.assertFalse(matches(bytes.fromhex("48 8B 5C 24 08"), expect))
        text = compare(bytes.fromhex("48 8B 5C 24 08 CC"), "48 89 ?? 24 08")
        self.assertIn("PROLOGUE MISMATCH", text)

    def test_empty_expect_is_refused(self):
        with self.assertRaises(ValueError):
            parse_expect("   ")


class AddressTableTests(unittest.TestCase):
    def test_rows_split_across_chunks(self):
        body = (
            b'{"Code constant offset": "1000"}\n'
            + b'{"hash": "10", "symbol": "Alpha", "offset": "0001:00001000"}\n'
            + b'{"hash": "11", "symbol": "Beta", "offset": "0002:00000020"}\n'
        )
        with workdir() as tmp:
            path = Path(tmp) / "table.json"
            path.write_bytes(body)
            rows = list(iter_entries(path, chunk_size=24, overlap=16))
        self.assertEqual([row[0] for row in rows], [10, 11])
        with workdir() as tmp:
            path = Path(tmp) / "table.json"
            path.write_bytes(body)
            text = "\n".join(lookup_hashes(path, {10}, chunk_size=24, overlap=16))
        self.assertIn("0x2000", text)
        self.assertIn("Alpha", text)


class EvidenceTests(unittest.TestCase):
    def test_a_claim_needs_a_source(self):
        with workdir() as tmp:
            path = Path(tmp) / "e.db"
            with self.assertRaises(ValueError):
                add_claim(path, game="cyberpunk", build="2.5", kind="function", name="X", note="n", source="")
            message = add_claim(
                path, game="cyberpunk", build="3.0.88.46235", kind="function", name="X",
                note="prologue matched", source="log line 10", address="0x1000", prologue="48 89",
            )
            self.assertIn("stored", message)
            listed = call("evidence_list", {"db": str(path), "game": "cyberpunk"})
            self.assertIn("prologue matched", listed)


class SurfaceTests(unittest.TestCase):
    def test_the_server_is_the_used_subset(self):
        names = list(TOOL_NAMES)
        self.assertLessEqual(len(names), 21)
        for banned in ("hash", "addr", "systems", "games", "funcof"):
            self.assertNotIn(banned, names)
        self.assertIn("inspect", names)
        self.assertIn("sigscan", names)
        self.assertIn("prologue", names)
        blob = json.dumps(tool_table()).lower()
        for word in ("red4ext", "codeware", "cyberpunk", "swkotor", "android", "firmware"):
            self.assertNotIn(word, blob)

    def test_sigscan_wildcards(self):
        pattern = parse_expect("48 8B ?? C3")
        haystack = bytes.fromhex("90 48 8B 11 C3 48 8B 22 C3")
        self.assertEqual(find_pattern(haystack, pattern, 10), [1, 5])


class McpTests(unittest.TestCase):
    def test_the_tool_list_is_the_short_one(self):
        server = Server()
        listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = [item["name"] for item in listed["result"]["tools"]]
        self.assertEqual(names, list(TOOL_NAMES))
        self.assertLessEqual(len(names), 21)
        blob = json.dumps(tool_table()).lower()
        for banned in REJECTED:
            self.assertNotIn(banned, blob)
        init = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        })
        self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("Hydralysis", init["result"]["instructions"])
        missing = server.handle({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "fingerprint", "arguments": {}},
        })
        self.assertTrue(missing["result"]["isError"])

    def test_cli_lists_the_same_tools(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["tools"])
        text = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("ghidra_run", text)
        self.assertNotIn("decompile_jeb", text)


if __name__ == "__main__":
    unittest.main()
