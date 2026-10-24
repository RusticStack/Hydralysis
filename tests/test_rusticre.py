import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from rusticre.api import REJECTED, TOOL_NAMES, call, tool_table
from rusticre.catalog import GAMES, MODS, SYSTEMS
from rusticre.cli import main
from rusticre.evidence import add_claim
from rusticre.ghidra import build_command, filter_script_output
from rusticre.mcp import Server
from rusticre.prologue import compare, matches, parse_expect
from rusticre.red4ext import iter_entries, lookup_hashes


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
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "table.json"
            path.write_bytes(body)
            rows = list(iter_entries(path, chunk_size=24, overlap=16))
        self.assertEqual([row[0] for row in rows], [10, 11])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "table.json"
            path.write_bytes(body)
            text = "\n".join(lookup_hashes(path, {10}, chunk_size=24, overlap=16))
        self.assertIn("0x2000", text)
        self.assertIn("Alpha", text)


class GhidraCommandTests(unittest.TestCase):
    def test_command_reuses_the_project(self):
        command = build_command(
            "G", "lane", "client", "swtor.exe", "scripts", "Recv.java", ["FN", "0x1"], "job.log", 4
        )
        text = " ".join(command)
        self.assertIn("-noanalysis", command)
        self.assertIn("-readOnly", command)
        self.assertIn("-process", command)
        self.assertNotIn("-import", text)
        self.assertIn("Recv.java", command)

    def test_script_output_drops_the_ghidra_log(self):
        stdout = "\n".join([
            "INFO  Analyzing... something (HeadlessAnalyzer)",
            "INFO  Recv.java> === FUNCTION FUN_1 === (GhidraScript)",
            "INFO  Recv.java> void FUN_1(void)",
            "more of the body",
            "(GhidraScript)",
            "INFO  REPORT: done",
        ])
        text = filter_script_output(stdout)
        self.assertIn("=== FUNCTION FUN_1 ===", text)
        self.assertIn("void FUN_1(void)", text)
        self.assertNotIn("HeadlessAnalyzer", text)
        self.assertNotIn("REPORT", text)


class EvidenceTests(unittest.TestCase):
    def test_a_claim_needs_a_source(self):
        with tempfile.TemporaryDirectory() as tmp:
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


class CatalogTests(unittest.TestCase):
    def test_the_three_games_and_the_mod_rule(self):
        self.assertEqual(set(GAMES), {"cyberpunk", "kotor", "swtor"})
        text = call("systems", {"game": "cyberpunk"})
        self.assertIn("new-game", text)
        self.assertIn("world-streaming", text)
        self.assertIn("codeware", text)
        self.assertIn("replace", text)
        self.assertTrue(any(row["id"] == "red4ext" and row["keep"] for row in MODS))
        self.assertTrue(any(row["id"] == "new-game" and row["status"] == "open" for row in SYSTEMS))


class McpTests(unittest.TestCase):
    def test_the_tool_list_is_the_short_one(self):
        server = Server()
        listed = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = [item["name"] for item in listed["result"]["tools"]]
        self.assertEqual(names, list(TOOL_NAMES))
        self.assertLessEqual(len(names), 20)
        blob = json.dumps(tool_table()).lower()
        for banned in REJECTED:
            self.assertNotIn(banned, blob)
        init = server.handle({
            "jsonrpc": "2.0", "id": 2, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        })
        self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("RusticRE", init["result"]["instructions"])
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
