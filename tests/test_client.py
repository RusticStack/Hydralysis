import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from support import workdir
from test_pe import image

from rusticre import cli
from rusticre.client import Client, RusticError, parse


class LibraryAPI(unittest.TestCase):
    def setUp(self):
        self.work = workdir("client")
        self.addCleanup(self.work.cleanup)
        self.exe = str(Path(self.work.name) / "fixture.exe")
        Path(self.exe).write_bytes(image(b"\x55\x8b\xec" + b"\x90" * 28 + b"\xc3").data)
        self.re = Client()

    def test_static_answers_are_data(self):
        fingerprint = self.re.fingerprint(self.exe)
        self.assertEqual(len(fingerprint["sha256"]), 64)
        self.assertEqual(self.re.read(self.exe, "rva:0x1000", 3), b"\x55\x8b\xec")

    def test_a_mismatching_table_is_returned_not_raised(self):
        result = self.re.check_prologues(self.exe, [
            {"name": "ok", "address": "rva:0x1000", "expect": ["00", "55 8B ??"]},
            {"name": "moved", "address": "rva:0x1001", "expect": "55"},
        ])
        self.assertFalse(result["matched"])
        self.assertEqual([row["match"] for row in result["rows"]], [True, False])
        self.assertEqual(result["rows"][0]["matched_alternative"], 1)

    def test_long_tables_are_paged_into_one_answer(self):
        rows = [{"name": "r%d" % index, "address": "rva:0x1000", "expect": "55"} for index in range(450)]
        result = self.re.check_prologues(self.exe, rows)
        self.assertTrue(result["matched"])
        self.assertEqual(result["summary"], {"checked": 450, "matched": 450, "failed": 0})

    def test_refusals_keep_the_tool_contract(self):
        with self.assertRaisesRegex(RusticError, "SHA-256 mismatch"):
            self.re.check_prologues(self.exe, [{"address": "rva:0x1000", "expect": "55"}], sha256="0" * 64)
        with self.assertRaisesRegex(RusticError, "unknown tool"):
            self.re.call("frida")
        with self.assertRaisesRegex(RusticError, "size must be"):
            self.re.read(self.exe, "rva:0x1000", 0)

    def test_parse_leaves_text_answers_alone(self):
        self.assertEqual(parse(' {"a": 1}'), {"a": 1})
        self.assertEqual(parse("# exe x\nCC"), "# exe x\nCC")


class JsonCommandLine(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(list(argv))
        return code, json.loads(out.getvalue())

    def test_one_envelope_for_success_and_refusal(self):
        work = workdir("client-cli")
        self.addCleanup(work.cleanup)
        exe = Path(work.name) / "fixture.exe"
        exe.write_bytes(image().data)
        code, answer = self.run_cli("call", "prologue", "--args", json.dumps(
            {"exe": str(exe), "checks": [{"address": "rva:0x1000", "expect": "90"}]}))
        self.assertEqual((code, answer["ok"], answer["result"]["matched"]), (0, True, True))
        arguments = Path(work.name) / "args.json"
        arguments.write_text(json.dumps({"exe": str(exe), "address": "rva:0x1000", "size": 2}), encoding="utf-8")
        code, answer = self.run_cli("call", "bytes", "--args-file", str(arguments))
        self.assertTrue(answer["result"].endswith("90 90"))
        code, answer = self.run_cli("call", "prologue", "--args", json.dumps(
            {"exe": str(exe), "address": "rva:0x1000", "expect": "55"}))
        self.assertEqual(code, 1)
        self.assertFalse(answer["ok"])
        self.assertIn("PROLOGUE MISMATCH", answer["error"])


if __name__ == "__main__":
    unittest.main()
