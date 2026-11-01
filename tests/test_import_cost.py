"""The start-up cost of an agent process: the MCP server must not import the PE reader or the engine client.

An agent starts `hydralysis mcp` once per session and then calls a handful of tools; the stacks a session never
touches must not be imported before `initialize`. Every check runs in a subprocess, so no other test's imports can
mask a regression. `pe.capstone()`/`pe.pefile()` (7.7 + 2.0 MB of private commit) and api's PEP 562 members exist
for this; `tests/test_address_maps` pins that `patch.object(api, "QueryRunner")` still wins.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from support import REPOSITORY

SRC = str(REPOSITORY / "src")


def run(code: str) -> str:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("HYDRALYSIS")}
    env["PYTHONPATH"] = SRC
    done = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, env=env, timeout=180)
    if done.returncode != 0:
        raise AssertionError("subprocess failed: %s\n%s" % (done.returncode, done.stderr[-2000:]))
    return done.stdout.strip()


class ImportCost(unittest.TestCase):
    def test_the_mcp_server_imports_neither_the_pe_reader_nor_the_engine_client(self):
        out = run("import sys, hydralysis.mcp; "
                  "print(','.join(sorted(m for m in ('capstone', 'pefile', 'hydralysis.query', "
                  "'hydralysis.views', 'hydralysis.workcopy', 'hydralysis.pe') if m in sys.modules)))")
        self.assertEqual(out, "", "importing hydralysis.mcp loaded: %s" % out)

    def test_the_reader_is_imported_by_the_first_pe_tool_and_not_before(self):
        exe = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/whoami.exe"
        if os.name != "nt" or not exe.is_file():
            self.skipTest("needs a Windows PE to read")
        out = run("import json, re, sys\n"
                  "from hydralysis import api\n"
                  "seen = lambda: [m for m in ('capstone', 'pefile') if m in sys.modules]\n"
                  "before = seen()\n"
                  "header = api.call('fingerprint', {'exe': %r})\n"
                  "after_header = seen()\n"
                  "entry = re.search(r'entry_rva (0x[0-9a-f]+)', header).group(1)\n"
                  "text = api.call('disasm', {'exe': %r, 'address': 'rva:' + entry, 'count': 4})\n"
                  "print(json.dumps({'before': before, 'after_header': after_header, 'after': seen(),"
                  " 'lines': text.count(chr(10))}))" % (str(exe), str(exe)))
        seen = json.loads(out)
        self.assertEqual(seen["before"], [], "a PE extension was loaded before the first PE tool ran")
        self.assertEqual(seen["after_header"], ["pefile"], "fingerprint must load pefile only, not the disassembler")
        self.assertEqual(seen["after"], ["capstone", "pefile"], "disasm did not load the disassembler")
        self.assertGreater(seen["lines"], 0)


if __name__ == "__main__":
    unittest.main()
