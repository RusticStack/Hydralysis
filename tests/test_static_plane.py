"""The static read plane (`HYDRALYSIS_IMPL=rust`): xrefs answered from the project files with no engine, everything
else declined to the engine. Needs the native extension carrying `static_call_rs`; skipped without it.

The fixture is the engine's analysed legacy project (rust/crates/hy-static/tests/fixtures); the expected rows are the
Java oracle's (`oracleprog-legacy-12.1.4-analysed.txt`)."""

from __future__ import annotations

import json
import os
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import query, staticplane, workcopy
from support import workdir

FIXTURES = Path(__file__).resolve().parent.parent / "rust" / "crates" / "hy-static" / "tests" / "fixtures"
SHA = "d105b8ad8a5f549a8a2c205e95f71e1b84bcc7ec183f63ea9804442be855179b"


def _native():
    try:
        import hydralysis_native
    except ImportError:
        return False
    return hasattr(hydralysis_native, "static_call_rs")


class AskedTheEngine(RuntimeError):
    pass


class NoEngine:
    """A stand-in that fails the moment the engine path is used."""
    key = "no-engine"
    role = "reader"
    lane = ""
    start = False

    def __init__(self, settings=None):
        self.settings = settings
        self.calls = []

    def call(self, *args, **kwargs):
        self.calls.append(args)
        raise AskedTheEngine(args)

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)

        def refuse(*args, **kwargs):
            self.calls.append(name)
            raise AskedTheEngine(name)
        return refuse


def oracle_refs():
    """to-address -> [(from, type)] in the oracle's order, for plain memory references to RAM."""
    groups = {}
    path = FIXTURES / "oracle" / "oracleprog-legacy-12.1.4-analysed.txt"
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("toref from="):
            continue
        fields = dict(part.split("=", 1) for part in line.split(" ")[1:] if "=" in part)
        if not fields["to"].startswith("ram:") or fields["kind"] not in ("MemReferenceDB", "EntryPointReferenceDB"):
            continue
        origin = "Entry Point" if fields["from"] == "EXT_FROM" else "%08x" % int(fields["from"][4:], 16)
        groups.setdefault(int(fields["to"][4:], 16), []).append(("0x" + origin, fields["type"]))
    return groups


@unittest.skipUnless(_native(), "hydralysis_native with the static plane is not built")
class StaticPlane(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("static")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.project = root / "project"
        shutil.copytree(FIXTURES / "legacy-12.1.4-analysed", self.project)
        self.settings = {"root": str(root / "data"), "hydra_dir": "x", "hydra_client": "x",
                         "targets": {"flow": {"gpr": str(self.project / "legacy.gpr"), "program": "/flow_fixture.exe",
                                              "sha256": SHA}}}
        env = patch.dict(os.environ, {"HYDRALYSIS_IMPL": "rust"})
        env.start()
        self.addCleanup(env.stop)
        query._keys.clear()
        staticplane.reset()
        self.engine = NoEngine(self.settings)
        self.runner = query.QueryRunner(self.settings, self.engine)

    def ask(self, action, address, **kwargs):
        return json.loads(self.runner.query("flow", action, address, options={"view": "shared"}, **kwargs))

    def test_xrefs_come_from_the_files_and_equal_the_oracle(self):
        groups = oracle_refs()
        busiest = max(groups, key=lambda key: len(groups[key]))
        sample = sorted(groups)[::40][:60] + [busiest]
        for address in sample:
            reply = self.ask("xrefs", "va:0x%x" % address, limit=200)
            rows = [(row["from"], row["type"]) for row in reply["references"]]
            self.assertEqual(rows, groups[address][:200], hex(address))
            self.assertTrue(all(row["to"] == "0x%08x" % address for row in reply["references"]))
            self.assertEqual(reply["engine"]["mode"], "static")
            self.assertEqual(reply["sha256"], SHA)
            self.assertEqual(reply["program"], "flow_fixture.exe")
            self.assertEqual(reply["target"], "flow")
        self.assertEqual(self.engine.calls, [], "the engine must not be touched for a static answer")

    def test_function_rows_equal_the_engine_answers_recorded_from_the_real_engine(self):
        truth = json.loads((FIXTURES / "engine" / "function.json").read_text(encoding="utf-8"))
        answered = 0
        for address, want in truth.items():
            try:
                got = self.ask("function", address)
            except AskedTheEngine:
                continue
            self.assertEqual(got["function"], want["function"], address)
            self.assertEqual(got["engine"]["mode"], "static")
            answered += 1
        self.assertGreater(answered, 380)
        pages = json.loads((FIXTURES / "engine" / "functions.json").read_text(encoding="utf-8"))
        cursor, seen = "", 0
        for page in pages:
            try:
                got = self.ask("functions", "", limit=200, cursor=cursor)
            except AskedTheEngine:
                got = None
            if got is not None:
                self.assertEqual(got["functions"], page["functions"])
                for key in ("scanned", "truncated", "next_cursor"):
                    self.assertEqual(got.get(key), page.get(key))
                seen += 1
            if not page["truncated"]:
                break
            cursor = page["next_cursor"]
        self.assertGreaterEqual(seen, 1)

    def test_paging_matches_one_big_page(self):
        groups = oracle_refs()
        address = max(groups, key=lambda key: len(groups[key]))
        whole = self.ask("xrefs", hex(address), limit=200)["references"]
        self.assertGreaterEqual(len(whole), 3)
        paged, cursor = [], ""
        while True:
            page = self.ask("xrefs", hex(address), limit=2, cursor=cursor)
            paged += page["references"]
            if not page["truncated"]:
                break
            cursor = page["next_cursor"]
        self.assertEqual(paged, whole)

    def test_a_question_the_plane_cannot_answer_goes_to_the_engine(self):
        for action in ("decompile", "types", "data"):
            with self.assertRaises(AskedTheEngine, msg=action):
                self.ask(action, "0x140001030")
        self.assertFalse(staticplane.supports("decompile"))
        # a thiscall function: the plane declines (automatic `this`), the engine is asked
        with self.assertRaises(AskedTheEngine):
            self.ask("function", "0x140003c60")
        self.assertIn("unsupported: calling convention that may add automatic parameters", staticplane.reasons())

    def test_unsupported_programs_fall_back_to_the_engine(self):
        # not the analysed program of this project: the index does not list it
        self.settings["targets"]["flow"]["program"] = "/other.exe"
        with self.assertRaises(AskedTheEngine):
            self.ask("xrefs", "0x1400014f0")
        # a hash the program does not have
        self.settings["targets"]["flow"].update(program="/flow_fixture.exe", sha256="00" * 32)
        with self.assertRaises(Exception):
            self.ask("xrefs", "0x1400014f0")

    def test_a_view_with_overlays_is_never_answered_statically(self):
        with patch.object(workcopy, "expected_state", return_value='{"n": 1}'), \
                patch.object(workcopy, "has_overlays", return_value=True):
            with self.assertRaises(Exception):
                self.ask("xrefs", "0x1400014f0")
        self.assertEqual(staticplane.reasons(), {})

    def test_without_the_switch_the_engine_is_asked(self):
        with patch.dict(os.environ, {"HYDRALYSIS_IMPL": ""}):
            with self.assertRaises(AskedTheEngine):
                self.ask("xrefs", "0x1400014f0")

    def test_direct_calls(self):
        ok, info = staticplane.call("info", str(self.project / "legacy.gpr"), "/flow_fixture.exe")
        self.assertTrue(ok)
        self.assertEqual(info["sha256"], SHA)
        ok, hexed = staticplane.call("read_bytes", str(self.project), "flow_fixture.exe", 0x140000000, 2)
        self.assertEqual((ok, hexed), (True, "4d5a"))
        ok, functions = staticplane.call("functions", str(self.project), "flow_fixture.exe")
        self.assertTrue(ok and len(functions) > 400)
        ok, reason = staticplane.call("read_bytes", str(self.project), "flow_fixture.exe", 0x10, 2)
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("unsupported"))


if __name__ == "__main__":
    unittest.main()
