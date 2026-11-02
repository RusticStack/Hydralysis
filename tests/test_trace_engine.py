"""The `trace` tool against a real engine: open, append `hydra-trace gen` segments, query, diff, check, explain, export, close.

Runs only when HYDRALYSIS_INTEGRATION_ENGINE (a Hydra install that advertises the `trace` capability) and
HYDRALYSIS_INTEGRATION_CLIENT (its ghidra_session.py) are set, and HYDRA_TRACE_EXE names the engine's `hydra-trace.exe`
(it makes the events and is the offline tool). HYDRALYSIS_INTEGRATION_UNPINNED=1 allows an engine that is not the pinned
release. Every request goes through the same entry point as the MCP tool, `api.call("trace", ...)`; the engine has its own
data root and daemon, which is stopped at the end.
"""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from support import workdir

ENGINE = os.environ.get("HYDRALYSIS_INTEGRATION_ENGINE") or os.environ.get("RUSTICRE_INTEGRATION_ENGINE")
CLIENT = os.environ.get("HYDRALYSIS_INTEGRATION_CLIENT") or os.environ.get("RUSTICRE_INTEGRATION_CLIENT")
EXE = os.environ.get("HYDRA_TRACE_EXE", "")
HAVE = bool(ENGINE and CLIENT and EXE and Path(EXE).is_file())


@unittest.skipUnless(HAVE, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT and HYDRA_TRACE_EXE")
class RealEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hydralysis import hydra, trace_canon
        cls.canon = trace_canon
        cls.work = workdir("trace-real")
        cls.root = Path(cls.work.name)
        cls.settings = {"root": str(cls.root / "data"), "hydra_dir": ENGINE, "hydra_client": CLIENT, "hydra_idle_s": 600}
        if os.environ.get("HYDRALYSIS_INTEGRATION_UNPINNED"):
            cls.settings["hydra_allow_unpinned"] = True
        cls.env = patch.dict(os.environ, {"HYDRALYSIS_ROOT": cls.settings["root"]})
        cls.env.start()
        cls.patch = patch("hydralysis.api._settings", return_value=cls.settings)
        cls.patch.start()
        cls.hydra = hydra
        engine = hydra.Engine(cls.settings)
        if not hydra.supports(engine, "trace"):
            cls.tearDownClass()
            raise unittest.SkipTest("this engine does not advertise the trace capability")
        cls.events = {}
        for name, seed in (("a", 7), ("b", 8)):
            folder = cls.root / ("gen-" + name)
            folder.mkdir()
            subprocess.run([EXE, "gen", "baseline", str(seed), "200", str(folder)], check=True, capture_output=True, timeout=60)
            segment = next(folder.glob("*.trace"))
            scan = trace_canon.scan(segment.read_bytes(), segment.stem)
            assert scan.clean, scan.damage
            cls.events[name] = [{k: v for k, v in record.items() if k not in ("hash", "n", "prev")} for record in scan.records]

    @classmethod
    def tearDownClass(cls):
        try:
            engine = cls.hydra.Engine(cls.settings)
            try:
                engine.stop(force=True)
            finally:
                daemon = engine.module().Daemon(str(engine.engine_dir), str(cls.hydra.state_dir(cls.settings)), cls.hydra.INSTANCE)
                if daemon.jvm_alive() or daemon.read_endpoint():
                    daemon.kill()
        finally:
            for item in (getattr(cls, "patch", None), getattr(cls, "env", None)):
                if item is not None:
                    item.stop()
            cls.work.cleanup()

    def tool(self, action, session=None, **options):
        from hydralysis import api
        args = {"action": action, "options": options}
        if session is not None:
            args["session"] = session
        return json.loads(api.call("trace", args))

    def fill(self, session, name):
        """Open SESSION through the tool and append the generator's events with the capability it handed out."""
        from hydralysis import trace
        started = self.tool("start", session)
        self.assertEqual(started["session"], session, started)
        self.assertTrue(started["cap"].startswith("cap_"), started)
        client = trace.TraceClient(trace._engine(self.settings))
        events = self.events[name]
        for start in range(0, len(events), 100):
            reply = client.append(session, events[start:start + 100], cap=started["cap"])
            self.assertEqual(reply["rejected"], [], reply)
        return started

    def test_the_whole_cycle_through_the_tool(self):
        a = self.fill("rt_a", "a")
        self.fill("rt_b", "b")
        marked = self.tool("mark", "rt_a", label="phase-one", phase="p1")
        self.assertEqual(marked["accepted"], 1, marked)

        status = self.tool("status", "rt_a")
        self.assertEqual(status["events"], 203, status)  # 202 generated, one marker
        self.assertTrue(status["writer_open"])
        listing = self.tool("status")
        self.assertGreaterEqual(listing["count"], 2, listing)

        page = self.tool("query", "rt_a", kinds=["core.state.write"], limit=5)
        self.assertEqual(len(page["rows"]), 5, page)
        self.assertTrue(page["coverage"]["reported"])
        self.assertEqual(page["coverage"]["revision"], page["revision"])
        self.assertTrue(page["citations"])
        self.assertEqual(page["citations"][0]["session"], "rt_a")
        rest = self.tool("query", "rt_a", kinds=["core.state.write"], limit=5, cursor=page["next"], up_to=page["up_to"])
        self.assertNotEqual(rest["rows"][0]["event_id"], page["rows"][0]["event_id"])

        groups = self.tool("query", "rt_a", group_by="kind")
        self.assertEqual({g["key"]: g["count"] for g in groups["groups"]}["core.marker"], 1, groups)

        event_id = page["rows"][0]["event_id"]
        explained = self.tool("explain", "rt_a", event_id=event_id, direction="downstream", depth=3)
        self.assertEqual(explained["root"], event_id, explained)

        checked = self.tool("check", "rt_a", assertions=[{"type": "cardinality", "name": "one-marker", "kind": "core.marker",
                                                         "min": 1, "max": 1}])
        self.assertEqual(checked["results"][0]["verdict"], "pass", checked)
        self.assertTrue(checked["persisted"], "the lease holder's check is stored in the session")
        missing = self.tool("check", "rt_a", assertions=[{"type": "forbidden", "name": "no-writes", "kind": "core.state.write"}])
        self.assertEqual(missing["results"][0]["verdict"], "fail", missing)
        with self.assertRaises(ValueError):
            self.tool("check", "rt_a")

        diff = self.tool("diff", "rt_a", against="rt_b", group_by="kind")
        entries = diff["diff"]["entries"]
        self.assertTrue(entries and all("class" in entry for entry in entries), diff)
        self.assertTrue(diff["coverage"]["reported"])
        again = self.tool("diff", "rt_a", against="rt_b", group_by="kind")
        self.assertEqual(diff["diff"], again["diff"], "a diff of the same two snapshots is byte-deterministic")

        exported = self.tool("export", "rt_a", name="cycle")
        self.assertIn("bundle_id", exported, exported)
        folder = Path(exported["out"])
        self.assertTrue((folder / "manifest.json").is_file(), exported)
        self.assertTrue((folder / "traces" / "events.jsonl").is_file())

        stopped = self.tool("stop", "rt_a")
        self.assertTrue(stopped["closed"]["was_open"], stopped)
        self.assertFalse(self.tool("status", "rt_a")["writer_open"])
        self.assertEqual(a["cap"][:4], "cap_")

    def test_a_session_that_is_not_open_for_writing_is_refused_with_the_real_code(self):
        self.fill("rt_c", "a")
        refused = self.tool("mark", "rt_c", label="x", cap="cap_not_the_one")
        self.assertEqual(refused["error"], "not_owner", refused)
        missing = self.tool("query", "no_such_session")
        self.assertIn(missing.get("error"), ("not_found", "failed"), missing)

    def test_online_import_of_a_jsonl_file(self):
        path = self.root / "events.jsonl"
        path.write_bytes(b"".join(json.dumps(e, sort_keys=True).encode() + b"\n" for e in self.events["a"][:120]))
        imported = self.tool("import", "rt_imp", input=str(path))
        self.assertEqual(imported["imported"], 120, imported)
        self.assertEqual(self.tool("status", "rt_imp")["events"], 120)
        self.assertFalse(self.tool("status", "rt_imp")["writer_open"])

    def test_the_offline_tool_imports_verifies_and_exports(self):
        store = self.root / "offline-store"
        path = self.root / "off.jsonl"
        path.write_bytes(b"".join(json.dumps(e, sort_keys=True).encode() + b"\n" for e in self.events["b"][:50]))
        with patch.dict(os.environ, {"HYDRA_TRACE_EXE": EXE}):
            imported = self.tool("import", offline=True, session="off1", input=str(path), store=str(store))
            self.assertEqual((imported["imported"], imported["ok"]), (50, True), imported)
            verified = self.tool("status", offline=True, op="verify", session="off1", store=str(store), engine=True)
            self.assertEqual(verified["outcome"], "clean", verified)
            self.assertTrue(verified["engine"]["ok"], verified)
            exported = self.tool("export", offline=True, op="export", session="off1", store=str(store),
                                 output=str(self.root / "off-export"))
        self.assertTrue(exported["ok"], exported)
        self.assertTrue((self.root / "off-export" / "manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
