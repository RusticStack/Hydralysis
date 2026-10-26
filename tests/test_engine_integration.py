"""End to end on the real engine: prepare, query, overlays, revert, adopt.

Runs only when RUSTICRE_INTEGRATION_ENGINE names a Hydra install and
RUSTICRE_INTEGRATION_CLIENT its ghidra_session.py (optionally
RUSTICRE_INTEGRATION_JAVA a JDK and RUSTICRE_INTEGRATION_BINARY a small PE;
the default is Windows' whoami.exe). Everything lives in its own data root, with
its own daemon, which is stopped at the end.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from support import workdir

ENGINE = os.environ.get("RUSTICRE_INTEGRATION_ENGINE")
CLIENT = os.environ.get("RUSTICRE_INTEGRATION_CLIENT")
BINARY = os.environ.get("RUSTICRE_INTEGRATION_BINARY") or (
    os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "System32", "whoami.exe") if os.name == "nt" else "")


@unittest.skipUnless(ENGINE and CLIENT and BINARY and Path(BINARY).is_file(), "set RUSTICRE_INTEGRATION_ENGINE/CLIENT")
class EngineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from rusticre import preparation, query
        cls.work = workdir("engine")
        cls.root = Path(cls.work.name)
        binary = cls.root / "fixture.exe"
        shutil.copy2(BINARY, binary)
        cls.settings = {"root": str(cls.root / "data"), "hydra_dir": ENGINE, "hydra_client": CLIENT,
                        "hydra_idle_s": 600, "overlay_save_debounce_s": 2}
        if os.environ.get("RUSTICRE_INTEGRATION_JAVA"):
            cls.settings["java_home"] = os.environ["RUSTICRE_INTEGRATION_JAVA"]
        query._keys.clear()
        env = {"RUSTICRE_ROOT": cls.settings["root"], "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        cls.env = patch.dict(os.environ, env)
        cls.env.start()
        job = preparation.prepare(cls.settings, str(binary), "fixture")
        deadline = time.monotonic() + 600
        while True:
            status = preparation.status(cls.settings, job["job_id"])
            if status["state"] not in preparation.ACTIVE or time.monotonic() > deadline:
                break
            time.sleep(1)
        if status["state"] != "done":
            raise AssertionError("prepare did not finish: %s" % json.dumps(status)[:3000])
        cls.prepared = status
        cls.runner = query.QueryRunner(cls.settings)

    @classmethod
    def tearDownClass(cls):
        from rusticre import hydra
        engine = hydra.Engine(cls.settings)
        try:
            engine.stop(force=True)
        finally:
            # A daemon that ignored the stop must not outlive the test (it holds the work dir).
            daemon = engine.module().Daemon(str(engine.engine_dir), str(hydra.state_dir(cls.settings)), hydra.INSTANCE)
            if daemon.jvm_alive() or daemon.read_endpoint():
                daemon.kill()
            cls.env.stop()
            time.sleep(1)
            cls.work.cleanup()

    def ask(self, action, address="", **kwargs):
        return json.loads(self.runner.query("fixture", action, address, **kwargs))

    def entry(self):
        listed = self.ask("functions", limit=5)
        self.assertTrue(listed["functions"])
        return listed["functions"][0]["address"]

    def test_queries_answer_from_the_prepared_project(self):
        address = self.entry()
        for action in ("decompile", "dossier", "blocks", "pcode", "variables"):
            with self.subTest(action=action):
                answer = self.ask(action, address)
                self.assertTrue(answer["ok"])
                self.assertEqual(answer["engine"]["mode"], "contained")
        traced = self.ask("trace", address, options={"brief": True, "depth": 4})
        for key in ("constants", "stops", "memory_edges", "selected_operations"):
            self.assertIn(key, traced)
        self.assertNotIn("result", traced)
        scanned = self.ask("vcalls", limit=5, options={"offset": "0x8"})
        self.assertIn("callers", scanned)
        self.assertGreater(scanned["instructions_scanned"], 0)
        self.assertIn("vtables", self.ask("vtables", address))
        warm = [self.ask("decompile", address)["query_s"] for _ in range(3)]
        self.assertLess(min(warm), 1.0)

    def test_overlay_edit_read_and_revert(self):
        address = self.entry()
        original = self.ask("decompile", address)["function"]["name"]
        edited = json.loads(self.runner.query("fixture", "type_edit", address, timeout_s=300,
                                              options={"kind": "rename", "name": "integration_named", "source": "integration test"}))
        self.assertTrue(edited["ok"])
        self.assertEqual(self.ask("decompile", address)["function"]["name"], "integration_named")
        reverted = json.loads(self.runner.query("fixture", "type_edit", options={"kind": "revert", "ids": [edited["overlay_id"]]}))
        self.assertEqual(reverted["reverted"], 1)
        self.assertEqual(self.ask("decompile", address, timeout_s=300)["function"]["name"], original)

    def test_adopt_registers_the_prepared_project_in_place(self):
        from rusticre import hydra, targets
        gpr = self.prepared["project"]["gpr"]
        result = targets.adopt(self.settings, hydra.Engine(self.settings), str(Path(gpr).parent),
                               expected=self.prepared["sha256"], target="adopted-fixture")
        self.assertTrue(result["registered"], result)
        self.assertFalse(result["copied"])


if __name__ == "__main__":
    unittest.main()
