"""End to end on the real engine: prepare, query, overlays, revert, adopt.

Runs only when HYDRALYSIS_INTEGRATION_ENGINE (or RUSTICRE_INTEGRATION_ENGINE) names a Hydra install and
HYDRALYSIS_INTEGRATION_CLIENT its ghidra_session.py (optionally
HYDRALYSIS_INTEGRATION_JAVA a JDK and HYDRALYSIS_INTEGRATION_BINARY a small PE;
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

def _env(name):
    """HYDRALYSIS_<name>, else the old RUSTICRE_<name>."""
    return os.environ.get("HYDRALYSIS_" + name) or os.environ.get("RUSTICRE_" + name)


ENGINE = _env("INTEGRATION_ENGINE")
CLIENT = _env("INTEGRATION_CLIENT")
BINARY = _env("INTEGRATION_BINARY") or (
    os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "System32", "whoami.exe") if os.name == "nt" else "")


@unittest.skipUnless(ENGINE and CLIENT and BINARY and Path(BINARY).is_file(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class EngineIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hydralysis import preparation, query
        cls.work = workdir("engine")
        cls.root = Path(cls.work.name)
        binary = cls.root / "fixture.exe"
        shutil.copy2(BINARY, binary)
        cls.settings = {"root": str(cls.root / "data"), "hydra_dir": ENGINE, "hydra_client": CLIENT,
                        "hydra_idle_s": 600, "overlay_save_debounce_s": 2}
        if _env("INTEGRATION_JAVA"):
            cls.settings["java_home"] = _env("INTEGRATION_JAVA")
        query._keys.clear()
        env = {"HYDRALYSIS_ROOT": cls.settings["root"], "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
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
        from hydralysis import hydra
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
        orphans = self.ask("orphans", limit=5)
        self.assertIn("orphans", orphans)
        self.assertGreater(orphans["instructions_scanned"], 0)
        warm = [self.ask("decompile", address)["query_s"] for _ in range(3)]
        self.assertLess(min(warm), 1.0)

    def test_a_bulk_export_runs_in_its_own_worker(self):
        # The export worker ignores the user site; it must still find Hydralysis's dependencies.
        from hydralysis import exporting
        job = exporting.start(self.settings, "fixture", {"mode": "decompile", "limit": 5})
        deadline = time.monotonic() + 300
        while job["state"] in exporting.ACTIVE and time.monotonic() < deadline:
            time.sleep(1)
            job = exporting.status(self.settings, job["id"])
        self.assertEqual(job["state"], "done", job.get("log_tail", "")[-2000:])
        self.assertEqual(job["succeeded"], 5)

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

    def test_cited_data_label_is_visible_and_revertible(self):
        from hydralysis.pe import Image
        image = Image(Path(self.root / "fixture.exe"))
        section = next(s for s in image.sections if not (s.Characteristics & 0x20000000) and s.SizeOfRawData)
        address = hex(image.base + section.VirtualAddress)
        edited = self.ask("type_edit", address, timeout_s=300,
                          options={"kind": "label", "name": "integration_global", "source": "fixture section table"})
        data = self.ask("data", address, options={"table": True})
        self.assertIn("integration_global", [item["name"] for item in data["labels"]])
        self.ask("type_edit", options={"kind": "revert", "ids": [edited["overlay_id"]]})
        data = self.ask("data", address, options={"table": True})
        self.assertNotIn("integration_global", [item["name"] for item in data["labels"]])

    def test_gdt_archive_import_and_revert(self):
        from hydralysis import overlayjobs
        archive = Path(ENGINE) / "Ghidra/Features/Base/data/pcodetest/EmuTesting.gdt"
        self.assertTrue(archive.is_file(), str(archive))
        def submit(paths, revision):
            job = self.ask("type_edit", options={"kind": "import_archive", "archive": str(archive),
                                                "paths": paths, "source": "bundled EmuTesting.gdt",
                                                "view": "archive-fixture", "expect_revision": revision})
            deadline = time.monotonic() + 300
            while job["state"] in overlayjobs.ACTIVE and time.monotonic() < deadline:
                time.sleep(1)
                job = overlayjobs.status(self.settings, job["id"])
            return job
        job = submit(["/u4"], 0)
        self.assertEqual(job["state"], "done", job)
        self.assertEqual(self.ask("type", options={"path": "/u4", "view": "archive-fixture"})["type"]["length"], 4)
        self.assertEqual(job["result"]["import_report"]["records"], 1)
        self.assertEqual(job["result"]["import_report"]["archive_types"], 1)
        mismatch = submit(["/pointer"], 1)
        self.assertEqual(mismatch["state"], "failed", mismatch)
        self.assertIn("differs", mismatch.get("error", "").lower())
        self.assertEqual(self.ask("status", options={"view": "archive-fixture"})["overlays"]["revision"], 1)
        self.assertEqual(self.ask("type", options={"path": "/u4", "view": "archive-fixture"})["type"]["length"], 4)
        with self.assertRaises(RuntimeError):
            self.ask("type", options={"path": "/u4"})
        self.ask("type_edit", options={"kind": "revert", "ids": [job["result"]["overlay_id"]],
                                       "view": "archive-fixture", "expect_revision": 1})
        with self.assertRaises(RuntimeError):
            self.ask("type", options={"path": "/u4", "view": "archive-fixture"})

    def test_adopt_registers_the_prepared_project_in_place(self):
        from hydralysis import hydra, targets
        gpr = self.prepared["project"]["gpr"]
        result = targets.adopt(self.settings, hydra.Engine(self.settings), str(Path(gpr).parent),
                               expected=self.prepared["sha256"], target="adopted-fixture")
        self.assertTrue(result["registered"], result)
        self.assertFalse(result["copied"])


if __name__ == "__main__":
    unittest.main()
