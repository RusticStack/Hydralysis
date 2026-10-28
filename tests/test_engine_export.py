"""Corpus export on the real engine at fixture scale: parity against the engine's own count, kill and resume, cancel.

Runs only when HYDRALYSIS_INTEGRATION_ENGINE and HYDRALYSIS_INTEGRATION_CLIENT name a Hydra install (see
test_engine_integration.py). The binary is the fixture (Windows' whoami.exe by default, or
HYDRALYSIS_INTEGRATION_BINARY); the engine, its daemon and the data root are the test's own and are stopped at the end.
Nothing here holds game text. The KotOR run is the local tier: tools/verify_corpus.py --export (see its help).
"""

from __future__ import annotations

import json
import os
import signal
import time
import unittest
from pathlib import Path

from test_engine_integration import BINARY, CLIENT, ENGINE, _prepare, _release


def wait(settings, job, seconds=600):
    from hydralysis import exporting
    deadline = time.monotonic() + seconds
    while job["state"] in exporting.ACTIVE and time.monotonic() < deadline:
        time.sleep(0.25)
        job = exporting.status(settings, job["id"])
    return job


def rows_of(job):
    return [json.loads(line) for line in Path(job["output_path"]).read_text(encoding="utf-8").splitlines()]


def comparable(job):
    """The rows of a job without what names the job (its id, the header copy); the content is what must be equal."""
    result = []
    for row in rows_of(job):
        row = {key: value for key, value in row.items() if key not in ("job", "provenance")}
        result.append(row)
    return result


@unittest.skipUnless(ENGINE and CLIENT and BINARY and Path(BINARY).is_file(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class EngineExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _prepare(cls, BINARY, "export", "fixture")
        # The corpus size, counted independently of the export: the engine's own enumeration, page by page.
        cls.enumerated, cursor = [], ""
        while True:
            page = json.loads(cls.runner.query("fixture", "functions", limit=100, cursor=cursor))
            cls.enumerated.extend(item["address"] for item in page["functions"])
            if not page.get("truncated"):
                break
            cursor = page["next_cursor"]
        cls.status = json.loads(cls.runner.query("fixture", "status"))

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def test_the_expected_count_is_the_engines_internal_function_count(self):
        from hydralysis import exporting
        job = wait(self.settings, exporting.start(self.settings, "fixture", {"mode": "functions"}))
        self.assertEqual(job["state"], "done", job.get("log_tail", "")[-2000:])
        parity = job["parity"]
        self.assertGreater(len(self.enumerated), 0)
        self.assertEqual(parity["expected"], len(self.enumerated))
        self.assertEqual(parity["written"] + parity["failed"], parity["expected"])
        self.assertTrue(parity["ok"] and job["all_succeeded"] and job["complete"])
        snapshot = json.loads((Path(job["output_path"]).parent / "snapshot.json").read_text(encoding="utf-8"))
        self.assertEqual(snapshot["keys"], self.enumerated)
        # The engine's total counts functions the enumeration does not: it can only be at least the internal count.
        total = parity["engine_function_total"]
        self.assertIsInstance(total, int)
        self.assertGreaterEqual(total, parity["expected"])
        self.assertEqual(parity["non_internal"], total - parity["expected"])
        print("fixture corpus: expected %d internal, engine total %d, non-internal %d" % (parity["expected"], total, parity["non_internal"]))

    def test_a_kill_at_half_and_a_resume_equal_an_uninterrupted_decompile_export(self):
        from hydralysis import exporting
        count = min(len(self.enumerated), 60)
        whole = wait(self.settings, exporting.start(self.settings, "fixture", {"mode": "decompile", "limit": count}))
        self.assertEqual(whole["state"], "done", whole.get("log_tail", "")[-2000:])
        self.assertEqual(whole["parity"]["expected"], count)
        print("fixture decompile export: %d rows in %.2f s (%.1f ms per row)"
              % (count, whole["elapsed_run_s"], 1000 * whole["elapsed_run_s"] / count))
        # The second job differs only by its timeout, so it is not deduplicated onto the first.
        job = exporting.start(self.settings, "fixture", {"mode": "decompile", "limit": count, "timeout_s": 31})
        output = Path(job["output_path"])
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            lines = len(output.read_text(encoding="utf-8").splitlines()) if output.exists() else 0
            if lines >= count // 2:
                break
            time.sleep(0.05)
        record = exporting.status(self.settings, job["id"])
        if record["state"] == "done":
            self.skipTest("the export finished before it could be killed at 50%; the fixture is too small for this run")
        os.kill(int(record["worker_pid"]), signal.SIGTERM)  # the worker this test started
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            record = exporting.status(self.settings, job["id"])
            if record["state"] not in exporting.ACTIVE:
                break
            time.sleep(0.5)  # status() reports a dead worker as interrupted once 5 s have passed since it was queued
        self.assertIn(record["state"], ("interrupted", "failed", "paused"), record)
        partial = len(output.read_text(encoding="utf-8").splitlines())
        self.assertLess(partial, count)
        self.assertGreater(partial, 0)
        resumed = wait(self.settings, exporting.start(self.settings, "fixture", {"resume": job["id"]}))
        self.assertEqual(resumed["state"], "done", resumed.get("log_tail", "")[-2000:])
        # The run is limited to count rows, so it is not "complete" (exhausted); parity is against the limit.
        self.assertTrue(resumed["parity"]["ok"] and resumed["limited"])
        self.assertEqual((resumed["all_succeeded"], resumed["failed"]), (whole["all_succeeded"], whole["failed"]))
        first, second = comparable(whole), comparable(resumed)
        for rows in (first, second):
            for row in rows:
                row["result"].pop("query_s", None)
                row["result"].pop("engine", None)
        self.assertEqual([row["key"] for row in first], [row["key"] for row in second])
        self.assertEqual([(row["key"], row["state"], row.get("c_sha256"), row.get("body_sha256")) for row in first],
                         [(row["key"], row["state"], row.get("c_sha256"), row.get("body_sha256")) for row in second])

    def test_cancel_latency_on_the_engine(self):
        from hydralysis import exporting
        count = min(len(self.enumerated), 80)
        job = exporting.start(self.settings, "fixture", {"mode": "decompile", "limit": count, "timeout_s": 32})
        output = Path(job["output_path"])
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if output.exists() and len(output.read_text(encoding="utf-8").splitlines()) >= 2:
                break
            time.sleep(0.05)
        started = time.monotonic()
        exporting.cancel(self.settings, job["id"], job.get("owner_token", ""))
        final = wait(self.settings, exporting.status(self.settings, job["id"]), 120)
        latency = time.monotonic() - started
        self.assertIn(final["state"], ("cancelled", "done"), final)
        self.assertLess(latency, 30.0)  # one bounded query (timeout_s 32 is the cap, a fixture function takes well under a second)
        print("cancel latency on the engine: %.2f s (state %s, %d of %d rows)"
              % (latency, final["state"], final["completed"], count))


if __name__ == "__main__":
    unittest.main()
