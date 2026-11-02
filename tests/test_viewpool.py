"""Warm publish workers (`viewpool`): one job per worker, the job record untouched, the one-shot worker as the fallback.

The stub worker speaks the same two control lines as `hydralysis.viewpool --serve` and writes a line to a log per job it
runs, so a test can tell which process took which job, and kill one mid-job. The last test uses the real worker module
and the real `views.run_job` against a job whose target does not exist: the record it leaves is the one the one-shot
worker leaves, written by the same code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import viewpool
from support import REPOSITORY, workdir

SRC = str(REPOSITORY / "src")
STUB = r'''
import json, os, sys, time
from pathlib import Path
PREFIX = b"@hydralysis-viewpool "
def say(**message):
    sys.stdout.buffer.write(PREFIX + json.dumps(message).encode("ascii") + b"\n")
    sys.stdout.buffer.flush()
log = Path(sys.argv[1])
release = log.parent / "release"
mode = sys.argv[2] if len(sys.argv) > 2 else "normal"
if mode == "die-before-hello":
    sys.exit(9)
say(ready=True, pid=os.getpid())
for line in sys.stdin.buffer:
    message = json.loads(line)
    if message.get("stop"):
        break
    job = message.get("job")
    if not job:
        continue
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"pid": os.getpid(), "job": job}) + "\n")
    if mode == "hold":
        while not release.exists():
            time.sleep(0.02)
    if mode == "die-mid-job":
        os._exit(7)
    say(done=True)
'''


def wait_for(predicate, timeout=15.0, step=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return predicate()


class Base(unittest.TestCase):
    mode = "normal"

    def setUp(self):
        self.temp = workdir("viewpool")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "jobs.jsonl"
        self.stub = self.root / "stub.py"
        self.stub.write_text(STUB, encoding="utf-8")
        self.pools = []
        self.addCleanup(self.stop_pools)

    def pool(self, mode=None):
        pool = viewpool.Pool()
        self.pools.append(pool)
        self.mode = mode or self.mode
        self.addCleanup(self.release_holds)
        return pool

    def command(self, mode=None):
        return [sys.executable, str(self.stub), str(self.log), mode or self.mode]

    def send(self, pool, name="job.json", max_workers=8):
        path = self.root / name
        path.write_text("{}", encoding="utf-8")
        with patch.object(viewpool, "command", lambda: self.command()):
            return pool.send(path, dict(os.environ), max_workers)

    def jobs(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def release_holds(self):
        (self.root / "release").write_text("go", encoding="utf-8")

    def stop_pools(self):
        self.release_holds()
        for pool in self.pools:
            pool.close_all()
            wait_for(lambda: not pool.workers, timeout=5)
            for worker in list(pool.workers):
                worker.child.kill()
            pool.shutdown()


class Reuse(Base):
    def test_a_second_job_reuses_the_warm_worker(self):
        pool = self.pool()
        self.assertTrue(self.send(pool, "one.json"))
        self.assertTrue(wait_for(lambda: len(self.jobs()) == 1))
        self.assertTrue(wait_for(lambda: pool.workers and not pool.workers[0].busy))
        self.assertTrue(self.send(pool, "two.json"))
        self.assertTrue(wait_for(lambda: len(self.jobs()) == 2))
        self.assertEqual(len({row["pid"] for row in self.jobs()}), 1, "the second job needed a second process")
        self.assertEqual(len(pool.workers), 1)

    def test_two_jobs_at_once_use_two_workers_and_never_share_one(self):
        pool = self.pool("hold")
        self.assertTrue(self.send(pool, "one.json"))
        self.assertTrue(self.send(pool, "two.json"))
        self.assertTrue(wait_for(lambda: len(self.jobs()) == 2))
        self.assertEqual(len({row["pid"] for row in self.jobs()}), 2)
        self.assertEqual((len(pool.workers), sum(worker.busy for worker in pool.workers)), (2, 2))
        self.release_holds()
        self.assertTrue(wait_for(lambda: not any(worker.busy for worker in pool.workers)))

    def test_the_cap_sends_the_overflow_to_the_one_shot_path(self):
        pool = self.pool("hold")
        self.assertTrue(self.send(pool, "one.json", max_workers=1))
        self.assertFalse(self.send(pool, "two.json", max_workers=1))
        self.assertTrue(wait_for(lambda: len(self.jobs()) == 1))
        self.release_holds()


class Failure(Base):
    def test_a_worker_that_dies_before_its_hello_is_not_delivered_and_the_pool_is_disabled(self):
        pool = self.pool("die-before-hello")
        self.assertFalse(self.send(pool))
        self.assertTrue(pool.broken)
        self.assertEqual(self.jobs(), [])

    def test_a_worker_killed_mid_job_does_not_touch_the_caller_or_the_job_file_and_the_pool_drops_it(self):
        pool = self.pool("hold")
        self.assertTrue(self.send(pool, "one.json"))
        self.assertTrue(wait_for(lambda: len(self.jobs()) == 1))
        record = json.loads((self.root / "one.json").read_text(encoding="utf-8"))
        worker = pool.workers[0]
        worker.child.kill()
        self.assertTrue(wait_for(lambda: not pool.workers))
        self.assertEqual(json.loads((self.root / "one.json").read_text(encoding="utf-8")), record)
        self.assertFalse(worker.alive())
        self.assertTrue(self.send(pool, "two.json"), "the pool did not survive a killed worker")
        self.assertTrue(wait_for(lambda: len(self.jobs()) == 2))
        self.assertEqual(len({row["pid"] for row in self.jobs()}), 2)

    def test_a_failing_job_is_never_a_failing_publish(self):
        pool = self.pool()
        with patch.object(pool, "_spawn", side_effect=OSError("no process available")):
            self.assertFalse(self.send(pool))
        self.assertTrue(pool.broken)

    def test_the_test_fault_environment_never_pools(self):
        with patch.object(viewpool, "_POOL", None), patch.object(viewpool, "_DISABLED", False), \
                patch.object(viewpool, "Pool") as pool_class:
            with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "publish.after_seal:raise"}):
                self.assertFalse(viewpool.dispatch(self.root / "x.json", dict(os.environ), 8))
        pool_class.assert_not_called()


class Idle(Base):
    def test_one_idle_worker_is_kept_and_an_idle_one_is_stopped_after_the_timeout(self):
        with patch.object(viewpool, "IDLE_S", 0.3):
            pool = self.pool()
            self.assertTrue(self.send(pool, "one.json"))
            self.assertTrue(wait_for(lambda: len(self.jobs()) == 1))
            self.assertTrue(wait_for(lambda: pool.workers and not pool.workers[0].busy))
            self.assertTrue(self.send(pool, "two.json"))
            self.assertTrue(wait_for(lambda: len(self.jobs()) == 2))
            self.assertTrue(wait_for(lambda: not pool.workers, timeout=5), "the idle worker was not stopped")


class StartJob(Base):
    """`views.start_job`: a warm worker takes the job; every other publish takes the one-shot path it always had."""

    def settings(self):
        return {"root": str(self.root), "hydra_dir": str(self.root / "engine"), "hydra_client": str(self.root / "client.py")}

    def test_a_warm_worker_takes_the_job_and_no_process_is_spawned_here(self):
        from hydralysis import overlayjobs, views
        with patch("hydralysis.viewpool.dispatch", return_value=True) as dispatch, \
                patch("hydralysis.proc.popen") as popen:
            job = views.start_job(self.settings(), "owned", {"csid": "c-abcd1234", "lineage": "l-0123456789abcdef"}, view="one")
        popen.assert_not_called()
        path = overlayjobs.job_path(self.settings(), job["id"])
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual((record["id"], record["kind"], record["state"], record["view"], record["target"]),
                         (job["id"], "publish", "queued", "one", "owned"))
        self.assertNotIn("worker_pid", record, "the warm worker writes its own pid when it starts the job")
        self.assertTrue(job["owner_token"])
        self.assertTrue((path.parent / "settings.json").is_file())
        self.assertEqual(dispatch.call_args.args[0], path)
        self.assertEqual(json.loads((path.parent / "settings.json").read_text(encoding="utf-8"))["root"], str(self.root))

    def test_the_one_shot_worker_is_spawned_when_the_pool_does_not_take_the_job(self):
        from hydralysis import overlayjobs, views
        child = type("Child", (), {"pid": 4321})()
        with patch("hydralysis.viewpool.dispatch", return_value=False), \
                patch("hydralysis.proc.popen", return_value=child) as popen, \
                patch("hydralysis.overlayjobs.proc_start", return_value=7777):
            job = views.start_job(self.settings(), "owned", {"csid": "c-abcd1234", "lineage": "l-0123456789abcdef"})
        self.assertEqual(popen.call_args.args[0][1:3], ["-m", "hydralysis.views"])
        record = json.loads(overlayjobs.job_path(self.settings(), job["id"]).read_text(encoding="utf-8"))
        self.assertEqual((job["state"], record["worker_pid"], record["worker_started_ms"]), ("queued", 4321, 7777))


class RunJobLifecycle(Base):
    """`views.run_job` leaves a reusable process behind: the cancel watcher ends and the connection it opened is dropped."""

    def test_a_finished_job_stops_its_watcher_and_resets_the_engine_it_opened(self):
        import threading
        from unittest.mock import patch as _patch
        from hydralysis import views
        folder = self.root / "overlay-jobs" / "overlay-cccccccccccc"
        folder.mkdir(parents=True)
        path = folder / "job.json"
        path.write_text(json.dumps({"id": folder.name, "kind": "publish", "target": "missing", "view": "", "address": "",
                                    "options": {"csid": "c-abcd1234", "lineage": "l-0123456789abcdef"},
                                    "state": "queued", "created_at": time.time()}), encoding="utf-8")
        (folder / "settings.json").write_text(json.dumps({"root": str(self.root)}), encoding="utf-8")
        resets = []

        class Engine:
            def __init__(self, settings):
                self.settings = settings

            def reset(self):
                resets.append(True)

        with _patch.object(views.hydra, "Engine", Engine):
            views.run_job(path)
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(record["state"], "failed")
        self.assertEqual(record["worker_pid"], os.getpid())
        self.assertIn("no analysis target 'missing'", record["error"])
        self.assertEqual(resets, [True])
        self.assertTrue(wait_for(lambda: not any(thread.name == "hydralysis-publish-cancel"
                                                 for thread in threading.enumerate()), timeout=2),
                        "the cancel watcher outlived its job")


class RealWorker(Base):
    """`python -m hydralysis.viewpool --serve` with the real `views.run_job`, on a job whose target does not exist."""

    def setUp(self):
        super().setUp()
        # `viewpool` keeps process-wide state (`_POOL`, `_DISABLED`). A test elsewhere in the same process that reaches the real
        # `views.start_job` with `proc.popen` patched out leaves the pool disabled for good (a worker without pipes is a broken
        # pool, by design), so `unittest discover` made `dispatch` answer False here. This test owns a fresh pool.
        for name, value in (("_POOL", None), ("_DISABLED", False)):
            patcher = patch.object(viewpool, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def job(self, job_id, name):
        folder = self.root / "overlay-jobs" / job_id
        folder.mkdir(parents=True)
        path = folder / "job.json"
        path.write_text(json.dumps({"id": job_id, "kind": "publish", "target": "missing", "view": "", "address": "",
                                    "options": {"csid": "c-abcd1234", "lineage": "l-0123456789abcdef"},
                                    "state": "queued", "created_at": time.time()}), encoding="utf-8")
        (folder / "settings.json").write_text(json.dumps({"root": str(self.root), "hydra_dir": str(self.root / "engine"),
                                                          "hydra_client": str(self.root / "client.py")}), encoding="utf-8")
        return path

    def status(self, path):
        # The worker's `durable` replace can hold the file for a moment on Windows; a poll retries it.
        for _ in range(50):
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (PermissionError, ValueError):
                time.sleep(0.02)
        return json.loads(path.read_text(encoding="utf-8"))

    def test_the_real_worker_runs_the_job_records_the_failure_and_is_reused(self):
        from hydralysis import overlayjobs
        self.addCleanup(viewpool.close_all)
        first, second = self.job("overlay-aaaaaaaaaaaa", "one"), self.job("overlay-bbbbbbbbbbbb", "two")
        self.assertTrue(viewpool.dispatch(first, dict(os.environ, PYTHONPATH=SRC), 8))
        self.assertTrue(wait_for(lambda: self.status(first).get("state") == "failed", timeout=60))
        self.assertTrue(wait_for(lambda: viewpool._POOL and viewpool._POOL.workers and not viewpool._POOL.workers[0].busy))
        worker_pid = viewpool._POOL.workers[0].pid
        self.assertTrue(viewpool.dispatch(second, dict(os.environ, PYTHONPATH=SRC), 8))
        self.assertTrue(wait_for(lambda: self.status(second).get("state") == "failed", timeout=60))
        one, two = self.status(first), self.status(second)
        self.assertIn("no analysis target 'missing'", one["error"])
        self.assertEqual((one["state"], two["state"]), ("failed", "failed"))
        self.assertEqual((one["worker_pid"], two["worker_pid"]), (worker_pid, worker_pid), "the warm worker was not reused")
        self.assertEqual(overlayjobs.status({"root": str(self.root)}, "overlay-aaaaaaaaaaaa")["state"], "failed")


if __name__ == "__main__":
    unittest.main()
