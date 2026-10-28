"""Overlay job launcher identity races, with no subprocesses or games."""

from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from hydralysis import overlayjobs
from support import workdir


class LauncherIdentity(TestCase):
    def setUp(self):
        self.temp = workdir("overlay-jobs")
        self.addCleanup(self.temp.cleanup)
        self.settings = {"root": self.temp.name}

    def test_parent_preserves_worker_identity_published_before_launcher_returns(self):
        def spawn(command, **kwargs):
            overlayjobs._update(Path(command[-1]), state="running", worker_pid=2222, worker_started_ms=3333)
            return Mock(pid=1111)

        with patch("hydralysis.overlayjobs.proc.popen", side_effect=spawn), \
             patch("hydralysis.overlayjobs.proc_start", return_value=4444):
            job = overlayjobs.start(self.settings, "owned", "edit")
        self.assertEqual(job["state"], "running")
        self.assertEqual((job["worker_pid"], job["worker_started_ms"]), (2222, 3333))

    def test_parent_records_provisional_launcher_identity_while_queued(self):
        with patch("hydralysis.overlayjobs.proc.popen", return_value=Mock(pid=1111)), \
             patch("hydralysis.overlayjobs.proc_start", return_value=4444):
            job = overlayjobs.start(self.settings, "owned", "edit")
        self.assertEqual(job["state"], "queued")
        self.assertEqual((job["worker_pid"], job["worker_started_ms"]), (1111, 4444))

    def test_sync_reuse_is_limited_to_the_same_view(self):
        with patch("hydralysis.overlayjobs.proc.popen", return_value=Mock(pid=1111)), \
             patch("hydralysis.overlayjobs.proc_start", return_value=4444):
            first = overlayjobs.start(self.settings, "owned", "sync", view="alice")
            second = overlayjobs.start(self.settings, "owned", "sync", view="bob")
            again = overlayjobs.start(self.settings, "owned", "sync", view="alice")
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["id"], again["id"])
        self.assertTrue(again["reused"])


class CommitKind(TestCase):
    """Kind `commit` (PROTOCOL-3.md 4.6): the worker runs the commit and records its report, or the structured refusal."""

    def setUp(self):
        self.temp = workdir("overlay-jobs")
        self.addCleanup(self.temp.cleanup)
        self.settings = {"root": self.temp.name, "targets": {"owned": {"gpr": "x.gpr", "program": "/p", "sha256": "a" * 64}}}

    def start(self, options):
        with patch("hydralysis.overlayjobs.proc.popen", return_value=Mock(pid=1111)), \
             patch("hydralysis.overlayjobs.proc_start", return_value=4444):
            return overlayjobs.start(self.settings, "owned", "commit", "", options, view="alice")

    def run_worker(self, job, outcome):
        from hydralysis import commits, targets, workcopy
        path = overlayjobs.job_path(self.settings, job["id"])
        selected = {"name": "owned", "gpr": "x.gpr", "program": "/p", "sha256": "a" * 64, "key": "k" * 16}
        seen = {}

        def fake_commit(settings, chosen, options, engine, timeout):
            seen.update(view=chosen["view"], options=options, timeout=timeout)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        with patch.object(targets, "resolve", return_value=selected), patch.object(commits, "run_commit", fake_commit), \
             patch("hydralysis.overlayjobs.hydra.Engine"), patch("hydralysis.overlayjobs.threading.Thread"):
            overlayjobs.run(path)
        return overlayjobs.status(self.settings, job["id"]), seen

    def test_the_job_record_carries_the_kind_and_the_commit_options(self):
        job = self.start({"kind": "commit", "cid": "c-0badf00d", "expect_revision": 3})
        self.assertEqual(job["kind"], "commit")
        self.assertEqual(job["options"]["cid"], "c-0badf00d")
        self.assertEqual(job["view"], "alice")

    def test_a_finished_commit_is_recorded_as_done_with_its_report(self):
        job = self.start({"kind": "commit", "cid": "c-0badf00d", "expect_revision": 3})
        record, seen = self.run_worker(job, {"ok": True, "cid": "c-0badf00d", "generation": 2})
        self.assertEqual((record["state"], record["result"]["generation"]), ("done", 2))
        self.assertEqual(seen["view"], "alice")
        self.assertEqual(seen["options"]["expect_revision"], 3)

    def test_a_refused_or_aborted_commit_is_failed_with_the_structured_payload(self):
        from hydralysis import commits
        job = self.start({"kind": "commit", "cid": "c-0badf00d", "expect_revision": 3})
        record, _ = self.run_worker(job, commits.CommitError("drift", "1 record drifted", drift=[{"id": "x"}]))
        self.assertEqual(record["state"], "failed")
        self.assertTrue(record["error"].startswith("drift:"))
        self.assertEqual(record["error_payload"]["error"], "drift")
        self.assertEqual(record["error_payload"]["drift"], [{"id": "x"}])

    def test_any_other_failure_is_recorded_like_the_other_kinds(self):
        job = self.start({"kind": "commit", "cid": "c-0badf00d", "expect_revision": 3})
        record, _ = self.run_worker(job, RuntimeError("engine gone"))
        self.assertEqual(record["state"], "failed")
        self.assertIn("RuntimeError: engine gone", record["error"])
