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
