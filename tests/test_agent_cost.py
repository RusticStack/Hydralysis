"""Per-agent CPU of a Hydralysis process (rust/t-hy-agents): what one agent costs while it queries and while it waits.

- A query resolved the data root and its project paths about twenty times; `Path.resolve` opens each path twice on Windows.
  `paths.resolved` keeps the answer for RESOLVE_TTL_S.
- A publish worker that waits for a leader looked at the queue every POLL_S (0.1 s) and rewrote its job record each time. It
  now waits in the kernel queue of `publish.lock` (Windows) and reports progress only when it changed.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import locks, paths, targets, views


class ResolvedPaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for cache in (getattr(paths, "_resolved_cache", {}), getattr(paths, "_roots", {})):
            cache.clear()
            self.addCleanup(cache.clear)

    def count_resolves(self):
        real = Path.resolve
        calls = []

        def counting(path, *args, **kwargs):
            calls.append(str(path))
            return real(path, *args, **kwargs)
        return calls, patch.object(Path, "resolve", counting)

    def test_a_warm_root_path_does_not_resolve_again(self):
        settings = {"root": str(Path(self.tmp.name) / "data")}
        calls, patcher = self.count_resolves()
        with patcher:
            first = paths.root_path(settings)
            for _ in range(50):
                self.assertEqual(paths.root_path(settings), first)
        self.assertLessEqual(len(calls), 2, calls[:6])
        self.assertEqual(first, (Path(self.tmp.name) / "data").resolve())

    def test_a_remembered_root_still_honours_forbidden_drives(self):
        root = str(Path(self.tmp.name) / "data")
        drive = Path(root).resolve().drive
        self.assertTrue(paths.root_path({"root": root}))
        with self.assertRaises(ValueError):
            paths.root_path({"root": root, "forbidden_drives": [drive]})
        self.assertEqual(paths.root_path({"root": root}), Path(root).resolve())

    def test_an_old_answer_is_resolved_again(self):
        target = Path(self.tmp.name) / "p.gpr"
        calls, patcher = self.count_resolves()
        with patcher, patch.object(paths, "RESOLVE_TTL_S", 0.0):
            for _ in range(3):
                paths.resolved(target)
        self.assertEqual(len(calls), 3)

    def test_a_relative_path_is_keyed_by_the_working_directory(self):
        one, two = Path(self.tmp.name) / "one", Path(self.tmp.name) / "two"
        one.mkdir()
        two.mkdir()
        here = os.getcwd()
        self.addCleanup(os.chdir, here)
        os.chdir(one)
        first = paths.resolved("x.gpr")
        os.chdir(two)
        second = paths.resolved("x.gpr")
        self.assertEqual(first, (one / "x.gpr").resolve())
        self.assertEqual(second, (two / "x.gpr").resolve())

    def test_target_key_is_unchanged(self):
        gpr = str(Path(self.tmp.name) / "Proj" / "a.gpr")
        import hashlib
        expected = hashlib.sha256((str(Path(gpr).expanduser().resolve()).lower() + "\n" + "prog.exe").encode()).hexdigest()[:16]
        self.assertEqual(targets.target_key(gpr, "/prog.exe"), expected)

    def test_validate_project_path_still_refuses_dot_folders(self):
        with self.assertRaises(ValueError):
            paths.validate_project_path(Path(self.tmp.name) / ".hidden" / "p.gpr")


class ImportCost(unittest.TestCase):
    """What a query process imports: a download (urllib, ssl, http.client, email), an archive (zipfile with bz2, lzma and
    zstd) and statistics (decimal, fractions) are imported where they are used, not by every agent process."""

    def test_a_query_process_does_not_import_download_archive_or_statistics_modules(self):
        import json
        import subprocess
        import sys
        import hydralysis
        src = str(Path(hydralysis.__file__).resolve().parent.parent)
        code = ("import json, sys; from hydralysis import query, views, hydra, backends, lineage, workcopy; "
                "print(json.dumps(sorted(m for m in ('urllib.request', 'ssl', 'http.client', 'zipfile', 'statistics', 'decimal') "
                "if m in sys.modules)))")
        env = dict(os.environ, PYTHONPATH=src)
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120, check=True)
        self.assertEqual(json.loads(out.stdout.strip().splitlines()[-1]), [])

    def test_backends_urllib_is_still_reachable_for_a_download(self):
        from hydralysis import backends
        self.assertTrue(callable(backends.urllib.request.urlopen))


class ProcessMemo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_a_known_build_hash_is_not_read_from_the_cache_file_again(self):
        exe = Path(self.tmp.name) / "a.exe"
        exe.write_bytes(b"MZ" + bytes(64))
        settings = {"root": str(Path(self.tmp.name) / "data")}
        first = targets.exe_sha256(settings, exe)
        real = targets.read_json
        with patch.object(targets, "read_json", side_effect=real) as reads:
            for _ in range(5):
                self.assertEqual(targets.exe_sha256(settings, exe), first)
        self.assertEqual(reads.call_count, 0)
        exe.write_bytes(b"MZ" + bytes([1]) * 80)   # a rebuilt binary is hashed again
        self.assertNotEqual(targets.exe_sha256(settings, exe), first)

    @unittest.skipUnless(os.name == "nt", "Windows process identity")
    def test_process_identity_loads_kernel32_once(self):
        import ctypes
        from hydralysis import proc, views
        started = views.process_started_ms()
        real = ctypes.WinDLL
        with patch.object(ctypes, "WinDLL", side_effect=real) as loads:
            for _ in range(5):
                self.assertTrue(proc.identity(os.getpid(), started))
            self.assertFalse(proc.identity(os.getpid(), started + 10_000))
        self.assertLessEqual(loads.call_count, 1)


class QueueRecords(unittest.TestCase):
    """`status show=queue` read and seal-checked every pending/done/declined record on each poll. They are written once, so a
    record whose file is unchanged is answered from the last read; a new file, a removed one or a .bak are still honoured."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        views._forget_records()
        self.addCleanup(views._forget_records)
        self.settings = {"root": str(Path(self.tmp.name) / "data")}
        self.lineage_id = "l-" + "0" * 16
        from hydralysis import lineage
        self.patch_dir = patch.object(lineage, "lineage_dir", lambda settings, lid: Path(self.tmp.name) / "lineages" / lid)
        self.patch_dir.start()
        self.addCleanup(self.patch_dir.stop)

    def counting(self):
        from hydralysis import durable
        return patch.object(durable, "read_sealed_info", side_effect=durable.read_sealed_info)

    def test_a_decided_changeset_is_read_from_disk_once(self):
        from hydralysis import durable
        csid = views.new_csid()
        path = views.done_path(self.settings, self.lineage_id, csid)
        path.parent.mkdir(parents=True)
        durable.write_sealed(path, {"csid": csid, "outcome": "applied", "generation": 3})
        with self.counting() as reads:
            for _ in range(20):
                found = views.read_done(self.settings, self.lineage_id, csid)
                self.assertEqual((found["outcome"], found["generation"]), ("applied", 3))
                found["outcome"] = "mutated by a caller"
        self.assertEqual(reads.call_count, 1)

    def test_an_undecided_changeset_reads_nothing(self):
        with self.counting() as reads:
            for _ in range(5):
                self.assertIsNone(views.read_done(self.settings, self.lineage_id, views.new_csid()))
        self.assertEqual(reads.call_count, 0)

    def test_a_replaced_record_and_a_backup_are_honoured(self):
        from hydralysis import durable
        csid = views.new_csid()
        path = views.declined_path(self.settings, self.lineage_id, csid)
        path.parent.mkdir(parents=True)
        durable.write_sealed(path, {"csid": csid, "outcome": "conflict"})
        self.assertEqual(views.read_done(self.settings, self.lineage_id, csid)["outcome"], "conflict")
        durable.write_sealed(path, {"csid": csid, "outcome": "skipped"})   # an atomic replace: a new file
        self.assertEqual(views.read_done(self.settings, self.lineage_id, csid)["outcome"], "skipped")
        os.replace(path, durable.backup_path(path))                         # only the .bak is left
        self.assertEqual(views.read_done(self.settings, self.lineage_id, csid)["outcome"], "skipped")
        durable.backup_path(path).unlink()
        self.assertIsNone(views.read_done(self.settings, self.lineage_id, csid))

    def test_a_large_pending_record_is_not_kept(self):
        from hydralysis import durable
        csid = views.new_csid()
        path = views.pending_path(self.settings, self.lineage_id, csid)
        path.parent.mkdir(parents=True)
        durable.write_sealed(path, {"csid": csid, "format": 1, "records": ["x" * 1024] * 1024})   # ~1 MB
        for _ in range(3):
            self.assertEqual(len(views.read_changeset(self.settings, self.lineage_id, csid)["records"]), 1024)
        self.assertEqual(len(views._RECORDS), 0)
        self.assertEqual(views._records_size, 0)

    def test_the_memo_is_bounded_in_bytes_least_recently_used_first(self):
        from hydralysis import durable
        folder = views.done_path(self.settings, self.lineage_id, views.new_csid()).parent
        folder.mkdir(parents=True)
        ids = []
        for n in range(40):
            csid = "c-%016x" % n
            durable.write_sealed(folder / (csid + ".json"), {"csid": csid, "outcome": "applied", "generation": n, "pad": "p" * 30000})
            ids.append(csid)
        with patch.object(views, "_RECORDS_BUDGET", 10 * 31000):
            for csid in ids:
                self.assertEqual(views.read_done(self.settings, self.lineage_id, csid)["csid"], csid)
                views.read_done(self.settings, self.lineage_id, ids[0])   # kept warm: the least recently used go first
            self.assertLessEqual(views._records_size, 10 * 31000)
            self.assertEqual(views._records_size, sum(len(text) for _, text in views._RECORDS.values()))
            kept = {key[0] for key in views._RECORDS}
            self.assertIn(os.path.normcase(str(folder / (ids[0] + ".json"))), kept)
            self.assertIn(os.path.normcase(str(folder / (ids[-1] + ".json"))), kept)
            self.assertNotIn(os.path.normcase(str(folder / (ids[1] + ".json"))), kept)

    def test_a_corrupt_changeset_is_still_refused(self):
        from hydralysis import durable
        csid = views.new_csid()
        path = views.pending_path(self.settings, self.lineage_id, csid)
        path.parent.mkdir(parents=True)
        durable.write_sealed(path, {"csid": csid, "format": 1, "records": []})
        self.assertEqual(views.read_changeset(self.settings, self.lineage_id, csid)["csid"], csid)
        path.write_bytes(b"{ not json")
        with self.assertRaises(durable.StoreCorrupt):
            views.read_changeset(self.settings, self.lineage_id, csid)


class ViewLease(unittest.TestCase):
    """A query of an agent's own view refreshed its lease record under the record lock on every call; with a fresh lease of
    this process the record is answered without the lock, and every other case still takes it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from hydralysis import lineage
        patcher = patch.object(lineage, "lineage_dir", lambda settings, lid: Path(self.tmp.name) / "lineages" / lid)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.settings = {"root": str(Path(self.tmp.name) / "data")}
        self.selected = {"key": "k" * 16, "name": "t", "lineage": {"id": "l-1", "generation": 0}}

    def locks_taken(self):
        return patch.object(views, "_record_lock", side_effect=views._record_lock)

    def test_a_fresh_own_lease_takes_no_lock(self):
        who = {"agent": "agent-a", "kind": "explicit", "name": "agent-a", "shared": False}
        first = views.claim(self.settings, self.selected, who, "l-1", 600)
        with self.locks_taken() as taken:
            for _ in range(10):
                self.assertEqual(views.claim(self.settings, self.selected, who, "l-1", 600, create=False), first)
        self.assertEqual(taken.call_count, 0)

    def test_an_old_lease_is_still_refreshed_under_the_lock(self):
        who = {"agent": "agent-b", "kind": "explicit", "name": "agent-b", "shared": False}
        first = views.claim(self.settings, self.selected, who, "l-1", 600)
        with self.locks_taken() as taken, patch.object(views.time, "time", return_value=time.time() + 120):
            again = views.claim(self.settings, self.selected, who, "l-1", 600)
        self.assertEqual(taken.call_count, 1)
        self.assertGreater(again["lease_until"], first["lease_until"])

    def test_another_process_default_view_is_still_refused(self):
        record = views.claim(self.settings, self.selected, {"agent": "agent-c", "kind": "default", "name": "agent-c",
                                                            "shared": False}, "l-1", 600)
        import subprocess
        import sys
        from hydralysis import preparation
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])   # a process certain to be alive
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        record["holders"] = {"other-boot": {"pid": other.pid, "pid_started_ms": preparation.process_start_ms(other.pid),
                                            "lease_until": time.time() + 600, "agent_name": "x"}}
        from hydralysis import durable
        durable.write_sealed(views.record_path(self.settings, "l-1", "agent-c"), record, max_bytes=65536)
        with self.assertRaises(views.ViewError):
            views.claim(self.settings, self.selected, {"agent": "agent-c", "kind": "explicit", "name": "agent-c", "shared": False},
                        "l-1", 600)


@unittest.skipUnless(os.name == "nt", "the queued wait is the Windows kernel lock queue")
class FollowerWait(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.lock_path = Path(self.tmp.name) / "publish.lock"

    def hold(self, seconds: float) -> threading.Thread:
        holder = locks.LaneLock(str(self.lock_path))
        self.assertTrue(holder.acquire())

        def later():
            time.sleep(seconds)
            holder.release()
        thread = threading.Thread(target=later)
        thread.start()
        self.addCleanup(thread.join)
        return thread

    def test_await_turn_returns_the_lock_soon_after_the_leader_lets_go(self):
        self.hold(0.4)
        with patch.object(views, "publish_lock_path", return_value=self.lock_path):
            started = time.monotonic()
            turn = views.await_turn({}, "l-1", 5.0)
            waited = time.monotonic() - started
        self.assertIsNotNone(turn)
        try:
            self.assertGreaterEqual(waited, 0.3)
            self.assertLess(waited, 2.0)
            self.assertTrue(locks.held(str(self.lock_path)), "the granted turn holds publish.lock")
        finally:
            turn.release()
        self.assertFalse(locks.held(str(self.lock_path)))

    def test_await_turn_gives_up_after_its_timeout(self):
        self.hold(1.5)
        with patch.object(views, "publish_lock_path", return_value=self.lock_path):
            started = time.monotonic()
            self.assertIsNone(views.await_turn({}, "l-1", 0.3))
            self.assertLess(time.monotonic() - started, 1.2)

    def test_a_waiting_follower_neither_polls_nor_rewrites_its_progress(self):
        """While a leader holds the lock for 1.5 s, the old loop looked at the queue ~15 times and wrote progress each time."""
        self.hold(1.5)
        looks, reports, drains = [], [], []
        decided = {"outcome": "applied", "generation": 1}

        def read_done(settings, lineage_id, csid):
            looks.append(time.monotonic())
            return decided if drains and drains[-1] == "led" else None

        def drain(settings, lineage_id, engine=None, stop_after=None, timeout_s=600, lock=None):
            if lock is None:
                probe = locks.LaneLock(str(self.lock_path))
                if not probe.acquire():
                    drains.append("busy")
                    return {"led": False, "built": [], "failure": None}
                lock = probe
            lock.release()
            drains.append("led")
            return {"led": True, "built": [1], "failure": None}

        info = {"state": "publish_pending", "csid": "c-1", "position": 2, "etaMs": None, "leader": True}
        with patch.object(views, "publish_lock_path", return_value=self.lock_path), \
                patch.object(views, "read_done", side_effect=read_done), patch.object(views, "drain", side_effect=drain), \
                patch.object(views, "pending_info", return_value=dict(info)), \
                patch.object(views, "_settle_own", return_value=True), patch.object(views, "_revision_of", return_value=1):
            result = views.run_publish_job({}, {"name": "t"}, {"csid": "c-1", "lineage": "l-1"}, engine=object(), timeout_s=60,
                                           progress=reports.append)
        self.assertEqual(result["outcome"], "applied")
        self.assertEqual(drains[-1], "led")
        self.assertLessEqual(drains.count("busy"), 3, drains)
        self.assertEqual(len(reports), 1, "progress is written when it changes, not on every look")
        self.assertFalse(locks.held(str(self.lock_path)))

    def wait_for(self, decide_after: float, hold_s: float, heartbeat_s: float | None = None):
        """A follower of a real lineage folder while a leader holds publish.lock for HOLD_S and writes the follower's result
        after DECIDE_AFTER (None: never). Returns (seconds the job took, progress reports)."""
        from hydralysis import lineage
        lineage_id = "l-" + "0" * 16
        with patch.object(lineage, "lineage_dir", lambda settings, lid: Path(self.tmp.name) / "lineages" / lid):
            settings = {"root": str(Path(self.tmp.name) / "data")}
            csid = views.new_csid()
            self.lock_path = views.publish_lock_path(settings, lineage_id)
            self.lock_path.parent.mkdir(parents=True)
            self.hold(hold_s)
            if decide_after is not None:
                timer = threading.Timer(decide_after, views.write_done, (settings, lineage_id, csid, {"outcome": "applied", "generation": 1}))
                timer.start()
                self.addCleanup(timer.join)
            reports = []
            busy = {"led": False, "built": [], "failure": None}
            info = {"state": "publish_pending", "csid": csid, "position": 2, "etaMs": None, "leader": True}
            options = dict(publish_wait_s=hold_s + 5)
            patches = [patch.object(views, "drain", return_value=busy), patch.object(views, "pending_info", return_value=dict(info)),
                       patch.object(views, "_settle_own", return_value=True), patch.object(views, "_revision_of", return_value=1)]
            if heartbeat_s is not None:
                patches += [patch.object(views, "PROGRESS_HEARTBEAT_S", heartbeat_s), patch.object(views, "TURN_WAIT_S", 0.1)]
            for item in patches:
                item.start()
                self.addCleanup(item.stop)
            started = time.monotonic()
            try:
                result = views.run_publish_job(dict(settings, **options), {"name": "t"}, {"csid": csid, "lineage": lineage_id},
                                               engine=object(), timeout_s=60, progress=reports.append)
            except views.ViewError as error:
                result = {"error": error.args[0]}
            return time.monotonic() - started, reports, result

    def test_a_follower_returns_as_soon_as_a_leader_decides_its_changeset(self):
        """The leader keeps the lock (it drains others); the follower must not wait for its next TURN_WAIT_S look."""
        took, _, result = self.wait_for(decide_after=0.3, hold_s=3.0)
        self.assertEqual(result["outcome"], "applied")
        self.assertLess(took, 0.3 + 0.35, "woken by the result, not by the 1 s look")

    def test_a_long_waiting_follower_still_refreshes_its_job_record(self):
        """`hydra.active_jobs` keeps the newest records by time: an unchanged wait still rewrites its record now and then."""
        took, reports, result = self.wait_for(decide_after=1.4, hold_s=1.6, heartbeat_s=0.3)
        self.assertEqual(result["outcome"], "applied")
        self.assertGreaterEqual(len(reports), 3, reports)
        self.assertLessEqual(len(reports), 8, "a heartbeat, not a rewrite on every look")


if __name__ == "__main__":
    unittest.main()
