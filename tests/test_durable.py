"""Durable IO (PROTOCOL-3.md 4.1, package Y0a): atomic writes, sealed JSON, the append log, the write gate."""

import ast
import hashlib
import json
import os
import subprocess
import sys
import threading
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from hydralysis import backends, durable, hydra, overlayjobs, runtime, runtime_worker, targets, workcopy
from support import workdir

SRC = Path(__file__).resolve().parent.parent / "src"
TARGET = {"key": "k" * 16, "sha256": "a" * 64, "name": "t", "view": "shared"}


def child_env(fault=None):
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    env.pop("HYDRALYSIS_TEST_FAULT", None)
    env.pop("HYDRALYSIS_TEST_MODE", None)
    if fault:
        env.update(HYDRALYSIS_TEST_MODE="1", HYDRALYSIS_TEST_FAULT=fault)
    return env


def run_child(code, *args, fault=None, timeout=120):
    return subprocess.run([sys.executable, "-c", code, *map(str, args)], env=child_env(fault), capture_output=True,
                          text=True, timeout=timeout)


class Base(unittest.TestCase):
    def setUp(self):
        self.work = workdir("durable")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        # the process-wide "log already verified" memory must not leak between tests
        durable._VERIFIED.clear()


class AtomicWrite(Base):
    def test_writes_replaces_and_leaves_no_temporary(self):
        path = self.root / "a" / "file.bin"
        durable.atomic_write(path, b"one")
        durable.atomic_write(path, b"two")
        self.assertEqual(path.read_bytes(), b"two")
        self.assertEqual([item.name for item in path.parent.iterdir()], ["file.bin"])

    def test_the_data_is_fsynced_before_the_replace(self):
        order = []
        real_fsync, real_replace = os.fsync, durable._replace_once
        with patch("hydralysis.durable.os.fsync", side_effect=lambda fd: (order.append("fsync"), real_fsync(fd))[1]), \
             patch("hydralysis.durable._replace_once", side_effect=lambda a, b: (order.append("replace"), real_replace(a, b))[1]):
            durable.atomic_write(self.root / "f", b"x")
        self.assertLess(order.index("fsync"), order.index("replace"))

    def test_permission_error_is_retried_through_a_monkeypatched_os_replace(self):
        path = self.root / "f"
        calls, sleeps = [], []

        def flaky(source, destination):
            calls.append(source)
            if len(calls) < 4:
                raise PermissionError(13, "Access is denied", str(destination))
            return real(source, destination)

        real = os.replace
        with patch.object(durable, "NATIVE_MOVE", False), patch("hydralysis.durable.os.replace", side_effect=flaky), \
             patch.object(durable, "_sleep", side_effect=sleeps.append):
            durable.atomic_write(path, b"data")
        self.assertEqual(path.read_bytes(), b"data")
        self.assertEqual(len(calls), 4)
        self.assertEqual(sleeps, [0.05, 0.1, 0.2])  # 50 ms doubling to 500 ms

    def test_native_move_is_retried_too_and_backoff_is_capped(self):
        path = self.root / "f"
        calls, sleeps = [], []

        def flaky(source, destination):
            calls.append(1)
            if len(calls) < 9:
                raise PermissionError(13, "Access is denied")
            os.replace(source, destination)

        with patch.object(durable, "NATIVE_MOVE", True), patch.object(durable, "_move_file_ex", side_effect=flaky), \
             patch.object(durable, "_sleep", side_effect=sleeps.append):
            durable.atomic_write(path, b"data")
        self.assertEqual(sleeps, [0.05, 0.1, 0.2, 0.4, 0.5, 0.5, 0.5, 0.5])

    def test_a_replace_that_stays_denied_raises_after_the_budget_and_leaves_the_old_file(self):
        path = self.root / "f"
        durable.atomic_write(path, b"old")
        slept = []
        with patch.object(durable, "NATIVE_MOVE", False), \
             patch("hydralysis.durable.os.replace", side_effect=PermissionError(13, "denied")), \
             patch.object(durable, "_sleep", side_effect=slept.append):
            with self.assertRaises(PermissionError):
                durable.atomic_write(path, b"new")
        self.assertLessEqual(sum(slept), durable.RETRY_TOTAL_S)
        self.assertGreater(sum(slept), durable.RETRY_TOTAL_S - 1)
        self.assertEqual(path.read_bytes(), b"old")
        self.assertEqual([item.name for item in self.root.iterdir()], ["f"])  # the temporary is removed

    def test_other_errors_are_not_retried(self):
        sleeps = []
        with patch.object(durable, "NATIVE_MOVE", False), patch("hydralysis.durable.os.replace", side_effect=OSError(5, "io")), \
             patch.object(durable, "_sleep", side_effect=sleeps.append):
            with self.assertRaises(OSError):
                durable.atomic_write(self.root / "f", b"x")
        self.assertEqual(sleeps, [])

    @unittest.skipUnless(os.name == "nt", "MoveFileExW is Windows only")
    def test_the_native_move_really_replaces_an_existing_file(self):
        path = self.root / "f"
        path.write_bytes(b"old")
        with patch.object(durable, "NATIVE_MOVE", True):
            durable.atomic_write(path, b"new")
        self.assertEqual(path.read_bytes(), b"new")

    def test_killing_the_writer_between_the_temporary_and_the_replace_keeps_the_old_content(self):
        path = self.root / "f.json"
        durable.write_sealed(path, {"v": 1})
        code = "import sys; from hydralysis import durable; durable.write_sealed(sys.argv[1], {'v': 2})"
        result = run_child(code, path, fault="atomic.before_replace:exit")
        self.assertEqual(result.returncode, 137, result.stderr)
        self.assertEqual(durable.read_sealed(path), {"v": 1})
        self.assertTrue(any(item.name.endswith(".tmp") for item in self.root.iterdir()))  # the orphan stays visible
        durable.write_sealed(path, {"v": 3})
        self.assertEqual(durable.read_sealed(path), {"v": 3})

    def test_killing_the_writer_after_the_replace_leaves_the_new_content(self):
        path = self.root / "f.json"
        durable.write_sealed(path, {"v": 1})
        result = run_child("import sys; from hydralysis import durable; durable.write_sealed(sys.argv[1], {'v': 2})", path,
                           fault="atomic.after_replace:exit")
        self.assertEqual(result.returncode, 137, result.stderr)
        self.assertEqual(durable.read_sealed(path), {"v": 2})
        self.assertEqual(durable.read_sealed(durable.backup_path(path)), {"v": 1})

    def test_a_non_atomic_writer_killed_midway_is_detected_and_the_previous_version_is_returned(self):
        path = self.root / "f.json"
        durable.write_sealed(path, {"v": 1, "pad": "x" * 200})
        result = run_child("import sys; from hydralysis import durable; durable.write_sealed(sys.argv[1], {'v': 2})", path,
                           fault="atomic.torn:torn:20")
        self.assertEqual(result.returncode, 137, result.stderr)
        self.assertEqual(path.stat().st_size, 20)
        value, source = durable.read_sealed_info(path)
        self.assertEqual((value["v"], source), (1, "backup"))

    def test_the_hook_is_inert_without_test_mode(self):
        env = dict(child_env(), HYDRALYSIS_TEST_FAULT="atomic.before_replace:exit")  # no HYDRALYSIS_TEST_MODE
        result = subprocess.run([sys.executable, "-c", "import sys; from hydralysis import durable; "
                                 "durable.atomic_write(sys.argv[1], b'ok')", str(self.root / "f")],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "f").read_bytes(), b"ok")
        with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "x:raise"}):
            self.assertIsNone(durable.fault("y"))
            with self.assertRaises(durable.FaultInjected):
                durable.fault("x")
        with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "x:torn:7"}):
            self.assertEqual(durable.fault("x"), 7)
        with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "x:bogus"}):
            with self.assertRaises(ValueError):
                durable.fault("x")


class SealedJson(Base):
    def write_two(self):
        path = self.root / "r.json"
        durable.write_sealed(path, {"gen": 1, "text": "café", "n": 1.5})
        durable.write_sealed(path, {"gen": 2, "text": "café", "n": 1.5})
        return path

    def test_round_trip_seals_a_canonical_body_and_keeps_the_previous_version(self):
        path = self.write_two()
        raw = json.loads(path.read_text(encoding="utf-8"))
        body = {key: value for key, value in raw.items() if key != "seal"}
        self.assertEqual(raw["seal"], {"algo": "sha256", "value": hashlib.sha256(
            json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()})
        self.assertEqual(durable.read_sealed(path), {"gen": 2, "text": "café", "n": 1.5})
        self.assertEqual(durable.read_sealed(durable.backup_path(path))["gen"], 1)

    def test_zero_length_returns_the_previous_version_not_empty(self):
        path = self.write_two()
        path.write_bytes(b"")
        value, source = durable.read_sealed_info(path)
        self.assertEqual((value["gen"], source), (1, "backup"))

    def test_a_torn_file_at_every_cut_returns_the_old_content_never_empty(self):
        path = self.write_two()
        good = path.read_bytes()
        for cut in range(0, len(good)):  # includes the cut that drops only the final "}"
            with self.subTest(cut=cut):
                path.write_bytes(good[:cut])
                value, source = durable.read_sealed_info(path)
                self.assertEqual((value["gen"], source), (1, "backup"))
        path.write_bytes(good)
        self.assertEqual(durable.read_sealed_info(path)[1], "file")

    def test_an_unpaired_surrogate_is_refused_not_sealed(self):
        # PROTOCOL-3.md 3.4: an unpaired surrogate is refused (no 'surrogatepass').
        for value in ({"a": "\ud800"}, {"a": ["x", "\udc00"]}, {"\udfff": 1}):
            with self.subTest(value=ascii(value)):
                with self.assertRaisesRegex(ValueError, "unpaired surrogate"):
                    durable.canonical(value)
                path = self.root / ("s%d.json" % abs(hash(ascii(value))))
                with self.assertRaisesRegex(ValueError, "unpaired surrogate"):
                    durable.write_sealed(path, value)
                self.assertFalse(path.exists())
        # a real astral character is one code point and is fine
        self.assertEqual(durable.canonical({"a": "\U0001F600"}), '{"a":"\U0001F600"}'.encode("utf-8"))
        # a stored record whose body holds an escaped lone surrogate cannot be verified: it is invalid, not sealed
        path = self.root / "lone.json"
        path.write_text('{"a": "\\ud800", "seal": {"algo": "sha256", "value": "' + "0" * 64 + '"}}', encoding="utf-8")
        self.assertEqual(durable.inspect_file(path)[0::2], ("invalid", "body cannot be canonicalised"))

    def test_a_mis_sealed_file_is_rejected(self):
        path = self.write_two()
        record = json.loads(path.read_text(encoding="utf-8"))
        record["gen"] = 99  # parses, but the seal no longer matches
        path.write_text(json.dumps(record), encoding="utf-8")
        self.assertEqual(durable.inspect_file(path)[2], "mis-sealed (content does not match its seal)")
        value, source = durable.read_sealed_info(path)
        self.assertEqual((value["gen"], source), (1, "backup"))

    def test_a_missing_file_with_a_backup_returns_the_backup(self):
        path = self.write_two()
        path.unlink()
        self.assertTrue(durable.exists(path))
        self.assertEqual(durable.read_sealed_info(path), ({"gen": 1, "text": "café", "n": 1.5}, "backup"))

    def test_no_valid_version_raises_store_corrupt_naming_both_paths(self):
        path = self.write_two()
        path.write_bytes(path.read_bytes()[:30])
        durable.backup_path(path).write_bytes(b"")
        with self.assertRaises(durable.StoreCorrupt) as raised:
            durable.read_sealed(path)
        error = raised.exception
        self.assertEqual(error.code, "store_corrupt")
        self.assertIsInstance(error, ValueError)
        self.assertIn(str(path), str(error))
        self.assertIn(str(durable.backup_path(path)), str(error))
        self.assertIn("zero-length", str(error))

    def test_a_torn_file_with_no_backup_raises_store_corrupt(self):
        path = self.root / "r.json"
        path.write_bytes(b'{"gen": 1, "se')
        with self.assertRaises(durable.StoreCorrupt):
            durable.read_sealed(path)
        path.write_bytes(b"")
        with self.assertRaises(durable.StoreCorrupt):
            durable.read_sealed(path)

    def test_a_file_that_was_never_written_is_not_corruption(self):
        path = self.root / "never.json"
        self.assertFalse(durable.exists(path))
        self.assertEqual(durable.read_sealed(path, default={"fresh": True}), {"fresh": True})
        with self.assertRaises(FileNotFoundError):
            durable.read_sealed(path)

    def test_a_pre_seal_record_loads_and_becomes_the_backup_of_the_first_sealed_write(self):
        path = self.root / "legacy.json"
        path.write_text(json.dumps({"version": 2, "edits": []}, indent=2), encoding="utf-8")
        self.assertEqual(durable.inspect_file(path)[0], "unsealed")
        self.assertEqual(durable.read_sealed(path), {"version": 2, "edits": []})
        with self.assertRaises(durable.StoreCorrupt):
            durable.read_sealed(path, require_seal=True)
        durable.write_sealed(path, {"version": 2, "edits": [1]})
        self.assertEqual(durable.read_sealed(durable.backup_path(path)), {"version": 2, "edits": []})

    def test_a_bad_file_never_replaces_the_good_backup_and_is_preserved_aside(self):
        path = self.write_two()
        path.write_bytes(path.read_bytes()[:40])
        durable.write_sealed(path, {"gen": 3})
        self.assertEqual(durable.read_sealed(path), {"gen": 3})
        self.assertEqual(durable.read_sealed(durable.backup_path(path))["gen"], 1)  # not the torn file
        aside = [item for item in self.root.iterdir() if ".corrupt-" in item.name]
        self.assertEqual(len(aside), 1)
        self.assertEqual(aside[0].stat().st_size, 40)

    def test_oversize_and_reserved_keys_are_refused_before_anything_is_written(self):
        path = self.root / "r.json"
        with self.assertRaises(ValueError):
            durable.write_sealed(path, {"seal": 1})
        with self.assertRaisesRegex(ValueError, "custom"):
            durable.write_sealed(path, {"a": "x" * 100}, max_bytes=50, too_large="custom message")
        self.assertFalse(path.exists())

    def test_update_sealed_loses_no_update_across_processes(self):
        path = self.root / "counter.json"
        code = ("import sys\nfrom hydralysis import durable\n"
                "for _ in range(12):\n"
                "    durable.update_sealed(sys.argv[1], lambda v: {**v, 'n': v.get('n', 0) + 1})\n")
        children = [subprocess.Popen([sys.executable, "-c", code, str(path)], env=child_env(), stderr=subprocess.PIPE,
                                     text=True) for _ in range(5)]
        for child in children:
            _, error = child.communicate(timeout=180)
            self.assertEqual(child.returncode, 0, error)
        self.assertEqual(durable.read_sealed(path)["n"], 60)


class StoreIntegration(Base):
    def setUp(self):
        super().setUp()
        self.settings = {"root": str(self.root)}
        self.path = workcopy._store_path(self.settings, TARGET)

    def store(self, revision=1):
        edit = {"id": "e" * 32, "address": "0x401000", "options": {"kind": "rename", "name": "Foo", "source": "test"}}
        return {"version": 2, "sha256": TARGET["sha256"], "revision": revision,
                "edits": [{**edit, "by": {"client": "c"}, "at": 1.0}], "reverted": [], "journal": []}

    def test_never_written_store_is_the_empty_one(self):
        self.assertEqual(workcopy.load_store(self.settings, TARGET)["edits"], [])

    def test_save_then_load_round_trips_and_seals(self):
        workcopy._save_store(self.settings, TARGET, self.store())
        self.assertIn("seal", json.loads(self.path.read_text(encoding="utf-8")))
        loaded = workcopy.load_store(self.settings, TARGET)
        self.assertEqual((loaded["revision"], len(loaded["edits"]), "seal" in loaded), (1, 1, False))

    def test_a_v2_store_written_before_seals_loads_unchanged(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps(self.store(7), indent=2), encoding="utf-8")
        loaded = workcopy.load_store(self.settings, TARGET)
        self.assertEqual((loaded["version"], loaded["revision"], loaded["edits"][0]["address"]), (2, 7, "0x401000"))
        workcopy._save_store(self.settings, TARGET, {**loaded, "revision": 8})
        self.assertEqual(workcopy.load_store(self.settings, TARGET)["revision"], 8)
        self.assertEqual(json.loads(durable.backup_path(self.path).read_text(encoding="utf-8"))["revision"], 7)

    def test_torn_zero_length_and_mis_sealed_stores_return_the_previous_edits_never_none(self):
        workcopy._save_store(self.settings, TARGET, self.store(1))
        workcopy._save_store(self.settings, TARGET, self.store(2))
        good = self.path.read_bytes()
        broken = {"torn": good[:len(good) // 2], "zero": b"",
                  "mis-sealed": good.replace(b'"revision": 2', b'"revision": 3')}
        for name, data in broken.items():
            with self.subTest(name):
                self.path.write_bytes(data)
                loaded = workcopy.load_store(self.settings, TARGET)
                self.assertEqual((loaded["revision"], len(loaded["edits"])), (1, 1))

    def test_a_missing_store_with_a_backup_returns_the_backup(self):
        workcopy._save_store(self.settings, TARGET, self.store(1))
        workcopy._save_store(self.settings, TARGET, self.store(2))
        self.path.unlink()
        self.assertEqual(workcopy.load_store(self.settings, TARGET)["revision"], 1)

    def test_no_valid_version_is_store_corrupt_not_start_empty(self):
        workcopy._save_store(self.settings, TARGET, self.store(1))
        self.path.write_bytes(b"")
        with self.assertRaises(durable.StoreCorrupt):
            workcopy.load_store(self.settings, TARGET)
        self.path.write_bytes(b'{"version": 2, "sha256": "aaa')
        with self.assertRaises(durable.StoreCorrupt):
            workcopy.load_store(self.settings, TARGET)
        self.assertEqual(self.path.read_bytes(), b'{"version": 2, "sha256": "aaa')  # untouched, preserved

    def test_a_store_of_another_build_is_refused_not_replaced_by_the_backup(self):
        workcopy._save_store(self.settings, TARGET, self.store(1))
        with self.assertRaisesRegex(ValueError, "another build or format"):
            workcopy.load_store(self.settings, {**TARGET, "sha256": "b" * 64})

    def test_the_history_limit_message_is_kept(self):
        with patch.object(workcopy, "MAX_HISTORY_BYTES", 50):
            with self.assertRaisesRegex(ValueError, "would exceed 20 MiB"):
                workcopy._save_store(self.settings, TARGET, self.store())
        self.assertFalse(self.path.exists())


class RecordFiles(Base):
    """write_json (targets.register, working/state.json, job records) goes through durable."""

    def test_write_json_seals_and_read_json_unseals_with_the_same_dict(self):
        path = self.root / "x" / "state.json"
        backends.write_json(path, {"state": "ok", "n": [1, 2]})
        self.assertIn("seal", json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual(backends.read_json(path), {"state": "ok", "n": [1, 2]})
        self.assertEqual(backends.read_json(self.root / "none.json"), {})

    def test_read_json_falls_back_and_raises_store_corrupt(self):
        path = self.root / "state.json"
        backends.write_json(path, {"v": 1})
        backends.write_json(path, {"v": 2})
        path.write_bytes(b"")
        self.assertEqual(backends.read_json(path), {"v": 1})
        durable.backup_path(path).unlink()
        with self.assertRaises(durable.StoreCorrupt):
            backends.read_json(path)

    def test_target_registry_and_job_records_are_sealed_and_survive_a_torn_file(self):
        settings = {"root": str(self.root)}
        targets.register(settings, ["one"], {"sha256": "c" * 64, "gpr": "x.gpr"})
        targets.register(settings, ["two"], {"sha256": "d" * 64, "gpr": "y.gpr"})
        registry = targets.registry_path(settings)
        self.assertIn("seal", json.loads(registry.read_text(encoding="utf-8")))
        registry.write_bytes(registry.read_bytes()[:25])
        self.assertEqual(sorted(targets.registry(settings)), ["one"])  # the previous generation, not "no targets"
        job = overlayjobs.job_path(settings, "overlay-" + "0" * 12)
        backends.write_json(job, {"id": "x", "state": "queued", "created_at": 1})
        overlayjobs._update(job, state="running")
        self.assertEqual(backends.read_json(job)["state"], "running")
        self.assertIn("seal", json.loads(job.read_text(encoding="utf-8")))

    def test_a_hand_edited_sealed_record_is_detected(self):
        path = self.root / "map.json"
        backends.write_json(path, {"entries": [1]})
        record = json.loads(path.read_text(encoding="utf-8"))
        record["entries"] = [2]
        path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(durable.StoreCorrupt):
            backends.read_json(path)


class DaemonConfig(Base):
    """hydra.write_daemon_config: durable (fsync, write-through replace) but unsealed (PROTOCOL-3.md 8.2)."""

    def setUp(self):
        super().setUp()
        self.settings = {"root": str(self.root / "data")}

    def path(self):
        return hydra.state_dir(self.settings) / "config.json"

    def test_it_is_the_plain_json_the_launcher_reads_with_no_seal_no_backup_and_no_temporary(self):
        path = hydra.write_daemon_config(self.settings)
        self.assertEqual(path, self.path())
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), hydra.daemon_config(self.settings))
        self.assertNotIn("seal", json.loads(path.read_text(encoding="utf-8")))
        hydra.write_daemon_config({**self.settings, "hydra_idle_s": 99})  # a second, different version
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["idleTimeout"], 99)
        self.assertEqual(sorted(item.name for item in path.parent.iterdir()), ["config.json"])

    def test_it_writes_through_durable_atomic_write_and_only_when_the_content_changed(self):
        with patch.object(hydra.durable, "atomic_write", wraps=durable.atomic_write) as write:
            hydra.write_daemon_config(self.settings)
            hydra.write_daemon_config(self.settings)
            self.assertEqual(write.call_count, 1)
            hydra.write_daemon_config({**self.settings, "hydra_keep_warm_s": 5})
            self.assertEqual(write.call_count, 2)
        self.assertEqual(write.call_args.args[0], self.path())
        self.assertIsInstance(write.call_args.args[1], bytes)

    def test_a_writer_killed_before_the_replace_leaves_the_previous_config_whole(self):
        hydra.write_daemon_config(self.settings)
        before = self.path().read_bytes()
        code = ("import sys, json\nfrom hydralysis import hydra\n"
                "hydra.write_daemon_config({**json.loads(sys.argv[1]), 'hydra_idle_s': 1234})\n")
        result = run_child(code, json.dumps(self.settings), fault="atomic.before_replace:exit")
        self.assertEqual(result.returncode, 137, result.stderr)
        self.assertEqual(self.path().read_bytes(), before)
        self.assertEqual(json.loads(before.decode("utf-8")), hydra.daemon_config(self.settings))

    def test_a_torn_config_is_rewritten_not_trusted(self):
        hydra.write_daemon_config(self.settings)
        self.path().write_bytes(b'{"scriptPath": [')
        hydra.write_daemon_config(self.settings)
        self.assertEqual(json.loads(self.path().read_text(encoding="utf-8")), hydra.daemon_config(self.settings))


class RuntimeMailbox(Base):
    """runtime._write and runtime_worker._write are sealed; their readers unseal, fall back and never read empty."""

    def pairs(self):
        return (("runtime", runtime._write, runtime._json), ("runtime_worker", runtime_worker._write, runtime_worker._read))

    def test_a_record_is_sealed_on_disk_and_reads_back_without_its_seal(self):
        for name, write, read in self.pairs():
            with self.subTest(module=name):
                path = self.root / name / "ready.json"
                path.parent.mkdir()
                record = {"pid": 7, "started_ms": 9, "ok": True, "ipc": {"token": "t"}, "text": "café"}
                write(path, record)
                on_disk = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(on_disk["seal"], durable.seal_of(record))
                self.assertEqual(read(path), record)
                rewritten = read(path)  # the read-modify-write of runtime.py (group_id) must not trip over the seal
                rewritten["group_id"] = 1
                write(path, rewritten)
                self.assertEqual(read(path), {**record, "group_id": 1})
                self.assertEqual(sorted(item.name for item in path.parent.iterdir()), ["ready.json", "ready.json.bak"])

    def test_a_record_that_was_never_written_is_empty_and_a_pre_seal_record_loads_as_it_is(self):
        for name, write, read in self.pairs():
            with self.subTest(module=name):
                path = self.root / name
                path.mkdir()
                self.assertEqual(read(path / "none.json"), {})
                (path / "old.json").write_text(json.dumps({"detached": True, "pid": 4242}), encoding="utf-8")
                self.assertEqual(read(path / "old.json"), {"detached": True, "pid": 4242})
                write(path / "old.json", {"detached": True, "pid": 4243})  # the pre-seal file becomes the .bak
                self.assertEqual(read(durable.backup_path(path / "old.json")), {"detached": True, "pid": 4242})

    def test_a_torn_or_mis_sealed_file_falls_back_to_the_previous_version_and_never_reads_empty(self):
        for name, write, read in self.pairs():
            with self.subTest(module=name):
                path = self.root / name / "state.json"
                path.parent.mkdir()
                write(path, {"v": 1})
                write(path, {"v": 2})
                path.write_bytes(path.read_bytes()[:12])  # torn
                self.assertEqual(read(path), {"v": 1})
                other = self.root / name / "other.json"
                write(other, {"v": 1})
                write(other, {"v": 2})
                tampered = json.loads(other.read_text(encoding="utf-8"))
                tampered["v"] = 4
                other.write_text(json.dumps(tampered), encoding="utf-8")  # mis-sealed
                self.assertEqual(read(other), {"v": 1})
                path.write_bytes(b"")
                durable.backup_path(path).write_bytes(b"[1]")
                with self.assertRaises(durable.StoreCorrupt) as raised:
                    read(path)
                self.assertIn("state.json.bak", str(raised.exception))

    def test_the_mailbox_error_contract_of_the_readers_is_unchanged(self):
        error = PermissionError(13, "denied")
        error.winerror = 5
        for name, module in (("runtime", runtime), ("runtime_worker", runtime_worker)):
            with self.subTest(module=name), patch.object(module, "local_read_text", side_effect=error), \
                    self.assertRaisesRegex(RuntimeError, "errno=13 winerror=5"):
                (module._json if name == "runtime" else module._read)(self.root / "response.json")

    def test_releasing_the_executable_lock_removes_the_record_and_its_previous_version(self):
        runner = runtime.RuntimeRunner({"root": str(self.root / "sessions")})
        exe = self.root / "game.exe"
        first, second = "a" * 32, "b" * 32
        (runner.root / first).mkdir(parents=True)
        runtime._write(runner.root / first / "ready.json", {"pid": 0, "started_ms": 0})  # no longer "starting"
        with patch.object(runtime.RuntimeRunner, "_live", return_value=False):
            runner._claim(exe, first)
            runner._claim(exe, second)  # the first session's worker is gone: the lock is taken over, the old record is the .bak
        path = runner._lock_path(exe)
        self.assertEqual((runtime._json(path)["session"], runtime._json(durable.backup_path(path))["session"]), (second, first))
        runner._release(str(exe), second)
        self.assertEqual((path.exists(), durable.backup_path(path).exists()), (False, False))
        self.assertEqual(runtime._json(path), {})  # a released lock is not resurrected from the .bak

    def test_a_writer_killed_before_the_replace_leaves_the_previous_record_whole(self):
        path = self.root / "ready.json"
        runtime._write(path, {"v": 1})
        code = ("import sys\nfrom pathlib import Path\nfrom hydralysis import runtime_worker\n"
                "runtime_worker._write(Path(sys.argv[1]), {'v': 2})\n")
        result = run_child(code, path, fault="atomic.before_replace:exit")
        self.assertEqual(result.returncode, 137, result.stderr)
        self.assertEqual(runtime._json(path), {"v": 1})


def line_of(record):
    return durable.frame(record)


class AppendLogTests(Base):
    def log(self, **options):
        return durable.AppendLog(self.root / "CURRENT.log", lock_path=self.root / ".commit.lock", by="test", **options)

    def test_the_line_format_is_crc_hex8_space_json_lf_with_zlib_crc32(self):
        body = b'{"a":1}'
        self.assertEqual(durable.frame({"a": 1}), b"%08x " % (zlib.crc32(body) & 0xFFFFFFFF) + body + b"\n")
        self.assertEqual(durable.frame({"a": 1})[:8], b"%08x" % zlib.crc32(body))
        log = self.log()
        log.append({"a": 1})
        log.append({"b": "café  "})
        self.assertEqual(log.read(), [{"a": 1}, {"b": "café  "}])
        self.assertEqual(log.status()["torn_tail"], None)
        self.assertTrue(all(byte < 128 for byte in log.path.read_bytes()))

    def test_a_cut_at_every_offset_of_the_last_line_is_read_then_repaired_then_clean(self):
        first = [{"n": 1}, {"n": 2}]
        last = {"n": 3, "pad": "x" * 30}
        prefix = b"".join(line_of(record) for record in first)
        final = line_of(last)
        for cut in range(0, len(final) + 1):
            with self.subTest(cut=cut):
                durable._VERIFIED.clear()
                folder = self.root / ("cut%d" % cut)
                folder.mkdir()
                log = durable.AppendLog(folder / "CURRENT.log", lock_path=folder / ".commit.lock", by="test")
                log.path.write_bytes(prefix + final[:cut])
                complete = cut == len(final)
                read = log.read()  # no error, no write
                self.assertEqual(read, first + ([last] if complete else []))
                status = log.status()
                expected_tail = None if cut in (0, len(final)) else {"offset": len(prefix), "bytes": cut}
                self.assertEqual(status["torn_tail"], expected_tail)
                self.assertEqual(log.path.read_bytes(), prefix + final[:cut])  # a reader never repairs
                log.append({"n": 4})
                expected = first + ([last] if complete else []) + [{"n": 4}]
                self.assertEqual(log.read(), expected)
                self.assertIsNone(log.status()["torn_tail"])
                self.assertIsNone(log.status()["corrupt"])
                copies = sorted(item.name for item in folder.iterdir() if ".torn-" in item.name)
                repairs = log.repairs()
                if expected_tail:
                    fragment = final[:cut]
                    name = "CURRENT.log.torn-%d-%s" % (len(prefix), hashlib.sha256(fragment).hexdigest()[:8])
                    self.assertEqual(copies, [name])
                    self.assertEqual((folder / name).read_bytes(), fragment)
                    self.assertEqual(len(repairs), 1)
                    self.assertEqual({key: repairs[0][key] for key in ("offset", "bytes", "sha256", "by")},
                                     {"offset": len(prefix), "bytes": cut, "sha256": hashlib.sha256(fragment).hexdigest(),
                                      "by": "test"})
                    self.assertIn("at", repairs[0])
                else:
                    self.assertEqual((copies, repairs), ([], []))

    def test_a_fragment_without_lf_is_never_valid_even_when_its_crc_matches(self):
        log = self.log()
        log.append({"n": 1})
        whole = line_of({"n": 2})
        log.path.write_bytes(log.path.read_bytes() + whole[:-1])  # a full line minus its LF
        self.assertEqual(log.read(), [{"n": 1}])
        self.assertEqual(log.status()["torn_tail"]["bytes"], len(whole) - 1)
        log.append({"n": 3})
        self.assertEqual(log.read(), [{"n": 1}, {"n": 3}])

    def test_several_invalid_lines_at_the_end_are_one_torn_tail(self):
        log = self.log()
        log.append({"n": 1})
        size = log.path.stat().st_size
        log.path.write_bytes(log.path.read_bytes() + b"garbage line\n" + b"00000000 {}\n" + b"frag")
        self.assertEqual(log.read(), [{"n": 1}])
        self.assertEqual(log.status()["torn_tail"], {"offset": size, "bytes": len(b"garbage line\n00000000 {}\nfrag")})
        log.append({"n": 2})
        self.assertEqual(log.read(), [{"n": 1}, {"n": 2}])

    def corrupt_middle(self):
        log = self.log()
        for number in range(3):
            log.append({"n": number})
        data = bytearray(log.path.read_bytes())
        lines = bytes(data).split(b"\n")
        offset = len(lines[0]) + 1 + 12  # inside the second line's JSON
        data[offset] ^= 0x01
        log.path.write_bytes(bytes(data))
        return log, bytes(data), len(lines[0]) + 1

    def test_mid_log_corruption_is_refused_by_the_reader_and_by_the_writer(self):
        log, data, offset = self.corrupt_middle()
        with self.assertRaises(durable.LineageCorrupt) as raised:
            log.read()
        self.assertEqual((raised.exception.code, raised.exception.offset, raised.exception.records), ("lineage_corrupt", offset, [{"n": 0}]))
        self.assertEqual(log.status()["corrupt"]["offset"], offset)
        self.assertIsNone(log.status()["torn_tail"])
        durable._VERIFIED.clear()
        with self.assertRaises(durable.LineageCorrupt):
            log.append({"n": 9})
        self.assertEqual(log.path.read_bytes(), data)  # nothing appended, nothing repaired
        self.assertEqual([item.name for item in self.root.iterdir() if ".torn-" in item.name or item.name.endswith(".repairs")], [])
        with self.assertRaises(durable.LineageCorrupt):  # and again: the refusal is not a one-off
            log.append({"n": 9})

    def test_an_unknown_crc_prefix_or_bad_json_after_a_valid_crc_is_invalid(self):
        for line in (b"ABCDEF01 {}", b"1234 {}", b"zzzzzzzz {}", b"00000000{}", b"%08x not json" % (zlib.crc32(b"not json"))):
            self.assertIsNone(durable._parse(line), line)

    def test_a_crash_inside_the_repair_heals_on_the_next_append(self):
        for fault_name in ("log.repair.after_copy", "log.repair.after_truncate"):
            with self.subTest(fault=fault_name):
                durable._VERIFIED.clear()
                folder = self.root / fault_name
                folder.mkdir()
                path = folder / "CURRENT.log"
                path.write_bytes(line_of({"n": 1}) + line_of({"n": 2})[:9])
                code = ("import sys\nfrom hydralysis import durable\n"
                        "durable.AppendLog(sys.argv[1], by='crashing').append({'n': 3})\n")
                result = run_child(code, path, fault=fault_name + ":exit")
                self.assertEqual(result.returncode, 137, result.stderr)
                log = durable.AppendLog(path, by="healer")
                self.assertEqual(log.read(), [{"n": 1}])
                log.append({"n": 4})
                self.assertEqual(log.read(), [{"n": 1}, {"n": 4}])
                self.assertIsNone(log.status()["torn_tail"])
                self.assertEqual(len([item for item in folder.iterdir() if ".torn-" in item.name]), 1)

    def test_a_writer_killed_in_the_middle_of_an_append_is_followed_by_a_normal_successful_append(self):
        path = self.root / "CURRENT.log"
        durable.AppendLog(path).append({"n": 1})
        full = len(line_of({"n": 2}))
        for cut in (1, 8, 9, full - 1):
            with self.subTest(cut=cut):
                code = "import sys\nfrom hydralysis import durable\ndurable.AppendLog(sys.argv[1]).append({'n': 2})\n"
                result = run_child(code, path, fault="log.torn_append:torn:%d" % cut)
                self.assertEqual(result.returncode, 137, result.stderr)
                self.assertEqual(path.read_bytes()[-cut:], line_of({"n": 2})[:cut])
                self.assertEqual(durable.AppendLog(path).read(), [{"n": 1}])
                durable._VERIFIED.clear()
                durable.AppendLog(path).append({"n": 2})
                self.assertEqual(durable.AppendLog(path).read(), [{"n": 1}, {"n": 2}])
                path.write_bytes(line_of({"n": 1}))

    def test_a_failed_append_forces_a_check_before_the_next_one(self):
        log = self.log()
        log.append({"n": 1})
        with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "log.after_append:raise"}):
            with self.assertRaises(durable.FaultInjected):
                log.append({"n": 2})
        self.assertNotIn(log._key, durable._VERIFIED)
        log.path.write_bytes(log.path.read_bytes() + b"1234")  # a foreign fragment, as another process might leave
        log.append({"n": 3})
        self.assertEqual(log.read(), [{"n": 1}, {"n": 2}, {"n": 3}])

    def test_a_fragment_left_by_another_process_after_this_one_verified_is_still_repaired(self):
        log = self.log()
        log.append({"n": 1})
        self.assertIn(log._key, durable._VERIFIED)
        log.path.write_bytes(log.path.read_bytes() + line_of({"n": 2})[:5])
        log.append({"n": 3})
        self.assertEqual(log.read(), [{"n": 1}, {"n": 3}])

    def scans(self):
        """Patch durable.scan_file so a test can see which scans the writer made: a list of start offsets."""
        started, real = [], durable.scan_file

        def spy(path, start=0, collect=True):
            started.append(start)
            return real(path, start, collect)

        patcher = patch("hydralysis.durable.scan_file", side_effect=spy)
        patcher.start()
        self.addCleanup(patcher.stop)
        return started

    def test_a_foreign_garbage_line_that_ends_in_lf_is_also_repaired_on_the_next_acquisition(self):
        log = self.log()
        log.append({"n": 1})
        size = log.path.stat().st_size
        log.path.write_bytes(log.path.read_bytes() + b"not a framed line\n")  # ends in LF, but invalid
        log.append({"n": 2})
        self.assertEqual(log.read(), [{"n": 1}, {"n": 2}])
        self.assertEqual([(row["offset"], row["bytes"]) for row in log.repairs()], [(size, len(b"not a framed line\n"))])

    def test_the_cheap_check_scans_nothing_when_the_log_is_as_this_process_left_it(self):
        log = self.log()
        log.append({"n": 1})
        started = self.scans()
        log.append({"n": 2})
        log.append({"n": 3})
        self.assertEqual(started, [])  # size equals the last known valid end and the file ends in LF
        # a valid line appended by another process: only the new bytes are scanned, from the known end
        known = durable._VERIFIED[log._key]
        code = ("import sys\nfrom hydralysis import durable\n"
                "durable.AppendLog(sys.argv[1], lock_path=sys.argv[2]).append({'n': 4})\n")
        result = run_child(code, log.path, log.lock_path)
        self.assertEqual(result.returncode, 0, result.stderr)
        log.append({"n": 5})
        self.assertEqual(started, [known])
        self.assertEqual(log.read(), [{"n": 1}, {"n": 2}, {"n": 3}, {"n": 4}, {"n": 5}])
        self.assertEqual(log.repairs(), [])

    def test_a_log_larger_than_the_32_mib_localio_budget_is_read_scanned_and_appended_to(self):
        from hydralysis import localio

        pad = "p" * 1000
        lines = [line_of({"n": number, "pad": pad}) for number in range(64)]
        block = b"".join(lines)  # about 66 KB; the file is built from repeated blocks, so it is cheap
        repeats = (localio.DEFAULT_MAX_BYTES // len(block)) + 20
        log = self.log()
        with open(log.path, "wb") as handle:
            for _ in range(repeats):
                handle.write(block)
        size = log.path.stat().st_size
        self.assertGreater(size, localio.DEFAULT_MAX_BYTES)
        with self.assertRaises(ValueError):  # the premise: the old whole-file read refuses this file
            localio.read_bytes(log.path)
        started = self.scans()
        status = log.status()  # streamed: no budget error
        self.assertEqual((status["records"], status["valid_bytes"], status["size"]), (64 * repeats, size, size))
        self.assertEqual(len(log.read()), 64 * repeats)
        self.assertEqual(log.last(), {"n": 63, "pad": pad})  # tail-aware: reads a window, not the file
        self.assertEqual(log.last(strict=True), {"n": 63, "pad": pad})
        del started[:]  # the reads above scanned too; count only the writer's scans from here
        # the writer's first acquisition scans the whole log by streaming (O(n), required once), then never again
        offset = log.append({"n": "new"})
        self.assertEqual((offset, started), (size, [0]))
        log.append({"n": "newer"})
        self.assertEqual(started, [0])
        self.assertEqual(log.last(), {"n": "newer"})
        # a torn tail after the huge prefix is found by the bounded scan from the known end, not the start
        known = durable._VERIFIED[log._key]
        with open(log.path, "ab") as handle:
            handle.write(b"1234")
        entry = log.repair()
        self.assertEqual((entry["offset"], entry["bytes"]), (known, 4))
        self.assertEqual(started, [0, known])
        self.assertIsNone(log.status()["torn_tail"])

    def test_the_tail_read_finds_the_last_valid_line_across_garbage_and_long_lines(self):
        log = self.log()
        log.append({"n": 1})
        big = {"n": 2, "pad": "z" * (durable.TAIL_WINDOW * 3)}  # longer than the first window
        log.append(big)
        self.assertEqual(log.last(), big)
        log.path.write_bytes(log.path.read_bytes() + b"garbage\n" + b"frag")
        self.assertEqual(log.last(), big)
        with patch.object(durable, "TAIL_WINDOW", 100), patch.object(durable, "TAIL_WINDOW_MAX", 400):
            self.assertEqual(log.last(), big)  # window limit reached: falls back to the full scan
        self.assertIsNone(durable.AppendLog(self.root / "none.log").last())
        (self.root / "empty.log").write_bytes(b"")
        self.assertIsNone(durable.AppendLog(self.root / "empty.log").last())

    def test_an_append_to_a_missing_log_creates_it_and_the_caller_may_hold_the_lock(self):
        log = self.log()
        with durable.file_lock(log.lock_path):
            self.assertEqual(log.append({"n": 1}, lock_held=True), 0)
        self.assertEqual(log.read(), [{"n": 1}])
        self.assertEqual(self.log().repair(), None)
        self.assertEqual(durable.AppendLog(self.root / "absent.log").read(), [])

    def test_the_writer_lock_excludes_a_second_writer(self):
        log = self.log(lock_timeout_s=0.3)
        with durable.file_lock(log.lock_path):
            with self.assertRaisesRegex(ValueError, "busy"):
                log.append({"n": 1})
        log.append({"n": 1})

    def test_concurrent_writer_processes_lose_no_line_and_tear_none(self):
        path = self.root / "backups.log"
        code = ("import sys\nfrom hydralysis import durable\n"
                "log = durable.AppendLog(sys.argv[1], by='w' + sys.argv[2])\n"
                "for i in range(25):\n"
                "    log.append({'w': int(sys.argv[2]), 'i': i, 'pad': 'x' * (i * 7)})\n")
        children = [subprocess.Popen([sys.executable, "-c", code, str(path), str(number)], env=child_env(),
                                     stderr=subprocess.PIPE, text=True) for number in range(5)]
        for child in children:
            _, error = child.communicate(timeout=180)
            self.assertEqual(child.returncode, 0, error)
        result = durable.AppendLog(path).scan()
        self.assertEqual((result.torn_tail, result.corrupt), (None, None))
        self.assertEqual(len(result.records), 5 * 25)
        for number in range(5):
            self.assertEqual([row["i"] for row in result.records if row["w"] == number], list(range(25)))  # per-writer order


# A black-box test of the writer-lock check: it uses only the public API and real processes, and reads nothing
# of the module's internal memory. Process A is a persistent writer that appends, reports and then WAITS on its
# stdin pipe. While it waits, another process (B) damages the log. Then A appends again and a fresh reader looks
# at the file. A writer that checked the tail only on its first append in a process would write straight after
# B's damage and produce a merged or invalid line.
#
# What each test proves, measured by running this class against the 589432e source (before the tail check
# on every acquisition):
#   * the killed-mid-line test (a fragment that does not end in LF) PASSES on 589432e as well: that code already
#     refused to append behind a file that did not end in LF. It guards the contract; it does not discriminate.
#   * the terminated-but-invalid-line test FAILS on 589432e (LineageCorrupt: an invalid line followed by A's valid
#     line, no repair record) and passes now: it is the one that needs the check on every lock acquisition.
#   * the control (a valid line from another process) passes on both and shows the failure above is not noise.

PERSISTENT_WRITER = """
import json, sys
from hydralysis import durable
log = durable.AppendLog(sys.argv[1], lock_path=sys.argv[2], by="A")
print("ready", flush=True)
for command in sys.stdin:
    command = command.strip()
    if command == "quit":
        break
    log.append(json.loads(command))
    print("appended", flush=True)
"""

RAW_DAMAGE = """
import os, sys
descriptor = os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
os.write(descriptor, sys.argv[2].encode("ascii").decode("unicode_escape").encode("latin-1"))
os.fsync(descriptor)
os._exit(137)
"""

APPEND_ONE = """
import sys
from hydralysis import durable
durable.AppendLog(sys.argv[1], lock_path=sys.argv[2], by="B").append({"n": 2, "pad": "y" * 20})
"""

APPEND_RECORD = """
import json, sys
from hydralysis import durable
durable.AppendLog(sys.argv[1], lock_path=sys.argv[2] or None, by="B").append(json.loads(sys.argv[3]))
"""


class TwoProcessWriters(unittest.TestCase):
    def setUp(self):
        self.work = workdir("durable2p")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.path = self.root / "CURRENT.log"
        self.lock = self.root / ".commit.lock"

    def start_a(self):
        child = subprocess.Popen([sys.executable, "-c", PERSISTENT_WRITER, str(self.path), str(self.lock or "")],
                                 env=child_env(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        watchdog = threading.Timer(90, child.kill)  # a hung child fails the test instead of blocking the suite
        watchdog.start()

        def stop():
            watchdog.cancel()
            if child.poll() is None:
                try:
                    child.stdin.write("quit\n")
                    child.stdin.flush()
                    child.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    child.kill()
            for stream in (child.stdin, child.stdout, child.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
            child.wait()

        self.addCleanup(stop)
        self.assertEqual(child.stdout.readline().strip(), "ready")
        return child

    def a_appends(self, child, record):
        child.stdin.write(json.dumps(record) + "\n")
        child.stdin.flush()
        self.assertEqual(child.stdout.readline().strip(), "appended",
                         "writer A did not append %r (exit code %r)" % (record, child.poll()))

    def torn_copies(self):
        return sorted(item for item in self.root.iterdir() if ".torn-" in item.name)

    def assert_repaired_and_valid(self, damage: bytes, expect_lines):
        fresh = durable.AppendLog(self.path, lock_path=self.lock, by="reader")  # a new object in a new process state
        self.assertEqual(fresh.read(), expect_lines)  # a LineageCorrupt would raise here
        status = fresh.status()
        self.assertEqual((status["torn_tail"], status["corrupt"]), (None, None))
        repairs = fresh.repairs()
        self.assertEqual(len(repairs), 1, repairs)
        self.assertEqual((repairs[0]["bytes"], repairs[0]["by"], repairs[0]["sha256"]),
                         (len(damage), "A", hashlib.sha256(damage).hexdigest()))
        self.assertEqual([copy.read_bytes() for copy in self.torn_copies()], [damage])  # the fragment was kept aside
        self.assertEqual(fresh.last(), expect_lines[-1])
        self.assertTrue(self.path.read_bytes().endswith(b"\n"))

    def test_a_appends_b_is_killed_mid_line_a_appends_again_and_a_repair_is_recorded(self):
        full = line_of({"n": 2, "pad": "y" * 20})
        for cut in (1, 9, len(full) - 1):
            with self.subTest(cut=cut):
                for leftover in [self.path, *self.torn_copies(), *self.root.glob("*.repairs")]:
                    leftover.unlink(missing_ok=True)
                a = self.start_a()
                self.a_appends(a, {"n": 1})
                result = run_child(APPEND_ONE, self.path, self.lock, fault="log.torn_append:torn:%d" % cut)
                self.assertEqual(result.returncode, 137, result.stderr)  # B was killed after writing `cut` bytes
                self.assertEqual(self.path.read_bytes(), line_of({"n": 1}) + full[:cut])
                self.a_appends(a, {"n": 3})  # A verified the log long ago and has been waiting since
                self.assert_repaired_and_valid(full[:cut], [{"n": 1}, {"n": 3}])

    def test_the_same_with_a_rollback_append_and_with_a_backups_log_append(self):
        # PROTOCOL-3.md 4.1 tests: "the same test with a rollback append (reason: rollback) and a backups.log append".
        # CURRENT.log and the intent logs lock on `.commit.lock`; backups.log locks on its own `.lock` (the default).
        cases = (("CURRENT.log", self.root / ".commit.lock", {"reason": "rollback", "to": 4, "pad": "r" * 30}),
                 ("backups.log", None, {"op": "backup", "id": "b-0001", "pad": "k" * 30}))
        for name, lock, record in cases:
            for cut in (1, 12, len(line_of(record)) - 1):
                with self.subTest(log=name, cut=cut):
                    for leftover in self.root.glob("*.log*"):  # the log, its .torn-* copies, .repairs and own .lock
                        leftover.unlink(missing_ok=True)
                    self.path, self.lock = self.root / name, lock
                    a = self.start_a()
                    self.a_appends(a, {"n": 1})
                    result = run_child(APPEND_RECORD, self.path, lock or "", json.dumps(record),
                                       fault="log.torn_append:torn:%d" % cut)
                    self.assertEqual(result.returncode, 137, result.stderr)
                    self.assertEqual(self.path.read_bytes(), line_of({"n": 1}) + line_of(record)[:cut])
                    self.a_appends(a, {"n": 3})
                    self.assert_repaired_and_valid(line_of(record)[:cut], [{"n": 1}, {"n": 3}])
                    self.a_appends(a, {"n": 4})  # and the log keeps working
                    self.assertEqual(durable.AppendLog(self.path, lock_path=lock).read(), [{"n": 1}, {"n": 3}, {"n": 4}])
                    a.stdin.write("quit" + chr(10))
                    a.stdin.flush()
                    a.wait(timeout=30)

    def test_a_foreign_writer_leaves_a_terminated_but_invalid_line_and_a_still_repairs_it(self):
        junk = b"half a rec\n"
        a = self.start_a()
        self.a_appends(a, {"n": 1})
        result = subprocess.run([sys.executable, "-c", RAW_DAMAGE, str(self.path), "half a rec\\n"], env=child_env(),
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 137, result.stderr)
        self.assertEqual(self.path.read_bytes(), line_of({"n": 1}) + junk)
        self.a_appends(a, {"n": 2})
        self.assert_repaired_and_valid(junk, [{"n": 1}, {"n": 2}])

    def test_control_a_valid_line_from_another_process_needs_no_repair(self):
        a = self.start_a()
        self.a_appends(a, {"n": 1})
        result = run_child(APPEND_ONE, self.path, self.lock)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.a_appends(a, {"n": 3})
        fresh = durable.AppendLog(self.path, lock_path=self.lock)
        self.assertEqual(fresh.read(), [{"n": 1}, {"n": 2, "pad": "y" * 20}, {"n": 3}])
        self.assertEqual((fresh.repairs(), self.torn_copies()), ([], []))


# --------------------------------------------------------------------------- the write gate

# A write site is (file, enclosing function, kind). The gate has two halves.
#
# 1. In the files Y0a owns, the only record writes are write_json / _save_store (through durable). The sites
#    below are not records (downloads, binary copies, logs, markers, an engine input file); anything else fails.
# 2. In the rest of src, the sites are frozen (a ratchet): a NEW write_text / write_bytes / open-for-write /
#    replace that is not listed fails the suite. "record" rows are the follow-up table: they bear state and
#    should move to durable in the package that owns the file; "artifact" rows are exports, logs and copies.

OWNED = {"backends.py", "workcopy.py", "targets.py", "overlayjobs.py"}

NOT_A_RECORD = {  # (file, function, kind) -> why
    ("backends.py", "_download", "open(xb)"): "archive download (hash-checked)",
    ("backends.py", "_download", "Path.replace"): "archive download rename",
    ("backends.py", "_extract", "Path.rename"): "unpacked directory rename",
    ("workcopy.py", "store_corpus", "shutil.copyfile"): "content-addressed corpus copy",
    ("workcopy.py", "store_corpus", "Path.replace"): "content-addressed corpus copy",
    ("workcopy.py", "store_archive", "open(xb)"): "content-addressed archive copy",
    ("workcopy.py", "store_archive", "Path.replace"): "content-addressed archive copy",
    ("workcopy.py", "_apply", "write_text"): "request file handed to the engine, deleted after use",
    ("workcopy.py", "_start_saver", "open(ab)"): "saver process log",
    ("overlayjobs.py", "start", "open(ab)"): "worker process log",
    ("overlayjobs.py", "cancel", "write_text"): "cancel marker file",
}

FOLLOW_UP = {  # (file, function, kind) -> (category, note)
    ("hydra.py", "sync_scripts", "write_bytes"): ("artifact", "engine script staging"),
    ("hydra.py", "sync_scripts", "Path.replace"): ("artifact", "engine script staging"),
    ("hydra.py", "install", "Path.rename"): ("artifact", "engine install directory rename"),
    ("userscripts.py", "_stage", "write_bytes"): ("artifact", "staged user script copy"),
    ("userscripts.py", "_stage", "Path.replace"): ("artifact", "staged user script copy"),
    ("crossbuild.py", "run", "open(w)"): ("artifact", "diff report"),
    ("crossbuild.py", "run", "write_text"): ("artifact", "diff summary"),
    ("crossbuild.py", "_export_overlay_candidates", "write_text"): ("artifact", "export"),
    ("crossbuild.py", "transfer_checks", "write_text"): ("artifact", "export"),
    ("evidence.py", "export", "write_text"): ("artifact", "evidence export (the database is SQLite WAL)"),
    ("evidence.py", "export", "open(w)"): ("artifact", "evidence export"),
    ("export_worker.py", "run", "open(a)"): ("artifact", "export output rows"),
    ("exporting.py", "_launch", "open(ab)"): ("artifact", "worker log"),
    ("locks.py", "LaneLock.acquire", "open(a+b)"): ("artifact", "lock file"),
    ("preparation.py", "cancel", "write_text"): ("artifact", "cancel marker"),
    ("preparation.py", "_launch", "open(wb)"): ("artifact", "worker log"),
    ("preparation_worker.py", "_log", "open(a)"): ("artifact", "worker log"),
    ("preparation_worker.py", "_prepare", "shutil.copy2"): ("artifact", "binary copy"),
    ("query.py", "run_script", "write_text"): ("artifact", "request file handed to the engine"),
    ("runtime.py", "setup", "write_text"): ("artifact", "pip requirements file"),
    ("runtime.py", "setup", "open(wb)"): ("artifact", "install log"),
    ("runtime.py", "RuntimeRunner._start", "open(wb)"): ("artifact", "worker log"),
}


COUNTS = {("hydra.py", "install", "Path.rename"): 2, ("crossbuild.py", "run", "open(w)"): 2}


def write_sites(path):
    """(function, kind, line) for every call that can write a file, found on the syntax tree."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []

    def mode(call, index):
        for keyword in call.keywords:
            if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                return keyword.value.value
        if len(call.args) > index and isinstance(call.args[index], ast.Constant):
            return call.args[index].value
        return None

    def visit(node, scope):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = scope + [node.name]
        if isinstance(node, ast.Call):
            func, kind = node.func, None
            if isinstance(func, ast.Attribute):
                owner = func.value.id if isinstance(func.value, ast.Name) else None
                if func.attr in ("write_text", "write_bytes"):
                    kind = func.attr
                elif func.attr == "dump" and owner == "json":
                    kind = "json.dump"
                elif func.attr in ("replace", "rename") and owner == "os":
                    kind = "os." + func.attr
                elif func.attr in ("replace", "rename") and len(node.args) == 1 and not node.keywords:
                    kind = "Path." + func.attr  # str.replace takes two arguments
                elif owner == "shutil" and func.attr in ("copy", "copy2", "copyfile", "copyfileobj", "move", "copytree"):
                    kind = "shutil." + func.attr
                elif func.attr == "open":
                    value = mode(node, 1 if owner in ("os", "io") else 0)
                    if isinstance(value, str) and set(value) & set("wax+"):
                        kind = "open(%s)" % value
            elif isinstance(func, ast.Name) and func.id == "open":
                value = mode(node, 1)
                if isinstance(value, str) and set(value) & set("wax+"):
                    kind = "open(%s)" % value
            if kind:
                found.append((".".join(scope) or "<module>", kind, node.lineno))
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(tree, [])
    return found


class WriteGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sites = {}
        for path in sorted((SRC / "hydralysis").glob("*.py")):
            if path.name != "durable.py":
                for function, kind, line in write_sites(path):
                    cls.sites.setdefault((path.name, function, kind), []).append(line)

    def test_owned_files_write_records_only_through_durable(self):
        for (name, function, kind), lines in sorted(self.sites.items()):
            if name in OWNED:
                with self.subTest(site=(name, function, kind), lines=lines):
                    self.assertIn((name, function, kind), NOT_A_RECORD,
                                  "%s:%s %s writes a file outside durable; use backends.write_json or durable.write_sealed"
                                  % (name, lines, kind))
        for key in NOT_A_RECORD:
            self.assertIn(key, self.sites, "stale allow-list entry %s" % (key,))

    def test_no_new_write_site_appears_in_the_rest_of_src(self):
        rest = {key: lines for key, lines in self.sites.items() if key[0] not in OWNED}
        new = sorted(key for key in rest if key not in FOLLOW_UP)
        self.assertEqual(new, [], "new file write outside durable: route record state through durable.write_sealed / "
                                  "AppendLog, or classify the site in FOLLOW_UP if it is not a record")
        for key, lines in FOLLOW_UP.items():
            self.assertIn(key, rest, "stale follow-up entry %s" % (key,))
            self.assertEqual(len(rest[key]), COUNTS.get(key, 1), "%s changed its number of write sites" % (key,))

    def test_record_helpers_are_the_only_json_writers_and_nothing_dumps_json_to_a_file(self):
        self.assertFalse([key for key in self.sites if key[2] == "json.dump"])

    def test_the_follow_up_table_is_counted(self):
        records = [key for key, (category, _) in FOLLOW_UP.items() if category == "record"]
        # Y0e moved hydra.write_daemon_config, runtime._write and runtime_worker._write onto durable (six rows gone);
        # Y1 deleted the legacy analysis.save_overlay (its two rows). What is left is the artifact sites that are
        # not records: no record-bearing writer stands outside durable.
        self.assertEqual(len(records), 0)
        self.assertEqual(len(FOLLOW_UP), 22)
        self.assertEqual(sum(COUNTS.get(key, 1) for key in FOLLOW_UP), 24)
        self.assertEqual(sorted(key[:2] for key in records), [])


if __name__ == "__main__":
    unittest.main()
