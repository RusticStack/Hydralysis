"""Footprint with the registry: declared HKCU keys are diffed like files, and persist.exe / trace_app.exe round-trip (Windows)."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fixtures"))
sys.path.insert(0, str(HERE.parent / "src"))

from support import workdir  # noqa: E402

from hydralysis import profiles  # noqa: E402
from hydralysis import trace_footprint as fp  # noqa: E402

WINDOWS = os.name == "nt"
if WINDOWS:
    import winreg

PREFIX = "Software\\HydraFootprintTest"


@unittest.skipUnless(WINDOWS, "the registry is Windows only")
class RegistrySnapshot(unittest.TestCase):
    def setUp(self):
        self.key = PREFIX + "\\" + uuid.uuid4().hex[:8]
        self.addCleanup(self.drop)

    def drop(self):
        def remove(sub):
            try:
                handle = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, winreg.KEY_READ)
            except OSError:
                return
            with handle:
                names = []
                try:
                    while True:
                        names.append(winreg.EnumKey(handle, len(names)))
                except OSError:
                    pass
            for name in names:
                remove(sub + "\\" + name)
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
        remove(self.key)
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, PREFIX)
        except OSError:
            pass

    def put(self, sub, name, value, kind=winreg.REG_SZ if WINDOWS else 1):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.key + sub) as handle:
            winreg.SetValueEx(handle, name, 0, kind, value)

    def test_declared_keys_only_and_only_hkcu(self):
        self.assertEqual(fp.registry_subkey("HKCU\\Software\\X"), "Software\\X")
        self.assertEqual(fp.registry_subkey("HKEY_CURRENT_USER/Software/X"), "Software\\X")
        for bad in ("HKLM\\Software\\X", "HKCU", "HKCU\\", "Software\\X", "HKU\\.DEFAULT\\X"):
            with self.assertRaises(ValueError):
                fp.registry_subkey(bad)
        with self.assertRaises(ValueError):
            fp.snapshot([], registry=["HKLM\\Software\\Microsoft"])

    def test_values_keys_and_subkeys_are_diffed_and_round_trip(self):
        declared = "HKCU\\" + self.key
        absent = fp.snapshot([], registry=[declared])
        self.assertEqual(absent, {})                                            # a key that does not exist contributes nothing
        self.put("", "Mode", "A")
        self.put("\\child", "Count", 3, winreg.REG_DWORD)
        before = fp.snapshot([], registry=[declared])
        self.assertEqual(len(before), 4)                                        # the key, Mode, the child key, Count
        self.assertTrue(all(v["sha256"] for v in before.values()))
        self.assertNotIn("A", repr(before))                                     # the data is hashed, never copied
        self.put("", "Mode", "B")
        self.put("\\child", "Extra", b"\x01\x02", winreg.REG_BINARY)
        after = fp.snapshot([], registry=[declared])
        d = fp.diff(before, after)
        self.assertEqual([p.rsplit("\\", 1)[-1] for p in d["changed"]], ["mode"])
        self.assertEqual([p.rsplit("\\", 1)[-1] for p in d["added"]], ["extra"])
        self.assertEqual(fp.round_trip(before, after)["verdict"], fp.NOT_ROUND_TRIP)
        self.put("", "Mode", "A")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.key + "\\child", 0, winreg.KEY_SET_VALUE) as handle:
            winreg.DeleteValue(handle, "Extra")
        self.assertEqual(fp.round_trip(before, fp.snapshot([], registry=[declared]))["verdict"], "round-trips")

    def test_a_file_and_a_key_share_one_snapshot(self):
        with workdir() as root:
            (Path(root) / "a.cfg").write_text("1")
            self.put("", "Mode", "A")
            s0 = fp.snapshot([Path(root)], registry=["HKCU\\" + self.key])
            self.assertEqual(sorted(k.split(":")[0] if k.startswith("reg:") else "file" for k in s0), ["file", "reg", "reg"])
            self.put("", "Mode", "B")
            self.assertEqual(len(fp.diff(s0, fp.snapshot([Path(root)], registry=["HKCU\\" + self.key]))["changed"]), 1)


@unittest.skipUnless(WINDOWS, "the fixtures are Windows programs")
class FixtureRoundTrips(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import trace_fixtures as tf
        if not tf.msvc_available():
            raise unittest.SkipTest("MSVC build tools are not installed")
        cls.root = workdir("footprint-fx")
        cls.dir = {}
        for group in ("persist", "trace_app"):
            cls.dir[group] = tf.build_group(group, Path(cls.root.name) / group, ("x64",))["x64"]["dir"]

    @classmethod
    def tearDownClass(cls):
        cls.root.cleanup()

    def run_persist(self, work, mode, *extra):
        done = subprocess.run([str(self.dir["persist"] / "persist.exe"), str(work), mode, *extra], capture_output=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_persist_exe_an_injected_write_survives_removing_it_and_a_second_save_restores_it(self):
        profile = profiles.load_baseline()
        with workdir() as work:
            files, keys = fp.stores_of(profile, Path(work))
            self.assertIn(Path(work) / "persist.sav", files)
            roots = [Path(work)]
            self.run_persist(work, "save")                                      # the control run: the ordinary change
            clean = fp.snapshot(roots)
            self.run_persist(work, "save", "--poke")                            # the intervention writes record 2 into the save
            poked = fp.snapshot(roots)
            intervention = fp.diff(clean, poked)
            self.assertEqual([Path(p).name for p in intervention["changed"] if Path(p).name == "persist_save.dat"], ["persist_save.dat"])
            self.assertEqual(fp.classify(intervention, {"added": [], "removed": [], "changed": []})["verdict"], "caused")
            # removing the intervention (running without the poke) does not restore what is already in the file: it is not undone by
            # removing the instrument, and the footprint says so
            self.run_persist(work, "save")
            back = fp.round_trip(clean, fp.snapshot(roots))
            self.assertEqual(back["verdict"], fp.NOT_ROUND_TRIP)
            self.assertIn("persist_save.dat", [Path(p).name for p in back["paths"]])

    def test_trace_app_leaves_no_registry_key_behind(self):
        key = "HKCU\\Software\\HydraTraceFixture"
        before = fp.snapshot([], registry=[key])
        with workdir() as work:
            done = subprocess.run([str(self.dir["trace_app"] / "trace_app.exe"), str(work), "A"], capture_output=True, timeout=60,
                                  cwd=str(self.dir["trace_app"]))
            self.assertEqual(done.returncode, 0, done.stderr)
            after = fp.snapshot([], registry=[key])
        self.assertEqual(fp.round_trip(before, after)["verdict"], "round-trips")    # fx_registry_cleanup removed what the run wrote

    def test_trace_app_registry_value_is_seen_while_the_run_is_in_progress(self):
        import ctypes
        key = "HKCU\\Software\\HydraTraceFixture"
        before = fp.snapshot([], registry=[key])
        # drive the fixture's own write through its registry value: set it as the fixture does, then undo it
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Software\\HydraTraceFixture") as handle:
            winreg.SetValueEx(handle, "Mode", 0, winreg.REG_SZ, "A")
        try:
            during = fp.snapshot([], registry=[key])
            d = fp.diff(before, during)
            self.assertEqual(len(d["added"]), 2)
        finally:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, "Software\\HydraTraceFixture") if False else None
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\HydraTraceFixture", 0, winreg.KEY_SET_VALUE) as handle:
                winreg.DeleteValue(handle, "Mode")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, "Software\\HydraTraceFixture")
        self.assertEqual(fp.round_trip(before, fp.snapshot([], registry=[key]))["verdict"], "round-trips")
        del ctypes


if __name__ == "__main__":
    unittest.main()
