"""The Rust runtime (`HYDRALYSIS_IMPL=rust`) driven through the Python runtime layer and through its PyO3 surface.

Two groups. `ThroughTheWorker` runs the real fixtures under a `RuntimeAgent` whose device is the Rust one: the same
`capture start/stop` the Frida implementation serves, with the same TRACE-1 segment at the end. `Surface` drives
`hydralysis_rt.RtSession` directly against the Rust `hy-fixture` target: the authorized memory write, the watch, the breakpoint.

Skipped, with the reason, unless the Rust pieces are built (`cargo build --release` in rust/, with PYO3_PYTHON set for hy-py)
and, for the first group, MSVC is available to build the C fixtures.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fixtures"))
sys.path.insert(0, str(HERE.parent / "src"))

from hydralysis import rust_frida  # noqa: E402

try:
    RT = rust_frida._load_rt()
    AGENT = rust_frida.agent_dll()
    READY = os.name == "nt"
    WHY = ""
except Exception as exc:        # noqa: BLE001 - the reason is the skip message
    RT, AGENT, READY, WHY = None, None, False, str(exc)

HY_FIXTURE = Path(os.environ.get("HYDRALYSIS_HY_FIXTURE") or rust_frida._RELEASE / "hy-fixture.exe")


def _wait_for(path: Path, needle: str, timeout: float = 20.0) -> str:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            text = ""
        if needle in text:
            return text
        time.sleep(0.01)
    raise AssertionError("%r never appeared in %s" % (needle, path))


def _kv(text: str, key: str) -> str:
    for word in text.split():
        if word.startswith(key):
            return word[len(key):]
    raise AssertionError("%s not in %r" % (key, text))


@unittest.skipUnless(READY, "the Rust runtime is not built: %s" % WHY)
class ThroughTheWorker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import trace_fixtures as tf
        if not tf.msvc_available():
            raise unittest.SkipTest("needs MSVC to build the fixtures")
        import trace_live
        cls.tl = trace_live
        cls.previous = os.environ.get("HYDRALYSIS_IMPL")
        os.environ["HYDRALYSIS_IMPL"] = "rust"
        cls.root = tempfile.TemporaryDirectory(prefix="rt-worker-")
        cls.fx = None
        for group in ("frameloop", "trace_app", "interleave"):
            cls.fx = tf.build_group(group, Path(cls.root.name) / "fx", ("x64",))["x64"]["dir"]
        cls.lives = []

    @classmethod
    def tearDownClass(cls):
        for live in cls.lives:
            live.close()
        if cls.previous is None:
            os.environ.pop("HYDRALYSIS_IMPL", None)
        else:
            os.environ["HYDRALYSIS_IMPL"] = cls.previous
        try:
            cls.root.cleanup()
        except OSError:
            pass

    def traced(self, exe, argv, *, hooks=None, linger_ms=600, wait=True, **trace):
        specs, _ = self.tl.specs_for(self.fx, [exe], hooks)
        live = self.tl.Live(Path(self.root.name) / "runs", self.fx / exe, argv, linger_ms=linger_ms)
        self.lives.append(live)
        live.start(specs, **trace)
        live.resume()
        if wait:
            self.assertTrue(live.wait_exit(90))
            time.sleep(0.3)
        return live

    def stop(self, live):
        reply = live.agent.trace_stop({"reason": "capture stopped", "timeout_ms": 30000})
        self.assertTrue(reply["stopped"], reply)
        live.stopped = live.agent.handle("capture", {"op": "stop"})
        return reply

    def events(self, live):
        from hydralysis import trace_capture as tc
        return tc.read_events(live.segment, live.agent.trace.segment_id)

    def test_the_device_is_the_rust_one(self):
        live = self.traced("frameloop.exe", ["--frames=5"])
        self.assertIsInstance(live.agent.device, rust_frida.RustDevice)
        self.stop(live)

    def test_control_script_answers_info_modules_locate_read(self):
        live = self.traced("frameloop.exe", ["--frames=100000", "--spin-us=1000"], wait=False)
        control = live.agent.control.exports_sync
        info = control.info(str(self.fx / "frameloop.exe"))
        self.assertEqual((info["arch"], info["pointer_size"], info["selected_module_found"]), ("x64", 8, True))
        main = info["main"]
        modules = control.modules(200)
        self.assertIn("kernel32.dll", [m["name"].lower() for m in modules["modules"]])
        base = int(main["base"], 16)
        head = bytes(control.read(main["base"], 2))
        self.assertEqual(head, b"MZ")
        located = control.locate(hex(base + 16))
        self.assertEqual(located["module"]["path"].lower(), main["path"].lower())
        self.assertEqual(located["range"]["protection"][0], "r")
        with self.assertRaises(RuntimeError):
            control.read("0x10", 4)               # unmapped: refused, not a crash
        self.assertGreaterEqual(control.threads(1)["total"], 1)
        self.stop(live)

    def test_frameloop_every_frame_and_stage_is_recorded_without_loss(self):
        live = self.traced("frameloop.exe", ["--frames=60"])
        self.stop(live)
        health = live.agent.trace.health()
        kinds = Counter(e["kind"] for e in self.events(live))
        self.assertEqual(kinds["app.frame"], 120)                 # begin and end of 60 frames
        self.assertEqual(kinds["app.stage"], 180)
        self.assertEqual(health["producer"]["dropped"], 0)
        self.assertEqual(health["encoder"]["records"], health["producer"]["attempted"])
        self.assertEqual(live.agent.trace.verify()["outcome"], "clean")

    def test_exact_mode_keeps_every_hit_and_labels_nothing_sampled(self):
        live = self.traced("frameloop.exe", ["--frames=300"], sampling="exact")
        self.stop(live)
        health = live.agent.trace.health()
        self.assertEqual(health["producer"]["dropped"], 0)
        self.assertEqual(health["producer"]["sampling"]["skipped"], 0)
        self.assertEqual(health["encoder"]["records"], health["producer"]["attempted"])
        self.assertFalse([e for e in self.events(live) if e.get("confidence") == "sampled"])

    def test_a_loop_over_the_rate_budget_is_thinned_and_every_skip_is_counted(self):
        live = self.traced("frameloop.exe", ["--frames=60000"], sampling={"mode": "adaptive", "rate_budget": 20000})
        self.stop(live)
        health = live.agent.trace.health()
        sampling = health["producer"]["sampling"]
        self.assertGreater(sampling["skipped"], 0)
        kept = sum(row["kept"] for row in sampling["sites"])
        self.assertEqual(kept + sampling["skipped"], sampling["hits"], "kept + skipped is every hit, exactly")
        self.assertGreater(len([e for e in self.events(live) if e.get("confidence") == "sampled"]), 0)

    def test_a_killed_target_still_yields_what_it_wrote(self):
        live = self.traced("frameloop.exe", ["--frames=100000", "--spin-us=1000"], wait=False)
        end = time.monotonic() + 60
        while time.monotonic() < end and live.agent.trace.health().get("producer", {}).get("attempted", 0) < 200:
            time.sleep(0.05)
        self.assertGreaterEqual(live.agent.trace.health()["producer"]["attempted"], 200)
        live.job.kill()
        self.assertTrue(live.wait_exit(30))
        reply = live.agent.trace_stop({"reason": "target killed", "timeout_ms": 10000})
        self.assertTrue(reply["stopped"], reply)         # the target is gone: nothing runs the stubs, the rings are ours
        self.assertTrue(live.agent.detached)

    def test_other_script_templates_are_refused_clearly(self):
        live = self.traced("frameloop.exe", ["--frames=100000", "--spin-us=1000"], wait=False)
        with self.assertRaises(NotImplementedError):
            live.agent.session.create_script("send({});")
        live.job.kill()


@unittest.skipUnless(READY and HY_FIXTURE.is_file(), "needs the Rust runtime and hy-fixture.exe (cargo build --release in rust/)")
class Surface(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(prefix="rt-surface-")
        self.sessions = []

    def tearDown(self):
        for s in self.sessions:
            try:
                s.terminate()
            except Exception:
                pass
            s.close()
        try:
            self.dir.cleanup()
        except OSError:
            pass

    def start(self, mode, inject=False):
        out = Path(self.dir.name) / (mode + ".txt")
        s = RT.RtSession.spawn(str(HY_FIXTURE), [mode], stdout=str(out))
        self.sessions.append(s)
        if inject:
            s.inject(AGENT)
        s.resume()
        return s, out

    def wait_exit(self, s, timeout=60, tick=None):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if s.wait_exit(10):
                return
            if tick:
                tick()
        self.fail("the target did not exit")

    def test_cas_write_and_undo_and_refusals(self):
        s, out = self.start("write")
        text = _wait_for(out, "BASE=")
        addr = int(_kv(text, "ADDR="), 16)
        base = int(_kv(text, "BASE="), 16)
        q = lambda x: x.to_bytes(8, "little")        # noqa: E731
        with self.assertRaisesRegex(RuntimeError, "compare failed"):
            s.write_cas(addr, q(0x9999), q(1), "a good enough reason")
        with self.assertRaisesRegex(RuntimeError, "reason"):
            s.write_cas(addr, q(0x1111), q(1), "short")
        with self.assertRaisesRegex(RuntimeError, "EXECUTABLE"):
            s.write_cas(base + 0x1000, b"\0" * 8, q(1), "patching code is refused")
        self.assertEqual(s.read_memory(addr, 8), q(0x1111))
        undo = s.write_cas(addr, q(0x1111), q(0x2222), "a good enough reason")
        self.assertEqual(s.read_memory(addr, 8), q(0x2222))
        s.undo_write(undo)
        self.assertEqual(s.read_memory(addr, 8), q(0x1111))
        s.write_cas(addr, q(0x1111), q(0x3333), "release the fixture loop")
        self.wait_exit(s, 20)
        self.assertIn("SAW", out.read_text())

    def test_an_authorization_for_another_range_refuses_the_write(self):
        import json
        s, out = self.start("write")
        text = _wait_for(out, "BASE=")
        addr = int(_kv(text, "ADDR="), 16)
        entry = json.dumps({"sha256": "0" * 64, "actions": ["write"], "max_size": 8, "note": "a test authorization",
                            "ranges": [{"module": HY_FIXTURE.name, "rva_start": "0x0", "rva_end": "0x8"}]})
        with self.assertRaisesRegex(RuntimeError, "(?i)authoriz|range|refus"):
            s.write_cas(addr, (0x1111).to_bytes(8, "little"), (0x2222).to_bytes(8, "little"), "outside the authorized range", entry)
        self.assertEqual(s.read_memory(addr, 8), (0x1111).to_bytes(8, "little"))

    def test_watch_sees_writes_from_old_and_new_threads_and_disarms_clean(self):
        s, out = self.start("watch", inject=True)
        addr = int(_kv(_wait_for(out, "ADDR="), "ADDR="), 16)
        with self.assertRaises(RuntimeError):
            s.arm_watch(addr + 1, 8, "write", 100)             # misaligned: refused before anything is armed
        slot = s.arm_watch(addr, 8, "write", 100)
        events = []
        self.wait_exit(s, 60, lambda: (s.sync_watch_threads(), events.extend(s.events())))
        events.extend(s.events())
        hits = [e for e in events if e[0] == 3]
        self.assertEqual(s.exit_code(), 0)
        self.assertEqual(len(hits), 6)
        self.assertEqual(len({e[2] for e in hits}), 2)

    def test_breakpoint_parks_until_continued(self):
        info_out = Path(self.dir.name) / "info.txt"
        probe = RT.RtSession.spawn(str(HY_FIXTURE), ["info"], stdout=str(info_out))
        self.sessions.append(probe)
        probe.resume()
        self.wait_exit(probe, 20)
        text = info_out.read_text()
        rva = int(_kv(text, "RVA="), 16)
        expect = bytes.fromhex(_kv(text, "BYTES="))
        s, out = (lambda o: (RT.RtSession.spawn(str(HY_FIXTURE), ["pause"], stdout=str(o)), o))(Path(self.dir.name) / "pause.txt")
        self.sessions.append(s)
        s.inject(AGENT)
        ok, code = s.arm_site(0, {"rva": rva, "expect": list(expect), "nargs": 1, "pause": True})
        self.assertTrue(ok, code)
        s.resume()
        end = time.monotonic() + 20
        parked = []
        while time.monotonic() < end and not parked:
            parked = s.paused()
            time.sleep(0.005)
        self.assertTrue(parked, "never parked")
        slot = parked[0][0]
        time.sleep(0.3)
        self.assertNotIn("AFTER", out.read_text() if out.exists() else "")
        self.assertTrue(s.continue_breakpoint(slot))
        self.wait_exit(s, 20)
        self.assertIn("AFTER", out.read_text())


if __name__ == "__main__":
    unittest.main()
