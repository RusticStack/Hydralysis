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

    def test_a_module_loaded_while_recording_is_reported_and_the_counters_are_filled_in(self):
        work = Path(self.root.name) / "w-mod"
        work.mkdir()
        live = self.traced("trace_app.exe", [str(work), "A"], linger_ms=1500)
        self.stop(live)
        events = self.events(live)
        loads = [e for e in events if e["kind"] == "core.module.load"]
        self.assertTrue([e for e in loads if str(e["payload"]["name"]).lower() == "trace_plugin.dll"], [e["payload"] for e in loads][:6])
        counters = live.agent.trace.health()["producer"]
        self.assertGreater(counters["entered"], 0)
        self.assertLessEqual(counters["left"], counters["entered"])
        self.assertLessEqual(counters["entered"] - counters["left"], counters["dropped"], counters)
        self.assertTrue(all("rate_per_s" in row for row in counters["sampling"]["sites"]))

    def test_a_running_loop_reports_its_rate_per_site(self):
        live = self.traced("frameloop.exe", ["--frames=100000", "--spin-us=1000"], wait=False)

        def rates():
            sites = live.agent.trace.health().get("producer", {}).get("sampling", {}).get("sites", [])
            return [row["rate_per_s"] for row in sites]

        end = time.monotonic() + 60
        while time.monotonic() < end and not any(rates()):
            time.sleep(0.1)
        self.assertTrue(any(rate > 0 for rate in rates()), rates())
        live.job.kill()
        self.assertTrue(live.wait_exit(30))
        self.assertIn("stall_ticks", live.agent.trace.health()["producer"])

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

    def test_sampling_calls_from_several_threads_never_deadlock_on_the_gil(self):
        """`sampling_tick` / `sampling_report` / `configure_sampling` take the sampler mutex, then the session mutex. They must
        do so with the GIL released: a thread that holds the sampler guard while it waits to get the GIL back would deadlock
        with one that holds the GIL and waits for the guard (the whole interpreter stops; `faulthandler` ends the run)."""
        import faulthandler
        import threading
        s, out = self.start("write")
        _wait_for(out, "BASE=")
        s.configure_sampling("adaptive", 1000.0, 1, 5, [])
        stop = threading.Event()
        errors = []

        def hammer(call):
            while not stop.is_set():
                try:
                    call()
                except Exception as exc:            # noqa: BLE001 - reported below
                    errors.append(repr(exc))
                    return

        calls = [s.sampling_tick, s.sampling_tick, s.sampling_report, s.counters,
                 lambda: s.configure_sampling("adaptive", 1000.0, 1, 5, [])]
        threads = [threading.Thread(target=hammer, args=(c,), daemon=True) for c in calls]
        faulthandler.dump_traceback_later(40, exit=True)
        try:
            for t in threads:
                t.start()
            end = time.monotonic() + 3.0
            while time.monotonic() < end:
                time.sleep(0.01)
            stop.set()
            for t in threads:
                t.join(10)
        finally:
            faulthandler.cancel_dump_traceback_later()
        self.assertEqual(errors, [])
        self.assertFalse(any(t.is_alive() for t in threads))

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


@unittest.skipUnless(READY and HY_FIXTURE.is_file(), "needs the Rust runtime and hy-fixture.exe (cargo build --release in rust/)")
class ThroughTheAgent(unittest.TestCase):
    """The templates the worker loads (observe, break, the memory agent, the control script's threads) on the Rust device:
    a real `RuntimeAgent` on `hy-fixture.exe`, the same actions the fake-binding suites drive against in-memory targets."""

    GATE_FROM = "17.24.3"

    @classmethod
    def setUpClass(cls):
        import subprocess
        info = dict(word.split("=", 1) for word in subprocess.run([str(HY_FIXTURE), "info"], capture_output=True, text=True,
                                                                  timeout=60).stdout.split())
        cls.site_rva = int(info["RVA"], 16)
        cls.cell_rva = int(info["CELL"], 16)
        cls.prologue = bytes.fromhex(info["BYTES"])[:8]

    def setUp(self):
        import hashlib
        from unittest.mock import patch
        self.dir = tempfile.TemporaryDirectory(prefix="rt-agent-")
        self.device = rust_frida.RustDevice()
        self.agents = []
        self.digest = hashlib.sha256(HY_FIXTURE.read_bytes()).hexdigest()
        marked = patch("hydralysis.runtime_memory.fixture_marked", return_value=True)
        marked.start()
        self.addCleanup(marked.stop)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for raw in list(self.device._live.values()):          # the targets first: a closed session cannot terminate its process
            try:
                raw.terminate()
            except Exception:
                pass
        for agent in self.agents:
            try:
                if not agent.closed:
                    agent.cleanup()
            except Exception:
                pass
        for raw in list(self.device._live.values()):
            raw.close()
        try:
            self.dir.cleanup()
        except OSError:
            pass

    def start(self, *argv):
        import uuid
        from hydralysis.runtime_worker import RuntimeAgent
        directory = Path(self.dir.name) / uuid.uuid4().hex
        directory.mkdir()
        agent = RuntimeAgent(directory, self.device)
        self.agents.append(agent)
        agent.startup({"action": "spawn", "exe": str(HY_FIXTURE), "sha256": self.digest, "argv": [str(a) for a in argv], "env": {}})
        return agent

    def base(self, agent):
        return int(agent.control.exports_sync.info(str(HY_FIXTURE))["main"]["base"], 16)

    def gate(self, agent):
        stamp = {"version": 1, "result": "pass", "arch": "x64", "fixture_sha256": agent.target_sha256, "frida": self.GATE_FROM,
                 "iterations": 100}
        return {"fixture_sha256": agent.target_sha256, "frida": self.GATE_FROM, "stamps": {"x64": stamp}}

    def payloads(self, agent, hook):
        out = agent.handle("status", {"limit": 200})["events"]
        return [e["message"]["payload"] for e in out if (e["message"].get("payload") or {}).get("hook_id") == hook]

    def until(self, what, test, timeout=20.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = test()
            if value:
                return value
            time.sleep(0.02)
        self.fail("never: " + what)

    def wait_gone(self, agent, timeout=20.0):
        self.until("the target exits", lambda: agent.session.exited(), timeout)

    def observe(self, agent, **options):
        args = {"module": HY_FIXTURE.name, "rva": hex(self.site_rva), "sha256": self.digest,
                "expect": " ".join("%02X" % b for b in self.prologue), "limit": 3, **options}
        return agent.handle(args.pop("action", "observe"), args)

    def test_the_control_script_reports_thread_state_and_registers(self):
        agent = self.start("write")
        agent.handle("resume", {})
        threads = agent.control.exports_sync.threads(50)
        self.assertGreaterEqual(threads["total"], 1)
        self.assertTrue({t["state"] for t in threads["threads"]} <= {"running", "waiting", "stopped", "uninterruptible", "halted"})
        with_registers = [t for t in threads["threads"] if t["context"]]
        self.assertTrue(with_registers, threads)
        for t in with_registers:
            self.assertTrue({"pc", "sp", "rip", "rsp", "rax", "rcx", "r15"} <= set(t["context"]))
            self.assertTrue(all(v.startswith("0x") for v in t["context"].values()))
        self.assertIn("waiting", {t["state"] for t in threads["threads"]})      # the fixture sleeps between polls

    def test_observe_sends_enter_and_return_and_counts_every_hit(self):
        go = Path(self.dir.name) / "go"
        agent = self.start("hits", 5, go)
        agent.handle("resume", {})
        hook = self.observe(agent)["hook_id"]
        go.write_text("go")
        events = self.until("three enters and returns", lambda: (lambda e: e if sum(x["event"] == "return" for x in e) >= 3 else None)(
            self.payloads(agent, hook)))
        entered = [e for e in events if e["event"] == "enter"]
        self.assertEqual([e["hit"] for e in entered], [1, 2, 3])
        base = self.base(agent)
        for index, e in enumerate(entered):
            self.assertEqual(int(e["arguments"][0], 16), index)                      # fx_hit(i)
            self.assertEqual(e["address"], hex(base + self.site_rva))
            self.assertTrue(e["backtrace"])
        returns = [e for e in events if e["event"] == "return"]
        mask = 2 ** 64 - 1
        want = []
        for i in range(3):
            v = (i * 0x9E3779B97F4A7C15) & mask
            want.append((((v << 13) | (v >> 51)) & mask) ^ i)
        self.assertEqual([int(r["value"], 16) for r in returns], want)
        script = agent.scripts[hook]["handle"]
        self.until("all five hits counted", lambda: script.exports_sync.counters()["seen"] == 5)
        self.assertEqual(script.exports_sync.counters(), {"seen": 5, "hits": 3, "limit": 3})
        time.sleep(0.2)
        self.assertEqual(len([e for e in self.payloads(agent, hook) if e["event"] == "enter"]), 3)   # the limit holds
        agent.handle("unload", {"hook_id": hook})
        self.assertEqual(self.device._live[agent.pid].site_status(48)[0], 3)        # the site is retired

    def test_a_wrong_prologue_is_refused_before_any_byte_changes(self):
        agent = self.start("hits", 1, Path(self.dir.name) / "never")
        agent.handle("resume", {})
        with self.assertRaisesRegex(ValueError, "PROLOGUE MISMATCH"):
            self.observe(agent, expect="90 90 90 90 90")
        self.assertEqual(agent.scripts, {})

    def test_break_parks_the_thread_until_continue(self):
        agent = self.start("pause")
        hook = self.observe(agent, action="break", limit=1)["hook_id"]
        agent.handle("resume", {})
        event = self.until("a break event", lambda: next((e for e in self.payloads(agent, hook) if e["event"] == "break"), None))
        self.assertEqual(int(event["arguments"][0], 16), 7)
        self.assertEqual(agent.handle("status", {})["paused_hooks"], [hook])
        time.sleep(0.4)
        self.assertFalse(agent.session.exited(), "the thread is parked, so the target cannot finish")
        agent.handle("continue", {"hook_id": hook})
        self.wait_gone(agent)
        self.assertEqual(self.device._live[agent.pid].exit_code(), 0)

    def test_write_compare_and_swap_undo_and_divergence(self):
        agent = self.start("write")
        agent.handle("resume", {})
        address = hex(self.base(agent) + self.cell_rva)

        def q(v):
            return " ".join("%02X" % b for b in v.to_bytes(8, "little"))

        def write(**o):
            return agent.handle("write", {"_gate": self.gate(agent), "address": address, "reason": "set the fixture cell", **o})

        with self.assertRaisesRegex(ValueError, "CAS MISMATCH"):
            write(expect=q(0x9999), bytes=q(1))
        done = write(expect=q(0x1111), bytes=q(0x2222))
        self.assertTrue(done["written"])
        self.assertEqual(agent.control.exports_sync.read(address, 8), list((0x2222).to_bytes(8, "little")))
        undone = agent.handle("write", {"_gate": self.gate(agent), "op": "undo"})
        self.assertTrue(undone["undone"], undone)
        self.assertEqual(agent.control.exports_sync.read(address, 8), list((0x1111).to_bytes(8, "little")))
        first = write(expect=q(0x1111), bytes=q(0x2222))
        write(expect=q(0x2222), bytes=q(0x4444))                                      # someone else moves it on
        stale = agent.handle("write", {"_gate": self.gate(agent), "op": "undo", "id": first["entry"]["id"]})
        self.assertFalse(stale["undone"])
        self.assertEqual(stale["status"], "DIVERGED")
        write(expect=q(0x4444), bytes=q(0x3333))                                      # lets the fixture finish
        self.wait_gone(agent)

    def test_watch_arms_every_thread_reads_back_and_ends_clear(self):
        agent = self.start("write")
        agent.handle("resume", {})
        address = hex(self.base(agent) + self.cell_rva)
        gate = self.gate(agent)
        armed = agent.handle("watch", {"_gate": gate, "op": "arm", "address": address, "size": 8, "reason": "watch the fixture cell"})["watch"]
        self.assertEqual(armed["state"], "armed")
        self.assertTrue(armed["threads"])
        readback = agent.memory_script.exports_sync.readback()
        self.assertEqual({t["id"] for t in readback["threads"] if armed["slot"] in t["enabled_slots"]}, set(armed["threads"]))
        done = agent.handle("watch", {"_gate": gate, "op": "disarm", "watch": armed["id"]})
        self.assertEqual(done["state"], "clear", done)
        self.assertEqual(done["watch"]["verified"]["still_enabled"], [])
        self.assertEqual(agent.tainted, "")
        again = agent.handle("watch", {"_gate": gate, "op": "arm", "address": address, "size": 8, "reason": "arm the slot again"})["watch"]
        self.assertEqual(again["slot"], armed["slot"], "a clear slot is reused")
        agent.handle("watch", {"_gate": gate, "op": "disarm", "watch": again["id"]})

    def test_watch_sees_writes_from_old_and_new_threads(self):
        agent = self.start("watch", 3000)
        agent.handle("resume", {})
        address = hex(self.base(agent) + self.cell_rva)
        gate = self.gate(agent)
        armed = agent.handle("watch", {"_gate": gate, "op": "arm", "address": address, "size": 8, "reason": "watch the fixture cell"})["watch"]
        # The late thread is created by the fixture some time after arming (0.8 s on a quiet machine, longer under load):
        # rearm until it is covered, bounded, rather than once after a fixed sleep.
        added = self.until("the thread created after arming is covered by rearm",
                           lambda: (lambda r: r if r["added"] else None)(
                               agent.handle("watch", {"_gate": gate, "op": "rearm", "watch": armed["id"]})), 30)
        self.assertTrue(added["added"], "the thread created after arming is covered by rearm")
        self.until("six writes seen", lambda: agent.handle("watch", {"_gate": gate, "op": "list"})["watches"][0]["hits"] >= 6, 30)
        done = agent.handle("watch", {"_gate": gate, "op": "disarm", "watch": armed["id"]})
        self.assertEqual(done["state"], "clear", done)
        self.assertEqual(done["watch"]["hits"], 6)
        self.assertEqual(done["watch"]["seen"], 6)


if __name__ == "__main__":
    unittest.main()
