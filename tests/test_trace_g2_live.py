"""Gate M1 extras, live (Frida + MSVC fixtures, the real engine): per-source health, payload mode, a real ETW capture.

* per-source observer health: the stop result names each source (producer ring, encoder, ETW, watchdog) with its own counters;
* metadata mode: no payload text reaches the events or the export (the authorized-range cases are in test_trace_capture.py);
* ETW: with an elevated token a real `hydra-etw` consumer records the fixture's process tree; its segment is verified,
  ingested through the engine and queried. Without elevation the refusal is visible (tests/test_trace_e2e.py).

Run elevated for the ETW test (`Start-Process -Verb RunAs`); it skips otherwise.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fixtures"))
sys.path.insert(0, str(HERE.parent / "src"))

import trace_fixtures as tf  # noqa: E402
import trace_gate_support as g  # noqa: E402
from support import workdir  # noqa: E402

from hydralysis import trace_capture as tc  # noqa: E402

ELEVATED = bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False
LIVE = g.HAVE_ENGINE and g.HAVE_LIVE


def clean(events):
    return [{k: v for k, v in e.items() if k not in ("hash", "n", "prev")} for e in events]


@unittest.skipUnless(LIVE, "needs a trace engine, Frida and MSVC")
class M1Extras(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import trace_live
        cls.tl = trace_live
        cls.work = workdir("trace-g2-live")
        cls.root = Path(cls.work.name)
        cls.fx = tf.build_group("frameloop", cls.root / "fx", ("x64",))["x64"]["dir"]
        cls.trace_app = tf.build_group("trace_app", cls.root / "fx2", ("x64",))["x64"]["dir"]
        cls.lives = []
        cls.engine = g.Engine("g2live")

    @classmethod
    def tearDownClass(cls):
        for live in cls.lives:
            live.close()
        cls.engine.close()
        cls.work.cleanup()

    def traced(self, directory, exe, argv, **trace):
        specs, _ = self.tl.specs_for(directory, [exe])
        live = self.tl.Live(self.root / "runs", directory / exe, argv, linger_ms=600)
        self.lives.append(live)
        live.start(specs, **trace)
        live.resume()
        self.assertTrue(live.wait_exit(90))
        time.sleep(0.3)
        return live

    def test_every_source_reports_its_own_health(self):
        live = self.traced(self.fx, "frameloop.exe", ["--frames=20"])
        trace = live.stop()["trace"]
        health = trace["health"]
        for source in ("producer", "encoder"):
            self.assertIn(source, health, health)
        self.assertEqual(health["producer"]["dropped"], 0)
        self.assertEqual(health["encoder"]["records"], health["producer"]["attempted"])
        self.assertIn("watchdog", trace)
        self.assertIn("etw", trace)                       # present even when the source was not asked for
        self.assertTrue(health["claims"]["fault_free"])

    @unittest.skipUnless(ELEVATED, "needs an elevated token (run this file with Start-Process -Verb RunAs)")
    def test_a_real_etw_capture_of_the_fixture_tree_is_ingested_and_queried(self):
        live = self.traced(self.fx, "frameloop.exe", ["--frames=40"], etw=True)
        stopped = live.stop()["trace"]
        etw = stopped["etw"]
        self.assertEqual(etw["start"]["state"], "running", etw)
        self.assertEqual(etw["stop"]["state"], "stopped", etw)
        segment = Path(live.agent.trace.directory) / "etw.seg"
        self.assertTrue(segment.is_file(), "the consumer wrote no segment")
        segment_id = "%s/etw/1" % live.agent.trace.session
        self.assertEqual(tc.verify_segment(segment, segment_id)["outcome"], "clean")
        events = clean(tc.read_events(segment, segment_id))
        self.assertGreater(len(events), 0, "an elevated ETW capture of a running process recorded nothing")
        name = g.unique("etw")
        self.engine.load(name, events, close=True)
        rows = self.engine.rows(name)
        self.assertEqual(len(rows), len(events))
        groups = self.engine.tool("query", name, group_by="kind")
        self.assertEqual(sum(group["count"] for group in groups["groups"]), len(events), groups)
        self.assertTrue(all(str(e["source_id"]).startswith("etw") or "etw" in str(e["source_id"]) for e in events[:50]),
                        {e["source_id"] for e in events[:5]})
        coverage = etw["coverage"]
        self.assertIn("complete", coverage)
        json.dumps(coverage)

    def test_metadata_mode_keeps_no_payload_text_and_the_export_omits_it(self):
        # the trace_app fixture writes the file name it is given: the buffer hook keeps `max` bytes of the name only when the
        # profile authorizes payload capture; the default (metadata) mode stores none of it
        work = self.root / "w-app"
        work.mkdir()
        meta = self.traced(self.trace_app, "trace_app.exe", [str(work), "A"])
        events = clean(tc.read_events(meta.segment, meta.segment_id))
        meta.stop()
        name = g.unique("meta")
        self.engine.load(name, events, close=True)
        exported = self.engine.tool("export", name, name="out")
        lines = (Path(exported["out"]) / "traces" / "events.jsonl").read_text(encoding="utf-8").splitlines()
        resources = [json.loads(line) for line in lines if '"core.resource.' in line]
        self.assertGreaterEqual(len(resources), 2)
        for row in resources:
            self.assertNotIn("w-app", json.dumps(row).lower(), "the export keeps no path text of a resource event")


if __name__ == "__main__":
    unittest.main()
