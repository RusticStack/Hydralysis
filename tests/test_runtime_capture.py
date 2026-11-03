"""Runtime capture: the durable event log, counters, capture windows with coverage, export-name hooks (Z10).

Everything here runs on the fake frida binding (tests/fakefrida): no process is started and nothing is injected.
The real-process side is tests/fixtures/verify_fixtures.py (`capture`, `export_hook`, `break_continue`), which needs
MSVC and the pinned Frida and is not run by CI.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fakefrida.harness import attached_agent
from hydralysis import durable, evidence, runtime
from hydralysis import runtime_capture as capture
from hydralysis.runtime_events import (EventLog, LOG_NAME, _frame, genesis_hash, iter_records, read_events,
                                       record_hash, verify_log)
from hydralysis.runtime_exports import export_table, resolve_export
from support import workdir

SESSION = "a" * 32
CAPTURE_ID = re.compile(r"^cap_[0-9a-f]{64}$")


def messages(log, count, event="enter", pad=0, script="hook"):
    for index in range(count):
        message = {"type": "send", "payload": {"event": event, "hook_id": script, "hit": index + 1, **({"pad": "x" * pad} if pad else {})}}
        log.count_message(script, message, False)
        log.record(script, message)


class Case(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("capture")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "runtime-sessions" / SESSION
        self.directory.mkdir(parents=True)


class EventChain(Case):
    def logged(self, count=5, **options):
        log = EventLog(self.directory, SESSION, **options)
        self.addCleanup(log.close)
        messages(log, count)
        log.close()
        return log

    def lines(self):
        return (self.directory / LOG_NAME).read_bytes().split(b"\n")[:-1]

    def rewrite(self, lines):
        (self.directory / LOG_NAME).write_bytes(b"".join(line + b"\n" for line in lines))

    def test_a_clean_log_verifies_and_ends_at_the_loggers_head(self):
        log = self.logged(5)
        result = verify_log(self.directory, SESSION)
        self.assertTrue(result["ok"], result)
        self.assertEqual((result["records"], result["last_sequence"], result["head"]), (5, 5, log.head))
        self.assertEqual(genesis_hash(SESSION), json.loads(self.lines()[0][9:])["prev"])
        self.assertNotEqual(genesis_hash(SESSION), genesis_hash("b" * 32))

    def test_the_log_is_the_durable_frame_format(self):
        self.logged(3)
        scanned = durable.scan_file(self.directory / LOG_NAME)
        self.assertEqual([record["n"] for record in scanned.records], [1, 2, 3])
        self.assertIsNone(scanned.corrupt)

    def test_a_flipped_byte_fails_the_crc(self):
        self.logged(4)
        data = bytearray((self.directory / LOG_NAME).read_bytes())
        data[len(self.lines()[0]) + 40] ^= 0x01
        (self.directory / LOG_NAME).write_bytes(bytes(data))
        result = verify_log(self.directory, SESSION)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"]["after_sequence"], 1)

    def test_an_edited_record_with_a_valid_crc_fails_its_hash(self):
        self.logged(4)
        lines = self.lines()
        record = json.loads(lines[1][9:])
        record["message"]["payload"]["hit"] = 99
        lines[1] = _frame(record).rstrip(b"\n")
        self.rewrite(lines)
        result = verify_log(self.directory, SESSION)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"]["sequence"], 2)
        self.assertIn("hash", result["first_bad"]["reason"])

    def test_a_removed_record_breaks_the_chain(self):
        self.logged(5)
        lines = self.lines()
        del lines[2]
        self.rewrite(lines)
        result = verify_log(self.directory, SESSION)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"]["sequence"], 4)
        self.assertIn("missing", result["first_bad"]["reason"])

    def test_reordered_records_are_found(self):
        self.logged(5)
        lines = self.lines()
        lines[1], lines[2] = lines[2], lines[1]
        self.rewrite(lines)
        self.assertFalse(verify_log(self.directory, SESSION)["ok"])

    def test_a_record_rehashed_after_an_edit_still_breaks_the_next_one(self):
        self.logged(4)
        lines = self.lines()
        record = json.loads(lines[1][9:])
        record["message"]["payload"]["hit"] = 99
        record["hash"] = record_hash(record)
        lines[1] = _frame(record).rstrip(b"\n")
        self.rewrite(lines)
        result = verify_log(self.directory, SESSION)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"]["sequence"], 3)

    def test_a_torn_tail_is_reported_and_is_not_a_failure(self):
        self.logged(4)
        data = (self.directory / LOG_NAME).read_bytes()
        (self.directory / LOG_NAME).write_bytes(data[:-20])
        result = verify_log(self.directory, SESSION)
        self.assertTrue(result["ok"])
        self.assertTrue(result["torn_tail"])
        self.assertEqual(result["records"], 3)
        self.assertEqual([event["sequence"] for event in read_events(self.directory, limit=10)["events"]], [1, 2, 3])

    def test_a_flipped_byte_in_the_last_record_is_corrupt_not_torn(self):
        self.logged(5)
        data = bytearray((self.directory / LOG_NAME).read_bytes())
        self.assertEqual(data[-1:], b"\n")
        data[-12] ^= 0x01                      # inside the last, complete, LF-terminated record
        (self.directory / LOG_NAME).write_bytes(bytes(data))
        result = verify_log(self.directory, SESSION)
        self.assertFalse(result["ok"])
        self.assertNotIn("torn_tail", result)
        self.assertEqual(result["first_bad"]["after_sequence"], 4)
        self.assertEqual(result["records"], 4)
        self.assertEqual([error for _, error in iter_records(self.directory / LOG_NAME)][-1], "corrupt")
        self.assertEqual(read_events(self.directory, limit=10)["log_problem"], "corrupt")

    def test_a_last_line_without_its_lf_is_torn_whether_or_not_it_parses(self):
        self.logged(3)
        path = self.directory / LOG_NAME
        data = path.read_bytes()
        path.write_bytes(data[:-1])            # a complete record that lost only its LF
        result = verify_log(self.directory, SESSION)
        self.assertTrue(result["ok"])
        self.assertTrue(result["torn_tail"])
        self.assertEqual(result["records"], 2)

    def test_the_log_for_another_session_does_not_verify(self):
        self.logged(3)
        self.assertFalse(verify_log(self.directory, "b" * 32)["ok"])

    def test_counters_stay_true_when_the_record_is_incomplete(self):
        log = EventLog(self.directory, SESSION, ring_events=5, log_max_bytes=3000)
        self.addCleanup(log.close)
        messages(log, 40, pad=300)
        counters = log.counters_copy()
        self.assertEqual(counters["messages"], 40)
        self.assertEqual(counters["by_event"], {"enter": 40})
        self.assertEqual(counters["by_script"]["hook"]["seen"], 40)
        self.assertEqual(counters["ring_evicted"], 35)
        self.assertEqual(log.dropped, 35)
        self.assertTrue(log.full)
        self.assertGreater(counters["log_full_dropped"], 0)
        self.assertLess(counters["recorded"], 40)
        self.assertEqual(counters["recorded"] + counters["log_full_dropped"], 40 + 1)  # the log_full marker is a record
        log.close()
        result = verify_log(self.directory, SESSION)
        self.assertTrue(result["ok"], result)
        kinds = [record["type"] for record, _ in iter_records(self.directory / LOG_NAME)]
        self.assertEqual(kinds[-1], "log_full")

    def test_a_failed_write_leaves_a_hole_the_chain_reports(self):
        log = EventLog(self.directory, SESSION)
        self.addCleanup(log.close)
        messages(log, 2)
        with patch("hydralysis.runtime_events.os.write", side_effect=OSError(28, "no space")):
            messages(log, 1)
        messages(log, 2)
        log.close()
        self.assertEqual(log.counters["log_failed"], 1)
        self.assertIn("no space", log.error)
        result = verify_log(self.directory, SESSION)
        self.assertFalse(result["ok"])
        self.assertEqual(result["first_bad"]["sequence"], 4)

    def test_a_clipped_message_is_counted_by_what_it_said(self):
        agent, *_ = self.agent()
        agent.message("hook", {"type": "send", "payload": {"event": "enter", "hook_id": "hook", "pad": "x" * 10000}})
        counters = agent.log.counters_copy()
        self.assertEqual(counters["clipped"], 1)
        self.assertEqual(counters["by_event"].get("enter"), 1)
        self.assertEqual(agent.events[-1][0]["message"]["type"], "truncated")

    def agent(self, **options):
        agent, exe, digest, head = attached_agent(self.directory, **options)
        self.addCleanup(lambda: (agent.cleanup() if not agent.closed else None))
        return agent, exe, digest, head


class AgentCase(Case):
    def setUp(self):
        super().setUp()
        self.agent, self.exe, self.digest, self.head = attached_agent(self.directory)
        self.addCleanup(self.close_agent)

    def close_agent(self):
        if not self.agent.closed:
            try:
                self.agent.cleanup()
            except Exception:
                self.agent.log.close()

    def hook(self, kind="observe", limit=20, **extra):
        return self.agent.handle(kind, {"module": Path(self.exe).name, "rva": "0x0", "sha256": self.digest,
                                        "expect": self.head, "limit": limit, **extra})

    def start(self, name="window"):
        return self.agent.handle("capture", {"op": "start", "name": name})

    def stop(self):
        return self.agent.handle("capture", {"op": "stop"})

    def environment(self, **values):
        patcher = patch.dict(os.environ, values)
        patcher.start()
        self.addCleanup(patcher.stop)


class CaptureWindow(AgentCase):
    def test_a_capture_that_saw_everything_is_complete_and_names_its_limits(self):
        started = self.start()
        self.assertRegex(started["capture"], CAPTURE_ID)
        self.hook(limit=20)
        closed = self.stop()
        self.assertEqual(closed["state"], "closed")
        self.assertEqual(closed["coverage"]["status"], "complete")
        self.assertEqual(closed["limitations"], ["single_run"])
        row = closed["hooks"][0]
        self.assertEqual((row["seen"], row["recorded"], row["lost"]), (1, 1, 0))
        self.assertEqual(closed["capture"], started["capture"])
        self.assertEqual(closed["evidence"]["from_capture"], started["capture"])
        self.assertEqual(closed["evidence"]["subject_sha256"], self.digest)
        self.assertEqual(len(closed["evidence"]["parameters"]["script_sha256"]), 1)

    def test_a_probe_past_its_limit_makes_the_capture_partial_and_never_complete(self):
        self.environment(HYDRALYSIS_FAKE_HITS="5")
        self.start()
        self.hook(limit=3)
        closed = self.stop()
        row = closed["hooks"][0]
        self.assertEqual((row["seen"], row["recorded"], row["lost"], row["limit_reached"]), (5, 3, 2, True))
        self.assertEqual(closed["coverage"], {"status": "partial", "limitations": ["hit_limit_reached"]})
        # the ledger refuses what the capture refuses to claim
        with self.assertRaisesRegex(ValueError, "bounds what it covers"):
            evidence.add_claim(self.root / "ledger.sqlite", game="t", build="1", kind="note", name="x", note="n", source="s",
                               coverage="complete", limitations=["hit_limit_reached"])

    def test_the_evidence_block_goes_into_the_ledger_as_it_is(self):
        self.environment(HYDRALYSIS_FAKE_HITS="5")
        self.start()
        self.hook(limit=3)
        block = self.stop()["evidence"]
        ledger = self.root / "ledger.sqlite"
        claim = dict(game="t", build="1", kind="note", name="x", note="a capture", source="runtime capture", **block)
        first = evidence.add_claim(ledger, **claim)
        self.assertRegex(first, r"stored .* evidence_id=ev_[0-9a-f]{64}$")
        again = evidence.add_claim(ledger, **claim)       # the same claim twice is one row
        self.assertIn("already stored", again)
        self.assertEqual(first.rsplit("evidence_id=", 1)[1], again.rsplit("evidence_id=", 1)[1])

    def test_every_code_a_capture_can_state_is_one_the_ledger_knows(self):
        for code in capture.BOUNDING:
            evidence.check_limitation_code(code)
            self.assertTrue(evidence.bounds_coverage(code), code)
        self.assertFalse(evidence.bounds_coverage("single_run"))

    def test_a_sampling_probe_makes_the_capture_partial(self):
        self.start()
        self.hook(capture=[{"arg": 1, "as": "f32"}], sample={"window_s": 10, "capture": 0})
        closed = self.stop()
        self.assertEqual(closed["coverage"], {"status": "partial", "limitations": ["sampled"]})
        self.assertTrue(closed["hooks"][0]["sampled"])

    def test_a_capture_with_no_probe_says_it_knows_nothing(self):
        self.start()
        closed = self.stop()
        self.assertEqual(closed["coverage"]["status"], "unknown")
        self.assertIn("no probe", closed["coverage"]["reason"])
        self.assertIn("coverage_unknown", closed["limitations"])

    def test_a_probe_that_cannot_count_makes_the_capture_partial(self):
        self.environment(HYDRALYSIS_FAKE_NO_COUNTERS="1")
        self.start()
        self.hook()
        closed = self.stop()
        self.assertEqual(closed["coverage"], {"status": "partial", "limitations": ["runtime:counters_unavailable"]})
        self.assertIn("counters_unavailable", closed["hooks"][0])

    def test_only_what_happened_inside_the_window_counts(self):
        self.environment(HYDRALYSIS_FAKE_HITS="5")
        self.hook(limit=3)            # already past its limit before the window opens
        self.start()
        closed = self.stop()
        row = closed["hooks"][0]
        self.assertEqual((row["seen"], row["recorded"], row["lost"]), (0, 0, 0))
        self.assertEqual(closed["coverage"]["status"], "complete")

    def test_a_probe_unloaded_inside_the_window_keeps_its_counters(self):
        self.environment(HYDRALYSIS_FAKE_HITS="2")
        self.start()
        probe = self.hook(limit=20)
        self.agent.handle("unload", {"hook_id": probe["hook_id"]})
        closed = self.stop()
        row = closed["hooks"][0]
        self.assertEqual((row["seen"], row["recorded"]), (2, 2))
        self.assertEqual(closed["coverage"]["status"], "complete")

    def test_the_durable_log_keeps_what_the_ring_evicts(self):
        self.agent.cleanup()
        self.agent, *_ = attached_agent(self.directory.parent / ("b" * 32), ring_events=2)
        self.directory = self.agent.directory
        self.environment(HYDRALYSIS_FAKE_HITS="6")
        self.start()
        self.hook(limit=10)
        closed = self.stop()
        self.assertGreater(self.agent.dropped, 0)
        self.assertLessEqual(len(self.agent.events), 2)
        page = self.agent.handle("capture", {"op": "read", "capture": closed["capture"], "limit": 200})
        enters = [event for event in page["events"] if (event["message"].get("payload") or {}).get("event") == "enter"]
        self.assertEqual(len(enters), 6)
        self.assertEqual(closed["coverage"]["status"], "complete")
        self.assertNotIn("event_ring_overflow", closed["limitations"])

    def test_a_clipped_payload_makes_the_capture_partial(self):
        self.start()
        probe = self.hook(limit=20)
        self.agent.message(probe["hook_id"], {"type": "send", "payload": {"event": "log", "hook_id": probe["hook_id"], "pad": "x" * 10000}})
        closed = self.stop()
        self.assertEqual(closed["counters"]["clipped"], 1)
        self.assertEqual(closed["coverage"], {"status": "partial", "limitations": ["payload_clipped"]})
        self.assertIn("payload_clipped", closed["limitations"])
        self.assertIn("payload_clipped", closed["evidence"]["limitations"])

    def test_clipped_data_makes_the_capture_partial_too(self):
        self.start()
        probe = self.hook(limit=20)
        self.agent.message(probe["hook_id"], {"type": "send", "payload": {"event": "log", "hook_id": probe["hook_id"]}}, data=bytes(2000))
        closed = self.stop()
        self.assertEqual(closed["coverage"], {"status": "partial", "limitations": ["payload_clipped"]})

    def test_a_clipped_payload_before_the_window_does_not_count(self):
        probe = self.hook(limit=20)
        self.agent.message(probe["hook_id"], {"type": "send", "payload": {"event": "log", "hook_id": probe["hook_id"], "pad": "x" * 10000}})
        self.start()
        closed = self.stop()
        self.assertEqual(closed["counters"]["clipped"], 0)
        self.assertEqual(closed["coverage"]["status"], "complete")

    def test_a_failed_log_write_makes_the_capture_partial(self):
        self.start()
        probe = self.hook(limit=20)
        with patch("hydralysis.runtime_events.os.write", side_effect=OSError(28, "no space")):
            self.agent.message(probe["hook_id"], {"type": "send", "payload": {"event": "log", "hook_id": probe["hook_id"]}})
        closed = self.stop()
        self.assertEqual(closed["counters"]["log_failed"], 1)
        self.assertEqual(closed["coverage"], {"status": "partial", "limitations": ["runtime:event_log_write_failed"]})
        self.assertIn("runtime:event_log_write_failed", closed["evidence"]["limitations"])
        with self.assertRaisesRegex(ValueError, "bounds what it covers"):
            evidence.add_claim(self.root / "ledger.sqlite", game="t", build="1", kind="note", name="x", note="n", source="s",
                               coverage="complete", limitations=closed["limitations"])

    def test_a_full_log_makes_the_capture_partial(self):
        self.agent.cleanup()
        self.agent, *_ = attached_agent(self.directory.parent / ("c" * 32), log_max_bytes=6000)
        self.environment(HYDRALYSIS_FAKE_HITS="30")
        self.start()
        self.hook(limit=30)
        closed = self.stop()
        self.assertIn("runtime:event_log_full", closed["coverage"]["limitations"])
        self.assertEqual(closed["state"], "closed")
        self.assertTrue(capture.verify_capture(self.agent.directory, self.agent.directory.name,
                                               {"capture": closed["capture"]})["ok"])

    def test_one_capture_at_a_time_and_stop_needs_an_open_one(self):
        with self.assertRaisesRegex(ValueError, "no capture is open"):
            self.stop()
        self.start()
        with self.assertRaisesRegex(ValueError, "is open; stop it first"):
            self.start("second")
        with self.assertRaisesRegex(ValueError, "the open capture is"):
            self.agent.handle("capture", {"op": "stop", "capture": "other"})
        self.stop()

    def test_bad_options_are_refused(self):
        for options, message in (({"op": "start", "name": "a b"}, "name is"), ({"op": "nope"}, "capture op is one of"),
                                 ({"op": "start", "colour": 1}, "unknown capture options")):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, message):
                self.agent.handle("capture", options)

    def test_detach_seals_an_open_capture_while_its_probes_can_still_count(self):
        self.environment(HYDRALYSIS_FAKE_HITS="2")
        started = self.start()
        self.hook()
        self.agent.handle("detach", {})
        record = capture.read_capture(self.directory, {"capture": started["capture"], "limit": 5})
        self.assertEqual(record["state"], "closed")
        self.assertEqual(record["hooks"][0]["seen"], 2)

    def test_read_pages_the_window_and_stays_inside_it(self):
        self.environment(HYDRALYSIS_FAKE_HITS="6")
        self.hook(limit=10)                       # before the window: not part of it
        started = self.start()
        self.hook(limit=10)
        closed = self.stop()
        self.agent.message("hook", {"type": "send", "payload": {"event": "enter", "hook_id": "after"}})
        first = capture.read_capture(self.directory, {"capture": started["capture"], "limit": 3})
        second = capture.read_capture(self.directory, {"capture": started["capture"], "after": first["next_after"], "limit": 200})
        sequences = [event["sequence"] for event in first["events"] + second["events"]]
        self.assertTrue(first["truncated"])
        self.assertEqual(sequences, sorted(set(sequences)))
        self.assertTrue(all(closed["from_sequence"] < n < closed["to_sequence"] for n in sequences))
        self.assertEqual(len([e for e in first["events"] + second["events"]
                              if (e["message"].get("payload") or {}).get("event") == "enter"]), 6)
        with self.assertRaisesRegex(ValueError, "not before the capture's start"):
            capture.read_capture(self.directory, {"capture": started["capture"], "after": 0})

    def test_verify_checks_the_capture_markers_and_finds_tampering(self):
        started = self.start()
        self.hook()
        closed = self.stop()
        self.agent.log.close()
        good = capture.verify_capture(self.directory, SESSION_OF(self.directory), {"capture": closed["capture"]})
        self.assertTrue(good["ok"], good)
        self.assertEqual(good["capture"], started["capture"])
        path = self.directory / LOG_NAME
        data = bytearray(path.read_bytes())
        data[60] ^= 0x01
        path.write_bytes(bytes(data))
        self.assertFalse(capture.verify_capture(self.directory, SESSION_OF(self.directory), {"capture": closed["capture"]})["ok"])

    def test_an_open_capture_reads_as_open_and_partial(self):
        started = self.start()
        self.hook()
        page = capture.read_capture(self.directory, {"capture": started["capture"]})
        self.assertEqual(page["state"], "open")
        self.assertEqual(page["coverage"], {"status": "partial", "limitations": ["runtime:capture_open"]})

    def test_list_names_the_session_captures_in_order(self):
        first = self.start("one")
        self.stop()
        second = self.start("two")
        self.stop()
        rows = capture.list_captures(self.directory)["captures"]
        self.assertEqual([row["capture"] for row in rows], [first["capture"], second["capture"]])
        self.assertEqual([row["name"] for row in rows], ["one", "two"])
        self.assertEqual(capture._find(self.directory, "two")["capture"], second["capture"])

    def test_state_is_published_at_a_bounded_rate_not_per_message(self):
        import time
        with patch.object(self.agent, "publish", wraps=self.agent.publish) as publish:
            for index in range(300):
                self.agent.message("hook", {"type": "send", "payload": {"event": "enter", "hook_id": "hook", "hit": index}})
            time.sleep(0.6)
        self.assertLess(publish.call_count, 6)
        state = json.loads((self.directory / "state.json").read_text())
        self.assertEqual(state["last_sequence"], self.agent.sequence)
        self.assertEqual(state["messages_seen"], self.agent.log.counters["messages"])

    def test_counters_op_reports_the_probes_own_counts(self):
        self.environment(HYDRALYSIS_FAKE_HITS="5")
        probe = self.hook(limit=3)
        report = self.agent.handle("capture", {"op": "counters"})
        self.assertEqual(report["hooks"][probe["hook_id"]]["seen"], 5)
        self.assertEqual(report["counters"]["by_script"][probe["hook_id"]]["events"]["enter"], 3)
        self.assertEqual(self.agent.handle("status", {})["messages_seen"], report["counters"]["messages"])


def SESSION_OF(directory: Path) -> str:
    return directory.name


class HostSide(AgentCase):
    """The host reads captures and compares snapshots from the session folder; the owner alone starts and stops one."""

    def runner(self):
        return runtime.RuntimeRunner({"root": str(self.root)})

    def setUp(self):
        super().setUp()
        self.session = self.directory.name

    def test_new_actions_are_listed(self):
        for name in ("capture", "snapshot", "compare"):
            self.assertIn(name, runtime.ACTION_NAMES)
        self.assertNotIn("capture", runtime.MUTATING)

    def test_a_finished_session_can_still_be_read_and_verified(self):
        self.start()
        self.hook()
        closed = self.stop()
        self.agent.cleanup()
        runner = self.runner()
        read = runner.call("capture", {"session": self.session, "op": "read", "capture": closed["capture"]})
        self.assertEqual(read["state"], "closed")
        self.assertTrue(runner.call("capture", {"session": self.session, "op": "verify", "capture": closed["capture"]})["ok"])
        self.assertEqual(len(runner.call("capture", {"session": self.session, "op": "list"})["captures"]), 1)

    def test_starting_and_stopping_are_the_owners_but_looking_is_anyones(self):
        (self.directory / "ready.json").write_text(json.dumps({"pid": 1, "started_ms": 1, "ipc": {"port": 1, "token": "t"}}))
        (self.directory / "owner.json").write_text(json.dumps({"client": "c", "harness": "h", "since": "now",
                                                                "token_sha256": hashlib.sha256(b"secret").hexdigest()}))
        runner = self.runner()
        answered = {"ok": True, "result": {}}
        with patch("hydralysis.runtime._identity", return_value=True), \
             patch("hydralysis.runtime.ipc_request", return_value=answered) as ipc:
            for op in ("start", "stop"):
                with self.assertRaises(PermissionError):
                    runner.call("capture", {"session": self.session, "op": op})
            self.assertEqual(ipc.call_count, 0)
            runner.call("snapshot", {"session": self.session})
            runner.call("capture", {"session": self.session, "op": "counters"})
            runner.call("capture", {"session": self.session, "op": "start", "owner": "secret"})
        self.assertEqual(ipc.call_count, 3)


class ExportHooks(unittest.TestCase):
    """A hook named by export is resolved from the module FILE's export table and checked again by the probe."""

    DLL = Path(sys.base_prefix) / ("python%d%d.dll" % sys.version_info[:2])

    def setUp(self):
        if not self.DLL.is_file():
            self.skipTest("no %s to read an export table from" % self.DLL)
        from hydralysis.runtime_worker import RuntimeAgent, _call_in_span, file_bytes
        self.temp = workdir("exports")
        self.addCleanup(self.temp.cleanup)
        self.digest = hashlib.sha256(self.DLL.read_bytes()).hexdigest()
        self.module = {"name": self.DLL.name, "path": str(self.DLL), "base": "0x10000000", "size": 0x7FFFFFF}
        from hydralysis.pe import Image
        self.image = Image(self.DLL)
        # An export whose first bytes hold no call (a probe cannot cover one), found in the file's own table.
        table = export_table(self.image)
        self.NAME = next(row["name"] for row in sorted(table, key=lambda row: row["name"] or "") if row["name"] and not row["forwarder"]
                         and row["name"].startswith("Py") and _call_in_span(str(self.DLL), row["rva"]) is None)
        self.rva = resolve_export(table, self.NAME)["rva"]
        self.agent = RuntimeAgent(Path(self.temp.name), Mock())
        self.agent.session = Mock()
        self.agent.control = Mock()
        self.agent.control.exports_sync.module.return_value = self.module
        self.loaded = list(file_bytes(str(self.DLL), self.rva, 8, 0x10000000))
        self.agent.control.exports_sync.read.return_value = self.loaded
        self.script = Mock()
        self.script.exports_sync.status.return_value = {"installed": True}
        self.agent.session.create_script.return_value = self.script
        self.agent.state = "running"
        self.addCleanup(self.agent.log.close)

    def hook(self, **extra):
        return self.agent.handle("observe", {"module": self.DLL.name, "sha256": self.digest, **extra})

    def test_the_export_name_alone_is_enough_and_is_checked_by_the_probe(self):
        result = self.hook(export=self.NAME)
        self.assertTrue(result["verified"])
        self.assertEqual(result["rva"], hex(self.rva))
        self.assertEqual(result["export"]["name"], self.NAME)
        self.assertEqual(result["expect_source"], "file")
        source = self.agent.session.create_script.call_args.args[0]
        self.assertIn('"export": "%s"' % self.NAME, source)
        self.assertIn("getExportByName(p.export)", source)
        self.assertLess(source.index("EXPORT MISMATCH"), source.index("Interceptor.attach"))
        self.agent.control.exports_sync.read.assert_called_with(hex(0x10000000 + self.rva), 8)

    def test_a_given_expect_and_rva_must_agree_with_the_table(self):
        given = " ".join("%02X" % byte for byte in self.loaded)
        self.assertEqual(self.hook(export=self.NAME, expect=given, rva=hex(self.rva))["expect_source"], "caller")
        with self.assertRaisesRegex(ValueError, "is at rva .* in the module's file"):
            self.hook(export=self.NAME, rva=hex(self.rva + 16))

    def test_a_site_that_differs_from_the_file_is_refused(self):
        self.agent.control.exports_sync.read.return_value = [0xCC] * 8
        with self.assertRaisesRegex(ValueError, "PROLOGUE MISMATCH"):
            self.hook(export=self.NAME)
        self.agent.session.create_script.assert_not_called()

    def test_an_export_the_file_does_not_have_is_refused_with_what_it_has(self):
        with self.assertRaisesRegex(ValueError, "no export %s .*similar: " % self.NAME[:-1]):
            self.hook(export=self.NAME[:-1])
        self.agent.session.create_script.assert_not_called()

    def test_a_wrong_build_hash_still_refuses(self):
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.agent.handle("observe", {"module": self.DLL.name, "sha256": "1" * 64, "export": self.NAME})

    def test_resolution_refuses_forwards_duplicates_and_odd_names(self):
        table = [{"name": "A", "ordinal": 1, "rva": 0x1000, "forwarder": None},
                 {"name": "F", "ordinal": 2, "rva": 0x2000, "forwarder": "OTHER.F"},
                 {"name": "D", "ordinal": 3, "rva": 0x3000, "forwarder": None}, {"name": "D", "ordinal": 4, "rva": 0x4000, "forwarder": None},
                 {"name": None, "ordinal": 9, "rva": 0x5000, "forwarder": None}]
        self.assertEqual(resolve_export(table, "A")["rva"], 0x1000)
        self.assertEqual(resolve_export(table, "#9")["rva"], 0x5000)
        for name, message in (("F", "forward to OTHER.F"), ("D", "listed 2 times"), ("Z", "no export Z"),
                              ("#x", "ordinal is written"), ("bad name", "printable ASCII"), ("", "printable ASCII")):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                resolve_export(table, name)

    def test_the_fake_probe_checks_the_table_too(self):
        from fakefrida.harness import load_fake
        fake = load_fake()
        session = fake.Session(os.getpid(), str(self.DLL))
        site = self.rva + 16
        script = fake.Script(session, "const p=" + json.dumps({"rva": site, "expect": session.read(fake.BASE + site, 5), "id": "x",
                                                              "export": self.NAME, "pause": False, "limit": 1, "captures": []}) + ";")
        with self.assertRaisesRegex(RuntimeError, "EXPORT MISMATCH"):
            script.load()


class CaptureOverMCP(unittest.TestCase):
    """The same actions through the stdio server, a real worker process and its authenticated IPC (fake binding)."""

    @classmethod
    def setUpClass(cls):
        import shutil
        import subprocess
        import time
        from test_mcp_runtime import FAKE_FRIDA, Server
        cls.work = workdir("mcp-capture")
        cls.root = Path(cls.work.name)
        shutil.copytree(FAKE_FRIDA, cls.root / "runtime-backend" / "frida-17.24.3" / "frida")
        cls.exe = str(Path(sys.executable).resolve())
        cls.site_rva = "0x0"
        cls.go = None
        cls.rust = False
        from hydralysis.runtime_device import implementation
        if implementation() == "rust":
            # The fake binding invents its hits (HYDRALYSIS_FAKE_HITS); the Rust device runs the real probe, so it gets a
            # real target that calls the hooked function exactly five times once the probe is installed (a file says when).
            from hydralysis import rust_frida
            fixture = Path(os.environ.get("HYDRALYSIS_HY_FIXTURE") or rust_frida._RELEASE / "hy-fixture.exe")
            if not fixture.is_file():
                raise unittest.SkipTest("the Rust device needs hy-fixture.exe (cargo build --release in rust/)")
            cls.exe = str(fixture.resolve())
            info = dict(word.split("=", 1) for word in subprocess.run([cls.exe, "info"], capture_output=True, text=True,
                                                                      timeout=60).stdout.split())
            cls.site_rva = "0x" + info["RVA"]
            cls.head = " ".join(info["BYTES"][i:i + 2].upper() for i in range(0, 10, 2))
            cls.go = cls.root / "go"
            cls.target = subprocess.Popen([cls.exe, "hits", "5", str(cls.go)], stdin=subprocess.DEVNULL)
            cls.rust = True
        else:
            cls.head = " ".join("%02X" % byte for byte in Path(cls.exe).read_bytes()[:5])
            cls.target = subprocess.Popen([cls.exe, "-c", "import time;time.sleep(120)"], stdin=subprocess.DEVNULL)
        cls.digest = hashlib.sha256(Path(cls.exe).read_bytes()).hexdigest()
        cls.server = Server(cls.root, HYDRALYSIS_FAKE_HITS="5")
        cls.time = time

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        cls.target.kill()
        cls.target.wait(timeout=10)
        deadline = cls.time.monotonic() + 10
        while Path(cls.work.name).exists() and cls.time.monotonic() < deadline:
            cls.work.cleanup()
            cls.time.sleep(0.1)

    def call(self, action, **options):
        result, _ = self.server.tool("runtime", {"action": action, "options": options})
        text = result["content"][0]["text"]
        self.assertFalse(result["isError"], text[:1500])
        return json.loads(text)

    def test_capture_window_snapshot_and_compare_end_to_end(self):
        started = self.call("attach", exe=self.exe, sha256=self.digest, pid=self.target.pid)
        session, owner = started["session"], started["owner"]
        module = Path(self.exe).name
        try:
            self.call("capture", session=session, owner=owner, op="start", name="mcp")
            probe = self.call("observe", session=session, owner=owner, module=module, rva=self.site_rva, sha256=self.digest,
                              expect=self.head, limit=3)
            if self.rust:
                self.go.write_text("go")             # the target calls the hooked function five times now
                end = self.time.monotonic() + 30
                while self.time.monotonic() < end:
                    seen = self.call("status", session=session, limit=200)["events"]
                    if sum(1 for e in seen if (e["message"].get("payload") or {}).get("event") == "enter") >= 3:
                        break
                    self.time.sleep(0.05)
                self.time.sleep(0.3)                  # the fourth and fifth hits are counted, not recorded
            region = {"name": "head", "module": module, "rva": "0x0", "size": 16}
            first = self.call("snapshot", session=session, regions=[region])
            second = self.call("snapshot", session=session, regions=[region])
            closed = self.call("capture", session=session, owner=owner, op="stop")
            self.assertEqual(closed["coverage"], {"status": "partial", "limitations": ["hit_limit_reached"]})
            self.assertEqual((closed["hooks"][0]["seen"], closed["hooks"][0]["recorded"]), (5, 3))
            compared = self.call("compare", session=session, a=first["snapshot"], b=second["snapshot"],
                                 predicates=[{"path": "regions/head/sha256", "op": "unchanged"}])
            self.assertTrue(compared["equal"] and compared["ok"], compared)
            self.assertTrue(self.call("capture", session=session, op="verify", capture=closed["capture"])["ok"])
            self.assertEqual(self.call("status", session=session)["log"]["records"] > 0, True)
            self.call("unload", session=session, owner=owner, hook_id=probe["hook_id"])
        finally:
            self.call("detach", session=session, owner=owner)
        # the worker has ended; the record is still there
        read = self.call("capture", session=session, op="read", capture=closed["capture"], limit=200)
        self.assertEqual(read["state"], "closed")
        self.assertEqual(len([e for e in read["events"] if (e["message"].get("payload") or {}).get("event") == "enter"]), 3)


if __name__ == "__main__":
    unittest.main()
