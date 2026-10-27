import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from support import workdir
from test_pe import image

from hydralysis import cli
from hydralysis.client import Client, RusticError, parse


class LibraryAPI(unittest.TestCase):
    def setUp(self):
        self.work = workdir("client")
        self.addCleanup(self.work.cleanup)
        self.exe = str(Path(self.work.name) / "fixture.exe")
        Path(self.exe).write_bytes(image(b"\x55\x8b\xec" + b"\x90" * 28 + b"\xc3").data)
        self.re = Client()

    def test_static_answers_are_data(self):
        fingerprint = self.re.fingerprint(self.exe)
        self.assertEqual(len(fingerprint["sha256"]), 64)
        self.assertEqual(self.re.read(self.exe, "rva:0x1000", 3), b"\x55\x8b\xec")

    def test_a_mismatching_table_is_returned_not_raised(self):
        result = self.re.check_prologues(self.exe, [
            {"name": "ok", "address": "rva:0x1000", "expect": ["00", "55 8B ??"]},
            {"name": "moved", "address": "rva:0x1001", "expect": "55"},
        ])
        self.assertFalse(result["matched"])
        self.assertEqual([row["match"] for row in result["rows"]], [True, False])
        self.assertEqual(result["rows"][0]["matched_alternative"], 1)

    def test_long_tables_are_paged_into_one_answer(self):
        rows = [{"name": "r%d" % index, "address": "rva:0x1000", "expect": "55"} for index in range(450)]
        result = self.re.check_prologues(self.exe, rows)
        self.assertTrue(result["matched"])
        self.assertEqual(result["summary"], {"checked": 450, "matched": 450, "failed": 0})

    def test_refusals_keep_the_tool_contract(self):
        with self.assertRaisesRegex(RusticError, "SHA-256 mismatch"):
            self.re.check_prologues(self.exe, [{"address": "rva:0x1000", "expect": "55"}], sha256="0" * 64)
        with self.assertRaisesRegex(RusticError, "unknown tool"):
            self.re.call("frida")
        with self.assertRaisesRegex(RusticError, "size must be"):
            self.re.read(self.exe, "rva:0x1000", 0)

    def test_engine_refusals_are_structured(self):
        from unittest.mock import patch
        refusal = RuntimeError(json.dumps({"ok": False, "error_kind": "not_found", "error": "no analysed function"}))
        with patch("hydralysis.client.api.call", side_effect=refusal):
            self.assertIsNone(self.re.try_query("t", "function", "0x1"))
            with self.assertRaises(RusticError) as caught:
                self.re.query("t", "function", "0x1")
        self.assertEqual(caught.exception.result["error_kind"], "not_found")
        with patch("hydralysis.client.api.call", side_effect=RuntimeError(json.dumps({"ok": False, "error_kind": "timeout"}))),                 self.assertRaises(RusticError):
            self.re.try_query("t", "decompile", "0x1")

    def test_parse_leaves_text_answers_alone(self):
        self.assertEqual(parse(' {"a": 1}'), {"a": 1})
        self.assertEqual(parse("# exe x\nCC"), "# exe x\nCC")


class ImportSlots(unittest.TestCase):
    def test_each_import_names_its_iat_slot_and_a_pattern_filters(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        pe = image()
        entry = SimpleNamespace(dll=b"OPENGL32.dll", imports=[
            SimpleNamespace(name=b"glClear", ordinal=None, address=pe.base + 0x2010),
            SimpleNamespace(name=b"glFlush", ordinal=None, address=pe.base + 0x2014),
            SimpleNamespace(name=None, ordinal=7, address=pe.base + 0x2018)])
        with patch.object(pe.pe, "parse_data_directories"):
            pe.pe.DIRECTORY_ENTRY_IMPORT = [entry]
            listed = pe.imports_text(10)
            filtered = pe.imports_text(10, "glclear")
        self.assertIn("rva:0x2010 OPENGL32.dll glClear", listed)
        self.assertIn("rva:0x2018 OPENGL32.dll ord:7", listed)
        self.assertNotIn("glFlush", filtered)


class JsonCommandLine(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(list(argv))
        return code, json.loads(out.getvalue())

    def test_one_envelope_for_success_and_refusal(self):
        work = workdir("client-cli")
        self.addCleanup(work.cleanup)
        exe = Path(work.name) / "fixture.exe"
        exe.write_bytes(image().data)
        code, answer = self.run_cli("call", "prologue", "--args", json.dumps(
            {"exe": str(exe), "checks": [{"address": "rva:0x1000", "expect": "90"}]}))
        self.assertEqual((code, answer["ok"], answer["result"]["matched"]), (0, True, True))
        arguments = Path(work.name) / "args.json"
        arguments.write_text(json.dumps({"exe": str(exe), "address": "rva:0x1000", "size": 2}), encoding="utf-8")
        code, answer = self.run_cli("call", "bytes", "--args-file", str(arguments))
        self.assertTrue(answer["result"].endswith("90 90"))
        code, answer = self.run_cli("call", "prologue", "--args", json.dumps(
            {"exe": str(exe), "address": "rva:0x1000", "expect": "55"}))
        self.assertEqual(code, 1)
        self.assertFalse(answer["ok"])
        self.assertIn("PROLOGUE MISMATCH", answer["error"])


class EngineRetryPolicy(unittest.TestCase):
    """hydra.Engine.call against a fake session library: a lost reply is re-sent only if it was a read (spec 4.3)."""

    def setUp(self):
        import hashlib
        from unittest.mock import patch
        import fakehydra
        from hydralysis import hydra
        self.fakehydra, self.hydra = fakehydra, hydra
        self.work = workdir("retry")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.daemon = fakehydra.reset()
        self.digest = hashlib.sha256(b"owned").hexdigest()
        self.gpr = self.root / "analysed" / "Owned" / "Owned.gpr"
        self.daemon.add_project(self.gpr, {"/owned.exe": {"sha256": self.digest}})
        self.settings = {"root": str(self.root / "data"), "hydra_dir": "x", "hydra_client": "x"}
        for item in (patch("hydralysis.hydra.load_client", return_value=fakehydra.FakeClientModule),
                     patch.dict(hydra.Engine._connections, clear=True)):
            item.start()
            self.addCleanup(item.stop)
        self.writer = hydra.Engine(self.settings, role="writer")
        opened = self.writer.call("open_project", path=str(self.gpr), writable=True)
        self.program = {"key": self.writer.call("open_program", path="/owned.exe", project=opened["id"], writable=True)["key"],
                        "project": opened["id"]}

    def sent(self, command, action=None):
        return [fields for _, name, fields in self.daemon.calls if name == command and
                (action is None or self.fakehydra.FakeSession._action(fields) == action)]

    def marker(self):
        from hydralysis import query
        request = {"id": "m", "action": "overlay_state", "address": "", "limit": 1, "cursor": "", "contains": "",
                   "timeout_s": 5, "options": {}}
        return query.run_script(self.writer, self.program, request, 5)[0]["overlay_state"]

    def test_a_dropped_apply_overlays_is_not_resent_and_the_marker_reconciles(self):
        from hydralysis import workcopy
        state = {"revision": "r2", "ids": ["e1"]}
        records = [{"id": "e1", "address": "0x140001000", "options": {"kind": "rename", "name": "renamed"}}]
        self.daemon.drops.append({"command": "script", "action": "apply_overlays", "when": "after"})
        with self.assertRaises(self.hydra.EngineError) as caught:
            workcopy._apply(self.settings, self.writer, self.program, records, state, 5)
        error = caught.exception
        self.assertEqual(error.code, "closed")
        self.assertTrue(error.ambiguous)
        self.assertTrue(json.loads(str(error))["ambiguous"])
        self.assertEqual(len(self.sent("script", "apply_overlays")), 1, "the apply was sent again")
        # The caller reconciles by reading the marker: the engine had applied it, and says so.
        self.assertEqual(json.loads(self.marker()), state)
        self.assertEqual(len(self.sent("script", "apply_overlays")), 1)

    def test_a_dropped_apply_that_never_arrived_reconciles_to_the_old_marker(self):
        from hydralysis import workcopy
        self.daemon.drops.append({"command": "script", "action": "apply_overlays", "when": "before"})
        with self.assertRaises(self.hydra.EngineError) as caught:
            workcopy._apply(self.settings, self.writer, self.program, [], {"revision": "r2"}, 5)
        self.assertTrue(caught.exception.ambiguous)
        self.assertEqual(self.sent("script", "apply_overlays"), [])
        self.assertEqual(self.marker(), "")

    def test_a_mutating_call_is_never_sent_twice(self):
        key = self.program["key"]
        for command, fields in (("save", {"program": key}),
                                ("fork_project", {"project": self.program["project"], "path": str(self.root / "fork")}),
                                ("edit", {"program": key}), ("rename", {"program": key}),
                                ("comment", {"program": key}), ("import", {"path": "x.exe"}),
                                ("script", {"script": "UserScript.java", "program": key}),
                                ("script", {"script": "RusticQuery.java", "program": key, "args": ["not json"]}),
                                ("cancel", {"target": 4})):
            for oserror in (False, True):
                with self.subTest(command=command, oserror=oserror):
                    before = len(self.sent(command))
                    self.daemon.drops.append({"command": command, "when": "before", "oserror": oserror})
                    with self.assertRaises(self.hydra.EngineError) as caught:
                        self.writer.call(command, **fields)
                    self.assertEqual(caught.exception.code, "closed")
                    self.assertTrue(caught.exception.ambiguous)
                    # "before": the daemon never saw it; a blind retry would have been the only call it saw.
                    self.assertEqual(len(self.sent(command)) - before, 0, "the call was sent again")
                    self.assertFalse(self.daemon.drops)

    def test_a_fork_whose_reply_was_lost_can_be_found_by_its_destination(self):
        destination = self.root / "fork"
        self.daemon.drops.append({"command": "fork_project", "when": "after"})
        with self.assertRaises(self.hydra.EngineError) as caught:
            self.writer.call("fork_project", project=self.program["project"], path=str(destination))
        self.assertTrue(caught.exception.ambiguous)
        self.assertEqual(len(self.sent("fork_project")), 1)
        self.assertTrue((destination / "Owned.gpr").is_file())

    def test_a_save_whose_reply_was_lost_is_sent_once(self):
        self.daemon.drops.append({"command": "save", "when": "after"})
        with self.assertRaises(self.hydra.EngineError) as caught:
            self.writer.call("save", program=self.program["key"])
        self.assertTrue(caught.exception.ambiguous)
        self.assertEqual(len(self.sent("save")), 1)

    def test_a_read_is_sent_again_on_a_new_connection(self):
        from hydralysis import query
        sessions = self.daemon.sessions
        self.daemon.drops.append({"command": "script", "action": "decompile", "when": "after"})
        request = {"id": "d", "action": "decompile", "address": "0x140001000", "limit": 1, "cursor": "", "contains": "",
                   "timeout_s": 5, "options": {}}
        answer, _ = query.run_script(self.writer, self.program, request, 5)
        self.assertTrue(answer["ok"])
        self.assertEqual(len(self.sent("script", "decompile")), 2)
        self.assertGreater(self.daemon.sessions, sessions)

    def test_read_commands_are_retried_through_oserror_and_closed(self):
        for oserror in (False, True):
            with self.subTest(oserror=oserror):
                before = len(self.sent("status"))
                self.daemon.drops.append({"command": "status", "when": "before", "oserror": oserror})
                self.assertIn("projects", self.writer.call("status"))
                self.assertEqual(len(self.sent("status")) - before, 1)

    def test_a_read_that_fails_twice_raises_closed_without_the_ambiguity_flag(self):
        self.daemon.drops.append({"command": "status", "when": "before", "times": 2})
        with self.assertRaises(self.hydra.EngineError) as caught:
            self.writer.call("status")
        self.assertEqual(caught.exception.code, "closed")
        self.assertFalse(caught.exception.ambiguous)

    def test_which_commands_are_idempotent(self):
        idempotent = self.hydra.idempotent
        for command in ("hello", "health", "status", "open_project", "open_program", "info", "list", "project", "functions", "decompile"):
            self.assertTrue(idempotent(command), command)
        for command in ("save", "import", "fork_project", "edit", "rename", "comment", "cancel", "analyze", "frobnicate"):
            self.assertFalse(idempotent(command), command)

        def script(action, name="RusticQuery.java"):
            return {"script": name, "args": [json.dumps({"action": action})]}
        self.assertTrue(idempotent("script", script("decompile")))
        self.assertTrue(idempotent("script", script("overlay_state")))
        for action in ("apply_overlays", "type_edit", "anything_new", None):
            self.assertFalse(idempotent("script", script(action)), action)
        self.assertFalse(idempotent("script", script("decompile", "RusticSetup.java")))
        self.assertFalse(idempotent("script", {"script": "RusticQuery.java", "args": []}))
        self.assertFalse(idempotent("script", {}))
        big = self.root / "request.json"
        big.write_text(json.dumps({"action": "decompile"}), encoding="utf-8")
        self.assertTrue(idempotent("script", {"script": "RusticQuery.java", "args": ["@" + str(big)]}))
        big.write_text(json.dumps({"action": "apply_overlays"}), encoding="utf-8")
        self.assertFalse(idempotent("script", {"script": "RusticQuery.java", "args": ["@" + str(big)]}))
        self.assertFalse(idempotent("script", {"script": "RusticQuery.java", "args": ["@" + str(self.root / "missing.json")]}))

    def test_a_busy_answer_is_parsed_into_the_engine_error(self):
        self.daemon.replies["open_program"] = self.fakehydra.busy_with_holder(retry_after_ms=2500, held_ms=4200, running=7)
        before = len(self.sent("open_program"))
        with self.assertRaises(self.hydra.EngineError) as caught:
            self.writer.call("open_program", path="/owned.exe", project=self.program["project"])
        error = caught.exception
        self.assertEqual(len(self.sent("open_program")) - before, 1, "busy is an answer, not a lost connection: no resend")
        self.assertEqual(error.code, "busy")
        self.assertEqual(error.retry_after_ms, 2500)
        self.assertEqual(error.details["reason"], "lock_wait")
        self.assertEqual((error.holder_info["client"], error.holder_info["harness"]), (3, "codex"))
        self.assertEqual(error.held_ms, 4200)
        self.assertEqual(error.queue["position"], 2)
        self.assertEqual(error.next, {"cmd": "status"})
        self.assertFalse(error.ambiguous)
        payload = json.loads(str(error))
        self.assertEqual(payload["retryAfterMs"], 2500)
        self.assertEqual(payload["holderInfo"]["command"], "script")
        self.assertEqual(payload["heldMs"], 4200)
        self.assertEqual(payload["queue"]["lane"], "long")
        self.assertEqual(payload["next"], {"cmd": "status"})
        self.assertEqual(len(payload["running"]), 5)
        self.assertEqual(payload["more"], {"running": 2})

    def test_an_error_from_another_reply_does_not_lend_its_retry_hint(self):
        # Library 1.0.0 keeps one last_response per connection: another thread's reply may replace it.
        busy = self.fakehydra.busy_with_holder(retry_after_ms=9000)
        session = self.writer.session()
        session.last_response = {"ok": False, "error": {**busy, "message": "some other error"}}
        error = self.writer._error(session, self.fakehydra.FakeClientModule.SessionError(
            busy["code"], busy["message"], busy["details"]), "open_program")
        self.assertIsNone(error.retry_after_ms)
        self.assertEqual(error.holder_info["client"], 3)

    def test_plain_errors_keep_their_shape(self):
        error = self.hydra.EngineError("not_found", "no program x", {"program": "p1:/x", "suggest": "list"}, "open_program")
        self.assertEqual(json.loads(str(error)), {"engine_error": "not_found", "message": "no program x", "command": "open_program",
                                                  "suggest": "list", "program": "p1:/x"})
        self.assertIsNone(error.retry_after_ms)
        self.assertIsNone(error.queue)
        self.assertFalse(error.ambiguous)

    def test_a_ready_request_in_next_survives_the_list_cap_unchanged(self):
        ready = {"cmd": "script", "script": "RusticQuery.java", "args": ["a%d" % number for number in range(8)],
                 "queue": [1, 2, 3, 4, 5, 6, 7]}
        waiting = [{"client": number} for number in range(9)]
        error = self.hydra.EngineError("busy", "held", {"running": list(range(8))}, "script", retry_after_ms=1500,
                                       next=ready, queue={"position": 2, "waiting": waiting})
        payload = json.loads(str(error))
        self.assertEqual(payload["next"], ready)  # not shortened to 5 args, and no `more` entry for it
        self.assertEqual(len(payload["next"]["args"]), 8)
        self.assertEqual(payload["queue"]["waiting"], waiting)
        self.assertEqual(payload["retryAfterMs"], 1500)
        self.assertEqual(len(payload["running"]), 5)  # other lists are still capped
        self.assertEqual(payload["more"], {"running": 3})
        self.assertEqual(error.next, ready)

    def test_a_pathological_queue_is_bounded_while_next_stays_whole(self):
        waiting = [{"client": number} for number in range(500)]
        ready = {"cmd": "script", "script": "RusticQuery.java", "args": ["a%d" % number for number in range(100)]}
        error = self.hydra.EngineError("busy", "held", {}, "script", retry_after_ms=1500, next=ready,
                                       queue={"position": 400, "lane": "long", "waiting": waiting})
        payload = json.loads(str(error))
        self.assertEqual(self.hydra.QUEUE_CAP, 64)
        self.assertEqual(payload["queue"]["waiting"], waiting[:64])  # bounded, the first 64 in engine order
        self.assertEqual((payload["queue"]["position"], payload["queue"]["lane"]), (400, "long"))
        self.assertEqual(payload["more"], {"queue.waiting": 500 - 64})
        self.assertEqual(payload["next"], ready)  # next is still exact: 100 args, no `more` entry for it
        self.assertEqual(payload["retryAfterMs"], 1500)
        self.assertEqual(error.queue["waiting"], waiting)  # the attribute is the engine's structure, unchanged
        # exactly at the cap nothing is cut and nothing is reported
        exact = self.hydra.EngineError("busy", "held", {}, "script", queue={"waiting": waiting[:64]})
        self.assertEqual(json.loads(str(exact))["queue"]["waiting"], waiting[:64])
        self.assertNotIn("more", json.loads(str(exact)))
        # a queue that comes from details.queue is bounded the same way
        nested = self.hydra.EngineError("busy", "held", {"queue": {"waiting": waiting}}, "script")
        self.assertEqual(len(json.loads(str(nested))["queue"]["waiting"]), 64)

    def test_a_stale_idle_connection_is_pinged_before_a_mutating_call_and_replaced_if_dead(self):
        save = lambda: self.writer.call("save", program=self.program["key"])
        # A mutating call on a connection that was just used is not probed, and a read never is.
        self.writer.call("list", project=self.program["project"])
        save()
        self.assertEqual(self.sent("ping"), [])
        # Idle past STALE_S and the socket is dead: the ping finds it, the call goes to a new connection and
        # is sent exactly once, and nothing is reported as ambiguous although the old connection was gone.
        self.hydra.Engine._used[self.writer.key] -= self.hydra.STALE_S + 1
        self.daemon.drops.append({"command": "ping", "when": "before"})
        sessions, saves = self.daemon.sessions, len(self.sent("save"))
        save()
        self.assertEqual(self.daemon.sessions, sessions + 1)
        self.assertEqual(len(self.sent("save")) - saves, 1)
        # An idle connection that is alive is pinged once and kept.
        self.hydra.Engine._used[self.writer.key] -= self.hydra.STALE_S + 1
        sessions, saves, pings = self.daemon.sessions, len(self.sent("save")), len(self.sent("ping"))
        save()
        self.assertEqual((self.daemon.sessions, len(self.sent("ping")) - pings, len(self.sent("save")) - saves),
                         (sessions, 1, 1))
        # A read after a long idle is not probed: it is retried anyway.
        self.hydra.Engine._used[self.writer.key] -= self.hydra.STALE_S + 1
        pings = len(self.sent("ping"))
        self.writer.call("list", project=self.program["project"])
        self.assertEqual(len(self.sent("ping")), pings)

    def test_capabilities_is_empty_on_protocol_2_and_never_raises_on_an_older_engine(self):
        self.assertEqual(self.writer.hello()["protocol"], 2)
        self.assertEqual(self.writer.capabilities(), {})
        # An engine whose hello says nothing useful about capabilities, and a library with no hello at all.
        self.daemon.hello_extra = {"capabilities": None}
        self.hydra.Engine._connections.clear()
        self.assertEqual(self.writer.capabilities(), {})
        del self.writer.session().hello
        self.assertEqual(self.writer.capabilities(), {})
        # Capabilities a protocol-2 connection should not carry are not believed.
        self.daemon.hello_extra = {"capabilities": {"health": 1}}
        self.hydra.Engine._connections.clear()
        self.assertEqual(self.writer.capabilities(), {})

    def test_capabilities_of_a_protocol_3_engine(self):
        self.daemon.hello_extra = {"protocol": 3, "capabilities": {"queueInfo": 1, "health": 2, "odd": "x", "flag": True}}
        self.hydra.Engine._connections.clear()
        self.assertEqual(self.writer.capabilities(), {"queueInfo": 1, "health": 2})
        self.assertNotIn("token", self.writer.hello())


if __name__ == "__main__":
    unittest.main()
