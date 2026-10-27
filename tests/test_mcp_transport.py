"""Exercise the real stdio boundary, plus responsiveness under bounded load."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from hydralysis.api import TOOL_NAMES
from hydralysis.mcp import (ENGINE_TOOLS, MAX_OUTSTANDING, MAX_OUTPUT_BYTES, RETRY_AFTER_MS, TOOL_WORKERS,
                            Server, _read_message, lane_of)


def request(ident, method, params=None):
    result = {"jsonrpc": "2.0", "id": ident, "method": method}
    if params is not None:
        result["params"] = params
    return result


def lines(messages):
    return b"".join(json.dumps(message).encode("utf-8") + b"\n" for message in messages)


class ObservedOutput(io.BytesIO):
    def __init__(self):
        super().__init__()
        self.ping = threading.Event()

    def write(self, value):
        result = super().write(value)
        if b'"id": "ping"' in value:
            self.ping.set()
        return result


class IdOutput:
    """Binary sink that parses each newline-JSON reply and lets a test wait on ids."""

    def __init__(self):
        self._cond = threading.Condition()
        self._replies = []

    def write(self, value):
        with self._cond:
            for line in value.splitlines():
                if line.strip():
                    self._replies.append(json.loads(line))
            self._cond.notify_all()
        return len(value)

    def flush(self):
        pass

    def replies(self):
        with self._cond:
            return list(self._replies)

    def ids(self):
        return {r["id"] for r in self.replies()}

    def reply(self, ident):
        return next(r for r in self.replies() if r["id"] == ident)

    def text(self, ident):
        return self.reply(ident)["result"]["content"][0]["text"]

    def wait_for(self, wanted, timeout):
        with self._cond:
            return self._cond.wait_for(lambda: wanted <= {r["id"] for r in self._replies}, timeout)


class TransportTests(unittest.TestCase):
    def run_server(self, payload):
        result = subprocess.run(
            [sys.executable, "-m", "hydralysis", "mcp"],
            input=payload, capture_output=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        return result.stdout

    def test_real_newline_client_initialize_list_failed_call_and_ping(self):
        payload = lines([
            request(1, "initialize", {"protocolVersion": "2025-06-18"}),
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            request(2, "tools/list"),
            request(3, "tools/call", {"name": "not_a_tool", "arguments": {}}),
            request(4, "ping"),
        ])
        output = self.run_server(payload)
        self.assertFalse(output.startswith(b"Content-Length:"))
        replies = {item["id"]: item for item in map(json.loads, output.splitlines())}
        self.assertEqual(set(replies), {1, 2, 3, 4})
        self.assertEqual(replies[1]["result"]["protocolVersion"], "2025-06-18")
        self.assertGreater(len(replies[2]["result"]["tools"]), 0)
        self.assertTrue(replies[3]["result"]["isError"])
        self.assertIn("unknown tool", replies[3]["result"]["content"][0]["text"])
        self.assertEqual(replies[4]["result"], {})

    def test_legacy_framed_request_gets_framed_response(self):
        body = json.dumps(request(1, "ping")).encode("utf-8")
        payload = b"Content-Length: %d\r\n\r\n" % len(body) + body
        output = self.run_server(payload)
        self.assertTrue(output.startswith(b"Content-Length:"))
        response = _read_message(io.BytesIO(output))
        self.assertEqual(response, {"jsonrpc": "2.0", "id": 1, "result": {}})

    def test_malformed_line_does_not_kill_next_ping(self):
        output = self.run_server(b'{bad json\n' + lines([request(2, "ping")]))
        responses = list(map(json.loads, output.splitlines()))
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertIsNone(responses[0]["id"])
        self.assertEqual(responses[1]["id"], 2)
        self.assertEqual(responses[1]["result"], {})

    def test_invalid_request_and_params_do_not_kill_next_ping(self):
        output = self.run_server(lines([None, request(1, "tools/call", []), request(2, "ping")]))
        responses = list(map(json.loads, output.splitlines()))
        self.assertEqual(responses[0]["error"]["code"], -32600)
        self.assertEqual(responses[1]["error"]["code"], -32602)
        self.assertEqual(responses[2]["id"], 2)

    def test_slow_tools_and_saturated_queue_leave_ping_responsive(self):
        release = threading.Event()
        output = ObservedOutput()
        calls = []

        def slow(name, arguments):
            calls.append(arguments["number"])
            if not release.wait(5):
                raise RuntimeError("test did not release worker")
            return "finished"

        messages = [request(index, "tools/call", {"name": "inspect", "arguments": {"number": index}})
                    for index in range(MAX_OUTSTANDING + 1)]
        messages.append(request("list", "tools/list"))
        messages.append(request("ping", "ping"))
        worker = threading.Thread(target=Server().serve, args=(io.BytesIO(lines(messages)), output))
        with patch("hydralysis.mcp.call", slow):
            worker.start()
            try:
                self.assertTrue(output.ping.wait(3), "ping blocked behind slow calls")
                self.assertNotIn(b'"text": "finished"', output.getvalue())
                self.assertIn(b'"id": "list"', output.getvalue())
            finally:
                release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        replies = list(map(json.loads, output.getvalue().splitlines()))
        self.assertEqual(len(replies), MAX_OUTSTANDING + 3)
        busy = next(reply for reply in replies if reply["id"] == MAX_OUTSTANDING)
        self.assertTrue(busy["result"]["isError"])
        self.assertIn("Server busy", busy["result"]["content"][0]["text"])
        self.assertIn("retryAfterMs", busy["result"]["content"][0]["text"])
        self.assertEqual(len(calls), MAX_OUTSTANDING)
        self.assertEqual(replies[1]["id"], "list")
        self.assertEqual(replies[2]["id"], "ping")

    def serve_in_thread(self, messages, fake_call):
        output = IdOutput()
        worker = threading.Thread(target=Server().serve, args=(io.BytesIO(lines(messages)), output))
        patcher = patch("hydralysis.mcp.call", fake_call)
        patcher.start()
        self.addCleanup(patcher.stop)
        worker.start()
        return worker, output

    @staticmethod
    def engine_call(release, entered):
        def fake(name, arguments):
            if name in ENGINE_TOOLS:
                entered.append(name)
                if not release.wait(10):
                    raise RuntimeError("test did not release engine call")
            return "%s:%s" % (name, (arguments or {}).get("tag"))
        return fake

    def test_four_blocked_engine_calls_do_not_delay_fingerprint_or_disasm(self):
        release = threading.Event()
        entered = []
        messages = [request("q%d" % i, "tools/call",
                            {"name": "ghidra_query", "arguments": {"tag": "q%d" % i}}) for i in range(TOOL_WORKERS)]
        messages += [request("fp", "tools/call", {"name": "fingerprint", "arguments": {"tag": "fp"}}),
                     request("dis", "tools/call", {"name": "disasm", "arguments": {"tag": "dis"}})]
        worker, output = self.serve_in_thread(messages, self.engine_call(release, entered))
        try:
            self.assertTrue(output.wait_for({"fp", "dis"}, 3), "local tools were delayed by blocked engine calls")
            self.assertEqual(output.ids() & {"q0", "q1", "q2", "q3"}, set())
            self.assertEqual(output.text("fp"), "fingerprint:fp")
            self.assertEqual(output.text("dis"), "disasm:dis")
        finally:
            release.set()
            worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(entered), TOOL_WORKERS)
        for i in range(TOOL_WORKERS):
            self.assertEqual(output.text("q%d" % i), "ghidra_query:q%d" % i)

    def test_saturated_engine_lane_answers_busy_with_retry_hint_and_fast_lane_stays_open(self):
        release = threading.Event()
        entered = []
        total = MAX_OUTSTANDING + 2
        messages = [request("q%d" % i, "tools/call",
                            {"name": "ghidra_query", "arguments": {"tag": "q%d" % i}}) for i in range(total)]
        messages.append(request("fp", "tools/call", {"name": "fingerprint", "arguments": {"tag": "fp"}}))
        worker, output = self.serve_in_thread(messages, self.engine_call(release, entered))
        try:
            self.assertTrue(output.wait_for({"fp", "q%d" % MAX_OUTSTANDING, "q%d" % (MAX_OUTSTANDING + 1)}, 3))
            for ident in ("q%d" % MAX_OUTSTANDING, "q%d" % (MAX_OUTSTANDING + 1)):
                reply = output.reply(ident)
                self.assertTrue(reply["result"]["isError"])
                text = reply["result"]["content"][0]["text"]
                self.assertIn("Server busy", text)
                self.assertIn("Retry", text)
                self.assertIn("retryAfterMs=%d" % RETRY_AFTER_MS, text)
            self.assertEqual(output.text("fp"), "fingerprint:fp")
        finally:
            release.set()
            worker.join(10)
        self.assertFalse(worker.is_alive())
        for i in range(MAX_OUTSTANDING):
            self.assertEqual(output.text("q%d" % i), "ghidra_query:q%d" % i)

    def test_fast_lane_saturation_does_not_block_engine_calls(self):
        release = threading.Event()
        entered = []

        def fake(name, arguments):
            if name not in ENGINE_TOOLS:
                if not release.wait(10):
                    raise RuntimeError("test did not release fast call")
            return "%s:%s" % (name, arguments["tag"])

        messages = [request("f%d" % i, "tools/call", {"name": "disasm", "arguments": {"tag": "f%d" % i}})
                    for i in range(MAX_OUTSTANDING + 1)]
        messages.append(request("job", "tools/call", {"name": "job", "arguments": {"tag": "job"}}))
        worker, output = self.serve_in_thread(messages, fake)
        try:
            self.assertTrue(output.wait_for({"job", "f%d" % MAX_OUTSTANDING}, 3))
            self.assertEqual(output.text("job"), "job:job")
            self.assertIn("Server busy", output.text("f%d" % MAX_OUTSTANDING))
        finally:
            release.set()
            worker.join(10)
        self.assertFalse(worker.is_alive())

    def test_every_reply_carries_its_own_id_under_concurrency(self):
        names = ["fingerprint", "disasm", "ghidra_query", "backend", "inspect", "job", "strings", "prepare"]
        rounds = 3
        messages = []
        for r in range(rounds):
            for n, name in enumerate(names):
                messages.append(request("%s-%d-%d" % (name, r, n), "tools/call",
                                        {"name": name, "arguments": {"tag": "%s-%d-%d" % (name, r, n)}}))
        delay = threading.Event()

        def fake(name, arguments):
            delay.wait(0.01 if name in ENGINE_TOOLS else 0.001)
            return "%s|%s" % (name, arguments["tag"])

        with patch("hydralysis.mcp.call", fake):
            output = IdOutput()
            Server().serve(io.BytesIO(lines(messages)), output)
        replies = output.replies()
        sent = [m["id"] for m in messages]
        busy = {r["id"] for r in replies if "Server busy" in r["result"]["content"][0]["text"]}
        # No reply is lost or duplicated; completion order is free, so match by id.
        self.assertEqual(sorted(r["id"] for r in replies), sorted(sent))
        for reply in replies:
            if reply["id"] in busy:
                continue
            name, tag = reply["result"]["content"][0]["text"].split("|")
            self.assertEqual(tag, reply["id"])
            self.assertTrue(tag.startswith(name))

    def test_shutdown_at_eof_waits_for_accepted_calls_and_answers_them_all(self):
        release = threading.Event()
        entered = []
        messages = [request("q%d" % i, "tools/call", {"name": "runtime", "arguments": {"tag": "q%d" % i}})
                    for i in range(TOOL_WORKERS)]
        messages.append(request("fp", "tools/call", {"name": "fingerprint", "arguments": {"tag": "fp"}}))
        worker, output = self.serve_in_thread(messages, self.engine_call(release, entered))
        try:
            self.assertTrue(output.wait_for({"fp"}, 3))
            worker.join(0.3)
            self.assertTrue(worker.is_alive(), "serve returned while engine calls were still running")
        finally:
            release.set()
            worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(output.ids(), {"q0", "q1", "q2", "q3", "fp"})
        leaked = [t for t in threading.enumerate() if t.name.startswith("hydralysis-")]
        self.assertEqual(leaked, [])

    def test_lane_classification_matches_the_tool_table(self):
        self.assertEqual(ENGINE_TOOLS, {"ghidra_run", "ghidra_query", "backend", "prepare", "job", "runtime"})
        self.assertTrue(ENGINE_TOOLS <= set(TOOL_NAMES))
        for name in set(TOOL_NAMES) - ENGINE_TOOLS:
            self.assertEqual(lane_of(name), "fast")
        for name in ENGINE_TOOLS:
            self.assertEqual(lane_of(name), "engine")
        self.assertEqual(lane_of(None), "fast")
        self.assertEqual(lane_of(["x"]), "fast")

    def test_large_unicode_tool_result_is_bounded_and_reports_loss(self):
        value = "HEAD" + "\U0001f680" * MAX_OUTPUT_BYTES + "TAIL"
        with patch("hydralysis.mcp.call", return_value=value):
            response = Server().handle(request(1, "tools/call", {"name": "fingerprint"}))
        result = response["result"]
        text = result["content"][0]["text"]
        self.assertTrue(result["isError"])
        self.assertLessEqual(len(text.encode("utf-8")), MAX_OUTPUT_BYTES)
        self.assertTrue(text.startswith("HEAD"))
        self.assertTrue(text.endswith("TAIL"))
        self.assertIn("OUTPUT TRUNCATED", text)
        self.assertIn("discarded", text)
        self.assertIn(str(len(value.encode("utf-8"))), text)


if __name__ == "__main__":
    unittest.main()
