"""Exercise the real stdio boundary, plus responsiveness under bounded load."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from rusticre.mcp import MAX_OUTSTANDING, MAX_OUTPUT_BYTES, Server, _read_message


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


class TransportTests(unittest.TestCase):
    def run_server(self, payload):
        result = subprocess.run(
            [sys.executable, "-m", "rusticre", "mcp"],
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

        messages = [request(index, "tools/call", {"name": "slow", "arguments": {"number": index}})
                    for index in range(MAX_OUTSTANDING + 1)]
        messages.append(request("list", "tools/list"))
        messages.append(request("ping", "ping"))
        worker = threading.Thread(target=Server().serve, args=(io.BytesIO(lines(messages)), output))
        with patch("rusticre.mcp.call", slow):
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
        self.assertEqual(len(calls), MAX_OUTSTANDING)
        self.assertEqual(replies[1]["id"], "list")
        self.assertEqual(replies[2]["id"], "ping")

    def test_large_unicode_tool_result_is_bounded_and_reports_loss(self):
        value = "HEAD" + "\U0001f680" * MAX_OUTPUT_BYTES + "TAIL"
        with patch("rusticre.mcp.call", return_value=value):
            response = Server().handle(request(1, "tools/call", {"name": "large"}))
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
