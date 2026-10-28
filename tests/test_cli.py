"""The command line reaches the same dispatcher as the MCP tool (PROTOCOL-3.md 7.1, 8.2: Y0e).

`backend` doctor and backups, and the `--options` JSON object, were reachable only through MCP. Until Y4b (doctor)
and Y2 (backups) land their handlers the dispatcher answers `not_available`, and the command line passes that
answer through unchanged: exit 0, the same JSON text. Y2 made the dispatcher read `api.HANDLER_MODULES`, so the two
stub tests below patch that table with a module that never exists and stay true whichever handlers ship.
"""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from hydralysis import api, cli
from hydralysis.api import call, catalog

from support import workdir


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class BackendActions(unittest.TestCase):
    def setUp(self):
        patcher = patch("hydralysis.api.load", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_cli_actions_are_exactly_the_enum_of_the_mcp_tool(self):
        table = {tool["name"]: tool["inputSchema"]["properties"] for tool in api.tool_table()}
        self.assertEqual(list(cli.BACKEND_ACTIONS), table["backend"]["action"]["enum"])

    def test_action_flag_and_positional_action_reach_the_dispatcher_as_one_call(self):
        for argv in (("backend", "--action", "doctor"), ("backend", "doctor"), ("backend", "doctor", "--action", "doctor")):
            with self.subTest(argv=argv), patch("hydralysis.cli.call", return_value="ok") as dispatch:
                self.assertEqual(run(*argv)[0], 0)
                dispatch.assert_called_once_with("backend", {"action": "doctor", "component": "analysis"})

    def test_options_json_is_passed_through_to_the_tool(self):
        with patch("hydralysis.cli.call", return_value="ok") as dispatch:
            code, out, _ = run("backend", "--action", "backups", "--options", '{"op": "verify", "id": "x"}',
                               "--component", "analysis")
        self.assertEqual((code, out.strip()), (0, "ok"))
        dispatch.assert_called_once_with("backend", {"action": "backups", "component": "analysis",
                                                     "options": {"op": "verify", "id": "x"}})

    def test_an_options_file_is_read_like_the_other_commands_do(self):
        with workdir() as folder:
            path = Path(folder) / "options.json"
            path.write_text(json.dumps({"op": "list", "sections": ["lineage"]}), encoding="utf-8-sig")
            with patch("hydralysis.cli.call", return_value="ok") as dispatch:
                self.assertEqual(run("backend", "--action", "doctor", "--options-file", str(path))[0], 0)
            self.assertEqual(dispatch.call_args.args[1]["options"], {"op": "list", "sections": ["lineage"]})
            path.write_text("[]", encoding="utf-8")
            with patch("hydralysis.cli.call") as dispatch:
                code, _, err = run("backend", "--action", "doctor", "--options-file", str(path))
            self.assertEqual(code, 1)
            self.assertIn("JSON object", err)
            dispatch.assert_not_called()

    def test_options_and_options_file_exclude_each_other(self):
        with patch("hydralysis.cli.call") as dispatch, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as stopped:
                cli.main(["backend", "--action", "doctor", "--options", "{}", "--options-file", "x.json"])
        self.assertEqual(stopped.exception.code, 2)
        dispatch.assert_not_called()

    def test_an_options_value_that_is_not_an_object_is_refused_by_the_parser(self):
        with patch("hydralysis.cli.call") as dispatch, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as stopped:
                cli.main(["backend", "--action", "doctor", "--options", "[1]"])
        self.assertEqual(stopped.exception.code, 2)
        dispatch.assert_not_called()

    def test_two_different_actions_are_refused_and_nothing_is_called(self):
        with patch("hydralysis.cli.call") as dispatch:
            code, _, err = run("backend", "doctor", "--action", "backups")
        self.assertEqual(code, 1)
        self.assertIn("two actions", err)
        dispatch.assert_not_called()

    def test_a_backend_command_without_options_is_the_call_it_always_was(self):
        for argv, expected in ((("backend",), {"action": "inspect", "component": "analysis"}),
                               (("backend", "status"), {"action": "status", "component": "analysis"}),
                               (("backend", "help", "--component", "runtime"), {"action": "help", "component": "runtime"}),
                               (("backend", "--options", "{}"), {"action": "inspect", "component": "analysis"})):
            with self.subTest(argv=argv), patch("hydralysis.cli.call", return_value="ok") as dispatch:
                self.assertEqual(run(*argv)[0], 0)
                dispatch.assert_called_once_with("backend", expected)

    def test_an_unknown_action_is_refused_by_the_parser(self):
        with redirect_stderr(io.StringIO()):
            for argv in (["backend", "repair"], ["backend", "--action", "repair"]):
                with self.subTest(argv=argv), self.assertRaises(SystemExit) as stopped:
                    cli.main(argv)
                self.assertEqual(stopped.exception.code, 2)

    @patch.dict(api.HANDLER_MODULES, {"doctor": "hydralysis._no_such_handler", "backups": "hydralysis._no_such_handler"})
    def test_doctor_and_backups_pass_the_not_available_answer_through_without_side_effects(self):
        with patch("hydralysis.api._settings") as settings, patch("hydralysis.hydra.Engine") as engine:
            doctor_code, doctor_out, _ = run("backend", "--action", "doctor")
            backups_code, backups_out, _ = run("backend", "--action", "backups")
            verify_code, verify_out, _ = run("backend", "--action", "backups", "--options", '{"op": "verify", "id": "x"}')
        settings.assert_not_called()
        engine.assert_not_called()
        self.assertEqual((doctor_code, backups_code, verify_code), (0, 0, 0))
        doctor, listed, verified = json.loads(doctor_out), json.loads(backups_out), json.loads(verify_out)
        self.assertEqual(doctor["not_available"], "doctor")
        self.assertEqual((listed["not_available"], listed["op"]), ("backups", "list"))
        self.assertEqual(verified["op"], "verify")
        for reply in (doctor, listed, verified):
            self.assertEqual(reply["catalog"], catalog())
            self.assertEqual(reply["tool"], "backend")
        # the very text the MCP tool returns, not a rewording
        self.assertEqual(doctor_out.strip(), call("backend", {"action": "doctor"}).strip())
        self.assertEqual(verify_out.strip(),
                         call("backend", {"action": "backups", "options": {"op": "verify", "id": "x"}}).strip())

    def test_the_dispatchers_own_refusals_come_back_as_exit_1(self):
        with patch("hydralysis.api._settings") as settings:
            code, out, err = run("backend", "--action", "backups", "--options", '{"op": "delete"}')
        settings.assert_not_called()
        self.assertEqual((code, out), (1, ""))
        self.assertIn("op must be list, verify or remove", err)

    def test_the_call_command_reaches_doctor_too(self):
        with patch.dict(api.HANDLER_MODULES, {"doctor": "hydralysis._no_such_handler"}):
            code, out, _ = run("call", "backend", "--args", '{"action": "doctor"}')
        self.assertEqual(code, 0)
        envelope = json.loads(out)
        self.assertTrue(envelope["ok"])
        self.assertEqual(envelope["result"]["not_available"], "doctor")


if __name__ == "__main__":
    unittest.main()
