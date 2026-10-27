import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from hydralysis import api
from hydralysis.api import _settings, call, catalog, catalog_hash, tool_table
from hydralysis.cli import main
from hydralysis.mcp import Server

from support import workdir

# One row per catalog epoch: the SHA-256 of the advertised tool table (api.catalog_hash). Running MCP
# sessions cache tools/list, so the table may change only by adding the next epoch here AND raising
# api.CATALOG_EPOCH. Never edit an existing row: that is how a silent schema change would pass.
# Epoch 0 is the table of Hydralysis 0.5 before the protocol-3 catalog epoch (d0466bc).
CATALOG_HISTORY = {
    0: "f2fbf7471829d41e7c2210a2883b10133fd9e5cf4a5824882e519ce12c2f4fde",
    1: "a16c22e45a57780b88e9bebc91df85ecbe0e3fa115ef18b79a6bebbb10d0086e",
    # Epoch 2: the pe_address description is "Use rva:/va:; ambiguous unprefixed addresses are refused." again
    # (epoch 1 had weakened it to "(bare values may be refused)"). Epoch 1 was never released outside this branch.
    2: "9f1051b0cf70c8a8231b9d07fe46e7a9561142dcfba2442fd9aa7e11a6d85423",
}


class CatalogEpoch(unittest.TestCase):
    def test_table_matches_its_epoch_so_a_change_needs_a_new_epoch(self):
        self.assertEqual(api.CATALOG_EPOCH, max(CATALOG_HISTORY), "CATALOG_EPOCH must be the newest epoch in CATALOG_HISTORY")
        self.assertEqual(len(set(CATALOG_HISTORY.values())), len(CATALOG_HISTORY), "an epoch must change the table")
        self.assertEqual(catalog_hash(), CATALOG_HISTORY[api.CATALOG_EPOCH],
                         "the advertised tool table changed without a new catalog epoch: add the next epoch to "
                         "CATALOG_HISTORY and raise api.CATALOG_EPOCH (running sessions cache tools/list)")

    def test_hash_covers_names_descriptions_and_schemas_and_ignores_key_order(self):
        base = tool_table()
        self.assertEqual(catalog_hash(base), catalog_hash())
        for field in ("name", "description", "inputSchema"):
            altered = json.loads(json.dumps(base))
            altered[0][field] = {"type": "object"} if field == "inputSchema" else "changed"
            self.assertNotEqual(catalog_hash(altered), catalog_hash(), field)
        reordered = json.loads(json.dumps(base))
        properties = reordered[0]["inputSchema"]["properties"]
        reordered[0]["inputSchema"]["properties"] = dict(reversed(list(properties.items())))
        self.assertEqual(catalog_hash(reordered), catalog_hash())
        extra = json.loads(json.dumps(base))
        extra[3]["inputSchema"]["properties"]["added"] = {"type": "string"}
        self.assertNotEqual(catalog_hash(extra), catalog_hash())

    def test_status_and_help_report_the_catalog(self):
        expected = {"epoch": api.CATALOG_EPOCH, "hash": catalog_hash()}
        self.assertEqual(catalog(), expected)
        with patch("hydralysis.api.load", return_value={}):
            helped = json.loads(call("backend", {"action": "help"}))
            self.assertEqual(helped["catalog"], expected)
            self.assertIn("carriers", helped)
            self.assertEqual(json.loads(call("backend", {"action": "help", "component": "runtime"}))["catalog"], expected)
            engine = Mock()
            engine.call.return_value = {"protocol": 2, "hydraVersion": "x", "projects": [], "programs": [], "clients": []}
            with patch("hydralysis.api._settings", return_value={}), patch("hydralysis.hydra.Engine", return_value=engine):
                status = json.loads(call("backend", {"action": "status"}))
        self.assertEqual(status["catalog"], expected)

    def test_inspect_and_the_mcp_initialize_reply_report_the_catalog_too(self):
        expected = {"epoch": api.CATALOG_EPOCH, "hash": catalog_hash()}
        for component in ("analysis", "runtime"):
            module = "hydralysis.backends.inspect" if component == "analysis" else "hydralysis.runtime.inspect"
            with patch("hydralysis.api.load", return_value={}), patch(module, return_value={"engine": "x"}):
                report = json.loads(call("backend", {"action": "inspect", "component": component}))
            self.assertEqual(report["catalog"], expected, component)
            self.assertEqual(report["engine"], "x")
        reply = Server().handle({"id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(reply["result"]["_meta"]["hydralysis/catalog"], expected)
        self.assertEqual(reply["result"]["serverInfo"], {"name": "hydralysis", "version": reply["result"]["serverInfo"]["version"]})

    def test_the_address_description_keeps_the_refusal_wording(self):
        for tool in tool_table():
            address = tool["inputSchema"]["properties"].get("address")
            if tool["name"] in ("disasm", "bytes", "inspect", "prologue") and address:
                self.assertIn("ambiguous unprefixed addresses are refused", address["description"], tool["name"])

    def test_new_surface_rides_options_and_two_enum_values_on_the_same_twenty_tools(self):
        table = {tool["name"]: tool["inputSchema"]["properties"] for tool in tool_table()}
        self.assertEqual(list(table), list(api.TOOL_NAMES))
        for name in ("backend", "ghidra_run", "job", "ghidra_query", "runtime"):
            self.assertEqual(table[name]["options"], {"type": "object"}, name)
        self.assertEqual(table["backend"]["action"]["enum"],
                         ["inspect", "install", "status", "stop", "help", "doctor", "backups"])
        reply = Server().handle({"id": 1, "method": "tools/list"})
        self.assertEqual(reply["result"]["tools"], tool_table())
        self.assertEqual(set(api.OPTION_BAGS), {"ghidra_query", "backend", "ghidra_run", "job", "runtime"})


class NotAvailableCarriers(unittest.TestCase):
    def setUp(self):
        patcher = patch("hydralysis.api.load", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_doctor_and_backups_answer_not_available_without_side_effects(self):
        with patch("hydralysis.api._settings") as settings, patch("hydralysis.hydra.Engine") as engine:
            doctor = json.loads(call("backend", {"action": "doctor"}))
            listed = json.loads(call("backend", {"action": "backups"}))
            verified = json.loads(call("backend", {"action": "backups", "options": {"op": "verify", "id": "x"}}))
        settings.assert_not_called()
        engine.assert_not_called()
        self.assertEqual(doctor["not_available"], "doctor")
        self.assertEqual((listed["not_available"], listed["op"]), ("backups", "list"))
        self.assertEqual(verified["op"], "verify")
        for reply in (doctor, listed, verified):
            self.assertIn("not implemented", reply["message"])
            self.assertEqual(reply["catalog"], catalog())
            self.assertEqual(reply["tool"], "backend")

    def test_through_mcp_it_is_a_result_not_an_error(self):
        reply = Server().handle({"id": 1, "method": "tools/call", "params": {
            "name": "backend", "arguments": {"action": "doctor"}}})
        self.assertFalse(reply["result"]["isError"])
        self.assertIn("not_available", reply["result"]["content"][0]["text"])

    def test_options_are_validated_before_anything_else(self):
        for args in ({"action": "backups", "options": {"op": "delete"}}, {"action": "doctor", "options": []},
                     {"action": "inspect", "options": "x"}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                call("backend", args)
        with self.assertRaisesRegex(ValueError, "backend action must be"):
            call("backend", {"action": "repair"})

    def test_ghidra_run_options_are_never_silently_ignored(self):
        with patch("hydralysis.api._settings", return_value={}), patch("hydralysis.userscripts.run", return_value="ran") as run:
            self.assertEqual(call("ghidra_run", {"target": "t", "script": "s.py"}), "ran")
            self.assertEqual(call("ghidra_run", {"target": "t", "script": "s.py", "options": {}}), "ran")
            run.reset_mock()
            reply = json.loads(call("ghidra_run", {"target": "t", "script": "s.py",
                                                  "options": {"isolation": "private", "readonly": True}}))
            self.assertEqual(reply["not_available"], "scriptIsolation")
            self.assertIn("script was not run", reply["message"])
            self.assertEqual(reply["options"], ["isolation", "readonly"])
            for bad in ({"isolation": "other"}, {"readonly": "yes"}, []):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    call("ghidra_run", {"target": "t", "script": "s.py", "options": bad})
            run.assert_not_called()

    def test_job_options_are_reserved_and_plain_job_calls_are_unchanged(self):
        reply = json.loads(call("job", {"options": {"kind": "commit"}}))
        self.assertEqual((reply["not_available"], reply["options"]), ("jobOptions", ["kind"]))
        with patch("hydralysis.preparation.status", return_value={"state": "done"}) as status:
            self.assertEqual(json.loads(call("job", {"id": "setup-0123456789ab"})), {"state": "done"})
            self.assertEqual(json.loads(call("job", {"id": "setup-0123456789ab", "options": {}})), {"state": "done"})
        self.assertEqual(status.call_count, 2)
        with self.assertRaises(ValueError):
            call("job", {"options": "x"})


class AgentContracts(unittest.TestCase):
    def test_catalog_stays_small_in_bytes_as_well_as_count(self):
        catalog = tool_table()
        self.assertEqual(len(catalog), 20)
        self.assertLess(len(json.dumps(catalog).encode("utf-8")), 8192)
        for tool in catalog:
            self.assertLess(len(json.dumps(tool["inputSchema"]).encode("utf-8")), 1024, tool["name"])
        self.assertIn("ghidra_query", [tool["name"] for tool in catalog])

    def test_long_prologue_reads_all_expected_bytes_and_mismatch_fails_clients(self):
        image = Mock()
        image.header.return_value = "# sha256 build"
        image.base = 0x140000000
        image.read_rva.return_value = b"\x90" * 79 + b"\xc3"
        expect = " ".join(["90"] * 79 + ["C3"])
        with patch("hydralysis.api._image", return_value=image):
            self.assertIn("PROLOGUE MATCH", call("prologue", {"address": "0x1000", "expect": expect}))
            image.read_rva.assert_called_with(0x1000, 80)
            args = {"exe": "unused", "address": "0x1000", "expect": "CC"}
            reply = Server().handle({"id": 1, "method": "tools/call",
                                     "params": {"name": "prologue", "arguments": args}})
            self.assertTrue(reply["result"]["isError"])
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["prologue", "--exe", "unused", "0x1000", "--expect", "CC"]), 1)

    def test_invalid_limits_refuse_before_binary_read(self):
        with patch("hydralysis.api._image") as image:
            for args in ({"limit": -1}, {"size": 65537}, {"count": 0}, {"limit": True}):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    call("bytes", args)
            image.assert_not_called()

    def test_discovered_backend_replaces_stale_config_without_installing(self):
        configured = {"root": "data", "hydra_dir": "obsolete", "java_home": "obsolete-jdk", "targets": {"owned": {}}}
        report = {"ready": True, "root": "resolved-data", "engine": {"path": "verified-engine"},
                  "client": {"path": "verified-client"}, "jdk": {"path": "verified-jdk"}}
        with patch("hydralysis.api.load", return_value=configured), \
                patch("hydralysis.backends.inspect", return_value=report), patch("hydralysis.backends.ensure") as install:
            selected = _settings()
        self.assertEqual(selected["hydra_dir"], "verified-engine")
        self.assertEqual(selected["hydra_client"], "verified-client")
        self.assertEqual(selected["java_home"], "verified-jdk")
        self.assertEqual(selected["targets"], configured["targets"])
        install.assert_not_called()

    def test_missing_engines_report_setup_without_installing_implicitly(self):
        with patch("hydralysis.api.load", return_value={}), \
                patch("hydralysis.backends.inspect", return_value={"ready": False, "engine": None, "client": None, "jdk": None}), \
                patch("hydralysis.backends.ensure") as install:
            with self.assertRaisesRegex(ValueError, "backend install"):
                _settings()
        install.assert_not_called()

    def test_runtime_setup_returns_background_job_through_cli_and_mcp(self):
        with patch("hydralysis.api.load", return_value={"root": "data"}), \
                patch("hydralysis.preparation.start_install", return_value={"job_id": "setup-0123456789ab"}) as launch:
            reply = Server().handle({"id": 1, "method": "tools/call", "params": {
                "name": "runtime", "arguments": {"action": "setup"}}})
            self.assertFalse(reply["result"]["isError"])
            self.assertIn("setup-0123456789ab", reply["result"]["content"][0]["text"])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["runtime", "setup"]), 0)
        self.assertEqual(launch.call_count, 2)
        launch.assert_called_with({"root": "data"}, "runtime")

    def test_prepare_refuses_non_boolean_install_before_creating_job(self):
        with patch("hydralysis.api.load", return_value={}), patch("hydralysis.preparation.prepare") as prepare:
            for value in ("false", 0, None):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "boolean"):
                    call("prepare", {"exe": "owned.exe", "install": value})
        prepare.assert_not_called()

    def test_cli_options_file_preserves_json_and_rejects_arrays(self):
        with workdir() as folder:
            path = Path(folder) / "options.json"
            expected = {"kind": "comment", "source": "fixture:1", "comment": "quoted \"value\"\nsecond line"}
            path.write_text(json.dumps(expected), encoding="utf-8-sig")
            with patch("hydralysis.cli.call", return_value="ok") as dispatch, redirect_stdout(io.StringIO()):
                self.assertEqual(main(["ghidra-query", "--target", "owned", "0x401000", "--action", "type_edit",
                                       "--options-file", str(path)]), 0)
            self.assertEqual(dispatch.call_args.args[1]["options"], expected)
            path.write_text("[]", encoding="utf-8")
            with patch("hydralysis.cli.call") as dispatch, redirect_stderr(io.StringIO()):
                self.assertEqual(main(["runtime", "status", "--options-file", str(path)]), 1)
            dispatch.assert_not_called()

    def test_prepared_registry_and_installed_paths_load_without_config_edits(self):
        from hydralysis.config import load
        with workdir() as folder:
            root = Path(folder)
            config = root / "local.json"
            config.write_text(json.dumps({"targets": {"manual": {"program": "manual.exe"}}}))
            (root / "backend.json").write_text(json.dumps({"hydra_dir": "installed-engine", "java_home": "installed-jdk"}))
            (root / "targets.json").write_text(json.dumps({"targets": {"prepared": {"program": "prepared.exe"}}}))
            with patch.dict(os.environ, {"HYDRALYSIS_ROOT": str(root), "HYDRALYSIS_CONFIG": str(config)}):
                settings = load()
            self.assertEqual(set(settings["targets"]), {"prepared", "manual"})
            self.assertEqual(settings["hydra_dir"], "installed-engine")

    def test_example_config_is_never_loaded_as_a_live_target(self):
        from hydralysis.config import config_path
        with workdir() as folder:
            root = Path(folder)
            (root / "config.example.json").write_text('{"targets":{"sample":{"exe":"missing.exe"}}}')
            with patch.dict(os.environ, {}, clear=True), patch("hydralysis.config.Path.cwd", return_value=root):
                self.assertIsNone(config_path())

    def test_default_evidence_follows_selected_data_root(self):
        from hydralysis.config import evidence_path
        with patch.dict(os.environ, {}, clear=True), patch("hydralysis.config.load", return_value={"root": "selected-data"}):
            self.assertEqual(evidence_path(), Path("selected-data/evidence.db"))

    def test_hook_manifest_normalizes_real_table_shape_and_checks_build(self):
        from test_pe import image
        pe = image()
        with workdir() as folder:
            path = Path(folder) / "hooks.json"
            envelope = {"schema": "owned-hooks/1", "module": "fixture.exe", "build_id": "fixture",
                        "build_sha256": pe.fingerprint()["sha256"], "image_base": hex(pe.base),
                        "hooks": [{"offset": "0x1000", "prologue": "90909090", "names": ["first", "alias"],
                                   "instrumented": True, "required": False} for _ in range(21)]}
            path.write_text(json.dumps(envelope))
            output = io.StringIO()
            with patch("hydralysis.api._image", return_value=pe) as opened, redirect_stdout(output):
                self.assertEqual(main(["prologue", "--exe", "fixture.exe", "--checks-file", str(path), "--offset-kind", "rva"]), 0)
            opened.assert_called_once()
            self.assertEqual(json.loads(output.getvalue())["summary"], {"checked": 21, "matched": 21, "failed": 0})
            envelope["hooks"][-1]["prologue"] = "CC"
            path.write_text(json.dumps(envelope))
            with patch("hydralysis.api._image", return_value=pe), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["prologue", "--exe", "fixture.exe", "--checks-file", str(path), "--offset-kind", "rva"]), 1)
            envelope["build_sha256"] = "f" * 64
            path.write_text(json.dumps(envelope))
            with patch("hydralysis.api._image", return_value=pe), patch.object(pe, "read_rva") as read, redirect_stderr(io.StringIO()):
                self.assertEqual(main(["prologue", "--exe", "fixture.exe", "--checks-file", str(path), "--offset-kind", "rva"]), 1)
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
