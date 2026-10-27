import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from hydralysis.api import _settings, call, tool_table
from hydralysis.cli import main
from hydralysis.mcp import Server

from support import workdir


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
