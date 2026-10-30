"""RUSTICRE_* names, rusticre.local.json and the old console script still work for one release, and say so."""

from __future__ import annotations

import io
import json
import os
import tomllib
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from hydralysis import compat, config
from support import REPOSITORY, workdir


class LegacyEnvironment(unittest.TestCase):
    def test_primary_wins_and_legacy_is_a_recorded_fallback(self):
        with patch.dict(compat._records, {}, clear=True):
            self.assertEqual(compat.env("X", environ={"HYDRALYSIS_X": "new", "RUSTICRE_X": "old"}), "new")
            self.assertEqual(compat.deprecations(), [])
            self.assertIsNone(compat.env("X", environ={}))
            self.assertEqual(compat.env("X", "dflt", environ={"HYDRALYSIS_X": ""}), "dflt")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(compat.env("X", environ={"RUSTICRE_X": "old"}), "old")
            self.assertEqual(compat.deprecations(), [{"deprecated": "RUSTICRE_X", "use": "HYDRALYSIS_X"}])

    def test_the_notice_is_printed_once(self):
        with patch.dict(compat._records, {}, clear=True):
            err = io.StringIO()
            with redirect_stderr(err):
                for _ in range(5):
                    compat.env("Y", environ={"RUSTICRE_Y": "1"})
            self.assertEqual(err.getvalue().count("RUSTICRE_Y"), 1)
            self.assertEqual(len(compat.deprecations()), 1)


class ConfigFile(unittest.TestCase):
    def _find(self, folder: Path):
        # The configuration lives in the per-user folder, never the working directory (Z3).
        with patch.dict(os.environ, {}, clear=True), patch("hydralysis.config.user_config_dir", return_value=folder):
            return config.config_path()

    def test_old_config_name_is_found_and_recorded_but_the_new_one_wins(self):
        with workdir("compat-config") as name, patch.dict(compat._records, {}, clear=True):
            folder = Path(name)
            (folder / "rusticre.local.json").write_text(json.dumps({}), encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(self._find(folder), folder / "rusticre.local.json")
            self.assertEqual(compat.deprecations()[0]["use"], "hydralysis.local.json")
            (folder / "hydralysis.local.json").write_text(json.dumps({}), encoding="utf-8")
            self.assertEqual(self._find(folder), folder / "hydralysis.local.json")

    def test_old_config_variable(self):
        with patch.dict(compat._records, {}, clear=True), redirect_stderr(io.StringIO()), \
                patch.dict(os.environ, {"RUSTICRE_CONFIG": "old.json"}, clear=True):
            self.assertEqual(config.config_path(), Path("old.json"))
            self.assertEqual(compat.deprecations()[0]["deprecated"], "RUSTICRE_CONFIG")


class Packaging(unittest.TestCase):
    def test_both_console_scripts_share_one_entry_point_and_the_version_is_dev_or_released(self):
        project = tomllib.loads((REPOSITORY / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["name"], "hydralysis")
        self.assertEqual(project["scripts"], {"hydralysis": "hydralysis.cli:main", "rusticre": "hydralysis.cli:main"})
        from hydralysis import __version__
        self.assertEqual(project["version"], __version__)
        # Between releases a dev version; on a release commit, a version with its own CHANGELOG section
        if "dev" not in __version__:
            changelog = (REPOSITORY / "CHANGELOG.md").read_text(encoding="utf-8")
            self.assertIn("\n## %s\n" % __version__, changelog.replace("\r\n", "\n"))

    def test_mcp_server_name_and_attribution_prefix(self):
        from hydralysis import hydra, mcp
        self.assertEqual(mcp.SERVER_INFO["name"], "hydralysis")
        # Kept on purpose for this release; see the comment on hydra.INSTANCE.
        self.assertEqual((hydra.INSTANCE, hydra.ATTRIBUTION), ("rusticre", "rusticre"))


if __name__ == "__main__":
    unittest.main()
