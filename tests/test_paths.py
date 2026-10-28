"""The data root has no host policy by default, and children never inherit stdin."""

from __future__ import annotations

import ast
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import paths
from support import REPOSITORY, workdir


class DataRoot(unittest.TestCase):
    def test_default_root_is_per_user_and_dot_free(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HYDRALYSIS_ROOT", None)
            root = paths.root_path({})
        self.assertFalse(any(part.startswith(".") for part in root.parts))
        if os.name == "nt":
            # Hydralysis, unless only a RusticRE root exists on this machine (see the fallback test).
            self.assertIn(root, [(Path(os.environ["LOCALAPPDATA"]) / name).resolve() for name in ("Hydralysis", "RusticRE")])

    def test_each_platform_default(self):
        home = "/home/user" if os.name != "nt" else "C:/Users/user"
        none = lambda path: False  # no existing directory of either name
        self.assertEqual(paths.default_root("linux", {"XDG_DATA_HOME": "/home/user/.local/share"}, home, none),
                         Path(home, "hydralysis"))
        self.assertEqual(paths.default_root("linux", {"XDG_DATA_HOME": "/srv/data"}, home, none), Path("/srv/data", "hydralysis"))
        self.assertEqual(paths.default_root("linux", {}, home, none), Path(home, "hydralysis"))
        self.assertEqual(paths.default_root("darwin", {}, home, none), Path(home, "Library", "Application Support", "Hydralysis"))
        self.assertEqual(paths.default_root("win32", {"LOCALAPPDATA": "C:/Users/user/AppData/Local"}, home, none),
                         Path("C:/Users/user/AppData/Local", "Hydralysis"))

    def test_existing_rusticre_root_is_used_in_place_and_recorded(self):
        from hydralysis import compat
        home = "C:/Users/user"
        environ = {"LOCALAPPDATA": "C:/Users/user/AppData/Local"}
        legacy, current = Path("C:/Users/user/AppData/Local", "RusticRE"), Path("C:/Users/user/AppData/Local", "Hydralysis")
        with patch.dict(compat._records, {}, clear=True), patch("sys.stderr"):
            self.assertEqual(paths.default_root("win32", environ, home, lambda p: Path(p) == legacy), legacy)
            self.assertEqual([item["deprecated"] for item in compat.deprecations()], [str(legacy)])
        # Both present, or only the new one: the new root wins and nothing is recorded.
        with patch.dict(compat._records, {}, clear=True):
            self.assertEqual(paths.default_root("win32", environ, home, lambda p: Path(p) in (legacy, current)), current)
            self.assertEqual(paths.default_root("win32", environ, home, lambda p: Path(p) == current), current)
            self.assertEqual(compat.deprecations(), [])

    def test_legacy_environment_root_is_honoured_and_recorded(self):
        from hydralysis import compat
        with workdir("root") as folder:
            old = Path(folder) / "old-env-root"
            with patch.dict(compat._records, {}, clear=True), \
                    patch.dict(os.environ, {"RUSTICRE_ROOT": str(old)}), patch("sys.stderr"):
                os.environ.pop("HYDRALYSIS_ROOT", None)
                self.assertEqual(paths.root_path({}), old.resolve())
                self.assertEqual(compat.deprecations(), [{"deprecated": "RUSTICRE_ROOT", "use": "HYDRALYSIS_ROOT"}])
            with patch.dict(os.environ, {"RUSTICRE_ROOT": str(old), "HYDRALYSIS_ROOT": str(Path(folder) / "new")}):
                self.assertEqual(paths.root_path({}), (Path(folder) / "new").resolve())

    def test_any_drive_is_allowed_unless_configured(self):
        with workdir("root") as folder:
            root = Path(folder) / "data"
            self.assertEqual(paths.root_path({"root": str(root)}), root.resolve())
            drive = root.resolve().drive
            if drive:
                with self.assertRaisesRegex(ValueError, "forbids"):
                    paths.root_path({"root": str(root), "forbidden_drives": [drive.lower()]})
                with patch.dict(os.environ, {"HYDRALYSIS_FORBIDDEN_DRIVES": "Q:," + drive}):
                    with self.assertRaisesRegex(ValueError, "forbids"):
                        paths.root_path({"root": str(root)})

    def test_environment_root_and_dot_components(self):
        with workdir("root") as folder:
            with patch.dict(os.environ, {"HYDRALYSIS_ROOT": str(Path(folder) / "env-root")}):
                self.assertEqual(paths.root_path({}), (Path(folder) / "env-root").resolve())
            with self.assertRaisesRegex(ValueError, "dot-prefixed"):
                paths.root_path({"root": str(Path(folder) / ".cache" / "data")})

    def test_runtime_and_static_analysis_resolve_the_same_root(self):
        from hydralysis import backends, runtime
        with workdir("root") as folder:
            settings = {"root": str(Path(folder) / "shared")}
            self.assertEqual(runtime._root(settings, create=False), paths.root_path(settings))
            self.assertEqual(Path(backends.inspect(settings)["root"]), paths.root_path(settings))


class ChildProcesses(unittest.TestCase):
    def test_only_proc_starts_children(self):
        offenders = []
        for path in (REPOSITORY / "src" / "hydralysis").rglob("*.py"):
            if path.name == "proc.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                function = node.func if isinstance(node, ast.Call) else None
                if (isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name)
                        and function.value.id == "subprocess"
                        and function.attr in ("run", "Popen", "call", "check_call", "check_output")):
                    offenders.append("%s:%d" % (path.relative_to(REPOSITORY), node.lineno))
        self.assertEqual(offenders, [], "start children through hydralysis.proc so they never inherit stdin")

    def test_children_cannot_be_given_the_servers_stdin(self):
        from hydralysis import proc
        import subprocess
        with self.assertRaises(ValueError):
            proc.run(["x"], stdin=subprocess.PIPE)
        with patch("subprocess.run") as run:
            proc.run(["x"], capture_output=True)
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
