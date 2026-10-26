"""The data root has no host policy by default, and children never inherit stdin."""

from __future__ import annotations

import ast
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from rusticre import paths
from support import REPOSITORY, workdir


class DataRoot(unittest.TestCase):
    def test_default_root_is_per_user_and_dot_free(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RUSTICRE_ROOT", None)
            root = paths.root_path({})
        self.assertFalse(any(part.startswith(".") for part in root.parts))
        if os.name == "nt":
            self.assertEqual(root, (Path(os.environ["LOCALAPPDATA"]) / "RusticRE").resolve())

    def test_each_platform_default(self):
        home = "/home/user" if os.name != "nt" else "C:/Users/user"
        self.assertEqual(paths.default_root("linux", {"XDG_DATA_HOME": "/home/user/.local/share"}, home),
                         Path(home, "rusticre"))
        self.assertEqual(paths.default_root("linux", {"XDG_DATA_HOME": "/srv/data"}, home), Path("/srv/data", "rusticre"))
        self.assertEqual(paths.default_root("linux", {}, home), Path(home, "rusticre"))
        self.assertEqual(paths.default_root("darwin", {}, home), Path(home, "Library", "Application Support", "RusticRE"))
        self.assertEqual(paths.default_root("win32", {"LOCALAPPDATA": "C:/Users/user/AppData/Local"}, home),
                         Path("C:/Users/user/AppData/Local", "RusticRE"))

    def test_any_drive_is_allowed_unless_configured(self):
        with workdir("root") as folder:
            root = Path(folder) / "data"
            self.assertEqual(paths.root_path({"root": str(root)}), root.resolve())
            drive = root.resolve().drive
            if drive:
                with self.assertRaisesRegex(ValueError, "forbids"):
                    paths.root_path({"root": str(root), "forbidden_drives": [drive.lower()]})
                with patch.dict(os.environ, {"RUSTICRE_FORBIDDEN_DRIVES": "Q:," + drive}):
                    with self.assertRaisesRegex(ValueError, "forbids"):
                        paths.root_path({"root": str(root)})

    def test_environment_root_and_dot_components(self):
        with workdir("root") as folder:
            with patch.dict(os.environ, {"RUSTICRE_ROOT": str(Path(folder) / "env-root")}):
                self.assertEqual(paths.root_path({}), (Path(folder) / "env-root").resolve())
            with self.assertRaisesRegex(ValueError, "dot-prefixed"):
                paths.root_path({"root": str(Path(folder) / ".cache" / "data")})

    def test_runtime_and_static_analysis_resolve_the_same_root(self):
        from rusticre import backends, runtime
        with workdir("root") as folder:
            settings = {"root": str(Path(folder) / "shared")}
            self.assertEqual(runtime._root(settings, create=False), paths.root_path(settings))
            self.assertEqual(Path(backends.inspect(settings)["root"]), paths.root_path(settings))


class ChildProcesses(unittest.TestCase):
    def test_only_proc_starts_children(self):
        offenders = []
        for path in (REPOSITORY / "src" / "rusticre").rglob("*.py"):
            if path.name == "proc.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                function = node.func if isinstance(node, ast.Call) else None
                if (isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name)
                        and function.value.id == "subprocess"
                        and function.attr in ("run", "Popen", "call", "check_call", "check_output")):
                    offenders.append("%s:%d" % (path.relative_to(REPOSITORY), node.lineno))
        self.assertEqual(offenders, [], "start children through rusticre.proc so they never inherit stdin")

    def test_children_cannot_be_given_the_servers_stdin(self):
        from rusticre import proc
        import subprocess
        with self.assertRaises(ValueError):
            proc.run(["x"], stdin=subprocess.PIPE)
        with patch("subprocess.run") as run:
            proc.run(["x"], capture_output=True)
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
