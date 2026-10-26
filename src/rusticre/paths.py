"""One resolver for RusticRE's data root, shared by static analysis and runtime.

The default is per user and holds no host policy. A machine that keeps its data
off some drives says so explicitly with forbidden_drives (or the environment).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def validate_project_path(directory: str | Path) -> Path:
    """Fail before an engine launch: Ghidra rejects dot-prefixed path components."""
    path = Path(directory).expanduser().resolve()
    if any(part.startswith(".") for part in path.parts):
        raise ValueError("Ghidra project paths cannot contain dot-prefixed directories: %s; "
                         "choose a dot-free data root/project directory" % path)
    return path


def default_root(platform: str = sys.platform, environ=os.environ, home: str | None = None) -> Path:
    """Per-user, dot-free: Ghidra refuses project paths under a `.local`-style folder."""
    home = home or str(Path.home())
    if platform == "win32":
        return Path(environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local"), "RusticRE")
    if platform == "darwin":
        return Path(home, "Library", "Application Support", "RusticRE")
    data = environ.get("XDG_DATA_HOME", "")
    if data and data.startswith("/") and not any(part.startswith(".") for part in data.split("/")):
        return Path(data, "rusticre")
    return Path(home, "rusticre")


def forbidden_drives(settings: dict) -> list[str]:
    value = settings.get("forbidden_drives")
    if value is None:
        value = os.environ.get("RUSTICRE_FORBIDDEN_DRIVES", "")
    if isinstance(value, str):
        value = [item for item in value.replace(";", ",").split(",") if item.strip()]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("forbidden_drives must be a list of drive names such as [\"C:\"]")
    return [item.strip().upper().rstrip("\\/") for item in value]


def root_path(settings: dict) -> Path:
    raw = settings.get("root") or os.environ.get("RUSTICRE_ROOT") or default_root()
    root = Path(raw).expanduser().resolve()
    banned = forbidden_drives(settings)
    if root.drive and root.drive.upper() in banned:
        raise ValueError("RusticRE data root %s is on %s, which this configuration forbids (forbidden_drives=%s); "
                         "set root or RUSTICRE_ROOT to an allowed location" % (root, root.drive, ",".join(banned)))
    return validate_project_path(root)
