"""One resolver for Hydralysis's data root, shared by static analysis and runtime.

The default is per user and holds no host policy. A machine that keeps its data
off some drives says so explicitly with forbidden_drives (or the environment).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from hydralysis import compat


def validate_project_path(directory: str | Path) -> Path:
    """Fail before an engine launch: Ghidra rejects dot-prefixed path components."""
    path = Path(directory).expanduser().resolve()
    if any(part.startswith(".") for part in path.parts):
        raise ValueError("Ghidra project paths cannot contain dot-prefixed directories: %s; "
                         "choose a dot-free data root/project directory" % path)
    return path


def _root_for(name_cased: str, name_plain: str, platform: str, environ, home: str) -> Path:
    if platform == "win32":
        return Path(environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local"), name_cased)
    if platform == "darwin":
        return Path(home, "Library", "Application Support", name_cased)
    data = environ.get("XDG_DATA_HOME", "")
    if data and data.startswith("/") and not any(part.startswith(".") for part in data.split("/")):
        return Path(data, name_plain)
    return Path(home, name_plain)


def default_root(platform: str = sys.platform, environ=os.environ, home: str | None = None, exists=os.path.exists) -> Path:
    """Per-user, dot-free: Ghidra refuses project paths under a `.local`-style folder.

    The directory is named hydralysis. If a RusticRE-named root already exists and the
    Hydralysis one does not, that existing root is used as it is: nothing is moved or
    copied, so there is still one data root and one daemon. The fallback is recorded
    (see compat.deprecations); remove it by moving the directory yourself or by
    setting HYDRALYSIS_ROOT.
    """
    home = home or str(Path.home())
    current = _root_for("Hydralysis", "hydralysis", platform, environ, home)
    legacy = _root_for("RusticRE", "rusticre", platform, environ, home)
    if not exists(current) and exists(legacy):
        compat.note("root", str(legacy), str(current),
                    "existing RusticRE data root in use; not moved or copied. Set HYDRALYSIS_ROOT to keep using it explicitly")
        return legacy
    return current


def forbidden_drives(settings: dict) -> list[str]:
    value = settings.get("forbidden_drives")
    if value is None:
        value = compat.env("FORBIDDEN_DRIVES", "")
    if isinstance(value, str):
        value = [item for item in value.replace(";", ",").split(",") if item.strip()]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("forbidden_drives must be a list of drive names such as [\"C:\"]")
    return [item.strip().upper().rstrip("\\/") for item in value]


def root_path(settings: dict) -> Path:
    raw = settings.get("root") or compat.env("ROOT") or default_root()
    root = Path(raw).expanduser().resolve()
    banned = forbidden_drives(settings)
    if root.drive and root.drive.upper() in banned:
        raise ValueError("Hydralysis data root %s is on %s, which this configuration forbids (forbidden_drives=%s); "
                         "set root or HYDRALYSIS_ROOT to an allowed location" % (root, root.drive, ",".join(banned)))
    return validate_project_path(root)
