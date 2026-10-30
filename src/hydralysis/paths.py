"""One resolver for Hydralysis's data root, shared by static analysis and runtime.

The default is per user and holds no host policy. A machine that keeps its data
off some drives says so explicitly with forbidden_drives (or the environment).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from hydralysis import compat

# `Path.resolve` on Windows opens the path twice (GetFinalPathNameByHandle): a query resolved the data root and its project
# paths about twenty times, which was over half of the CPU a warm query spent in Hydralysis. The answer for one path text is
# kept briefly; a junction or link retargeted under a running process is seen once the entry is older than RESOLVE_TTL_S.
RESOLVE_TTL_S = 2.0
_RESOLVE_CAP = 512
_resolved_cache: dict[tuple[str, str], tuple[float, Path]] = {}
_resolved_guard = threading.Lock()


def resolved(path: str | Path) -> Path:
    """`Path(path).expanduser().resolve()`, remembered for RESOLVE_TTL_S per path text (and working directory when the
    text is relative)."""
    expanded = Path(path).expanduser()
    text = str(expanded)
    key = (text, "" if expanded.is_absolute() else os.getcwd())
    now = time.monotonic()
    with _resolved_guard:
        found = _resolved_cache.get(key)
    if found is not None and now - found[0] < RESOLVE_TTL_S:
        return found[1]
    result = expanded.resolve()
    with _resolved_guard:
        if len(_resolved_cache) >= _RESOLVE_CAP:
            _resolved_cache.clear()
        _resolved_cache[key] = (now, result)
    return result


def validate_project_path(directory: str | Path) -> Path:
    """Fail before an engine launch: Ghidra rejects dot-prefixed path components."""
    path = resolved(directory)
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


_roots: dict[tuple, tuple[float, Path]] = {}


def root_path(settings: dict) -> Path:
    raw = settings.get("root") or compat.env("ROOT") or default_root()
    banned = forbidden_drives(settings)
    # A query asks for the root a few dozen times; the checked answer is kept as long as `resolved` keeps its part.
    key = (str(raw), tuple(banned), "" if os.path.isabs(str(raw)) else os.getcwd())
    now = time.monotonic()
    with _resolved_guard:
        found = _roots.get(key)
    if found is not None and now - found[0] < RESOLVE_TTL_S:
        return found[1]
    checked = _root_path(raw, banned)
    with _resolved_guard:
        if len(_roots) >= _RESOLVE_CAP:
            _roots.clear()
        _roots[key] = (now, checked)
    return checked


def _root_path(raw, banned: list[str]) -> Path:
    root = resolved(raw)
    if root.drive and root.drive.upper() in banned:
        raise ValueError("Hydralysis data root %s is on %s, which this configuration forbids (forbidden_drives=%s); "
                         "set root or HYDRALYSIS_ROOT to an allowed location" % (root, root.drive, ",".join(banned)))
    return validate_project_path(root)


def root_source(settings: dict | None = None, environ=os.environ, exists=os.path.exists) -> str:
    """Where the data root comes from: `env`, `config`, `default` or `legacy` (an existing RusticRE-named root)."""
    settings = settings or {}
    if compat.env("ROOT", environ=environ):
        return "env"
    if settings.get("root"):
        return "config"
    home = str(Path.home())
    current = _root_for("Hydralysis", "hydralysis", sys.platform, environ, home)
    legacy = _root_for("RusticRE", "rusticre", sys.platform, environ, home)
    return "legacy" if not exists(current) and exists(legacy) else "default"


def system_drive(platform: str = sys.platform, environ=os.environ) -> str | None:
    """The drive Windows lives on (`C:`), or None where there is no drive letter."""
    if platform != "win32":
        return None
    return (environ.get("SystemDrive") or "C:").upper().rstrip("\\/")


def volume_info(path: str | Path, probe=None) -> dict:
    """The file system under PATH: `{fs, cow, drive}`; `fs` is None and `cow` None when it cannot be read.

    `cow` is True for ReFS (and APFS, btrfs, xfs, bcachefs), where a fork can be a block clone, and False for
    others, so a non-COW root can be warned about. PROBE(path) -> fs name replaces the system call (tests).
    """
    target = Path(path)
    while not target.exists() and target.parent != target:
        target = target.parent
    drive = target.drive.upper() if target.drive else None
    try:
        name = probe(target) if probe is not None else _fs_name(target)
    except Exception:
        name = None
    if not name:
        return {"fs": None, "cow": None, "drive": drive}
    return {"fs": name, "cow": name.lower() in ("refs", "apfs", "btrfs", "xfs", "bcachefs", "zfs"), "drive": drive}


def _fs_name(path: Path) -> str | None:
    if sys.platform == "win32":
        import ctypes
        root = ctypes.create_unicode_buffer(260)
        if not ctypes.windll.kernel32.GetVolumePathNameW(str(path), root, 260):
            return None
        fs = ctypes.create_unicode_buffer(64)
        if not ctypes.windll.kernel32.GetVolumeInformationW(root.value, None, 0, None, None, None, fs, 64):
            return None
        return fs.value or None
    best, found = "", None
    try:
        with open("/proc/mounts", encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 3:
                    mount = parts[1].replace("\\040", " ")
                    if str(path).startswith(mount) and len(mount) > len(best):
                        best, found = mount, parts[2]
    except OSError:
        return None
    return found
