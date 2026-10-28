"""Optional local config. The path is HYDRALYSIS_CONFIG, else hydralysis.local.json in the per-user Hydralysis folder
(never the working directory). rusticre.local.json and RUSTICRE_CONFIG still work for one release; see compat."""

from __future__ import annotations

import json
from pathlib import Path

from hydralysis import compat

DEFAULT_NAMES = compat.config_names()


def user_config_dir() -> Path:
    """The per-user folder that holds the configuration: the default data root, wherever the process runs from."""
    from hydralysis.paths import default_root
    try:
        return default_root()
    except RuntimeError as exc:  # no home directory in a scrubbed environment
        raise ValueError("no per-user folder: %s; set HYDRALYSIS_CONFIG and HYDRALYSIS_ROOT" % exc) from exc


def config_source() -> tuple[Path | None, str]:
    """The configuration file and where it was found: `env` (HYDRALYSIS_CONFIG), `user` (the per-user folder) or `none`.

    The working directory is never searched (PROTOCOL-3.md Z3): the same configuration, and so the same data root,
    applies to every harness launch whatever directory it starts in. `ignored_cwd_config()` names a file a
    previous release would have picked up there.
    """
    env = compat.env("CONFIG")
    if env:
        return Path(env), "env"
    try:
        folder = user_config_dir()
    except ValueError:
        return None, "none"
    for name in DEFAULT_NAMES:
        candidate = folder / name
        if candidate.is_file():
            if name == compat.LEGACY_CONFIG:
                compat.note("config-file", str(candidate), compat.PRIMARY_CONFIG)
            return candidate, "user"
    return None, "none"


def config_path() -> Path | None:
    return config_source()[0]


def ignored_cwd_config() -> Path | None:
    """A configuration file in the working directory that is NOT used (earlier releases read it), or None."""
    try:
        here = Path.cwd()
    except OSError:
        return None
    for name in DEFAULT_NAMES:
        if (here / name).is_file():
            return here / name
    return None


def read_settings() -> dict:
    """The configuration file as written (an empty dict when there is none)."""
    path = config_path()
    settings = {}
    if path is not None and path.is_file():
        with path.open(encoding="utf-8") as handle:
            settings = json.load(handle)
        if not isinstance(settings, dict):
            raise ValueError("Hydralysis config must be a JSON object")
    return settings


def load() -> dict:
    settings = read_settings()
    from hydralysis.backends import read_json, root_path

    # HYDRALYSIS_ROOT selects an independent workspace without editing a config.
    if compat.env("ROOT"):
        settings["root"] = compat.env("ROOT")
    root = root_path(settings)
    installed = read_json(root / "backend.json")
    prepared = read_json(root / "targets.json").get("targets", {})
    result = {"root": str(root), "max_mem": "6G", "max_cpu": 4, **installed, **settings}
    # Explicit local target definitions win; prepared targets need no hand edits.
    result["targets"] = {**prepared, **(settings.get("targets") or settings.get("projects") or {})}
    return result


def evidence_path(explicit: str = "") -> Path:
    if explicit:
        return Path(explicit)
    env = compat.env("EVIDENCE")
    if env:
        return Path(env)
    settings = load()
    if settings.get("evidence"):
        return Path(settings["evidence"])
    return Path(settings["root"]) / "evidence.db"
