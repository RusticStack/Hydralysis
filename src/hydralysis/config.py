"""Optional local config. The path is HYDRALYSIS_CONFIG, else hydralysis.local.json
(rusticre.local.json and RUSTICRE_CONFIG still work for one release; see compat)."""

from __future__ import annotations

import json
from pathlib import Path

from hydralysis import compat

DEFAULT_NAMES = compat.config_names()


def config_path() -> Path | None:
    env = compat.env("CONFIG")
    if env:
        return Path(env)
    for name in DEFAULT_NAMES:
        candidate = Path.cwd() / name
        if candidate.is_file():
            if name == compat.LEGACY_CONFIG:
                compat.note("config-file", str(candidate), compat.PRIMARY_CONFIG)
            return candidate
    return None


def load() -> dict:
    path = config_path()
    settings = {}
    if path is not None and path.is_file():
        with path.open(encoding="utf-8") as handle:
            settings = json.load(handle)
        if not isinstance(settings, dict):
            raise ValueError("Hydralysis config must be a JSON object")
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
