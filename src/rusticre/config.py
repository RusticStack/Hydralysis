"""Optional local config. The path is RUSTICRE_CONFIG, else rusticre.local.json."""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_NAMES = ("rusticre.local.json",)


def config_path() -> Path | None:
    env = os.environ.get("RUSTICRE_CONFIG")
    if env:
        return Path(env)
    for name in DEFAULT_NAMES:
        candidate = Path.cwd() / name
        if candidate.is_file():
            return candidate
    return None


def load() -> dict:
    path = config_path()
    settings = {}
    if path is not None and path.is_file():
        with path.open(encoding="utf-8") as handle:
            settings = json.load(handle)
        if not isinstance(settings, dict):
            raise ValueError("RusticRE config must be a JSON object")
    from rusticre.backends import read_json, root_path

    # RUSTICRE_ROOT selects an independent workspace without editing a config.
    if os.environ.get("RUSTICRE_ROOT"):
        settings["root"] = os.environ["RUSTICRE_ROOT"]
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
    env = os.environ.get("RUSTICRE_EVIDENCE")
    if env:
        return Path(env)
    settings = load()
    if settings.get("evidence"):
        return Path(settings["evidence"])
    return Path(settings["root"]) / "evidence.db"
