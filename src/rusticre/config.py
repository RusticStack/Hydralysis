"""Optional local config. The path is RUSTICRE_CONFIG, else rusticre.local.json."""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_NAMES = ("rusticre.local.json", "config.example.json")


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
    if path is None or not path.is_file():
        return {}
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def evidence_path(explicit: str = "") -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get("RUSTICRE_EVIDENCE")
    if env:
        return Path(env)
    settings = load()
    if settings.get("evidence"):
        return Path(settings["evidence"])
    return Path.cwd() / ".rusticre" / "evidence.db"
