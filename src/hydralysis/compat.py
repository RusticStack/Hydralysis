"""The single resolver for names Hydralysis inherited from RusticRE.

HYDRALYSIS_* environment variables, hydralysis.local.json and the Hydralysis data
root are primary. For one release the old RUSTICRE_* variables, rusticre.local.json
and an existing RusticRE data root are still honoured, so an installed MCP
registration or a running setup keeps working. Every fallback that actually fires is
recorded here, announced once on stderr, and listed by `backend inspect`
(`deprecated`), so nothing is silently relied on.
"""

from __future__ import annotations

import os
import sys
import threading

PRIMARY_PREFIX = "HYDRALYSIS_"
LEGACY_PREFIX = "RUSTICRE_"
PRIMARY_CONFIG = "hydralysis.local.json"
LEGACY_CONFIG = "rusticre.local.json"

_lock = threading.Lock()
_records: dict[str, dict] = {}


def note(key: str, old: str, new: str, detail: str = "") -> None:
    """Record one deprecated name in use; the first time only, it is also announced."""
    with _lock:
        if key in _records:
            return
        _records[key] = {"deprecated": old, "use": new, "detail": detail} if detail else {"deprecated": old, "use": new}
    # stderr only: the MCP transport owns stdout.
    print("hydralysis: %s is deprecated (formerly RusticRE); use %s. It is still honoured for this release."
          % (old, new), file=sys.stderr)


def deprecations() -> list[dict]:
    """What this process has fallen back to so far, for backend inspect."""
    with _lock:
        return [dict(item) for item in _records.values()]


def env(name: str, default: str | None = None, environ=None) -> str | None:
    """HYDRALYSIS_<name>, else RUSTICRE_<name> (recorded as deprecated), else default.

    An empty value counts as unset, matching how the callers already treated it.
    """
    environ = os.environ if environ is None else environ
    value = environ.get(PRIMARY_PREFIX + name)
    if value:
        return value
    legacy = environ.get(LEGACY_PREFIX + name)
    if legacy:
        note("env:" + name, LEGACY_PREFIX + name, PRIMARY_PREFIX + name)
        return legacy
    return default


def config_names() -> tuple[str, str]:
    return PRIMARY_CONFIG, LEGACY_CONFIG
