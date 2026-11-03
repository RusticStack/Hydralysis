"""Which device the runtime layer talks to: Frida (the default) or the Rust runtime (`HYDRALYSIS_IMPL=rust`).

A Frida stand-in that is configured wins over the variable: a `frida` package that declares `HYDRALYSIS_STAND_IN = True`
(tests/fakefrida does) is a test double for Frida that somebody put on the path on purpose, so the Frida-shaped device keeps
serving it even under `HYDRALYSIS_IMPL=rust`. The Rust device is chosen only when no stand-in is configured. The real
binding, wherever it is installed, is not a stand-in and does not stop the variable from selecting Rust.
"""

from __future__ import annotations

import importlib.util
import os
import sys

_STAND_IN: bool | None = None


def stand_in_configured() -> bool:
    """True when the `frida` this process would import is a declared stand-in (decided once per process)."""
    global _STAND_IN
    if _STAND_IN is None:
        _STAND_IN = _probe_stand_in()
    return _STAND_IN


def _probe_stand_in() -> bool:
    module = sys.modules.get("frida")
    if module is None:
        try:
            if importlib.util.find_spec("frida") is None:
                return False
            import frida as module
        except Exception:
            return False
    return getattr(module, "HYDRALYSIS_STAND_IN", False) is True


def implementation() -> str:
    if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() == "rust" and not stand_in_configured():
        return "rust"
    return "frida"


def get_local_device():
    if implementation() == "rust":
        from hydralysis.rust_frida import RustDevice
        return RustDevice()
    import frida
    return frida.get_local_device()
