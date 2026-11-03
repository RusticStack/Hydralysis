"""Which device the runtime layer talks to: Frida (the default) or the Rust runtime (`HYDRALYSIS_IMPL=rust`)."""

from __future__ import annotations

import os


def implementation() -> str:
    return "rust" if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() == "rust" else "frida"


def get_local_device():
    if implementation() == "rust":
        from hydralysis.rust_frida import RustDevice
        return RustDevice()
    import frida
    return frida.get_local_device()
