"""Opt-in routing of the trace tool's pure logic to the Rust port (`hydralysis_native`, crate `hy-trace`).

`HYDRALYSIS_IMPL=rust` turns it on (the same switch every ported lane uses); `HYDRALYSIS_NATIVE=0` turns it off again. A
missing extension or an input the port does not model (`hydralysis_native.TraceFallback`) leaves the call to the Python
implementation, which stays the specification: the tests under tests/test_trace*.py run against both.
"""

from __future__ import annotations

import os


def native():
    """The `hydralysis_native` module when routing is on and it carries the trace port, else None."""
    if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() != "rust" or os.environ.get("HYDRALYSIS_NATIVE", "1") == "0":
        return None
    try:
        import hydralysis_native as module  # type: ignore[import-not-found]
    except ImportError:
        return None
    return module if hasattr(module, "TraceFallback") else None


def function(name: str):
    """The native function NAME, or None (routing off, or this build of the extension lacks it)."""
    module = native()
    return getattr(module, name, None) if module is not None else None
