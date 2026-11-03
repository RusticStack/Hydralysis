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


# Ported, tested against the Python and exposed by the extension, but not routed unless asked for: measured no faster than the
# Python (the report builders and `shape` spend their time moving Python objects across, not in the logic; see
# rust/crates/hy-trace/PORTING.md). HYDRALYSIS_TRACE_HELD=1 routes them anyway; the parity tests do.
HELD_BACK = ("reports_", "trace_shape")


def function(name: str):
    """The native function NAME, or None (routing off, held back, or this build of the extension lacks it)."""
    module = native()
    if module is None:
        return None
    if name.startswith(HELD_BACK) and os.environ.get("HYDRALYSIS_TRACE_HELD") != "1":
        return None
    return getattr(module, name, None)
