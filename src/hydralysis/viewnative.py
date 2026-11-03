"""Routing of the disk-level view and commit functions to the optional Rust implementation (`HYDRALYSIS_IMPL=rust`).

The Rust side is `hy_views` behind `hydralysis_native.views_call_rs(name, json_args)`. Python stays the default and the
fallback: without the variable, or without a native module that carries the binding, the original function runs."""

from __future__ import annotations

import functools
import inspect
import json
import os
import sys

from hydralysis import durable

_REPLACE_FILE = durable.replace_file
_OVERLAY_CAP = 4096


def native_views():
    """The native module when `HYDRALYSIS_IMPL=rust` and it carries the views binding, else None (Python runs)."""
    if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() != "rust":
        return None
    try:
        import hydralysis_native as native
    except ImportError:
        return None
    if not hasattr(native, "views_call_rs"):
        return None
    return None if _python_seams_active() else native


def _python_seams_active() -> bool:
    """True while a Python-side seam the Rust code cannot see is in use (fault injection, a patched replace or overlay cap):
    those calls run the original so the behaviour under the seam stays the specified one."""
    if os.environ.get("HYDRALYSIS_TEST_FAULT"):
        return True
    if durable.replace_file is not _REPLACE_FILE:
        return True
    workcopy = sys.modules.get("hydralysis.workcopy")
    return workcopy is not None and getattr(workcopy, "MAX_OVERLAYS", _OVERLAY_CAP) != _OVERLAY_CAP


def routed(name: str, python_function, error, prepare=None, finish=None):
    """PYTHON_FUNCTION answered by the native function NAME when it exists. The arguments cross as JSON; the exceptions come
    back as the ones the original raises (ERROR for a code-carrying refusal, RuntimeError, ValueError)."""
    signature = inspect.signature(python_function)

    @functools.wraps(python_function)
    def wrapper(*args, **kwargs):
        native = native_views()
        if native is None:
            return python_function(*args, **kwargs)
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        values = list(bound.arguments.values())
        values = prepare(values) if prepare else values
        reply = json.loads(native.views_call_rs(name, json.dumps(values, default=str)))
        if "ok" in reply:
            return finish(reply["ok"]) if finish else reply["ok"]
        failure = reply["err"]
        if failure["kind"] == "view":
            detail = {key: item for key, item in failure["payload"].items() if key not in ("error", "message")}
            raise error(failure["code"], failure["message"], **detail)
        if failure["kind"] == "runtime":
            raise RuntimeError(failure["message"])
        raise ValueError(failure["message"])

    wrapper.python_function = python_function
    return wrapper
