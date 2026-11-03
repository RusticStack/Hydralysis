"""Routing of the disk-level view, commit and working-copy functions to the optional Rust implementation
(`HYDRALYSIS_IMPL=rust`).

The Rust side is `hy_views` behind `hydralysis_native.views_call_rs(name, json_args)` (plain JSON in, JSON out) and
`hydralysis_native.workcopy_host_call_rs(name, json_args, host)` (the functions that call back into Python for the engine:
`heal`, `_sync`, the caller's identity). Python stays the default and the fallback: without the variable, or without a native
module that carries the binding, the original function runs.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
import sys

from hydralysis import durable

_REPLACE_FILE = durable.replace_file
_OVERLAY_CAP = 4096
_READY: list = []


def _impl_is_rust() -> bool:
    return os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() == "rust"


def _ready(native) -> None:
    """Once per process: the Rust store cleans the records it loads with `analysis.validate_options` exactly as `_clean_record`
    does (the Rust validator for what it can answer, this callable for the rest)."""
    if _READY or not hasattr(native, "workcopy_set_validator"):
        return

    def validate(text: str) -> str:
        from hydralysis import analysis
        return json.dumps(analysis.validate_options("type_edit", json.loads(text), _record=True))

    native.workcopy_set_validator(validate)
    _READY.append(True)


def native_views():
    """The native module when `HYDRALYSIS_IMPL=rust` and it carries the views binding, else None (Python runs)."""
    if not _impl_is_rust():
        return None
    try:
        import hydralysis_native as native
    except ImportError:
        return None
    if not hasattr(native, "views_call_rs"):
        return None
    if _python_seams_active():
        return None
    _ready(native)
    return native


# What a test (or a caller) may replace in `workcopy`: the Rust code cannot see these, so the original runs while one is
# replaced. `workcopy` records the originals at the end of its own module (`_SEAMS`).
def _python_seams_active() -> bool:
    """True while a Python-side seam the Rust code cannot see is in use (fault injection, a patched replace, a patched
    `workcopy` function or limit): those calls run the original so the behaviour under the seam stays the specified one."""
    if os.environ.get("HYDRALYSIS_TEST_FAULT"):
        return True
    if durable.replace_file is not _REPLACE_FILE:
        return True
    workcopy = sys.modules.get("hydralysis.workcopy")
    if workcopy is None:
        return False
    if getattr(workcopy, "MAX_OVERLAYS", _OVERLAY_CAP) != _OVERLAY_CAP:
        return True
    seams = getattr(workcopy, "_SEAMS", None)
    if seams is None:
        return False
    return any(getattr(workcopy, name, original) is not original and getattr(workcopy, name, original) != original
               for name, original in seams.items())


def _view_error():
    from hydralysis import views
    return views.ViewError


def _raise(failure: dict, error=None):
    kind = failure["kind"]
    if kind == "view":
        detail = {key: item for key, item in failure["payload"].items() if key not in ("error", "message")}
        raise (error or _view_error())(failure["code"], failure["message"], **detail)
    if kind == "runtime":
        raise RuntimeError(failure["message"])
    if kind == "io":
        raise (FileNotFoundError if failure.get("not_found") else OSError)(failure["message"])
    if kind == "store_corrupt":
        from pathlib import Path
        raise durable.StoreCorrupt(Path(failure["path"]), Path(failure["backup"]), dict(failure["reasons"]))
    if kind == "lock_busy":
        from pathlib import Path
        from hydralysis.locks import LockBusy
        raise LockBusy(failure["what"], Path(failure["path"]), failure["waited_s"], failure["retry_after_ms"])
    raise ValueError(failure["message"])


def call(native, name: str, values: list):
    """The native function NAME on VALUES (JSON); the reply's value, or the exception the original raises."""
    reply = json.loads(native.views_call_rs(name, json.dumps(values, default=str)))
    if "ok" in reply:
        return reply["ok"]
    _raise(reply["err"])


def routed(name: str, python_function, error=None, prepare=None, finish=None):
    """PYTHON_FUNCTION answered by the native function NAME when it exists. The arguments cross as JSON; the exceptions come
    back as the ones the original raises (ERROR for a code-carrying refusal, RuntimeError, ValueError, OSError)."""
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
        _raise(reply["err"], error)

    wrapper.python_function = python_function
    return wrapper


def _store_unpatched() -> bool:
    """False while a white-box test has replaced a part of the store writer or reader (see `_rust_store.install_storelog`):
    the whole-store load and save then run in Python, through the patched part."""
    storelog = sys.modules.get("hydralysis.storelog")
    check = getattr(storelog, "rust_unpatched", None)
    return check is None or check()


def store_text(settings: dict, target: dict) -> str | None:
    """The version-3 store of the view as JSON text, loaded and cleaned by Rust; None when Rust does not answer (the Python
    `_load_store_uncached` then does). The reply is `{"ok":<store>}`: the store text is cut out of it, not parsed twice."""
    native = native_views()
    if native is None or not _store_unpatched():
        return None
    reply = native.views_call_rs("workcopy_load_store", json.dumps([settings, target], default=str))
    if reply.startswith('{"ok":') and reply.endswith("}"):
        return reply[6:-1]
    _raise(json.loads(reply)["err"])


def save_store(settings: dict, target: dict, store: dict) -> bool:
    """Write the store with Rust (`HYDRALYSIS_IMPL=rust`, no seam replaced); False when Rust does not answer."""
    native = native_views()
    if native is None or not _store_unpatched():
        return False
    reply = native.views_call_rs("workcopy_save_store", json.dumps([settings, target, store], default=str))
    if not reply.startswith('{"ok":'):
        _raise(json.loads(reply)["err"])
    return True


class WorkcopyHost:
    """What the Rust `edit`, `revert` and `add_proposals` ask of Python: the engine-bound steps and the caller's identity.
    Each method takes one JSON array text and answers one JSON text; an exception propagates to the caller unchanged. The
    functions are looked up on `workcopy` at the moment of the call, so a replaced `heal` or `_sync` is the one that runs."""

    def heal(self, text: str) -> str:
        from hydralysis import workcopy
        settings, target = json.loads(text)
        return json.dumps(bool(workcopy.heal(settings, target)))

    def sync(self, text: str) -> str:
        from hydralysis import workcopy
        settings, target, store, timeout_s, extra, sweep = json.loads(text)
        extras = {} if sweep else {"sweep": False}
        state = workcopy._sync(settings, target, store, timeout_s, extra=extra, **extras)
        return json.dumps(state, default=str)

    def attribution(self, text: str) -> str:
        from hydralysis import workcopy
        return json.dumps(workcopy._attribution(), default=str)


_HOST = WorkcopyHost()


def hosted(name: str, python_function, drop: tuple[str, ...] = ("engine",), finish=None):
    """Like `routed`, for the functions whose engine-bound steps Rust asks `WorkcopyHost` for. The parameters named in DROP
    (the engine handle) do not cross.

    Opt-in (`HYDRALYSIS_ROUTE_HOSTED=1`, besides `HYDRALYSIS_IMPL=rust`): measured on a 3000-record view
    (benchmarks/bench_workcopy.py -w edit), the Rust edit, revert and add_proposals cost about the CPU of the Python ones
    (4.5 s against 5.0 s) but a peak of 164 MiB against 87 MiB, because the store crosses as JSON text in every call; the
    default rust route (Rust `load_store` and `save_store`, Python `edit`/`revert`) is 119 MiB, so by default the hosted ones
    stay Python. The Rust code is tested against Python."""
    signature = inspect.signature(python_function)

    @functools.wraps(python_function)
    def wrapper(*args, **kwargs):
        native = native_views() if os.environ.get("HYDRALYSIS_ROUTE_HOSTED") == "1" else None
        if native is None or not hasattr(native, "workcopy_host_call_rs"):
            return python_function(*args, **kwargs)
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        values = [value for key, value in bound.arguments.items() if key not in drop]
        reply = json.loads(native.workcopy_host_call_rs(name, json.dumps(values, default=str), _HOST))
        if "ok" in reply:
            return finish(reply["ok"]) if finish else reply["ok"]
        _raise(reply["err"])

    wrapper.python_function = python_function
    return wrapper
