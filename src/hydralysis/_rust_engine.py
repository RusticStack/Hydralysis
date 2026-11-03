"""Rust implementation of the pure logic of hydra.py, api.py and a few small leaf modules (`HYDRALYSIS_IMPL=rust`).

The Rust side is `hy_engine` (rust/crates/hy-engine), bound in native/src/hyapi.rs as `hydralysis_native.engine_*_rs`. Each
module that has a Rust twin ends with a hook that calls `install(module)` when `HYDRALYSIS_IMPL` is `rust`; the functions
below then replace the module's own, keeping the original as `wrapper.python_function`.

Python stays the specification and the fallback. A wrapper answers from Rust only for inputs Rust models exactly; for
anything else (a Python integer past 64 bits, `NaN` in a JSON body, a non-string where the original calls `str()`, a patched
seam, a file-system error whose native spelling matters) it runs the original function, which raises its own exceptions.
Exceptions Rust raises are the ones the original raises, with the same message."""

from __future__ import annotations

import functools
import json
import os
import sys

try:
    import hydralysis_native as _native
except ImportError:  # the extension is not built: every function stays Python
    _native = None
else:
    if not hasattr(_native, "engine_call_rs"):
        _native = None

_FALLBACK = object()


def available() -> bool:
    return _native is not None


def _call(name: str, *arguments):
    """The JSON result of the Rust function NAME, or `_FALLBACK` when the original must answer."""
    try:
        text = json.dumps(arguments)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return _FALLBACK
    reply = _native.engine_call_rs(name, text)
    return _FALLBACK if reply is None else json.loads(reply)


def _wrap(module, name: str, rust: str, prepare, finish=None):
    """Replace `module.NAME` by a function that asks Rust first. PREPARE(*args, **kwargs) returns the Rust arguments, or None
    to run the original; FINISH(answer) turns the JSON answer into the value the original returns."""
    original = getattr(module, name)

    @functools.wraps(original)
    def wrapper(*args, **kwargs):
        prepared = prepare(*args, **kwargs)
        if prepared is not None:
            answer = _call(rust, *prepared)
            if answer is not _FALLBACK:
                return finish(answer) if finish else answer
        return original(*args, **kwargs)

    wrapper.python_function = original
    setattr(module, name, wrapper)
    return original


def _replace(module, name: str, make):
    """Replace `module.NAME` by `make(original)`, with the original kept as `python_function`."""
    original = getattr(module, name)
    wrapper = functools.wraps(original)(make(original))
    wrapper.python_function = original
    setattr(module, name, wrapper)
    return original


def _plain_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# ---- hydra ------------------------------------------------------------------------------------------------------

def install_hydra(module) -> None:
    if _native is None:
        return

    def error_text(code, message, details, command, queue, held_ms, retry_after_ms, next):
        if not (isinstance(code, str) and isinstance(message, str) and isinstance(command, str) and isinstance(details, dict)):
            return None
        return code, message, details, command, retry_after_ms, next, queue

    _wrap(module, "_error_text", "engine_error_text", error_text)

    def script_action(fields):
        if fields.get("script") != "RusticQuery.java":
            return None
        args = fields.get("args") or ()
        if isinstance(args, (list, tuple)) and args and isinstance(args[0], str):
            return (args[0],)
        return None

    _wrap(module, "_script_action", "script_action", script_action)
    _wrap(module, "engine_release", "engine_release", lambda directory: (os.fspath(directory),))

    def inspect_engine(directory, allow_unpinned=False):
        from pathlib import Path
        path = Path(directory).expanduser().resolve()
        return (str(path), bool(allow_unpinned), module.RELEASE, module.PROTOCOL, module.PROTOCOL_MIN, module.CLIENT_VERSION)

    _wrap(module, "inspect_engine", "inspect_engine", inspect_engine)

    def client_stamps(path, allow_unpinned):
        shown = str(path)
        return (shown, shown, bool(allow_unpinned), module.RELEASE, module.PROTOCOL, module.PROTOCOL_MIN, module.CLIENT_VERSION)

    _wrap(module, "_client_stamps", "client_stamps", client_stamps)

    def daemon_config(settings):
        if not isinstance(settings, dict):
            return None
        return settings, str(module.root_path(settings))

    _wrap(module, "daemon_config", "daemon_config", daemon_config)

    def wedge_signal(health, stall_ms=30_000):
        if not (health is None or isinstance(health, dict)) or not _plain_int(stall_ms):
            return None
        return health, stall_ms

    _wrap(module, "wedge_signal", "wedge_signal", wedge_signal)


# ---- api --------------------------------------------------------------------------------------------------------

def install_api(module) -> None:
    if _native is None:
        return
    table = module.tool_table
    names, cli_only = module.TOOL_NAMES, module.CLI_ONLY

    def catalog_hash(original):
        def wrapper(table_arg=None):
            # the table of this build is the one `tool_table` makes, unless a test replaced it
            if table_arg is None and module.tool_table is table and module.TOOL_NAMES is names:
                return _native.engine_catalog_hash_rs()
            return original(table_arg)
        return wrapper

    _replace(module, "catalog_hash", catalog_hash)

    def not_available(original):
        def wrapper(capability, message, **detail):
            if isinstance(capability, str) and isinstance(message, str):
                answer = _call("not_available", capability, message, detail, module.CATALOG_EPOCH, module.catalog_hash())
                if answer is not _FALLBACK:
                    return answer
            return original(capability, message, **detail)
        return wrapper

    _replace(module, "not_available", not_available)

    def check_call(original):
        def wrapper(name, args):
            if module.TOOL_NAMES is names and module.CLI_ONLY is cli_only:
                # only the bounded keys cross: the arguments of a batch edit can be large
                bounded = {key: args[key] for key in ("limit", "count", "size") if key in args} if isinstance(args, dict) else args
                if _call("validate_call", name, bounded) is not _FALLBACK:
                    return args or {}
            return original(name, args)
        return wrapper

    _replace(module, "_check_call", check_call)

    def hex_bytes(original):
        def wrapper(data):
            if isinstance(data, bytes):
                return _native.engine_hex_bytes_rs(data)
            return original(data)
        return wrapper

    _replace(module, "_hex", hex_bytes)

    def job_listing(records, limit):
        if not isinstance(records, list) or not _plain_int(limit):
            return None
        return records, limit

    _wrap(module, "_job_listing", "job_listing", job_listing)
    _wrap(module, "_sha256_arg", "prologue_sha256", lambda value: (value,))

    def image_base(value):
        return (value,) if isinstance(value, str) or _plain_int(value) else None

    _wrap(module, "_image_base_arg", "prologue_image_base", image_base, int)
    _wrap(module, "_md_path", "export_path_ok", lambda text: (text,) if isinstance(text, str) else None)


# ---- the small leaf modules -----------------------------------------------------------------------------------------

def install_address_maps(module) -> None:
    if _native is None:
        return

    def normalize(original):
        def wrapper(raw, digest, source_path):
            if isinstance(raw, bytes) and isinstance(digest, str):
                try:
                    file = str(source_path.resolve())
                except (OSError, ValueError, RuntimeError):
                    return original(raw, digest, source_path)
                found = _native.engine_address_map_rs(raw, digest, file)
                if found is not None:
                    content_hash, count, text = found
                    return content_hash, count, lambda: json.loads(text)
            return original(raw, digest, source_path)
        return wrapper

    _replace(module, "_normalize", normalize)


def install_red4ext(module) -> None:
    if _native is None:
        return

    def lookup(kind, original):
        def wrapper(path, wanted, chunk_size=4 * 1024 * 1024, *rest, **named):
            values = list(wanted) if isinstance(wanted, (set, frozenset, list, tuple)) else None
            if values is not None and all(_plain_int(item) and item >= 0 for item in values) and _plain_int(chunk_size) and chunk_size > 0:
                found = _native.engine_red4ext_rs(kind, os.fspath(path), [str(item) for item in values], chunk_size)
                if found is not None:
                    return found
            return original(path, wanted, chunk_size, *rest, **named)
        return wrapper

    _replace(module, "lookup_hashes", lambda original: lookup("hash", original))
    _replace(module, "lookup_rvas", lambda original: lookup("rva", original))


def install_integrity(module) -> None:
    if _native is None:
        return
    _wrap(module, "scan", "integrity_scan", lambda path: (str(module.project_folder(path)),))


def install_localio(module) -> None:
    if _native is None:
        return

    kernel_function = module._kernel

    def kernel_untouched() -> bool:
        """The ctypes seams are the specification of the Python reader (tests patch `_kernel` or its functions): once the
        kernel handle exists with a patched member, or `_kernel` itself is replaced, the Python reader serves."""
        if module._kernel is not kernel_function:
            return False
        if kernel_function.cache_info().currsize == 0:
            return True
        kernel = kernel_function()
        return not any(type(getattr(kernel, name)).__module__.startswith("unittest") for name in ("CreateFileW", "CloseHandle", "ReadFile"))

    def read_bytes(original):
        def wrapper(path, *, max_bytes=module.DEFAULT_MAX_BYTES):
            if _plain_int(max_bytes) and 1 <= max_bytes <= module.DEFAULT_MAX_BYTES and kernel_untouched():
                try:
                    filename = os.fsdecode(os.fspath(path))
                except (TypeError, ValueError):
                    return original(path, max_bytes=max_bytes)
                if chr(0) not in filename:
                    data = _native.engine_read_bytes_rs(filename, max_bytes)
                    if data is not None:
                        return data
            return original(path, max_bytes=max_bytes)
        return wrapper

    _replace(module, "read_bytes", read_bytes)


def install_jobowner(module) -> None:
    if _native is None:
        return

    def check(record, token=""):
        if not isinstance(record, dict) or not isinstance(token, str):
            return None
        return record, token, module._TOKENS.get(module._id(record), "")

    _wrap(module, "check", "owner_check", check, lambda answer: None)


_INSTALLERS = {
    "hydralysis.hydra": install_hydra,
    "hydralysis.api": install_api,
    "hydralysis.address_maps": install_address_maps,
    "hydralysis.red4ext": install_red4ext,
    "hydralysis.integrity": install_integrity,
    "hydralysis.localio": install_localio,
    "hydralysis.jobowner": install_jobowner,
}


def install(module=None) -> None:
    """Route MODULE (default: the calling module) to Rust; a module without a twin is left alone."""
    module = module if module is not None else sys.modules[sys._getframe(1).f_globals["__name__"]]
    installer = _INSTALLERS.get(module.__name__)
    if installer is not None:
        installer(module)
