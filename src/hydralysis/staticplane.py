"""The static read plane: questions about an analysed project answered from its database files, with no engine.

Behind `HYDRALYSIS_IMPL=rust` and the optional native module (`hydralysis_native.static_call_rs`, the Rust crate
`hy-static` in `rust/crates/hy-static`). The engine stays the default and the fallback: every function here returns
None when the plane cannot answer *exactly* (no native module, an action it does not answer, a database version,
language, address space, memory kind or reference kind it does not port, files that are changing), and the caller asks
the engine as before. Nothing is guessed and nothing is partial.

What the plane answers is listed by `supports`; `rust/crates/hy-static/PORTING.md` says why the rest is not there.
"""

from __future__ import annotations

import json
import os
import threading
import time

_REASONS: dict[str, int] = {}
_GUARD = threading.Lock()
_LAST = threading.local()


def _native():
    """The native module when `HYDRALYSIS_IMPL=rust` and it carries the static binding, else None."""
    if os.environ.get("HYDRALYSIS_IMPL", "").strip().lower() != "rust":
        return None
    try:
        import hydralysis_native as native
    except ImportError:
        return None
    return native if hasattr(native, "static_call_rs") else None


def available() -> bool:
    """Whether the plane can answer anything now."""
    return _native() is not None


def call(name: str, *args):
    """The Rust call NAME. Returns `(True, value)` or `(False, reason)`; `(False, 'no native')` when it is not there."""
    native = _native()
    if native is None:
        return False, "no native module"
    try:
        reply = json.loads(native.static_call_rs(name, json.dumps(list(args), ensure_ascii=False)))
    except (TypeError, ValueError) as error:   # arguments that are not JSON: the engine path answers
        return False, "arguments: %s" % error
    if "ok" in reply:
        return True, reply["ok"]
    why = "%s: %s" % (reply["fallback"]["kind"], reply["fallback"]["reason"])
    with _GUARD:
        _REASONS[why] = _REASONS.get(why, 0) + 1
    _LAST.reason = why
    return False, why


_SUPPORTS: dict[str, bool] = {}


def supports(action: str) -> bool:
    """Whether the plane answers ACTION at all (it may still decline a given question). Asked of the native module once
    per action: the list is fixed in the binary."""
    known = _SUPPORTS.get(action)
    if known is None:
        ok, value = call("supports", action)
        known = bool(ok and value)
        if ok:
            _SUPPORTS[action] = known
    return known


def answer(gpr: str, program: str, request: dict) -> dict | None:
    """The engine-shaped reply for REQUEST (the dict RusticQuery would be given) from the project at GPR, or None.

    The reply has the program envelope and the rows of the engine's, plus `overlay_state`; the caller adds what the
    engine path adds (`target`, `view`, `query_s`, `engine`)."""
    if not supports(str(request.get("action"))):
        return None
    ok, value = call("answer", str(gpr), str(program), request)
    if not ok:
        return None
    value.setdefault("overlay_state", "")
    return value


def reasons() -> dict[str, int]:
    """How often the plane declined, by reason, in this process (diagnostics and tests)."""
    with _GUARD:
        return dict(_REASONS)


def last_reason() -> str | None:
    """Why this thread's latest question was declined."""
    return getattr(_LAST, "reason", None)


def reset() -> None:
    with _GUARD:
        _REASONS.clear()
    _SUPPORTS.clear()


def cache_stats() -> dict | None:
    """Counters of the native process-wide cache (entries, bytes, budget, hits, misses, evictions, invalidations)."""
    ok, value = call("cache_stats")
    return value if ok else None


def cache_clear() -> None:
    """Drop the native cache's entries."""
    call("cache_clear")


def timed(gpr: str, program: str, request: dict) -> tuple[dict | None, float]:
    """`answer` and the seconds it took."""
    started = time.monotonic()
    reply = answer(gpr, program, request)
    return reply, time.monotonic() - started
