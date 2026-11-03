"""Python-side test seams that the Rust implementation (`HYDRALYSIS_IMPL=rust`) cannot see.

A white-box test patches a Python function (`os.fsync`, `os.replace`, `durable.replace_file`, a verify function, a private
helper) and then checks that the patched function was called, or that the code reacted to its failure. The Rust path does
its work without calling those Python objects, so while one is patched the call is answered by the original Python
function instead, which goes through the patched object exactly as it always did. The production path pays one identity
comparison per watched object: `Seam.active()` is a loop of `getattr(owner, name) is original` over a handful of pairs.

A Seam remembers what each watched attribute held when it was added, so it is built (or extended with `add`) at import,
once the Rust wrappers are installed and before any test runs. Each guard is listed in the "Python seams" section of the
TESTMAP.md of the crate that implements the routed function.
"""

from __future__ import annotations


class Seam:
    """A set of (owner, attribute) pairs, each remembered with the object it held when it was added."""

    __slots__ = ("_watched",)

    def __init__(self, *targets):
        self._watched = ()
        self.add(*targets)

    def add(self, *targets) -> "Seam":
        """Also watch TARGETS ((owner, name) pairs), remembering what they hold now."""
        self._watched += tuple((owner, name, getattr(owner, name)) for owner, name in targets)
        return self

    def active(self) -> bool:
        """True while any watched attribute holds an object other than the original."""
        for owner, name, original in self._watched:
            if getattr(owner, name, original) is not original:
                return True
        return False


def any_active(seams) -> bool:
    for seam in seams:
        if seam.active():
            return True
    return False


def guarded(rust_function, python_function, *seams):
    """RUST_FUNCTION, except that it is PYTHON_FUNCTION while any of the SEAMS is active.

    Both take the same arguments. The wrapper keeps the Python function's name and docstring and exposes both as
    attributes (`python_function`, `rust_function`), as the views routing does."""

    def routed(*args, **kwargs):
        for seam in seams:
            if seam.active():
                return python_function(*args, **kwargs)
        return rust_function(*args, **kwargs)

    routed.__name__ = getattr(python_function, "__name__", routed.__name__)
    routed.__qualname__ = getattr(python_function, "__qualname__", routed.__qualname__)
    routed.__doc__ = getattr(python_function, "__doc__", None)
    routed.python_function = python_function
    routed.rust_function = rust_function
    return routed
