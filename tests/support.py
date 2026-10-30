"""Test work directories live under an explicit root, never the ambient TEMP.

HYDRALYSIS_TEST_ROOT selects it; the default is test-work/ in the repository
(ignored by git). Ghidra refuses dot-prefixed path components, so the default is
dot-free on every host.
"""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent


def test_root() -> Path:
    root = Path(os.environ.get("HYDRALYSIS_TEST_ROOT") or os.environ.get("RUSTICRE_TEST_ROOT") or REPOSITORY / "test-work").resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


class WorkDir:
    """A drop-in for tempfile.TemporaryDirectory under the explicit test root."""

    def __init__(self, prefix: str = "t"):
        self.name = str(test_root() / ("%s-%s" % (prefix, uuid.uuid4().hex[:12])))
        Path(self.name).mkdir()

    def cleanup(self):
        shutil.rmtree(self.name, ignore_errors=True)

    def __enter__(self):
        return self.name

    def __exit__(self, *exc):
        self.cleanup()


def workdir(prefix: str = "t") -> WorkDir:
    return WorkDir(prefix)


def require_hydra4(engine, what: str, release=None) -> None:
    """The hydra.3 degraded set (docs/versioning.md, gate 9.8): a real-engine class that needs a hydra.4-only feature
    skips, with the reason, on an engine whose connection serves protocol 2 (hydra.2 and hydra.3 serve nothing else).

    The decision is the protocol the client negotiated (`Engine.protocol()`, from hello), never a name. An engine that
    serves protocol 3 is never skipped: on hydra.4 a missing feature still fails the class. RELEASE, when given, is
    called before the skip (setUpClass raising SkipTest gets no tearDownClass, and the daemon must not outlive it)."""
    import unittest
    served = engine.protocol()
    if served >= 3:
        return
    version = engine.hello().get("hydraVersion", "unknown")
    if release is not None:
        release()
    raise unittest.SkipTest("hydra.3 degraded set: engine %s serves protocol %d; %s needs hydra.4 (protocol 3)"
                            % (version, served, what))


def default_to_shared(runner) -> None:
    """Make a QueryRunner name the `shared` view for every call that names neither a `view` nor an agent (`as`).

    A caller with neither has a view of its own now (Y5, D43), and reads the sealed master until its first edit. Tests that
    exercise the store, the replay or the commit machinery of the shared view say so here, in one place."""
    ask = runner.query

    def shared_unless_named(target, action="decompile", address="", limit=40, cursor="", contains="", timeout_s=30, options=None):
        options = dict(options or {})
        if "view" not in options and "as" not in options:
            options["view"] = "shared"
        return ask(target, action, address, limit, cursor, contains, timeout_s, options)

    runner.query = shared_unless_named
