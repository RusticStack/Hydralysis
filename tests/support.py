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


def hydra4_missing(engine, what: str) -> str | None:
    """The hydra.3 degraded set (docs/versioning.md, gate 9.8): the skip reason of a real-engine class that needs a hydra.4-only
    feature, or None. The reason is given when the connection negotiated protocol 2 (`Engine.protocol()`, from hello; hydra.2
    and hydra.3 serve nothing else), never from a name. An engine that serves protocol 3 never gets one: on hydra.4 a missing
    feature still fails the class."""
    served = engine.protocol()
    if served >= 3:
        return None
    return ("hydra.3 degraded set: engine %s serves protocol %d; %s needs hydra.4 (protocol 3)"
            % (engine.hello().get("hydraVersion", "unknown"), served, what))


class Hydra4Only:
    """Mixin (first base) of a hydra.4-only real-engine class: setUpClass sets `degraded` from `hydra4_missing` and returns
    early; every test then skips with that reason. The skip is per test, so a run counts each test (tools/run_tests.py checks
    "Ran N" against the plan), and tearDownClass still releases the daemon."""

    degraded: str | None = None

    def setUp(self):
        if self.degraded:
            self.skipTest(self.degraded)
        super().setUp()


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
