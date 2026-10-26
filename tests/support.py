"""Test work directories live under an explicit root, never the ambient TEMP.

RUSTICRE_TEST_ROOT selects it; the default is test-work/ in the repository
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
    root = Path(os.environ.get("RUSTICRE_TEST_ROOT") or REPOSITORY / "test-work").resolve()
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
