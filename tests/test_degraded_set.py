"""The hydra.3 degraded set of gate 9.8 (docs/versioning.md): `support.require_hydra4` skips a hydra.4-only real-engine
class on a protocol-2 engine, never on a protocol-3 one, and every class that uses it is listed in the document."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from support import require_hydra4

TESTS = Path(__file__).resolve().parent
DOC = TESTS.parent / "docs" / "versioning.md"


class Engine:
    def __init__(self, protocol: int):
        self._protocol = protocol

    def protocol(self) -> int:
        return self._protocol

    def hello(self) -> dict:
        return {"hydraVersion": "12.3-hydra.%d" % (3 if self._protocol < 3 else 4), "protocol": self._protocol}


class RequireHydra4(unittest.TestCase):
    def test_a_protocol_2_engine_skips_with_the_reason_after_the_release(self):
        released = []
        with self.assertRaises(unittest.SkipTest) as skipped:
            require_hydra4(Engine(2), "the feature", lambda: released.append(True))
        self.assertEqual(released, [True], "the daemon is released before the skip (no tearDownClass follows)")
        self.assertTrue(str(skipped.exception).startswith("hydra.3 degraded set: engine 12.3-hydra.3 serves protocol 2"))
        self.assertIn("the feature needs hydra.4", str(skipped.exception))

    def test_a_protocol_3_engine_is_never_skipped(self):
        released = []
        self.assertIsNone(require_hydra4(Engine(3), "the feature", lambda: released.append(True)))
        self.assertEqual(released, [])

    def test_every_class_that_uses_it_is_in_the_degraded_set_table(self):
        users = set()
        for path in TESTS.glob("test_*.py"):
            if path.name == Path(__file__).name:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and any(
                        isinstance(call, ast.Call) and getattr(call.func, "id", None) == "require_hydra4"
                        for call in ast.walk(node)):
                    users.add("%s.%s" % (path.stem, node.name))
        self.assertGreaterEqual(users, {"test_backups.RealEngineBackups", "test_backups.RealEngineFaultMatrix",
                                        "test_userscripts.RealWorker"})
        text = DOC.read_text(encoding="utf-8")
        for name in sorted(users):
            self.assertIn("`%s`" % name, text, "%s skips on hydra.3 but docs/versioning.md does not list it" % name)


if __name__ == "__main__":
    unittest.main()
