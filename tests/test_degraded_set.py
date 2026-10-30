"""The hydra.3 degraded set of gate 9.8 (docs/versioning.md): `support.hydra4_missing` gives a skip reason on a protocol-2
engine and none on a protocol-3 one, `support.Hydra4Only` skips each test of such a class (so a run counts every test), and
every class that uses it is listed in the document."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from support import Hydra4Only, hydra4_missing

TESTS = Path(__file__).resolve().parent
DOC = TESTS.parent / "docs" / "versioning.md"


class Engine:
    def __init__(self, protocol: int):
        self._protocol = protocol

    def protocol(self) -> int:
        return self._protocol

    def hello(self) -> dict:
        return {"hydraVersion": "12.3-hydra.%d" % (3 if self._protocol < 3 else 4), "protocol": self._protocol}


class DegradedSet(unittest.TestCase):
    def test_a_protocol_2_engine_gets_the_reason(self):
        reason = hydra4_missing(Engine(2), "the feature")
        self.assertTrue(reason.startswith("hydra.3 degraded set: engine 12.3-hydra.3 serves protocol 2"), reason)
        self.assertIn("the feature needs hydra.4", reason)

    def test_a_protocol_3_engine_is_never_skipped(self):
        self.assertIsNone(hydra4_missing(Engine(3), "the feature"))

    def test_each_test_of_a_degraded_class_is_counted_as_a_skip_and_a_hydra4_class_runs(self):
        class Probe(Hydra4Only, unittest.TestCase):
            ran = []

            @classmethod
            def setUpClass(cls):
                cls.degraded = hydra4_missing(cls.engine, "the feature")

            def test_one(self):
                self.ran.append(1)

            def test_two(self):
                self.ran.append(2)

        for protocol, skipped, ran in ((2, 2, []), (3, 0, [1, 2])):
            Probe.engine, Probe.ran, Probe.degraded = Engine(protocol), [], None
            result = unittest.TestResult()
            unittest.defaultTestLoader.loadTestsFromTestCase(Probe).run(result)
            self.assertEqual((result.testsRun, len(result.skipped), Probe.ran, result.wasSuccessful()),
                             (2, skipped, ran, True), protocol)

    def test_every_class_that_uses_it_is_in_the_degraded_set_table(self):
        users = set()
        for path in TESTS.glob("test_*.py"):
            if path.name == Path(__file__).name:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and any(getattr(base, "id", None) == "Hydra4Only" for base in node.bases):
                    users.add("%s.%s" % (path.stem, node.name))
        self.assertGreaterEqual(users, {"test_backups.RealEngineBackups", "test_backups.RealEngineFaultMatrix",
                                        "test_userscripts.RealWorker"})
        text = DOC.read_text(encoding="utf-8")
        for name in sorted(users):
            self.assertIn("`%s`" % name, text, "%s skips on hydra.3 but docs/versioning.md does not list it" % name)


if __name__ == "__main__":
    unittest.main()
