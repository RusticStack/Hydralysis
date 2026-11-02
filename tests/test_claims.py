"""The claims ledger (docs/data/claims.json) and the wording rule of the Hydralysis documents.

The ledger holds one row per claim. These tests fail when
 - a number in the ledger differs from its source (the tool catalog's byte size and tool count, the
   limit written in tests/test_contracts.py, the KotOR function counts of the golden header),
 - a document no longer carries the wording its ledger row says it carries, or quotes a number that
   differs from the live value,
 - a claim marked "gated" has no test, or its test does not exist, is skipped or does not pass,
 - a document uses a wording the rule does not allow until a gate has passed ("never corrupt",
   "any number of", "never blocks", ...), or mentions a GUI.

The checks are plain functions of (ledger, repository root), so the last class plants violations and
shows that each check can fail.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
LEDGER = REPOSITORY / "docs" / "data" / "claims.json"
CLASSES = {"supported", "true_today", "gated", "future"}
SURFACES = {"hydralysis", "engine", "site"}
# The 25 claims of the audit (PROTOCOL-3.md section 8.3) must all have a row.
AUDIT_IDS = ["C%d" % n for n in range(1, 12)] + ["U%d" % n for n in range(1, 15)]
FUTURE_IDS = ["F%d" % n for n in range(1, 6)]
# The documents this ledger governs.
GOVERNED = ("README.md", "THIRD_PARTY.md", "skills/hydralysis/SKILL.md", "skills/ghidra-project/SKILL.md",
            "docs/golden-harness.md")

# The wording rule: until the gate of a claim passes, these strong forms are not allowed.
# (pattern, why). The patterns are case-insensitive and run on one line at a time.
FORBIDDEN_WORDING = (
    (r"never collid", "'never collide' (C1): writes are serialized; collisions are detected only with expect_revision"),
    (r"any number of", "'any number of' (U1): say 'several' and what was tested"),
    (r"never block", "'never blocks' (C3, C4): lanes and locks can delay other clients"),
    (r"cleaned up at once|clean release", "'cleaned up at once' (C5): cleanup happens when the running request ends"),
    (r"deaf script|a script that ignores cancel is killed|killed when it ignores", "'a deaf script is killed' (C5): not before the gate of E7"),
    (r"never corrupt", "'never corrupt' (U3): say what was tested ('no corruption was seen in the tests listed')"),
    (r"cannot change what (another|other|others)", "'cannot change what others see' (C2): other clients can see a contained script's changes while it runs"),
    (r"so it cannot change the project", "'cannot change the project' (C2): the changes are rolled back and never saved"),
    (r"never lost", "'never lost' (U4): no power-loss test has been run"),
    (r"analysis never slows", "'analysis never slows questions' (C3)"),
    (r"never wait on each other|never waits? on each other", "'never wait on each other' (C4)"),
    (r"starve", "'cannot starve' (U2)"),
    (r"no lost updates", "'No lost updates' (U9) only 'when you pass expect'"),
    (r"a ghidra window can read", "'a Ghidra window can read it' (U14): say 'other processes can read it'"),
    (r"identical to the window", "the window (U14): the options are DecompileOptions.grabFromProgram"),
)
# "7 ms" is allowed only with its size qualifier on the same line (U10).
SEVEN_MS = re.compile(r"(?<![\d.])7(\.\d)? ?ms\b", re.IGNORECASE)
SIZE_QUALIFIER = re.compile(r"by function size|benchmark function", re.IGNORECASE)
# GUI: the only allowed mention is the headless-only sentence. "window" in the sense of the Ghidra
# application is also out.
GUI_WORD = re.compile(r"\bGUI\b")
GUI_ALLOWED = re.compile(r"\bno GUI\b", re.IGNORECASE)
GHIDRA_WINDOW = re.compile(r"ghidra'?s? window|the window\b|ghidra window", re.IGNORECASE)


# ----- the checks: plain functions of the ledger and a repository root -----------------------------

def load(path: Path = LEDGER) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def live_values(root: Path) -> dict:
    """The numbers read from their sources right now."""
    sys.path.insert(0, str(root / "src"))
    try:
        from hydralysis.api import tool_table
    finally:
        sys.path.pop(0)
    table = tool_table()
    values = {"catalog_tools": len(table), "catalog_bytes": len(json.dumps(table).encode("utf-8"))}
    return values


def source_value(entry: dict, root: Path, live: dict):
    """The value a ledger number's source gives now, or raise LookupError when the source is gone."""
    kind = entry["source"]
    if kind in ("tool_count", "tool_table_bytes"):
        return live["catalog_tools" if kind == "tool_count" else "catalog_bytes"]
    if kind in ("test_limit", "file_number"):
        text = (root / entry["path"]).read_text(encoding="utf-8")
        match = re.search(entry["pattern"], text)
        if not match:
            raise LookupError("%s: pattern %r not found in %s" % (entry["id"], entry["pattern"], entry["path"]))
        return int(match.group(1).replace(",", ""))
    if kind == "pending":
        return None
    raise LookupError("%s: unknown source kind %r" % (entry["id"], kind))


def check_numbers(ledger: dict, root: Path, live: dict) -> list[str]:
    problems = []
    for entry in ledger["numbers"]:
        try:
            actual = source_value(entry, root, live)
        except LookupError as error:
            problems.append(str(error))
            continue
        if entry["source"] == "pending":
            if entry.get("value") is not None:
                problems.append("%s: a pending number (package %s) carries the value %r" % (entry["id"], entry.get("package"), entry["value"]))
        elif entry.get("value") != actual:
            problems.append("%s: the ledger says %r, the source says %r" % (entry["id"], entry.get("value"), actual))
    return problems


def render(template: str, ledger: dict, live: dict, root: Path) -> str:
    """Fill {id} and {id:,} placeholders from the live source values, never from the ledger's copy."""
    values = {}
    for entry in ledger["numbers"]:
        if entry["source"] != "pending":
            values[entry["id"]] = source_value(entry, root, live)
    return template.format(**values)


def check_shape(ledger: dict, root: Path) -> list[str]:
    problems, seen = [], set()
    for row in ledger["claims"]:
        cid = row.get("id", "?")
        if cid in seen:
            problems.append("%s: duplicate id" % cid)
        seen.add(cid)
        for field in ("id", "text", "class", "evidence", "flips", "surface"):
            if field not in row:
                problems.append("%s: missing field %s" % (cid, field))
        if row.get("class") not in CLASSES:
            problems.append("%s: class %r is not one of %s" % (cid, row.get("class"), sorted(CLASSES)))
        if row.get("surface") not in SURFACES:
            problems.append("%s: surface %r is not one of %s" % (cid, row.get("surface"), sorted(SURFACES)))
        if row.get("class") in ("true_today", "future") and row.get("flips") == "" and row.get("class") == "future":
            problems.append("%s: a future claim must name the package that makes it true" % cid)
        evidence = row.get("evidence", "")
        if evidence.startswith("external:"):
            if row.get("surface") == "hydralysis":
                problems.append("%s: a Hydralysis claim needs evidence inside this repository" % cid)
        elif not (root / evidence).exists():
            problems.append("%s: the evidence path %s does not exist" % (cid, evidence))
        for number in row.get("numbers", []):
            if number not in {n["id"] for n in ledger["numbers"]}:
                problems.append("%s: unknown number id %s" % (cid, number))
        if row.get("class") == "gated" and not row.get("test"):
            problems.append("%s: a gated claim has no test" % cid)
    for needed in AUDIT_IDS + FUTURE_IDS:
        if needed not in seen:
            problems.append("%s: the audit claim has no row" % needed)
    return problems


def check_documents(ledger: dict, root: Path, live: dict) -> list[str]:
    """Every appears_in entry is found in its file, with numbers taken from the live values."""
    problems = []
    for row in ledger["claims"]:
        for place in row.get("appears_in", []):
            path = root / place["path"]
            if not path.is_file():
                problems.append("%s: %s does not exist" % (row["id"], place["path"]))
                continue
            try:
                wanted = render(place["contains"], ledger, live, root)
            except (KeyError, LookupError, ValueError) as error:
                problems.append("%s: cannot render %r: %r" % (row["id"], place["contains"], error))
                continue
            text = " ".join(path.read_text(encoding="utf-8").split())
            if " ".join(wanted.split()) not in text:
                problems.append("%s: %s no longer carries %r" % (row["id"], place["path"], wanted))
    return problems


def split_ref(ref: str) -> tuple[str, str]:
    path, _, name = ref.partition("::")
    return path, name.replace("::", ".")


def run_suite(suite: unittest.TestSuite) -> unittest.TestResult:
    result = unittest.TestResult()
    suite.run(result)
    return result


def check_gated(ledger: dict, root: Path, self_name: str = "tests/test_claims.py") -> list[str]:
    """A gated claim needs a test that exists, is not skipped, and passes (run here, once)."""
    problems = []
    for row in ledger["claims"]:
        if row.get("class") != "gated":
            continue
        ref = row.get("test") or ""
        if not ref:
            problems.append("%s: a gated claim has no test" % row["id"])
            continue
        path, name = split_ref(ref)
        if path == self_name:
            problems.append("%s: a gated claim may not be gated by the ledger test itself" % row["id"])
            continue
        if not (root / path).is_file():
            problems.append("%s: the test file %s does not exist" % (row["id"], path))
            continue
        module = Path(path).with_suffix("").as_posix().replace("/", ".")
        module = module[len("tests."):] if module.startswith("tests.") else module
        sys.path.insert(0, str(root / "tests"))
        sys.path.insert(0, str(root / "src"))
        try:
            suite = unittest.defaultTestLoader.loadTestsFromName("%s.%s" % (module, name))
        except Exception as error:  # noqa: BLE001 - any import or lookup failure is a finding
            problems.append("%s: cannot load %s: %r" % (row["id"], ref, error))
            continue
        finally:
            sys.path.pop(0)
            sys.path.pop(0)
        problems.extend(gated_result(row["id"], ref, suite))
    return problems


def gated_result(claim_id: str, ref: str, suite: unittest.TestSuite) -> list[str]:
    result = run_suite(suite)
    if result.testsRun != 1 or any(isinstance(t, unittest.loader._FailedTest) for t in suite):
        return ["%s: %s did not resolve to exactly one test (ran %d)" % (claim_id, ref, result.testsRun)]
    if result.skipped:
        return ["%s: %s was skipped: %s" % (claim_id, ref, result.skipped[0][1])]
    if not result.wasSuccessful():
        return ["%s: %s does not pass" % (claim_id, ref)]
    return []


def scan_wording(root: Path, files=GOVERNED) -> list[str]:
    found = []
    for relative in files:
        path = root / relative
        if not path.is_file():
            found.append("%s: missing" % relative)
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            where = "%s:%d" % (relative, number)
            for pattern, why in FORBIDDEN_WORDING:
                if re.search(pattern, line, re.IGNORECASE):
                    found.append("%s: %s" % (where, why))
            if SEVEN_MS.search(line) and not SIZE_QUALIFIER.search(line):
                found.append("%s: '7 ms' without its size qualifier (U10)" % where)
            if GUI_WORD.search(line) and not GUI_ALLOWED.search(line):
                found.append("%s: a GUI mention; there is no GUI (U14)" % where)
            if GHIDRA_WINDOW.search(line):
                found.append("%s: a Ghidra window mention; there is no GUI (U14)" % where)
    return found


# ----- the tests ----------------------------------------------------------------------------------

class LedgerFile(unittest.TestCase):
    ledger = None

    @classmethod
    def setUpClass(cls):
        cls.ledger = load()

    def test_every_audit_claim_has_one_well_formed_row(self):
        self.assertEqual(check_shape(self.ledger, REPOSITORY), [])
        ids = [row["id"] for row in self.ledger["claims"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len([i for i in ids if i in AUDIT_IDS]), 25)

    def test_numbers_equal_their_sources(self):
        live = live_values(REPOSITORY)
        self.assertEqual(check_numbers(self.ledger, REPOSITORY, live), [])
        by_id = {entry["id"]: entry["value"] for entry in self.ledger["numbers"]}
        self.assertEqual((by_id["catalog_tools"], by_id["catalog_bytes"], by_id["catalog_limit"]), (21, 8878, 9216))
        self.assertEqual((by_id["kotor_functions_total"], by_id["kotor_functions_internal"], by_id["kotor_functions_thunks"]), (8966, 8616, 60))
        self.assertIsNone(by_id["x0_baselines"])

    def test_the_catalog_has_room_under_the_limit(self):
        # The size budget is the existing test's (tests/test_contracts.py); this keeps the ledger's headroom visible.
        live = live_values(REPOSITORY)
        limit = next(n["value"] for n in self.ledger["numbers"] if n["id"] == "catalog_limit")
        self.assertLess(live["catalog_bytes"], limit)

    def test_documents_carry_the_wording_their_rows_name(self):
        live = live_values(REPOSITORY)
        self.assertEqual(check_documents(self.ledger, REPOSITORY, live), [])

    def test_gated_claims_have_a_test_that_passes(self):
        gated = [row for row in self.ledger["claims"] if row["class"] == "gated"]
        self.assertGreaterEqual(len(gated), 2)
        self.assertEqual(check_gated(self.ledger, REPOSITORY), [])

    def test_documents_follow_the_wording_rule(self):
        self.assertEqual(scan_wording(REPOSITORY), [])


class TheChecksCanFail(unittest.TestCase):
    """Plant one violation per check and require the check to report it."""

    def ledger(self):
        return load()

    def test_a_number_that_differs_from_its_source_is_reported(self):
        ledger, live = self.ledger(), live_values(REPOSITORY)
        for entry in ledger["numbers"]:
            if entry["id"] == "catalog_bytes":
                entry["value"] = 7634
            if entry["id"] == "kotor_functions_internal":
                entry["value"] = 10849
            if entry["id"] == "x0_baselines":
                entry["value"] = 123
        problems = check_numbers(ledger, REPOSITORY, live)
        self.assertEqual(len(problems), 3, problems)

    def test_a_document_number_is_checked_against_the_live_catalog(self):
        ledger, live = self.ledger(), live_values(REPOSITORY)
        live = dict(live, catalog_bytes=live["catalog_bytes"] + 104)  # the catalog grew; the README did not follow
        self.assertTrue([p for p in check_documents(ledger, REPOSITORY, live) if p.startswith("C10")])

    def test_a_missing_sentence_and_a_missing_row_are_reported(self):
        ledger = self.ledger()
        ledger["claims"][0]["appears_in"] = [{"path": "README.md", "contains": "this sentence is not in the readme"}]
        self.assertTrue(check_documents(ledger, REPOSITORY, live_values(REPOSITORY)))
        ledger = self.ledger()
        ledger["claims"] = [row for row in ledger["claims"] if row["id"] != "C5"]
        self.assertIn("C5: the audit claim has no row", check_shape(ledger, REPOSITORY))

    def test_a_gated_claim_without_a_passing_test_is_reported(self):
        base = self.ledger()
        base["claims"] = [row for row in base["claims"] if row["class"] == "gated"][:1]
        cases = {
            "no test": None,
            "missing file": "tests/test_nothing_here.py::X::y",
            "missing method": "tests/test_contracts.py::AgentContracts::test_there_is_no_such_test",
            "itself": "tests/test_claims.py::LedgerFile::test_numbers_equal_their_sources",
        }
        for label, ref in cases.items():
            ledger = json.loads(json.dumps(base))
            if ref is None:
                ledger["claims"][0].pop("test", None)
            else:
                ledger["claims"][0]["test"] = ref
            self.assertTrue(check_gated(ledger, REPOSITORY), label)

    def test_a_failing_and_a_skipped_test_do_not_count_as_passing(self):
        failing = unittest.TestSuite([unittest.FunctionTestCase(lambda: self.fail("planted failure"))])
        self.assertEqual(len(gated_result("G", "ref", failing)), 1)

        def skipped():
            raise unittest.SkipTest("planted skip")
        self.assertIn("skipped", gated_result("G", "ref", unittest.TestSuite([unittest.FunctionTestCase(skipped)]))[0])
        passing = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        self.assertEqual(gated_result("G", "ref", passing), [])

    def test_the_wording_scan_reports_each_forbidden_form(self):
        import tempfile
        planted = [
            "Writes never collide.", "Works with any number of agents.", "A query never blocks.",
            "Cleaned up at once.", "A deaf script is killed.", "Serialized, never corrupt.",
            "so a query cannot change what another client reads", "so it cannot change the project",
            "is replayed from the store, never lost", "analysis never slows questions",
            "different projects never wait on each other", "an agent cannot starve one that sends one",
            "No lost updates", "so a Ghidra window can read it", "about 7 ms", "Open it in the GUI.",
            "as the Ghidra window does",
        ]
        clean = ["There is no GUI. Hydra Engine is headless only.", "about 1 to 45 ms by function size (7 ms in the benchmark function)"]
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "doc.md").write_text("\n".join(planted + clean), encoding="utf-8")
            found = scan_wording(Path(tmp), files=("doc.md",))
        flagged = {int(item.split(":")[1]) for item in found if item.startswith("doc.md:")}
        self.assertEqual(flagged, set(range(1, len(planted) + 1)), found)


if __name__ == "__main__":
    unittest.main()
