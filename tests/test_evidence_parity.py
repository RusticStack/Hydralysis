"""Parity of evidence v2 with the reference checkout (audit C1-25, C2-25 to C2-28).

The reference is read, never written: its own canonical-digest code is run by Node (type stripping, no install) and
its published identity vector is checked against this implementation. The cases are loaded from the checkout, not
copied into this repository. With no checkout (CI) they are skipped, and the skip names the reason. Set
HYDRALYSIS_REA_REFERENCE to another path.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from hydralysis import evidence, evidence_bundle
from support import workdir

REVISION = "f196ebf80665107aedc16892af25a1e1f9f26f43"
REFERENCE = Path(os.environ.get("HYDRALYSIS_REA_REFERENCE") or r"F:\dev-cache\ref-repos\rusticre-rea-reference")
NODE = shutil.which("node")


def reference_revision() -> str:
    head = REFERENCE / ".git" / "HEAD"
    try:
        text = head.read_text().strip()
        if text.startswith("ref:"):
            return (REFERENCE / ".git" / text.split()[1]).read_text().strip()
        return text
    except OSError:
        return ""


def read(relative: str) -> str:
    return (REFERENCE / relative).read_text(encoding="utf-8")


def skip_reason() -> str:
    if not REFERENCE.is_dir():
        return "no reference checkout at %s" % REFERENCE
    found = reference_revision()
    if found and found != REVISION:
        return "the reference checkout is at %s, these cases were written against %s" % (found[:7], REVISION[:7])
    return ""


def schema_fields() -> set[str]:
    text = read("src/domain/evidence.ts")
    block = text[text.index("const evidenceBaseSchema"):text.index(".strict();")]
    return set(re.findall(r"^    ([a-z_]+):", block, re.MULTILINE))


@unittest.skipIf(skip_reason(), skip_reason())
class FieldsAndEnums(unittest.TestCase):
    def test_every_reference_field_has_a_counterpart_or_a_stated_gap(self):
        fields = schema_fields()
        self.assertGreaterEqual(len(fields), 16, "the schema parse found too few fields: %s" % sorted(fields))
        self.assertIn("evidence_id", fields)
        unclassified = fields - set(evidence.REA_FIELD_MAP) - set(evidence.REA_FIELD_GAPS)
        self.assertEqual(unclassified, set(), "reference fields with neither a column nor a documented gap")
        self.assertEqual((set(evidence.REA_FIELD_MAP) | set(evidence.REA_FIELD_GAPS)) - fields, set(),
                         "a mapped field the reference no longer has")
        self.assertEqual(set(evidence.REA_FIELD_MAP) & set(evidence.REA_FIELD_GAPS), set())
        columns = set(evidence.FIELDS)
        for field, counterpart in evidence.REA_FIELD_MAP.items():
            for column in counterpart.split(","):
                self.assertIn(column, columns, "%s maps to %s, which is not a column" % (field, column))
        for field, reason in evidence.REA_FIELD_GAPS.items():
            self.assertTrue(reason.strip(), field)

    def test_the_vocabularies_are_the_references(self):
        text = read("src/domain/evidence.ts")
        authority = text[text.index("evidenceAuthoritySchema = z.enum(["):]
        authority = authority[:authority.index("]")]
        self.assertEqual(tuple(re.findall(r'"([a-z-]+)"', authority)), evidence.AUTHORITIES)
        confidence = re.search(r'confidence: z\.enum\(\[([^\]]+)\]\)', text).group(1)
        self.assertEqual(tuple(re.findall(r'"([a-z]+)"', confidence)), evidence.CONFIDENCES)
        coverage = read("src/domain/relationshipCoverage.ts")
        self.assertEqual(set(re.findall(r'status: z\.literal\("([a-z]+)"\)', coverage)), set(evidence.COVERAGE_STATES))
        self.assertIn('prefixedDigestSchema("ev")', text)
        self.assertIn("`ev_${", text)  # the id is `ev_` + the digest, as here

    def test_the_bundle_fields_have_a_counterpart_or_a_stated_gap(self):
        text = read("src/domain/evidenceBundle.ts")
        block = text[text.index("export const evidenceBundleSchema"):]
        block = block[:block.index("});")]
        fields = set(re.findall(r"^  ([a-z]+):", block, re.MULTILINE))
        self.assertEqual(fields, {"artifacts", "providers", "environments", "scenarios", "captures", "unknowns", "records"})
        mapped = set(evidence_bundle.REA_BUNDLE_MAP) | set(evidence_bundle.REA_BUNDLE_GAPS)
        self.assertEqual(fields, mapped)
        self.assertIn("compareUnicodeCodePoints(left.evidence_id, right.evidence_id)", text)  # records sort by id
        for target in evidence_bundle.REA_BUNDLE_MAP.values():
            self.assertTrue(target.strip())

    def test_the_reference_commands_exist_for_every_operation_here(self):
        commands = read("src/cliEvidenceCommands.ts")
        for operation in ("evidenceImport", "evidenceExport", "compare"):
            self.assertIn("CLI_COMMANDS.%s" % operation, commands)
        done = subprocess.run([sys.executable, "-m", "hydralysis.evidence_bundle", "--help"], capture_output=True,
                              text=True, timeout=60, stdin=subprocess.DEVNULL,
                              env=dict(os.environ, PYTHONPATH=str(Path(evidence.__file__).parent.parent)))
        self.assertEqual(done.returncode, 0, done.stderr)
        for command in ("export", "verify", "compare", "import"):
            self.assertIn(command, done.stdout)


@unittest.skipIf(skip_reason() or not NODE, skip_reason() or "node is not installed")
class IdentityVectors(unittest.TestCase):
    def setUp(self):
        self.work = workdir("evparity")
        self.addCleanup(self.work.cleanup)

    def node(self, source: str) -> str:
        script = Path(self.work.name) / "probe.mjs"
        script.write_text(source, encoding="utf-8")
        done = subprocess.run([NODE, str(script)], capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
        self.assertEqual(done.returncode, 0, done.stderr[-3000:])
        return done.stdout

    def reference_digests(self, values: list) -> list[str]:
        data = Path(self.work.name) / "values.json"
        data.write_text(json.dumps(values), encoding="utf-8")
        module = (REFERENCE / "src" / "domain" / "canonicalDigest.ts").as_uri()
        out = self.node('import { digestCanonicalValue } from "%s";\nimport { readFileSync } from "node:fs";\n'
                        'const values = JSON.parse(readFileSync(%s, "utf8"));\n'
                        'process.stdout.write(JSON.stringify(values.map((value) => digestCanonicalValue(value))));'
                        % (module, json.dumps(str(data))))
        return json.loads(out)

    def test_the_canonical_digest_equals_the_references_on_hard_values(self):
        pinned = evidence.build_content(game="cp", build="2.5", kind="function", name="ForceMoveTo", address="rva:0x2e3270",
                                        note="moves the vehicle", source="decompile line 12", subsystem="vehicles")
        values = [
            pinned,
            {"b": [1, "x\u2028\u0001\U0001F600", None, True, False, -7, 0], "a": {"\uffee": 1, "\U00010000": 2}},
            {"": "", "z": [], "y": {}, "control": "".join(chr(i) for i in range(32)) + "\x7f\"\\/"},
            {"Z": 1, "a": 2, "_": 3, "\u00e9": 4, "e": 5, "\u0301": 6, "10": 7, "9": 8},
            [[], [[]], {"nested": {"deeper": {"deepest": [1, 2, {"k": "v"}]}}}],
            "plain string", None, 12345678901234, 0,
        ]
        mine = [evidence.canonical_digest(value) for value in values]
        self.assertEqual(mine, self.reference_digests(values))
        self.assertEqual("ev_" + mine[0], "ev_429247fbd78b7252e2ccd84c4e669781dbe9d812f958e3865d48b43f6ed467ed")

    def legacy_record(self) -> dict:
        module = (REFERENCE / "src" / "domain" / "evidenceLegacy.fixture.ts").as_uri()
        out = self.node('import { PRE_66_NULL_COVERAGE_EVIDENCE as record } from "%s";\n'
                        'process.stdout.write(JSON.stringify(record));' % module)
        return json.loads(out)

    @staticmethod
    def reference_content(record: dict, legacy: bool) -> dict:
        """evidenceSemanticContent of src/domain/evidence.ts, written out; `legacy` omits relationship_coverage."""
        subject = record["subject"]
        content = {
            "subject": None if subject is None else {"digest": subject["digest"], "format": subject["format"],
                                                     "architecture": subject["architecture"]},
            "provider": record["provider"], "analysis_profile": record["analysis_profile"],
            "predicate_type": record["predicate_type"], "operation": record["operation"],
            "parameters": record["parameters"], "raw_result": record["raw_result"],
            "normalized_result": record["normalized_result"], "confidence": record["confidence"],
            "authority": record["authority"], "environment": record["environment"],
            "limitations": record["limitations"], "relationship_coverage": record["relationship_coverage"],
            "locations": record["locations"], "evidence_links": record["evidence_links"],
        }
        if legacy:
            del content["relationship_coverage"]
        return content

    def test_the_references_published_identity_is_reproduced(self):
        record = self.legacy_record()
        self.assertEqual(set(record), schema_fields() - {"caller_input_path"})  # that one is optional
        expected = record["evidence_id"]
        self.assertTrue(evidence.is_evidence_id(expected))
        legacy = "ev_" + evidence.canonical_digest(self.reference_content(record, legacy=True))
        self.assertEqual(legacy, expected)
        # the current rule commits the explicit null, so the same record has another id today
        current = "ev_" + evidence.canonical_digest(self.reference_content(record, legacy=False))
        self.assertNotEqual(current, expected)
        self.assertEqual(current, "ev_" + self.reference_digests([self.reference_content(record, legacy=False)])[0])

    def test_a_flipped_byte_in_the_reference_vector_is_rejected_the_same_way(self):
        record = self.legacy_record()
        record["normalized_result"] = {"observed": False}
        tampered = "ev_" + evidence.canonical_digest(self.reference_content(record, legacy=True))
        self.assertNotEqual(tampered, record["evidence_id"])
        # and here: the same flip in a stored claim is refused on read, which is what the reference's parse does
        content = evidence.build_content(game="g", build="b", kind="k", name="n", note="a", source="s")
        identifier = evidence.compute_evidence_id(content)
        evidence.verify_content(content, identifier)
        with self.assertRaises(evidence.EvidenceIntegrityError):
            evidence.verify_content({**content, "note": "b"}, identifier)


if __name__ == "__main__":
    unittest.main()
