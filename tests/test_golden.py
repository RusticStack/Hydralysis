"""The golden harness's normaliser, diff and gate, on small synthetic captures.

No game data and no engine: the C text below is invented. (The capture drivers need an engine and
are run by hand; see docs/golden-harness.md.)
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import golden  # noqa: E402

from support import workdir  # noqa: E402

BASE = """int __cdecl demo(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 local_10;
  char *pcVar3;

  iVar1 = FUN_00401000(param_1);
  iVar2 = iVar1 + 1;
  pcVar3 = "iVar1 local_10";
  local_10 = DAT_00402000;
  return iVar2 + local_10;
}
"""
RENUMBERED = BASE.replace("iVar1", "iVar7").replace("iVar2", "iVar4").replace("local_10", "local_14") \
    .replace("pcVar3", "pcVar9").replace('"iVar7 local_14"', '"iVar1 local_10"')


def capture(root: Path, name: str, rows: dict, header: dict | None = None, level: str = "standard") -> Path:
    """rows: entry -> (status, c) or (status, c, name, size, ms)."""
    writer = golden.CaptureWriter(root / name, {"label": name, "path": "explicit", "program_sha256": "ab" * 32,
                                                "options_sha256": "cd" * 32, "engine": {"ghidra_version": "12.3"},
                                                **(header or {})}, level)
    for entry, item in rows.items():
        status, c = item[0], item[1]
        label = item[2] if len(item) > 2 else "FUN_" + entry[2:].zfill(8)
        size = item[3] if len(item) > 3 else 10
        ms = item[4] if len(item) > 4 else 1.0
        writer.add(entry, label, size, status, ms, c if status == "ok" else None, None if status == "ok" else "refused")
    writer.close()
    return root / name


class Normaliser(unittest.TestCase):
    def test_whitespace_level_only_touches_layout(self):
        messy = BASE.replace("\n", "\r\n").replace("+ 1;", "+ 1;   ").rstrip() + "\n\n\n"
        self.assertEqual(golden.normalise(messy, "whitespace"), golden.normalise(BASE, "whitespace"))
        self.assertNotEqual(golden.normalise(BASE, "whitespace"), golden.normalise(RENUMBERED, "whitespace"))

    def test_temporaries_and_stack_names_are_alpha_renamed(self):
        self.assertEqual(golden.normalise(BASE), golden.normalise(RENUMBERED))

    def test_a_real_change_survives(self):
        for edited in (BASE.replace("iVar1 + 1", "iVar1 + 2"), BASE.replace("FUN_00401000", "FUN_00401004"),
                       BASE.replace("DAT_00402000", "DAT_00402004"), BASE.replace("int __cdecl", "int __stdcall"),
                       BASE.replace("param_1", "param_2"), BASE.replace("iVar2 + local_10", "iVar1 + local_10")):
            self.assertNotEqual(golden.normalise(edited), golden.normalise(BASE), edited)

    def test_string_literals_are_left_alone(self):
        changed = BASE.replace('"iVar1 local_10"', '"iVar2 local_10"')
        self.assertNotEqual(golden.normalise(changed), golden.normalise(BASE))

    def test_renaming_is_a_bijection(self):
        # Two distinct temporaries must not collapse into one name.
        merged = BASE.replace("iVar2", "iVar1")
        self.assertNotEqual(golden.normalise(merged), golden.normalise(BASE))

    def test_banner_comments_go_but_warnings_stay_with_masked_addresses(self):
        plate = "/* Function: demo\n   by hand */\n// note\n" + BASE
        self.assertEqual(golden.normalise(plate), golden.normalise(BASE))
        warn = "/* WARNING: Removing unreachable block (ram,0x00401234) */\n" + BASE
        moved = "/* WARNING: Removing unreachable block (ram,0x00405678) */\n" + BASE
        self.assertEqual(golden.normalise(warn), golden.normalise(moved))
        self.assertNotEqual(golden.normalise(warn), golden.normalise(BASE))
        other = "/* WARNING: Could not recover jumptable at 0x00401234 */\n" + BASE
        self.assertNotEqual(golden.normalise(warn), golden.normalise(other))

    def test_end_of_line_comments_are_not_removed(self):
        self.assertNotEqual(golden.normalise(BASE.replace("return", "/* why */ return")), golden.normalise(BASE))

    def test_levels(self):
        self.assertEqual(golden.normalise(BASE, "raw"), BASE)
        with self.assertRaises(ValueError):
            golden.normalise(BASE, "aggressive")


class Diff(unittest.TestCase):
    def setUp(self):
        self.work = workdir("golden")
        self.root = Path(self.work.name)
        self.addCleanup(self.work.cleanup)

    def run_diff(self, a_rows, b_rows, **options):
        a = capture(self.root, "a", a_rows)
        b = capture(self.root, "b", b_rows, header=options.pop("header_b", None))
        return golden.diff_captures(a, b, **options)

    def test_every_class(self):
        a_rows = {"0x401000": ("ok", BASE), "0x401010": ("ok", BASE), "0x401020": ("ok", BASE),
                  "0x401030": ("ok", BASE), "0x401040": ("failed", None), "0x401050": ("failed", None),
                  "0x401060": ("ok", BASE)}
        b_rows = {"0x401000": ("ok", BASE), "0x401010": ("ok", RENUMBERED), "0x401020": ("ok", BASE.replace("+ 1", "+ 2")),
                  "0x401030": ("failed", None), "0x401040": ("ok", BASE), "0x401050": ("failed", None),
                  "0x401070": ("ok", BASE)}
        report = self.run_diff(a_rows, b_rows)
        self.assertEqual(report["counts"], {"identical": 1, "identical_after_normalisation": 1, "changed": 1,
                                            "failed_only_in_B": 1, "failed_only_in_A": 1, "failed_in_both": 1,
                                            "missing_in_B": 1, "missing_in_A": 1})
        self.assertEqual(report["compared_base_ok_in_A"], 5)
        self.assertEqual(report["matched"], 2)
        changed = report["examples"]["changed"][0]
        self.assertEqual(changed["entry"], "0x401020")
        self.assertTrue(any(line.startswith("+") and "+ 2" in line for line in changed["diff"]))
        self.assertEqual(report["examples"]["failed_only_in_B"][0]["status_B"], "failed")
        self.assertFalse(report["gate"]["passed"])

    def test_examples_are_bounded(self):
        a_rows = {"0x%x" % (0x401000 + 16 * index): ("ok", BASE) for index in range(20)}
        b_rows = {entry: ("ok", BASE.replace("+ 1", "+ 9")) for entry in a_rows}
        report = self.run_diff(a_rows, b_rows, examples=3, excerpt_lines=4)
        self.assertEqual(report["counts"]["changed"], 20)
        self.assertEqual(len(report["examples"]["changed"]), 3)
        self.assertLessEqual(len(report["examples"]["changed"][0]["diff"]), 5)

    def test_no_text_report_holds_no_c(self):
        report = self.run_diff({"0x401000": ("ok", BASE)}, {"0x401000": ("ok", BASE.replace("+ 1", "+ 2"))}, with_text=False)
        self.assertNotIn("diff", report["examples"]["changed"][0])
        self.assertNotIn("iVar", json.dumps(report))

    def test_gate_corpus_profile(self):
        a_rows = {"0x%x" % (0x401000 + 16 * index): ("ok", BASE) for index in range(100)}
        b_rows = dict(a_rows)
        b_rows["0x401000"] = ("ok", BASE.replace("+ 1", "+ 2"))
        b_rows["0x401010"] = ("ok", BASE.replace("+ 1", "+ 3"))
        report = self.run_diff(a_rows, b_rows)           # 98 of 100: exactly the threshold
        self.assertEqual(report["match_pct"], 98.0)
        self.assertTrue(report["gate"]["passed"], report["gate"])
        b_rows["0x401020"] = ("ok", BASE.replace("+ 1", "+ 4"))
        report = self.run_diff(a_rows, b_rows)
        self.assertFalse(report["gate"]["passed"])
        self.assertIn("identical-or-normalised", report["gate"]["problems"][0])

    def test_gate_failed_only_in_b_is_zero_by_default(self):
        a_rows = {"0x%x" % (0x401000 + 16 * index): ("ok", BASE) for index in range(200)}
        b_rows = dict(a_rows)
        b_rows["0x401000"] = ("failed", None)
        report = self.run_diff(a_rows, b_rows)           # 99.5% matched, but a function stopped decompiling
        self.assertFalse(report["gate"]["passed"])
        self.assertIn("failed_only_in_B", report["gate"]["problems"][0])
        report = self.run_diff(a_rows, b_rows, max_failed_only_in_B=1)
        self.assertTrue(report["gate"]["passed"])

    def test_gate_fixtures_profile_needs_everything(self):
        a_rows = {"0x401000": ("ok", BASE), "0x401010": ("ok", BASE)}
        report = self.run_diff(a_rows, {"0x401000": ("ok", BASE), "0x401010": ("ok", RENUMBERED)}, profile="fixtures")
        self.assertTrue(report["gate"]["passed"])
        report = self.run_diff(a_rows, {"0x401000": ("ok", BASE), "0x401010": ("ok", BASE.replace("+ 1", "+ 2"))}, profile="fixtures")
        self.assertFalse(report["gate"]["passed"])

    def test_failed_only_in_a_does_not_fail_the_gate(self):
        a_rows = {"0x401000": ("ok", BASE), "0x401010": ("failed", None)}
        report = self.run_diff(a_rows, {"0x401000": ("ok", BASE), "0x401010": ("ok", BASE)}, profile="fixtures")
        self.assertEqual(report["counts"]["failed_only_in_A"], 1)
        self.assertTrue(report["gate"]["passed"])

    def test_a_different_program_or_path_fails_unless_allowed(self):
        rows = {"0x401000": ("ok", BASE)}
        report = self.run_diff(rows, rows, header_b={"program_sha256": "ee" * 32})
        self.assertFalse(report["gate"]["passed"])
        self.assertIn("program SHA-256 differs", report["gate"]["problems"][0])
        report = self.run_diff(rows, rows, header_b={"program_sha256": "ee" * 32}, allow_mismatch=True)
        self.assertTrue(report["gate"]["passed"])
        self.assertTrue(report["warnings"])
        report = self.run_diff(rows, rows, header_b={"path": "production"})
        self.assertFalse(report["gate"]["passed"])

    def test_level_can_be_stricter_at_diff_time(self):
        rows_a = {"0x401000": ("ok", BASE)}
        rows_b = {"0x401000": ("ok", RENUMBERED)}
        self.assertEqual(self.run_diff(rows_a, rows_b)["counts"]["identical_after_normalisation"], 1)
        self.assertEqual(self.run_diff(rows_a, rows_b, level="whitespace")["counts"]["changed"], 1)

    def test_duplicate_entries_are_refused(self):
        path = self.root / "dup"
        path.mkdir()
        row = {"type": "function", "entry": "0x401000", "status": "ok"}
        (path / "rows.jsonl").write_text(json.dumps({"type": "header"}) + "\n" + json.dumps(row) + "\n" + json.dumps(row) + "\n")
        with self.assertRaises(ValueError):
            golden.read_capture(path)

    def test_capture_roundtrip_hashes(self):
        directory = capture(self.root, "round", {"0xABC": ("ok", RENUMBERED)})
        header, rows, texts = golden.read_capture(directory, with_text=True)
        row = rows["0xabc"]
        self.assertEqual(row["c_sha256"], golden.sha256_text(RENUMBERED))
        self.assertEqual(row["normalized_c_sha256"], golden.sha256_text(golden.normalise(BASE)))
        self.assertEqual(texts["0xabc"], RENUMBERED)
        self.assertEqual(header["function_rows"], 1)
        self.assertEqual(header["status_counts"], {"ok": 1})
        self.assertFalse((directory / "rows.jsonl.part").exists())


class Helpers(unittest.TestCase):
    def test_canonical_entry(self):
        for text in ("0x00401000", "401000", "ram:00401000", "0X401000"):
            self.assertEqual(golden.canonical_entry(text), "0x401000")

    def test_size_buckets_and_timing_table(self):
        self.assertEqual([golden.size_bucket(value) for value in (1, 2, 64, 65, 512, 513, None)],
                         ["1-byte", "small (2-64 B)", "small (2-64 B)", "medium (65-512 B)", "medium (65-512 B)",
                          "large (>512 B)", "unknown"])
        rows = {str(index): {"size": 1 if index < 3 else 100, "ms": float(index + 1), "status": "ok"} for index in range(10)}
        rows["bad"] = {"size": 100, "ms": 999.0, "status": "failed"}
        table = {row["bucket"]: row for row in golden.timing_table(rows)}
        self.assertEqual(table["1-byte"]["n"], 3)
        self.assertEqual(table["1-byte"]["median_ms"], 2.0)
        self.assertEqual(table["medium (65-512 B)"]["n"], 7)
        self.assertEqual(table["all"]["max_ms"], 10.0)
        self.assertAlmostEqual(golden.percentile([1, 2, 3, 4, 5], 0.95), 4.8)
        self.assertIn("| bucket |", golden.render_timing(list(table.values())))

    def test_parse_size(self):
        self.assertEqual(golden._parse_size(["[00401000, 00401004]", "[00401010, 0040101f]"]), 21)
        self.assertIsNone(golden._parse_size(["nonsense"]))
        self.assertIsNone(golden._parse_size([]))

    def test_stratified_sample_is_deterministic_and_covers_buckets(self):
        rows = [{"entry": "0x%x" % (0x1000 + index), "size": (1 if index % 50 == 0 else 20 if index % 3 else 700)}
                for index in range(600)]
        first = golden.stratified_sample(rows, 60, seed=3)
        self.assertEqual(first, golden.stratified_sample(rows, 60, seed=3))
        self.assertNotEqual(first, golden.stratified_sample(rows, 60, seed=4))
        self.assertEqual({golden.size_bucket(item["size"]) for item in first}, {"1-byte", "small (2-64 B)", "large (>512 B)"})
        self.assertEqual(golden.stratified_sample(rows, 10000, seed=1), rows)


class Trees(unittest.TestCase):
    def test_tree_hash_detects_any_change_and_copy_proves_identity(self):
        with workdir("tree") as name:
            root = Path(name)
            source = root / "src"
            (source / "sub").mkdir(parents=True)
            (source / "a.bin").write_bytes(b"one")
            (source / "sub" / "b.bin").write_bytes(b"two")
            before = golden.tree_hash(source)
            self.assertEqual(before["files"], 2)
            self.assertEqual(golden.tree_hash(source)["tree_sha256"], before["tree_sha256"])
            proof = golden.project_copy(source, root / "dst")
            self.assertTrue(proof["source_unchanged"])
            self.assertEqual(golden.tree_hash(root / "dst")["tree_sha256"], before["tree_sha256"])
            (source / "sub" / "b.bin").write_bytes(b"twp")
            self.assertNotEqual(golden.tree_hash(source)["tree_sha256"], before["tree_sha256"])
            with self.assertRaises(SystemExit):
                golden.project_copy(source, root / "dst")      # never overwrites


if __name__ == "__main__":
    unittest.main()
