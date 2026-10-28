"""Lineage, generations and CURRENT.log (PROTOCOL-3.md 4.4, 4.1 item 3): the canonical form, the manifest, the log under a
second process, and the stable key across a generation flip."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from hydralysis import durable, lineage, targets
from support import workdir
from test_commit import World

SRC = Path(__file__).resolve().parent.parent / "src"
VECTOR = Path(__file__).resolve().parent / "vectors" / "canonical-manifest.json"


class CanonicalForm(unittest.TestCase):
    def test_the_fixed_vector_is_reproduced_byte_for_byte(self):
        vector = json.loads(VECTOR.read_text(encoding="utf-8"))
        manifest = vector["manifest"]
        body = {key: value for key, value in manifest.items() if key != "selfSha256"}
        self.assertEqual(lineage.canonical(body).hex(), vector["canonicalWithoutSelfSha256Utf8Hex"])
        self.assertEqual(hashlib.sha256(lineage.canonical(body)).hexdigest(), vector["canonicalWithoutSelfSha256Sha256"])
        self.assertEqual(lineage.fileset_sha256(manifest["files"]), vector["filesetSha256"])
        self.assertEqual(lineage.self_hash(manifest), vector["selfSha256"])
        self.assertEqual(manifest["filesetSha256"], vector["filesetSha256"])
        self.assertEqual(manifest["selfSha256"], vector["selfSha256"])

    def test_the_vector_holds_the_awkward_paths_of_the_spec(self):
        paths = [row["path"] for row in json.loads(VECTOR.read_text(encoding="utf-8"))["manifest"]["files"]]
        self.assertTrue(any("é" in path for path in paths))      # an accented letter
        self.assertTrue(any("日" in path for path in paths))      # CJK
        self.assertTrue(any("\U0001F600" in path for path in paths))  # a supplementary character
        self.assertTrue(any(" " in path and " " in path for path in paths))

    def test_what_is_escaped_and_what_is_not(self):
        text = lineage.canonical({"b": 1, "a": 'q"\\\t\u001f<>&\'\u007f é'}).decode("utf-8")
        self.assertEqual(text, '{"a":"q\\"\\\\\\t\\u001f<>&\'\u007f é","b":1}')

    def test_keys_sort_by_code_point_and_there_is_no_whitespace(self):
        self.assertEqual(lineage.canonical({"b": [1, {"z": 0, "a": 0}], "a": None, "B": True}), b'{"B":true,"a":null,"b":[1,{"a":0,"z":0}]}')

    def test_an_unpaired_surrogate_is_refused_in_a_manifest(self):
        with self.assertRaises(UnicodeEncodeError):
            lineage.canonical({"path": "\ud800"})

    def test_nan_is_refused(self):
        with self.assertRaises(ValueError):
            lineage.canonical({"x": float("nan")})


class Manifests(unittest.TestCase):
    def setUp(self):
        self.temp = workdir("lineage")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / "gen"
        (self.folder / "p.rep").mkdir(parents=True)
        (self.folder / "p.gpr").write_text("gpr", encoding="utf-8")
        (self.folder / "p.rep" / "db.1.gbf").write_bytes(b"data" * 10)
        (self.folder / "p.fork.json").write_text(json.dumps({"purpose": "generation", "disposable": False, "state": "candidate"}), encoding="utf-8")

    def test_a_written_manifest_verifies_and_hides_nothing(self):
        manifest = lineage.write_manifest(self.folder, {"cid": "c-1"})
        self.assertEqual({row["path"] for row in manifest["files"]}, {"p.gpr", "p.rep/db.1.gbf", "p.fork.json"})
        self.assertTrue(lineage.verify_manifest(self.folder)["ok"])
        self.assertEqual(manifest["selfSha256"], lineage.self_hash(manifest))
        self.assertEqual(lineage.read_manifest(self.folder)["filesetSha256"], lineage.fileset_sha256(manifest["files"]))

    def test_sealing_changes_neither_the_sidecar_hash_nor_the_verification(self):
        lineage.write_manifest(self.folder, {"cid": "c-1"})
        (self.folder / "p.fork.json").write_text(json.dumps({"purpose": "generation", "disposable": False, "state": "complete"}), encoding="utf-8")
        (self.folder / lineage.SEAL_MARKER).write_text("{}", encoding="utf-8")
        (self.folder / "p.lock").write_text("x", encoding="utf-8")
        (self.folder / "projectState").write_text("x", encoding="utf-8")
        self.assertTrue(lineage.verify_manifest(self.folder)["ok"])

    def test_a_changed_missing_or_added_file_is_tampering(self):
        lineage.write_manifest(self.folder, {"cid": "c-1"})
        (self.folder / "p.rep" / "db.1.gbf").write_bytes(b"other" * 8)
        self.assertIn("changed file p.rep/db.1.gbf", lineage.verify_manifest(self.folder)["problems"])
        (self.folder / "p.gpr").unlink()
        self.assertIn("missing file p.gpr", lineage.verify_manifest(self.folder)["problems"])
        (self.folder / "extra.bin").write_bytes(b"x")
        self.assertIn("unlisted file extra.bin", lineage.verify_manifest(self.folder)["problems"])

    def test_an_edited_manifest_fails_its_self_hash(self):
        lineage.write_manifest(self.folder, {"cid": "c-1"})
        path = self.folder / lineage.MANIFEST
        path.write_bytes(path.read_bytes().replace(b'"c-1"', b'"c-2"'))
        self.assertIn("selfSha256 does not match", lineage.verify_manifest(self.folder)["problems"])

    def test_a_folder_without_a_manifest_is_invisible(self):
        self.assertFalse(lineage.verify_manifest(self.folder)["ok"])
        self.assertIsNone(lineage.read_manifest(self.folder))

    def test_a_newer_manifest_format_is_refused_not_guessed(self):
        manifest = lineage.write_manifest(self.folder, {"cid": "c-1"})
        manifest = {**manifest, "format": 99}
        manifest["selfSha256"] = lineage.self_hash(manifest)
        (self.folder / lineage.MANIFEST).write_bytes(lineage.canonical(manifest))
        self.assertTrue(any("format_unreadable" in problem for problem in lineage.verify_manifest(self.folder)["problems"]))

    def test_the_tree_hash_ignores_locks_and_the_manifest_but_not_content(self):
        before = lineage.tree_hash(self.folder)
        (self.folder / "p.lock").write_text("x", encoding="utf-8")
        lineage.write_manifest(self.folder, {"cid": "c-1"})
        self.assertEqual(lineage.tree_hash(self.folder), before)
        (self.folder / "p.gpr").write_text("changed", encoding="utf-8")
        self.assertNotEqual(lineage.tree_hash(self.folder), before)


class Log(World, unittest.TestCase):
    def test_creation_is_idempotent_and_generation_zero_is_the_adopted_project(self):
        selected = {**self.runner.target("owned"), "origin_key": self.runner.target("owned")["key"]}
        first = lineage.ensure(self.settings, selected)
        second = lineage.ensure(self.settings, selected)
        self.assertEqual(first, second)
        self.assertRegex(first["id"], r"^L-[0-9a-f]{8}$")
        self.assertEqual(lineage.find(self.settings, selected["origin_key"]), first["id"])
        self.assertIsNone(lineage.find(self.settings, "0" * 16))
        rows = lineage.history(self.settings, first["id"])
        self.assertEqual([(row["seq"], row["gen"], row["reason"]) for row in rows], [(1, 0, "register")])
        self.assertEqual(Path(rows[0]["gpr"]), self.gpr)

    def test_lines_chain_by_the_hash_of_the_previous_valid_line(self):
        selected = {**self.runner.target("owned"), "origin_key": self.runner.target("owned")["key"]}
        lid = lineage.ensure(self.settings, selected)["id"]
        for number in range(3):
            lineage.append_current(self.settings, lid, {"gen": number + 1, "cid": "c-%08x" % number, "reason": "commit", "gpr": "x",
                                                        "manifestSha256": "m"})
        rows = lineage.history(self.settings, lid)
        self.assertEqual([row["seq"] for row in rows], [1, 2, 3, 4])
        self.assertIsNone(rows[0]["prevHash"])
        for previous, row in zip(rows, rows[1:]):
            self.assertEqual(row["prevHash"], lineage.sha256_hex(lineage.canonical(previous)))
        self.assertEqual(lineage.head(self.settings, lid)["gen"], 3)

    def test_a_target_with_a_lineage_resolves_to_the_head_and_keeps_its_key(self):
        before = self.runner.target("owned")
        lid = lineage.ensure(self.settings, {**before, "origin_key": before["key"]})["id"]
        generation = Path(self.settings["root"]) / "elsewhere" / "Owned.gpr"
        lineage.append_current(self.settings, lid, {"gen": 1, "cid": "c-00000001", "reason": "commit", "gpr": str(generation), "manifestSha256": "m"})
        after = self.runner.target("owned")
        self.assertEqual(after["gpr"], str(generation))
        self.assertEqual(after["key"], before["key"])          # the overlay store, the working directory and the view keys survive
        self.assertEqual(after["adopted_gpr"], str(self.gpr))
        self.assertEqual((after["lineage"]["id"], after["lineage"]["generation"]), (lid, 1))
        self.assertEqual(targets.registry(self.settings)["owned"]["gpr"], str(self.gpr))  # the registry stays a cache of the adopted path

    def test_a_target_without_a_lineage_resolves_exactly_as_before(self):
        resolved = self.runner.target("owned")
        self.assertNotIn("lineage", resolved)
        self.assertEqual(resolved["key"], targets.target_key(str(self.gpr), "/owned.exe"))

    def test_configuration_targets_are_not_given_a_lineage_by_the_cache(self):
        settings = {**self.settings, "targets": {"cfg": {"gpr": str(self.gpr), "program": "/owned.exe", "sha256": self.digest}}}
        resolved = targets.resolve(settings, "cfg")
        lid = lineage.ensure(settings, {**resolved, "origin_key": resolved["key"]})["id"]  # created, but the registry has no row to extend
        self.assertEqual(lineage.load(settings, lid)["origin_key"], resolved["key"])
        self.assertNotIn("lineage", targets.resolve(settings, "cfg"))

    def test_generation_numbers_are_never_reused(self):
        before = self.runner.target("owned")
        lid = lineage.ensure(self.settings, {**before, "origin_key": before["key"]})["id"]
        self.assertEqual(lineage.next_generation(self.settings, lid), 1)
        lineage.generation_dir(self.settings, lid, 1).mkdir(parents=True)          # an abandoned folder
        self.assertEqual(lineage.next_generation(self.settings, lid), 2)
        log = lineage.intent_log(self.settings, lid, "c-00000009")
        log.append({"cid": "c-00000009", "attempt": 1, "step": "CANDIDATE_RESERVED", "gen": 5})  # a reservation without a folder
        self.assertEqual(lineage.next_generation(self.settings, lid), 6)

    def test_invalid_ids_are_refused(self):
        for bad in ("", "L-xyz", "../x", "L-123456789"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                lineage.lineage_dir(self.settings, bad)
        with self.assertRaises(ValueError):
            lineage.intent_log(self.settings, "L-00000000", "../c")


WRITER_A = r"""
import json, sys
sys.path.insert(0, %(src)r)
from hydralysis import lineage
settings = {"root": %(root)r}
lid = %(lid)r
for command in sys.stdin:
    command = command.strip()
    if command == "append":
        line = lineage.append_current(settings, lid, {"gen": 0, "cid": None, "reason": "recover", "gpr": "a"})
        print(json.dumps({"seq": line["seq"]}), flush=True)
    elif command == "rollback":
        line = lineage.append_current(settings, lid, {"gen": 0, "cid": "c-0000000a", "reason": "rollback", "gpr": "a"})
        print(json.dumps({"seq": line["seq"]}), flush=True)
    elif command == "quit":
        break
"""
WRITER_B = r"""
import sys
sys.path.insert(0, %(src)r)
from hydralysis import lineage
lineage.append_current({"root": %(root)r}, %(lid)r, {"gen": 0, "cid": None, "reason": "recover", "gpr": "b" * 80})
"""


class TwoProcessTornTail(World, unittest.TestCase):
    """4.1 item 3 on CURRENT.log: a long-lived process appends again after a second process was killed mid-line."""

    def start(self, source, **values):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        env.pop("HYDRALYSIS_TEST_FAULT", None)
        env.pop("HYDRALYSIS_TEST_MODE", None)
        process = subprocess.Popen([sys.executable, "-c", source % {"src": str(SRC), "root": self.settings["root"], **values}],
                                   env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (process.poll() is None and process.kill(), process.communicate()))
        return process

    def ask(self, process, command):
        process.stdin.write(command + "\n")
        process.stdin.flush()
        line = process.stdout.readline()
        self.assertTrue(line, process.stderr.read() if process.poll() is not None else "no answer")
        return json.loads(line)

    def test_a_long_lived_writer_appends_again_after_a_killed_writer_left_a_fragment(self):
        before = self.runner.target("owned")
        lid = lineage.ensure(self.settings, {**before, "origin_key": before["key"]})["id"]
        alive = self.start(WRITER_A, lid=lid)
        self.assertEqual(self.ask(alive, "append")["seq"], 2)
        # process B appends through a fault and is killed mid-line
        env = dict(os.environ, HYDRALYSIS_TEST_MODE="1", HYDRALYSIS_TEST_FAULT="log.torn_append:torn:30", PYTHONIOENCODING="utf-8")
        killed = subprocess.run([sys.executable, "-c", WRITER_B % {"src": str(SRC), "root": self.settings["root"], "lid": lid}], env=env,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(killed.returncode, 137)
        log = lineage.current_log(self.settings, lid)
        self.assertIsNotNone(log.scan().torn_tail)
        self.assertEqual(len(lineage.history(self.settings, lid)), 2)  # a reader ignores the fragment and never repairs
        self.assertEqual(self.ask(alive, "append")["seq"], 3)           # A appends again: it repairs first
        rows = lineage.history(self.settings, lid)
        self.assertEqual([row["seq"] for row in rows], [1, 2, 3])
        self.assertIsNone(log.scan().torn_tail)
        self.assertIsNone(log.scan().corrupt)
        self.assertEqual(len(log.repairs()), 1)
        (kept,) = list(log.path.parent.glob("CURRENT.log.torn-*"))
        self.assertEqual(len(kept.read_bytes()), 30)
        self.assertNotIn(b"bbbbbbbb", log.path.read_bytes())            # no fragment is left in the log
        self.assertEqual(self.ask(alive, "rollback")["seq"], 4)         # a rollback line goes through the same rule
        alive.stdin.write("quit\n")
        alive.stdin.flush()


if __name__ == "__main__":
    unittest.main()
