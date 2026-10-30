"""Z5 (PROTOCOL-3.md section 8): ghidra_run (userscripts.py) on the real engine.

Runs only against a real Hydra install, with the same variables as tests/test_engine_integration.py. One prepared
program, one daemon, one data root for the class. The scripts are written by the tests themselves (a few lines of Java).

The .py decision (docs/verification-prepare.md): Hydralysis accepts a `.py` name, stages it and sends it, and an engine that
was not started with PyGhidra answers a typed `script did not load` failure; the job ends `failed`, the project is not
touched and the daemon takes the next script. No Python script runs on the install under test, and a test here pins that
answer, so an engine that gains PyGhidra shows up as a failing test to be reviewed, not as a silent change.
"""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from test_engine_integration import BINARY, CLIENT, ENGINE, _prepare, _release
from test_engine_prepare import daemon_programs, daemon_status, evidence, read_only_everywhere

NAME_OF_FIRST = """import ghidra.app.script.GhidraScript;
public class %(cls)s extends GhidraScript {
    public void run() throws Exception {
        println("first=" + currentProgram.getFunctionManager().getFunctions(true).next().getName());
    }
}
"""

MARK = """import ghidra.app.script.GhidraScript;
public class %(cls)s extends GhidraScript {
    public void run() throws Exception {
        println("%(text)s args=" + getScriptArgs().length + " program=" + currentProgram.getName());
    }
}
"""

RENAME_FIRST = """import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class Mutate extends GhidraScript {
    public void run() throws Exception {
        var function = currentProgram.getFunctionManager().getFunctions(true).next();
        function.setName("zz_mutated_by_script", SourceType.USER_DEFINED);
        println("renamed=" + function.getName());
    }
}
"""

OLD_STYLE = """// Usage: OldCount <prefix>   counts the functions whose name starts with the prefix
//@category Hydralysis.Tests
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
public class OldCount extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String prefix = args.length > 0 ? args[0] : "";
        int total = 0, matching = 0;
        for (Function f = getFirstFunction(); f != null; f = getFunctionAfter(f)) {
            total++;
            if (f.getName().startsWith(prefix)) matching++;
        }
        println("total=" + total + " matching=" + matching);
    }
}
"""

BROKEN = """import ghidra.app.script.GhidraScript;
public class Broken extends GhidraScript {
    public void run() throws Exception { int x = "not an int"; }
}
"""


@unittest.skipUnless(ENGINE and CLIENT and BINARY and Path(BINARY).is_file(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class ScriptStaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hydralysis import lineage, targets
        _prepare(cls, BINARY, "scripts", "fixture")
        cls.folder = Path(cls.prepared["project"]["gpr"]).parent
        cls.scripts = cls.root / "my-scripts"
        cls.scripts.mkdir()
        record = dict(targets.registry(cls.settings)["fixture"], scripts=str(cls.scripts))
        # a COPY of the prepared project for the mutating script: the original's tree hash is the control
        cls.copy = cls.root / "project-copy"
        shutil.copytree(cls.folder, cls.copy)
        copied = dict(record, gpr=str(next(cls.copy.glob("*.gpr"))))
        cls.settings["targets"] = {"scripted": record, "scripted-copy": copied}
        cls.original_hash = lineage.tree_hash(cls.folder)
        # the daemon is running before any script is staged
        cls.first = json.loads(cls.runner.query("scripted", "functions", "", limit=3))["functions"][0]["address"]
        cls.daemon_pid = daemon_status(cls.settings)["pid"]

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def write(self, name, text, folder=None):
        path = (folder or self.scripts) / name
        path.write_text(text, encoding="utf-8")
        return path

    def run_script(self, name, *args, target="scripted"):
        from hydralysis import userscripts
        return userscripts.run(self.settings, target, name, list(args), timeout_s=120)

    def jobs(self):
        found = {}
        for path in sorted((Path(self.settings["root"]) / "jobs").glob("job-*.json")):
            record = json.loads(path.read_text(encoding="utf-8"))
            found[path.stem] = record
        return found

    def latest_job(self, script):
        rows = [record for record in self.jobs().values() if record.get("script") == script]
        return max(rows, key=lambda record: record["started_at"])

    def test_a_java_script_staged_after_the_daemon_started_runs(self):
        from hydralysis import hydra
        self.write("Late.java", MARK % {"cls": "Late", "text": "late-mark"})
        output = self.run_script("Late", "a", "b", "c")
        self.assertIn("late-mark args=3", output)
        self.assertIn("state=done", output)
        self.assertEqual(daemon_status(self.settings)["pid"], self.daemon_pid, "the daemon was restarted for the script")
        self.assertTrue((hydra.script_dirs(self.settings)[1] / "Late.java").is_file())
        self.assertEqual(self.latest_job("Late.java")["state"], "done")

    def test_a_changed_script_of_the_same_name_runs_its_new_text(self):
        self.write("Edit.java", MARK % {"cls": "Edit", "text": "version-one"})
        self.assertIn("version-one", self.run_script("Edit"))
        self.write("Edit.java", MARK % {"cls": "Edit", "text": "version-two"})
        output = self.run_script("Edit")
        self.assertIn("version-two", output)
        self.assertNotIn("version-one", output)

    def test_a_different_script_of_the_same_name_from_another_folder_is_refused(self):
        from hydralysis import hydra
        other = self.root / "other-scripts"
        other.mkdir(exist_ok=True)
        self.write("Same.java", MARK % {"cls": "Same", "text": "from-first"})
        self.write("Same.java", MARK % {"cls": "Same", "text": "from-other"}, folder=other)
        self.settings["targets"]["scripted-other"] = dict(self.settings["targets"]["scripted"], scripts=str(other))
        self.assertIn("from-first", self.run_script("Same"))
        with self.assertRaises(ValueError) as caught:
            self.run_script("Same", target="scripted-other")
        self.assertIn("a different Same.java", str(caught.exception))
        staged = (hydra.script_dirs(self.settings)[1] / "Same.java").read_text(encoding="utf-8")
        self.assertIn("from-first", staged, "the refused script must not replace the staged one")
        owners = json.loads((hydra.script_dirs(self.settings)[1] / "owners.json").read_text(encoding="utf-8"))
        self.assertEqual(owners["Same.java"], str((self.scripts / "Same.java").resolve()))

    def test_the_name_of_a_hydralysis_script_is_refused(self):
        self.write("RusticQuery.java", MARK % {"cls": "RusticQuery", "text": "impostor"})
        with self.assertRaises(ValueError) as caught:
            self.run_script("RusticQuery")
        self.assertIn("one of Hydralysis's own scripts", str(caught.exception))

    def test_a_compile_error_is_reported_with_the_compiler_text_and_the_daemon_takes_the_next_script(self):
        self.write("Broken.java", BROKEN)
        with self.assertRaises(RuntimeError) as caught:
            self.run_script("Broken")
        message = str(caught.exception)
        self.assertIn("script did not load", message)
        self.assertIn("Broken.java:3: error: incompatible types", message)
        record = self.latest_job("Broken.java")
        self.assertEqual(record["state"], "failed")
        self.assertIn("incompatible types", record["error"])
        self.write("AfterBroken.java", MARK % {"cls": "AfterBroken", "text": "still-fine"})
        self.assertIn("still-fine", self.run_script("AfterBroken"))
        self.assertEqual(daemon_status(self.settings)["pid"], self.daemon_pid)

    def test_a_py_script_never_runs_and_changes_nothing(self):
        """The .py decision. This install was not started with PyGhidra, so a Python script cannot run. Today the name
        passes Hydralysis's regex and the engine answers a typed `script did not load` failure; if userscripts.py later
        refuses the name up front (the other half of the decision, Y4e's file), that is accepted too. What is never
        accepted: the script running, a job left active, or the project changing."""
        from hydralysis import lineage
        self.write("Snake.py", "print('hello from python')\n")
        before = lineage.tree_hash(self.folder)
        with self.assertRaises((RuntimeError, ValueError)) as caught:
            self.run_script("Snake.py")
        message = str(caught.exception)
        self.assertNotIn("hello from python", message)
        if isinstance(caught.exception, RuntimeError):
            self.assertIn("script did not load", message)
            self.assertIn("PyGhidra", message)
            self.assertEqual(self.latest_job("Snake.py")["state"], "failed")
        else:
            self.assertIn(".java", message)
        self.assertEqual(lineage.tree_hash(self.folder), before)
        self.write("AfterSnake.java", MARK % {"cls": "AfterSnake", "text": "java-still-works"})
        self.assertIn("java-still-works", self.run_script("AfterSnake"))
        evidence("scripts-py-decision", {"outcome": type(caught.exception).__name__, "error": message[:300]})

    def test_a_representative_old_style_script_runs_with_arguments_and_is_listed_with_its_usage(self):
        """A GhidraMCP/REA-era script ported to headless use: it reads its arguments from getScriptArgs() instead of
        asking, walks the listing through FlatProgramAPI calls and prints one line. The total it prints is the engine's."""
        from hydralysis import userscripts
        self.write("OldCount.java", OLD_STYLE)
        listed = userscripts.list_scripts(self.settings, "scripted", "OldCount")
        self.assertIn("OldCount.java", listed)
        self.assertIn("Usage: OldCount <prefix>", listed)
        output = self.run_script("OldCount", "FUN_")
        matching = int(output.split("matching=")[1].split()[0])
        total = int(output.split("total=")[1].split()[0])
        self.assertGreater(matching, 0)
        self.assertGreaterEqual(total, matching)
        # FlatProgramAPI walks the program's own functions; the engine's count also holds external and thunk entries
        from hydralysis import hydra
        key = daemon_programs(self.settings)[0]["key"]
        listed = hydra.Engine(self.settings).call("functions", program=key, limit=10000)["functions"]
        self.assertEqual(total, len([item for item in listed if not item["external"]]), "the script's count is the engine's")

    def test_a_mutating_script_on_a_copy_leaves_the_tree_hash_unchanged(self):
        from hydralysis import lineage
        self.write("Mutate.java", RENAME_FIRST)
        self.write("NameOfFirst.java", NAME_OF_FIRST % {"cls": "NameOfFirst"})
        before_copy = lineage.tree_hash(self.copy)
        original_name = self.run_script("NameOfFirst", target="scripted-copy").split("first=")[1].split()[0]
        self.assertNotEqual(original_name, "zz_mutated_by_script")
        output = self.run_script("Mutate", target="scripted-copy")
        self.assertIn("renamed=zz_mutated_by_script", output)
        # hydra.3 runs a script on a program as "contained"; on hydra.4 (Y4e) it runs "private". Both roll the change back.
        self.assertRegex(output, r"mode=(contained|private)\b")
        self.assertEqual(lineage.tree_hash(self.copy), before_copy, "the script changed the copy's tree")
        self.assertEqual(lineage.tree_hash(self.folder), self.original_hash, "the script changed the original's tree")
        # contained: the rename is rolled back, so the next reader sees the original name
        again = self.run_script("NameOfFirst", target="scripted-copy")
        self.assertIn("first=" + original_name, again)
        status = read_only_everywhere(self, self.settings)
        evidence("scripts-mutating-copy", {"tree_sha256_copy": before_copy, "tree_unchanged": True,
                                           "programs_open": len(status["programs"])})


class StageUnit(unittest.TestCase):
    """userscripts._stage on its own (no engine): the staging rules ghidra_run depends on."""

    def setUp(self):
        from support import workdir
        self.work = workdir("stage-unit")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.settings = {"root": str(self.root / "data")}
        self.mine = self.root / "mine"
        self.mine.mkdir()

    def staged(self):
        from hydralysis import hydra
        return hydra.script_dirs(self.settings)[1]

    def test_staging_copies_records_the_owner_and_is_idempotent(self):
        from hydralysis import userscripts
        source = self.mine / "A.java"
        source.write_text("class A {}", encoding="utf-8")
        self.assertEqual(userscripts._stage(self.settings, source), "A.java")
        self.assertEqual((self.staged() / "A.java").read_text(encoding="utf-8"), "class A {}")
        owners = json.loads((self.staged() / "owners.json").read_text(encoding="utf-8"))
        self.assertEqual(owners["A.java"], str(source.resolve()))
        stamp = (self.staged() / "A.java").stat().st_mtime_ns
        userscripts._stage(self.settings, source)
        self.assertEqual((self.staged() / "A.java").stat().st_mtime_ns, stamp, "an unchanged script is not rewritten")
        source.write_text("class A { int x; }", encoding="utf-8")
        userscripts._stage(self.settings, source)
        self.assertIn("int x", (self.staged() / "A.java").read_text(encoding="utf-8"))
        self.assertEqual(list(self.staged().glob("*.tmp")), [], "no temporary file is left behind")

    def test_another_owner_with_other_text_is_refused_and_the_staged_copy_survives(self):
        from hydralysis import userscripts
        other = self.root / "other"
        other.mkdir()
        (self.mine / "B.java").write_text("class B { /* mine */ }", encoding="utf-8")
        (other / "B.java").write_text("class B { /* theirs */ }", encoding="utf-8")
        userscripts._stage(self.settings, self.mine / "B.java")
        with self.assertRaises(ValueError) as caught:
            userscripts._stage(self.settings, other / "B.java")
        self.assertIn("a different B.java from", str(caught.exception))
        self.assertIn("mine", (self.staged() / "B.java").read_text(encoding="utf-8"))
        # the same text from another folder is not a collision
        (other / "B.java").write_text("class B { /* mine */ }", encoding="utf-8")
        userscripts._stage(self.settings, other / "B.java")

    def test_a_name_of_one_of_hydralysis_own_scripts_is_refused(self):
        from hydralysis import userscripts
        (self.mine / "RusticQuery.java").write_text("class RusticQuery {}", encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            userscripts._stage(self.settings, self.mine / "RusticQuery.java")
        self.assertIn("one of Hydralysis's own scripts", str(caught.exception))
        self.assertFalse((self.staged() / "RusticQuery.java").exists())


if __name__ == "__main__":
    unittest.main()
