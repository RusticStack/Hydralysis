"""Y4e (PROTOCOL-3.md 3.6, 7.4, D20, D47, D64, section 8): `ghidra_run` modes in userscripts.py.

The fake daemon (tests/fakehydra.py) is Y4a's in this wave, so the script-isolation surface the tests need is added here,
in a subclass that only this module uses (`IsolatingEngine`): the capability versions an engine advertises, the
`isolation` request field (`private` reads the saved state, `exclusive` the live one, `worker` the saved one and refuses
a program with unsaved edits with `conflict`/`reason:"unsaved"`, like E7), the reply keys (`isolation`, `attemptedChanges`,
`attemptedChangesCount`, `basedOn`), a revision that moves on every save, and a deaf script that the worker kills.

`RealWorker` runs the same flow on a real install (E7, hydra.4), gated like tests/test_engine_integration.py.
"""

from __future__ import annotations

import hashlib
import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import api, hydra, query, userscripts, workcopy
from hydralysis.hydra import EngineError
from support import Hydra4Only, hydra4_missing, workdir


class IsolatingEngine(fakehydra.FakeEngine):
    """FakeEngine plus the E4/E7 script-isolation surface (opt-in through CAPS)."""

    CAPS: dict = {}
    RUNS: list = []
    REVISIONS = {"n": 0}

    def capabilities(self):
        return dict(self.CAPS)

    def _info(self, program, **fields):
        reply = super()._info(program, **fields)
        reply["revision"] = self._program(program).get("rev", "rev-0")
        return reply

    def _save(self, program, **fields):
        reply = super()._save(program, **fields)
        self.REVISIONS["n"] += 1
        self._program(program)["rev"] = "rev-%d" % self.REVISIONS["n"]
        return {**reply, "revision": self._program(program)["rev"]}

    def _script(self, script, program=None, args=(), isolation=None, **fields):
        if script == "RusticQuery.java" or isolation is None:
            return super()._script(script, program=program, args=args, **fields)
        entry = self._program(program)
        unsaved = entry["live"] is not None and entry["live"] != entry["saved"]
        self.RUNS.append({"script": script, "isolation": isolation, "program": program, "basedOn": fields.get("basedOn"),
                          "unsaved": unsaved})
        if isolation == "worker":
            if not self.CAPS.get("scriptIsolation", 0) >= 2:
                raise EngineError("bad_request", "isolation must be one of [shared, exclusive, private]", {"field": "isolation"})
            if unsaved:
                raise EngineError("conflict", "%s has 1 unsaved edit(s); save it first" % program,
                                  {"reason": "unsaved", "program": program, "unsavedEdits": 1}, "script",
                                  next={"cmd": "save", "program": program})
            if script == "Deaf.java":
                raise EngineError("cancelled", "script timed out; its worker process was killed", {}, "script")
        seen = entry["saved"] if isolation in ("private", "worker") else self._view(entry)
        attempted = 1 if "mutate" in args else 0
        reply = {"output": "names=%s\n" % json.dumps(seen["names"], sort_keys=True), "truncated": False,
                 "mode": {"exclusive": "contained"}.get(isolation, isolation), "changed": False, "isolation": isolation,
                 "attemptedChanges": attempted > 0, "attemptedChangesCount": attempted,
                 "basedOn": {"saved": True, "programRevision": entry.get("rev", "rev-0")}, "unsavedIgnored": 0}
        if isolation == "private" and unsaved:
            reply["unsavedIgnored"] = 1
        if isolation == "worker":
            reply["worker"] = {"pid": 4242, "totalMs": 900, "startMs": 400, "cloneMs": 20, "killed": False}
        return reply


class ModesCase(unittest.TestCase):
    CAPS = {"scriptIsolation": 2, "attemptedChanges": 1, "scriptSha256": 1}

    def setUp(self):
        self.temp = workdir("userscripts")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exe = self.root / "owned.exe"
        self.exe.write_bytes(b"MZ a small owned executable")
        self.digest = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        self.daemon = fakehydra.reset()
        self.gpr = self.root / "analysed" / "Owned" / "Owned.gpr"
        self.daemon.add_project(self.gpr, {"/owned.exe": {"sha256": self.digest}})
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        for name in ("Names.java", "Deaf.java"):
            (self.scripts / name).write_text("// fixture " + name, encoding="utf-8")
        self.settings = {"root": str(self.root / "data"), "hydra_dir": "x", "hydra_client": "x",
                         "targets": {"owned": {"gpr": str(self.gpr), "program": "/owned.exe", "exe": str(self.exe),
                                               "scripts": str(self.scripts)}}}
        IsolatingEngine.CAPS = dict(self.CAPS)
        IsolatingEngine.RUNS = []
        IsolatingEngine.REVISIONS = {"n": 0}
        engine_patch = patch("hydralysis.hydra.Engine", IsolatingEngine)
        engine_patch.start()
        self.addCleanup(engine_patch.stop)
        query._keys.clear()
        self.addCleanup(query._keys.clear)
        self.runner = query.QueryRunner(self.settings, IsolatingEngine(self.settings))

    # ---- helpers ------------------------------------------------------------------------------------------------
    def edit(self, view="alice", name="Edited"):
        target = workcopy.with_view(self.runner.target("owned"), view)
        expect = workcopy.load_store(self.settings, target)["revision"]
        return json.loads(self.runner.query("owned", "type_edit", "0x140001000", options={
            "source": "cited test evidence", "kind": "rename", "name": name, "expect_revision": expect, "view": view}))

    def run_script(self, script="Names.java", view="alice", args=(), **options):
        return userscripts.run(self.settings, "owned", script, list(args), timeout_s=30, view=view,
                               options=options or None)

    def saves(self):
        return [fields for role, command, fields in self.daemon.calls if command == "save"]

    def scripts_sent(self):
        return [fields for role, command, fields in self.daemon.calls if command == "script" and fields["script"] != "RusticQuery.java"]

    def job(self):
        found = sorted((Path(self.settings["root"]) / "jobs").glob("job-*.json"), key=lambda path: path.stat().st_mtime_ns)
        return json.loads(found[-1].read_text(encoding="utf-8"))

    def view_program(self, view="alice"):
        target = workcopy.with_view(self.runner.target("owned"), view)
        state = json.loads((workcopy._directory(self.settings, target) / "state.json").read_text(encoding="utf-8"))
        project = self.daemon.projects[self.daemon._norm(state["fork_gpr"])]
        return project["programs"]["/owned.exe"]


class Worker(ModesCase):
    """hydra.4 (scriptIsolation 2): a user script on a view runs in the killable worker on the saved view (D64)."""

    def test_a_script_on_an_edited_view_sees_the_edit_after_one_save(self):
        self.edit()
        self.assertNotEqual(self.view_program()["live"], self.view_program()["saved"], "the edit is unsaved before the run")
        output = self.run_script()
        self.assertIn('"0x140001000": "Edited"', output, "the worker's clone must hold the edit (a stale clone reads FUN_)")
        self.assertIn("isolation=worker", output)
        self.assertIn("view_saved=yes", output)
        self.assertEqual(len(self.saves()), 1, "the owner saves the view exactly once")
        sent = self.scripts_sent()[-1]
        self.assertEqual(sent["isolation"], "worker")
        self.assertEqual(sent["basedOn"], {"saved": True, "programRevision": "rev-1"}, "the saved revision is passed as basedOn")
        record = self.job()
        self.assertEqual(record["isolation"], "worker")
        self.assertEqual(record["based_on"]["programRevision"], "rev-1")
        self.assertEqual(len(record["view_saves"]), 1)
        self.assertIs(record["attempted_changes"], False)

    def test_an_unedited_view_is_not_saved(self):
        self.edit()
        self.run_script()
        self.assertEqual(len(self.saves()), 1)
        output = self.run_script()
        self.assertEqual(len(self.saves()), 1, "a view with nothing unsaved (info.changed false) must not be saved again")
        self.assertIn("view_saved=no", output)
        self.assertEqual(self.scripts_sent()[-1]["basedOn"]["programRevision"], "rev-1")

    def test_the_save_is_taken_under_the_per_view_lock(self):
        self.edit()
        held = []
        real = workcopy.view_lock

        def spy(settings, target):
            held.append(target["key"])
            return real(settings, target)
        with patch("hydralysis.workcopy.view_lock", spy):
            self.run_script()
        alice = workcopy.with_view(self.runner.target("owned"), "alice")["key"]
        self.assertIn(alice, held)

    def test_a_busy_view_lock_refuses_and_does_not_run(self):
        from hydralysis import locks
        self.edit()
        target = workcopy.with_view(self.runner.target("owned"), "alice")
        before = len(self.scripts_sent())
        with patch.object(workcopy, "SYNC_LOCK_S", 0.2):
            lease = locks.LaneLock(str(workcopy._directory(self.settings, target) / ".view.lock"))
            self.assertTrue(lease.acquire())
            try:
                with self.assertRaises(RuntimeError) as caught:
                    self.run_script()
            finally:
                lease.release()
        self.assertIn("busy", str(caught.exception))
        self.assertEqual(len(self.scripts_sent()), before, "nothing is submitted without the owner's save")
        self.assertEqual(self.saves(), [])

    def test_a_mutating_run_reports_attempted_changes_and_leaves_the_view(self):
        self.edit()
        before = json.dumps(self.view_program()["live"], sort_keys=True)
        output = self.run_script(args=["mutate"])
        self.assertIn("attemptedChanges=true (1)", output)
        self.assertEqual(json.dumps(self.view_program()["live"], sort_keys=True), before)

    def test_readonly_fails_a_run_that_attempted_changes(self):
        self.edit()
        with self.assertRaises(RuntimeError) as caught:
            self.run_script(args=["mutate"], readonly=True)
        self.assertIn("readonly run", str(caught.exception))
        self.assertEqual(self.job()["state"], "failed")
        self.assertIn("state=done", self.run_script(readonly=True), "a readonly run that changes nothing is done")

    def test_a_deaf_script_is_killed_and_the_next_one_runs(self):
        self.edit()
        before = json.dumps(self.view_program()["live"], sort_keys=True)
        with self.assertRaises(RuntimeError) as caught:
            self.run_script("Deaf.java")
        self.assertIn("worker process was killed", str(caught.exception))
        self.assertEqual(self.job()["state"], "failed")
        self.assertEqual(self.job()["isolation"], "worker")
        self.assertEqual(json.dumps(self.view_program()["live"], sort_keys=True), before)
        self.assertIn("Edited", self.run_script())

    def test_an_edit_between_save_and_clone_is_saved_once_more(self):
        self.edit()
        original = IsolatingEngine._script
        raced = {"done": False}

        def racing(engine, script, program=None, args=(), isolation=None, **fields):
            if isolation == "worker" and not raced["done"]:
                raced["done"] = True
                entry = engine._program(program)
                entry["live"] = {**entry["live"], "names": {**entry["live"]["names"], "0x140001000": "Late"}}
            return original(engine, script, program=program, args=args, isolation=isolation, **fields)
        with patch.object(IsolatingEngine, "_script", racing):
            output = self.run_script()
        self.assertIn("Late", output)
        self.assertEqual(len(self.saves()), 2)

    def test_the_master_runs_private(self):
        output = self.run_script(view="")
        self.assertIn("isolation=private", output)
        self.assertEqual(self.scripts_sent()[-1]["isolation"], "private")
        self.assertEqual(self.saves(), [])

    def test_a_user_script_never_runs_shared(self):
        with self.assertRaises(ValueError) as caught:
            self.run_script(isolation="shared")
        self.assertIn("never runs shared", str(caught.exception))
        self.assertEqual(self.scripts_sent(), [])
        for view in ("", "alice"):
            if view:
                self.edit()
            self.run_script(view=view)
        self.assertNotIn("shared", [item.get("isolation") for item in self.scripts_sent()])


class WithoutWorker(ModesCase):
    """An engine with E4 but not E7 (scriptIsolation 1): private on a clean working copy, exclusive otherwise."""

    CAPS = {"scriptIsolation": 1, "attemptedChanges": 1}

    def test_an_edited_view_runs_exclusive_and_is_not_saved(self):
        self.edit()
        output = self.run_script()
        self.assertEqual(self.scripts_sent()[-1]["isolation"], "exclusive")
        self.assertIn('"0x140001000": "Edited"', output, "exclusive reads the live view")
        self.assertEqual(self.saves(), [])
        self.assertNotIn("basedOn", self.scripts_sent()[-1])

    def test_a_clean_working_copy_runs_private(self):
        self.edit()
        program = self.view_program()
        program["saved"] = json.loads(json.dumps(program["live"]))   # saved by its owner: nothing unsaved
        self.run_script()
        self.assertEqual(self.scripts_sent()[-1]["isolation"], "private")
        self.run_script(view="")
        self.assertEqual(self.scripts_sent()[-1]["isolation"], "private")

    def test_private_is_refused_on_unsaved_edits(self):
        self.edit()
        with self.assertRaises(ValueError) as caught:
            self.run_script(isolation="private")
        self.assertIn("unsaved edits", str(caught.exception))
        self.assertEqual(self.scripts_sent(), [])

    def test_exclusive_on_request(self):
        self.run_script(view="", isolation="exclusive")
        self.assertEqual(self.scripts_sent()[-1]["isolation"], "exclusive")


class NoCapability(ModesCase):
    """hydra.2/3: today's contained mode, and options are answered not_available without running (7.5, Y0d)."""

    CAPS = {}

    def test_no_options_runs_as_today(self):
        self.edit()
        output = self.run_script()
        sent = self.scripts_sent()[-1]
        self.assertNotIn("isolation", sent)
        self.assertNotIn("isolation=", output)
        self.assertIn("mode=contained", output)
        self.assertEqual(self.saves(), [])

    def test_options_are_not_available_and_nothing_runs(self):
        for options in ({"isolation": "private"}, {"isolation": "exclusive"}, {"readonly": True}):
            reply = json.loads(self.run_script(view="", **options))
            self.assertIn(reply["not_available"], ("scriptIsolation", "attemptedChanges"))
        self.assertEqual(self.scripts_sent(), [])


class ThroughApi(ModesCase):
    """api.py's dispatcher reaches `handle` through HANDLER_MODULES, and the options reach exactly one `run`."""

    def call(self, **arguments):
        with patch("hydralysis.api._settings", return_value=self.settings):
            return api.call("ghidra_run", {"target": "owned", "script": "Names", **arguments})

    def test_the_handler_is_registered(self):
        self.assertIs(api.handler("scriptIsolation"), userscripts)

    def test_options_reach_run_and_do_not_outlive_the_call(self):
        self.call(options={"isolation": "exclusive", "as": "bob"})
        self.assertEqual(self.scripts_sent()[-1]["isolation"], "exclusive")
        self.call(options={"as": "bob"})
        self.assertEqual(self.scripts_sent()[-1]["isolation"], "private", "the previous call's options were reused")

    def test_options_of_a_call_that_failed_early_do_not_leak(self):
        with self.assertRaises(ValueError):
            self.call(script="Missing", options={"isolation": "exclusive"})
        self.call()
        self.assertEqual(self.scripts_sent()[-1]["isolation"], "private")

    def test_shared_and_unknown_options_are_refused(self):
        with self.assertRaises(ValueError):
            self.call(options={"isolation": "shared"})
        with self.assertRaises(ValueError):
            self.call(options={"isolatoin": "private"})
        self.assertEqual(self.scripts_sent(), [])


# ---- the real engine (E7, hydra.4) ---------------------------------------------------------------------------------

from test_engine_integration import BINARY, CLIENT, ENGINE, _prepare, _release  # noqa: E402

FIRST = """import ghidra.app.script.GhidraScript;
public class %(cls)s extends GhidraScript {
    public void run() throws Exception {
        println("first=" + currentProgram.getFunctionManager().getFunctions(true).next().getName());
    }
}
"""

MUTATE = """import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class Y4eMutate extends GhidraScript {
    public void run() throws Exception {
        var function = currentProgram.getFunctionManager().getFunctions(true).next();
        function.setName("y4e_mutated_by_script", SourceType.USER_DEFINED);
        println("renamed=" + function.getName());
    }
}
"""

DEAF = """import ghidra.app.script.GhidraScript;
public class Y4eDeaf extends GhidraScript {
    public void run() throws Exception {
        println("first=" + currentProgram.getFunctionManager().getFunctions(true).next().getName());
        long end = System.currentTimeMillis() + 120_000;
        while (System.currentTimeMillis() < end) {
            try { Thread.sleep(100); } catch (InterruptedException ignored) { }
        }
    }
}
"""


@unittest.skipUnless(ENGINE and CLIENT and BINARY and Path(BINARY).is_file(), "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class RealWorker(Hydra4Only, unittest.TestCase):
    """E7 on a real install: an edited view, the owner's one save, the worker sees the edit, a deaf script is killed."""

    VIEW = "y4e"

    @classmethod
    def setUpClass(cls):
        from hydralysis import targets
        _prepare(cls, BINARY, "y4e-real", "fixture")
        cls.scripts = cls.root / "my-scripts"
        cls.scripts.mkdir()
        for name, text in (("Y4eFirst.java", FIRST % {"cls": "Y4eFirst"}), ("Y4eMutate.java", MUTATE), ("Y4eDeaf.java", DEAF)):
            (cls.scripts / name).write_text(text, encoding="utf-8")
        cls.settings["targets"] = {"fixture": dict(targets.registry(cls.settings)["fixture"], scripts=str(cls.scripts))}
        cls.degraded = hydra4_missing(cls.runner.engine, "E7's killable script worker (scriptIsolation 2)")
        if cls.degraded:
            return
        level = userscripts._level(cls.runner.engine, "scriptIsolation")
        if level < userscripts.WORKER_VERSION:
            _release(cls)
            raise AssertionError("the install advertises scriptIsolation %s; E7's worker (2) is required" % level)
        functions = json.loads(cls.runner.query("fixture", "functions", "", limit=3, options={"view": cls.VIEW}))["functions"]
        cls.first = functions[0]
        cls.original = functions[0]["name"]

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def run_script(self, name, view=None, timeout_s=120, **options):
        return userscripts.run(self.settings, "fixture", name, [], timeout_s=timeout_s,
                               view=self.VIEW if view is None else view, options=options or None)

    def edit(self, name):
        target = workcopy.with_view(self.runner.target("fixture"), self.VIEW)
        expect = workcopy.load_store(self.settings, target)["revision"]
        return json.loads(self.runner.query("fixture", "type_edit", self.first["address"], options={
            "source": "y4e real-engine test", "kind": "rename", "name": name, "expect_revision": expect, "view": self.VIEW}))

    def program(self):
        target = workcopy.with_view(self.runner.target("fixture"), self.VIEW)
        return self.runner.program_for(target)

    def changed(self):
        return bool(self.runner.engine.call("info", program=self.program()["key"]).get("changed"))

    def job(self, script):
        found = []
        for path in (Path(self.settings["root"]) / "jobs").glob("job-*.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            if record.get("script") == script:
                found.append(record)
        return sorted(found, key=lambda item: item["started_at"])[-1]

    def test_1_worker_on_an_edited_view(self):
        self.edit("y4e_edited")
        self.assertTrue(self.changed(), "the view holds its edit unsaved before the run")
        # (1) the engine itself refuses a worker clone of an unsaved view: the owner's save is required
        staged = userscripts._stage(self.settings, self.scripts / "Y4eFirst.java")
        with self.assertRaises(EngineError) as caught:
            self.runner.engine.call("script", script=staged, program=self.program()["key"], args=[], timeout=60,
                                    isolation="worker", wait=30000)
        self.assertEqual(caught.exception.code, "conflict")
        self.assertEqual(caught.exception.details.get("reason"), "unsaved")
        # (2) after the owner's one save the worker sees the edit
        output = self.run_script("Y4eFirst")
        self.assertIn("first=y4e_edited", output, "a stale clone answers the unedited name")
        self.assertIn("isolation=worker", output)
        self.assertIn("view_saved=yes", output)
        record = self.job("Y4eFirst.java")
        self.assertEqual(record["isolation"], "worker")
        self.assertEqual(len(record["view_saves"]), 1)
        self.assertTrue(record["based_on"]["saved"])
        self.assertEqual(record["based_on"]["programRevision"], record["view_saves"][0]["revision"])
        self.assertFalse(self.changed())
        # (5) nothing unsaved: the next run does not save
        output = self.run_script("Y4eFirst")
        self.assertIn("view_saved=no", output)
        self.assertIn("first=y4e_edited", output)

    def test_2_mutation_is_measured_on_the_clone(self):
        output = self.run_script("Y4eMutate")
        self.assertIn("renamed=y4e_mutated_by_script", output)
        self.assertIn("attemptedChanges=true", output)
        self.assertFalse(self.changed(), "nothing of the worker's run reaches the view")
        self.assertIn("first=y4e_edited", self.run_script("Y4eFirst"))
        with self.assertRaises(RuntimeError) as caught:
            self.run_script("Y4eMutate", readonly=True)
        self.assertIn("readonly run", str(caught.exception))

    def test_3_a_deaf_script_is_killed_at_its_timeout(self):
        started = time.monotonic()
        with self.assertRaises(RuntimeError) as caught:
            self.run_script("Y4eDeaf", timeout_s=8)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 60, "the deaf script ran on past its timeout (%.1f s)" % elapsed)
        # under load the engine's own deadline can answer first ("script timed out", cancelled) before the worker is
        # reported killed: either way the deaf script was stopped at its timeout and the job failed
        self.assertRegex(str(caught.exception), "killed|timed out")
        self.assertEqual(self.job("Y4eDeaf.java")["state"], "failed")
        self.assertFalse(self.changed())
        self.assertIn("first=y4e_edited", self.run_script("Y4eFirst"), "the next script runs after the kill")
        health = self.runner.engine.call("health")
        workers = health.get("scriptWorkers")
        if isinstance(workers, dict):
            self.assertEqual(workers.get("running", 0), 0, json.dumps(workers))

    def test_4_the_master_runs_private(self):
        # a view with no store reads the sealed master: nothing unsaved, so private
        output = self.run_script("Y4eFirst", view="unused-view")
        self.assertIn("isolation=private", output)
        self.assertIn("first=" + self.original, output)


if __name__ == "__main__":
    unittest.main()
