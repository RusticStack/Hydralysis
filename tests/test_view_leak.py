"""Gate 9.17 (soak, round 2): Hydralysis left superseded working copies open in the engine, and the publish spot check refused
the rename of a called function.

A. The view leak. A sync leaves its working copy in the daemon in shared mode with the replayed records unsaved (D61); its
writer leaves, and the daemon keeps that work as an orphan for ever (`orphanKeepS` 0), counted as a view against `maxViews`.
A copy the view no longer uses (replaced after a publish or a rebase, built by a rebase that failed, left by a process that
ended) stayed there: the soak's Hydralysis daemon reached maxViews 32 in about two minutes and publishes stalled. The fake
daemon models what the real one reports (`status` programs with users and unsavedEdits, `Daemon.orphans`), and a reader's
close that discards nothing. Every test asserts that the only orphans left are the current copies of views that hold pending
records (one per view at most), and the real-engine class repeats the publish and rebase cycles on hydra.4.

B. The publish spot check. Renaming a function changes how its callers decompile (they print the new name); the check now
accepts a difference the changeset's renames explain and still refuses any other.
"""

from __future__ import annotations

import json
import os
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import commits, hydra, lineage, query, viewgov, views, workcopy
from test_commit import A, B, C
from test_views import ViewWorld, lying_probe


def _norm(gpr) -> str:
    return str(Path(gpr).resolve()).lower()


def current_copies(root: Path) -> set[str]:
    """The current working copy of every view that held pending records at its last sync (`working/*/state.json`)."""
    found = set()
    for state_file in (root / "working").glob("*/state.json"):
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if state.get("fork_gpr") and state.get("edits"):
            found.add(_norm(state["fork_gpr"]))
    return found


class LeakChecks:
    """The assertion of every test here: no orphan in the daemon is anything but a view's current copy."""

    def assert_no_leak(self, orphans: list[dict], note: str = "") -> None:
        allowed = current_copies(Path(self.settings["root"]))
        stray = [row for row in orphans if _norm(row["gpr"]) not in allowed]
        self.assertEqual(stray, [], "copies no view uses are left in the daemon with unsaved work %s" % note)
        self.assertLessEqual(len(orphans), len(allowed), note)


class FakeViewLeak(LeakChecks, ViewWorld, unittest.TestCase):
    def setUp(self):
        super().setUp()
        viewgov.GOVERNOR.reset()
        self.addCleanup(viewgov.GOVERNOR.reset)

    def check(self, note=""):
        self.assert_no_leak(self.daemon.orphans(), note)

    def test_publish_cycles_leave_no_superseded_copy_in_the_daemon(self):
        for cycle in range(5):
            self.edit("One%d" % cycle, A, view="one")
            self.assertEqual(self.name_of(A, view="one"), "One%d" % cycle)
            self.assertEqual(self.publish("one")["outcome"], "applied")
            self.check("after publish %d" % cycle)
            # nothing is pending in the view now: it reads the head, and its old copy was closed by the publish
            self.assertEqual(self.daemon.orphans(), [], "cycle %d" % cycle)
            self.assertEqual(self.name_of(A, view="one"), "One%d" % cycle)

    def test_a_copy_retired_by_another_process_is_let_go_by_the_process_that_reads_it(self):
        """The publish worker is another process: it discards the view's copy but cannot end this process's reading of it, so
        the daemon keeps the edits for that reader (and, once the reader leaves, with no user at all: K7). The next use of
        the view in this process closes its rows and repeats the discard (real engine: 2 such copies per cycle before)."""
        self.edit("One", A, view="one")
        self.assertEqual(self.name_of(A, view="one"), "One")   # this process reads the view's copy
        with patch.object(workcopy, "_close_reader_rows", lambda settings, gprs: None):   # as from the worker's process
            self.assertEqual(self.publish("one")["outcome"], "applied")
        self.assertEqual(len(self.daemon.orphans()), 1, "the reader still holds the copy the worker discarded")
        # the next use, with this process's row cache as it is (`name_of` clears it)
        answer = json.loads(self.runner.query("owned", "decompile", A, options={"view": "one"}))
        self.assertEqual(answer["function"]["name"], "One")
        self.assertEqual(self.daemon.orphans(), [])

    def test_a_discarded_copy_another_reader_still_holds_is_not_reused(self):
        """The daemon keeps a discarded program's edits for a reader of another connection, and its marker no longer says
        what it holds (soak: K8, "overlay state ''"): the view forks a new copy instead of replaying into it."""
        self.edit("One", A, view="one")
        target = self.target("one")
        old = workcopy._state(self.settings, target)["fork_gpr"]
        other = fakehydra.FakeEngine(self.settings, role="reader", lane="another-process")
        project = other.call("open_project", path=old)
        other.call("open_program", project=project["id"], path="/owned.exe")
        workcopy.release(self.runner.engine, self.settings, target)
        self.assertNotIn("fork_gpr", workcopy._state(self.settings, target), "the held copy is not the view's any more")
        self.assertEqual(self.name_of(A, view="one"), "One")
        self.assertNotEqual(_norm(workcopy._state(self.settings, target)["fork_gpr"]), _norm(old))
        other.call("close_project", project=project["id"])

    def test_a_discarded_copy_nobody_holds_is_reused(self):
        self.edit("One", A, view="one")
        target = self.target("one")
        old = workcopy._state(self.settings, target)["fork_gpr"]
        workcopy.release(self.runner.engine, self.settings, target)
        self.assertEqual(self.name_of(A, view="one"), "One")
        self.assertEqual(_norm(workcopy._state(self.settings, target)["fork_gpr"]), _norm(old), "replayed into the same fork (D61)")

    def test_rebase_cycles_leave_no_superseded_copy_in_the_daemon(self):
        self.edit("Two", B, view="two")
        for cycle in range(4):
            self.edit("One%d" % cycle, A, view="one")
            self.publish("one")
            result = self.rebase("two")
            self.assertTrue(result["rebased"], result)
            self.assertEqual(self.name_of(B, view="two"), "Two")
            self.assertEqual(self.name_of(A, view="two"), "One%d" % cycle)
            self.check("after rebase %d" % cycle)
            self.assertLessEqual(len(self.daemon.orphans()), 1, "only view two holds records")

    def test_a_publish_with_records_left_in_the_view_closes_the_copy_its_base_moved_from(self):
        self.edit("Theirs", C, view="two")
        self.publish("two")           # generation 1
        self.edit("First", A, view="one")
        sealed = self.seal("one")
        self.edit("Later", B, view="one")   # stays pending: the view's base moves to generation 2 with it
        self.run_job(sealed, "one")
        self.check("after the publish")
        self.assertEqual(self.name_of(B, view="one"), "Later")
        self.check("after the rebuild")

    def test_a_lost_state_file_does_not_strand_the_copy_it_named(self):
        """K15 removes the state file and the next read rebuilds the view: the copy the file named is found on disk."""
        self.edit("Mine", A, view="one")
        state_file = workcopy._directory(self.settings, self.target("one")) / "state.json"
        old = json.loads(state_file.read_text(encoding="utf-8"))["fork_gpr"]
        state_file.unlink()
        self.assertEqual(self.name_of(A, view="one"), "Mine")
        self.assertNotIn(_norm(old), {_norm(row["gpr"]) for row in self.daemon.orphans()})
        self.check()

    def test_a_rebase_whose_copy_fails_verification_closes_that_copy(self):
        self.edit("FromTwo", B, view="two")
        self.edit("FromOne", A, view="one")
        self.publish("one")
        with patch.object(workcopy, "probe", lying_probe(workcopy.probe, "_build_rebased_copy")):
            with self.assertRaises(views.ViewError):
                self.rebase("two")
        shadow = workcopy._directory(self.settings, views._shadow(self.target("two")))
        self.assertFalse([row for row in self.daemon.orphans() if Path(row["gpr"]).resolve().is_relative_to(shadow.resolve())],
                         "the copy the failed rebase built is not left in the daemon")
        self.check()

    def test_a_sync_that_fails_after_forking_closes_the_fork_it_made(self):
        self.edit("Mine", A, view="one")
        target = self.target("one")
        (workcopy._directory(self.settings, target) / "state.json").unlink()   # the next edit forks a new copy
        before = {_norm(path) for path in workcopy._forks_on_disk(self.settings, target)}
        with self.assertRaisesRegex(ValueError, "refused"):
            self.edit("FAIL", B, view="one")   # the fake refuses this record: the replay fails after the fork
        made = [path for path in workcopy._forks_on_disk(self.settings, target) if _norm(path) not in before]
        self.assertEqual(len(made), 1)
        self.assertNotIn(_norm(made[0]), {_norm(row["gpr"]) for row in self.daemon.orphans()})

    def test_the_end_of_the_session_closes_every_view_the_process_used(self):
        self.edit("One", A, view="one")
        self.edit("Two", B, view="two")
        self.assertEqual(len(self.daemon.orphans()), 2, "each view's current copy is kept while the process uses it")
        closed = viewgov.end_session(timeout_s=30)
        self.assertEqual(sorted(closed), ["one", "two"])
        self.assertEqual(self.daemon.orphans(), [])
        self.assertEqual((self.name_of(A, view="one"), self.name_of(B, view="two")), ("One", "Two"), "replayed from the store")

    def test_stop_closes_the_views_copy_with_discard(self):
        self.edit("One", A, view="one")
        self.assertEqual(len(self.daemon.orphans()), 1)
        answer = json.loads(self.runner.query("owned", "stop", options={"view": "one"}))
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(self.daemon.orphans(), [])

    def test_an_eviction_discards_through_the_writer_lane_not_a_readers_leave(self):
        self.edit("One", A, view="one")
        target = self.target("one")
        self.assertEqual(len(self.daemon.orphans()), 1)
        workcopy.release(self.runner.engine, self.settings, target)
        self.assertEqual(self.daemon.orphans(), [])
        roles = [role for role, name, fields in self.daemon.calls if name == "close_project" and fields.get("discard")]
        self.assertIn("writer", roles)


class ReaderRows(ViewWorld, unittest.TestCase):
    """c1139d7 closes the least recently used read-only rows of a connection at the engine's per-connection cap. Rows this
    process dropped without closing hid open programs from it; now only the rows of the program that is gone are dropped."""

    def test_a_program_that_is_gone_drops_only_its_own_rows(self):
        self.edit("One", A, view="one")
        query._keys.clear()
        engine = self.runner.engine
        self.runner.query("owned", "decompile", A, options={"view": "shared"})   # the master (the shared view holds nothing)
        self.runner.query("owned", "decompile", A, options={"view": "one"})      # the view's working copy
        master_rows = [key for key in query._keys if key[0] == engine.key and _norm(key[1]) == _norm(self.gpr)]
        working_rows = [key for key in query._keys if key[0] == engine.key and _norm(key[1]) != _norm(self.gpr)]
        self.assertTrue(master_rows and working_rows)
        self.daemon.fail_next["script"] = hydra.EngineError("no_program", "closed by the cap")
        self.assertEqual(json.loads(self.runner.query("owned", "decompile", A, options={"view": "one"}))["function"]["name"], "One")
        self.assertTrue(all(key in query._keys for key in master_rows), "the master's row is kept: it is still open")


# ---- B. the publish spot check and renamed callees -------------------------------------------------------------

from test_backups import CallerEngine   # noqa: E402  (the fake daemon with callers)


class PublishRenameOfACalledFunction(ViewWorld, unittest.TestCase):
    ROWS = [{"address": A, "name": "FUN_140001000"}, {"address": B, "name": "FUN_140002000"},
            {"address": C, "name": "FUN_140003000"}]

    def setUp(self):
        super().setUp()
        patcher = patch.multiple(CallerEngine, ROWS=self.ROWS, CALLEES={B: [A]})   # B calls A: it prints A's name
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("hydralysis.hydra.Engine", "fakehydra.FakeEngine"):
            engine = patch(name, CallerEngine)
            engine.start()
            self.addCleanup(engine.stop)
        self.runner = query.QueryRunner(self.settings, CallerEngine(self.settings))

    def test_a_rename_of_a_called_function_is_published(self):
        self.edit("renamed_callee", A, view="one")
        sealed = self.seal("one")
        result = self.run_job(sealed, "one")
        self.assertEqual(result["outcome"], "applied", result)
        spot = self.done(sealed["csid"])["spot_check"]
        self.assertEqual(spot["explained_by_renames"], [B], "the caller differs by the new name only")
        self.assertEqual(spot["compared"], 2, "B (rewritten) and C (unchanged) are both compared")
        self.assertEqual(self.name_of(A), "renamed_callee")

    def test_a_caller_that_diverges_beyond_the_rename_fails_the_candidate(self):
        self.edit("renamed_callee", A, view="one")
        real = commits._decompile

        def drifted(engine, program, address, sha256):
            text = real(engine, program, address, sha256)
            return text.replace("renamed_callee();", "renamed_callee(); extra();") \
                if address == B and "publish-verify" in str(program.get("gpr", "")).replace("\\", "/") else text

        sealed = self.seal("one")
        with patch.object(commits, "_decompile", drifted):
            led = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        self.assertEqual((led["failure"]["error"], led["failure"]["counted"]), ("candidate_failed", True))
        self.assertIn("untouched function %s decompiles differently" % B, led["failure"]["message"])
        self.assertEqual(led["failure"]["address"], B)
        self.assertEqual(self.head()["gen"], 0)
        self.assertEqual(self.run_job(sealed, "one")["outcome"], "applied")   # the same publish, truthful, is applied

    def test_a_function_that_diverges_without_any_rename_involved_still_fails(self):
        self.edit("renamed_callee", A, view="one")
        real = commits._decompile

        def drifted(engine, program, address, sha256):
            text = real(engine, program, address, sha256)
            return text + "x" if address == C and "publish-verify" in str(program.get("gpr", "")).replace("\\", "/") else text

        sealed = self.seal("one")
        with patch.object(commits, "_decompile", drifted):
            led = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        self.assertEqual((led["failure"]["error"], led["failure"]["address"]), ("candidate_failed", C))

    def test_renames_and_their_rewrite(self):
        records = [{"address": A, "options": {"kind": "rename", "name": "x"},
                    "effects": [{"subject": "address:" + A, "field": "name", "before": "FUN_140001000", "after": "x"}]},
                   {"address": A, "options": {"kind": "rename", "name": "y"},
                    "effects": [{"subject": "address:" + A, "field": "name", "before": "x", "after": "y"}]},
                   {"address": B, "options": {"kind": "rename", "name": "ns::z"},
                    "effects": [{"subject": "address:" + B, "field": "name", "before": "FUN_140002000", "after": "ns::z"}]}]
        mapping = commits.renames(records, self.ROWS)
        self.assertEqual(mapping, {"FUN_140001000": "y", "FUN_140002000": "ns::z"})
        self.assertEqual(commits.with_renames("FUN_140001000(); FUN_1400010000(); FUN_140002000();", mapping),
                         "y(); FUN_1400010000(); ns::z();")
        swap = {"a": "b", "b": "a"}
        self.assertEqual(commits.with_renames("a(b);", swap), "b(a);")

    def test_the_rewrite_accounts_for_the_length_the_rename_changes(self):
        """The engine's answer counts the text (`total_characters`): the rename of a callee changes it in every caller."""
        def answer(c, total=None, truncated=False, name="FUN_140002000"):
            return lineage.canonical({"c": c, "total_characters": len(c) if total is None else total, "truncated": truncated,
                                      "function": {"address": B, "name": name}}).decode("utf-8")
        mapping = {"FUN_140001000": "renamed_callee"}
        before = answer("void f(void) {\n  FUN_140001000();\n}\n")
        self.assertTrue(commits.explained_by(before, answer("void f(void) {\n  renamed_callee();\n}\n"), mapping))
        # the count must move by what the rewrite added, and every other field must be equal
        self.assertFalse(commits.explained_by(before, answer("void f(void) {\n  renamed_callee();\n}\n", total=40), mapping))
        self.assertFalse(commits.explained_by(before, answer("void f(void) {\n  renamed_callee();\n}\n", name="g"), mapping))
        self.assertFalse(commits.explained_by(before, answer("void f(void) {\n  renamed_callee(); extra();\n}\n"), mapping))
        # a truncated head: the count of the whole text is not compared, the head is
        head = answer("void f(void) {\n  FUN_140001000();", total=900, truncated=True)
        self.assertTrue(commits.explained_by(head, answer("void f(void) {\n  renamed_callee();", total=906, truncated=True), mapping))
        self.assertFalse(commits.explained_by(head, answer("void f(void) {\n  other();", total=906, truncated=True), mapping))


# ---- the real engine (hydra.4) -------------------------------------------------------------------------------------

import test_engine_integration as integration   # noqa: E402
from support import Hydra4Only, hydra4_missing   # noqa: E402

HAVE_ENGINE = bool(integration.ENGINE and integration.CLIENT and integration.BINARY and Path(integration.BINARY).is_file())


@unittest.skipUnless(HAVE_ENGINE, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class RealEngineViewLeak(Hydra4Only, LeakChecks, unittest.TestCase):
    """Two agents publish and rebase in turn on the real engine; after every cycle the daemon holds no orphaned copy but the
    current one of each view with pending records, and its view count stays bounded. Red on the code before the fix: each
    publish and each rebase left one more orphan (the soak reached maxViews 32 in two minutes)."""

    CYCLES = 6

    @classmethod
    def setUpClass(cls):
        integration._prepare(cls, integration.BINARY, "view-leak", "fixture")
        cls.degraded = hydra4_missing(cls.runner.engine, "the hydra.4 governor and per-agent views")

    @classmethod
    def tearDownClass(cls):
        integration._release(cls)

    def ask(self, action, address="", who="h00", **options):
        return json.loads(self.runner.query("fixture", action, address, limit=200, timeout_s=300, options={"as": who, **options}))

    def revision(self, who):
        return self.ask("status", who=who)["view_revision"]

    def edit(self, who, address, name):
        return self.ask("type_edit", address, who, kind="rename", name=name, source="gate 9.17 view leak test",
                        expect_revision=self.revision(who))

    def publish(self, who):
        sealed = self.ask("type_edit", "", who, kind="publish", expect_revision=self.revision(who), confirm_one_way_upgrade=True)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            changeset = self.ask("status", "", who, show="queue", csid=sealed["csid"]).get("changeset") or {}
            if changeset.get("state") in ("done", "unknown"):
                return {**changeset, "csid": sealed["csid"]}
            time.sleep(0.5)
        self.fail("publish %s not decided in 600 s" % sealed["csid"])

    def facts(self):
        engine = hydra.Engine(self.settings)
        status = engine.call("status")
        # held for orphaned work (ProgramEntry.holdsOrphanedWork): unsaved edits and no writer, whoever still reads it
        orphans = [{"gpr": next((p.get("gpr") for p in status.get("projects", []) if p.get("id") == row.get("project")), ""),
                    **row} for row in status.get("programs", []) if not row.get("writers") and (row.get("unsavedEdits") or 0) > 0]
        governor = (engine.call("health").get("governor") or {})
        # what the daemon holds for somebody: a program in use, or one with unsaved work. A read-only program nobody uses is
        # the engine's warm cache (`keepWarm`), let go when room is needed (Governor.evictIdle), and not counted
        held = [row for row in status.get("programs", []) if row.get("users") or row.get("writers") or (row.get("unsavedEdits") or 0) > 0]
        return orphans, governor.get("views"), len(held)

    def test_publish_and_rebase_cycles_keep_the_engine_view_count_bounded(self):
        functions = [row["address"] for row in self.ask("functions", who="reader")["functions"]]
        self.assertGreaterEqual(len(functions), 4)
        views_seen, held_seen = [], []
        for cycle in range(self.CYCLES):
            with self.subTest(cycle=cycle):
                self.edit("h00", functions[0], "leak_a_%d" % cycle)
                self.edit("h01", functions[1], "leak_b_%d" % cycle)
                self.ask("decompile", functions[0], "h00")
                self.ask("decompile", functions[1], "h01")
                self.assertIn(self.publish("h00").get("outcome"), ("applied", "rebased", "converged", "skipped"))
                rebased = self.ask("type_edit", "", "h01", kind="rebase", expect_revision=self.revision("h01"))
                self.assertTrue(rebased.get("ok"), rebased)
                self.ask("decompile", functions[1], "h01")
                self.assertIn(self.publish("h01").get("outcome"), ("applied", "rebased", "converged", "skipped"))
                # each agent uses its view once more: a copy the publish worker retired is let go by the process reading it
                self.ask("decompile", functions[0], "h00")
                self.ask("decompile", functions[1], "h01")
                orphans, count, held = self.facts()
                views_seen.append(count)
                held_seen.append(held)
                self.assert_no_leak(orphans, "after cycle %d" % cycle)
                self.assertLessEqual(len(orphans), 2, "at most the current copy of each of the two views")
        self.assertLessEqual(max(held_seen), min(held_seen) + 2,
                             "the programs the daemon holds do not grow with the cycles: %s (views %s)" % (held_seen, views_seen))
        viewgov.end_session(timeout_s=60)
        orphans, _, _ = self.facts()
        self.assertEqual(orphans, [], "the end of the session closes every view's copy")

    def test_a_rename_of_a_called_function_is_published(self):
        import re
        rows = self.ask("functions", who="reader")["functions"]
        texts = {row["address"]: json.dumps(self.ask("decompile", row["address"], "reader")) for row in rows[:60]}
        callee = None
        for row in rows:
            pattern = re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(row["name"]))
            if any(other != row["address"] and pattern.search(text) for other, text in texts.items()):
                callee = row["address"]
                break
        if callee is None:
            self.skipTest("the fixture has no function called by another among the first 60")
        self.edit("rn00", callee, "renamed_callee_9_17")
        done = self.publish("rn00")
        self.assertIn(done.get("outcome"), ("applied", "rebased"), done)
        record = views.read_done(self.settings, self.runner.target("fixture")["lineage"]["id"], done["csid"])
        self.assertTrue(record["spot_check"]["explained_by_renames"] or record["spot_check"]["users_of_changed_symbols"],
                        record["spot_check"])
        self.assertGreater(record["spot_check"]["compared"], 0, record["spot_check"])
        self.assertIn("renamed_callee_9_17", json.dumps(self.ask("decompile", callee, "fresh-reader")))


if __name__ == "__main__":
    unittest.main()
