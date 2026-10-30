"""Gate 9.17 (soak, nightly-2): a view behind the head is built from its own base generation, never from the head.

H. Views h01 and h02 were on generation 394 with edits of their own. Their working copies were rebuilt (07:53:45Z) and then
showed names first published in generations 395 and 396; their state files said "generation 394" with the master revision of
the head. `workcopy._sync` opened the head project (`target["gpr"]`) as the master while it keyed and labelled the base with
the view's own generation, so a view behind the head was rebuilt from the head's content plus its own edits: it moved without
a rebase, and its isolation was gone. Every path that builds a view's copy goes through `_sync` (a read's rebuild, a repair
after the daemon lost the replay, the K15 rebuild after a lost state file, an eviction's replay, an edit, a commit, a merge,
the rebase's shadow copy); it now opens the generation the store is based on, and only an explicit rebase moves the base. A
base generation whose folder is gone is refused with `base_unavailable`, naming the rebase; the head is never substituted.

G. A read of a view behind the head whose working copy was gone was refused with `stale_view` (GATE11 soak-pr2, twice). The
contract (the reader's docstring, README, SKILL) is that reads keep answering and only edits are refused: such a read now
rebuilds the copy from the view's base generation (the rule of H) and answers from it.

The fake daemon names a project's saved content by its revision (as the engine does), so two generations never share one.
"""

from __future__ import annotations

import json
import shutil
import time
import unittest
from pathlib import Path

from hydralysis import hydra, lineage, query, viewgov, workcopy
from test_commit import A, B, C
from test_views import ViewWorld


class Behind:
    """View `h` holds an edit on generation 1; view `one` then publishes generations 2 and 3 on the same function."""

    def behind(self):
        self.edit("Gen1", A, view="one")
        self.assertEqual(self.publish("one")["generation"], 1)
        self.edit("Mine", B, view="h")
        self.assertEqual(self.names([A, B], "h"), {A: "Gen1", B: "Mine"})
        for number in (2, 3):
            self.edit("Gen%d" % number, A, view="one")
            self.assertEqual(self.publish("one")["generation"], number)
        self.assertEqual(self.store("h")["base"]["generation"], 1)
        self.assertEqual(self.name_of(A), "Gen3", "the head")
        return self.target("h")

    def generation_gpr(self, number):
        return [row for row in self.rows() if row["gen"] == number][-1]["gpr"]

    def revision_of(self, number):
        return self.runner.engine.call("open_project", path=self.generation_gpr(number))["revision"]

    def assert_on_base(self, target, note=""):
        self.assertEqual(self.names([A, B], "h"), {A: "Gen1", B: "Mine"}, "generation 1 plus the view's own edit %s" % note)
        state = workcopy._state(self.settings, target)
        self.assertEqual(state["master_revision"], self.revision_of(1), "the copy was built from generation 1 %s" % note)
        self.assertEqual((state["base"]["generation"], self.store("h")["base"]["generation"]), (1, 1))

    def drop_copy(self, target):
        """The view has no working copy any more: every copy closed and its folder gone, the state file too."""
        workcopy.release(self.runner.engine, self.settings, target)   # this process's reads of it end
        with workcopy.view_lock(self.settings, target):
            workcopy.retire_copies(self.settings, target)
        for gpr in workcopy._forks_on_disk(self.settings, target):
            shutil.rmtree(gpr.parent)
        (workcopy._directory(self.settings, target) / "state.json").unlink(missing_ok=True)
        self.assertEqual(workcopy._forks_on_disk(self.settings, target), [])


class ViewBase(Behind, ViewWorld, unittest.TestCase):
    def setUp(self):
        super().setUp()
        viewgov.GOVERNOR.reset()
        self.addCleanup(viewgov.GOVERNOR.reset)

    def test_generations_have_their_own_revision(self):
        self.behind()
        self.assertEqual(len({self.revision_of(number) for number in (1, 2, 3)}), 3)

    # ---- H ----------------------------------------------------------------------------------------------------------

    def test_a_rebuild_of_a_view_behind_the_head_replays_onto_its_own_base_generation(self):
        target = self.behind()
        workcopy.repair(self.settings, self.runner.engine, target)   # the daemon lost the replay: rebuilt from the store
        self.assert_on_base(target, "after a repair")

    def test_a_lost_state_file_rebuilds_the_view_on_its_own_base_generation(self):
        target = self.behind()
        (workcopy._directory(self.settings, target) / "state.json").unlink()   # K15
        self.assert_on_base(target, "after K15")

    def test_an_evicted_view_replays_onto_its_own_base_generation(self):
        target = self.behind()
        workcopy.release(self.runner.engine, self.settings, target)
        self.assert_on_base(target, "after an eviction")

    def test_a_rebuild_after_a_discarded_copy_stays_on_the_base(self):
        target = self.behind()
        old = workcopy._state(self.settings, target)["fork_gpr"]
        with workcopy.view_lock(self.settings, target):
            workcopy.retire_copies(self.settings, target)   # GATE11's retire path: the copy is closed and forgotten
        self.assertNotEqual(workcopy._state(self.settings, target).get("fork_gpr"), old)
        self.assert_on_base(target, "after a retire")

    def test_only_a_rebase_moves_the_view(self):
        target = self.behind()
        workcopy.repair(self.settings, self.runner.engine, target)
        result = self.rebase("h")
        self.assertEqual((result["rebased"], result["from_generation"], result["to_generation"]), (True, 1, 3))
        self.assertEqual(self.names([A, B], "h"), {A: "Gen3", B: "Mine"})
        self.assertEqual(workcopy._state(self.settings, target)["master_revision"], self.revision_of(3))

    def test_a_view_on_generation_zero_is_rebuilt_from_the_adopted_project(self):
        self.edit("Mine", B, view="h")
        self.edit("Gen1", A, view="one")
        self.publish("one")
        target = self.target("h")
        workcopy.repair(self.settings, self.runner.engine, target)
        self.assertEqual(self.names([A, B], "h"), {A: "FUN_140001000", B: "Mine"})
        self.assertEqual(workcopy._state(self.settings, target)["master_revision"], self.revision_of(0))

    def test_a_base_generation_that_was_removed_is_refused_naming_the_rebase(self):
        target = self.behind()
        self.drop_copy(target)
        shutil.rmtree(lineage.generation_dir(self.settings, self.lineage_id(), 1))
        body = self.error(lambda: workcopy.repair(self.settings, self.runner.engine, target))
        self.assertEqual((body["error"], body["base"]["generation"], body["head"]["generation"]), ("base_unavailable", 1, 3))
        self.assertEqual(body["next"]["options"]["kind"], "rebase")
        self.assertEqual(body["next"]["options"]["expect_revision"], self.store("h")["revision"])
        query._keys.clear()
        reply = self.error(lambda: self.runner.query("owned", "decompile", A, options={"view": "h"}))
        self.assertEqual(reply["error"], "base_unavailable", reply)   # never the head's answer
        self.assertEqual(self.rebase("h")["to_generation"], 3)   # the rebase settles it
        self.assertEqual(self.names([A, B], "h"), {A: "Gen3", B: "Mine"})

    # ---- G ----------------------------------------------------------------------------------------------------------

    def test_a_read_of_a_view_behind_the_head_without_a_working_copy_answers_from_its_base(self):
        target = self.behind()
        self.drop_copy(target)
        query._keys.clear()
        reply = json.loads(self.runner.query("owned", "decompile", B, options={"view": "h"}))
        self.assertNotEqual(reply.get("error"), "stale_view", reply)
        self.assertEqual(reply["function"]["name"], "Mine")
        self.assertEqual(reply["stale"], {"base": 1, "head": 3, "behind": 2})
        self.assert_on_base(target, "after a read rebuilt the copy")
        # a mutation is still refused until the view rebases (the query layer first tries a clean rebase of its own)
        self.assertEqual(self.error(lambda: workcopy.refuse_stale(self.store("h"), target, "type_edit"))["error"], "stale_view")

    def test_a_view_whose_records_are_all_committed_reads_its_base_not_the_head(self):
        self.edit("Gen1", A, view="one")
        self.publish("one")
        self.edit("Mine", B, view="h")
        self.publish("h")              # generation 2: h's record is committed, nothing pending
        self.edit("Gen3", A, view="one")
        self.publish("one")            # generation 3
        store = self.store("h")
        if not workcopy.stale_reason(store, self.target("h")):
            self.skipTest("a view with nothing pending follows the head")
        self.assertEqual(self.names([A, B], "h"), {A: "Gen1", B: "Mine"})


# ---- the real engine (hydra.4) -------------------------------------------------------------------------------------

import test_engine_integration as integration   # noqa: E402
from support import Hydra4Only, hydra4_missing   # noqa: E402

HAVE_ENGINE = bool(integration.ENGINE and integration.CLIENT and integration.BINARY and Path(integration.BINARY).is_file())


@unittest.skipUnless(HAVE_ENGINE, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class RealEngineViewBase(Hydra4Only, unittest.TestCase):
    """The soak's H and G on the real engine: agent h01 holds an edit on generation G1 while p00 publishes two more
    generations on another function. A rebuild of h01's copy (a repair, a lost state file) answers G1's name and h01's own
    edit, with G1's master revision; a read with no copy at all answers the same instead of stale_view."""

    @classmethod
    def setUpClass(cls):
        integration._prepare(cls, integration.BINARY, "view-base", "fixture")
        cls.degraded = hydra4_missing(cls.runner.engine, "the hydra.4 governor and per-agent views")

    @classmethod
    def tearDownClass(cls):
        try:
            viewgov.end_session(timeout_s=60)
        finally:
            integration._release(cls)

    def ask(self, action, address="", who="h01", **options):
        return json.loads(self.runner.query("fixture", action, address, limit=200, timeout_s=300, options={"as": who, **options}))

    def revision(self, who):
        return self.ask("status", who=who)["view_revision"]

    def edit(self, who, address, name):
        answer = self.ask("type_edit", address, who, kind="rename", name=name, source="gate 9.17 H view base test",
                          expect_revision=self.revision(who))
        self.assertTrue(answer.get("ok"), answer)
        return answer

    def publish(self, who):
        sealed = self.ask("type_edit", "", who, kind="publish", expect_revision=self.revision(who), confirm_one_way_upgrade=True)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            changeset = self.ask("status", "", who, show="queue", csid=sealed["csid"]).get("changeset") or {}
            if changeset.get("state") in ("done", "unknown"):
                self.assertIn(changeset.get("outcome"), ("applied", "rebased"), changeset)
                return changeset
            time.sleep(0.5)
        self.fail("publish %s not decided in 600 s" % sealed["csid"])

    def name(self, address, who="h01"):
        query._keys.clear()
        reply = self.ask("decompile", address, who)
        self.assertNotIn("error", reply, reply)
        return reply["function"]["name"]

    def test_a_view_behind_the_head_is_rebuilt_and_read_from_its_own_base_generation(self):
        functions = [row["address"] for row in self.ask("functions", who="reader")["functions"]]
        self.assertGreaterEqual(len(functions), 2)
        a, b = functions[0], functions[1]
        self.edit("p00", a, "h917_gen_a")
        self.publish("p00")
        base = self.runner.target("fixture")["lineage"]
        self.edit("h01", b, "h917_mine")
        self.assertEqual((self.name(a), self.name(b)), ("h917_gen_a", "h917_mine"))
        for step in ("b", "c"):
            self.edit("p00", a, "h917_gen_" + step)
            self.publish("p00")
        head = self.runner.target("fixture")["lineage"]
        self.assertEqual(head["generation"], base["generation"] + 2)
        self.assertEqual(self.name(a, "reader"), "h917_gen_c", "the head")
        target = workcopy.with_view(self.runner.target("fixture"), "h01")
        self.assertEqual(workcopy.load_store(self.settings, target)["base"]["generation"], base["generation"])
        gpr = [row for row in lineage.history(self.settings, base["id"]) if row["gen"] == base["generation"]][-1]["gpr"]
        engine = hydra.Engine(self.settings)
        expected_revision = engine.call("open_project", path=gpr)["revision"]

        def check(note):
            self.assertEqual((self.name(a), self.name(b)), ("h917_gen_a", "h917_mine"), note)
            state = workcopy._state(self.settings, target)
            self.assertEqual(state["master_revision"], expected_revision, note)
            self.assertEqual(state["base"]["generation"], base["generation"], note)

        # H: a rebuild after the daemon lost the replay, then after a lost state file (K15)
        workcopy.repair(self.settings, self.runner.engine, target)
        check("after a repair")
        (workcopy._directory(self.settings, target) / "state.json").unlink()
        check("after K15")
        # G: no working copy at all; a read answers from the base generation, never stale_view
        with workcopy.view_lock(self.settings, target):
            workcopy.retire_copies(self.settings, target)
        (workcopy._directory(self.settings, target) / "state.json").unlink(missing_ok=True)
        check("after a read without a working copy")
        # only the rebase moves it
        rebased = self.ask("type_edit", "", "h01", kind="rebase", expect_revision=self.revision("h01"))
        self.assertTrue(rebased.get("rebased"), rebased)
        self.assertEqual((self.name(a), self.name(b)), ("h917_gen_c", "h917_mine"))


if __name__ == "__main__":
    unittest.main()
