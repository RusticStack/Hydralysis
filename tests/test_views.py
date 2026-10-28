"""Rebase, publish and merge between views, and the publish queue (PROTOCOL-3.md 4.7, 4.8, 4.10, D45), on the fake daemon.

The queue is tested above the primitive (the OS lock and the CRC log were validated on their own): leader election,
the FIFO drain, the verification of a candidate before it can be head, exactly-once through the manifest's ids, the
rebase outcomes (applied, rebased, converged, conflict, skipped), a storm of 24 publishers (threads, and processes
that are killed), the K16 model fold, and that no reader or view waits for the leader (K13).

Real-engine rows are not here: the fake models forks, saves, effects, `verify_before` and the sealed predicate only.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import fakehydra
from hydralysis import commits, durable, hydra, lineage, locks, query, targets, views, workcopy
from support import workdir
from test_commit import A, B, C, World

ENV_FAULT = ("HYDRALYSIS_TEST_MODE", "HYDRALYSIS_TEST_FAULT")


def address(index: int) -> str:
    return hex(0x140010000 + index * 0x100)


class ViewWorld(World):
    """World (a target on the fake daemon with a lineage-capable root) plus publish helpers."""

    def engine(self):
        return fakehydra.FakeEngine(self.settings)

    def seal(self, view="", **options):
        body = {"kind": "publish", "confirm_one_way_upgrade": True, "expect_revision": self.store(view)["revision"], **options}
        return views.seal_changeset(self.settings, self.target(view), body)

    def run_job(self, sealed, view=""):
        return views.run_publish_job(self.settings, self.target(view), {"csid": sealed["csid"], "lineage": sealed["lineage"]},
                                     self.engine(), 120)

    def publish(self, view="", **options):
        """Seal and wait for the result, like the publish job does."""
        return self.run_job(self.seal(view, **options), view)

    def _drain_for(self, csid):
        views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=csid)
        return views.read_done(self.settings, self.lineage_id(), csid)

    def settle(self, view=""):
        return workcopy.heal(self.settings, self.target(view))

    def done(self, csid):
        return views.read_done(self.settings, self.lineage_id(), csid)

    def rebase(self, view="", **options):
        body = {"kind": "rebase", "expect_revision": self.store(view)["revision"], **options}
        return views.rebase(self.settings, self.engine(), self.target(view), body)

    def merge(self, source, destination, **options):
        body = {"kind": "merge", "from": source, "expect_revision": self.store(destination)["revision"], **options}
        return views.merge(self.settings, self.engine(), self.target(source), self.target(destination), views.validate(body))

    def names(self, addresses, view=""):
        return {item: self.name_of(item, view=view) for item in addresses}

    def manifest(self, generation):
        return lineage.read_manifest(lineage.generation_dir(self.settings, self.lineage_id(), generation))

    def rows(self):
        return lineage.history(self.settings, self.lineage_id())

    def error(self, call):
        with self.assertRaises(RuntimeError) as raised:
            call()
        return json.loads(str(raised.exception))


class Publish(ViewWorld, unittest.TestCase):
    def test_a_publish_makes_one_generation_that_the_manifest_and_the_log_name(self):
        record = self.edit("Mine", A, view="one")["overlay_id"]
        sealed = self.seal("one")
        self.assertEqual((sealed["state"], sealed["position"]), ("publish_pending", 1))
        self.assertTrue(sealed["csid"].startswith("c-"))
        result = self.run_job(sealed, "one")
        self.assertEqual((result["outcome"], result["generation"]), ("applied", 1))
        row = self.rows()[-1]
        self.assertEqual(([item["csid"] for item in row["changesets"]], row["via"], row["reason"]), ([sealed["csid"]], "publish", "commit"))
        manifest = self.manifest(1)
        self.assertEqual((manifest["store"]["ids"], manifest["changesets"], manifest["store"]["by_changeset"][sealed["csid"]]["ids"]),
                         ([record], [sealed["csid"]], [record]))
        self.assertTrue(lineage.verify_head(self.settings, self.lineage_id())["ok"])
        self.assertEqual(self.name_of(A), "Mine")  # the master (shared view, no edits) now answers with it
        self.assertEqual(self.done(sealed["csid"])["generation"], 1)

    def test_the_publishing_view_is_finalized_in_one_store_write(self):
        record = self.edit("Mine", A, view="one")["overlay_id"]
        sealed = self.seal("one")
        self.run_job(sealed, "one")
        store = self.store("one")
        self.assertEqual([(entry["cid"], entry["ids"], entry["generation"]) for entry in store["commits"]], [(sealed["csid"], [record], 1)])
        self.assertEqual((store["base"]["generation"], self.pending_ids("one")), (1, []))
        self.assertEqual([item["csid"] for item in store["changesets"]], [sealed["csid"]])
        self.assertEqual(self.name_of(A, view="one"), "Mine")
        self.assertIsNone(workcopy.stale_reason(store, self.target("one")))

    def test_the_same_pending_records_sealed_twice_are_one_changeset(self):
        self.edit("Mine", A, view="one")
        first, second = self.seal("one"), self.seal("one")
        self.assertEqual((first["csid"], second["reused"]), (second["csid"], True))
        self.assertEqual(len(views.outstanding(self.settings, self.lineage_id())), 1)

    def test_a_publish_needs_the_confirmation_the_revision_and_records(self):
        self.edit("Mine", A, view="one")
        with self.assertRaises(commits.CommitError) as raised:
            views.seal_changeset(self.settings, self.target("one"), {"kind": "publish", "expect_revision": 1})
        self.assertEqual(raised.exception.code, "confirmation_required")
        with self.assertRaises(commits.CommitError) as raised:
            self.seal("one", expect_revision=0)
        self.assertEqual(raised.exception.code, "revision_changed")
        with self.assertRaises(ValueError):
            views.validate({"kind": "publish", "confirm_one_way_upgrade": True})
        with self.assertRaises(ValueError):
            views.validate({"kind": "publish", "expect_revision": 1, "surprise": 1})
        with self.assertRaises(commits.CommitError) as raised:
            self.seal("two", expect_revision=0)  # a view with no records
        self.assertEqual(raised.exception.code, "nothing_to_commit")

    def test_records_added_while_a_changeset_waits_stay_pending(self):
        first = self.edit("First", A, view="one")["overlay_id"]
        sealed = self.seal("one")
        later = self.edit("Later", B, view="one")["overlay_id"]
        self.run_job(sealed, "one")
        self.assertEqual(self.pending_ids("one"), [later])
        self.assertEqual(self.manifest(1)["store"]["ids"], [first])

    def test_two_views_on_different_subjects_publish_one_after_the_other_and_the_second_is_rebased(self):
        self.edit("FromOne", A, view="one")
        self.edit("FromTwo", B, view="two")
        sealed_one, sealed_two = self.seal("one"), self.seal("two")
        self.assertLess(sealed_one["csid"], sealed_two["csid"])
        self.assertEqual(self.run_job(sealed_one, "one")["outcome"], "applied")
        result = self.run_job(sealed_two, "two")
        self.assertEqual((result["outcome"], result["generation"], result["base_generation"]), ("rebased", 2, 1))
        self.assertEqual(self.names([A, B]), {A: "FromOne", B: "FromTwo"})
        self.assertEqual([row["gen"] for row in self.rows()], [0, 1, 2])
        self.assertEqual(self.store("two")["base"]["generation"], 2)

    def test_a_conflict_publishes_nothing_names_the_editor_and_keeps_the_records_pending(self):
        self.edit("Theirs", A, view="one")
        record = self.edit("Mine", A, view="two")["overlay_id"]
        self.publish("one")
        sealed = self.seal("two")
        with self.assertRaises(views.ViewError) as raised:
            self.run_job(sealed, "two")
        body = raised.exception.payload()
        self.assertEqual(body["error"], "publish_conflict")
        conflict = body["conflicts"][0]
        self.assertEqual((conflict["subject"], conflict["field"], conflict["theirs"], conflict["mine"]),
                         ("address:" + A, "name", "Theirs", "Mine"))
        self.assertEqual([item["generation"] for item in conflict["editors"]], [1])
        self.assertEqual(conflict["editors"][0]["views"], ["one"])
        self.assertEqual(self.head()["gen"], 1)  # no generation was made
        self.assertEqual(self.pending_ids("two"), [record])  # never dropped
        self.assertEqual(self.done(sealed["csid"])["outcome"], "conflict")
        self.assertEqual(self.name_of(A), "Theirs")

    def test_values_the_master_already_holds_converge_and_the_records_leave_the_view(self):
        self.edit("Same", A, view="one")
        record = self.edit("Same", A, view="two")["overlay_id"]
        self.publish("one")
        result = self.publish("two")
        self.assertEqual((result["outcome"], result["generation"], result["converged"]), ("converged", None, [record]))
        self.assertEqual(self.head()["gen"], 1)  # no generation for a value that was already there
        self.assertEqual(self.pending_ids("two"), [])
        self.assertEqual(self.store("two")["reverted"][-1]["reason"], "published:already_in_master")

    def test_a_changeset_whose_records_are_in_the_master_is_skipped_not_applied_twice(self):
        self.edit("Once", A, view="one")
        sealed = self.seal("one")
        copy = dict(views.read_changeset(self.settings, self.lineage_id(), sealed["csid"]))
        self.run_job(sealed, "one")
        # the same records sealed again by a stale copy of the view (a restored backup, a retry from another process)
        copy["csid"] = views.new_csid()
        durable.write_sealed(views.pending_path(self.settings, self.lineage_id(), copy["csid"]), copy)
        result = views.outcome_of(views.read_done(self.settings, self.lineage_id(), copy["csid"]) or self._drain_for(copy["csid"]))
        self.assertEqual(result["outcome"], "skipped")
        self.assertEqual(list(result["record_outcomes"].values()), ["skipped"])
        self.assertEqual([row["gen"] for row in self.rows()], [0, 1])  # no second generation
        self.assertEqual(self.manifest(1)["store"]["ids"], copy["ids"])

    def test_a_record_published_from_another_view_matches_by_merged_from(self):
        record = self.edit("Shared", A, view="one")["overlay_id"]
        self.assertEqual(self.merge("one", "two")["merged"], 1)
        self.publish("two")
        self.assertIn(record, self.manifest(1)["store"]["merged_from_ids"])
        # the first view still holds its record; publishing it again is "already in the master", not a second application
        result = self.publish("one")
        self.assertEqual((result["outcome"], result["generation"]), ("skipped", None))
        self.assertEqual([row["gen"] for row in self.rows()], [0, 1])

    def test_a_pending_view_edit_after_the_publish_sees_the_new_generation_as_its_base(self):
        self.edit("One", A, view="one")
        self.publish("one")
        self.assertEqual(self.edit("More", B, view="one")["revision"], 3)  # edit after a publish: the view is not stale
        self.assertEqual(self.name_of(A, view="one"), "One")
        self.assertEqual(self.name_of(B, view="one"), "More")

    def test_a_publish_is_refused_by_a_damaged_log_and_by_a_tampered_generation(self):
        self.edit("One", A, view="one")
        self.publish("one")
        folder = lineage.generation_dir(self.settings, self.lineage_id(), 1)
        (next(folder.glob("*.gpr"))).write_text("someone wrote here", encoding="utf-8")
        self.edit("Two", B, view="two")
        sealed = self.seal("two")
        led = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        self.assertEqual(led["failure"]["error"], "tampered")
        self.assertIsNone(self.done(sealed["csid"]))  # still queued: nothing was decided
        self.assertEqual(self.pending_ids("two") != [], True)


class Queue(ViewWorld, unittest.TestCase):
    def test_the_queue_is_first_in_first_out_and_position_and_eta_are_reported(self):
        for index in range(3):
            self.edit("Name%d" % index, address(index), view="v%d" % index)
        sealed = [self.seal("v%d" % index) for index in range(3)]
        self.assertEqual([item["position"] for item in sealed], [1, 2, 3])
        self.assertIsNone(sealed[2]["etaMs"])  # nothing was measured yet: no figure is stated
        status = json.loads(self.runner.query("owned", "status", options={"show": "queue", "view": "v2"}))
        self.assertEqual([item["csid"] for item in status["queue"]["changesets"]], [item["csid"] for item in sealed])
        self.assertEqual(status["queue"]["leader"], False)
        # the last in line leads, and drains the two before it first (they are decided in id order)
        self.run_job(sealed[2], "v2")
        generations = [self.done(item["csid"])["generation"] for item in sealed]
        self.assertEqual(generations, [1, 2, 3])
        self.assertEqual(views.outstanding(self.settings, self.lineage_id()), [])
        info = views.pending_info(self.settings, self.lineage_id(), sealed[0]["csid"])
        self.assertEqual((info["state"], info["outcome"]), ("done", "applied"))
        self.assertIsNotNone(views._eta_ms(self.settings, self.lineage_id(), 2))  # measured now

    def test_a_follower_does_not_become_a_second_leader(self):
        self.edit("One", A, view="one")
        sealed = self.seal("one")
        lock = locks.LaneLock(str(views.publish_lock_path(self.settings, self.lineage_id())))
        self.assertTrue(lock.acquire())
        try:
            self.assertEqual(views.drain(self.settings, self.lineage_id(), self.engine())["led"], False)
            self.assertEqual(views.pending_info(self.settings, self.lineage_id(), sealed["csid"])["leader"], True)
        finally:
            lock.release()
        self.assertEqual(views.drain(self.settings, self.lineage_id(), self.engine())["built"], [1])

    def test_a_job_that_waits_leads_when_the_lock_is_free(self):
        self.edit("One", A, view="one")
        sealed = self.seal("one")
        lock = locks.LaneLock(str(views.publish_lock_path(self.settings, self.lineage_id())))
        self.assertTrue(lock.acquire())
        seen = []
        timer = threading.Timer(0.5, lock.release)
        timer.start()
        result = views.run_publish_job(self.settings, self.target("one"), {"csid": sealed["csid"], "lineage": sealed["lineage"]},
                                       self.engine(), 120, progress=seen.append)
        timer.join()
        self.assertEqual(result["outcome"], "applied")
        self.assertTrue(seen and seen[0]["state"] == "publish_pending" and seen[0]["position"] == 1)

    def test_the_leader_and_a_commit_take_turns(self):
        self.edit("One", A, view="one")
        sealed = self.seal("one")
        held = locks.LaneLock(str(lineage.commit_lock_path(self.settings, self.lineage_id())))
        self.assertTrue(held.acquire())
        with patch.object(views, "COMMIT_WAIT_S", 0.2):
            led = views.drain(self.settings, self.lineage_id(), self.engine())
        held.release()
        self.assertEqual(led["failure"]["error"], "commit_busy")
        self.assertEqual(views.outstanding(self.settings, self.lineage_id()), [sealed["csid"]])  # nothing lost, nothing counted
        self.assertFalse(views.failure_path(self.settings, self.lineage_id(), sealed["csid"]).exists())
        self.assertEqual(self.run_job(sealed, "one")["generation"], 1)

    def test_a_corrupt_changeset_does_not_hold_the_queue(self):
        self.edit("One", A, view="one")
        self.edit("Two", B, view="two")
        bad, good = self.seal("one"), self.seal("two")
        path = views.pending_path(self.settings, self.lineage_id(), bad["csid"])
        path.write_bytes(b"{ not json")
        views.pending_path(self.settings, self.lineage_id(), bad["csid"]).with_name(path.name + ".bak").unlink(missing_ok=True)
        result = self.run_job(good, "two")
        self.assertEqual(result["generation"], 1)
        self.assertEqual(self.done(bad["csid"])["outcome"], "corrupt_changeset")
        self.assertEqual(self.pending_ids("one") != [], True)  # its records are pending still


class Batch(ViewWorld, unittest.TestCase):
    """`publish_batch_max` above 1 (off by default, D45): several changesets in one generation, each decided on its own."""

    def test_a_batch_makes_one_generation_for_several_changesets_and_rejects_the_conflicting_one_alone(self):
        self.settings["publish_batch_max"] = 3
        self.edit("First", A, view="one")
        self.edit("Second", B, view="two")
        self.edit("Clash", A, view="three")  # the same subject as `one`, sealed after it: it loses, the others do not
        sealed = [self.seal(view) for view in ("one", "three", "two")]
        led = views.drain(self.settings, self.lineage_id(), self.engine())
        self.assertEqual((led["built"], led["failure"]), ([1], None))
        row = self.rows()[-1]
        self.assertEqual([item["csid"] for item in row["changesets"]], [sealed[0]["csid"], sealed[2]["csid"]])
        self.assertEqual(self.done(sealed[1]["csid"])["outcome"], "conflict")
        self.assertEqual([self.done(item["csid"])["generation"] for item in sealed], [1, None, 1])
        self.assertEqual(sorted(self.manifest(1)["store"]["by_changeset"]), sorted([sealed[0]["csid"], sealed[2]["csid"]]))
        self.assertEqual(self.names([A, B]), {A: "First", B: "Second"})
        self.settle("one")
        self.settle("two")
        self.assertEqual((self.pending_ids("one"), self.pending_ids("two")), ([], []))
        self.assertEqual(self.pending_ids("three") != [], True)  # the loser's record is pending still
        self.assertEqual([row["gen"] for row in self.rows()], [0, 1])

    def test_a_later_changeset_in_a_batch_is_checked_against_the_one_before_it(self):
        self.settings["publish_batch_max"] = 2
        self.edit("Early", A, view="one")
        self.edit("Late", A, view="two")
        sealed = [self.seal("one"), self.seal("two")]
        views.drain(self.settings, self.lineage_id(), self.engine())
        # `two` rests on the original value, which `one` changes inside the same batch: a conflict, not a lost update
        self.assertEqual((self.done(sealed[0]["csid"])["outcome"], self.done(sealed[1]["csid"])["outcome"]), ("applied", "conflict"))
        self.assertEqual(self.name_of(A), "Early")
        conflict = self.done(sealed[1]["csid"])["conflicts"][0]
        self.assertEqual((conflict["reason"], conflict["theirs"]), ("chain", "Early"))


class VerifyBeforeHead(ViewWorld, unittest.TestCase):
    def test_a_candidate_is_sealed_and_verified_before_the_log_line_is_appended(self):
        self.edit("One", A, view="one")
        order = []
        verify, append = views._verify_candidate, views._append_line

        def checking_verify(*args, **kwargs):
            order.append("verify")
            return verify(*args, **kwargs)

        def checking_append(settings, lineage_id, line):
            folder = lineage.project_folder_of(line["gpr"])
            order.append(("append", (folder / lineage.SEAL_MARKER).is_file(), lineage.verify_manifest(folder)["ok"],
                          json.loads(next(folder.glob("*.fork.json")).read_text(encoding="utf-8")).get("state")))
            return append(settings, lineage_id, line)
        with patch.object(views, "_verify_candidate", checking_verify), patch.object(views, "_append_line", checking_append):
            self.publish("one")
        self.assertEqual(order, ["verify", ("append", True, True, "complete")])

    def test_a_candidate_that_fails_verification_is_never_head_and_the_records_stay_pending(self):
        record = self.edit("One", A, view="one")["overlay_id"]
        sealed = self.seal("one")
        before = self.tree_snapshot()

        def refuse(*args, **kwargs):
            raise views.PublishFailure("candidate_failed", "planted: the decompile lacks the name", counted=True, csid=sealed["csid"])
        with patch.object(views, "_verify_candidate", refuse):
            led = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
            self.assertEqual(led["failure"]["error"], "candidate_failed")
            self.assertEqual(self.head()["gen"], 0)
            self.assertIsNone(self.done(sealed["csid"]))  # attempt 1 of 3: the changeset stays queued
            views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
            views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        result = self.done(sealed["csid"])
        self.assertEqual((result["outcome"], result["attempts"]), ("candidate_failed", 3))
        with self.assertRaises(views.ViewError) as raised:
            views.outcome_of(result)
        self.assertEqual(raised.exception.code, "candidate_failed")
        self.assertEqual(self.head()["gen"], 0)
        self.assertEqual(self.pending_ids("one"), [record])
        self.assertEqual(self.tree_snapshot(), before)
        # the failed candidates are left in place, unregistered, for manual removal (D28): the last one at its number, the
        # earlier ones moved aside when their number was taken again
        folders = sorted(path.name for path in (lineage.lineage_dir(self.settings, self.lineage_id()) / "gen").iterdir())
        self.assertEqual((len(folders), sum(".abandoned-" in name for name in folders)), (3, 2))
        self.assertEqual([row["gen"] for row in self.rows()], [0])
        # a later publish of the same view is a new changeset and succeeds; the log stays consecutive
        again = self.publish("one")
        self.assertEqual(again["generation"], 1)
        self.assertEqual([row["gen"] for row in self.rows()], [0, 1])
        self.assertEqual(len(list((lineage.lineage_dir(self.settings, self.lineage_id()) / "gen").iterdir())), 4)

    def test_a_decompile_that_lacks_the_applied_name_fails_verification(self):
        self.edit("One", A, view="one")
        sealed = self.seal("one")
        with patch.object(commits, "_decompile", return_value='{"function":{"name":"FUN_other"}}'):
            led = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        self.assertEqual(led["failure"]["error"], "candidate_failed")
        self.assertIn("current name", led["failure"]["message"])
        self.assertEqual(self.head()["gen"], 0)

    def test_an_engine_that_is_away_costs_the_changeset_nothing(self):
        self.edit("One", A, view="one")
        sealed = self.seal("one")
        self.daemon.fail_next["save"] = hydra.EngineError("closed", "the connection ended")
        led = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        self.assertEqual((led["failure"]["error"], led["failure"]["counted"]), ("engine_refused", False))
        self.assertFalse(views.failure_path(self.settings, self.lineage_id(), sealed["csid"]).exists())
        self.assertEqual(self.run_job(sealed, "one")["outcome"], "applied")

    def test_a_replay_the_engine_refuses_is_counted_and_nothing_is_published(self):
        self.edit("One", A, view="one")
        sealed = self.seal("one")
        path = views.pending_path(self.settings, self.lineage_id(), sealed["csid"])
        record = durable.read_sealed(path)
        record["records"][0]["options"]["name"] = "FAIL"  # the fake refuses this record
        durable.write_sealed(path, record)
        led = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        self.assertEqual((led["failure"]["error"], led["failure"]["counted"]), ("candidate_failed", True))
        self.assertEqual(self.head()["gen"], 0)


class Recovery(ViewWorld, unittest.TestCase):
    """A leader killed at each point of the publish leaves the old state or the new one, and the next leader ends with the
    changeset applied exactly once. The kill is a FaultInjected raise at the same fault point `exit` ends a process at."""

    POINTS = ["after_lock", "after_backup", "after_fork", "mid_apply", "after_save", "after_force", "after_manifest", "after_verify",
              "after_seal", "before_append", "after_append", "after_done"]

    def killed_publish(self, point):
        self.edit("Mine", A, view="one")
        sealed = self.seal("one")
        with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "publish." + point + ":raise"}):
            with self.assertRaises(durable.FaultInjected):
                views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        return sealed

    def check_kill_point(self, point):
        before_tree = lineage.tree_hash(self.gpr.parent)
        sealed = self.killed_publish(point)
        published = point in ("after_append", "after_done")
        self.assertEqual(self.head()["gen"], 1 if published else 0, point)
        self.assertEqual(lineage.tree_hash(self.gpr.parent), before_tree, "O1 " + point)
        # the next leader (any process) reaches the same end whatever the first one did
        self.assertEqual(views.outcome_of(self._drain_for(sealed["csid"]))["outcome"], "applied")
        rows = [row for row in self.rows() if row.get("changesets")]
        self.assertEqual(len(rows), 1, point)
        self.assertEqual([item["csid"] for item in rows[0]["changesets"]], [sealed["csid"]])
        self.assertEqual(self.name_of(A), "Mine")
        self.assertTrue(lineage.verify_head(self.settings, self.lineage_id())["ok"], point)
        # the view settles, once, whichever process wrote the log line
        self.settle("one")
        self.assertEqual(len(self.store("one")["commits"]), 1, point)
        self.assertEqual(self.pending_ids("one"), [], point)
        self.assertEqual(self.store("one")["commits"][0]["ids"], self.manifest(rows[0]["gen"])["store"]["ids"], point)

    def test_a_torn_log_line_is_repaired_and_the_changeset_is_published_by_the_next_leader(self):
        self.edit("Mine", A, view="one")
        sealed = self.seal("one")
        with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "publish.append_torn:torn:30"}):
            with patch.object(durable, "_die", side_effect=durable.FaultInjected("died")):
                with self.assertRaises(durable.FaultInjected):
                    views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        self.assertEqual(self.head()["gen"], 0)  # a reader sees the old head: the tail is torn
        self.assertIsNotNone(self.head()["torn_tail"])
        result = views.outcome_of(self._drain_for(sealed["csid"]))
        # the log stays consecutive (K12): the abandoned candidate, which was never head, is moved aside and its number is used
        self.assertEqual(result["generation"], 1)
        self.assertEqual([row["gen"] for row in self.rows()], [0, 1])
        gen = lineage.lineage_dir(self.settings, self.lineage_id()) / "gen"
        self.assertEqual(sorted(path.name[:4] for path in gen.iterdir() if ".abandoned-" in path.name), ["0001"])
        self.assertTrue(lineage.current_log(self.settings, self.lineage_id()).repairs())

    def test_a_published_generation_that_no_longer_verifies_is_rolled_back_and_the_changeset_stays_queued(self):
        sealed = self.killed_publish("after_append")
        folder = lineage.generation_dir(self.settings, self.lineage_id(), 1)
        next(folder.glob("*.gpr")).write_text("damaged after the append", encoding="utf-8")
        led = views.drain(self.settings, self.lineage_id(), self.engine())
        self.assertEqual(self.head()["gen"], 0)  # the rollback line returned the head to generation 0
        self.assertEqual(self.rows()[-1]["reason"], "rollback")
        self.assertEqual(led["led"], True)


for _point in Recovery.POINTS:
    setattr(Recovery, "test_a_kill_at_%s_ends_with_the_changeset_applied_exactly_once" % _point,
            (lambda point: lambda self: self.check_kill_point(point))(_point))


class Rebase(ViewWorld, unittest.TestCase):
    def stale_view(self):
        """View `two` holds a record on generation 0; view `one` publishes generation 1 meanwhile."""
        self.edit("FromOne", A, view="one")
        record = self.edit("FromTwo", B, view="two")["overlay_id"]
        self.publish("one")
        return record

    def test_a_view_is_stale_after_a_publish_refuses_edits_with_next_and_the_editors_and_keeps_answering(self):
        self.stale_view()
        self.assertEqual(self.name_of(B, view="two"), "FromTwo")  # reads keep answering from its working copy
        body = self.error(lambda: self.edit("More", C, view="two"))
        self.assertEqual((body["error"], body["stale"]), ("stale_view", "master_generation_changed"))
        self.assertEqual(body["next"]["options"]["kind"], "rebase")
        self.assertEqual(body["next"]["options"]["expect_revision"], self.store("two")["revision"])
        self.assertEqual([(item["generation"], item["views"]) for item in body["editors"]], [(1, ["one"])])
        self.assertEqual(body["head"]["generation"], 1)

    def test_a_clean_rebase_keeps_the_record_and_moves_the_base(self):
        record = self.stale_view()
        result = self.rebase("two")
        self.assertEqual((result["rebased"], result["outcome"], result["kept"], result["verified"]), (True, "clean", [record], True))
        self.assertEqual((result["from_generation"], result["to_generation"]), (0, 1))
        self.assertEqual(self.store("two")["base"]["generation"], 1)
        self.assertEqual(self.names([A, B], "two"), {A: "FromOne", B: "FromTwo"})  # the new base plus the replayed record
        self.assertEqual(self.edit("Again", C, view="two")["revision"], 3)  # not stale any more (the rebase was revision 2)
        self.assertEqual(self.rebase("two")["outcome"], "up_to_date")

    def test_a_rebased_view_publishes_as_applied(self):
        self.stale_view()
        self.rebase("two")
        self.assertEqual(self.publish("two")["outcome"], "applied")

    def test_the_value_the_master_already_holds_converges(self):
        self.edit("Same", A, view="one")
        record = self.edit("Same", A, view="two")["overlay_id"]
        self.publish("one")
        result = self.rebase("two")
        self.assertEqual((result["converged"], result["kept"]), ([record], []))
        self.assertEqual(self.pending_ids("two"), [])
        self.assertEqual(self.store("two")["base"]["generation"], 1)

    def test_a_record_the_master_holds_by_id_or_by_merged_from_is_dropped(self):
        by_merge = self.edit("Merged", A, view="one")["overlay_id"]
        self.merge("one", "carrier")
        self.edit("Plain", B, view="plain")
        plain = self.pending_ids("plain")
        self.publish("carrier")
        # a stale copy of view `plain`'s store whose records the master holds by id (a restored backup)
        self.publish("plain")
        copy = self.target("copy")
        old = workcopy.load_store(self.settings, self.target("plain"))
        stale = {**workcopy._empty_store(self.digest), "revision": 1, "edits": old["edits"] + [], "base": {"lineage": "", "generation": 0}}
        stale["commits"] = []
        workcopy._save_store(self.settings, copy, stale)
        self.assertIsNotNone(workcopy.stale_reason(self.store("copy"), self.target("copy")))
        result = self.rebase("copy")
        self.assertEqual(sorted(result["dropped_in_master"]), sorted(plain))
        result = self.rebase("one")
        self.assertEqual((result["dropped_in_master"], result["kept"]), ([by_merge], []))
        self.assertEqual(self.pending_ids("one"), [])

    def test_a_conflict_changes_nothing_and_lists_what_the_master_holds(self):
        self.edit("Theirs", A, view="one")
        record = self.edit("Mine", A, view="two")["overlay_id"]
        self.publish("one")
        before = self.store("two")
        result = self.rebase("two")
        self.assertEqual((result["ok"], result["rebased"], result["outcome"]), (False, False, "conflict"))
        conflict = result["conflicts"][0]
        self.assertEqual((conflict["id"], conflict["subject"], conflict["field"], conflict["master_now"], conflict["after"], conflict["before"]),
                         (record, "address:" + A, "name", "Theirs", "Mine", "FUN_" + A.removeprefix("0x")))
        self.assertEqual(conflict["editors"][0]["generation"], 1)
        after = self.store("two")
        self.assertEqual((after["revision"], after["base"], after["edits"]), (before["revision"], before["base"], before["edits"]))  # untouched
        self.assertEqual(self.name_of(A, view="two"), "Mine")  # and the view still answers from its own copy

    def test_resolve_take_mine_keeps_the_record_re_anchored_to_the_master_value(self):
        self.edit("Theirs", A, view="one")
        record = self.edit("Mine", A, view="two")["overlay_id"]
        self.publish("one")
        result = self.rebase("two", resolve={"address:" + A: "take_mine"})
        self.assertEqual((result["outcome"], result["kept"], result["reanchored"]), ("resolved", [record], [record]))
        self.assertEqual(self.store("two")["edits"][0]["effects"][0]["before"], "Theirs")
        self.assertEqual(self.name_of(A, view="two"), "Mine")
        self.assertEqual(self.publish("two")["outcome"], "applied")  # it now rests on the master's value
        self.assertEqual(self.name_of(A), "Mine")

    def test_resolve_keep_drops_the_record_and_the_records_that_rest_on_it(self):
        self.edit("Theirs", A, view="one")
        first = self.edit("Mine", A, view="two")["overlay_id"]
        second = self.edit("MineAgain", A, view="two")["overlay_id"]
        other = self.edit("Unrelated", B, view="two")["overlay_id"]
        self.publish("one")
        result = self.rebase("two", resolve={"address:" + A: "keep"})
        self.assertEqual((sorted(result["dropped_keep"]), result["kept"]), (sorted([first, second]), [other]))
        self.assertEqual(self.pending_ids("two"), [other])
        self.assertEqual(self.names([A, B], "two"), {A: "Theirs", B: "Unrelated"})

    def test_a_rebase_whose_copy_fails_verification_changes_nothing(self):
        self.stale_view()
        before = self.store("two")
        with patch.object(views, "_build_rebased_copy", side_effect=views.ViewError("rebase_verify_failed", "planted")):
            with self.assertRaises(views.ViewError):
                self.rebase("two")
        self.assertEqual(self.store("two")["base"], before["base"])
        self.assertEqual(self.name_of(B, view="two"), "FromTwo")  # the old working copy still serves reads

    def test_a_kill_after_the_store_write_is_healed_by_the_next_read(self):
        self.stale_view()
        with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "publish.after_rebase_store:raise"}):
            with self.assertRaises(durable.FaultInjected):
                self.rebase("two")
        self.assertEqual(self.store("two")["base"]["generation"], 1)
        self.assertEqual(self.names([A, B], "two"), {A: "FromOne", B: "FromTwo"})  # the copy is rebuilt from the base and the store

    def test_the_expected_revision_must_match(self):
        self.stale_view()
        body = self.error(lambda: self.rebase("two", expect_revision=0))
        self.assertIn("conflict", body)

    def test_a_view_with_no_lineage_has_nothing_to_rebase(self):
        self.edit("Mine", A, view="one")
        self.assertEqual(self.rebase("one")["outcome"], "up_to_date")


class Merge(ViewWorld, unittest.TestCase):
    def test_records_move_to_the_destination_with_new_ids_and_merged_from(self):
        first = self.edit("One", A, view="src")
        second = self.edit("Two", B, view="src")
        result = self.merge("src", "dst")
        self.assertEqual((result["outcome"], result["merged"]), ("merged", 2))
        records = self.store("dst")["edits"]
        self.assertEqual([item["merged_from"] for item in records],
                         [{"view": "src", "id": first["overlay_id"], "seq": 1}, {"view": "src", "id": second["overlay_id"], "seq": 2}])
        self.assertTrue(set(result["ids"]).isdisjoint({first["overlay_id"], second["overlay_id"]}))
        self.assertEqual([item["effects"][0]["after"] for item in records], ["One", "Two"])
        self.assertEqual(self.names([A, B], "dst"), {A: "One", B: "Two"})
        self.assertEqual(self.store("src")["published_through"], {"dst": 2})
        self.assertEqual(self.store("dst")["revision"], 2)

    def test_a_second_merge_is_idempotent_and_the_next_one_takes_only_what_is_new(self):
        self.edit("One", A, view="src")
        self.merge("src", "dst")
        self.assertEqual(self.merge("src", "dst")["merged"], 0)
        self.edit("Two", B, view="src")
        self.assertEqual(self.merge("src", "dst")["merged"], 1)
        self.assertEqual(len(self.store("dst")["edits"]), 2)

    def test_a_publish_to_a_view_is_the_same_merge_in_the_other_direction(self):
        self.edit("One", A, view="src")
        body = {"kind": "publish", "to": "dst", "expect_revision": 0}
        result = views.merge(self.settings, self.engine(), self.target("src"), self.target("dst"), views.validate(body))
        self.assertEqual(result["merged"], 1)

    def test_a_conflict_is_returned_with_theirs_and_mine_and_nothing_is_merged(self):
        self.edit("Source", A, view="src")
        self.edit("Destination", A, view="dst")
        before = self.store("dst")
        result = self.merge("src", "dst")
        self.assertEqual((result["ok"], result["outcome"], result["merged"]), (False, "conflict", 0))
        conflict = result["conflicts"][0]
        self.assertEqual((conflict["subject"], conflict["theirs"], conflict["mine"]), ("address:" + A, "Destination", "Source"))
        self.assertEqual(self.store("dst")["edits"], before["edits"])
        self.assertEqual(self.store("src")["published_through"], {})

    def test_resolve_take_mine_applies_over_the_destination_and_keep_leaves_it(self):
        self.edit("Source", A, view="src")
        self.edit("Destination", A, view="dst")
        kept = self.merge("src", "dst", resolve={"address:" + A: "keep"})
        self.assertEqual((kept["merged"], kept["kept_destination"] != []), (0, True))
        self.assertEqual(self.name_of(A, view="dst"), "Destination")
        self.assertEqual(self.store("src")["published_through"], {"dst": 1})  # decided, so not offered again
        self.edit("Again", A, view="src")
        taken = self.merge("src", "dst", resolve={"address:" + A: "take_mine"})
        self.assertEqual(taken["merged"], 1)
        self.assertEqual(self.name_of(A, view="dst"), "Again")

    def test_a_value_the_destination_already_holds_is_converged_not_appended(self):
        self.edit("Same", A, view="src")
        self.edit("Same", A, view="dst")
        result = self.merge("src", "dst")
        self.assertEqual((result["merged"], len(result["converged"])), (0, 1))
        self.assertEqual(len(self.store("dst")["edits"]), 1)

    def test_a_crash_between_the_destination_and_the_source_mark_does_not_duplicate(self):
        self.edit("One", A, view="src")
        with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "publish.after_merge_destination:raise"}):
            with self.assertRaises(durable.FaultInjected):
                self.merge("src", "dst")
        self.assertEqual(len(self.store("dst")["edits"]), 1)
        self.assertEqual(self.store("src")["published_through"], {})
        result = self.merge("src", "dst")
        self.assertEqual(result["merged"], 0)
        self.assertEqual((len(self.store("dst")["edits"]), self.store("src")["published_through"]), (1, {"dst": 1}))

    def test_the_two_view_locks_are_taken_in_the_order_of_their_keys(self):
        self.edit("One", A, view="src")
        self.edit("Two", B, view="dst")
        order = []
        original = workcopy.view_lock
        from contextlib import contextmanager

        @contextmanager
        def recording(settings, target):
            order.append(target["key"])
            with original(settings, target):
                yield
        keys = sorted([self.target("src")["key"], self.target("dst")["key"]])
        with patch.object(workcopy, "view_lock", recording):
            self.merge("src", "dst")
            first = list(order)
            order.clear()
            self.edit("Three", C, view="dst")
            order.clear()
            views.merge(self.settings, self.engine(), self.target("dst"), self.target("src"),
                        views.validate({"kind": "merge", "from": "dst", "expect_revision": self.store("src")["revision"]}))
        self.assertEqual([key for key in first if key in keys], keys)
        self.assertEqual([key for key in order if key in keys][:2], keys)

    def test_two_opposite_merges_at_once_do_not_deadlock(self):
        self.edit("One", A, view="left")
        self.edit("Two", B, view="right")
        outcomes = {}

        def run(source, destination):
            try:
                outcomes[source] = self.merge(source, destination)["merged"]
            except BaseException as error:  # noqa: BLE001
                outcomes[source] = error
        threads = [threading.Thread(target=run, args=("left", "right")), threading.Thread(target=run, args=("right", "left"))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertFalse(any(thread.is_alive() for thread in threads), "a merge deadlocked")
        self.assertEqual(outcomes, {"left": 1, "right": 1})
        self.assertEqual(self.names([A, B], "left"), {A: "One", B: "Two"})
        self.assertEqual(self.names([A, B], "right"), {A: "One", B: "Two"})

    def test_a_stale_view_is_refused_with_stale_view(self):
        self.edit("One", A, view="src")
        self.edit("Mine", B, view="dst")
        self.edit("Head", C, view="other")
        self.publish("other")
        body = self.error(lambda: self.merge("src", "dst"))
        self.assertEqual(body["error"], "stale_view")

    def test_before_unknown_records_are_refused_unless_allowed(self):
        self.edit("One", A, view="src")
        store = self.store("src")
        store["edits"][0]["effects"] = None
        store["edits"][0]["before_unknown"] = True
        workcopy._save_store(self.settings, self.target("src"), store)
        with self.assertRaises(views.ViewError) as raised:
            self.merge("src", "dst")
        self.assertEqual(raised.exception.code, "before_unknown")
        self.assertEqual(self.merge("src", "dst", allow_unverified_before=True)["merged"], 1)


def lying_probe(real, caller: str, lie: str = "Lie"):
    """`workcopy.probe` as the daemon would answer if the program it was asked about did not hold what the code just wrote:
    the answer for a call made from CALLER is wrong, every other call (the classification of the records) is true."""
    def probe(engine, program, probes, *args, **kwargs):
        found = real(engine, program, probes, *args, **kwargs)
        if sys._getframe(1).f_code.co_name == caller:
            found = {pair: (lie if value is not None else None) for pair, value in found.items()}
        return found
    return probe


class VerificationCanFail(ViewWorld, unittest.TestCase):
    """Each check of the verification fails when the daemon returns a wrong value, and the message names the check that
    failed: a test that cannot fail proves nothing (review of Y3, round 1)."""

    def drain_one(self, view="one"):
        sealed = self.seal(view)
        return sealed, views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])

    def test_an_applied_effect_that_the_candidate_does_not_hold_fails_verification(self):
        self.edit("Mine", A, view="one")
        with patch.object(workcopy, "probe", lying_probe(workcopy.probe, "_verify_candidate")):
            sealed, led = self.drain_one()
        self.assertEqual((led["failure"]["error"], led["failure"]["counted"]), ("candidate_failed", True))
        self.assertIn("applied effect(s) are not what the candidate holds", led["failure"]["message"])
        self.assertEqual(led["failure"]["mismatches"][0]["found"], "Lie")
        self.assertEqual(self.head()["gen"], 0)
        # the same publish with a truthful daemon succeeds: the failure above came from the planted value
        self.assertEqual(self.run_job(sealed, "one")["outcome"], "applied")

    def test_an_untouched_function_that_decompiles_differently_in_the_candidate_fails_verification(self):
        self.edit("Mine", B, view="one")  # A is the function the fake lists, and the changeset does not touch it
        real, seen = commits._decompile, {}

        def decompile(engine, program, address, sha256):
            text = real(engine, program, address, sha256)
            seen[address] = seen.get(address, 0) + 1
            return text + " tampered" if address == A and seen[address] == 2 else text  # the 2nd call is the candidate's
        with patch.object(commits, "_decompile", decompile):
            sealed, led = self.drain_one()
        self.assertEqual((led["failure"]["error"], led["failure"]["counted"]), ("candidate_failed", True))
        self.assertIn("untouched function %s decompiles differently" % A, led["failure"]["message"])
        self.assertEqual(self.head()["gen"], 0)
        self.assertEqual(self.run_job(sealed, "one")["outcome"], "applied")

    def test_a_rebased_copy_that_does_not_hold_the_kept_values_changes_nothing(self):
        record = self.edit("FromTwo", B, view="two")["overlay_id"]
        self.edit("FromOne", A, view="one")
        self.publish("one")
        before = self.store("two")
        with patch.object(workcopy, "probe", lying_probe(workcopy.probe, "_build_rebased_copy")):
            with self.assertRaises(views.ViewError) as raised:
                self.rebase("two")
        self.assertEqual(raised.exception.code, "rebase_verify_failed")
        self.assertEqual(raised.exception.detail["mismatches"][0]["found"], "Lie")
        after = self.store("two")
        self.assertEqual((after["base"], after["revision"], after["edits"]), (before["base"], before["revision"], before["edits"]))
        self.assertEqual(self.pending_ids("two"), [record])
        self.assertEqual(self.rebase("two")["outcome"], "clean")  # and the same rebase with a truthful daemon works


class MergedFrom(ViewWorld, unittest.TestCase):
    """`in_master` matches a record by the id it was merged from, not only by its own id (and not only through the manifest's
    `merged_from_ids`): view one published X; view two holds Y, merged from X, and Y must not be applied a second time."""

    def setup_merged(self):
        x = self.edit("Shared", A, view="one")["overlay_id"]
        self.assertEqual(self.merge("one", "two")["merged"], 1)
        (y,) = self.pending_ids("two")
        self.assertNotEqual(x, y)
        self.assertEqual(self.store("two")["edits"][0]["merged_from"]["id"], x)
        self.publish("one")
        self.assertIn(x, self.manifest(1)["store"]["ids"])
        self.assertNotIn(x, self.manifest(1)["store"]["merged_from_ids"])
        return x, y

    def test_a_record_merged_from_a_published_one_is_skipped_by_the_leader(self):
        x, y = self.setup_merged()
        result = self.publish("two")
        self.assertEqual((result["outcome"], result["generation"], result["record_outcomes"]), ("skipped", None, {y: "skipped"}))
        self.assertEqual([row["gen"] for row in self.rows()], [0, 1])

    def test_a_record_merged_from_a_published_one_is_dropped_by_the_rebase(self):
        x, y = self.setup_merged()
        result = self.rebase("two")
        self.assertEqual((result["dropped_in_master"], result["converged"], result["kept"]), ([y], [], []))
        self.assertEqual(self.pending_ids("two"), [])


class Guards(ViewWorld, unittest.TestCase):
    """The idempotence guards and the fallbacks, tested directly (a concurrency test cannot hit them deterministically)."""

    def test_the_first_result_written_for_a_changeset_is_the_outcome(self):
        self.edit("Mine", A, view="one")
        sealed = self.seal("one")
        first = views.write_done(self.settings, sealed["lineage"], sealed["csid"], {"outcome": "applied", "generation": 7})
        again = views.write_done(self.settings, sealed["lineage"], sealed["csid"], {"outcome": "conflict", "generation": None})
        other = views.write_done(self.settings, sealed["lineage"], sealed["csid"], {"outcome": "skipped", "generation": 9})
        self.assertEqual((first["outcome"], again["outcome"], other["outcome"]), ("applied", "applied", "applied"))
        self.assertEqual(views.read_done(self.settings, sealed["lineage"], sealed["csid"])["generation"], 7)
        self.assertFalse(views.declined_path(self.settings, sealed["lineage"], sealed["csid"]).exists())

    def test_a_changeset_is_finalized_in_its_view_once(self):
        record = self.edit("Mine", A, view="one")["overlay_id"]
        sealed = self.seal("one")
        self.run_job(sealed, "one")
        first = self.store("one")
        target = self.target("one")
        self.assertFalse(views.finalize_changeset(self.settings, target, sealed["lineage"], sealed["csid"], 1, [record], first["revision"]))
        second = self.store("one")
        self.assertEqual((second["revision"], second["commits"], second["changesets"], second["journal"]),
                         (first["revision"], first["commits"], first["changesets"], first["journal"]))
        self.assertEqual(len(second["commits"]), 1)

    def test_acquiring_the_lock_repairs_a_torn_log_tail_before_anything_is_appended(self):
        self.edit("Mine", A, view="one")
        sealed = self.seal("one")
        with patch.dict(os.environ, {"HYDRALYSIS_TEST_MODE": "1", "HYDRALYSIS_TEST_FAULT": "publish.append_torn:torn:30"}):
            with patch.object(durable, "_die", side_effect=durable.FaultInjected("died")):
                with self.assertRaises(durable.FaultInjected):
                    views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        self.assertIsNotNone(self.head()["torn_tail"])
        # the changeset is decided elsewhere, so this leader has nothing to append: the repair is the acquisition's own
        views.write_done(self.settings, sealed["lineage"], sealed["csid"], {"outcome": "conflict", "generation": None, "conflicts": []})
        self.assertEqual(views.outstanding(self.settings, self.lineage_id()), [])
        led = views.drain(self.settings, self.lineage_id(), self.engine())
        self.assertEqual((led["led"], led["built"]), (True, []))
        self.assertIsNone(self.head()["torn_tail"])
        self.assertTrue(lineage.current_log(self.settings, self.lineage_id()).repairs())

    def test_a_candidate_folder_that_cannot_be_moved_aside_costs_a_gap_not_a_failure(self):
        self.edit("Mine", A, view="one")
        sealed = self.seal("one")
        folder = lineage.generation_dir(self.settings, self.lineage_id(), 1)
        folder.mkdir(parents=True)
        (folder / "left-by-a-dead-leader.txt").write_text("never head", encoding="utf-8")
        real = durable.replace_file

        def held(source, target, *args, **kwargs):
            if Path(source) == folder:
                raise OSError("an open handle")  # only the move of the abandoned candidate is refused
            return real(source, target, *args, **kwargs)
        with patch.object(durable, "replace_file", held):
            number = views.reserve_generation(self.settings, self.lineage_id())
        self.assertEqual(number, 2)  # the number is skipped: a gap, and nothing else
        self.assertTrue((folder / "left-by-a-dead-leader.txt").is_file())  # nothing was deleted
        with patch.object(durable, "replace_file", held):
            result = self.run_job(sealed, "one")
        self.assertEqual(result["generation"], 2)
        self.assertEqual([row["gen"] for row in self.rows()], [0, 2], "the log has a gap, as the module text says it can")
        self.assertTrue(lineage.verify_head(self.settings, self.lineage_id())["ok"])


class LateRecords(ViewWorld, unittest.TestCase):
    """A record added to a view while its changeset waits, then another view's publish decided first: the remainder is
    classified against the generations the base would jump over (review of Y3, round 1, blocking 2)."""

    def late_scenario(self):
        """View two seals C0 on A. View one seals C1 on B, then renames A (the view is not stale yet, so the edit is accepted).
        The leader publishes C0 as generation 1 and C1 as generation 2 (rebased)."""
        self.edit("TwoName", A, view="two")
        self.edit("OneB", B, view="one")
        sealed_two, sealed_one = self.seal("two"), self.seal("one")
        late = self.edit("OneLate", A, view="one")["overlay_id"]
        led = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed_one["csid"])
        self.assertEqual((led["built"], self.done(sealed_one["csid"])["outcome"]), ([1, 2], "rebased"))
        self.assertEqual(self.name_of(A), "TwoName")  # the master
        return sealed_one, late

    def test_the_base_does_not_jump_over_a_generation_the_remaining_records_were_never_checked_against(self):
        sealed, late = self.late_scenario()
        store = self.store("one")
        self.assertEqual(self.pending_ids("one"), [late])
        self.assertEqual(store["base"]["generation"], 0)  # not 2
        self.assertIsNotNone(workcopy.stale_reason(store, self.target("one")))
        body = self.error(lambda: self.edit("More", C, view="one"))
        self.assertEqual(body["error"], "stale_view")
        self.assertEqual([item["generation"] for item in body["editors"]], [1, 2])
        self.assertEqual([entry["generation"] for entry in store["commits"]], [2])  # what the view published is recorded

    def test_rebase_lists_the_late_record_as_a_conflict_and_take_mine_works(self):
        self.late_scenario()
        listed = self.rebase("one")
        self.assertEqual((listed["ok"], listed["outcome"]), (False, "conflict"))
        conflict = listed["conflicts"][0]
        self.assertEqual((conflict["subject"], conflict["theirs"], conflict["mine"]), ("address:" + A, "TwoName", "OneLate"))
        self.assertEqual([item["generation"] for item in conflict["editors"]], [1])  # generation 2 did not touch A
        kept = self.rebase("one", resolve={"address:" + A: "take_mine"})
        self.assertEqual((kept["outcome"], kept["to_generation"]), ("resolved", 2))
        self.assertEqual(self.names([A, B], "one"), {A: "OneLate", B: "OneB"})
        self.assertEqual(self.publish("one")["outcome"], "applied")
        self.assertEqual(self.names([A, B]), {A: "OneLate", B: "OneB"})

    def test_rebase_keep_drops_the_late_record(self):
        self.late_scenario()
        done = self.rebase("one", resolve={"address:" + A: "keep"})
        self.assertEqual((done["outcome"], len(done["dropped_keep"])), ("resolved", 1))
        self.assertEqual(self.pending_ids("one"), [])
        self.assertEqual(self.names([A, B], "one"), {A: "TwoName", B: "OneB"})

    def test_the_conflict_of_a_publish_names_a_rebase_call_that_works(self):
        self.late_scenario()
        again = self.seal("one")
        with self.assertRaises(views.ViewError) as raised:
            self.run_job(again, "one")
        body = raised.exception.payload()
        self.assertEqual(body["error"], "publish_conflict")
        call = body["next"]["options"]
        self.assertEqual((call["kind"], call["expect_revision"]), ("rebase", self.store("one")["revision"]))
        self.assertEqual(sorted(call["resolve"]), ["address:" + A])
        done = self.rebase("one", resolve={subject: "take_mine" for subject in call["resolve"]})
        self.assertTrue(done["rebased"])
        self.assertEqual(self.publish("one")["outcome"], "applied")

    def test_a_view_with_nothing_left_still_moves_to_the_generation_it_published(self):
        self.edit("TwoName", A, view="two")
        self.edit("OneB", B, view="one")
        self.seal("two")
        sealed_one = self.seal("one")
        views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed_one["csid"])
        self.assertEqual(self.store("one")["base"]["generation"], 2)
        self.assertIsNone(workcopy.stale_reason(self.store("one"), self.target("one")))


class DeadEnds(ViewWorld, unittest.TestCase):
    """`take_mine` settles every kind of conflict, so the publish that follows does not conflict again, and `rebase` does not
    answer `up_to_date` while a record still conflicts (review of Y3, round 1, nit 3)."""

    def with_second_effect(self, record_id, view, **effect):
        store = self.store(view)
        for item in store["edits"]:
            if item["id"] == record_id:
                item["effects"] = item["effects"] + [effect]
        workcopy._save_store(self.settings, self.target(view), store)

    def test_a_partially_converged_record_is_settled_by_take_mine(self):
        record = self.edit("X", A, view="two")["overlay_id"]
        self.with_second_effect(record, "two", subject="address:" + B, field="name", before="FUN_" + B.removeprefix("0x"), after="Y")
        self.edit("Y", B, view="one")
        self.publish("one")  # the master now holds B = Y, which is the second effect's `after`
        listed = self.rebase("two")
        self.assertEqual((listed["outcome"], listed["conflicts"][0]["reason"]), ("conflict", "partially_converged"))
        done = self.rebase("two", resolve={"address:" + B: "take_mine"})
        self.assertEqual((done["outcome"], done["reanchored"]), ("resolved", [record]))
        self.assertEqual(self.publish("two")["outcome"], "applied")
        self.assertEqual(self.names([A, B]), {A: "X", B: "Y"})

    def test_a_chain_conflict_on_an_up_to_date_view_is_listed_and_settled_by_take_mine(self):
        record = self.edit("X", A, view="one")["overlay_id"]
        self.with_second_effect(record, "one", subject="address:" + A, field="name", before="Z", after="X")
        sealed = self.seal("one")
        with self.assertRaises(views.ViewError) as raised:
            self.run_job(sealed, "one")
        self.assertEqual(raised.exception.payload()["conflicts"][0]["reason"], "chain")
        # the view is on the head generation: the old answer here was `up_to_date`, a dead end
        listed = self.rebase("one")
        self.assertEqual((listed["outcome"], listed["conflicts"][0]["reason"]), ("conflict", "chain"))
        done = self.rebase("one", resolve={"address:" + A: "take_mine"})
        self.assertEqual((done["rebased"], done["outcome"], done["reanchored"]), (True, "resolved", [record]))
        self.assertEqual(self.publish("one")["outcome"], "applied")
        self.assertEqual(self.rebase("one")["outcome"], "up_to_date")

    def test_an_up_to_date_view_with_records_that_do_not_conflict_is_still_up_to_date(self):
        self.edit("X", A, view="one")
        self.assertEqual(self.rebase("one")["outcome"], "up_to_date")
        self.publish("one")
        self.edit("More", B, view="one")
        self.assertEqual(self.rebase("one")["outcome"], "up_to_date")


class Classify(unittest.TestCase):
    """The one rule of rebase, merge and publish."""

    @staticmethod
    def record(ident, before, after, subject="address:0x1", field="name", seq=1):
        return {"id": ident, "seq": seq, "effects": [{"subject": subject, "field": field, "before": before, "after": after}]}

    def test_apply_converged_conflict(self):
        live = {("address:0x1", "name"): "FUN_1", ("address:0x2", "name"): "Done", ("address:0x3", "name"): "Else"}
        verdicts, chain = views.classify([self.record("a", None, "X"), self.record("b", None, "Done", "address:0x2"),
                                          self.record("c", None, "Y", "address:0x3")], live)
        self.assertEqual([item["outcome"] for item in verdicts], ["conflict", "converged", "conflict"])
        # an absent `before` is the text "absent", which is not what a function that exists holds
        live = {("address:0x1", "name"): "absent"}
        verdicts, chain = views.classify([self.record("a", None, "X")], live)
        self.assertEqual((verdicts[0]["outcome"], chain), ("apply", {("address:0x1", "name"): "X"}))

    def test_a_chain_is_checked_and_a_record_on_a_conflicting_pair_is_a_conflict_too(self):
        live = {("address:0x1", "name"): "Old"}
        verdicts, _ = views.classify([self.record("a", "Old", "B", seq=1), self.record("b", "B", "C", seq=2)], live)
        self.assertEqual([item["outcome"] for item in verdicts], ["apply", "apply"])
        verdicts, _ = views.classify([self.record("a", "Old", "B", seq=1), self.record("b", "Wrong", "C", seq=2)], live)
        self.assertEqual([(item["outcome"], item.get("reason")) for item in verdicts], [("apply", None), ("conflict", "chain")])
        verdicts, _ = views.classify([self.record("a", "Other", "B", seq=1), self.record("b", "B", "C", seq=2)], live)
        self.assertEqual([(item["outcome"], item.get("reason")) for item in verdicts], [("conflict", "drift"), ("conflict", "depends_on_conflict")])

    def test_what_cannot_be_checked_is_said_so_and_applied(self):
        verdicts, _ = views.classify([{"id": "a", "seq": 1, "effects": None},
                                      self.record("b", None, "x", "*", "report", seq=2),
                                      self.record("c", None, "x", seq=3)], {})
        self.assertEqual([item["outcome"] for item in verdicts], ["unchecked", "unchecked", "unchecked"])

    def test_a_record_that_is_only_partly_converged_is_a_conflict(self):
        record = {"id": "a", "seq": 1, "effects": [{"subject": "address:0x1", "field": "name", "before": "Old", "after": "New"},
                                                   {"subject": "address:0x1", "field": "signature", "before": "x", "after": "y"}]}
        verdicts, _ = views.classify([record], {("address:0x1", "name"): "New", ("address:0x1", "signature"): "x"})
        self.assertEqual((verdicts[0]["outcome"], verdicts[0]["reason"]), ("conflict", "partially_converged"))


class Storm(ViewWorld, unittest.TestCase):
    """24 publishers (K12, K16, K13)."""

    PUBLISHERS = 24

    def run_publishers(self, plan):
        """PLAN: a list of (view, address, name). Every publisher edits its own view, seals and runs its job in its own thread."""
        for view, where, name in plan:
            self.edit(name, where, view=view)
        outcomes, errors = {}, []

        def publisher(view):
            try:
                sealed = self.seal(view)
            except BaseException as error:  # noqa: BLE001
                errors.append((view, error))
                return
            try:
                outcomes[view] = (sealed["csid"], self.run_job(sealed, view))
            except views.ViewError as error:
                outcomes[view] = (sealed["csid"], error.payload())
            except BaseException as error:  # noqa: BLE001
                errors.append((view, error))
        threads = [threading.Thread(target=publisher, args=(view,)) for view, _, _ in plan]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(300)
        self.assertFalse(any(thread.is_alive() for thread in threads), "a publisher did not finish")
        self.assertEqual(errors, [])
        return outcomes

    def k12(self, expect_changesets):
        """K12: the log is linear; each generation equals its parent plus exactly the changesets its manifest lists, none acknowledged
        is missing and none is applied twice."""
        rows = [row for row in lineage.history(self.settings, self.lineage_id())]
        self.assertEqual([row["seq"] for row in rows], list(range(1, len(rows) + 1)))
        generations = [row["gen"] for row in rows]
        self.assertEqual(generations, list(range(len(rows))), "the generations of CURRENT.log are not consecutive")
        parent = 0
        seen = []
        for row in rows[1:]:
            manifest = lineage.read_manifest(lineage.project_folder_of(row["gpr"]))
            self.assertEqual(manifest["base"]["generation"], parent, "generation %s is not a child of %s" % (row["gen"], parent))
            self.assertEqual(manifest["changesets"], [item["csid"] for item in row["changesets"]])
            self.assertTrue(lineage.verify_manifest(lineage.project_folder_of(row["gpr"]))["ok"])
            seen.extend(manifest["changesets"])
            parent = row["gen"]
        self.assertEqual(len(seen), len(set(seen)), "a changeset was applied twice")
        self.assertEqual(sorted(seen), sorted(expect_changesets))
        ids = [ident for row in rows[1:] for ident in lineage.read_manifest(lineage.project_folder_of(row["gpr"]))["store"]["ids"]]
        self.assertEqual(len(ids), len(set(ids)), "a record is in two generations")

    def k16(self, plan, outcomes):
        """K16: fold the changesets in CURRENT.log order against a model of the names; a changeset whose `before` is not what the
        model holds is rejected exactly as the engine claimed, and the model equals the head."""
        order = [item["csid"] for row in lineage.history(self.settings, self.lineage_id()) for item in row.get("changesets") or []]
        by_view = {view: (where, name) for view, where, name in plan}
        model, applied = {}, []
        for csid in order:
            view = next(view for view, (c, _) in outcomes.items() if c == csid)
            where, name = by_view[view]
            self.assertEqual(model.get(where, "FUN_" + where.removeprefix("0x")), "FUN_" + where.removeprefix("0x"),
                             "the engine applied a changeset the model rejects: %s" % view)
            model[where] = name
            applied.append(view)
        for view, (csid, result) in outcomes.items():
            if view not in applied:
                self.assertEqual(result.get("error"), "publish_conflict", (view, result))
                self.assertEqual(self.pending_ids(view) != [], True, "a rejected changeset's records must stay pending")
        for where in {item[1] for item in plan}:
            self.assertEqual(self.name_of(where), model.get(where, "FUN_" + where.removeprefix("0x")))
        return applied

    def test_24_publishers_on_24_subjects_make_24_linear_generations(self):
        plan = [("v%02d" % index, address(index), "Name%02d" % index) for index in range(self.PUBLISHERS)]
        outcomes = self.run_publishers(plan)
        self.assertEqual({view: result.get("outcome") in ("applied", "rebased") for view, (_, result) in outcomes.items()},
                         {view: True for view, _, _ in plan}, {view: result for view, (_, result) in outcomes.items() if "outcome" not in result})
        self.assertEqual(self.head()["gen"], self.PUBLISHERS)
        self.assertEqual(len([path for path in lineage.lineages_root(self.settings).iterdir() if path.name.startswith("L-")]), 1,
                         "24 first publishers made more than one lineage")
        self.k12([csid for csid, _ in outcomes.values()])
        self.assertEqual(sorted(self.k16(plan, outcomes)), sorted(view for view, _, _ in plan))
        # every view was finalized in its own store, once
        for view, _, _ in plan:
            self.assertEqual(len(self.store(view)["commits"]), 1, view)
            self.assertEqual(self.pending_ids(view), [], view)

    def test_24_publishers_on_6_subjects_exactly_one_per_subject_wins_and_the_model_agrees(self):
        plan = [("w%02d" % index, address(index % 6), "Winner%02d" % index) for index in range(self.PUBLISHERS)]
        outcomes = self.run_publishers(plan)
        applied = self.k16(plan, outcomes)
        self.assertEqual(len(applied), 6)  # one winner per subject
        in_log = {item["csid"] for row in lineage.history(self.settings, self.lineage_id()) for item in row.get("changesets") or []}
        self.assertEqual({view: result for view, (csid, result) in outcomes.items() if csid in in_log and result.get("error")}, {},
                         "a changeset is in the log but its publisher was told it failed")
        self.k12([csid for csid, result in outcomes.values() if csid and result.get("error") is None])
        self.assertEqual(self.head()["gen"], 6)
        for view, (csid, result) in outcomes.items():
            if view not in applied:
                self.assertEqual(self.done(csid)["outcome"], "conflict")
                self.assertTrue(result["conflicts"][0]["editors"])

    def test_a_reader_and_an_unrelated_view_never_wait_for_the_leader(self):
        """K13: while the leader is stopped inside its build, a read of the master, a read and an edit of another view, and a
        sealing of a new changeset all complete. None of them touches `publish.lock`."""
        self.edit("Publish", A, view="writer")
        self.edit("Other", B, view="other")
        sealed = self.seal("writer")
        inside, release = threading.Event(), threading.Event()
        original = commits._backup

        def stalled(*args, **kwargs):
            inside.set()
            release.wait(60)
            return original(*args, **kwargs)
        result = {}

        def lead():
            with patch.object(commits, "_backup", stalled):
                result["led"] = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
        leader = threading.Thread(target=lead)
        leader.start()
        self.assertTrue(inside.wait(60))
        try:
            started = time.monotonic()
            probes = {}

            def probing():
                probes["master"] = self.name_of(A)
                probes["other"] = self.name_of(B, view="other")
                probes["edit"] = self.edit("Edited", C, view="other")["revision"]
                self.edit("Late", address(9), view="late")
                probes["seal"] = self.seal("late")["position"]
                probes["status"] = json.loads(self.runner.query("owned", "status", options={"show": "queue"}))["queue"]["leader"]
            worker = threading.Thread(target=probing)
            worker.start()
            worker.join(30)
            self.assertFalse(worker.is_alive(), "a reader or a view waited for the leader")
        finally:
            release.set()
            leader.join(120)
        self.assertEqual(probes["master"], "FUN_" + A.removeprefix("0x"))  # the sealed master, until the publish lands
        self.assertEqual((probes["other"], probes["edit"], probes["seal"], probes["status"]), ("Other", 2, 2, True))
        self.assertLess(time.monotonic() - started, 60)
        self.assertEqual(result["led"]["built"], [1])


# ---- processes: a storm whose leaders are killed (TerminateProcess) and the deterministic kill points ---------------------

class LazyProjects(dict):
    """The fake daemon's project table for a process that did not create the projects: a project that is on disk is loaded on
    first use (its programs' saved state is the `programs.json` the fake's save wrote into its `.rep` folder)."""

    def __init__(self, daemon, programs):
        super().__init__()
        self.daemon, self.programs = daemon, programs

    def _load(self, key):
        gpr = Path(key)
        if not gpr.is_file():
            return None
        project = {"gpr": str(gpr), "revision": "rev-1", "programs": {}}
        saved_file = gpr.parent / (gpr.stem + ".rep") / "programs.json"
        saved = json.loads(saved_file.read_text(encoding="utf-8")) if saved_file.is_file() else {}
        for path, info in self.programs.items():
            project["programs"][path] = {"sha256": info["sha256"], "analyzed": True, "functions": info.get("functions", 3),
                                         "imageBase": "0x140000000",
                                         "saved": saved.get(path) or {"marker": "", "names": {}}, "live": None, "writers": set()}
        dict.__setitem__(self, key, project)
        return project

    def __contains__(self, key):
        return dict.__contains__(self, key) or self._load(key) is not None

    def __getitem__(self, key):
        if not dict.__contains__(self, key) and self._load(key) is None:
            raise KeyError(key)
        return dict.__getitem__(self, key)


def worker_main(argv):
    """`python tests/test_views.py --worker <json>`: one publisher process. It runs the publish job of an already sealed changeset
    against a fake daemon that reads the projects from disk, so a kill of this process leaves only files behind."""
    spec = json.loads(argv[0])
    daemon = fakehydra.reset()
    daemon.effects = True
    daemon.projects = LazyProjects(daemon, spec["programs"])
    from unittest.mock import patch as _patch
    with _patch("hydralysis.hydra.Engine", fakehydra.FakeEngine):
        settings = spec["settings"]
        engine = fakehydra.FakeEngine(settings)
        selected = workcopy.with_view(targets.resolve(settings, spec["target"]), spec["view"])
        try:
            result = views.run_publish_job(settings, selected, {"csid": spec["csid"], "lineage": spec["lineage"]}, engine, 120)
            print(json.dumps({"ok": True, "result": result}))
        except views.ViewError as error:
            print(json.dumps({"ok": False, "error": error.payload()}))


class Processes(ViewWorld, unittest.TestCase):
    TIMEOUT = 240

    def setUp(self):
        super().setUp()
        # The generations are made by other processes: this process's daemon loads a project from disk when it first meets it.
        lazy = LazyProjects(self.daemon, {"/owned.exe": {"sha256": self.digest, "functions": 3}})
        lazy.update(self.daemon.projects)
        self.daemon.projects = lazy

    def spawn(self, sealed, view, fault=None, extra_env=None):
        spec = {"settings": self.settings, "target": "owned", "view": view, "csid": sealed["csid"], "lineage": sealed["lineage"],
                "programs": {"/owned.exe": {"sha256": self.digest, "functions": 3}}}
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(Path(views.__file__).resolve().parent.parent),
                                                           str(Path(__file__).resolve().parent)]))
        for name in ENV_FAULT:
            env.pop(name, None)
        if fault:
            env.update(HYDRALYSIS_TEST_MODE="1", HYDRALYSIS_TEST_FAULT=fault)
        env.update(extra_env or {})
        return subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--worker", json.dumps(spec)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def finish(self, process):
        try:
            out, err = process.communicate(timeout=self.TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate()
            self.fail("a publisher process did not finish: %s" % err[-2000:])
        return process.returncode, out.strip().splitlines()[-1] if out.strip() else "", err

    POINTS = ("after_fork", "after_save", "after_manifest", "after_seal", "before_append", "after_append", "after_done")

    def check_exit_point(self, point):
        self.edit("Mine", A, view="one")
        sealed = self.seal("one")
        code, out, err = self.finish(self.spawn(sealed, "one", fault="publish.%s:exit" % point))
        self.assertEqual(code, 137, (point, out, err[-1500:]))
        self.assertFalse(locks.held(str(views.publish_lock_path(self.settings, self.lineage_id()))), "the OS did not free the lock")
        code, out, err = self.finish(self.spawn(sealed, "one"))
        self.assertEqual(code, 0, (point, out, err[-1500:]))
        self.assertEqual(json.loads(out)["result"]["outcome"], "applied")
        rows = [row for row in self.rows() if row.get("changesets")]
        self.assertEqual([[item["csid"] for item in row["changesets"]] for row in rows], [[sealed["csid"]]], point)
        self.assertTrue(lineage.verify_head(self.settings, self.lineage_id())["ok"])
        self.settle("one")
        self.assertEqual(self.pending_ids("one"), [])

    def test_a_storm_of_24_publisher_processes_with_leaders_killed(self):
        count, kills = 24, 6
        plan = [("p%02d" % index, address(index % 12), "Proc%02d" % index) for index in range(count)]
        for view, where, name in plan:
            self.edit(name, where, view=view)
        sealed = {view: self.seal(view) for view, _, _ in plan}
        processes = {view: self.spawn(sealed[view], view) for view, _, _ in plan}
        rng = random.Random(7)
        killed = []
        deadline = time.monotonic() + self.TIMEOUT
        lock = str(views.publish_lock_path(self.settings, self.lineage_id()))
        leaders_killed = 0
        leader_file = lineage.lineage_dir(self.settings, self.lineage_id()) / "publish.leader.json"
        while (len(killed) < kills or leaders_killed < kills - 2) and time.monotonic() < deadline:
            time.sleep(rng.uniform(0.05, 0.4))
            if not locks.held(lock):
                continue
            alive = [view for view, process in processes.items() if process.poll() is None and view not in killed]
            if not alive:
                break
            try:
                leader_pid = json.loads(leader_file.read_text(encoding="utf-8"))["pid"]
            except (OSError, ValueError, KeyError):
                leader_pid = None
            leaders = [view for view in alive if processes[view].pid == leader_pid]
            # four kills of the process that holds the lock (the loop waits until it has made them), the rest of any process: a
            # follower's kill must cost nothing
            if leaders_killed < kills - 2 and not leaders:
                continue
            victim = leaders[0] if leaders_killed < kills - 2 else rng.choice(alive)
            leaders_killed += victim in leaders
            processes[victim].kill()  # TerminateProcess on Windows
            killed.append(victim)
        results = {}
        for view, process in processes.items():
            if view in killed:
                process.communicate()
                continue
            code, out, err = self.finish(process)
            self.assertEqual(code, 0, (view, out, err[-1500:]))
            results[view] = json.loads(out)
        # the survivors' jobs ended; whatever the killed processes left in the queue is drained by one more leader
        views.drain(self.settings, self.lineage_id(), self.engine())
        self.assertEqual(views.outstanding(self.settings, self.lineage_id()), [])
        order = [item["csid"] for row in lineage.history(self.settings, self.lineage_id()) for item in row.get("changesets") or []]
        self.assertEqual(len(order), len(set(order)), "a changeset was applied twice")
        # K12/K16 on what is on disk: every decided changeset is either in exactly one generation or was refused
        outcomes = {name: views.read_done(self.settings, self.lineage_id(), sealed[name]["csid"]) for name in sealed}
        models, applied = {}, set()
        for csid in order:
            view = next(name for name, item in sealed.items() if item["csid"] == csid)
            where = next(item[1] for item in plan if item[0] == view)
            self.assertEqual(models.get(where, "FUN_" + where.removeprefix("0x")), "FUN_" + where.removeprefix("0x"))
            models[where] = next(item[2] for item in plan if item[0] == view)
            applied.add(view)
        for name, outcome in outcomes.items():
            self.assertIsNotNone(outcome, name)
            self.assertEqual(outcome["outcome"] in ("applied", "rebased"), name in applied, (name, outcome["outcome"]))
            if name not in applied:
                self.assertEqual(outcome["outcome"], "conflict")
                self.assertTrue(self.pending_ids(name) != [], "a rejected changeset's records must stay pending")
        self.assertEqual(len(applied), 12)  # one winner per subject, whoever was killed
        for where, name in models.items():
            self.assertEqual(self.name_of(where), name)
        self.assertEqual([row["gen"] for row in self.rows()], list(range(len(self.rows()))), "a killed leader left a gap in the log")
        for row in self.rows()[1:]:
            self.assertTrue(lineage.verify_manifest(lineage.project_folder_of(row["gpr"]))["ok"])
        self.assertGreaterEqual(leaders_killed, kills - 2, "fewer than %d kills of the lock holder: the test did not exercise it" % (kills - 2))
        self.assertGreaterEqual(len(killed), kills)


for _point in Processes.POINTS:
    setattr(Processes, "test_a_leader_process_that_exits_at_%s_is_replaced_by_the_next_one" % _point,
            (lambda point: lambda self: self.check_exit_point(point))(_point))


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--worker":
        worker_main(sys.argv[2:])
    else:
        unittest.main()
