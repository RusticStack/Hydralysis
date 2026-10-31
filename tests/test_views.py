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
from hydralysis import commits, durable, hydra, lineage, locks, query, targets, viewgov, views, workcopy
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
        self.settings["publish_batch_max"] = 1  # the rule tested here is one generation per changeset
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
        self.settings["publish_batch_max"] = 1  # one generation per changeset: the order is read off the generations
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

    def test_the_leader_does_not_wait_for_a_busy_view_and_the_job_settles_it(self):
        record = self.edit("Mine", A, view="one")["overlay_id"]
        sealed = self.seal("one")
        with patch.object(workcopy, "SYNC_LOCK_S", 5), workcopy.view_lock(self.settings, self.target("one")):
            started = time.monotonic()
            led = views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])
            waited = time.monotonic() - started
        self.assertEqual(led["built"], [1])
        self.assertLess(waited, 5)  # the settle is tried after the commit lock is released, without a wait (H13)
        self.assertEqual(self.store("one")["changesets"], [])  # the view was busy: not settled yet
        result = self.run_job(sealed, "one")  # the job of the changeset settles its own view before it answers
        self.assertEqual((result["outcome"], result["generation"]), ("applied", 1))
        store = self.store("one")
        self.assertEqual([(entry["cid"], entry["ids"]) for entry in store["commits"]], [(sealed["csid"], [record])])

    def test_a_converged_changeset_waits_for_a_busy_view_since_no_log_row_replays_it(self):
        """A result without a generation is in no CURRENT.log row, so `settle` never replays it: with no job left to settle
        it (expired, cancelled, dead), the leader must settle it, waiting for the view as before H13."""
        self.edit("Same", A, view="one")
        record = self.edit("Same", A, view="two")["overlay_id"]
        self.publish("one")
        sealed = self.seal("two")
        held = threading.Event()

        def hold():
            with workcopy.view_lock(self.settings, self.target("two")):
                held.set()
                time.sleep(0.5)

        holder = threading.Thread(target=hold)
        holder.start()
        held.wait(5)
        views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=sealed["csid"])  # no run_job: the job is gone
        holder.join()
        self.assertEqual(self.done(sealed["csid"])["outcome"], "converged")
        store = self.store("two")
        self.assertEqual([(item["csid"], item["generation"], item["ids"]) for item in store["changesets"]],
                         [(sealed["csid"], None, [record])])
        self.assertEqual(self.pending_ids("two"), [])
        self.assertEqual(views.settle(self.settings, self.target("two")), False)  # nothing left for the next call

    def test_a_generation_settled_after_a_later_one_of_its_view_does_not_replace_it(self):
        """A view's later changeset holds the records of its earlier undecided one, so settling the earlier generation last
        finds them committed already: it adds no commit entry and the newer one stays live."""
        self.settings["publish_batch_max"] = 1  # two generations of the same view are what this test settles
        first = self.edit("One", A, view="one")["overlay_id"]
        early = self.seal("one")
        second = self.edit("Two", B, view="one")["overlay_id"]
        late = self.seal("one")
        with workcopy.view_lock(self.settings, self.target("one")):
            views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=early["csid"])  # busy: not settled
        views.drain(self.settings, self.lineage_id(), self.engine(), stop_after=late["csid"])  # generation 2 settles first
        self.assertEqual([item["csid"] for item in self.store("one")["changesets"]], [late["csid"]])
        views.settle(self.settings, self.target("one"))  # then generation 1, replayed from CURRENT.log
        store = self.store("one")
        live = [(entry["cid"], entry["generation"], entry["ids"]) for entry in store["commits"] if not entry.get("reverted")]
        self.assertEqual(live, [(late["csid"], 2, sorted([first, second]))])
        self.assertEqual(store.get("archived") or [], [])
        self.assertEqual(sorted(item["csid"] for item in store["changesets"]), sorted([early["csid"], late["csid"]]))
        self.assertEqual(store["base"]["generation"], 2)

    def test_an_existing_lineage_is_found_without_the_creation_lock(self):
        self.edit("Mine", A, view="one")
        self.run_job(self.seal("one"), "one")
        selected = self.target("one")
        origin = selected.get("origin_key") or selected["key"]
        root = lineage.lineages_root(self.settings)
        held = locks.LaneLock(str(root / (".create.%s.lock" % lineage.sha256_hex(origin.encode("utf-8"))[:24])))
        self.assertTrue(held.acquire())
        try:
            with patch.object(durable, "LOCK_TIMEOUT_S", 0.3):
                self.assertEqual(views.ensure_lineage(self.settings, selected)["id"], self.lineage_id())  # H14: no lock taken
                with self.assertRaises(locks.LockBusy):
                    views.ensure_lineage(self.settings, {**selected, "lineage": None})  # no registry row: the locked path
        finally:
            held.release()

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

    def test_a_batch_the_engine_refuses_is_decided_one_changeset_at_a_time_and_only_the_culprit_fails(self):
        """A batch shares one candidate, so a hard failure names no changeset: the leader retries the batch one at a time,
        the innocent changesets land, and the one the engine refuses carries the failure (counted once, not twice)."""
        self.settings["publish_batch_max"] = 2
        good = self.edit("Good", A, view="one")["overlay_id"]
        bad = self.edit("Bad", B, view="two")["overlay_id"]
        sealed = [self.seal("one"), self.seal("two")]
        verify = views._verify_candidate
        seen = []

        def refuse_the_second(settings, engine, job, target, candidate_gpr, clone_folder, source_gpr, applied):
            seen.append([record["id"] for record in applied])
            if any(record["id"] == bad for record in applied):
                raise views.PublishFailure("candidate_failed", "planted: the second record is refused", counted=True,
                                           csid=sealed[1]["csid"])
            return verify(settings, engine, job, target, candidate_gpr, clone_folder, source_gpr, applied)
        with patch.object(views, "_verify_candidate", refuse_the_second):
            led = views.drain(self.settings, self.lineage_id(), self.engine())
        self.assertEqual(seen, [[good, bad], [good], [bad]])  # the batch, then one at a time
        self.assertEqual(led["built"], [1])
        self.assertEqual(led["failure"]["error"], "candidate_failed")
        self.assertEqual(self.done(sealed[0]["csid"])["outcome"], "applied")
        self.assertEqual(self.name_of(A), "Good")
        failed = json.loads(views.failure_path(self.settings, self.lineage_id(), sealed[1]["csid"]).read_text(encoding="utf-8"))
        self.assertEqual(failed["attempts"], 1)  # the failed batch was not counted against it
        self.assertEqual(self.pending_ids("two"), [bad])  # its records stay pending
        self.assertEqual(self.pending_ids("one"), [])


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
        # `two` holds a record on A as well as on B, so a clean-only rebase cannot settle it (Y5, 4.10) and its next edit is refused.
        self.edit("FromOne", A, view="one")
        self.edit("FromTwo", B, view="two")
        self.edit("AlsoTwo", A, view="two")
        self.publish("one")
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

    def test_the_rebase_builds_outside_the_view_lock(self):
        # H12: the engine round trips of the build no longer hold `.view.lock` (with it held, this acquisition is busy).
        self.stale_view()
        original, seen = views._build_rebased_copy, []

        def build(settings, engine, selected, *rest):
            with patch.object(workcopy, "SYNC_LOCK_S", 0.5), workcopy.view_lock(settings, selected):
                seen.append(True)
            return original(settings, engine, selected, *rest)
        with patch.object(views, "_build_rebased_copy", side_effect=build):
            self.assertTrue(self.rebase("two")["rebased"])
        self.assertEqual(seen, [True])

    def test_an_edit_during_the_build_makes_the_switch_refuse_and_change_nothing(self):
        self.stale_view()
        before = self.store("two")
        original = views._build_rebased_copy

        def build(*args):
            with workcopy.view_lock(self.settings, self.target("two")):  # another agent's mutation lands mid-build
                store = workcopy.load_store(self.settings, self.target("two"))
                store["revision"] += 1
                workcopy._save_store(self.settings, self.target("two"), store)
            return original(*args)
        with patch.object(views, "_build_rebased_copy", side_effect=build):
            body = self.error(lambda: self.rebase("two"))
        self.assertEqual((body["expected_revision"], body["current_revision"]), (before["revision"], before["revision"] + 1))
        after = self.store("two")
        self.assertEqual((after["base"], after["revision"], after["edits"]), (before["base"], before["revision"] + 1, before["edits"]))
        self.assertTrue(self.rebase("two")["rebased"])  # and a rebase from the new revision goes through

    def test_a_published_through_mark_set_during_the_build_survives_the_switch(self):
        # review finding: merge marks the SOURCE view's published_through without a revision bump; the switch kept the
        # decision-time copy and silently dropped the mark.
        self.stale_view()
        original = views._build_rebased_copy

        def build(*args):
            with workcopy.view_lock(self.settings, self.target("two")):
                store = workcopy.load_store(self.settings, self.target("two"))
                store["published_through"] = {**store.get("published_through", {}), "other": 7}
                workcopy._save_store(self.settings, self.target("two"), store)
            return original(*args)
        with patch.object(views, "_build_rebased_copy", side_effect=build):
            self.assertTrue(self.rebase("two")["rebased"])
        after = self.store("two")
        self.assertEqual(after["published_through"].get("other"), 7)
        self.assertEqual(after["base"]["generation"], 1)

    def test_a_versioned_change_without_a_revision_bump_makes_the_switch_refuse(self):
        self.stale_view()
        before = self.store("two")
        original = views._build_rebased_copy

        def build(*args):
            with workcopy.view_lock(self.settings, self.target("two")):
                store = workcopy.load_store(self.settings, self.target("two"))
                store["stale"] = "planted"
                workcopy._save_store(self.settings, self.target("two"), store)
            return original(*args)
        with patch.object(views, "_build_rebased_copy", side_effect=build):
            body = self.error(lambda: self.rebase("two"))
        self.assertIn("conflict", body)
        after = self.store("two")
        self.assertEqual((after["base"], after["stale"]), (before["base"], "planted"))

    def test_a_sync_of_the_view_during_the_build_leaves_the_rebase_copy_alone(self):
        # review finding: a concurrent sync swept the copy being built in the rebase folder, and the switch then named the
        # discarded copy as the view's fork. The sync runs in another thread (another caller) while the build holds its lane.
        self.stale_view()
        original, seen = views._build_rebased_copy, {}

        def build(settings, engine, selected, *rest):
            built = original(settings, engine, selected, *rest)
            seen["fork"] = (built.get("state") or {}).get("fork_gpr")
            errors = []

            def other():
                try:
                    workcopy.repair(settings, self.engine(), selected)
                except Exception as error:  # noqa: BLE001
                    errors.append(error)
            thread = threading.Thread(target=other)
            thread.start()
            thread.join(120)
            seen["errors"] = errors
            seen["exists"] = bool(seen["fork"]) and Path(seen["fork"]).is_file()
            seen["synced"] = json.loads((workcopy._directory(settings, selected) / "state.json").read_text())
            return built
        with patch.object(views, "_build_rebased_copy", side_effect=build):
            self.assertTrue(self.rebase("two")["rebased"])
        self.assertEqual(seen["errors"], [])
        self.assertTrue(seen["exists"])
        # the concurrent sync did not close (discard) or retire the copy being built
        self.assertNotIn(workcopy._norm(seen["fork"]), {workcopy._norm(item) for item in seen["synced"].get("retired") or []})
        self.assertNotIn("discarded", seen["synced"].get("last_sync") or {})
        state = json.loads((workcopy._directory(self.settings, self.target("two")) / "state.json").read_text())
        self.assertEqual(state["fork_gpr"], seen["fork"])
        self.assertNotIn(seen["fork"], state.get("retired") or [])
        self.assertEqual(self.names([A, B], "two"), {A: "FromOne", B: "FromTwo"})

    def test_the_switch_refuses_a_copy_that_was_closed_while_it_was_building(self):
        # The guard behind the sweep fix: if the built copy was discarded anyway (same thread here, so the lane does not
        # hide it), the switch refuses instead of adopting a discarded program.
        self.stale_view()
        before = self.store("two")
        original = views._build_rebased_copy

        def build(settings, engine, selected, *rest):
            built = original(settings, engine, selected, *rest)
            workcopy.repair(settings, self.engine(), selected)
            return built
        with patch.object(views, "_build_rebased_copy", side_effect=build):
            body = self.error(lambda: self.rebase("two"))
        self.assertIn("closed", body["reason"])
        self.assertEqual(self.store("two")["base"], before["base"])
        self.assertTrue(self.rebase("two")["rebased"])

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

    def assert_candidate_refused(self, sealed, led, message):
        """The same assertions for every check of the verification: counted, named, never head, the records still pending."""
        self.assertEqual((led["failure"]["error"], led["failure"]["counted"]), ("candidate_failed", True))
        self.assertIn(message, led["failure"]["message"])
        self.assertEqual(self.head()["gen"], 0)
        self.assertEqual([row["gen"] for row in self.rows()], [0])
        self.assertIsNone(self.done(sealed["csid"]))  # attempt 1 of 3: still queued
        self.assertEqual(len(self.pending_ids("one")), 1)

    def test_a_candidate_with_an_invalid_database_header_fails_verification(self):
        self.edit("Mine", A, view="one")
        verify = views._verify_candidate

        def damaged(settings, engine, job, target, candidate_gpr, *args, **kwargs):
            database = Path(candidate_gpr).parent / (Path(candidate_gpr).stem + ".rep") / "idata" / "00" / "~00000000.db"
            database.mkdir(parents=True, exist_ok=True)
            (database / "db.1.gbf").write_bytes(b"not a database")  # the newest (and only) version has no valid header
            return verify(settings, engine, job, target, candidate_gpr, *args, **kwargs)
        with patch.object(views, "_verify_candidate", damaged):
            sealed, led = self.drain_one()
        self.assert_candidate_refused(sealed, led, "without a valid header")
        self.assertEqual(led["failure"]["report"]["newest_invalid"][0]["file"], "db.1.gbf")
        self.assertEqual(self.run_job(sealed, "one")["outcome"], "applied")  # an undamaged candidate is published

    def clone_reports(self, **different):
        """`commits._program_of` as the daemon would answer if the read-only open of the verification clone said something
        else than the parent says (the clone's folder is the one under publish-verify)."""
        real = commits._program_of

        def program_of(engine, gpr, target, writable=False, **fields):
            found = real(engine, gpr, target, writable=writable, **fields)
            if "publish-verify" in str(gpr).replace("\\", "/") and not writable:
                found = {**found, **different}
            return found
        return program_of

    def test_a_candidate_with_another_function_count_than_its_parent_fails_verification(self):
        self.edit("Mine", A, view="one")
        with patch.object(commits, "_program_of", self.clone_reports(functions=999)):  # the fake's program has 2
            sealed, led = self.drain_one()
        self.assert_candidate_refused(sealed, led, "function count or analysed flag differs")
        self.assertEqual(self.run_job(sealed, "one")["outcome"], "applied")

    def test_a_candidate_with_another_analysed_flag_than_its_parent_fails_verification(self):
        self.edit("Mine", A, view="one")
        with patch.object(commits, "_program_of", self.clone_reports(analyzed=False)):  # the fake's program is analysed
            sealed, led = self.drain_one()
        self.assert_candidate_refused(sealed, led, "function count or analysed flag differs")
        self.assertEqual(self.run_job(sealed, "one")["outcome"], "applied")

    def test_a_clone_that_does_not_open_writable_fails_verification(self):
        self.edit("Mine", A, view="one")
        real = commits._program_of

        def program_of(engine, gpr, target, writable=False, **fields):
            if writable and "publish-verify" in str(gpr).replace("\\", "/"):
                raise hydra.EngineError("corrupt", "planted: the database does not open for writing")
            return real(engine, gpr, target, writable=writable, **fields)
        with patch.object(commits, "_program_of", program_of):
            sealed, led = self.drain_one()
        self.assert_candidate_refused(sealed, led, "does not open writable")
        self.assertEqual(self.run_job(sealed, "one")["outcome"], "applied")

    def test_an_engine_that_is_away_during_the_writable_open_is_not_held_against_the_candidate(self):
        self.edit("Mine", A, view="one")
        real = commits._program_of

        def program_of(engine, gpr, target, writable=False, **fields):
            if writable and "publish-verify" in str(gpr).replace("\\", "/"):
                raise hydra.EngineError("closed", "the connection ended")
            return real(engine, gpr, target, writable=writable, **fields)
        with patch.object(commits, "_program_of", program_of):
            sealed, led = self.drain_one()
        self.assertEqual((led["failure"]["error"], led["failure"]["counted"]), ("engine_refused", False))
        self.assertEqual(self.head()["gen"], 0)

    def test_an_effect_the_candidate_cannot_report_is_not_a_mismatch(self):
        """None from the probe means "could not read it", not "holds another value": only a wrong value fails (see `lying_probe`)."""
        self.edit("Mine", A, view="one")
        real = workcopy.probe

        def silent(engine, program, probes, *args, **kwargs):
            found = real(engine, program, probes, *args, **kwargs)
            return {pair: None for pair in found} if sys._getframe(1).f_code.co_name == "_verify_candidate" else found
        with patch.object(workcopy, "probe", silent):
            self.assertEqual(self.publish("one")["outcome"], "applied")

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

    def setUp(self):
        super().setUp()
        # Two generations decided in one drain are what this scenario is about; a batch would decide them as one.
        self.settings["publish_batch_max"] = 1

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

    def setUp(self):
        super().setUp()
        # 24 publishers make 24 linear generations here (and 6 winners on 6 subjects): one changeset per generation.
        self.settings["publish_batch_max"] = 1

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
        # A leader killed between its fork and its append leaves one generation to recover: this class kills leaders on every
        # step of a build, and a storm of 24 publishers gives 24 builds to kill only when each build is one changeset.
        self.settings["publish_batch_max"] = 1

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


# ---- Y5: per-agent default views (PROTOCOL-3.md D43, D59, 4.10, K11, K11p, K15) -----------------------------------------------

def _install_fake_daemon(spec):
    """The set-up of a child process: the fake daemon loads projects from disk, the engine is the fake, and the settings
    are the test's (no engine install is needed)."""
    daemon = fakehydra.reset()
    daemon.effects = True
    daemon.projects = LazyProjects(daemon, spec["programs"])
    patch("hydralysis.hydra.Engine", fakehydra.FakeEngine).start()
    from hydralysis import api
    api._settings = lambda: spec["settings"]
    return daemon


def agent_main(argv):
    """`test_views.py --agent <json>`: one agent process. It runs `steps` (`{tool, args}`) through the public dispatch, prints one
    JSON line per step as it goes, and with `hold` then waits on stdin so that the test can kill it after its edits are in the store."""
    spec = json.loads(argv[0])
    _install_fake_daemon(spec)
    from hydralysis import api, hydra as _hydra
    if spec.get("client"):
        _hydra.set_harness(spec["client"])
    for step in spec["steps"]:
        try:
            line = {"ok": True, "text": api.call(step["tool"], step["args"])}
        except Exception as error:  # noqa: BLE001 - the test inspects the refusal
            line = {"ok": False, "error": "%s: %s" % (type(error).__name__, error)}
        print(json.dumps(line), flush=True)
    if spec.get("hold"):
        sys.stdin.read()


def mcp_main(argv):
    """`test_views.py --mcp <json>`: the real stdio MCP server over the fake daemon."""
    spec = json.loads(argv[0])
    _install_fake_daemon(spec)
    from hydralysis import mcp
    mcp.Server().serve()


class McpProcess:
    """A real stdio MCP server process and a client for it. Several threads may call at once (replies are matched by id)."""

    def __init__(self, spec, name="claude-code", env=None):
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join([str(Path(views.__file__).resolve().parent.parent),
                                                                  str(Path(__file__).resolve().parent)]))
        for key in ENV_FAULT:
            environment.pop(key, None)
        environment.pop("HYDRALYSIS_AGENT_ID", None)
        environment.update(env or {})
        self.process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--mcp", json.dumps(spec)], env=environment,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._cond = threading.Condition()
        self._replies, self._next, self.stderr = {}, 1, []
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()
        self.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": name, "version": "1"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _read(self):
        for line in self.process.stdout:
            if line.strip():
                message = json.loads(line)
                with self._cond:
                    self._replies[message.get("id")] = message
                    self._cond.notify_all()

    def _drain(self):
        for line in self.process.stderr:
            self.stderr.append(line.decode("utf-8", "replace"))

    def _send(self, message):
        self.process.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        self.process.stdin.flush()

    def request(self, method, params, timeout=120):
        with self._cond:
            ident, self._next = self._next, self._next + 1
        self._send({"jsonrpc": "2.0", "id": ident, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        with self._cond:
            while ident not in self._replies:
                left = deadline - time.monotonic()
                if left <= 0 or self.process.poll() is not None and ident not in self._replies:
                    raise AssertionError("no reply to %s (exit %s): %s" % (method, self.process.poll(), "".join(self.stderr)[-1500:]))
                self._cond.wait(min(left, 0.5))
            return self._replies.pop(ident)

    def call(self, tool, arguments, timeout=120):
        """(decoded JSON or text, is_error)."""
        reply = self.request("tools/call", {"name": tool, "arguments": arguments}, timeout)
        text = reply["result"]["content"][0]["text"]
        for candidate in (text, text.split(": ", 1)[-1]):  # an error is "RuntimeError: {json}"
            try:
                return json.loads(candidate), reply["result"]["isError"]
            except ValueError:
                continue
        return text, reply["result"]["isError"]

    def kill(self):
        self.process.kill()
        self.process.wait()

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.close()
                self.process.wait(timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait()
        for stream in (self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except OSError:
                pass


class AgentWorld(ViewWorld):
    """ViewWorld plus helpers for callers that identify themselves with `options.as` (or not at all)."""

    def setUp(self):
        super().setUp()
        viewgov.GOVERNOR.reset()
        self.addCleanup(viewgov.GOVERNOR.reset)
        query._announced.clear()
        self.addCleanup(query._announced.clear)

    def ask(self, agent, action, address="", **options):
        if agent is not None:
            options["as"] = agent
        return json.loads(self.runner.query("owned", action, address, options=options))

    def revision_of(self, agent):
        return self.ask(agent, "status")["view_revision"]

    def rename(self, agent, name, address=A, **options):
        return self.ask(agent, "type_edit", address, kind="rename", name=name, source="cited test evidence",
                        expect_revision=options.pop("expect_revision", self.revision_of(agent)), **options)

    def seen(self, agent, address=A, **options):
        query._keys.clear()
        return self.ask(agent, "decompile", address, **options)["function"]["name"]

    def refusal(self, agent, action, address="", **options):
        with self.assertRaises(RuntimeError) as raised:
            self.ask(agent, action, address, **options)
        return json.loads(str(raised.exception))

    def lineage_of(self):
        return self.runner.target("owned")["lineage"]["id"]

    def view_of(self, agent):
        return views.view_name(agent) if agent is not None else views.view_name(views.default_agent_id()[0])


class PerAgentViews(AgentWorld, unittest.TestCase):
    def test_an_edit_goes_to_the_agents_own_view_and_every_other_caller_reads_the_master(self):
        edited = self.rename("agent-1", "Mine")
        self.assertEqual(edited["view"], "agent-1")
        self.assertEqual(edited["agent"], "agent-1")
        self.assertEqual(self.seen("agent-1"), "Mine")
        self.assertEqual(self.seen("agent-2"), "FUN_140001000")
        self.assertEqual(self.seen(None), "FUN_140001000", "a caller with no id reads the master, not another agent's view")
        self.assertEqual(self.seen("agent-1", scope="master"), "FUN_140001000")
        self.assertEqual(self.ask("agent-2", "decompile", A)["view"], "master")
        self.assertEqual(self.ask("agent-1", "decompile", A)["view"], "agent-1")

    def test_a_caller_without_a_view_reads_the_master_and_creates_nothing(self):
        before = lineage.tree_hash(self.gpr.parent)
        reply = self.ask("nobody", "decompile", A)
        self.assertEqual((reply["view"], reply["agent"]), ("master", "nobody"))
        self.assertFalse((lineage.lineages_root(self.settings)).exists() and any(lineage.lineages_root(self.settings).iterdir()),
                         "a read made a lineage")
        self.assertFalse(workcopy.view_exists(self.settings, self.target("nobody")))
        status = self.ask("nobody", "status")
        self.assertEqual((status["view_revision"], status["overlays"]["pending"]), (0, 0))
        self.assertEqual(self.ask("nobody", "status", show="changes")["changes"], [])
        self.assertEqual(lineage.tree_hash(self.gpr.parent), before)

    def test_the_first_edit_creates_the_view_with_its_record_and_the_master_is_untouched(self):
        edited = self.rename("agent-1", "Mine", expect_revision=0)
        lid = self.lineage_of()
        record = views.read_record(self.settings, lid, "agent-1")
        self.assertEqual((record["agent"], record["id_kind"], record["boot_id"], record["pid"]),
                         ("agent-1", "explicit", views.BOOT_ID, os.getpid()))
        self.assertGreater(record["lease_until"], time.time())
        self.assertEqual(views.holder_state(record), "mine")
        self.assertEqual(edited["base"], {"lineage": lid, "generation": 0})
        self.assertEqual(lineage.tree_hash(self.gpr.parent), self.master_tree)
        self.assertEqual([row["gen"] for row in self.rows()], [0], "an edit made a generation")

    def test_the_default_id_is_the_client_name_at_the_boot_id_and_never_a_process_id(self):
        with patch.object(hydra, "_IDENTITY", {"client": "x", "harness": "claude-code"}):
            agent, kind = views.default_agent_id()
            self.assertEqual((agent, kind), ("claude-code@" + views.BOOT_ID, "default"))
            self.assertRegex(views.BOOT_ID, r"^[0-9a-f]{16}$")
            self.assertNotIn(str(os.getpid()), agent.split("@")[1])
            edited = self.rename(None, "Default")
            self.assertEqual(edited["agent"], agent)
            self.assertEqual(self.seen(None), "Default")
            self.assertEqual(self.seen("someone-else"), "FUN_140001000")
            listed = self.ask(None, "status", show="views")
            self.assertEqual([row["agent"] for row in listed["views"]], [agent])
            self.assertEqual((listed["boot_id"], listed["default_agent"], listed["default_kind"]), (views.BOOT_ID, agent, "default"))
        with patch.dict(os.environ, {"HYDRALYSIS_AGENT_ID": "stable-1"}):
            self.assertEqual(views.default_agent_id(), ("stable-1", "stable"))

    def test_two_ids_that_look_alike_never_share_a_view(self):
        names = {views.view_name(item) for item in ("a@b", "a-b", "a.at.b", "A@b", "a@b ", "a b")}
        self.assertEqual(len(names), 5 if "a@b" == "a@b " else 6)  # "a@b " is stripped to "a@b" by clean_agent_id, not by view_name
        self.assertEqual(views.view_name("plain"), "plain")
        for name in names:
            workcopy.with_view({"key": "k"}, name)  # every derived name is a valid view name

    def test_two_ids_that_differ_only_in_case_get_two_view_files_even_where_file_names_ignore_case(self):
        """The view name is a file name (`views/<name>.json`) and NTFS ignores case, so a name that differs only in case collides."""
        names = [views.view_name(item) for item in ("Alice", "alice", "ALICE", "aLiCe")]
        self.assertEqual(len({name.lower() for name in names}), 4, names)
        self.assertEqual(views.view_name("alice"), "alice", "a lower-case id that is a view name is still the name itself")
        self.rename("Alice", "FromUpper")
        self.rename("alice", "FromLower", B)
        self.assertEqual(self.seen("Alice"), "FromUpper")
        self.assertEqual(self.seen("alice", B), "FromLower")
        self.assertEqual(self.seen("alice"), "FUN_140001000", "the lower-case agent does not see the upper-case agent's edit")
        lid = self.lineage_of()
        listed = views.list_records(self.settings, lid)
        self.assertEqual(sorted(row["agent"] for row in listed), ["Alice", "alice"], "both agents have their own record")
        files = [path.name for path in views.views_dir(self.settings, lid).iterdir() if path.suffix == ".json"]
        self.assertEqual(len({name.lower() for name in files}), len(files), "no two record files differ only in case")
        self.assertEqual(len(files), 2)
        status = self.ask("Alice", "status", show="views")
        self.assertEqual(sorted(row["agent"] for row in status["views"]), ["Alice", "alice"])

    def test_an_explicit_view_wins_over_the_agent_and_shared_is_named_explicitly(self):
        self.rename("agent-1", "Mine")
        self.assertEqual(self.ask("agent-1", "type_edit", A, kind="rename", name="Team", source="cited",
                                  view="shared", expect_revision=0)["view"], "shared")
        self.assertEqual(self.seen("agent-1", view="shared"), "Team")
        self.assertEqual(self.seen("agent-2", view="shared"), "Team")
        self.assertEqual(self.seen("agent-2", **{}), "FUN_140001000", "the shared view is not anyone's default")
        self.assertEqual(self.seen("shared"), "Team", "as:'shared' names the collaboration view")
        self.assertEqual(self.seen("agent-1"), "Mine")

    def test_the_shared_view_and_every_agent_view_keep_the_mandatory_expect_revision(self):
        shared = self.refusal("agent-1", "type_edit", A, kind="rename", name="X", source="cited", view="shared")
        mine = self.refusal("agent-1", "type_edit", A, kind="rename", name="X", source="cited")
        for refused in (shared, mine):
            self.assertEqual(refused["error"], "expect_revision_required", refused)
            self.assertEqual(refused["current_revision"], 0)
        self.assertEqual(self.pending_ids("agent-1"), [])

    def test_a_stale_expect_revision_is_rebased_or_refused_naming_the_other_editor(self):
        """Two callers of one id are serialised by the store revision: conflict control, not isolation (D59)."""
        self.rename("agent-1", "One", A)
        revision = self.revision_of("agent-1")
        self.rename("agent-1", "Two", A)  # a second caller of the same id edits the same subject
        self.assertTrue(self.rename("agent-1", "Three", C, expect_revision=revision)["rebased"], "a different subject is rebased")
        refused = self.refusal("agent-1", "type_edit", A, kind="rename", name="Mine-too", source="cited", expect_revision=revision)
        self.assertEqual(refused["conflict"], "overlay revision changed")
        self.assertIn("address:0x140001000", refused["subjects_changed_since"])
        self.assertTrue(refused["latest_editor"], "the conflict names the editor")
        self.assertEqual(self.seen("agent-1", A), "Two", "the stale edit was not applied over the other caller's")

    def test_a_reply_names_view_agent_base_and_the_staleness_when_the_view_is_behind(self):
        self.rename("agent-1", "Mine", A)
        self.rename("agent-2", "Theirs", B)
        self.publish(self.view_of("agent-2"))
        reply = self.ask("agent-1", "decompile", A)
        self.assertEqual(reply["stale"], {"base": 0, "head": 1, "behind": 1})
        self.assertEqual(reply["base"]["generation"], 0)
        self.assertEqual(reply["function"]["name"], "Mine")
        self.assertNotIn("stale", self.ask("agent-3", "decompile", A), "a master read is never stale")
        self.assertEqual(self.ask("agent-3", "decompile", A)["base"]["generation"], 1)

    def test_an_edit_in_a_view_that_is_behind_is_rebased_first_when_that_is_clean(self):
        self.rename("agent-1", "Mine", A)
        self.rename("agent-2", "Theirs", B)
        self.publish(self.view_of("agent-2"))
        edited = self.rename("agent-1", "More", C)
        self.assertEqual(edited["auto_rebased"]["to_generation"], 1)
        self.assertEqual(edited["base"]["generation"], 1)
        self.assertNotIn("stale", edited)
        self.assertEqual((self.seen("agent-1", A), self.seen("agent-1", B), self.seen("agent-1", C)), ("Mine", "Theirs", "More"))

    def test_an_edit_that_would_conflict_with_the_head_is_refused_with_stale_view_naming_the_editors(self):
        self.rename("agent-1", "Mine", A)
        self.rename("agent-2", "Theirs", A)
        self.publish(self.view_of("agent-2"))
        refused = self.refusal("agent-1", "type_edit", B, kind="rename", name="More", source="cited",
                               expect_revision=self.revision_of("agent-1"))
        self.assertEqual(refused["error"], "stale_view")
        self.assertTrue(refused["editors"], "stale_view names the editors that moved the head")
        self.assertEqual(refused["next"]["options"]["kind"], "rebase")
        self.assertEqual(len(self.pending_ids(self.view_of("agent-1"))), 1, "the refused edit left nothing behind")
        self.assertEqual(self.seen("agent-1", A), "Mine", "the view keeps answering from what it has")

    def test_follow_head_moves_a_clean_view_and_rebases_a_dirty_one_when_that_is_clean(self):
        self.rename("agent-1", "Mine", A)
        self.rename("agent-2", "Theirs", B)
        self.publish(self.view_of("agent-2"))
        reply = self.ask("agent-1", "decompile", B, follow="head")
        self.assertEqual((reply["function"]["name"], reply["base"]["generation"]), ("Theirs", 1))
        self.assertNotIn("stale", reply)
        self.assertNotIn("follow", reply)
        self.assertEqual(self.ask("agent-9", "decompile", B, follow="head")["function"]["name"], "Theirs")

    def test_status_with_follow_head_answers_from_the_store_the_rebase_wrote(self):
        self.rename("agent-1", "Mine", A)
        self.rename("agent-2", "Theirs", B)
        self.publish(self.view_of("agent-2"))
        reply = self.ask("agent-1", "status", follow="head")
        self.assertEqual(reply["base"]["generation"], 1, "the status after the rebase names the generation it moved to")
        self.assertNotIn("stale", reply)
        self.assertEqual(reply["view_revision"], self.revision_of("agent-1"))

    def test_status_show_views_lists_every_view_with_its_holder_and_pending_records(self):
        self.rename("agent-1", "One", A)
        self.rename("agent-2", "Two", B)
        self.rename("agent-2", "Three", C)
        listed = self.ask("agent-1", "status", show="views")
        rows = {row["agent"]: row for row in listed["views"]}
        self.assertEqual(sorted(rows), ["agent-1", "agent-2"])
        self.assertEqual((rows["agent-1"]["pending"], rows["agent-2"]["pending"]), (1, 2))
        self.assertEqual({row["state"] for row in rows.values()}, {"mine"})
        self.assertEqual(listed["you"], {"agent": "agent-1", "view": "agent-1"})
        self.assertEqual(listed["adoptable"], [])

    def test_24_agents_get_24_views_and_none_sees_anothers_tag(self):
        errors, tags = [], {}

        def work(index):
            agent = "k11-%02d" % index
            try:
                tags[agent] = "Tag%02d" % index
                self.rename(agent, tags[agent], address(index))
            except Exception as error:  # noqa: BLE001
                errors.append((agent, repr(error)))

        threads = [threading.Thread(target=work, args=(index,)) for index in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(120)
        self.assertEqual(errors, [])
        for index in range(24):
            agent = "k11-%02d" % index
            for other in range(24):
                expected = tags[agent] if other == index else "FUN_" + address(other).removeprefix("0x")
                self.assertEqual(self.seen(agent, address(other)), expected, (agent, other))
        self.assertEqual(self.seen(None, address(3)), "FUN_" + address(3).removeprefix("0x"), "the master shows no unpublished tag")
        self.assertEqual(len(self.ask("k11-00", "status", show="views")["views"]), 24)

    def test_a_default_id_view_of_a_live_process_is_refused_with_view_in_use_and_adopted_once_it_is_gone(self):
        lid = self.rename("cli@0123456789abcdef", "Orphan")["base"]["lineage"]
        name = views.view_name("cli@0123456789abcdef")
        record = views.read_record(self.settings, lid, name)
        record = {**record, "id_kind": "default", "boot_id": "0123456789abcdef",
                  "holders": {"0123456789abcdef": {"pid": os.getpid(), "pid_started_ms": views.process_started_ms(),
                                                   "lease_until": time.time() + 600, "agent_name": "cli"}}}
        durable.write_sealed(views.record_path(self.settings, lid, name), record)
        refused = self.refusal("cli@0123456789abcdef", "decompile", A)
        self.assertEqual(refused["error"], "view_in_use")
        self.assertEqual(refused["owner"]["pid"], os.getpid())
        self.assertEqual(self.seen(None), "FUN_140001000", "without the id the caller reads the master meanwhile")
        for holder in ({"pid": 2 ** 22 + 77, "pid_started_ms": 1, "lease_until": time.time() + 600, "agent_name": "cli"},
                       {"pid": os.getpid(), "pid_started_ms": views.process_started_ms(), "lease_until": time.time() - 5,
                        "agent_name": "cli"}):
            durable.write_sealed(views.record_path(self.settings, lid, name), {**record, "holders": {"0123456789abcdef": holder}})
            self.assertEqual(views.holder_state(views.read_record(self.settings, lid, name)), "orphaned")
        self.assertEqual(self.seen("cli@0123456789abcdef"), "Orphan", "an orphan is re-attached with options.as")
        adopted = views.read_record(self.settings, lid, name)
        self.assertEqual(adopted["adopted_from"]["boot_id"], "0123456789abcdef")
        self.assertEqual(views.holder_state(adopted), "mine")

    def test_the_first_reply_of_a_default_id_process_lists_the_orphans_of_the_same_agent_once(self):
        lid = self.rename("cli@fedcba9876543210", "Orphan")["base"]["lineage"]
        name = views.view_name("cli@fedcba9876543210")
        record = views.read_record(self.settings, lid, name)
        dead = {"pid": 2 ** 22 + 77, "pid_started_ms": 1, "lease_until": time.time() + 600, "agent_name": "cli"}
        durable.write_sealed(views.record_path(self.settings, lid, name), {**record, "id_kind": "default", "holders": {"fedcba9876543210": dead}})
        self.rename("other-agent-name-ok", "Alive")
        query._announced.clear()
        first = self.ask(None, "decompile", A)
        self.assertEqual([(row["agent"], row["pending"]) for row in first["adoptable"]], [("cli@fedcba9876543210", 1)])
        self.assertEqual(first["adoptable"][0]["use"], {"options": {"as": "cli@fedcba9876543210"}})
        self.assertEqual(first["function"]["name"], "FUN_140001000", "reads the master until it adopts")
        self.assertNotIn("adoptable", self.ask(None, "decompile", A), "listed once per lineage")
        listed = self.ask(None, "status", show="views")
        self.assertEqual([row["agent"] for row in listed["adoptable"]], ["cli@fedcba9876543210"], "status always lists them")
        self.assertEqual(self.seen("cli@fedcba9876543210"), "Orphan")
        query._announced.clear()
        self.assertNotIn("adoptable", self.ask(None, "decompile", A), "an adopted view is no longer an orphan")

    def test_native_tools_without_an_options_bag_read_the_master_and_never_a_view(self):
        self.rename("agent-1", "Mine")
        self.assertEqual(self.ask("agent-1", "decompile", A)["function"]["name"], "Mine")
        # inspect/function/callers/... are offline tools of the PE: they are never routed through a store.
        from hydralysis import api
        with patch.object(workcopy, "reader", side_effect=AssertionError("a native tool opened a view")), \
                patch.object(workcopy, "load_store", side_effect=AssertionError("a native tool read a store")):
            for tool in ("fingerprint", "inspect"):
                try:
                    api.call(tool, {"exe": str(self.exe)})
                except AssertionError:
                    raise
                except Exception:  # noqa: BLE001 - the fixture is not a real PE; only that no view was touched matters
                    pass

    def test_ghidra_run_takes_options_as_and_runs_in_the_callers_view_or_the_master(self):
        from hydralysis import api
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "Probe.java").write_text("// probe\n", encoding="utf-8")
        targets.register(self.settings, ["owned"], {**targets.registry(self.settings)["owned"], "scripts": str(scripts)})
        self.rename("agent-1", "Mine")
        with patch.object(api, "_settings", return_value=self.settings):
            mine = api.call("ghidra_run", {"target": "owned", "script": "Probe", "options": {"as": "agent-1"}})
            other = api.call("ghidra_run", {"target": "owned", "script": "Probe", "options": {"as": "agent-2"}})
            plain = api.call("ghidra_run", {"target": "owned", "script": "Probe"})
        self.assertIn("view=agent-1", mine)
        self.assertIn("view=master", other)
        self.assertIn("view=master", plain)


# ---- real processes: K11 with 12 and 24 agents, a killed agent (K15), sub-agents of one MCP server, restart and adopt ---------

class AgentProcesses(AgentWorld, unittest.TestCase):
    TIMEOUT = 240

    def setUp(self):
        super().setUp()
        lazy = LazyProjects(self.daemon, {"/owned.exe": {"sha256": self.digest, "functions": 3}})
        lazy.update(self.daemon.projects)
        self.daemon.projects = lazy
        self.extra = {}
        for name in ("owned2", "owned3"):  # the same build imported as three projects
            gpr = self.root / "analysed" / name / (name + ".gpr")
            self.daemon.add_project(gpr, {"/owned.exe": {"sha256": self.digest, "functions": 3}})
            targets.register(self.settings, [name], {"gpr": str(gpr), "program": "/owned.exe", "sha256": self.digest,
                                                     "exe": str(self.exe), "engine": "hydra"})
            self.extra[name] = gpr
        self.spec = {"settings": self.settings, "programs": {"/owned.exe": {"sha256": self.digest, "functions": 3}}}
        self.processes = []
        self.addCleanup(self.stop_all)

    def stop_all(self):
        for item in self.processes:
            if isinstance(item, McpProcess):
                item.close()
            elif item.poll() is None:
                item.kill()
                item.communicate()

    def environment(self, **extra):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(Path(views.__file__).resolve().parent.parent),
                                                          str(Path(__file__).resolve().parent)]))
        for key in (*ENV_FAULT, "HYDRALYSIS_AGENT_ID"):
            env.pop(key, None)
        env.update(extra)
        return env

    def agent(self, steps, client=None, hold=False, env=None):
        spec = {**self.spec, "steps": steps, "client": client, "hold": hold}
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--agent", json.dumps(spec)],
                                   env=self.environment(**(env or {})), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        return process

    @staticmethod
    def edit_step(target, agent, name, where, revision=0):
        return {"tool": "ghidra_query", "args": {"target": target, "action": "type_edit", "address": where,
                                                   "options": {"kind": "rename", "name": name, "source": "cited test evidence",
                                                               "expect_revision": revision, **({"as": agent} if agent else {})}}}

    @staticmethod
    def read_step(target, agent, where):
        return {"tool": "ghidra_query", "args": {"target": target, "action": "decompile", "address": where,
                                                   "options": {"as": agent} if agent else {}}}

    def finish(self, process):
        try:
            out, err = process.communicate(timeout=self.TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate()
            self.fail("an agent process did not finish: %s" % err[-2000:])
        self.assertEqual(process.returncode, 0, err[-2000:])
        return [json.loads(line) for line in out.strip().splitlines()]

    def k11(self, agents, projects):
        names = ["owned", "owned2", "owned3"][:projects]
        plan = []
        for index in range(agents):
            agent = "agent-%02d" % index
            tag = "Tag%02d" % index
            own = names[index % len(names)]
            steps = [self.edit_step(own, agent, tag, address(index))]
            for other in range(agents):  # every agent reads every agent's address on every project it can see
                for name in names:
                    steps.append(self.read_step(name, agent, address(other)))
            plan.append((agent, tag, own, self.agent(steps)))
        results = {agent: self.finish(process) for agent, _, _, process in plan}
        for agent, tag, own, _ in plan:
            lines = results[agent]
            self.assertTrue(lines[0]["ok"], (agent, lines[0]))
            self.assertNotIn("no_project", json.dumps(lines), agent)
            reads = iter(lines[1:])
            for other in range(agents):
                for name in names:
                    line = next(reads)
                    self.assertTrue(line["ok"], (agent, name, other, line))
                    seen = json.loads(line["text"])["function"]["name"]
                    mine = name == own and other == int(agent.split("-")[1])
                    # K11: the only unpublished tag an agent ever sees is its own, on the project it edited
                    self.assertEqual(seen, tag if mine else "FUN_" + address(other).removeprefix("0x"), (agent, name, other))
        for index in range(agents):  # the master shows none of them
            for name in names:
                self.assertEqual(self.master_name(name, address(index)), "FUN_" + address(index).removeprefix("0x"))

    def master_name(self, target, where):
        query._keys.clear()
        return json.loads(self.runner.query(target, "decompile", where, options={"scope": "master"}))["function"]["name"]

    def test_k11_12_agents_in_separate_processes_on_3_projects_see_no_unpublished_tag_of_another(self):
        self.k11(12, 3)

    def test_k11_24_agents_in_separate_processes_get_no_no_project_error_and_share_no_state(self):
        self.k11(24, 3)

    def test_a_killed_agent_process_rebuilds_its_view_from_the_store(self):
        agent = self.agent([self.edit_step("owned", "victim", "Kept", A), self.edit_step("owned", "victim", "Kept2", B, 1)], hold=True)
        for _ in range(2):
            self.assertTrue(json.loads(agent.stdout.readline())["ok"])
        agent.kill()
        agent.communicate()
        self.assertEqual(self.pending_ids(self.view_of("victim")).__len__(), 2)
        self.assertEqual((self.seen("victim", A), self.seen("victim", B)), ("Kept", "Kept2"))
        self.assertEqual(views.holder_state(views.read_record(self.settings, self.lineage_of(), "victim")), "mine",
                         "the reader that took it over now holds it")
        again = self.finish(self.agent([self.read_step("owned", "victim", A)]))
        self.assertEqual(json.loads(again[0]["text"])["function"]["name"], "Kept", "a new process rebuilds the same answer")

    def test_a_one_shot_cli_process_is_a_fresh_agent_unless_it_sets_an_id(self):
        """D59: each `hydralysis ...` invocation is a new process and so a new default id `cli@<boot id>`. An edit-then-read through two
        invocations only works with HYDRALYSIS_AGENT_ID or `options.as`; without them the second one reads the master (documented)."""
        first = self.finish(self.agent([self.edit_step("owned", None, "CliEdit", A)]))
        self.assertTrue(first[0]["ok"], first)
        edited = json.loads(first[0]["text"])
        self.assertTrue(edited["agent"].startswith("cli@"), edited["agent"])
        second = self.finish(self.agent([self.read_step("owned", None, A)]))
        reply = json.loads(second[0]["text"])
        self.assertEqual(reply["function"]["name"], "FUN_140001000", "a second one-shot process reads the master, not the first one's view")
        self.assertEqual(reply["view"], "master")
        self.assertNotEqual(reply["agent"], edited["agent"])
        self.assertEqual([row["agent"] for row in reply["adoptable"]], [edited["agent"]], "and it is told where the edit went")
        stable = {"HYDRALYSIS_AGENT_ID": "cli-user"}  # the documented way to keep edits across invocations
        self.finish(self.agent([self.edit_step("owned", None, "Kept", B)], env=stable))
        again = json.loads(self.finish(self.agent([self.read_step("owned", None, B)], env=stable))[0]["text"])
        self.assertEqual((again["function"]["name"], again["agent"]), ("Kept", "cli-user"))
        self.finish(self.agent([self.edit_step("owned", "scripted", "ByAs", C)]))  # so is options.as
        by_as = json.loads(self.finish(self.agent([self.read_step("owned", "scripted", C)]))[0]["text"])
        self.assertEqual(by_as["function"]["name"], "ByAs")

    def mcp(self, name="claude-code", env=None):
        server = McpProcess(self.spec, name=name, env=env)
        self.processes.append(server)
        return server

    def call_in(self, server, agent, action, address="", **options):
        if agent:
            options["as"] = agent
        return server.call("ghidra_query", {"target": "owned", "action": action, "address": address, "options": options})

    def test_subagents_one_process(self):
        """D59, K11p: two sub-agents of one MCP server process (one clientInfo, one boot id)."""
        server = self.mcp()
        errors = []

        def both(first, second, together=False):
            """Run FIRST on thread P and SECOND on thread Q: one after the other (P is done before Q starts), or at the same
            time with TOGETHER."""
            out = {}

            def run(key, call):
                try:
                    out[key] = call()
                except Exception as error:  # noqa: BLE001
                    errors.append(repr(error))
            threads = []
            for key, call in (("P", first), ("Q", second)):
                thread = threading.Thread(target=run, args=(key, call))
                thread.start()
                threads.append(thread)
                if not together:
                    thread.join(120)
            for thread in threads:
                thread.join(120)
            return out

        # (1) neither passes `as`: one id, one view, and Q sees P's unpublished rename
        status, failed = self.call_in(server, None, "status")
        self.assertFalse(failed)
        default = "claude-code@" + status["session"]["boot_id"]
        self.assertEqual(status["session"]["agent"], default)
        edited = both(lambda: self.call_in(server, None, "type_edit", A, kind="rename", name="FromP", source="cited", expect_revision=0),
                      lambda: self.call_in(server, None, "decompile", A))
        self.assertEqual(errors, [])
        self.assertEqual(edited["P"][0]["agent"], default)
        self.assertEqual(edited["Q"][0]["function"]["name"], "FromP", "a shared identity shares the view: documented, not a failure")
        listed, _ = self.call_in(server, None, "status", show="views")
        self.assertEqual([row["agent"] for row in listed["views"]], [default], "one view")
        # a Q edit that carries a stale expect_revision is rebased subject-aware or refused naming P, never applied over P's
        stale, failed = self.call_in(server, None, "type_edit", A, kind="rename", name="FromQ", source="cited", expect_revision=0)
        self.assertTrue(failed)
        self.assertIn("overlay revision changed", json.dumps(stale))
        self.assertIn("address:0x140001000", json.dumps(stale), "the conflict names the subject P changed")
        self.assertIn("latest_editor", json.dumps(stale))
        again, _ = self.call_in(server, None, "decompile", A)
        self.assertEqual(again["function"]["name"], "FromP", "no lost update")
        rebased, failed = self.call_in(server, None, "type_edit", B, kind="rename", name="FromQ2", source="cited", expect_revision=0)
        self.assertFalse(failed)
        self.assertTrue(rebased["rebased"], "a stale edit on another subject is rebased")
        # (2) P passes as:"P", Q passes as:"Q": two views, no tag crosses until a publish (K11)
        both(lambda: self.call_in(server, "P", "type_edit", C, kind="rename", name="TagP", source="cited", expect_revision=0),
             lambda: self.call_in(server, "Q", "type_edit", "0x140004000", kind="rename", name="TagQ", source="cited", expect_revision=0), together=True)
        seen = both(lambda: self.call_in(server, "P", "decompile", "0x140004000"), lambda: self.call_in(server, "Q", "decompile", C),
                    together=True)
        self.assertEqual(errors, [])
        self.assertEqual((seen["P"][0]["function"]["name"], seen["Q"][0]["function"]["name"]), ("FUN_140004000", "FUN_140003000"))
        self.assertEqual(self.call_in(server, "P", "decompile", C)[0]["function"]["name"], "TagP")
        self.assertEqual(self.call_in(server, "Q", "decompile", "0x140004000")[0]["function"]["name"], "TagQ")
        listed, _ = self.call_in(server, "P", "status", show="views")
        self.assertEqual(sorted(row["agent"] for row in listed["views"]), sorted([default, "P", "Q"]))
        # (3) no schema change: the bags are free-form, `backend help` lists `as`, the catalog is the pinned one, the skills say it
        table = {tool["name"]: tool["inputSchema"] for tool in server.request("tools/list", {})["result"]["tools"]}
        for tool in ("ghidra_query", "ghidra_run"):
            self.assertNotIn("as", table[tool]["properties"])
            self.assertEqual(table[tool]["properties"]["options"], {"type": "object"})
        from hydralysis import api
        import test_contracts
        self.assertEqual(api.catalog_hash(), test_contracts.CATALOG_HISTORY[api.CATALOG_EPOCH])
        helped, _ = server.call("backend", {"action": "help"})
        self.assertIn("options.as", json.dumps(helped["option_bags"]))
        self.assertEqual(helped["catalog"], {"epoch": api.CATALOG_EPOCH, "hash": api.catalog_hash()})
        repo = Path(views.__file__).resolve().parents[2]
        for skill in ("hydralysis", "ghidra-project"):
            text = (repo / "skills" / skill / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("distinct `options.as` for each editing sub-agent", text, skill)
            self.assertIn("conflict control and not isolation", text, skill)
            self.assertIn("one-shot `hydralysis` command is a new agent", text, skill)
            self.assertIn("HYDRALYSIS_AGENT_ID", text, skill)
        readme = (repo / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("Clients share the default view", readme)
        self.assertIn("conflict control, not isolation", readme, "the shared-identity behaviour is documented, not promised away")
        self.assertIn("one-shot `hydralysis` command is a new agent", readme, "the CLI consequence is documented")
        # (4) a native tool call (no options bag) takes no identity: it never reaches a store
        native, failed = server.call("fingerprint", {"exe": str(self.exe)})
        self.assertNotIn("view", json.dumps(native))

    def test_restart_adopts_orphaned_view(self):
        first = self.mcp()
        status, _ = self.call_in(first, None, "status")
        old = status["session"]["agent"]
        edited, failed = self.call_in(first, None, "type_edit", A, kind="rename", name="Orphaned", source="cited", expect_revision=0)
        self.assertFalse(failed, edited)
        second = self.mcp()  # same clientInfo name, a new boot id, while the first still lives
        reply, _ = self.call_in(second, None, "decompile", A)
        self.assertEqual(reply["function"]["name"], "FUN_140001000", "reads the master")
        self.assertNotIn("adoptable", reply, "a live holder is not an orphan")
        refused, failed = self.call_in(second, old, "decompile", A)
        self.assertTrue(failed)
        self.assertEqual(refused["error"], "view_in_use", "a live lease refuses")
        self.assertEqual(refused["owner"]["agent_name"], "claude-code")
        first.kill()
        third = self.mcp()  # the restart: a new process after the first one died
        reply, _ = self.call_in(third, None, "status")
        self.assertEqual([(row["agent"], row["pending"]) for row in reply["adoptable"]], [(old, 1)], "reported on its first call")
        self.assertNotEqual(reply["session"]["boot_id"], status["session"]["boot_id"])
        read, _ = self.call_in(third, None, "decompile", A)
        self.assertEqual(read["function"]["name"], "FUN_140001000", "it reads the master until it adopts")
        adopted, failed = self.call_in(third, old, "decompile", A)
        self.assertFalse(failed, adopted)
        self.assertEqual(adopted["function"]["name"], "Orphaned", "options.as re-attaches and sees the edits")
        listed, _ = self.call_in(third, None, "status", show="views")
        self.assertEqual(listed["adoptable"], [])
        row = next(item for item in listed["views"] if item["agent"] == old)
        self.assertEqual((row["state"], row["adopted_from"]["boot_id"]), ("mine", status["session"]["boot_id"]))

    def test_restart_with_a_stable_agent_id_keeps_the_view_without_adopting(self):
        env = {"HYDRALYSIS_AGENT_ID": "long-lived-agent"}
        first = self.mcp(env=env)
        edited, failed = self.call_in(first, None, "type_edit", A, kind="rename", name="Stable", source="cited", expect_revision=0)
        self.assertFalse(failed, edited)
        self.assertEqual(edited["agent"], "long-lived-agent")
        first.kill()
        second = self.mcp(env=env)
        reply, _ = self.call_in(second, None, "decompile", A)
        self.assertEqual(reply["function"]["name"], "Stable", "the same id: the same view")
        self.assertNotIn("adoptable", reply)
        status, _ = self.call_in(second, None, "status", show="views")
        self.assertEqual((status["default_agent"], status["default_kind"]), ("long-lived-agent", "stable"))
        self.assertEqual(status["adoptable"], [])


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--worker":
        worker_main(sys.argv[2:])
    elif len(sys.argv) > 2 and sys.argv[1] == "--agent":
        agent_main(sys.argv[2:])
    elif len(sys.argv) > 2 and sys.argv[1] == "--mcp":
        mcp_main(sys.argv[2:])
    else:
        unittest.main()
