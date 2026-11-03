# hy-views test map (old Python test -> new)

Status: PARTIAL. Ported modules: locks, jobowner, viewgov (policy core). Everything else is NOT ported yet.
Classification: B = black-box (must pass unchanged with HYDRALYSIS_IMPL=rust once the PyO3 binding exists),
W = white-box (re-expressed as Rust test with the same case).

## tests/test_locks.py
| Python | Class | Rust |
|---|---|---|
| LaneLockIsNonBlocking.test_a_second_acquire_returns_false_at_once | W | locks::tests::lane_lock_excludes_and_held_probes |
| ...test_acquire_is_idempotent_for_the_holder_and_held_reports_it | W | locks::tests::lane_lock_excludes_and_held_probes (held) ; idempotent re-acquire NOT yet asserted |
| ...test_the_os_releases_the_lock_when_the_holder_is_killed | W | TODO (needs child process kill) |
| LockBusyIsTyped.test_the_bounded_wait_raises_lockbusy_with_its_facts | W | locks::tests::locked_times_out_with_busy_payload_and_frees_on_drop |
| LockBusyIsTyped.test_a_free_lock_is_taken_and_released | W | same test (drop then re-lock) |
| LockBusyIsTyped.test_the_lock_is_released_when_the_body_raises | W | covered by Guard Drop; explicit panic test TODO |
| LockedIsFair.test_n_writers_released_together_are_served_in_turn | W | locks::tests::contending_waiters_are_all_served (no ordering/timing assertion yet) |
| LockedSurvivesAKilledHolder.* (2) | W | TODO |
| (new) cross-implementation exclusion | - | tests/py_interop.rs |

## tests/test_jobowner.py
| JobOwners.test_only_the_starting_client_cancels | W | jobowner::tests::owner_can_cancel_..., stranger_is_refused_with_python_message |
| JobOwners.test_jobs_from_before_owners_stay_open_and_status_hides_the_hash | W | jobowner::tests::legacy_jobs_are_open_and_public_hides_hash |
(the tool-surface half of both stays black-box and needs the binding.)

## tests/test_viewgov.py
| Limits.* (2) | W | viewgov::tests::limits_accept_both_spellings_and_reject_invalid |
| Governor.test_the_least_recently_used... / rebuilt once | W | lru_eviction_at_max_views_and_rebuilt_flag |
| Governor idle past limit / keep-warm | W | sweep_evicts_idle_but_keeps_warm_and_running |
| Governor running never closed / full house capacity | W | capacity_when_every_view_is_running_and_nothing_leaks |
| Governor failed close leaves open | W | failing_release_returns_to_open_with_error |
| Governor pin-or-evict is one step | W | pin_waits_for_a_closing_view_then_reopens_it (single scenario; Python variant is a stress loop: TODO) |
| Governor engine capacity -> evict_lru | W | evict_lru implemented, test TODO |
| Eviction.*, Capacity.* (RunnerWorld/fake engine) | B | need views/workcopy/binding: NOT ported |
| IdleFolders.* | B | delete_idle_folders NOT ported (needs views + workcopy) |

## Not ported (no tests mapped yet)
views.py, commits.py, workcopy.py, viewpool.py, userscripts.py, jobs/joblog helpers; tests/test_views.py,
test_view_base.py, test_view_leak.py, test_commit.py, test_viewpool.py, test_publish*.py, test_userscripts.py,
test_workcopy-related and the RealEngine* classes.

## Stage 1-3 additions (second session)

Modules: layout, error, proc, records (view records), queue (changeset queue), options (publish/rebase/merge options),
classify (the one rule), gens (CURRENT.log head/append, manifests, live_generations, master_ids, editors_since),
revisions, store (view store over hy-store storelog), commits (options, select, drift, intent log), settle (view lock,
finalize_changeset, settle, finalize_commit). Cross-implementation tests (Python 3.15 needed; skipped otherwise):

| Rust test | What it proves | Python tests it stands in for (white-box part) |
|---|---|---|
| tests/py_formats.rs | view record, changeset, done records: Python writes/Rust reads; Rust sealed bytes == durable.dumps_sealed | test_views.py record/claim/queue-record cases |
| tests/py_diff.rs | classify() on 600 generated cases == views.classify; CURRENT.log head/master_ids/editors/live chain agree | test_views.py classification, test_view_base.py chain rules |
| tests/py_store.rs | Rust-saved store (snapshot+log) loads equal in Python and the reverse; state_text byte-identical; subjects_of/fields_of/reconcile/dependents on 800 generated cases | test_views.py/test_workcopy.py store+revision cases |
| tests/py_commits.rs | commits.validate (400), select (300), drift_check/_later_dependents (300), intent log agree | test_commit.py option/selection/drift cases |
| tests/py_settle.rs | finalize_changeset (with/without generation), settle, commits.finalize produce equal stores | test_views.py settle/finalize, test_commit.py finalize cases |

NOT yet covered (no Rust code): views.rebase/merge/drain/_publish_candidate/run_publish_job/start_job (engine-driven),
seal_changeset (needs lineage.ensure, targets.resolve), queue memo, publish_job_of (overlayjobs), commits._commit,
_verify_candidate, revert, heal, recover, in_flight_ids, workcopy sync/edit/overlays, viewpool, userscripts, the
PyO3 binding and HYDRALYSIS_IMPL=rust. All black-box classes (RealEngine*, test_view_leak, test_viewpool, test_publish*)
remain Python-only.

## Stage 4 (third session)
| Rust test | What it proves | Python tests it stands in for (white-box part) |
|---|---|---|
| tests/py_rebase.rs | views.rebase on a lineage with a published generation: clean, converged, unprobed, conflict (unresolved), take_mine, keep, stale expect_revision. Engine calls are the same fake table on both sides (Python monkeypatches workcopy.heal/_sync/probe, query.open_program, _adopt_copy); result JSON and resulting store equal | test_views.py rebase cases |

## Stage 5 (fourth session)
tests/common/mod.rs holds the shared harness (Python runner, normaliser, the `Fake` host, the Python-side fake prelude).
| Rust test | What it proves | Python tests it stands in for (white-box part) |
|---|---|---|
| tests/py_merge.rs | views.merge: clean (4 merged), mixed conflict (unresolved), take_mine, keep, no engine effects (before_unknown), pending destination (sync + refresh path), unknown-before refused/allowed, published_through, already-merged crash leftover, stale expect_revision. Result and both stores equal; new random ids masked | test_views.py merge cases |
| tests/py_seal.rs | views.seal_changeset: sealed, reused (second identical publish), missing confirmation, revision_changed, nothing_to_commit, before_unknown refused/allowed, bad option. Result and the sealed file (read by Rust on both sides) equal | test_views.py seal/queue cases |

Not ported (was: Still NOT differentially tested: merge, seal_changeset): publish job/drain, commits._commit,
revert, workcopy, viewpool, userscripts, leader, PyO3 binding / HYDRALYSIS_IMPL=rust.
Cargo.toml: the only machine-local paths are the hy-core / hy-store lines (marked TODO); switch to ../hy-core, ../hy-store at merge.

## Stage 6 (publish leader and job)
New modules: generations (tree_files, write/verify_manifest, tampered, reserve_generation, next_generation), publish (count_failure,
reconcile, build/_build_locked decision half, drain, settle_one, run_publish_job, await_turn, wait_decision, outcome_of);
locks::LaneLock::queued (Python _QueuedLock); Host gains `publish_candidate`, `retire_copies`.

Seam: `views._publish_candidate` (fork, replay, save, manifest, verification, seal, the CURRENT.log line, warm_base) is the
engine-bound step and stays behind `Host::publish_candidate`; everything around it is native.

| Rust test | What it proves | Python tests it stands in for (white-box part) |
|---|---|---|
| tests/py_drain.rs drain_matches_python | drain with both implementations driving the same queue and the same fake candidate builder: clean batch (2 views, one generation), changeset-wide conflict (declined) beside a published one, all values converged, counted failures until candidate_failed (batch retried alone), corrupt changeset, reconcile of a leader that died after its log line (result resolved from the manifest), tampered generation (rollback line, then `tampered` refusal), lock held (led:false). Drain result, every record under the lineage folder, the log lines, both stores equal; the Rust-written MANIFEST.json is byte-identical to Python's | test_publish*.py queue/leader cases |
| tests/py_drain.rs publish_job_matches_python | run_publish_job: published (first and second changeset), publish_conflict with its `next`, candidate_failed after MAX_ATTEMPTS, publish_wait_expired | test_publish*.py job cases |

Python defect found: `run_publish_job` raises `ViewError("publish_wait_expired", ..., csid=csid, **pending_info(...))`, and
pending_info already carries `csid`, so Python raises TypeError ("got multiple values for keyword argument 'csid'") instead of the
structured error. The port raises the structured error; the test asserts the TypeError on the Python side and compares state only.

Not ported in this stage: tamper cache (`tampered_cache_s` > 0 re-hashes every time, same answer), FaultInjected
`publish.append_torn` (inside the candidate step), the engine-bound `_publish_candidate`, `_verify_candidate`.

## Stage 7 (commit lifecycle without the engine)
Module lifecycle: recover, in_flight_ids, revert (+ rehydrate from the archive), heal, close_intent, request_abort, find_lineage.
| Rust test | What it proves | Python tests it stands in for (white-box part) |
|---|---|---|
| tests/py_lifecycle.rs | 27 scenarios built on disk in two roots, run by each implementation, results + CURRENT.log + intent logs + store equal: recovery (roll forward, roll back on a tampered generation, unpublished candidate, after PREPARE, backup kept, nothing to do), revert (ok, stale expect, not latest, wrong view, previous generation gone, rehydration from the archive, archive mismatch, revert of a reverted commit, nothing to revert, commit lock busy), heal (rolls forward, closes the intent, finishes a revert, nothing, busy), in-flight ids (dead, live, published, settled), abort (requested, too late). Slow (about 200 s: the Python side) | test_commit.py recover/revert/heal cases |

Not ported: `commits._commit`, `_verify_candidate` (engine-driven candidate build; stays Python, as `views._publish_candidate`).
