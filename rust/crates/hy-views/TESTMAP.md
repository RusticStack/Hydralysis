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
