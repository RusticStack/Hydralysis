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

## Stage 8: PyO3 binding and HYDRALYSIS_IMPL=rust routing

- `native/src/views.rs` exposes `views_call_rs(name, json_args)` (JSON in, JSON out, error kinds view/runtime/value/other).
  Routed (disk-level only): `views.live_generations, master_ids, editors_since, outstanding, reserve_generation, validate`
  and `commits.recover, in_flight_ids, request_abort, revert`. Wrapper: `src/hydralysis/viewnative.py` (`routed`).
- Python stays the default and the fallback: no variable, no native module, or a module without the binding runs the original.
  The wrapper also runs the original while a Python-side seam is active (HYDRALYSIS_TEST_FAULT, a patched
  `durable.replace_file`, a patched `workcopy.MAX_OVERLAYS`), because the Rust code cannot see those.
- Results (Python 3.15, release .pyd from `C:/dev-overflow/claude-tmp/views-pyd`):
  - default (variable unset): test_views, test_commit, test_view_base, test_viewgov: 248 tests; the two k11 agent-process
    tests (12 and 24 agents) hit `LockBusy .targets.lock` under heavy machine load; alone (`AgentProcesses`, 7 tests) all pass.
  - `HYDRALYSIS_IMPL=rust`: the first full run failed 3 tests that rely on the Python seams above; fixed by the guard, those
    tests then pass in rust mode.
- Not ported: workcopy sync/edit/overlays, viewpool, userscripts, the in-process leader; engine-bound `_publish_candidate`,
  `commits._commit`, `_verify_candidate` (they stay Python behind the Host trait); rebase/merge/drain/job are not routed
  (tested only differentially in Rust).
- Known defect in Python: `run_publish_job` publish_wait_expired path raises TypeError (csid passed twice).

## Stage 9: workcopy, userscripts and viewpool (this branch: r/hy-workcopy)

New modules: `workcopy` (engine-free logic and the engine-bound steps behind the `Host` trait), `userscripts`, `viewpool`.
`Host` gained `attribution()` (default `settle::attribution()`; the Python host answers with `settle.attribution()`).

| Rust test | What it proves | Python tests it stands in for |
|---|---|---|
| src/userscripts.rs (5 unit tests) | `check_options`, `choose` (levels, `not_available`), `list_scripts` (Python `splitlines`, `strip`, suffix, Windows case-insensitive order), `stage` (owners.json, sealed) | test_userscripts.py option, choice, listing and staging cases |
| src/workcopy.rs (10 unit tests) | `prefix_matches`, `same_base`, `base_key`, archive and corpus stores, `replayable` | test_store_v3.py prefix cases, test_archive_import.py |
| tests/py_workcopy.rs (6 differential tests) | `revert`, `edit`, `add_proposals` (results and resulting stores equal to the Python implementation, on a fake engine host), `base_master_gpr`, `read_gpr`, `prefix_matches`, `base_key`, corpus/archive stores, `forget_current` | test_workcopy*.py white-box cases |
| tests/viewpool.rs (10 tests) | warm worker reuse, busy workers, broken stub, idle sweep, keep_idle, close_all and shutdown, max_workers | test_viewpool.py Reuse, Failure and Idle classes (the stub worker of the Python tests) |

Routing (`native/src/views.rs`, `src/hydralysis/viewnative.py`, `workcopy.py`, `userscripts.py`, `viewpool.py`):
- Routed under `HYDRALYSIS_IMPL=rust`: `workcopy.base_master_gpr, read_gpr, store_corpus, store_archive, verify_archive,
  _replayable`; `userscripts.check_options, choose, list_scripts, _stage`; the process pool of `viewpool.dispatch`
  (`NativePool`, a `hydralysis_native.ViewPool`).
- Opt-in only (`HYDRALYSIS_ROUTE_HOSTED=1` as well): `workcopy.edit, revert, add_proposals`, through `workcopy_host_call_rs`
  with a Python host object (`WorkcopyHost`: heal, sync, attribution). Measured slower and fatter than Python (see the
  benchmark), so they are not on by default. Exceptions raised by the Python host travel through Rust unchanged.
- The Python original runs while a seam is replaced (`workcopy._SEAMS`), `MAX_OVERLAYS` changed, `HYDRALYSIS_TEST_FAULT` set or
  `durable.replace_file` patched.

Quirks kept (not fixed, to be reported):
- `_REBASING` is thread-local state shared with Python's rebase, so `forks_on_disk`, `superseded_forks`, `rebase_lane` are
  ported but not routed; likewise `forget_current`, `retire`, `prefix_matches`, `same_base`, `base_key`, `bases_root`
  (sub-microsecond bodies; JSON overhead would dominate).
- Python `edit` mutates the caller's `options` (pops expect_revision, corpus, archive); the Rust version does not.
- `state["fork_gpr"]` missing is a `KeyError` in Python; Rust mirrors it as `Runtime("'fork_gpr'")`.
- `KEEP_IDLE=0` makes Python's `[:-0]` empty, so no idle worker is ever stopped; mirrored.
- Python viewpool defect: `_stop` marks the worker `dead`, so `alive()` is false for stopping entries; the `STOP_GRACE` kill
  in the sweeper is never reached and entries are just dropped at the next tick. Preserved.
- Rust sweeper is deadline-driven instead of a 0.25 s poll: stop time is more precise (the one observable difference).
- `revisions::dependents` is quadratic in Python (a double loop per pass); the Rust version indexes the lowest `seq` per
  touched pair, same visiting order and same result.
- The parsed-store cache (`_LOADED`) is still not ported.

Not ported (stays Python behind `Host`): `_sync`, `_apply`, `release`, `discard_forks`, `userscripts.run`,
`views._publish_candidate`, `_verify_candidate`, `start_job`, `run_job`, `adoptable`, `views_status`, the leader's manifest
and done-record helpers.

Benchmark: `benchmarks/bench_workcopy.py` (CPU time and peak working set per child process, median of 5 to 7 runs, Windows,
a loaded machine with other builds running; `--impl rust-hosted` adds the opt-in edit path):

| workload | Python | Rust (`HYDRALYSIS_IMPL=rust`) |
|---|---|---|
| files: store_archive + verify_archive + store_corpus of a 192 MiB file | 0.516 s CPU, 34.1 MiB peak | 0.375 s, 30.7 MiB (27 percent less CPU) |
| scripts: 30 list_scripts of 1500 scripts + 60 check_options | 0.297 s, 28.0 MiB | 0.109 s, 25.9 MiB (63 percent less CPU) |
| viewpool: 200 dispatches to a warm stub worker | 0.031 s, 25.7 MiB | 0.016 s, 26.0 MiB (at the clock's 16 ms tick: no real difference) |
| edit: 40 edits + 10 reverts + summary/changes on a 3000-record view, engine stubbed | 5.1 to 6.7 s, 87 MiB | not routed by default; `rust-hosted` 9.7 to 10.1 s, 172 MiB (about 1.9x the CPU, 2x the memory) |

The hosted edit/revert/add_proposals are therefore opt-in. In-process the Rust edit costs about 80 ms CPU on that view
(load 20, save 30) against about 50 ms in Python, which reuses the parsed store and its append log; the rest of the gap
and the memory are the `serde_json::Value` copies a store of 3000 records needs in Rust (a copy per load, per save and per
handoff to the Python host). With `HYDRALYSIS_IMPL=rust` alone, the edit workload is slower still (14 s, 167 MiB): there
the Python `load_store`/`_save_store` call the earlier storage-lane functions (`hydralysis_rs.storelog_read`,
about 200 ms per call on this view, `storelog_save`, `storelog_known_edits`), and that is not this stage's code.

## Python seam: `proc.popen` and the warm pool (branch r/hy-parityfix)

`viewpool.dispatch` hands a publish job to the native pool (`hydralysis_native.ViewPool`) under `HYDRALYSIS_IMPL=rust`, which starts its
warm workers in Rust. A test that patches `hydralysis.proc.popen` (test_query::ViewsThroughQuery::test_the_publish_job_runs_end_to_end_through_its_own_worker_record)
expects the spawn to go through it, so while `proc.popen` is patched `dispatch` serves the job from a Python `Pool` kept apart from
the native one (`viewpool._POPEN_SEAM`, `_SEAM_POOL`). Production pays one identity comparison per dispatch.
