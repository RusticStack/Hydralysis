# PR #6 traceability: what the two review comments asked for, and where each ask stands

As of 2026-10-27. Written against Hydralysis (formerly RusticRE) PR #6 at `f46788b`.

## 1. Purpose, sources, vocabulary, evidence rule

**Purpose.** The owner left two review comments on RusticStack/RusticRE PR #6. This file turns every ask in
them into a numbered requirement and records, for each one, what is actually done, what proves it, which
work package of the protocol-3 plan covers it, what is left, and the command that would prove it. It also
lists the asks that no work package covers, proposes packages for them, and gives the path to "every P0
satisfied". It is a status document, not a claim of completion: nothing here is rounded up.

**Sources of truth (the requirements).**

- Comment 1 (`C1-xx`): https://github.com/RusticStack/RusticRE/pull/6#issuecomment-6442759957
  ("What now works", "Missing item 1-10", and the P0/P1 lists).
- Comment 2 (`C2-xx`): https://github.com/RusticStack/RusticRE/pull/6#issuecomment-6443193867
  (the RusticRE and Hydra Engine checklists with pass criteria, and the omitted comparison data).

The numbering is ours. `C1-35` to `C1-43` are the nine P0 bullets of comment 1, `C1-44` to `C1-50` the seven P1
bullets. Everything else is unlabelled. Several unlabelled items restate a P0/P1 item; the restatement is
named in the requirement text.

**Other inputs.** The protocol-3 spec, committed revision 4 (`ae9de0fdc0`, `PROTOCOL-3.md` on branch
`design/protocol-3`). A revision 5 exists only as an uncommitted working file
(`D:/Projects/Hydra/_logs/spec-rev5/spec-work.md`, 206 diff lines from rev4); this file cites rev4 and notes
where rev5 differs in the one item we know of (the reader-leave lock stall, see C1-45 and C2-39). Package ids (E0-E6, P1a, P1b, R1, Y0a-Y0e, Y1-Y3, Y4a, Y4b, Y4d, Y4e, Y5) are the spec's.
Proposed new packages carry a `Z` prefix so they cannot be mistaken for spec packages.

**Status vocabulary.**

| Status | Meaning |
| --- | --- |
| `done` | The stated ask is met and the reviewer saw evidence: a passing test run, a committed file, or (for a documentation or state item) the artifact itself at the cited commit or path. |
| `partial` | Some of the ask is met and evidenced; the rest is not. The "what remains" column says which. |
| `designed` | Spec text only. No code or test that proves the behaviour exists. |
| `not-started` | Neither design nor code. |
| `stale-claim` | The premise of the ask is disproved or historical; the real action is to record it correctly. |
| `decision-needed` | Blocked on an owner choice. Listed in section 7. |

**Evidence rule.** `done` needs an observed pass or an observed artifact. A test that exists but was not run
is not evidence. A test against `FakeEngine`/`fakehydra` proves logic, not engine behaviour, and is labelled
"fake". A single measurement is "one run", never a distribution. "Unmeasured" means no number was recorded by
anyone we can cite. A figure that appears only in the owner's comment is "owner-reported, not reproduced".
`designed` means spec text only; `not-started` means neither. Where an item is covered by a package that
has not started, the status stays `designed` or `not-started`.

**Commits as of 2026-10-27 (read with `git rev-parse`).**

| Repo / branch | Commit | State |
| --- | --- | --- |
| Hydralysis `codex/complete-re-workflow` (PR #6 tip, pushed) | `f46788b` | Rename to Hydralysis 0.5.0.dev0, mandatory `expect_revision`, no-stock hygiene, golden harness, options fix, CI, durable IO, retry policy, MCP pools, catalog epoch. CI run 40577257118 on this head: all four jobs success (engine job: 7 tests OK, 95.9 s). |
| Hydralysis `feat/w1-hydralysis` (worktree `D:/Projects/Hydra/wt/y-w1`, read-only here) | `8e696e2` Y0e, `99212af` Y1 | Both committed in the worktree, **not** on the PR branch, not run for this document. The worktree also has uncommitted edits to `RusticQuery.java`, `workcopy.py`, `tests/test_query_script.py`. Treat as in progress. |
| Hydra Engine `release/hydra-3-rc` (pushed) | `b74e28157c` | Upstream merge, docs, licensing, platform limits. Release dry run 40576898783 was in progress when last checked; nothing merged, tagged or released. |
| Hydra Engine `main` | `a410b0c3bf` | Does not have the rc documentation. Its README still says "independent project" (README.md:13). |
| Hydra Engine `design/protocol-3` | `ae9de0fdc0` | Spec rev4, clean. |
| Hydra Engine `feat/protocol-3` | `f47ff15934` | E0 tests (baseline), local, not pushed. |
| Hydra Engine `feat/w1-hydra` (worktree `D:/Projects/Hydra/wt/hydra-w1`) | `fa7079b4b2` | P1a committed; E1 in progress (uncommitted). |
| Hydra Engine `feat/session-extract` | `b6df709e1e` | Not used as evidence here. |
| This file | branch `docs/pr6-traceability` (worktree `D:/Projects/Hydra/wt/rre-trace`), from `f46788b` | Not pushed. |

Hydra releases: `v12.3-hydra.2` is the latest public release (2026-10-26). hydra.3 is a candidate only.
Hydralysis has no release, no tag, and its repository is private (`gh repo view`).

## 2. Summary

### 2.1 Requirements by status (109 requirements)

| Status | Count | Ids |
| --- | --- | --- |
| done | 5 | C1-10, C1-19, C1-32, C2-07, C2-31 |
| partial | 68 | see tables |
| designed | 13 | C1-18, C1-28, C1-29, C1-45, C2-05, C2-06, C2-09, C2-10, C2-11, C2-15, C2-37, C2-39, C2-52 |
| not-started | 17 | C1-02, C1-03, C1-13, C1-15, C1-16, C1-22, C1-25, C1-34, C1-38, C1-44, C2-04, C2-12, C2-23, C2-24, C2-25, C2-29, C2-51 |
| stale-claim | 1 | C2-55 |
| decision-needed | 5 | C1-30, C2-16, C2-50, C2-53, C2-54 |
| **Total** | **109** | |

Only 5 of 109 are `done`, and none of the nine P0 items is `done`. Two of the five (C1-32, C2-31) are
documentation or state items with no test enforcing them.

### 2.2 By priority and status

| Priority | Total | done | partial | designed | not-started | stale | decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P0 | 9 | 0 | 8 | 0 | 1 | 0 | 0 |
| P1 | 7 | 0 | 5 | 1 | 1 | 0 | 0 |
| unlabelled | 93 | 5 | 55 | 12 | 15 | 1 | 5 |
| **All** | **109** | **5** | **68** | **13** | **17** | **1** | **5** |

### 2.3 By theme

| Theme | Total | done | partial | designed | not-started | stale | decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| concurrency | 16 | 3 | 12 | 0 | 0 | 1 | 0 |
| release-ci-bench | 16 | 1 | 4 | 1 | 7 | 0 | 3 |
| lanes-platform-fork | 21 | 0 | 16 | 4 | 0 | 0 | 1 |
| durability | 7 | 0 | 3 | 4 | 0 | 0 | 0 |
| import-export-golden | 15 | 0 | 9 | 1 | 4 | 0 | 1 |
| runtime-evidence | 17 | 0 | 12 | 0 | 5 | 0 | 0 |
| supervision-root | 9 | 0 | 5 | 3 | 1 | 0 | 0 |
| no-stock-surface-gui | 8 | 1 | 7 | 0 | 0 | 0 | 0 |
| **Total** | **109** | **5** | **68** | **13** | **17** | **1** | **5** |

### 2.4 Coverage by the protocol-3 plan

49 of 109 requirements have **no work package at all** (covered by `NONE`): 17 of 17 in runtime-evidence, 9 in
release-ci-bench, 7 in no-stock-surface-gui, 6 in import-export-golden, 4 in concurrency, 4 in
lanes-platform-fork, 1 in durability, 1 in supervision-root. Of the nine P0 items, four have no package
(C1-38, C1-40, C1-41, C1-42) and two more have a package that does not cover the actual ask (C1-37, C1-39:
the engine packages cover queues and script modes, not Hydralysis prepare on a real binary or script
migration). The spec rev4 contains no package for runtime or evidence parity, for the 12.1.4 to 12.3 golden
comparison, for the full-corpus export, or for the Hydralysis-side concurrency guard. Section 5 lists them.

### 2.5 The P0 list

| Id | P0 ask | Status | What blocks "done" | Packages |
| --- | --- | --- | --- | --- |
| C1-35 | Durable annotation commit/export/import, hash- and revision-bound | partial | The store is sealed, fsynced and hash-bound (Y0a, shipped). No commit, export or import path exists on the PR branch. Y1 (store v3, bundles) is committed only in `y-w1`; Y2 (commit as a new generation) and E2 (engine gate, backup) are not started. | Y1, Y2, E2, Y4d |
| C1-36 | Mandatory optimistic concurrency; per-agent views by default | partial | Mandatory `expect_revision` is done and pushed (de1b763). Per-agent default views are deferred by design (D26, Y5, OD7). No race test exists. | Y1, Y3, Y5, Z1 |
| C1-37 | Fresh import/analysis of a new executable | partial | Fresh `prepare` is proven only on `whoami.exe` and, by hand, on 8 MSVC fixtures. No KotOR-scale run, no cancel/kill/concurrency test on a real engine. | Z5 (E3a, E6 are engine-side only) |
| C1-38 | Full export | not-started | No full-corpus export has been run through the export job. No expected-count field. | Z6 |
| C1-39 | Script migration | partial | `RusticQuery.java` runs on 12.3 in every engine test; user-script staging has no test and no real-engine run; `.py` unproven. | Z5, E4, Y4e |
| C1-40 | Golden 12.1.4 to 12.3 decompile diff | partial | The harness and a real diff exist and the diff FAILS its own 98% proposal (77.124% identical). It is confounded by a decompiler option and has no accepted-difference policy. No gate or package owns it. | Z7 |
| C1-41 | Runtime/debug parity (attach, breakpoints/watchpoints, memory, modules, capture/compare) | partial | Attach/spawn/modules/read/break exist and pass fake-Frida unit tests plus a manual real-Frida smoke outside the repo. No write, no watchpoints, no capture/compare. No package. | Z9, Z10, Z11, Z12 |
| C1-42 | Evidence/coverage contract and exportable bundles | partial | Only a claims ledger with row export. No content-addressed id, coverage, limitations, bundle. No package. | Z9 |
| C1-43 | One supervised daemon per root, health probe, harness startup diagnostics | partial | Inline ping probe and lazy respawn exist; no periodic probe, wedge detection or restart policy; `doctor` answers `not_available`. E5, P1b, Y4a, Y4b not started; Y4b is the last package in W6. | E5, P1b, Y4a, Y4b, Z3 |

**Bottom line.** Hydra plus Hydralysis is better than lock-based GhidraMCP and the old busy-lock RusticRE for
static multi-agent queries (the concurrency items that are measured pass in the verifier's runs, as single
runs). It is not yet a replacement for REA's runtime and evidence breadth or for Ghidra's durable annotation
store, and this file does not support saying otherwise until the P0 list is met (see C1-51).

## 3. Requirements by theme

**Command key.** Commands run from the Hydralysis repository root unless stated. `U <mods>` means
`$env:PYTHONPATH='src;tests'; python -m unittest <mods>` (PowerShell). `E <mods>` is `U` with
`HYDRALYSIS_INTEGRATION_ENGINE`, `HYDRALYSIS_INTEGRATION_CLIENT` and `HYDRALYSIS_INTEGRATION_JAVA` set to a Hydra
install (see `docs/ci.md`) and `HYDRALYSIS_TEST_ROOT` on D:. `DT` means, in the Hydra repo,
`python Ghidra/Features/HeadlessSession/examples/daemon_tests.py --ghidra <install> --work <dir on D:> --exe A.exe --dll B.dll`.
"(to write)" means the file or command does not exist today. Single-run figures are "one run". The "Covered by"
column names spec packages; `NONE` means the plan has no package for the ask, and the Z package that would own
it is named in "what remains" and defined in section 5.

Evidence shorthand: "V:" is a reviewer's run during this investigation (logs under
`D:/Projects/Hydra/_logs/<stream>/`); "CI:" is GitHub Actions run 40577257118 at `f46788b`; "spec:" is
`PROTOCOL-3.md` rev4.

### 3.1 Concurrency

| Id | Requirement | Status | Evidence | Covered by | What remains | Acceptance command |
| --- | --- | --- | --- | --- | --- | --- |
| C1-01 | 2 and 3 simultaneous `ghidra_query` succeed; no per-target `.request.lock`; Hydra schedules | partial | V: `concurrency-verify/conc_probe.py` (probe2.json), pinned hydra.2, fresh `whoami.exe` project: 1, 2, 3 and 12 simultaneous calls all ok, no busy error; one run, tiny fixture. `query.py` never imports `locks.py`; the only `.request.lock` left is `runtime.py:240` (runtime session). Committed tests use fakes (`tests/test_mcp_transport.py`: 50 tests ok); `tests/test_engine_integration.py` has no concurrent call. Calls stair-step about 15 ms each; `ghidra_query` is engine `script` (`query.py:90`) and the engine puts `script` in the LONG lane (`Scheduler.laneOf`); 12-call burst gave long lane `everQueued` 6 (queued, not failed). | NONE | Z1: committed guard (no `LaneLock` in the query path; Barrier-started N=2, 3 and maxLong+1 against a real engine, all ok, no `busy`; in the CI engine job). Re-run through the MCP path on KotOR (only native decompile was run there). Y4a (explicit `lane:'quick'`) is what fixes the long-lane sharing. | `E test_concurrency` (to write); today one-off: `python D:/Projects/Hydra/_logs/concurrency-verify/conc_probe.py` |
| C1-04 | 2x20 concurrent decompiles 850 ms (1.9x), `everQueued` 0 | partial | The 1.9x figure is the NATIVE decompile command in the QUICK lane, not the agent path. V: KotOR copy, same 8,966 functions, hydra.2, 2 connections x 20 distinct cold functions: serial 16.0 ms/call, concurrent 321 ms for 2x20 (about 1.99x), quick `everQueued` 0 (kotor.json). Noisy: serial sets of 20 took 213.6 and 425.6 ms; not the owner's 44.8 ms/call. On the `ghidra_query` path with the whoami fixture: 1.39x and long-lane `everQueued` 6. Engine suite `t_two_projects` and `t_fairness` ok (`_logs/hydra3-rc/daemon.log`). E0 `lane_starvation` confirms the premise (8053-8265 ms vs 3000 ms bound). | E0, E3a, E6 | Decide what the guard means: (a) native decompile 2x20 on KotOR pinned by SHA-256, 5 repeats, median and spread, speedup >= 1.5x and quick `everQueued` 0; (b) agent-path speedup and long-lane `everQueued` reported separately. Stop calling 1.9x the agent-path figure. No package owns either: Z2 (benchmark) with Z1. | `python D:/Projects/Hydra/_logs/concurrency-verify/kotor_probe.py` (one-off); `benchmarks/concurrency_bench.py` (to write, Z2) |
| C1-05 | Read-only views take no lock; two daemons read one project at once | partial | V: `two_daemons.py` (two.json): two hydra.2 daemons (pids 29740, 38708, distinct state dirs) opened one KotOR copy read-only simultaneously, 8966 functions, 20 decompiles each, both ok, no lock error. Engine README states it; characterization scenario `clients` and `t_revisions` cover neighbouring cases. No committed test opens two daemons read-only at once. | NONE | Add engine test `two_readonly_daemons` (assert source tree hash unchanged) and a Hydralysis check. Relates to P1b `duplicate_daemon` (opposite direction) and OD3. Amendment A2. | `DT --only two_readonly_daemons` (to write); one-off `python D:/Projects/Hydra/_logs/concurrency-verify/two_daemons.py` |
| C1-07 | Rename in view `bench` visible only there; shared view unchanged | partial | `tests/test_query.py:173-186` (fake engine): alice and bob views isolate, shared keeps `FUN_140001000`, stale edit in alice conflicts. Real engine: `test_engine_integration.py:145` checks revisions and rebase, not shared-view isolation (V: 7 tests ok, 46.7 s). Engine `t_overlays` ok. | Y1, Y3 | Real-engine assertion: rename in `bench`, shared view unchanged, `bench` changed. Y1 (store v3) rewrites `workcopy.py`; the test must exist before Y1 merges. Amendment A3. | `E test_engine_integration` (existing); `test_named_view_edit_is_invisible_in_the_shared_view` (to write) |
| C1-08 | Revert of a per-client view returns revision 2 and a clean status | partial | `tests/test_query.py:208-217` (fake, shared view): revision 2. Real-engine `test_overlay_edit_read_and_revert` (`:130`) checks the name returns. Not asserted: named-view revert on a real engine, and a "clean" status. | Y1 | Add named-view revert on the real engine; assert status after revert. Y1's `has_dependents` refusal means revert of an earlier record in a chain is no longer always revision+1: keep the contract explicit. | `U test_query` plus extended `test_overlay_edit_read_and_revert` (to write) |
| C1-09 | Shared writers see each other's edits live | partial | Engine `t_shared` (`daemon_tests.py` 2036-2150) and `shared_stress` (4 clients x 2 threads, 3200 edits) ok in `_logs/hydra3-rc/daemon.log` (31/31). Hydralysis: all agents of a target share one working copy under `.sync.lock` (`workcopy.py:536`, `SYNC_LOCK_S=900`); no test drives two clients. | Y3, E6 | Hydralysis-level two-writer test (Z1). Note: readers wait on `.sync.lock` up to 900 s while a stale working copy rebuilds. | `DT --only shared,shared_stress`; `U test_concurrency` (to write) |
| C1-10 | Stale `expect` on a shared write gives a conflict | done | Engine `t_shared` asserts conflict with `details.current` and `holderInfo`; Hydralysis `tests/test_query.py:238`, real-engine `test_engine_integration.py:145`; `workcopy.require_revision` at `workcopy.py:507`. V: 50 unit and 7 integration tests ok. | E1, Y1 | Nothing for Hydralysis. Engine-direct clients: on protocol 2 the engine ignores `expect` on signature and data_type; `requireExpect` is documented but not built (E1 adds v3 enforcement). | `U test_query test_revisions`; `DT --only shared,edit` |
| C1-11 | Journal records both authors | partial | Engine journal asserted in `t_shared` (`daemon_tests.py:2082-2088`). Hydralysis records `by={client:'<attribution>:<pid>', harness}` (`workcopy.py:125-128`); `tests/test_query.py:210-213` asserts one author. Authors are process ids: ten agents behind one MCP server are one author. | Y1, Y5 | Two-author Hydralysis journal test (Z1). Stable agent id (`options.as`) is a Y5 precondition (OD7), not scheduled. | `U test_query.test_the_journal_names_both_authors` (to write) |
| C1-19 | Make `expect_revision` mandatory on shared edits, or per-agent default views | done | Option 1 pushed: commit de1b763 in `origin/codex/complete-re-workflow`. `workcopy.require_revision` (`workcopy.py:507-512`) raises `expect_revision_required` carrying the current revision; `query.py:146-148`. `tests/test_query.py:188`, `test_engine_integration.py:145`, `tests/test_revisions.py`. README.md:108-114 documents it. Spec D5. V: unit and integration runs ok. | Y1, Y3, Y5 | Done for the stated ask. Open: the race form (two threads, same `expect_revision`: exactly one succeeds, revision +1) holds by code reading only; Z1 owns the test and it must land before Y1 merges. Per-agent default (option 2) deferred (D26, Y5, OD7). | `U test_query test_revisions`; `U test_concurrency.SameAddressRace` (to write) |
| C1-33 | Qualify "writes never collide": last-writer-wins unless `expect` | partial | Hydralysis README.md:108 qualified (pushed). Hydra on `release/hydra-3-rc` (`b74e28157c`) README.md:146 and :297, CHANGELOG.md:24, release notes :88 carry the qualified wording; hydra-engine `main` does not. Two sentences on the rc branch are still overstated: README.md:44-46 ("its locks are freed"; analysis in the long lane while others' queries keep flowing in the quick lane) and module README.md:669. E0 disproves both for scripts and for a client blocked in a lock wait (`_logs/E0/baseline2.json`). | R1 | Publish the qualified wording to main and the release notes; qualify the two overstated sentences until E3a/E3b land; state `requireExpect` is not built. Amendment A6. | `rg -n -i "never collide|never overwrite|keep flowing in the quick lane|its locks are freed"` on both READMEs shows none or only qualified wording |
| C1-36 (P0) | Mandatory optimistic concurrency; per-agent views by default | partial | First half done (see C1-19). Second half deliberately deferred: README.md:111 "per-agent views by default is deferred until publish/merge exists"; spec D26, Y5 (W7), OD7. | Y1, Y3, Y5 | Y1, Y3, then Y5 after its four preconditions (Y3 soaked, stable agent id, view eviction, measured per-phase named-view cost). | `U test_views.test_default_view_is_per_agent` (to write, Y5); Z1 race test |
| C1-47 (P1) | Soak: dead-client lock release | partial | Engine `t_client_kill` passes (lock free 372 ms after kill) but only for a client running analysis; `t_import_kill`, `t_shared` ok. E0 `dead_client_lock_wait` CONFIRMS the gap on hydra.3: a client killed while blocked in `wait=3600000` stays registered 40+ s (`Connection.java:101-102`, 600 s `CLEANUP_WAIT_MS`). Hydralysis `locks.py` file locks are OS-released; no test. E6 not started. | E3b, E6, Y4a | E3b bounded release; E6 seeded kills; add a Hydralysis test that kills a process holding `.sync.lock` mid-edit and checks the next edit proceeds. | `DT --baseline` (must CONFIRM today); after E3b `--only dead_client_lock_wait`; `python examples/soak_tests.py` (to write) |
| C2-07 | Two agents editing one address cannot silently overwrite | done | Same fix as C1-19. `tests/test_query.py:238`: stale edit gets a conflict naming `latest_editor` and the overlapping subject; name stays `One`. Real engine `test_engine_integration.py:145` ok (V: 46.7 s). | Y1, Y3, Y5 | The simultaneous (race) form is untested (Z1). A subject-disjoint stale edit is rebased and applied by design (`rebased:true`). | `U test_query.Overlays`; `U test_concurrency.SameAddressRace` (to write) |
| C2-35 | Document and test: one program writer unless `share:true` | partial | Module README (rc) table "Who can do what at the same time", lines 678-702; `t_shared`, `holders`, `overlay_owned` ok. Not documented: the long lane has no queue position or ETA; default imports are `min(4, cpus/4)`, not a flat 4; `maxLong = max(2, cpus/4)`. No test uses 10+ clients. E0 baseline shows the starvation premise (see C2-39). | E0, E3a, E3b, E6 | E3a/E3b/E6 for the pass criteria; R1 docs state the sizing and that `ghidra_query` is long-lane work until Y4a sends `lane:'quick'`. | `DT --baseline`; after fixes `--only lane_starvation,maint_lane,fair_key,queue_info,import_wait,cancel_queued`; `soak_tests.py` |
| C2-55 | Old RusticRE PR6: 1 of 2 and 2 of 3 simultaneous queries failed | stale-claim | Historical, owner-reported. The failing build is pre-Hydra (before commit a495ea9); the current tree has no query lock (C1-01). Reproducing needs stock Ghidra, which the no-stock rule forbids. No repo doc records the figures. | NONE | Record as owner-reported historical data with source and old commit, "not re-run", next to the 0.4.0 result (Z13). No engineering package. | `rg -n "1 of 2\|2 of 3" docs` shows the sourced row once added |
| C2-56 | New 0.4.0: 2 and 3 simultaneous queries succeed | partial | Same as C1-01 (2/2, 3/3, 12/12 ok on HEAD with pinned hydra.2). "0.4.0" was `f03f334`; HEAD is 0.5.0.dev0 with a changed retry policy, MCP pools and durable IO. The owner's KotOR MCP latencies (function 24, decompile 61, status 22 ms) are not reproduced. | NONE | Z1; re-run at each wave tip (Y1, Y2, Y4a changes pool entries and deadlines); keep a table in `docs/verification.md`. | `python D:/Projects/Hydra/_logs/concurrency-verify/conc_probe.py` |

### 3.2 Release, CI and benchmarks

| Id | Requirement | Status | Evidence | Covered by | What remains | Acceptance command |
| --- | --- | --- | --- | --- | --- | --- |
| C1-02 | Warm MCP latencies: function 24, decompile 61, status 22 ms | not-started | No latency guard anywhere at `f46788b` (`benchmarks/` holds only `crossbuild_match.py`). The figures are one owner run, function size not stated. V: `tools/golden.py timing` on `_golden/baselines/hydra-2/kotor/production`: 8616 rows median 20.0 ms, p95 55.7 ms; large (>512 B) median 43.2 ms, p95 267.7 ms; first-touch calls, not warm repeats. Spec rev4 has no package; spec rule 3 freezes existing `benchmarks/` files. | NONE | Z2: harness that spawns the real stdio MCP server against a pinned target and function, discards warm-up, N>=30 warm calls of `function`, `ghidra_query` decompile and `status`, records median/p95/max with engine release, machine and program SHA-256; report-only budgets; owner machine only, never hosted CI. | `python benchmarks/mcp_latency.py --target <t> --function va:0x... --runs 30` (to write) |
| C1-03 | Hydra direct 20 serial decompiles 896 ms (44.8 ms/call) | not-started | Owner-reported, not reproduced; the harness that produced it is in no repo. 44.8 ms fits the engine README's 35-45 ms large-function range (a 29-block function), but function size is not stated. | E6 (p99 bound only) | Z2: throughput guard on one pinned function; state function address, size and program. | `bench_decompile.py --serial 20 --clients 2` (to write) |
| C1-13 | Backend install in about 18 s | not-started | No guard. Nearest: CI step "Download, verify SHA-256, unpack" 17 s on windows-latest (20:21:37 to 20:21:54, run 40577257118); that is `ci_engine.py`, not `backend install`, JDK from setup-java. Engine zip about 380 MB, so time is network-bound. | NONE | Z2: report-only timing of install from a pre-downloaded archive cache; never fail CI on download time. | `python benchmarks/bench_install.py --cached-archives <dir>` (to write) |
| C1-15 | Output size: function 0.58 KB, decompile 7.8 KB, dossier 28.1 KB, p-code 69 KB, trace 2 KB | not-started | Only a cap exists (32,000 chars of decompiler output, README.md:98). `docs/verification-complete-workflow.md:140` says sizes are bytes, not tokens. Figures are one KotOR run, function unstated. | NONE | Z2: fixture-based size budgets (public MSVC fixtures) per function size; KotOR numbers stay local evidence. The 0.5.0 options fix changes decompiled C for about one function in six, so budgets need headroom. | `HYDRALYSIS_INTEGRATION_FIXTURES=<dir> U test_output_size` (to write) |
| C1-16 | Comparison: GhidraMCP 7.3 KB / 64 KB, REA dossier 961 KB | not-started | Not recorded in any repo doc. `docs/tool-mapping.md` is a skeleton with "to verify" rows. Third-party, single run. | NONE | Z13: dated, sourced reference table, labelled not reproduced. Re-measuring needs REA and stock Ghidra (see C2-53). | `rg -n "961 KB\|7\\.3 KB\|64 KB" docs README.md` |
| C1-32 | Qualify the "~7 ms warm decompile" claim as size-dependent | done | Hydralysis README.md:7 and :123-125 ("Measured, not promised": 0.7-2.1 ms for a 1-byte function, 35-45 ms for a 6.7 KB one), commit 2245512 in `f46788b`. Engine: README.md:1071-1075 on `release/hydra-3-rc` (merged c75ac2e335 via docs/honest-claims), not on `main` yet. Caveats: the stored hydra-2 KotOR capture has one 1-byte row (n=1, 39.8 ms, cold), so 0.7-2.1 ms is not reproducible from stored captures; its large bucket is median 43 ms, p95 268 ms. No test enforces it. | R1 | Keep the qualification through R1's README rewrite; add percentiles; optional docs-lint test. | `rg -n -i "warm decompile\|about 7 ms" README.md` |
| C1-34 | A public versioned release (releases/latest was empty) | not-started | Still true: `gh api repos/RusticStack/RusticRE/releases/latest` 404, no tags, repo PRIVATE, version 0.5.0.dev0, no CHANGELOG, no release workflow. Engine has releases (`v12.3-hydra.2` public); hydra.3 is a candidate in dry-run CI. Hydralysis pins `RELEASE='12.3-hydra.2'` (`hydra.py:30`). Spec OD5 covers publishing hydra.4 and Hydralysis visibility; R1 forbids tag/push by its stream. | NONE | Z14: CHANGELOG, release workflow (sdist + wheel, SHA256SUMS, dry run), version policy. Blocked on OD5 (a private repo cannot have a public release). | `gh api repos/RusticStack/RusticRE/releases/latest --jq .tag_name` prints a version; fresh venv: install wheel, `hydralysis --version`, `hydralysis backend inspect` |
| C1-49 (P1) | Versioned release and upgrade/backup policy | partial | Engine release scheme and one-way upgrade advice exist on rc (`CONTRIBUTING.md` "Releases", release notes "Upgrading from 12.1.4 (one way)": "Keep a backup", advice only, not enforced). Hydralysis has an upgrade-from-RusticRE note only. Backup, restore and the upgrade gate are spec text (3.4, 4.5, D8/D12/D13/D28, gate 9.6, OD1); no backup code (`rg backup src` hits only `durable.py` `.bak`). | E2, Y2, Y4d, R1 | Implement E2/Y2/Y4d and gate 9.6. A written Hydralysis versioning and upgrade policy has no owner: Z14. | gate 9.6 script (to write); `tests/test_backups.py`, `tests/test_commit.py` (to write, Y2) |
| C1-51 | Guard the conclusion: not a replacement for REA runtime/evidence or Ghidra's durable store until P0 | partial | Prose guards exist (README.md:7, :169; `docs/capabilities-kotor.md:76-80`; `docs/clients.md:11`) but none states the PR conclusion; `docs/tool-mapping.md:3` says REA and GhidraMCP are "the two tools it replaced", which reads as full replacement. No mechanical check. | R1 | Z13: README "Evidence and limits" paragraph, fix tool-mapping wording, docs-lint test `tests/test_claims.py`. Re-check at each release against the P0 list. | `U test_claims` (to write); manual `rg -n -i "replac" README.md docs/*.md` |
| C2-08 | Track named-view work-copy cost (1.4 s; COW fork copy phase 95.6 ms) | partial | Instrumentation done: `workcopy.py:242` and `:409` report `last_sync.phases_ms` (master_open, fork, copy, base_upgrade, open, replay, total); V: `test_query.Overlays.test_sync_reports_stable_phase_timings` ok (0.119 s); `test_engine_integration.py:138` asserts the key is present. No recorded breakdown of the 1.4 s; spec D26 calls it a single unreproduced run. 95.6 ms may be the sum of two forks (base + working copy). D: is NTFS here; a ReFS number needs F:. | Y5 | Z2: N>=5 first-edit named-view builds on a KotOR copy, ReFS and NTFS, each phase plus engine clone/copy ms and bytes. Gate 9.10 lists it with no script. | `python benchmarks/named_view_cost.py --target kotor-copy --runs 5` (to write); existing `U test_query.Overlays.test_sync_reports_stable_phase_timings` |
| C2-47 | Document release cadence | partial | Process documented on rc (`CONTRIBUTING.md` "Upstream sync", "Releases"). No cadence, support window or security SLA anywhere (`rg` found none). Docs are on rc and docs/honest-claims, not on `main`. hydra.1 2026-10-26 10:28Z, hydra.2 18:57Z, hydra.3 candidate 2026-10-27. | NONE | Z15: cadence section (numbers are the owner's decision); Hydralysis line on how its pin follows engine releases. | `git show release/hydra-3-rc:.github/CONTRIBUTING.md \| rg -n -i "cadence\|support window"` |
| C2-50 | REA cold import/analysis 192 s | decision-needed | Owner-reported, not reproduced; no script. Re-measuring needs REA plus stock Ghidra, which conflicts with the no-stock proof machine. Own-side: engine README (rc) first answer 1.5 s for a same-format 243,855-function program; a fresh KotOR import on Hydra has never been timed. | NONE | Owner decision N8: record as dated historical reference or measure on another machine. The REA, Hydralysis and Hydra first-open figures measure different things; say so. | none possible without REA |
| C2-51 | RusticRE first query 7.6 s | not-started | No harness tracks it; 7.6 s is not decomposed (may include in-memory 12.1.4 upgrade, MCP start, JVM start). Engine README measures daemon start to first answer 1.5 s on a same-format program. | Y4a | Z2: cold-start breakdown (MCP start, daemon start, open, first answer), N runs, cold OS cache noted. | `python benchmarks/bench_cold_start.py --target kotor --runs 5` (to write) |
| C2-52 | Hydra first program open 4.3 s (one-time 12.1.4 to 12.3 upgrade) | designed | Scenario designed (gates 9.4 and 9.6 run on a legacy fixture); gate 9.10 does not list upgrade time. hydra.3 release notes say the legacy tests were skipped (no 12.1.4 project passed); engine README line 1087 says 21-24 s without the upgrade cache. Nearest measurement `_golden/baselines/upgrade/{A,B,C}.json`: 1.30-1.71 s but a same-format open (hydra.2 to hydra.3), not the 12.1.4 upgrade. | E2 | Log first-open time of the legacy fixture with the upgrade cache on and off, on a disposable copy; record as one-time cost. | `daemon_tests.py --legacy-project <12.1.4 copy>` (add printed `open_s`) |
| C2-53 | GhidraMCP second session fails on the project lock in 86 ms | decision-needed | Third-party figure, owner-reported. Needs stock Ghidra and the bridge (pinned `1e98025`): conflicts with the no-stock proof. | NONE | Owner decision N8. The own-side guard (simultaneous queries) is Z1. | none for the comparison |
| C2-54 | GhidraMCP init 3.3-4.0 s plus 2.2 s first open | decision-needed | Same constraint as C2-53. Own-side comparable numbers: engine README (rc) launch to ready 348 ms, open_program 847 ms, launch to first answer 1521 ms (medians of 9 interleaved rounds). | NONE | Owner decision N8. | none possible without stock Ghidra |

### 3.3 Lanes, platform and fork

| Id | Requirement | Status | Evidence | Covered by | What remains | Acceptance command |
| --- | --- | --- | --- | --- | --- | --- |
| C1-06 | `fork_project` on ReFS about 95.6 ms, 2.19 MB of 122 MB | partial | Correctness guard exists, numeric guard does not. Engine `t_fork` (`daemon_tests.py` 1367-1470) accepts clone or copy and records `copyMs` as a note. The only documented ReFS clone numbers are the 1.49 GB program: 204-225 ms, 2.8-5.0 MB (README:337-343, rc). 95.6 ms / 2.19 MB appears only in comment 1 (one run, not reproduced). Nothing runs on ReFS CI (`docs/ci.md`). E2 not started. | E2 | E2 `fork_report` ReFS-only numeric guard on a KotOR-sized project: `method=='clone'`, `cloned==True`, `freeSpaceUsedBytes` <= 5% of bytes, `copyMs` median of >=5 runs under a generous ceiling; skip loudly off ReFS. Re-measure once to confirm or retire the figures. Amendment A1. | `DT --project <KotOR copy on ReFS> --only fork_report` (to write, E2) |
| C1-30 | Use ReFS for COW (standardise the root) | decision-needed | The engine clones only on ReFS. Hydralysis has no filesystem detection; default root is `%LOCALAPPDATA%\Hydralysis` (`paths.py:23-33`); `fork_max_copy_mb` 8192 (`workcopy.py:265`) vs engine `forkCopyLimitMb` 2048, so on NTFS an edit can trigger a multi-GB copy. Spec 7.1 designs a doctor warning, not enforcement. ReFS has a measured cost: java.io.tmpdir on ReFS made program close take 22-41 s (README:1262-1266). | Y4b, E1 | Owner decision N6 (warn vs refuse). Then Y4b doctor file-system finding; engine `hello.platform.fileSystems/cow`; align fork limits; document tmpdir advice. | `U test_doctor` (to write, Y4b) |
| C1-31 | Do not read as independence from Ghidra | partial | Done on branches not merged: rc README.md:14, CHANGELOG hydra.3, release notes, NOTICE-HYDRA (`b74e28157c`); Hydralysis README.md:5 and THIRD_PARTY.md:7. `main` README.md:13 still says "independent project". Release dry run in progress, nothing merged. | NONE | Z15: finish dry run, merge, tag (owner action), verify the published body; add the phrase to R1's 5.2 mandatory lines (A6). | `gh release view v12.3-hydra.3 --repo RusticStack/hydra-engine --json body -q .body \| rg -c "fork of"`; `git grep -n -i "independent project" origin/main -- README.md NOTICE-HYDRA` prints nothing |
| C1-45 (P1) | Soak: 10+ clients, long vs quick lane | designed | No soak harness in any branch. Largest load: `shared_stress` (4 clients x 2 threads). E0 `lane_starvation` (one client): ten scripts took 8053-8265 ms vs 3000 ms bound, maxLong=2 (`_logs/E0/baseline1.log`, `baseline2.log`). Cause: `Scheduler.laneOf` puts `script` in LONG (`Scheduler.java:59-63`) and `query.py:90` sends every query as `script`. The rev5 draft adds a measured second cause: a leaving plain reader takes the exclusive program lock and freezes new joins for the length of a read (uncommitted). | E3a, E3b, E6, Y4a, E5 | Implement E3a, E3b, E5, Y4a, then E6 with 10+ OS-process clients plus a multiplexed profile (Hydralysis uses one connection per root with `parallel:true`). The spec's pass bound is "recorded by E0", but E0 recorded the FAILING latency: define a numeric bound first (A2). | baseline `DT --baseline --only lane_starvation` (must fail today); `python examples/soak_tests.py --clients 12 --seed 1` (to write) |
| C1-46 (P1) | Soak: import queue and cancellation | partial | Engine tests pass individually (31/31 on rc): `import_queue`, `import_kill`, `parallel_imports`, `cancel_all`, `client_kill`. Not exercised: imports in a mixed 10+ client load; queued import after a long wait (E0 `import_wait` CONFIRMED: fails `busy` about 20 s in, `ImportCommands.java:112`); imports through Hydralysis. E6's text lists no imports. | E3a, E6, Y4a | E3a import-wait fix; amend E6 with a standing import load, queued-import cancels and a kill in the queue (A2); Hydralysis records queue info in the prepare job record (Y4a). | `DT --only import_queue,import_kill,parallel_imports,cancel_all`; `--baseline --only import_wait` |
| C2-06 | ReFS must be used for COW work | designed | Hydralysis records fork details per sync (`workcopy.py:326`, `:390`: method, cloned, bytes, copyMs) so it is observable after the fact; nothing asserts it (`tests/fakehydra.py:293` hard-codes `cloned True`); no doctor. `docs/ci.md` says ReFS claims are never validated by CI. | Y4b, E2 | Y4b doctor finding; env-gated real-engine assertion `fork.cloned == True` on the Dev Drive. Not automatable on hosted CI. | `U test_doctor`; `E test_engine_integration -k clone` (to write) |
| C2-34 | Document and test: a writable project holds one OS lock | partial | Docs on rc (module README "Several clients", "Who can do what"). Tests: `t_holders` (`daemon_tests.py` 1345-1354), `not_owner` 1309-1319, fork refusal 1469-1475. Orphaned shared work keeps the lock until daemon shutdown (`Session.java:2603`, test `orphan_shutdown`). | E6 | State it in the hydra.4 limits (gate 9.11); E6 must include a second process contending for the project lock and a client killed while holding it. | `DT --only holders`; soak (to write) |
| C2-36 | Document and test: imports queue at `maxImports` (4) | partial | Documented and tested (`import_queue`, `parallel_imports`; queue FIFO, visible in `status.imports`). The "(4)" is imprecise: default is `max(1, min(4, cpus/4))` (`ImportGate.java:96-98`) and each import also holds a long slot, so the limit is `min(maxImports, maxLong)`. Known defect: E0 `import_wait` CONFIRMED (20005 ms). | E3a | Implement the E3a import-wait fix and its two v2 tests; correct the release-note wording. | `DT --only import_queue,parallel_imports`; `--baseline --only import_wait` |
| C2-37 | Long-lane queue ETA and queue position | designed | Premise true for the general long lane, false for imports (`ImportGate` already has position and estimate, but times only the load). `Scheduler.admit` reports no queue info (`Scheduler.java:155`). Spec 3.4/3.5 designs position/ahead and an ETA that is null until 5 completions and null when a holder has run >5x the median. Hydralysis `EngineError` already keeps `queue` and `retryAfterMs`. None implemented. | E3a, E5, Y4a | Implement E3a queue info, E5 health lanes, Y4a job-record `queue`. For an hours-long analysis there will be a position and no ETA: owner question N9. | `DT --only queue_info` (to write, E3a) |
| C2-38 | Cancellation of queued/running work | partial | Premise partly stale: cancel exists and is tested for running and queued work in the slot and import queues (`t_cancel_all`, `import_queue`; `Scheduler.java:157-183` polls every 100 ms). NOT cancellable: waits on program/project/overlay locks. E0 `cancel_lock_wait` CONFIRMED (cancel acknowledged, request still answered `busy` 6498 ms later). Overlay lifecycle untimed `lock()` calls are out of scope in the spec. | E3b, E4 | Implement E3b (`cancel_queued`, `cancel_while_waiting`, deadline in lock wait, abandoned holder). Non-cooperative scripts keep their lock (spec section 6). | `--baseline --only cancel_lock_wait,dead_client_lock_wait`; after E3b `--only cancel_lock_wait,cancel_while_waiting` |
| C2-39 | No quick-lane starvation with 10+ clients | designed | Confirmed failing premise (E0 `lane_starvation`); fix is E3a; test is E6. No `soak_tests.py`. Other causes: slot taken before locks, no per-client running cap (`MAX_PARALLEL` 32, `Connection.java:49`), fork/save in long behind analysis (E0 `fork_save_behind_analysis` CONFIRMED, busy after about 5 s), and the rev5 reader-leave stall. | E3a, E3b, E6 | Everything: engine changes, then the soak with defined p99 bounds for native decompile and for `lane:'quick'` RusticQuery under a saturated long lane. | `python examples/soak_tests.py --clients 12 --seed 1` (to write) |
| C2-40 | Cancellation and queued imports leave no orphaned programs | partial | Verified on hydra.3: `client_kill`, `import_kill` (no program, no temp file), `import_queue`, `cancel_all`. Gaps: dead client in a lock wait; orphaned SHARED work is kept until daemon shutdown by design with no TTL and a memory-only journal. E6's criterion covers owner lists only. | E3b, E6 | Define "orphaned program" (owner left; shared writer left with unsaved edits; program from a cancelled import; temp files) and assert each at the end of the soak; decide `orphanKeepS` default. | `DT --only client_kill,import_kill,orphan_shutdown`; soak (to write) |
| C2-41 | Release notes: Windows x64 only, COW ReFS only, else full copy | partial | Written on rc (README "Platform and limits", CHANGELOG hydra.3, release notes `b74e28157c`); nothing tagged. Hydralysis README has no ReFS/Windows-only/COW statement (only `docs/verification-complete-workflow.md:145` says Windows x64). | R1 | Publish hydra.3; carry the section forward in hydra.4; add to 5.2's mandatory lines (A6); add to Hydralysis release notes (Z14). | `gh release view v12.3-hydra.3 ... \| rg -i refs`; `rg -n -i refs README.md` |
| C2-42 | Platform/COW limits in the `fork_project` answer | partial | Today's reply: `method`, `cloned`, `clonedBy`, `bytes`, `files`, `copyMs`, `freeSpaceUsedBytes`; file systems appear only in refusals. Spec 3.4 v3 adds `cost{...}` and `warnings[]` (E2). Hydralysis passes through only method/cloned/bytes/copyMs. Gated on v3: protocol-2 clients never see warnings. | E2, Y2 | E2 `fork_report`; Y2 keeps fork cost and warnings in sync details and status. | `DT --only fork_report` (to write); `U test_query` (Y2) |
| C2-43 | Test the NTFS fallback and measure its time/space cost | partial | Measured for other sizes: README.md:336-343 (rc): NTFS `mode:full` of a 1.49 GB project 8.5 s; small NTFS fork 13 ms. `t_fork` runs the fallback on NTFS CI without asserting `method=='copy'`. No KotOR-size (122 MB) NTFS figure. Hydralysis builds two forks per named view, doubling the cost. | E2 | Run the 9.10 measurement on a KotOR copy on NTFS (D:) and ReFS (F:), n>=5; write the NTFS assertion into `fork_report`; decide the limit mismatch (8192 vs 2048 MB). | `DT --project <KotOR copy on D:> --only fork_report` (to write) |
| C2-44 | Document upstream rebases for the 12.3 DEV fork | partial | Stale wording: policy is merge, never rebase. Documented on rc (`CONTRIBUTING.md` "Upstream sync": merge never rebase, golden decompile gate, DB_VERSION check, conflict table). First sync done: `sync/upstream-2026-10-27` (`f634f94045`, 35 upstream commits, 0 conflicts; KotOR 8616/8616 identical). Docs not on `main`. No automation. | NONE | Z15: merge docs; scheduled upstream-sync workflow with golden diff and a touched-files guard; track policy (DEV master vs a stable line). | `git show origin/main:.github/CONTRIBUTING.md \| rg -n "Merge, never rebase"` after merge |
| C2-45 | Document security-update policy | partial | Fragments: `.github/SECURITY.md` (private reporting, "report Ghidra vulnerabilities upstream"), CONTRIBUTING (sync first; legacy-12.1.4 frozen EOL). No supported-versions table, no SLA. | NONE | Z15: policy text (numbers are the owner's: N9). | `git grep -n -i "supported versions" -- .github/SECURITY.md` |
| C2-46 | Document project-format compatibility | partial | Docs on rc: README, CHANGELOG "Database format gate" (ProgramDB 33, DataTypeManagerDB 3, DataTypeArchiveDB 5, ProgramUserDataDB 1, SlaFormat 4, LocalBufferFile header 1), release notes. Weak evidence: hydra.3 to hydra.2 and back is the same format; legacy tests were skipped. Machine check is E2 `format_gate.py` + `format-matrix.json` (gates 9.6, 9.7), not started. | E2 | Merge rc docs; implement `format_gate.py` and the legacy fixture. The data-type DB version is "null until it can be read" in the spec. | `python examples/format_gate.py --ghidra <install>` (to write, E2) |
| C2-48 | Document Apache-2.0 notices | partial | rc: NOTICE-HYDRA rewritten as the 4(b) notice; the three modified Java files carry the modification line; NOTICE and NOTICE-HYDRA ship in the engine and client zips; `release.yml` asserts them (hand-checked byte equal per release notes). Not on `main`; release run not complete. Open: 25 Hydra-authored files carry `IP: GHIDRA` headers. Hydralysis THIRD_PARTY.md updated. | NONE | Z15: finish dry run, merge, tag; verify real release zips; decide the header question after reading Ghidra's IP check. | `gh release download` then check each zip has LICENSE, NOTICE, NOTICE-HYDRA |
| C2-49 | Document the one-way project upgrade | partial | Docs on rc (README, release notes "Upgrading from 12.1.4 (one way)", module README). Code: writing a 12.1.4 project needs `upgrade:true`; nothing requires a backup. Gate is spec (E2, Y2, Y4d, gate 9.6). | E2, Y2, Y4d | Merge rc docs; implement the gate and backup round trip. | `DT --legacy-project <fixture> --only upgrade_gate,backup_fault` (to write) |
| C2-57 | Named-view work copy 1.4 s (COW fork 95.6 ms) | partial | Same as C2-08 for instrumentation. `test_query.py:269-280` asserts 82 = 2 x 41 ms with the fake and that a second edit costs fork 0 / copy 0. No real-engine `phases_ms` record exists (grep of `_logs` found none). | Y5 | Same as C2-08 (Z2). State whether 95.6 ms is one fork or two. | as C2-08 |

### 3.4 Durability, commit and backup

| Id | Requirement | Status | Evidence | Covered by | What remains | Acceptance command |
| --- | --- | --- | --- | --- | --- | --- |
| C1-12 | Save takes about 257 ms and changes the revision | partial | Revision half covered in the engine: `daemon_tests.py` `projectRevision` (about L1548-1560) forks, renames, saves, asserts `projectRevision != baseRevision`. Timing half has no guard: the 257 ms (shared writer, KotOR, ReFS) is owner-reported only. The only save-timing test is E0 `t_fork_save_behind_analysis`, an expected-fail premise test, not a regression guard. The spec's 35 s is for the 1.5 GB / 243,855-function program and is "unmeasured" on KotOR. Hydralysis asserts no save time or revision move. | NONE | Amendment A1: E2 `save_guard` on a KotOR copy: open writable, rename, save, repeat N, assert `saved` and revision change, record median/p95; bound relative to a same-machine hydra.3 baseline, not a hard 257. Add a Hydralysis env-gated test that a `workcopy_saver` save changes the working copy revision. | `DT --project <KotOR copy> --only save_guard` (to write); partial today `--only projectRevision` |
| C1-17 | Edits are not durable; canonical project never saved | partial | Premise partly stale. True at `f46788b`: `workcopy.py:5` "The canonical project is never written"; README.md:7 "nothing yet commits those corrections back". Stale: edits are not volatile; overlays live in sealed, fsynced, atomic stores with `.bak` fallback and `store_corrupt` (Y0a, `durable.py`; V: full unit suite on a git-archive of `f46788b`: 459 tests OK, 9 skipped, incl. `tests/test_durable.py`; log `_logs/durability-verify/full_unit.log`). Y1 (store v3) committed in `y-w1` as `99212af`, not on the PR branch and not run here. No `annotations.py`, `lineage.py`, `commits.py`, `backups.py` on any branch we checked at investigation time; store still version 2 on `f46788b`. `api.py:83,426` answers `not_available` for commit/backup. E2 not started. | Y0a, Y1, Y2, Y0e | Merge Y0e and Y1; build Y2 (lineage, `commit` as a new generation, never in place); then change README/skill wording to "written only by an explicit, backed-up commit as a new generation". Implied pass: a KotOR rename/comment/signature/type/label appears in a verified new generation read by a fresh engine session, generation 0 byte-identical (spec 9.2). Owner decision OD2: the Ghidra GUI opening the original `.gpr` will NOT see committed annotations. | `U test_durable` (459 OK at `f46788b`); `tests/test_commit.py` and `E commit_round_trip` (to write, Y2) |
| C1-18 | Commit/export/import path for names, comments, signatures, types, labels | designed | Spec only: 4.9 (bundle `*.hydralysis-annot.json`, `export_bundle`, `import_bundle` dry-run then `apply:true` into a named view), 4.2 (store v3 effects/before), 4.6 (commit). Code at `f46788b`: none; `exporting.py` exports program decompile/functions/types, not user annotations. Engine `promote_overlay` (`Session.java:1943`) is a different in-memory path Hydralysis never calls. Spec exports only Hydralysis store records, not annotations made in the Ghidra GUI. | Y1, Y2, Y0e | Y1 `annotations.py`, `export_bundle`/`import_bundle`, `tests/test_bundles.py`; Y2 commit. Gap against the literal ask: an export of ALL current annotations of a program is in no package; mark as a gap or explicit non-goal in the PR answer. | `U test_bundles test_store_v3` (to write, Y1) |
| C1-35 (P0) | Durable annotation commit/export/import, hash- and revision-bound | partial | Same state as C1-17/C1-18. Hash-bound: the v2 store is bound to the program SHA-256 (`workcopy.py:59`) and sealed. Revision-bound: `expect_revision` is mandatory on every view; the store is NOT bound to the master PROJECT revision (a changed master silently rebuilds; spec 4.2 `base.master_revision`, 4.6 `master_drifted`). | Y1, Y2, Y4d, E2 | Y1, then Y2 (preconditions, drift pre-pass, backup, verify, `CURRENT.log` commit point), then E2 and Y4d. Acceptance per spec: all fault points of 4.6 give oracle O1-O6, two simultaneous commits give one `commit_busy`, gate 9.2. Owner decisions OD1, OD2, OD7. | `U test_commit test_lineage test_backups` (to write, Y2); gate 9.2 round trip |
| C2-09 | Refuse a writable 12.1.4 to 12.3 upgrade without a backup | designed | Hydralysis side is latent: it never upgrades a canonical project (every `upgrade=True` open is on a disposable fork, `workcopy.py:310,375,392`; adopt is read-only). Engine side true: `Session.java` `openWritable` (L2502-2524) has only the opt-in `upgrade:true`; no backup, no refusal; README prose "do it in a copy". Spec: gate `backup_required` and `backup.json` (E2). E2 files exist on no branch. Legacy upgrade tests need `--legacy-project` and are skipped in CI. | E2, Y2, Y4d | E2 gate, format, backup writer, committed legacy fixture; Y2 Python backup writer on hydra.2/3; Y4d switch to the engine backup. The gate is a guard against accidents, not security (manifest is forgeable). | `daemon_tests.py --legacy-project <12.1.4 copy> --only upgrade_gate,backup_fault`, `examples/cc_e2.py` (to write) |
| C2-10 | Version canonical copies | designed | Spec: generations `<root>/lineages/<id>/gen/000N` (generation 0 is the adopted project, never written), `CURRENT.log`, per-generation `MANIFEST.json`, backups. No code. Y0a (CRC append log, torn-tail repair) is the shipped substrate. The work-copy base is already keyed by master revision and engine release (`workcopy.py` about L296-303). The spec reads "version canonical copies" as generations plus backups and rejects in-place replace and automatic deletion (D28, OD2); a version-controlled `.gpr` visible to the GUI is not delivered. | Y2, Y4d, E2 | Y2 `lineage.py`, `targets.resolve` via `CURRENT.log`, tamper detection, `backend action=backups op=list/verify`. Retention is "never delete automatically": unbounded growth except a doctor warning at 200 GB. | `U test_lineage test_backups` (to write); `hydralysis backend backups --options '{"op":"list"}'` (today `not_available`) |
| C2-11 | Test restore from backup end to end on a disposable copy | designed | Spec only: restore is `fork_project` from the backup into a new generation folder (no replace). Gate 9.6 on the legacy fixture: backup, refusal without it, success with it, commit, restore alongside, restored tree hash equals original, stock 12.1.4 opens the restored backup but not the committed generation. Nothing implemented. `tools/golden.py treehash` and `project-copy` exist and prove a copy byte-identical (`tests/test_golden.py:248-262`). | E2, Y2, Y4d | Write the round trip on a disposable copy of the real KotOR project as manual gate evidence (gate 9.6 runs only on the small legacy fixture), kill-mid-backup and kill-mid-restore cases. Gate 9.6 needs stock 12.1.4, which conflicts with the no-stock proof machine: run on different machines and say so. OD1: a clone backup on the same volume is no protection against volume loss. | gate 9.6 script and `tests/test_backups.py::restore_round_trip` (to write); `python tools/golden.py treehash <canonical>` before and after (exists) |

### 3.5 Import, export and golden

| Id | Requirement | Status | Evidence | Covered by | What remains | Acceptance command |
| --- | --- | --- | --- | --- | --- | --- |
| C1-14 | Configured target adopts the existing project in place: no copy, no import | partial | Guards at three levels, green at `f46788b`: `tests/test_query.py` `Adopt.test_exe_hash_selects_and_registers_the_program_without_copying` (fake); `tests/test_preparation.py:112` (configured target never re-imported); CI `test_adopt_registers_the_prepared_project_in_place` (`test_engine_integration.py:212`, 7 tests ok). Weakness verified in code: `targets.adopt` returns the literals `copied:False, imported:False` (`targets.py:171-172`), so those assertions are tautological. No tree-hash before/after, no check that no import/writable open was sent; the CI test adopts a project it just prepared. Engine may make a background upgrade-cache copy for 12.1.4 projects unless `GHIDRA_SESSION_UPGRADE_CACHE=off`. | NONE | Z5: measure instead of echo: tree hash before/after (`tools/golden.py treehash`), assert no import/analyze/fork/writable `open_program` in the daemon command log, report the upgrade-cache state, adopt a legacy 12.1.4 fixture. | `U test_query.Adopt test_preparation`; `E test_engine_integration` (existing); tree-hash version (to write) |
| C1-20 | Parity unverified: the run adopted an upgraded 12.1.4 project, not a fresh import | partial | Premise holds. Same DB, two decompilers on KotOR is measured (C1-40). Fresh 12.3 import+analysis is exercised on `whoami.exe` (CI) and the 8 MSVC fixtures (`_golden/sets/fixtures.json`, 472-650 functions each). Not done: any comparison of a fresh 12.3 import of the same exe against the 12.1.4-analysed project (entry-set overlap, names, counts), and no fresh KotOR import on Hydra. hydra.3 notes: legacy tests skipped. | E2 | Z7: golden mode 2 (prepare from scratch under a fresh root, capture, diff), coverage ratio not equality; engine suites with `--legacy-project`. | `python tools/golden.py prepare ...; capture ... --label fresh; diff <upgraded> <fresh> --profile corpus` (never run in this mode) |
| C1-21 | `prepare start` on a fresh executable needs tests | partial | Real engine: only `whoami.exe` (`_prepare()`, 600 s deadline, CI ok). Unit coverage with fakes: `tests/test_preparation.py` (about 15 tests). Fixtures prepared by hand (`prepare_fixtures.py`, MSVC-gated, not CI). Not tested: KotOR-scale import (time, count, first query), two concurrent prepares vs `maxImports`, cancel mid-import leaving no program or target, killed worker on a real engine. | E3a, E6 (engine side only) | Z5: gated real-engine test with whoami plus the 8 fixtures; local KotOR prepare with recorded seconds, function count, first-query time; concurrent, cancel and kill-worker tests. | `E test_engine_integration` (existing); `tests/test_engine_prepare.py` (to write) |
| C1-22 | Full-corpus export needs tests | not-started | None run through the export job. Fake-runner tests `tests/test_exporting.py` (28) and one real-engine test with limit 5 on whoami (`test_engine_integration.py:119`). `docs/exports.md:105-107` says a full decompilation is not automated verification. Nearest real evidence: golden production capture of the same RusticQuery path: 8,616 functions all ok, 315.4 s (hydra-3-candidate), 326.0 s on hydra-2; explicit Java driver 158.6 s. Not the export worker. Per-row overhead (two `frozen()` calls, sealed progress write, fsync) is inferred from code, unmeasured. | NONE | Z6: run `exporting.start mode=decompile` on a KotOR copy and record wall time, rows/s, bytes; measure the per-row cost before refactoring; add a fixture-scale real-engine export test to CI. | `tools/verify_corpus.py export --target <kotor copy>` or `tests/test_engine_export.py` (to write) |
| C1-23 | `RusticQuery.java` / script migration needs tests | partial | `RusticQuery.java` runs on 12.3 repeatedly (CI query tests; golden production path ran it for all 8,616 KotOR functions on hydra.2 and hydra.3, 0 failures). User scripts: `userscripts.run/_stage` have unit tests only with `QueryRunner` mocked; no test of `_stage` itself (collision, `owners.json`); no real-engine `ghidra_run` test. `.py` scripts pass the name regex (`userscripts.py:22`) but nothing shows Hydra runs Python. Migration of old GhidraMCP/REA scripts: `docs/tool-mapping.md` is a skeleton. | E4, Y4e | Z5: `_stage` tests; real-engine run of a staged `.java` after daemon start; compile-error case; a `.py` decision (prove PyGhidra or drop from the regex); a representative old script ported. | `U test_query test_contracts test_query_script`; `tests/test_userscripts.py`, `tests/test_engine_scripts.py` (to write) |
| C1-37 (P0) | Fresh import/analysis on a new executable | partial | Restates C1-20/C1-21. Real engine proven on `whoami.exe` (CI) and 8 fixtures; never on a real game exe with timings; CI pins `RELEASE='12.3-hydra.2'` (`hydra.py:30`). | E3a, E6 | As C1-21 and C1-20 (Z5, Z7). The CI engine job must follow the pin bump (R1 `tools/bump_hydra.py`, Y4a). | `E test_engine_integration`; KotOR fresh-prepare run (to write) |
| C1-38 (P0) | Full export | not-started | Same as C1-22. Counts are inconsistent across sources: golden header `function_counts` total 8,966, internal 8,616, thunks 60; `docs/exports.md:10`, `capabilities-kotor.md:14`, `open-pr-insights.md:46`, `research.md:111` say 10,849 "internal". The enumeration uses `fm.getFunctions(true)` (`RusticQuery.java:2469-2480`): internal plus thunks (8,676), not the remaining 290 (inference). Completion: `export_worker.py` sets `complete` only if `failed==0` and `truncated==0`, with no expected-count field, so one refusal makes a full export look incomplete. The capture holds 13.55 MB of C text for 8,616 functions; the 17.8 MB JSONL is plausible but not on disk. | NONE | Z6: expected count (engine `info.functions` minus a declared exclusion set) and a corpus-parity field (`written+failed==expected`) separate from `all_succeeded`; pin the target by SHA-256 (`0290889e...74e6`); reconcile 8,966 / 8,616 / 10,849. | `tests/test_engine_export.py` local tier asserting lines == expected and `c_sha256` equal to golden production `rows.jsonl` (to write) |
| C1-39 (P0) | Script migration | partial | Same facts as C1-23. Script path plumbing works: `hydra.script_dirs` gives `<root>/hydra/scripts` and `<root>/hydra/user-scripts` on `scriptPath` (`hydra.py:251-273`). Y0d made a non-empty `ghidra_run` options bag answer `not_available` (`tests/test_contracts.py:140-155`), so isolation/readonly are unavailable at HEAD. | E4, Y4e | As C1-23; Y4e (W6, S) tests are unit-level and cover modes, not migration. | `U test_userscripts test_contracts` plus a real-engine test (to write) |
| C1-40 (P0) | Golden 12.1.4 to 12.3 decompile diff | partial | Stale on "no harness": `tools/golden.py` (1001 lines), `tools/golden/GoldenExport.java`, `docs/golden-harness.md`, `tests/test_golden.py` (24 synthetic tests) are committed. A stock 12.1.4 baseline of KotOR exists (`_golden/baselines/ghidra-12.1.4/kotor/explicit`: 8,616 ok) and the diff was run against hydra-2 and the hydra-3 candidate on a copy. RESULT (saved reports read, not re-run): identical 6,645, changed 1,971, failed_only_in_A/B 0, missing 0, match 77.124%, `gate.passed false` ("77.12% < 98.00%"); `identical_after_normalisation` 0. Confound: `options_sha256` differs (`162f2fd3...` vs `1356caf7...`) because 12.3 has `maxBadData=4` and 12.1.4 has no such key (the only differing key), so 77.12% mixes an option default change with decompiler change. Source tree hash unchanged across runs (`6d8ced78...`). Only KotOR captured; no 12.1.4 baseline for the 8 fixtures. Spec gate 9.1 compares hydra.3 with the hydra.4 candidate, not 12.1.4 with 12.3 (D29 names the comparison, no gate). | NONE | Z7: re-capture with options held equal (or drop `maxBadData` from the options hash) and re-diff; classify the 1,971 by cause; accepted-difference list and a documented cross-major threshold or per-class policy (owner: N5); 12.1.4 baselines for the fixtures; counts-only report in docs (no game C text). Exit code of the current diff is 1. | `python tools/golden.py diff D:/Projects/Hydra/_golden/baselines/ghidra-12.1.4/kotor/explicit D:/Projects/Hydra/_golden/baselines/hydra-3-candidate/kotor/explicit --profile corpus --report <out>.json --no-text` (exits 1 today); `tools/golden.py classify` (to write) |
| C1-44 (P1) | Metadata, listing, read-memory, call-graph and name-address parity tests | not-started | No parity test against GhidraMCP or REA. `docs/tool-mapping.md` says "No row has been checked by running the other tool"; list_classes and list_namespaces are Gap, read_memory is Partial (Ghidra's own memory is not read). Engine-gated tests check shapes on whoami; `verify_fixtures.py` ground-truth checks cover other capabilities. The spec has no occurrence of these. | NONE | Z8: define the parity subset and test each against linker-map ground truth of the MSVC fixtures (x86 and x64); each tool-mapping row moves from "to verify" to tested or an explicit documented gap. | `python tests/fixtures/verify_fixtures.py <dir> listing callgraph namemap` (to write) |
| C2-12 | Full-corpus export on 8,966 functions / 17.8 MB JSONL matches the corpus count | not-started | Same as C1-22/C1-38. Lower bound from measurements: the capture decompiled 8,616 functions in 315.4 s (36.6 ms per function including round trip); explicit loop 158.6 s. Extrapolation from the pre-Hydra 42-function export gives about 22 min. Neither is measured for the job. The 17.8 MB file does not exist locally. | NONE | Z6: define expected count and exclusions; cross-check `c_sha256` per function with golden production rows; record wall time. | `HYDRALYSIS_INTEGRATION_KOTOR=<copy> U test_engine_export.FullCorpus` (to write) |
| C2-13 | Test export resume and cancel | partial | Fake-runner tests only (`tests/test_exporting.py`: crash after a durable row `:169`, cancel `:207`, resume refusals `:221-245`, dead worker `:260`, queued cancel `:279`). No real-engine resume or cancel. Verified in code: `frozen()` raises `Paused` when `code_sha256`, master revision or overlay state changes, so a long export on the shared view pauses whenever another agent edits an overlay. Spec 4.7 says exports snapshot at start; code does not (no `fork_project`). | Y2 (header and refusal on generation change only) | Z6: real-engine kill-at-50%-and-resume equal to an uninterrupted run, cancel latency, cancel while paused, non-owner cancel refused; decide snapshotting so overlay edits stop pausing exports. | `U test_exporting` (fake); `tests/test_engine_export.py::ResumeCancel` (to write) |
| C2-14 | Test Java `scriptPath` | partial | `RusticQuery.java` is found via `scriptPath` in every green engine test (CI); engine suites use `scriptPath` (`daemon_tests.py:106`). Not tested: a user script staged into `<root>/hydra/user-scripts` and run via `ghidra_run`; staging after daemon start; same-name collision; compile error. `tests/test_query.py:55-80` mocks the runner and `_stage`. | Y4e | Z5: real-engine `ghidra_run` of a staged `.java`; collision refused; compile-error output; script staged after start; `.py` decision. | `tests/test_engine_scripts.py` (to write) |
| C2-15 | `ghidra_run` on a read-only copy; scripts cannot mutate a read-only program | designed | Read-only by construction at HEAD but unproven in Hydralysis: `userscripts.run` gets programs from `QueryRunner.program_for` (`query.py:111-115`, read-only opens) and the engine runs the script contained with a rolled-back outer transaction; engine proof `session_smoke.py:154-159` (SmokeTryWrite renames, then nothing changed, `changed:false`). Limits: in shared mode a mutating script's transient writes may be visible to concurrent readers (E0 `script_shared_visibility`: 94 of 115 polls showed it); the engine reports `changed:false` for every contained script, so an attempted mutation is invisible to the caller. E4/Y4e add isolation and `attemptedChanges` (not implemented). | E4, Y4e | Implement E4 then Y4e; the E4 test must check the master tree hash, a second client's reads, and `attemptedChanges>0`. A cheap interim real-engine test needs no E4: run a mutating script via `ghidra_run` on a copy and compare tree hash and a follow-up decompile. | `python examples/dt_e4.py` (to write, E4); `python examples/session_smoke.py` (existing) |
| C2-16 | `ghidra_run` on a writable copy | decision-needed | No path today: `userscripts.run` only gets read-only programs; the writer handle holding a view's unsaved edits is separate (`workcopy.py:264,310,375,392`). Spec rev4 designs only a rolled-back run (isolation shared/private/exclusive); persisting a script's edits to a view is neither designed nor excluded in writing. | Y4e, E4 | Owner decision N7: rolled-back run against a copy that holds edits (then test: unsaved overlay edit visible to `exclusive`, `private` reports `unsavedIgnored`, master untouched) or a persistent script edit mode (new package depending on Y1/Y2). | `tests/test_userscripts.py` plus a real-engine variant (to write) |

### 3.6 Runtime and evidence

Every item in this theme is outside the protocol-3 plan: rev4 has no runtime or evidence package (only Y0e
touches `runtime.py` and `runtime_worker.py`, for sealed writes). This is the largest gap. Real-process
evidence is manual and lives outside the repo (`F:/dev-cache/rusticre/complete-20261024/runtime-integration-smoke-v5-ipc.log`
ends "RUNTIME SMOKE PASS"; an x86 run in `runtime-x86-integration-smoke-v4-ipc.log`). Hosted CI never runs
Frida, and `docs/upstream-runtime.md` says it is "not full native debugger parity". V: unit suites at HEAD
`f46788b`: `test_runtime` 41, `test_mcp_runtime` 15, `test_writers` 11, `test_runtime_decode` 8,
`test_evidence` 4, all OK, all against `tests/fakefrida`. A premise correction: REA (reference checkout
`f196ebf`) has 9 Frida session/script tools with a 16 MiB capture cap and gdb/rizin consoles, and a grep of its
source found no structured watchpoint, memory-write or minidump API, so watchpoints, write and process capture
are new scope rather than parity.

| Id | Requirement | Status | Evidence | Covered by | What remains | Acceptance command |
| --- | --- | --- | --- | --- | --- | --- |
| C1-24 | Runtime parity vs REA: attach, breakpoints, watchpoints, process capture | partial | `ACTION_NAMES` = setup, processes, spawn, attach, status, modules, threads, read, patches, observe, break, continue, unload, resume, detach, writers (`runtime.py:29-30`). Fake-Frida unit tests pass; manual real-Frida smoke passes outside the repo; no `runtime_fixture` source or smoke script in the repo; no watchpoint action; no capture. | NONE | Z10: write down what parity means (a REA-to-Hydralysis map for the 9 Frida tools; arbitrary scripts and gdb/rizin as non-goals); put the fixture (x64 and x86 C source, build script, asserted hash) and the smoke script in the repo as an env-gated lane. | `tests/test_runtime_fixture.py` with `HYDRALYSIS_INTEGRATION_RUNTIME=<dir>` (to write); `U test_runtime test_runtime_decode` (existing, fake) |
| C1-25 | Evidence/coverage bundle contract needs parity tests vs REA | not-started | The store is a claims ledger: `evidence.py:20-60` (integer id, free-text game/build/source, supersede columns), 4 tests. REA's contract (read in the reference checkout): `evidence_id` = `ev` + digest recomputed on parse (`src/domain/evidence.ts:141,193-197,420`), bundle comparison, relationship coverage. Spec has only a provenance sentence (line 1079); Y1's file list has no `evidence.py`. | NONE | Z9: decide the target contract and migrate `evidence.py` in place (legacy rows backfilled); write parity tests that load a case exported from the REA checkout and check each REA field has a counterpart. | `U test_evidence_model test_evidence_parity` (to write) |
| C1-41 (P0) | Runtime/debug parity: attach, breakpoints/watchpoints, memory, modules, capture/compare | partial | Attach, spawn, modules, threads, bounded absolute and module+rva reads, typed reads, observe, break, continue, detach exist and pass fake tests and the manual smoke. Missing (grep of `runtime*.py`): memory write, hardware watchpoints, stepping, snapshot/compare. `docs/hardware-watchpoint-research.md:3-6`: "does not yet provide hardware data watchpoints or CPU instruction stepping". The headless build excludes Debugger-agent modules. | NONE | Everything under C2-20, C2-22/23, C2-24, C2-29. x86 (KotOR's architecture) is the weakest watch prototype. | as C2-29 plus the fixture lane |
| C1-42 (P0) | Evidence/coverage contract and exportable bundles | partial | Only `evidence.export(path, out, game, subsystem)` writing `.md` and `.jsonl` of ledger rows. No coverage object, limitation catalog, manifest, verify/compare/import. Doc defect: `docs/upstream-runtime.md:64` says evidence records the probe's SHA-256, but `evidence_add` has no such field. Hydra already supplies identity (sha256, imageBase, revision; spec adds `hello.analysisIdentity`, E1/E2). | NONE | Z9: evidence v2 with structured coverage and limitations, bundle export/verify/compare/import, correct line 64, a second independent run to prove reproducibility, no game bytes in bundles. | `U test_evidence_bundle` (to write) |
| C2-17 | Runtime parity for KotOR: attach/spawn | partial | `spawn` (paused, exe path + SHA-256 check) and `attach` (PID-reuse refusal) implemented (`runtime.py:208-346`) with passing fake tests; real owned-fixture runs in the smoke logs. KotOR was never spawned or attached through Hydralysis. The old-toolchain scenario source is `E:/Projects/kotor-remaster/.../06-dynamic/scripts/vfs_probe.py` with results in `docs/recon/08_VFS_DYNAMIC.md`. | NONE | Z11: run the KotOR VFS-lookup scenario from a lane profile copy (never the install). Needs export-name hooks and caps lifted (see C2-29). Owner decision N4. | `tools/scenarios/kotor_vfs_lookup.py --profile <dir>` (to write) |
| C2-18 | Runtime parity: continue/detach | partial | `continue` (30 s watchdog), `unload`, `resume`, `detach` implemented; cleanup unit tests pass; real fixture smoke shows "continue breakpoint OK", "detach leaves fixture alive OK". No KotOR scenario; not in CI. | NONE | Z11: detach with target alive, probes inert, `patches` showing zero differences afterwards. | part of the scenario script (to write) |
| C2-19 | Runtime parity: modules listing | partial | `modules(limit)` in `runtime_worker.py:49-50`; module file SHA-256 computed per module (`:433`); real fixture "loaded modules OK", "live module bytes OK". Not exercised on KotOR. | NONE | Z11: in the scenario list modules after resume and record name, base, size and file sha256; snapshot/compare reuses the block. | scenario step 2 (to write) |
| C2-20 | Runtime parity: memory read/write | partial | Read only: bounded, range-checked (`runtime_worker.py:60`; three read tests pass). There is no write action. REA has no structured memory-write API either, so write is new scope. | NONE | Owner decision N2. If wanted: Z12 `runtime write` with mandatory compare-and-swap `expect`, required reason, executable-range guard, undo log on detach/death reporting DIVERGED. If not: record as an explicit non-goal. | `tests/test_runtime.py` fake tests, fixture write test (to write) |
| C2-21 | Runtime parity: typed live reads | partial | `runtime.py:349-375` `_layout` resolves a Ghidra struct/enum from the named view via `ghidra_query type`; `runtime_decode.layout_values` (8 tests) and `test_typed_read_resolves_struct_and_enum_from_the_requested_view` pass against fakes. The real smoke reads a raw absolute object, not a typed layout. | NONE | Z10/Z11: one typed read of a real object end to end (fixture first, then the KotOR resource table), recording the view revision. | `E tests.test_runtime_fixture.test_typed_read` (to write) |
| C2-22 | Runtime parity: breakpoints and watchpoints | partial | Breakpoints done and proven on fixtures (byte-gated probe; "verified breakpoint OK", "continue breakpoint OK"); cooperative pause, not a stop-the-world debugger. Watchpoints not implemented: `docs/hardware-watchpoint-research.md` is research only. The static-site `writers` action (`runtime.py:400-560`, `test_writers.py` 11 pass) answers "who writes this field" using probes and states its own coverage limit. | NONE | Owner decision N3. Z12: `runtime watch/unwatch` with state machine, tainted session on failed disarm, per-arch conformance stamp; or document `writers` as the supported route. A handler unloaded with a slot armed killed the fixture with `0x80000004` (research doc lines 14-19). | `tools/watch_conformance.py --arch x86\|x64` (to write) |
| C2-23 | Test watchpoint teardown specifically | not-started | No watchpoint code, so no teardown to test. Evidence is research only, outside the repo (`F:/dev-cache/rusticre/watchpoint-fixture`): individual x64 runs; the docs say they are "not proof against every timing or teardown failure". Probe and breakpoint teardown IS tested (cleanup unit tests, smoke "observer removal restored bytes OK"). | NONE | After a watch action exists: x86 and x64 matrix (normal unload, controller kill before/after arm, while suspended, during hit, IPC-timeout retire, thread exit while armed, TID reuse, occupied slot, 100-iteration race loop; target exit 0 and no `0x80000004`), with explicit debug-register readback. Fixture source into the repo; the deliberately unsafe test stays out. | `python tools/watch_conformance.py --arch x86 && ... --arch x64` (to write) |
| C2-24 | Runtime parity: process capture/compare | not-started | No snapshot, compare or capture-id action (`ACTION_NAMES`). Event capture is a volatile ring: 1000 events / 256 KiB (`runtime_worker.py:359`), per-probe hit limit 1..200; evicted events cannot be recovered; `dropped_events` discloses loss (`docs/upstream-runtime.md:65-66`). | NONE | Z10: durable append-only event log with sequence and hash chain; `runtime snapshot` and `runtime compare` with volatile masks; closed-grammar predicates. | `tests/test_runtime_capture.py`, `test_runtime_snapshot.py` (to write) |
| C2-25 | Evidence IDs | not-started | Ids are local SQLite integers (`evidence.py:20-60`); REA's are content-addressed and verified on read. No subject hash, no link to runtime events. 4 ledger tests only. | NONE | Z9: `evidence_id = 'ev_' + sha256(canonical content)` with verify-on-read; additive migration; `from_capture=<capture_id>`. | `U test_evidence_model` (to write) |
| C2-26 | Coverage | partial | Prose and counters only: the `writers` answer carries a free-text `coverage` string (`runtime.py:557-558`); status exposes `dropped_events`. No structured coverage object, no per-hook `hits_total` independent of recorded hits. REA has relationship coverage. | NONE | Z9: a Coverage object (`complete`/`partial`/`unknown` plus limitation codes) on every observe/break/writers/read/snapshot answer, stored with the evidence row; a capped capture must never present as complete. | `tests/test_runtime_capture.py` overflow cases (to write) |
| C2-27 | Limitations recorded with evidence | partial | Limitations exist as prose in `docs/upstream-runtime.md`, `docs/hardware-watchpoint-research.md`, `docs/ci.md`. Not attached to evidence rows; no limitation-code catalog. Doc defect: `docs/upstream-runtime.md` has the corrupted path `F:\dev-cacheusticre\complete-20261024`. | NONE | Z9: structured limitation catalog returned by each runtime answer and stored in rows and bundles; fix the two doc defects. | `U test_evidence_model`; `rg -n "dev-cacheusticre" docs/*.md` prints nothing |
| C2-28 | Exportable evidence bundles | partial | Only `evidence_list export=` writes `.md` and `.jsonl` ledger rows. No manifest, replay record, artifact hashes, verify/compare/import. REA ships these (`src/cliEvidenceCommands.ts`, `bundleComparison.ts`). The spec's annotation bundles (4.9, Y1) are for annotations, not evidence. | NONE | Z9: bundle format (manifest with `bundle_id`, `evidence.jsonl`, `subjects.json`, `captures/`, `replay.json`, `environment.json`, `limitations.md`); verify, compare, import; CLI only (the 20-tool target D25 stays). No payload bytes beyond bounded captured hex. | `U test_evidence_bundle` (to write) |
| C2-29 | Reproduce one dynamic scenario from the old toolchain end to end; evidence bundle reproducible | not-started | No scenario script or expected manifest in the repo. The old scenario is documented (`08_VFS_DYNAMIC.md`: five-pass order dir, ERF, RIM, ERF, KEY/BIF). Blockers read in code: probes are module+rva only (no export-name hook, so `CreateFileW/A` at `vfs_probe.py:54-55` cannot be hooked), 200-hit and 1000-event caps, no capture/compare/bundle, arbitrary scripts refused by design. The fixture smoke is a different scenario. | NONE | Z11 after Z9 and Z10: author `tools/scenarios/kotor_vfs_lookup.py` with an expected manifest; game-free analogue on the in-repo fixture for CI. Pass: pass sequence equals the recorded one, `hits_total` counters, zero silent drops or explicit limitation, evidence verify passes, second independent bundle compare shows no non-volatile deltas, install tree hash unchanged. Owner decision N4. | `python tools/scenarios/kotor_vfs_lookup.py --profile <dir> --twice`; CI analogue `U tests.test_runtime_scenario_fixture` (to write) |

### 3.7 Supervision and root

| Id | Requirement | Status | Evidence | Covered by | What remains | Acceptance command |
| --- | --- | --- | --- | --- | --- | --- |
| C1-26 | No supervision: no health probe, no auto-restart | partial | Premise partly stale. `hydra.py` has an idle-connection probe (`STALE_S=30`, `_probe` sends `ping` before a mutating call and reconnects: `hydra.py:76-78, 413-430`; `tests/test_client.py:335`); `Engine.call` retries an idempotent read once and `session()` respawns a dead daemon lazily; engine answers `ping`/`status`/`cancel` inline (`Session.java:231`). Still true: no periodic probe, no wedged-daemon detection, no kill and restart, no budget, no `lost_on_restart`; `ghidra_session.py:845` has `sock.settimeout(None)`, so a call to a hung daemon blocks forever. `rg` for Watchdog, DuplicateDaemon, `case "health"` finds nothing on three engine branches. V: 67 tests ok (`test_paths test_compat test_client test_no_stock_ghidra test_contracts`). | E5, P1b, Y4a, R1, Y2 | Build E5 (`Health`, `Watchdog`) and P1b (deadline, `Daemon.attach`); Y4a `Supervisor` (5 s probe on its own connection, wedged = pid alive and 3 bad probes, budget 3 restarts per 10 min, `lost_on_restart`). Working pass: a suspended daemon is detected in about 15-20 s and restarted within budget; a slow healthy daemon is not restarted; a 4th restart in 10 min returns `daemon_unhealthy`. OD4. | `U test_client test_contracts` (partial); `U test_supervisor test_deadline`, `dt_e5.py` (to write) |
| C1-27 | One supervised daemon per root, not per server process | partial | One daemon per (state dir, instance) already holds: launcher takes `<instance>.lock` and `<instance>.start.lock` (`ghidra_session.py:943-956`); Hydralysis fixes `INSTANCE="rusticre"` (`hydra.py:31-36`) and keeps one connection per (root, role). Live check 2026-10-27 20:27: one `java.exe` (pid 18220, instance `default`, `F:\dev-cache\hydra-state`). No test starts N concurrent launchers or MCP processes on one root and asserts one JVM. Supervision is C1-26. | P1b, Y4a, Y4b | P1b engine-side launcher test; add the Hydralysis-side multi-process test (a gap in the package test lists): Z3. | `dt_p1b.py` (to write); 8 `hydralysis mcp` processes, distinct cwd, scrubbed env, one root, exactly one `java.exe` (to write) |
| C1-28 | JDK 25 and about 700 MB footprint: document or reduce | designed | Docs name JDK 25 (`THIRD_PARTY.md:17`) but not memory; `backends.inspect` takes `java_min` 25; README.md:98 documents idle exit (`hydra_idle_s` 7200, `hydra_keep_warm_s` 3600). Measured now: pid 18220 private bytes 759 MB, working set 92 MB, `-Xmx8g -Xms512m`, `idleTimeout 0`, resident about 8 h (one machine). Engine default heap is a quarter of RAM clamped 2-31 GiB. Spec: `health.memory`, doctor memory, `heap_too_large` (P1b); none implemented. | E5, P1b, Y4b, R1 | Implement `health.memory` and doctor memory/heap/idle; write the measured footprint and JDK 25 into README and release notes. Do not quote 700 MB without a recorded measurement. | `U test_doctor` (to write); `Get-Process java \| Select Id,WorkingSet64,PrivateMemorySize64` |
| C1-29 | Duplicate daemons possible: standardise a single root | designed | Within a root duplicates are prevented (C1-27). Across roots nothing prevents them: no registry in code. The two live daemons (18220 and 17936) of the spec's premise are stale: only 18220 ran at 20:27; the `rusticre-latest` state dir remains on disk. Spec P1b registry, `singleton:"per-install"`, default warn (OD3). | P1b, Y4b | P1b registry + warn; doctor `other_daemons`; OD3 to consolidate roots; document the single-root recommendation (no package owns that text: Z3/Z13). | `dt_p1b.py duplicate_daemon` (to write); `Get-CimInstance Win32_Process -Filter "Name='java.exe'"` |
| C1-43 (P0) | One supervised daemon per root, health probe, harness startup diagnostics | partial | Pieces exist, the deliverable does not. Startup failures are strings ("the daemon exited with code N ... see <log>", "did not answer within 180 s"), not structured codes. `backend action=doctor` answers `not_available` (`api.py:499-507`, `tests/test_contracts.py:111-133` pass); Y0e (`8e696e2`, `y-w1`) wires the CLI to the same stub. No `doctor.py` on any branch. `backend status` is NOT a safe probe: `api.py:379` builds `hydra.Engine(settings)` with `start=True`, so it spawns a JVM when no daemon runs. Y4b (W6) is the last Hydralysis package. | Y4a, Y4b, P1b, E5, Y0d, Y0e | All of C1-26, C1-27, C1-29 plus doctor. Not in any package: `backend status` must use `start=False`; consider a hydra.2-compatible doctor slice before hydra.4 (Z3). | `U test_doctor` (to write, Y4b); `hydralysis backend --action doctor` must not change the `java.exe` list |
| C1-48 (P1) | Soak: daemon restart and upgrade | partial | E6 criteria include seeded client kills, not a daemon restart or an engine upgrade. Restart is tested only in Y4a (not implemented). Existing partial: `tests/test_client.py:335`, `tests/test_query.py:134/397` (restart loses a work copy, replayed). `soak_tests.py` absent. | E6, Y4a | Extend E6 or a Hydralysis soak: kill/suspend the daemon mid-run with >=10 clients; engine release swap under load with the pin refusal by name (A2). | `soak_tests.py --lane pr --restart-daemon --upgrade` (to write) |
| C2-03 | Make the effective root explicit (LocalAppData default) | partial | Default is still `%LOCALAPPDATA%\Hydralysis` (`paths.py:23-27`); an existing RusticRE root is reused. Explicit: `HYDRALYSIS_ROOT`, config `root`, `forbidden_drives` (`tests/test_paths.py` ok); `backend inspect` reports `root`. Not done: nothing reports the root SOURCE, the filesystem or the system-drive condition; MCP `initialize` carries only the catalog under `_meta` (`mcp.py:68`); doctor is `not_available`. F: is ReFS, C:/D:/E: NTFS. The spec warns only; refusal (`require_cow`) is not in it. | Y4b, E1, P1b | Z3: a resolver returning root plus source and filesystem/COW shared by doctor, `backend inspect/status` and the MCP initialize result, so every harness launch reports the same root and engine (the spec has only an on-demand doctor); warn on a system-drive root or non-COW volume (N6). | `U test_environment` (to write); `U test_paths` (existing, passes) |
| C2-04 | Config must be deterministic across harness launches (`RUSTICRE_CONFIG` not inherited) | not-started | Premise holds at `f46788b`: `config.py:14-25` takes `HYDRALYSIS_CONFIG` or `rusticre.local.json`/`hydralysis.local.json` in the CURRENT WORKING DIRECTORY; an env-less server from another cwd silently gets defaults and the default root. `docs/clients.md:9-25` suggests only `HYDRALYSIS_ROOT`. No test runs an env-less server from a foreign cwd; no pointer file; config source reported nowhere. Spec rev4 has no package; its doctor "root and why" omits the config file. | NONE | Z3: precedence env > per-user pointer > default, config inside the root, demote the cwd fallback with a warning, report config source in doctor and launch report. Risk: a stale pointer silently redirects, so doctor must print root, source and pointer. | `U test_environment test_mcp_runtime` (to write): same root and config from any cwd with scrubbed env |
| C2-05 | `doctor` view: root, engine, project, revision | designed | Carrier only (`api.py:80-81, 167-168, 499-507`; `workflow_help.py:79`). No `doctor.py`, no `test_doctor.py`. Spec 7.1 (Y4b, M, W6): read-only, never starts a JVM, findings with `{id, level, what, why, fix}`; it lists lineage and stale views but not an explicit `projects[{name, writable, revision}]` block, and omits config path and source. Inputs it needs (E1 hello, E5 health, P1b attach) are on no released branch. | Y4b, Y0d, Y0e, E1, E5, P1b, Y2, Y4a | Implement `doctor.py` through Y2's handler registry; add the projects block (status already carries `projects[].revision`, `api.py:385-387`) and config source. Ship a hydra.2-compatible slice earlier (Z3). | `U test_doctor`: zero Popen and zero `connect(start=True)` with no daemon (to write) |

### 3.8 No-stock Ghidra, tool surface and GUI

| Id | Requirement | Status | Evidence | Covered by | What remains | Acceptance command |
| --- | --- | --- | --- | --- | --- | --- |
| C1-50 (P1) | Documentation and a tool-mapping table for the 20-tool surface | partial | `docs/tool-mapping.md` exists (commit 2245512, in `f46788b`): counts table, 20-tool table, 30-row GhidraMCP table. It calls itself a skeleton: "No row has been checked by running the other tool"; REA is "Not mapped". `TOOL_NAMES` has 20 entries (`api.py:20-41`; `tests/test_contracts.py:169`). The 30 GhidraMCP names match the saved bridge. 28 vs 30 not reconciled. | NONE | Z13: verify each "to verify" row; resolve 28 vs 30 from a live `tools/list`; write the REA 207 table from a live list; list deliberate drops; add a drift test (doc table equals `api.TOOL_NAMES`); track the known functional gaps (segments, namespaces, classes, Ghidra-memory read). | `U test_tool_mapping` (to write); `U test_contracts` (existing, count only) |
| C2-01 | Test `backend inspect/install`, `prepare adopt/start`, a query and a script with stock Ghidra absent and `GHIDRA_INSTALL_DIR` unset | partial | CI engine job (job-level `GHIDRA_INSTALL_DIR` empty): hermetic step success; 7 integration tests ok including prepare on a fresh PE, queries, export, overlay edits and adopt in place (CI, 95.9 s). `backend inspect` with a bogus stock variable: pinned engine chosen, variable reported under `ignored` (`ci_engine.py hermetic`). V: `test_no_stock_ghidra` and `test_backends` with the variable emptied: 17 tests ok. Not proven: (a) no real-engine `ghidra_run`; (b) `backend install` as a product path (CI uses `hydra.install` via `ci_engine.py`, JDK from setup-java); (c) the test does not scrub the environment itself, and this dev machine has `GHIDRA_INSTALL_DIR` set; (d) "absent" is assumed from the hosted image; (e) `docs/ci.md` still says "Not yet run on GitHub Actions". | NONE | Z4: one sequential end-to-end test that scrubs `os.environ` and PATH itself and runs inspect, install, inspect, prepare, adopt, query and a user script in one fresh root, with a process audit (no `analyzeHeadless`/`ghidraRun` spawned) and a canary directory; wire into the CI engine job; fix `docs/ci.md`. | `U test_engine_nostock` with the variable unset (to write); `python .github/scripts/ci_engine.py hermetic <root> --java <jdk>` (existing) |
| C2-02 | Remove any stock-Ghidra path from preflight/config | partial | Fixed in Hydralysis and tested: `backends.py:91-94` lists only the pinned engine candidates, `_ignored()` reports `ghidra_dir`/`GHIDRA_INSTALL_DIR` and never probes them; V: 17 tests ok. README.md:24, THIRD_PARTY.md:9 and `skills/hydralysis/SKILL.md:3` updated. Remaining references are deliberate (`tools/golden.py --stock`, historical `docs/prompts/review.md`). Hydra side NOT fixed: `ghidra_session.py` lines 169-180 still fall back to `GHIDRA_INSTALL_DIR` and about 323-325 to a stock-written `java_home.save` on three branches; Hydralysis neutralises it by always passing `ghidra=<engine dir>`, java and settingsdir. | NONE | Nothing for Hydralysis code. The pass criterion needs the C2-01 pipeline test (Z4). Optional: engine `hello` reports install and JDK (P1b/E1 do not add it); the Hydra launcher stops honouring the stock variable. | `U test_no_stock_ghidra test_backends` (17 ok); Z4 test |
| C2-30 | Publish the tool mapping (20 / 28 / 207); fresh agent sees only RusticRE tools and no REA/Ghidra instructions | partial | Mapping: as C1-50. Tools true: harness configs hold only the RusticRE server, still registered as `rusticre` from `E:\Projects\rusticre-latest` at `f03f334` (0.4.0); this session's tools are `mcp__rusticre__*`. Skills mostly true (see C2-31). NOT true: `~/.agents/skills/re-workflow/SKILL.md:19` still names `re-ghidra-mcp` and `re-rea`; `re-hooking/SKILL.md:44` cites the prologue check "in re-ghidra-mcp". None of Hydralysis's four skills is installed in any harness. | NONE | Z4 and Z13: finish the mapping; edit the two dangling skill references (and the upstream copy in `F:/Projects/re-expertise` whose install table still lists the archived skills); install `skills/hydralysis`; align skill frontmatter names with directories; re-register the server as `hydralysis` from a pinned install; a fresh-agent audit. | `tools/audit_harness.py` (to write); spot check `grep -rn -i "re-rea\|re-ghidra-mcp" ~/.agents/skills` (currently hits two files) |
| C2-31 | Archive the stale `re-rea`, `re-ghidra-mcp`, `reverse-engineer-anything` skill guides | done | `E:\dev-cold\skills-archive\2026-10-27\MANIFEST.json` (2026-10-27T15:02:51Z) lists six items with `tree_sha256_before` equal to `tree_sha256_after_copy` and `removed_from_origin: true`; `RESTORE.ps1` and `config-backups\` beside it. Live listing: `~/.agents/skills` holds only computer-use, goal-mode, orca-cli, orchestration, orx, re-hooking, re-runtime-introspection, re-tooling, re-verification, re-workflow; no link for the three in `~/.claude/skills`; `.skill-lock.json` has 0 matches; this session's skill list shows none. | NONE | Done for the named three. Not covered: dangling references in `re-workflow` and `re-hooking` (C2-30) and the public upstream `re-expertise`, whose README install table could bring the skills back on a re-sync. | `ls ~/.agents/skills ~/.claude/skills ~/.qoder/skills`; `E:\dev-cold\skills-archive\2026-10-27\RESTORE.ps1` dry run |
| C2-32 | Running sessions cache tool lists and need a restart: document/verify | partial | Documented: `docs/clients.md` ("Restart the client after the edit"), README upgrade table, `mcp.py:76` workflow help; `mcp.py:68` returns `_meta['hydralysis/catalog']` and `api.catalog()` gives `{epoch, hash}` (`tests/test_contracts.py:10-56`). Real: this session still shows the old "RusticRE 0.4.0" server instructions and `mcp__rusticre__*` names. No harness re-registered as `hydralysis` or moved to 0.5.0.dev0. `listChanged` is false, so a running harness cannot learn it is stale; doctor has no stale-session check. | Y0d, R1 | R1 release notes carry the restart line (spec 5.2); a harness check (doctor finding or Z4's audit comparing the catalog hash a harness reports against the installed one); perform and record the migration from a pinned install, renaming `mcp__rusticre__*` allow-lists and hooks in the same change. | `U test_contracts`; per harness after restart: `_meta['hydralysis/catalog']` equals `api.catalog()` and `serverInfo.name == 'hydralysis'` (to write) |
| C2-33 | Decide whether manual analysis still needs a GUI; document it | partial | A de facto position is documented (README.md:119-121, THIRD_PARTY.md:10): stock GUI unsupported (a Hydra-saved project uses a newer DB version 12.2 and 12.1.4 cannot open); the Hydra full build (`gradle buildGhidra`) includes the GUI and can open a fork, never the analysed project; GUI edits are not imported back. Unverified: no log of opening a Hydra fork in the GUI; the released assets are headless only. Contradicting lines remain: `docs/research.md:163-165` ("Use Ghidra directly for ... deliberate writes to the master project") and `docs/verification-complete-workflow.md:148`. Spec OD2 is open. | NONE | Owner decision N1 (OD2). Then record it in one place, fix or qualify the two contradicting lines, and if GUI-on-fork is supported, a reproducible materialise-to-path action, a documented full-build recipe and a logged walkthrough (source tree hash unchanged). | docs test for the decision section (to write); manual logged walkthrough for the GUI option |
| C2-58 | Tool surfaces 20 / 28 / 207 | partial | 20: verified (`api.TOOL_NAMES`, `tests/test_contracts.py:169`). GhidraMCP: 30 `mcp.tool` functions counted in the saved bridge source, not 28 (28 = 30 minus two GUI-only tools is plausible, no live `tools/list`). REA 207 appears only as `tool_count` in the archived skill's metadata (`E:\dev-cold\skills-archive\2026-10-27\...\reverse-engineer-anything\SKILL.md:6`); never enumerated live. `docs/tool-mapping.md` records exactly this status. | NONE | Z13: reproducible counter that launches each configured server, sends `initialize` and `tools/list`, and stores names, date, version, command hash in `docs/data/tool-surfaces.json`; settle 28 vs 30. | `python tools/count_surfaces.py --server hydralysis --server ghidramcp --server rea --out docs/data/tool-surfaces.json` (to write) |

## 4. Stale or corrected claims

Premises in the comments, or in earlier notes, that the investigation disproved or narrowed. Each one changes
what has to be done, so none is a quibble.

| # | Claim | What the evidence shows | Evidence | Affects |
| --- | --- | --- | --- | --- |
| S1 | "8,966 functions" as the corpus to export | 8,966 is the program total: 8,616 internal plus 350 not internal. The header records 60 thunks; the remaining 290 are the externals, by subtraction. The golden capture holds 8,616 rows; the RusticQuery export enumerates `fm.getFunctions(true)`, which probably gives internal plus thunks (8,676; inference, not measured). Other docs say 10,849 "internal" and are unreconciled; fixture totals also differ (4,497 in the set file vs 3,959 in `docs/golden-harness.md:143`). | `_golden/baselines/hydra-3-candidate/kotor/explicit/header.json`: `function_counts {total 8966, internal 8616, thunks 60}`; `RusticQuery.java:2469-2480`; `docs/exports.md:10` | C1-38, C2-12 |
| S2 | The golden/production path and the "explicit options" path agree | They did not. Production (RusticQuery) now decompiles on the program's own options (commit 4d0ce5d), which changes decompiled C for about one function in six (README.md:11); that is why the harness has a parity section and two paths. Any figure quoted before that fix describes a different decompile. | README.md:11; `docs/golden-harness.md:127`; `tests/test_engine_options.py` (fixtures-gated, skipped in CI) | C1-20, C1-40, C1-15 |
| S3 | A 12.1.4 to 12.3 golden diff is "needed" because no harness exists | The harness and a real diff exist. The diff is 77.124% identical (6,645 of 8,616; 1,971 changed; 0 failed in either direction; gate 98% fails), so it is not a gated, passing result. It is also confounded by `maxBadData=4` (the only differing option key, so `options_sha256` differs). Gate 9.1 compares hydra.3 with the hydra.4 candidate (8616 identical hydra.3 against itself), never 12.1.4 with 12.3. | saved reports `baselines/hydra-3-candidate/diff-kotor-12.1.4-vs-h3.json`; both `header.json` options dicts | C1-40, C1-20 |
| S4 | Overlays/edits are not durable | Edits live in sealed, fsynced, atomic overlay stores with `.bak` fallback and `store_corrupt` instead of start-empty (Y0a, `durable.py`). What is missing is the commit path to a canonical generation, not durability of the edits themselves. | V: 459 unit tests OK on `f46788b` incl. `tests/test_durable.py` (`_logs/durability-verify/full_unit.log`) | C1-17, C1-35 |
| S5 | No-stock-Ghidra still has to be enforced in preflight/config | Enforced in Hydralysis since 0.5.0.dev0: stock settings are ignored and never probed, with a source scan test and a CI hermetic step. NOT enforced in the Hydra launcher (still honours `GHIDRA_INSTALL_DIR` and `java_home.save`), which affects standalone Hydra users only because Hydralysis passes `ghidra=<engine dir>`. What is unproven is the end-to-end pipeline including a script. | `backends.py:91-109`; V: 17 tests ok; `ghidra_session.py:169-180` | C2-01, C2-02 |
| S6 | No health probe exists | An inline probe exists: `hydra.py` pings an idle connection before a mutating call and reconnects; an idempotent read retries once on a dead daemon; the engine answers `ping`/`status`/`cancel` inline. What is missing is periodic probing, wedge detection and restart policy. | `hydra.py:76-78, 413-430`; `tests/test_client.py:335`; `Session.java:231` | C1-26, C1-43 |
| S7 | Runtime watchpoints and memory write are "REA parity" | They are not parity. REA has no structured watchpoint, memory-write or minidump API (grep of the reference checkout `f196ebf`). They are new scope the owner added; watchpoints carry a process-fault risk. | `F:/dev-cache/ref-repos/rusticre-rea-reference`; `docs/hardware-watchpoint-research.md:14-19` | C1-24, C1-41, C2-20, C2-22 |
| S8 | The 1.9x concurrent speedup describes what agents see | It is the NATIVE decompile command in the QUICK lane. Agents use `ghidra_query`, which is engine `script` in the LONG lane (`query.py:90`, `Scheduler.laneOf`), where 2x20 gave 1.39x and 12 simultaneous calls queued 6. The single-run KotOR native figures vary about 2x. | `concurrency-verify/probe2.json`, `kotor.json` | C1-04, C1-01 |
| S9 | Two Hydra daemons currently coexist | True earlier today (pids 18220 and 17936); not at 20:27: only 18220 ran. The `rusticre-latest` state dir remains on disk. | `Get-CimInstance Win32_Process` check | C1-29, OD3 |
| S10 | Dead clients release their locks, and analysis never delays quick queries (Hydra README) | Both overstated for scripts and for a client blocked in a lock wait: 8.0-8.3 s against a 3 s bound; a killed client stayed registered 40+ s. These sentences are still in the rc README (44-46) and module README (669). | `_logs/E0/baseline2.json` | C1-33, C1-47 |
| S11 | `fork_project` ReFS clone is 95.6 ms / 2.19 MB, and the named-view cost is 1.4 s | One run each, never reproduced; the engine README's only published ReFS clone numbers are for a 1.49 GB program (204-225 ms). 95.6 ms may be the sum of two forks. | README:337-343 (rc); `workcopy.py:262-268` | C1-06, C2-08, C2-57 |
| S12 | Old RusticRE PR6 failed 1 of 2 and 2 of 3 | Owner-reported historical data from a pre-Hydra build with a stock backend; cannot be reproduced under the no-stock rule. | commit a495ea9 and ancestors; no repo doc has the figures | C2-55 |
| S13 | Archive the three stale skill guides | Already done (manifest of 2026-10-27). The remaining problem is dangling references in `re-workflow` and `re-hooking`. | `E:\dev-cold\skills-archive\2026-10-27\MANIFEST.json` | C2-31, C2-30 |
| S14 | `docs/ci.md`: "Not yet run on GitHub Actions" | False now: run 40577257118 at `f46788b` is green (engine job 7 tests OK, plus the unit jobs). Other caveats stand: no ReFS, no game data, options-parity test not run. | CI run 40577257118 | C2-01, C1-13 |
| S15 | The GhidraMCP tool count is 28 | The saved bridge at pinned revision `1e98025` has 30 `mcp.tool` functions; 28 is plausible only as 30 minus two GUI-only tools. REA's 207 is a skill metadata field, never enumerated. | `docs/tool-mapping.md`; saved bridge source | C2-58, C1-50 |
| S16 | The 17.8 MB JSONL is an artifact we can compare against | It is not on disk anywhere searched (F:/dev-cache, D:/Projects, E:/dev-cold). The golden capture holds 13.55 MB of C text for 8,616 functions. | `find` over those roots | C2-12 |
| S17 | Hydra's hydra.3 wording ("fork of Ghidra", platform limits, notices) is published | It exists only on `release/hydra-3-rc` (`b74e28157c`); `main` (`a410b0c3bf`) still says "independent project" and nothing is tagged. | `git show main:README.md` | C1-31, C2-41, C2-44, C2-46, C2-48 |

## 5. Gaps: asks with no work package

**Loud summary.** The protocol-3 plan (spec rev4) is an engine-contract and state-contract plan. It does not own
the following, and nothing else in the repositories does either. These are real holes in the path to "every P0
satisfied". Four of the nine P0 items are in them outright (C1-38, C1-40, C1-41, C1-42); two more are only
covered at the engine end (C1-37, C1-39).

| Gap | Asks | Why the plan misses it | Proposed package |
| --- | --- | --- | --- |
| G1 | Runtime/debug parity, evidence contract, coverage, limitations, bundles, end-to-end dynamic scenario: C1-24, C1-25, C1-41, C1-42, C2-17 to C2-29 (17 requirements, all `NONE`) | Spec rev4 has no runtime or evidence package; only Y0e touches `runtime*.py` | Z9, Z10, Z11, Z12 |
| G2 | Full-corpus export, expected count, resume/cancel on a real engine: C1-22, C1-38, C2-12, C2-13 | Y2 touches `exporting.py` only for header and resume refusal | Z6 |
| G3 | 12.1.4 to 12.3 golden diff explained and gated; fresh vs upgraded analysis: C1-40, C1-20 | Gate 9.1 compares hydra.3 with hydra.4 only (D29 names the comparison, no gate) | Z7 |
| G4 | Hydralysis-side real-engine matrix: fresh prepare beyond `whoami`, cancel/kill/concurrent prepare, user scripts via `scriptPath`, adopt measured not echoed: C1-14, C1-21, C1-23, C1-37, C1-39, C2-14, C2-15 (interim), C2-16 | E3a/E6/E4/Y4e are engine-side or unit-level | Z5 |
| G5 | Surface parity tests: metadata, listing, read-memory, call-graph, name-address: C1-44 | Not in the spec at all | Z8 |
| G6 | Hydralysis concurrency regression guard: C1-01, C1-04, C1-05, C1-07, C1-08, C1-09, C1-11, C1-19 (race), C2-56 | E6 and E3a never run through the MCP/`QueryRunner` path | Z1 |
| G7 | Measurement harness: C1-02, C1-03, C1-13, C1-15, C2-08, C2-43, C2-51, C2-57 | Gate 9.10 lists measurements with no script and no owner; `benchmarks/` is frozen | Z2 |
| G8 | Deterministic config and root, launch-time report, `backend status` side effect, early doctor slice: C2-04, C2-03, C1-43, C2-05, C1-27 (Hydralysis half) | Y4b is last in W6 and omits config source and launch report | Z3 |
| G9 | No-stock end-to-end proof and harness audit: C2-01, C2-02, C2-30, C2-32 | No package mentions no-stock or the harness migration | Z4 |
| G10 | Tool-mapping completion, surface counter, third-party reference figures, claims lint: C1-16, C1-50, C1-51, C2-30, C2-50, C2-53, C2-54, C2-55, C2-58 | R1 owns the Hydra README only | Z13 |
| G11 | Hydralysis release: version policy, CHANGELOG, workflow, release notes: C1-34, C1-49 (policy) | R1 forbids a tag by its stream and covers hydra.4 only; OD5 is a decision, not a package | Z14 |
| G12 | Fork maintenance and policy: merge rc docs, cadence, security SLA, upstream-sync automation, notices verification: C1-31, C2-44, C2-45, C2-47, C2-48 | Spec packages are protocol 3 only | Z15 |

**Gaps inside covered requirements (amendments to existing packages, not new packages).**

| # | Package | Amendment | Requirements |
| --- | --- | --- | --- |
| A1 | E2 | `fork_report` numeric guard on a KotOR-sized project on ReFS and the NTFS `method=='copy'` assertion; `save_guard` (N repeats, median/p95, relative bound); log first-open time of the legacy fixture with the upgrade cache on and off; give the gate 9.10 measurements a script and owner | C1-06, C1-12, C2-43, C2-52 |
| A2 | E3a, E3b, E6 | Define numeric soak bounds before writing E6 (E0 recorded the FAILING latency, so "the bound recorded by E0" is not a bound); add a standing import load with queued-import cancels and a kill in the queue; a multiplexed profile (one connection, many callers); a second process contending for the project lock; the reader-leave-during-read case (rev5); a daemon restart and an engine-release swap under load; define "orphaned program" for the end-state check; add the `two_readonly_daemons` test | C1-05, C1-45, C1-46, C1-47, C1-48, C2-34, C2-39, C2-40 |
| A3 | Y1, Y3 | Real-engine named-view isolation and revert assertions; two-author journal test; the same-address race test must exist before Y1 merges (Z1) | C1-07, C1-08, C1-11, C1-19 |
| A4 | Y4a, Y2 | `lane:'quick'` and queue info in the job record; pass fork cost and warnings into sync details and status; align `fork_max_copy_mb` (8192) with the engine limit (2048) or surface the cost before copying | C2-37, C2-42, C2-43 |
| A5 | Y4b | Doctor: config path and source, an explicit `projects[{name, writable, revision}]` block, a harness stale-catalog check, compat deprecations; `backend status` must use `start=False` | C1-43, C2-03, C2-05, C2-32 |
| A6 | R1 | 5.2 mandatory release-note lines: "fork of Ghidra that depends on its project format, decompiler, analyzers and scripts; one-way 12.1.4 to 12.3 upgrade"; Windows x64 only, ReFS-only COW; one restart after the catalog epoch; `requireExpect` not built; quick-lane promise and crash-release wording corrected until E3a/E3b land; percentiles in the "Measured, not promised" tables | C1-31, C1-33, C1-32, C2-41, C2-32 |
| A7 | Gate 9.10 | Add rows: save time on KotOR; concurrent-speedup medians with spread (pin by SHA-256); NTFS full-copy cost on KotOR; first open of a real 12.1.4 project; MCP call latency | C1-02, C1-03, C1-12, C2-43, C2-52 |

### 5.1 Proposed work packages

Same format as spec section 8. Ids carry a `Z` so they cannot be confused with spec packages. Every new file
needs a row in the spec's 8.1 ownership matrix (spec 8 rule: any new test file). None is started. Waves refer
to the spec's wave plan; the placement is a proposal for the owner and for the spec author.

**Z1 (Hydralysis, S): concurrency regression guard.**
Goal: pin the behaviour the owner measured, on the path agents use.
Files: new `tests/test_concurrency.py` only.
Depends on: nothing; must merge BEFORE Y1 merges (Y1 rewrites `workcopy.py` and `revisions.py`).
Tests: (1) source guard that `query.py` and `hydra.py` never import `LaneLock` or create `.request.lock`;
(2) env-gated real engine, Barrier-started threads at N=2, 3 and `maxLong+1` through `QueryRunner.query`: all ok,
no `busy`, no `EngineError`; (3) `SameAddressRace`: N threads with one `expect_revision` on one address, exactly one
ok, N-1 conflicts, journal +1; (4) `TwoWriters`: each of two clients sees the other's edit at once; (5)
two-author journal; (6) a process killed holding `.sync.lock` mid-edit does not block the next edit.
Acceptance: `E test_concurrency` exit 0 in the CI engine job; no timing assertion.
Wave: W1 tail (parallel to Y1, disjoint file).

**Z2 (Hydralysis, M): measurement harness.**
Goal: replace single-run figures with recorded medians, report-only.
Files: new `benchmarks/mcp_latency.py`, `benchmarks/concurrency_bench.py`, `benchmarks/named_view_cost.py`,
`benchmarks/bench_cold_start.py`, `benchmarks/bench_install.py`, `benchmarks/budgets.json`, `tests/test_output_size.py`
(rev4 rule 3 freezes existing `benchmarks/` files, so these are new files with their own 8.1 rows).
Depends on: Y1 merged (named-view cost); Y0 phases already present.
Tests: harness spawns the real stdio MCP server against a pinned target and function, discards warm-up, N>=30
warm calls, records median/p95/max with engine release, machine, program SHA-256 and filesystem; concurrency
bench prints serial_ms, conc_ms, speedup and lane `everQueued` for native and `ghidra_query` paths separately;
named-view cost N>=5 on ReFS and NTFS with each phase; cold start split into MCP, daemon, open and first answer;
fixture-based output-size budgets with headroom (the options fix moves C by about one function in six).
Acceptance: each script exits 0 and writes JSON under `_logs/<stream>/`; budgets are 3x the recorded median and
report-only. Owner machine only; never hosted CI for time.
Wave: W4, so the numbers exist before gate 9.10 and before E6 fixes constants.

**Z3 (Hydralysis, M): environment, config and an early doctor slice.**
Goal: every harness launch reports the same root, engine and config; no surprise JVM from `backend status`.
Files: new `environment.py`, `tests/test_environment.py`; `config.py`, `paths.py`, `cli.py` (an `init` command)
and the `backend status` edit in `api.py` (after Y2's handler registry, per its promise of no later `api.py`
edits).
Depends on: Y2 (handler registry); E1 `hello.paths/platform` for the file-system field (optional; the slice
works on hydra.2).
Tests: same root and config from any cwd with scrubbed env; a process-level `hydralysis mcp` from a foreign
cwd; `backend status` with no daemon spawns nothing; a launch banner in MCP `initialize` `_meta` and on stderr
(root, source, config source, engine release, file system); warn on a system-drive root and on a non-COW volume;
8 `hydralysis mcp` processes, one root, exactly one `java.exe`.
Acceptance: `U test_environment test_mcp_runtime` exit 0; `hydralysis backend --action doctor` leaves the
`java.exe` list unchanged. Y4b later absorbs the doctor sections.
Wave: W3 (after Y2).

**Z4 (Hydralysis, M): no-stock end-to-end proof and harness audit.**
Goal: the C2 pass criterion, proven rather than assumed.
Files: new `tests/test_engine_nostock.py`, `tools/audit_harness.py`; edits to `docs/ci.md`, two skill files
outside the repo (`re-workflow`, `re-hooking`), `skills/*` frontmatter names.
Depends on: none for the test; the audit needs a pinned install for the rename.
Tests: one sequential class that scrubs `os.environ` and PATH itself, then inspect (not ready), install (job),
inspect (ready), prepare, adopt, `ghidra_query`, `ghidra_run` of a small script, with a process audit and a
canary directory; the audit reads each harness config, launches the configured server, dumps `tools/list` and
greps the skill dirs for REA, GhidraMCP, `re-rea`, `re-ghidra-mcp`, `analyzeHeadless`.
Acceptance: `U test_engine_nostock -v` with the variable unset exits 0 in the CI engine job; `python tools/audit_harness.py` exits 0.
Wave: W2.

**Z5 (Hydralysis, L): real-engine matrix for prepare, adopt and scripts.**
Goal: cover fresh import and script migration on a real engine.
Files: new `tests/test_engine_prepare.py`, `tests/test_engine_scripts.py`, a tree-hash variant of the adopt test.
Depends on: nothing; the `ghidra_run` mode tests stay with Y4e.
Tests: whoami plus the 8 MSVC fixtures as a gated test; concurrent prepare against `maxImports`; cancel
mid-import registers no program and no target; killed worker; local KotOR fresh prepare with recorded seconds,
count and first-query time; adopt with tree hash before and after, no import/analyze/fork/writable
`open_program` in the daemon command log, upgrade-cache state reported, a legacy 12.1.4 fixture; `_stage`
collision and ownership; a staged `.java` run after daemon start; compile-error output; the `.py` decision
(prove PyGhidra or drop it from the regex and docs); a mutating script on a copy leaves the tree hash unchanged
(interim C2-15 proof).
Acceptance: `E test_engine_prepare test_engine_scripts` exit 0; the KotOR timing run is local evidence in
`docs/verification-import-export.md` (counts and hashes only).
Wave: W2.

**Z6 (Hydralysis, M): corpus export parity and resume.**
Goal: a full export that provably equals the corpus.
Files: `exporting.py`, `export_worker.py` (after Y2's header edit), new `tests/test_engine_export.py`,
`tools/verify_corpus.py`.
Depends on: Y2.
Tests: expected count (engine `info.functions` minus a declared exclusion set) and a `written+failed==expected`
field separate from `all_succeeded`; per-row cost measured before any refactor; kill at 50% and resume equals an
uninterrupted run; cancel latency; cancel while paused; snapshot at start so overlay edits stop pausing exports;
the KotOR run pinned by SHA-256 `0290889e0cea6ebc00021c1bdb945704fc4c45afaf7fcebabb0e82ba674437e6`,
`c_sha256` equal to the golden production rows.
Acceptance: `HYDRALYSIS_INTEGRATION_KOTOR=<copy> E test_engine_export` exit 0 (local tier); fixture-scale export in CI.
Wave: W3.

**Z7 (Hydralysis, M): 12.1.4 to 12.3 golden comparison.**
Goal: the owner's golden diff, explained.
Files: new `tools/golden_classify.py` (a new file, since `tools/golden.py` is large and shared), `docs/verification-import-export.md`.
Depends on: owner decision N5 for the threshold.
Tests: re-capture with the options held equal (pin `maxBadData` or drop it from the options hash); classify the
changed functions by cause; accepted-difference list; stock-12.1.4 baselines for the 8 fixtures; fresh vs
upgraded analysis mode (C1-20); no game C text in the repo.
Acceptance: `python tools/golden.py diff ... --profile corpus` plus `golden_classify.py` exit 0 under the
accepted policy; counts-only report committed. Proposed gate 9.12 (section 6).
Wave: W2 (needs no engine change).

**Z8 (Hydralysis, M): surface parity tests.**
Goal: move tool-mapping rows from "to verify" to tested.
Files: `tests/fixtures/verify_fixtures.py` new check groups, new `tests/test_parity_surface.py`.
Depends on: nothing.
Tests: listing, call graph, name to address and read-memory against the linker-map ground truth of the MSVC
fixtures (x86 and x64); explicit documented gaps for segments, namespaces, classes and Ghidra-memory reads.
Acceptance: `python tests/fixtures/verify_fixtures.py <dir> listing callgraph namemap` exit 0.
Wave: W3.

**Z9 (Hydralysis, L): evidence v2 and bundles.**
Goal: C1-25, C1-42, C2-25 to C2-28.
Files: `evidence.py` (in place, legacy rows backfilled), new `evidence_bundle.py`, `tests/test_evidence_model.py`,
`tests/test_evidence_bundle.py`, `tests/test_evidence_parity.py`.
Depends on: Y1 (view/seq/generation provenance); Y2 for generation.
Tests: content-addressed `evidence_id` stable across key order and sessions and rejecting a flipped byte;
structured coverage and limitation catalog stored with each row; bundle export/verify/compare/import; parity
cases loaded from the REA checkout; no game payload bytes; correct `docs/upstream-runtime.md:64`.
Acceptance: `U test_evidence_model test_evidence_bundle test_evidence_parity` exit 0; two independent bundle exports compare equal modulo volatile fields.
Wave: W6 (parallel to Y4).

**Z10 (Hydralysis, L): runtime fixture lane, capture, snapshot, export-name hooks.**
Goal: C1-24, C1-41, C2-17 to C2-21, C2-24.
Files: new `tests/runtime_fixture/` (C source for x64 and x86, build script with pinned toolchain and asserted
hash), `tests/test_runtime_fixture.py`, `tests/test_runtime_capture.py`, `tests/test_runtime_snapshot.py`;
`runtime.py` and `runtime_worker.py` (after Y0e); split the 805-line worker into agent templates, event log,
action handlers and lifecycle before adding features.
Depends on: Y0e merged; Z9 for coverage objects.
Tests: env-gated windows-latest Frida lane; hook by module export name verified against the file's export table;
durable append-only event log with sequence and hash chain, counters independent of recorded events;
`runtime snapshot`/`runtime compare` with volatile masks; a REA-to-Hydralysis mapping for the 9 Frida tools.
Acceptance: `HYDRALYSIS_INTEGRATION_RUNTIME=<dir> U test_runtime_fixture test_runtime_capture` exit 0 in CI.
Wave: W6.

**Z11 (Hydralysis, M): runtime scenario end to end.**
Goal: C2-29 and the KotOR halves of C2-17 to C2-19.
Files: new `tools/scenarios/kotor_vfs_lookup.py`, `tests/test_runtime_scenario_fixture.py`.
Depends on: Z9, Z10; owner decision N4 (a live game run, profile copy only).
Tests: the 12-step scenario from the old toolchain (`vfs_probe.py`, `08_VFS_DYNAMIC.md`): verify sites,
spawn paused from a lane profile copy, observe, export hooks, capture, resume, typed read, snapshot, writers,
detach, evidence add, bundle export; install tree hash unchanged; a game-free analogue on the fixture for CI.
Acceptance: `python tools/scenarios/kotor_vfs_lookup.py --profile <dir> --twice` exit 0; the pass sequence equals
the recorded one, zero silent drops or an explicit limitation, the second bundle compares with zero non-volatile
deltas.
Wave: W7.

**Z12 (Hydralysis, M, gated): runtime write and watch.**
Goal: C2-20 (write), C2-22, C2-23.
Files: `runtime.py`, `runtime_worker.py`, new `tools/watch_conformance.py`, `tests/test_runtime_watch.py`,
`tests/test_runtime_write.py`.
Depends on: Z10; owner decisions N2 and N3. Not to be built without them.
Tests: compare-and-swap write with a required reason, executable-range guard and undo log reporting DIVERGED;
watch state machine to verified-clear, tainted session on failed disarm, per-arch conformance stamp; x86 and x64
teardown matrix with debug-register readback and 100-iteration race loop (target exits 0, never `0x80000004`).
Acceptance: `python tools/watch_conformance.py --arch x86 && python tools/watch_conformance.py --arch x64` exit 0.
Wave: W7, only after the decisions.

**Z13 (Hydralysis, M): documentation, surfaces and claims.**
Goal: C1-16, C1-50, C1-51, C2-30, C2-50, C2-53 to C2-55, C2-58.
Files: `docs/tool-mapping.md`, new `docs/data/tool-surfaces.json`, `tools/count_surfaces.py`, `tests/test_tool_mapping.py`,
`tests/test_claims.py`, `docs/verification.md` (dated reference table of owner-reported third-party figures,
each labelled "not reproduced"), README "Evidence and limits".
Depends on: Z4 for the harness facts; owner decision N8.
Tests: doc table equals `api.TOOL_NAMES`; no row says "to verify" once declared complete; README or docs that say
"replace" carry the qualifier and the bottom-line paragraph; the 8-outstanding-per-lane MCP cap documented.
Acceptance: `U test_tool_mapping test_claims` exit 0; `python tools/count_surfaces.py ...` writes three counts.
Wave: W5.

**Z14 (Hydralysis, M): Hydralysis release.**
Goal: C1-34 and the policy half of C1-49.
Files: new `CHANGELOG.md`, `.github/workflows/release.yml`, `docs/versioning.md`.
Depends on: R1 (`bump_hydra.py`), Y4a (pin), OD5 (repository visibility), Z13.
Tests: workflow dry run (`workflow_dispatch`) builds sdist and wheel, runs the unit and engine jobs, attaches
artifacts with SHA256SUMS; a version policy (which version pins which engine, what 0.x means, how to roll back
a pin); release notes carry the limits (Windows x64, ReFS-only COW, one-way upgrade, restart once).
Acceptance: `gh api repos/RusticStack/RusticRE/releases/latest --jq .tag_name` prints a version; in a fresh venv
`pip install <wheel>`, `hydralysis --version` equals the tag, `hydralysis backend inspect` reports ready.
No tag by this stream; the tag is an owner action.
Wave: end of W6.

**Z15 (Hydra, M): fork maintenance and policy.**
Goal: C1-31, C2-44, C2-45, C2-47, C2-48 and the publication of the rc documentation.
Files: `.github/CONTRIBUTING.md`, `.github/SECURITY.md`, new `.github/workflows/upstream-sync.yml`, new
`.github/hydra-touched-files.txt`; R1 keeps README and CHANGELOG.
Depends on: the rc dry run (run 40576898783) finishing green; owner numbers (N9).
Tests: a scheduled upstream-sync workflow (merge, `buildHeadless`, the three suites, golden diff, a PR with
shortlog and a file-overlap report); a guard for the three patched core classes; supported-versions table and
fix-time statement; cadence section; the real release zips contain LICENSE, NOTICE and NOTICE-HYDRA; decision on
the `IP: GHIDRA` headers after reading Ghidra's IP check.
Acceptance: `git show origin/main:.github/CONTRIBUTING.md | rg -n "Merge, never rebase"` matches after the merge;
`git grep -n -i "independent project" origin/main -- README.md NOTICE-HYDRA` prints nothing;
`git grep -n -i "supported versions" -- .github/SECURITY.md` matches.
Wave: parallel with W5 and R1; the rc merge itself is the hydra.3 track (section 6).

### 5.2 Wave plan with the proposed packages

| Wave | Hydra (engine) | Hydralysis | Proposed additions |
| --- | --- | --- | --- |
| W0 | E0 | Y0a-Y0d | none (done to the extent shown in section 1) |
| W1 | P1a, then E1 | Y0e, then Y1 | Z1 (before Y1 merges); Z15 first half (merge rc docs, hydra.3 track) |
| W2 | E2, E3a | Y2 | Z4, Z5, Z7 (no engine change needed); amendments A1, A2 (E3a part) |
| W3 | E3b | Y3 | Z3 (after Y2), Z6 (after Y2), Z8 |
| W4 | E4, E5, P1b | (catch-up) | Z2 (before gate 9.10 and E6) |
| W5 | E6, then R1 | | Z13, Z15 second half (policy, upstream-sync automation); amendment A6 in R1 |
| W6 | | Y4a, then Y4b, Y4d, Y4e | Z9, Z10 in parallel; Z14 at the end; amendments A4, A5 |
| W7 | | Y5 | Z11, Z12 (gated by N2, N3, N4) |

### 5.3 Extra improvements (deduplicated)

Items the investigators found that no requirement asked for. Each has the reason and a proposed owner.

| # | Improvement | Reason | Proposed owner |
| --- | --- | --- | --- |
| X1 | One measurement harness, not seven; method = interleaved medians of 9 rounds with warm-up, pin the program by SHA-256, record spread | PR figures are single runs; serial 20-call sets varied 2x (213.6 vs 425.6 ms); whoami's 1-byte functions give meaningless speedups | Z2, gate 9.10 (A7) |
| X2 | No millisecond budgets in hosted CI; KotOR timings are local manual evidence; CI asserts non-time properties only | hosted windows-latest is NTFS, noisy, has no game data, cannot validate ReFS | Z1, Z2 |
| X3 | Update `docs/ci.md` "Not yet run on GitHub Actions" | run 40577257118 is green | Z4 |
| X4 | Correct the two overstated rc sentences (README 44-46, module README 669) now, as a doc-only fix before E3a/E3b | E0 disproves both | Z15 / R1 (A6) |
| X5 | Make the missing-revision error harder to bypass: it hands back the current revision, so a blind retry passes a revision the agent never read; include `latest_editor` and `subjects_changed_since`, and test the read/edit/conflict/re-read loop in the skill text | the check protects only agents that pass a revision they read; rebase is dependency-blind (struct vs prototype subjects) | Y1/Y3 |
| X6 | Bound the reader wait on `.sync.lock` (`SYNC_LOCK_S` 900 s) with a structured busy hint; measure rebuild per phase | one agent's edit can stall every other agent's read on that view for up to 15 min | Y3 |
| X7 | Land the stable agent id (`options.as`) earlier | journal attribution (C1-11), per-agent views and E3a's fair key all depend on it; today attribution is per process, so ten agents behind one MCP server are one author | Y3 (pulled forward from a Y5 precondition) |
| X8 | State `requireExpect` is documented but not built; protocol-2 engine ignores `expect` on signature/data_type; struct/variable edits have no engine compare | engine-direct clients are unprotected | R1 (A6), E1 |
| X9 | Orphaned shared work never ages out (no TTL, memory-only journal, capped at 200k entries) and pins the project OS lock; decide `orphanKeepS` and the optional recovery dump | "no orphaned programs" cannot be a soak criterion otherwise | E3b, E6 |
| X10 | Document that one MCP process runs 4 engine workers and accepts 8 outstanding calls per lane; the 9th concurrent `ghidra_query` from one harness gets `Server busy` plus a retry hint, by design | the "2 and 3 simultaneous succeed" claim is silent on it | Z13 |
| X11 | `runtime.py:240` still takes a per-session `.request.lock` and answers "runtime session is busy" to a second concurrent runtime call | same failure class the comment complained about for queries | Y4a or Z10 |
| X12 | Reconcile function counts everywhere and name the denominator in every per-function figure | 8,966 vs 8,616 vs 10,849; fixtures 4,497 vs 3,959 | Z6, Z13 |
| X13 | Add percentiles to "Measured, not promised": large-function bucket median 43 ms, p95 268 ms in the stored capture | prevents the next review finding the same over-claim | R1 (A6) |
| X14 | Fix the golden confound and make the golden gate automation, not prose; re-baseline the x64 fixtures (one CRT `strncmp` function differs, GP-7212); note `identical_after_normalisation` is 0 on real KotOR diffs, so the normaliser's real effect is unmeasured | the 77.12% mixes causes; Hydra CONTRIBUTING states the policy but no workflow runs it | Z7, Z15 |
| X15 | Make the CI engine job follow the release under test (`hydra.py` pins `12.3-hydra.2`; `test_engine_options.py` is fixtures-gated and skipped) | CI should exercise hydra.3/hydra.4 after the pin bump | R1 (`bump_hydra.py`), Y4a |
| X16 | Derive `copied`/`imported` in `targets.adopt` from observation instead of literals; state the upgrade-cache background copy in the answer | tautological assertions today | Z5 |
| X17 | Tests for `userscripts._stage`; flag a read-mode script whose `attemptedChanges` is non-zero | a mutating script is rolled back silently with `changed:false` | Z5, Y4e |
| X18 | Doctor should recommend `java.io.tmpdir` on fast NTFS while root and work copies live on ReFS; say a block clone shares blocks with its source and is no protection against volume loss | tmpdir on ReFS made close take 22-41 s | Y4b, Y2 |
| X19 | Surface engine fork cost, warnings and queue info in Hydralysis sync/job/status details | users on NTFS or a loaded daemon cannot see why an operation is slow; `workcopy.py:326,390` keep only four fields | Y2, Y4a (A4) |
| X20 | ReFS claims cannot be validated on hosted runners: provision a ReFS volume (not verified whether hosted runners can) or keep ReFS tests as logged manual gate evidence | `docs/ci.md` | R1 / owner |
| X21 | Independent second backup copy (OD1) and a doctor count of independent verified copies; kill-mid-fork orphan folders listed by `backend backups` and swept at start | a same-volume clone survives a bad commit, not loss of the volume | Y2, Y4d |
| X22 | Cross-language canonical-manifest vector test (E2 plus Y2, gate 9.8) written first | the single highest-risk interoperability point of the backup gate | E2, Y2 |
| X23 | `ProjectFormat` must distinguish unknown from current (`olderFormat` swallows `IOException`; `currentDbVersion` returns -1 so a read failure looks current) | a failure would look like a current format | E2 |
| X24 | Test that the set of advertised-but-`not_available` actions shrinks monotonically | the 20-tool catalog epoch must not lie (`api.py:81-83` advertises commit/backup options that answer `not_available`) | Y2 |
| X25 | Verify that a read-only adopt of the 12.1.4 KotOR project leaves the tree byte-identical, as an automated test | the claim currently rests on code reading and `docs/verification.md:88` hashes from an earlier run | Z5 |
| X26 | Measure fsync, store write cost per volume, probe overhead per hit on x86, event-log append cost | gate 9.10 lists most as unmeasured | Z2, A7 |
| X27 | Pinned install for the harnesses instead of an editable checkout (`E:\Projects\rusticre-latest` at `f03f334`, shared by four harnesses); rename server `rusticre` to `hydralysis` with the `mcp__rusticre__*` allow-lists and hooks in the same change | any checkout there changes the server on next launch | Z4 |
| X28 | Skill hygiene: three skills have frontmatter names (`hydralysis-ghidra`, `hydralysis-evidence`, `hydralysis-hooks`) that differ from their directories | loaders that key on directory names may mismatch | Z4 |
| X29 | Hydra launcher and `hello` should expose install and JDK so a standalone user or the doctor can assert which install a daemon runs from; stop honouring the stock variable for the Hydra client | engine-side no-stock hole | P1b / E1 |
| X30 | Honest limits in the supervisor notes: on hydra.2/3 a stalled call can only be half-closed and abandoned (at most 8 user plus 3 supervisor abandoned connections); wedge detection costs at least 3 x 5 s; killing a daemon loses the Hydra journal and in-memory overlays not saved by `workcopy_saver` | spec 6 and 7.6 | R1 (A6), Z14 |
| X31 | Runtime: hook by export name; split `runtime_worker.py` (805 lines); correct the doc defects; pin the bundle's static side from `hello.analysisIdentity` and the view revision; a hung-worker case and a runtime/Frida doctor section | `CreateFileW/A` cannot be hooked by module+rva; spec lines 1722-1726 note `prologue` with `checks` can occupy fast workers | Z9, Z10, Y4b |
| X32 | Export refinements: header-row provenance instead of per-row, narrow `code_sha256` to files that affect decompile text, consider moving the loop into a Hydra-hosted script (explicit Java driver did 8,616 functions in 158.6 s vs 315.4 s per-request) | per-row overhead is inferred, unmeasured | Z6 |
| X33 | Functional holes vs GhidraMCP that nothing tracks (no listing of Ghidra memory blocks, namespaces/classes; no read of Ghidra's own memory) | if Hydralysis is declared a replacement these need parity tests or a "dropped" decision | Z8, Z13 |
| X34 | PR #6 description should say the durability of the store (Y0a) is shipped and canonical commit/backup/restore is NOT; Y0e and Y1 are in `y-w1`, not on the PR branch | avoids a stale-claim repeat | PR author |
| X35 | Housekeeping left by the investigators: about 245 MB under `D:/Projects/Hydra/_logs/concurrency-verify` (delete the `kotor/` subfolder when no longer needed), an empty `D:\tmp-supv-root-test`, a scratch file in the session scratchpad | recorded so nothing is forgotten | owner |

## 6. The ordered path to "every P0 satisfied"

Nothing here is scheduled or promised: it is the dependency order implied by the spec's wave plan, with the
proposed Z packages inserted. Dates are unknown and are not given. Release labels: **hydra.3** is the engine
candidate on `release/hydra-3-rc`; **hydra.4** is the engine release the spec prepares (E1-E6, R1);
**Hydralysis 0.5.0** is used here as the first Hydralysis release that pins hydra.4 after Y4, which is an
assumption: the spec says only that Y0a ships "in 0.5.x against hydra.2/3" and that Y4a adopts hydra.4. The
release label is owner decision N10.

### 6.1 Ordered steps

| Step | Wave | Work | P0 / requirements it moves | Evidence that closes the step |
| --- | --- | --- | --- | --- |
| 1 | hydra.3 track | Finish the rc dry run (run 40576898783 was in progress), merge `release/hydra-3-rc` to `main`, owner tags (OD5). Z15 first half: publish the documentation, notices, platform limits and fork wording; fix the two overstated README sentences. | C1-31, C1-33, C2-41, C2-44, C2-46, C2-48, C2-49 (docs) | the published release body contains "fork of"; `main` README no longer says "independent project"; release zips contain LICENSE, NOTICE, NOTICE-HYDRA |
| 2 | W1 | P1a, E1; Y0e, Y1; **Z1 before Y1 merges** | C1-36 (race test), C1-19, C1-07/08/09/11 | gate 9.1 after E1 (seams change nothing); `E test_concurrency` green |
| 3 | W2 | E2, E3a; Y2; **Z4, Z5, Z7** | **C1-35** (commit as a generation, backup, format gate), C1-37, C1-39 (partly), C1-40, C1-20 | gate 9.2 (commit round trip), gate 9.6 (upgrade and backup round trip on the legacy fixture), gate 9.7 (`format_gate.py`), gate 9.4 with `--legacy-project`; golden 12.1.4 vs 12.3 explained (proposed gate 9.12) |
| 4 | W3 | E3b; Y3; **Z3, Z6, Z8** | **C1-38** (full export), C1-44, C2-04, early doctor slice | `test_engine_export` full corpus equals the expected count; gate 9.9 fault matrices (Hydralysis commit points, engine `backup_fault`) |
| 5 | W4 | E4, E5, P1b; **Z2** | C2-15 (E4), C1-26/28/29 engine halves | gate 9.10 measurements recorded before any constant is fixed; Z2 numbers exist |
| 6 | W5 | E6 (soak), then R1; **Z13, Z15 second half** | C1-45, C1-46, C1-47, C1-48 (engine half), C2-34 to C2-40, C1-33 final | gate 9.5 (soak, 12 clients, PR lane green plus one nightly-length run recorded), gate 9.1 at release, 9.3, 9.7, 9.8, 9.11; then owner tags hydra.4 |
| 7 | W6 | Y4a, then Y4b, Y4d, Y4e; **Z9, Z10, Z14** | **C1-43** (supervised daemon, health probe, diagnostics), C1-35 (engine backup adopted), C1-42, C1-41 (partly), C1-34, C1-49 | gate 9.8 (Hydralysis suite against hydra.3 degraded and hydra.4), gate 9.6 again via Y4d; supervisor tests including kill under load |
| 8 | W7 | Y5 (after its four preconditions); **Z11; Z12 only after N2/N3** | **C1-36** second half (per-agent default), **C1-41**, **C1-42** | `tests/test_views.py::test_default_view_is_per_agent`; the KotOR scenario bundle compares equal twice (proposed gate 9.13) |

**"Every P0 satisfied" is reached only at the end of step 8**, and the runtime items (C1-41, C1-42) are the long
pole: they have no package in the spec and depend on Z9, Z10, Z11, and on owner decisions N2 to N4. Before then
the honest statement is the one in C1-51 and in section 2.5.

### 6.2 Where each requirement lands

| Release | Requirements |
| --- | --- |
| hydra.3 (engine, docs only; no behaviour change) | C1-31, C1-32 (engine README), C1-33 (wording), C2-41, C2-44, C2-45 (policy text, with N9), C2-46 (docs), C2-47 (cadence text, with N9), C2-48, C2-49 (docs) |
| hydra.4 (engine) | C1-06, C1-10 (engine half), C1-12, C1-26, C1-28 and C1-29 (engine halves: E5, P1b), C1-45, C1-46, C1-47, C1-48 (engine half), C2-34 to C2-40, C2-42, C2-43, C2-46 (machine check), C2-49 and C2-09 (gate), C2-52, C2-15 (E4), C1-30 (platform fields) |
| Hydralysis 0.5.0 | C1-01, C1-04, C1-05, C1-07, C1-08, C1-09, C1-11, C1-19, C2-07, C2-56, C2-55 (reference row); C1-14, C1-20, C1-21, C1-22, C1-23, C1-37, C1-38, C1-39, C1-40, C1-44, C2-12 to C2-16; C1-17, C1-18, C1-35, C2-10, C2-11, C2-42; C1-26, C1-27, C1-28 (docs), C1-29 (docs), C1-43, C2-03, C2-04, C2-05; C2-01, C2-02, C2-30, C2-31, C2-32, C2-33, C2-58, C1-50, C1-51, C1-16, C2-50, C2-53, C2-54; C1-34, C1-49; C1-02, C1-03, C1-13, C1-15, C2-08, C2-51, C2-57, C2-43 (report-only measurements); C2-06 |
| Hydralysis 0.5.0 only if W6 delivers Z9 and Z10 and N10 says 0.5.0 waits; otherwise the next Hydralysis release | C1-24, C1-25, C1-41 (without write/watch), C1-42, C2-17 to C2-19, C2-21, C2-24 to C2-28 |
| After 0.5.0 (W7, gated by owner decisions) | C1-36 second half (Y5), C2-29 (Z11), C2-20 write, C2-22, C2-23 (Z12) |

### 6.3 Release gates and where they stand

Gate numbers are the spec's section 9. Stated state is what was observed, not what is planned.

| Gate | Condition (short) | Which asks it proves | State observed |
| --- | --- | --- | --- |
| 9.1 Golden diff | hydra.3 vs hydra.4 candidate, KotOR copy, `production` and `explicit`, plus 8 MSVC fixtures, identical, source tree hash unchanged | decompile did not regress across engine changes (guards C1-40's sibling comparison) | not run for hydra.4 (no candidate). hydra.3 against itself: 8,616 identical per the spec. 12.1.4 vs 12.3 is NOT this gate (77.124%, S3) |
| 9.2 Commit round trip | after a commit on the KotOR copy, touched functions decompile identically to the working copy; 25 untouched identical to the previous generation | C1-35 | not run (Y2 not started) |
| 9.3 Characterization | seven scenarios identical at `--protocol 2`; v3 run with `--require-v3` | compatibility | E0 loaders exist (`f47ff15934`); not a release run |
| 9.4 Engine suites | all suites with `--legacy-project`, `client_compat_tests.py`, `format_gate.py`, fork tests on ReFS | C1-06, C1-46, C2-34 to C2-49 | hydra.3: 31/31 `daemon_tests` on the rc zip per the release notes, legacy tests skipped; not run for hydra.4 |
| 9.5 Soak, 12 clients | `soak_tests.py` PR lane green; one nightly-length run recorded | C1-45, C1-46, C1-47, C1-48, C2-39, C2-40 | not run (E6 not started; no harness exists) |
| 9.6 Upgrade and backup round trip | backup, refusal without it, success with it, commit to a new generation, restore, tree hash equal, stock 12.1.4 opens the backup and not the generation | C1-49, C2-09, C2-10, C2-11 | not run (E2, Y2, Y4d not started). Needs stock 12.1.4, so it cannot run on the no-stock proof machine |
| 9.7 DB-version check | `format_gate.py` exit 0; constants equal `format-matrix.json` | C2-46 | not run (E2 not started) |
| 9.8 Compatibility | raw protocol-2 transcript against hydra.4; 1.1.0 client against hydra.3; Hydralysis suite against hydra.3 (degraded) and hydra.4; `bump_hydra.py` verified; canonical manifest byte-identical in both repos | C1-34 pin, C1-10, C1-26 | not run |
| 9.9 Fault matrices | Hydralysis commit points (oracle O1-O6), engine `backup_fault`, Y0a torn files | C1-35 | Y0a torn-file tests pass (V: 459 unit tests); commit and backup matrices not run |
| 9.10 Measurements | fsync per volume, store write cost, backup hash throughput, clone vs copy on KotOR, private-instance open, quick-lane p99 before and after, per-phase named-view cost | C1-02, C1-03, C1-06, C1-12, C2-08, C2-43, C2-52, C2-57 | unmeasured; the figures in the comments are single owner runs |
| 9.11 Hygiene | KelpHect identity on every commit, certification manifest, docs state every limit | C1-31, C1-33, C2-41, C2-48 | not run at release level |
| 9.12 (proposed) | 12.1.4 vs 12.3 golden diff re-captured with options equal, classified, accepted-difference policy | C1-40, C1-20 | proposed here, not in the spec. Today 77.124% identical, gate fails the 98% proposal |
| 9.13 (proposed) | Hydralysis P0 evidence pack: commit round trip (9.2), KotOR runtime scenario run twice with equal bundles, full export equal to the expected count | C1-35, C1-38, C1-41, C1-42 | proposed here, not in the spec |

## 7. Decisions still needed from the owner

Only real choices. Each has the default this document assumes and what it blocks. OD items are the spec's
open decisions (section 10); N items are new, from this investigation.

| # | Decision | Default assumed | Blocks |
| --- | --- | --- | --- |
| OD1 | Backup policy: a second independent copy by default (`backup_min_independent` 1), and who authorises the 50 GB threshold | one primary clone, second root opt-in, ask before any copy over 50 GB | Y2 and Y4d defaults; C2-09, C2-11 |
| OD2 / N1 | Generation mode against the Ghidra GUI: the GUI opening the original `.gpr` sees none of the committed annotations. Headless-only (all work through Hydralysis), or GUI-on-a-fork supported with a "materialise current generation" action? (C2-33 asks the same) | headless-only for now; materialise later, in-place replace never | C2-33; the 0.5.0 documentation wording; the claim that Hydralysis replaces Ghidra as a long-term knowledge base (C1-17) |
| OD3 | Daemon singleton and roots: consolidate `F:\dev-cache\hydra-state` (instance `default`) and the RusticRE root, and enforce `singleton:"per-install"`? Renaming the instance id or state dir starts a second daemon | warn only; no consolidation | C1-29; P1b default policy |
| OD4 | Supervisor default: auto-restart dead or wedged daemons within 3 per 10 minutes, refusing while non-recoverable unsaved edits exist | on | C1-26, C1-43; Y4a default |
| OD5 | Tag and publish hydra.4, pin Hydralysis to it, and the visibility of the private Hydralysis repository | not done | C1-34, Z14, Y4a |
| OD7 | Per-agent default views and the agent identity (`options.as`): when, and who may commit when ten agents run | not before Y5's preconditions; any caller may commit with the confirmation | C1-36 second half, C1-11, Y5 |
| N2 | Is guarded runtime memory WRITE wanted (the comment says "memory read/write")? REA has none | not built; record as an explicit non-goal until answered | C2-20, Z12 |
| N3 | Are hardware watchpoints wanted? They are not REA parity and a mistake can fault the target; the alternative is the static-site `writers` route | not built; `writers` documented as the supported route | C2-22, C2-23, Z12 |
| N4 | Is a live KotOR runtime run acceptable (profile copy only, never the install, no game bytes in any repo), or is fixture-only proof the bar for C2-29? | fixture-only in CI, KotOR run manual on a profile copy | C2-17 to C2-19, C2-29, Z11 |
| N5 | Acceptance policy for the 12.1.4 to 12.3 decompile diff: which threshold or per-class rule counts as explained (the harness doc calls 98% "a starting proposal"; the current result is 77.124%) | decide after Z7 classifies the 1,971 changes | C1-40, proposed gate 9.12 |
| N6 | ReFS: warn only (the spec) or refuse/default the root to a ReFS volume? Refusal excludes every non-Dev-Drive user and hosted CI | warn only | C1-30, C2-06, C2-03 |
| N7 | What does "writable copy" mean for `ghidra_run`: a rolled-back run against a copy that holds edits (what the spec designs), or a persistent script edit mode (a new package that depends on Y1/Y2 and mandatory `expect_revision`)? | rolled-back run | C2-16, Y4e |
| N8 | The third-party comparison figures (GhidraMCP 7.3 KB / 64 KB, 86 ms lock failure, 3.3-4.0 s init; REA 961 KB dossier, 192 s cold import; the old PR6 failures): record as dated owner-reported historical references, or re-measure on another machine that has REA and stock Ghidra? Never on the no-stock proof machine | record as references, not re-run | C1-16, C2-50, C2-53, C2-54, C2-55 |
| N9 | Support and cadence numbers: how often upstream is synced, target time for a security fix to reach a release, how long a `hydra.N` line is supported; and whether a queue position without an ETA is acceptable for the long lane (the spec gives a null ETA when a holder has run >5x the median) | text drafted with blanks; ETA stays null | C2-45, C2-47, C2-37 |
| N10 | Release label: does Hydralysis 0.5.0 wait for runtime/evidence parity (so it can claim replacement), or ship with the C1-51 qualified statement and track runtime/evidence to the next release? | ship 0.5.0 qualified; claim replacement only after P0 | section 6.2 placement of C1-24, C1-25, C1-41, C1-42 |
| N11 | Does P0 C1-36 require BOTH mandatory `expect_revision` and per-agent default views? The "Missing item 2" wording says "or"; the P0 bullet says ";" | both (Y5 is required for C1-36) | whether C1-36 can be closed before W7 |

## 8. How to re-verify

Run from the Hydralysis repository root (`D:/Projects/Hydra/wt/rre-trace` is a clean checkout of `f46788b`
plus this file) with Python 3.11 or later. Keep temp and test roots on D:. Do not run anything below against the
live daemon (pid 18220) or a project you care about; use copies. "Exit code" means read the process exit code,
not the last line of output.

```powershell
# 0. identities and hashes
git rev-parse --short=7 HEAD HEAD~1                # this file's commit, then its parent f46788b (PR #6 tip)
git -C D:/Projects/Hydra/hydra-engine rev-parse --short=10 release/hydra-3-rc design/protocol-3 feat/protocol-3 feat/w1-hydra main
git log --format='%an <%ae> | %cn <%ce>' -3        # must read KelpHect <kellhect@gmail.com> both ways

# 1. full unit suite (459 tests OK, 9 skipped at f46788b per the durability reviewer; engine tests skip without env)
$env:PYTHONPATH='src;tests'; $env:TEMP='D:\tmp'; $env:HYDRALYSIS_TEST_ROOT='D:\tmp\hydralysis-tests'
python -m unittest discover -s tests

# 2. no-stock tests with the stock variable empty (17 tests OK)
$env:GHIDRA_INSTALL_DIR=''; python -m unittest test_no_stock_ghidra test_backends

# 3. real-engine integration (7 tests OK in CI, 95.9 s; the V runs: 46.7 s)
$env:HYDRALYSIS_INTEGRATION_ENGINE='<hydra-2 or hydra-3 install>'; $env:HYDRALYSIS_INTEGRATION_CLIENT='<ghidra_session.py>'; $env:HYDRALYSIS_INTEGRATION_JAVA='<jdk 25>'
python -m unittest test_engine_integration -v

# 4. concurrency one-offs (not committed tests; scripts live outside the repo)
python D:/Projects/Hydra/_logs/concurrency-verify/conc_probe.py      # 1/2/3/12 simultaneous ghidra_query
python D:/Projects/Hydra/_logs/concurrency-verify/kotor_probe.py     # native 2x20, KotOR copy
python D:/Projects/Hydra/_logs/concurrency-verify/two_daemons.py     # two read-only daemons, one project

# 5. golden 12.1.4 vs 12.3 (exits 1 today: 77.124% identical, gate 98%)
python tools/golden.py diff D:/Projects/Hydra/_golden/baselines/ghidra-12.1.4/kotor/explicit D:/Projects/Hydra/_golden/baselines/hydra-3-candidate/kotor/explicit --profile corpus --report D:/tmp/12.1.4-vs-h3.json --no-text
python tools/golden.py timing D:/Projects/Hydra/_golden/baselines/hydra-2/kotor/production   # per-size-bucket decompile time
python tools/golden.py treehash <project dir>                                              # source tree hash before and after

# 6. CI and release state
gh run view 40577257118 --repo RusticStack/RusticRE                     # four jobs success at f46788b
gh api repos/RusticStack/RusticRE/releases/latest                       # 404 today
gh repo view RusticStack/RusticRE --json visibility -q .visibility      # PRIVATE
git branch -r --contains de1b763                                        # mandatory expect_revision is on origin/codex/complete-re-workflow

# 7. process and filesystem checks (read-only)
Get-CimInstance Win32_Process -Filter "Name='java.exe'" | Select ProcessId,CommandLine
Get-Volume | Select DriveLetter,FileSystem
Get-Content E:\dev-cold\skills-archive\2026-10-27\MANIFEST.json
```

Engine suites, in the Hydra repo with a fresh state root (never the live daemons):

```powershell
$H='python Ghidra/Features/HeadlessSession/examples/daemon_tests.py --ghidra <install> --work D:\work\dt --exe A.exe --dll B.dll'
Invoke-Expression "$H"                                  # 31/31 on the rc zip per the release notes
Invoke-Expression "$H --baseline"                       # E0 premises: six CONFIRMED on hydra.3 (lane_starvation, dead_client_lock_wait, import_wait, fork_save_behind_analysis, cancel_lock_wait, script_shared_visibility)
Invoke-Expression "$H --only fork"                      # clone vs copy; add --project <KotOR copy> on ReFS for the numbers
```

Recount this file's summary table (bash; prints the number of requirement rows, the count by status and the
P0 rows; it should say 109 and match section 2.1):

```bash
python - <<'PYEOF'
import re, collections
rows = [l for l in open('docs/pr6-traceability.md', encoding='utf-8') if re.match(r'\| C[12]-\d\d', l)]
cells = [[c.strip() for c in l.strip().strip('|').split(' | ')] for l in rows]
cells = [c for c in cells if len(c) == 7]  # the P0 table in section 2.5 has 5 columns
print(len(cells), collections.Counter(c[2] for c in cells))
print([c[0] for c in cells if '(P0)' in c[0]])
PYEOF
```

What this file does not do: it ran no new measurement, it did not read the uncommitted rev5 spec, it did not
re-run the golden diff, and the `y-w1` and `hydra-w1` worktrees were read-only and may have moved since the
commit hashes in section 1 were taken.
