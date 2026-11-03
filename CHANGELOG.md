# Changelog

Hydralysis follows the version policy in [docs/versioning.md](docs/versioning.md): which release pins which
engine, what 0.x means, and how to roll back a pin. Every release states only the claims whose tests pass.
Nothing here is a tag: a release is tagged by the owner.

## Unreleased

- The engine client is native by default. With the optional `hydralysis_native` extension built (`native/`, `maturin develop --release`), `hydra.load_client` returns `hydralysis.engine_client.NativeClient` instead of importing the engine's `ghidra_session.py`: the request framing, ids, `hello` negotiation, deadlines (library 1.1.0 semantics), the pinned-release and protocol 3/2 checks and the mapping of an engine answer to `SessionError` run in Rust (a vendored copy of the engine's `hydra-client` session core), with the GIL released for every wait. A running daemon is joined without the library; a daemon that must be started, a wedged one and every launcher error still go through `ghidra_session.py`, which is then imported. `HYDRALYSIS_NATIVE=0`, a missing extension, or a library that is not 1.1.0 of protocol 3 keeps the Python client, with the same results (`tests/test_engine_client.py` runs the same script through both). Measured on one agent process against a running daemon: private bytes after connecting 13.9 MB -> 11.0 MB (median of 8), 40 fewer imported modules, connect CPU 39 ms -> 16 ms; per-call cost is the daemon's and does not change. The interpreter itself (8.4 MB) is what remains until the MCP host is native.
- Native MCP host (`native/hydralysis-mcp`, optional): a Rust build of the stdio server that keeps a few megabytes resident instead of a
  Python interpreter. Same catalog (epoch 5, same hash and bytes, from `native/hydralysis-mcp/catalog.json`), lanes, output cap and error
  envelopes. It answers `fingerprint`, `imports`, `function`, `bytes`, `strings`, `sigscan`, `callers` and `xrefs` itself for well-formed
  images and runs everything else, and every call it is not sure about, in `python -m hydralysis.worker`, started on demand and closed when
  idle. `hydralysis mcp` starts the binary when `src/hydralysis/bin/` (or `HYDRALYSIS_MCP_BIN`) has it and falls back to the Python server
  otherwise; `HYDRALYSIS_MCP=python` forces the Python server. Build with `tools/build_mcp_host.py`. See docs/clients.md.

## 0.8.0

Released 2026-11-02. This release (0.8.0) pins Hydra Engine `12.3-hydra.6` (protocol 3), released 2026-11-02; the pin statements, version strings
and archive hashes were written by `tools/bump_hydra.py` from the published release zips.

Test runs for 0.8.0: unit plus engine-gated suite 2,020 of 2,020 against a locally assembled 12.3-hydra.6 install (the `final2` install, not
the `final2b` install the engine's last gates ran on, and not the published zip): 0 failed alone, 2 failed only under load and passed alone
(`test_trace_e2e.M1` failure-mode tests); two earlier runs of the same suite on the same install had 1 failed alone and 0 failed alone with
2 load-only failures, and the unit run `hyd-unit.log` had 3 failed alone (`test_durable.WriteGate`, `test_trace_extras.Watchdog`,
`test_views.Processes`); fixes followed (store-load cache, phantom budget gap, decompile job write gate, test readiness) and the suite was not
re-run on the final commit. `bump_hydra.py` was not run because the release zips do not exist yet. Details in `.github/local-test-record.json`
and the engine's `docs/release-notes-12.3-hydra.6.md`.

Not met or not run: the bare-loop trace overhead with every hit kept; aggregate counters (not built); hosted CI; reproduction of the
issue-6 overflow on the reporter's real binary; the soak on the final engine install. See `docs/trace-overhead.md`.

Semantic trace (for 0.8.0, which pins engine 12.3-hydra.6; the version is bumped at release with `tools/bump_hydra.py`).

- New tool `trace` (the 21st; catalog epoch 3, schema budget 8,192 -> 9,216 bytes): start, stop, status, query, diff, explain, mark,
  export, check, import and resymbolize. Routed to the engine lane; export, import and resymbolize ride the long lane. Replies are
  bounded and carry counts, event ids, the revision and the coverage gaps. Offline: segment verify and JSONL import in Python,
  rebuild and export through the engine install's `hydra-trace.exe`.
- Evidence: source kind `from_trace` (session, event ids, revision); bundles gain `traces/<session>.json`.
  Trace limitation codes join the evidence catalog (underscored: `producer_lost`, `optional_hook_refused`, ...).
- `hydralysis.trace_canon`: Python twin of the TRACE-1 canonical JSON, record hash and segment framing, pinned to vectors.
- Vendored TRACE-1 schemas (`trace_schema/`) with a validator and a test that they equal the engine's.
- `hydralysis.profiles`: TOML profile loader, validator, build-bound hook verification, query modules; `docs/trace-profiles.md`.
- `trace_hashes` (FNV, CRC32, Murmur3, profile codecs, dictionary, interpretation revisions), `trace_bindings` (script/native
  tables), `trace_corpus_diff` (corpus diff and invalidation report), `trace_reports` (write survival, hook bypass).
- Runtime memory policy (GitHub issue #7): `write` and `watch` stay fixture-only by default (existing behaviour and tests unchanged). New owner-authorized mode: the local setting `runtime_authorized_targets` lists an exact build SHA-256 with its actions, a maximum size and bounded address ranges (module+RVA or absolute); the compare-and-swap write, undo log, executable-range refusal and disarm readback are unchanged, and a watch also needs the build's own conformance stamp (`tools/watch_conformance.py --bind-build <exe>` writes `watch-stamps/authorized/<sha256>.json`). No authorization is a coded refusal (`[not_authorized]`, `[outside_authorized_range]`, `[conformance_stamp_missing]`, ...); the fallback for an unverified build is documented as the static `writes` action plus a live probe. See `docs/runtime-memory-policy.md`; `config.example.json` lists both settings.
- `ghidra-query` / `ghidra_query`: decompile option `max_result_mb` (CLI `--max-result-mb`, MCP argument or `options`) bounds the engine's whole reply, unlike `max_characters`, which only clips the C text; `--max-characters` is now a CLI flag too, and `--help` states the difference.
- Partial decompile results: the engine fields `fragments` (`[{start,end,class: code|data|unknown}]`), `truncated`, `bytes_emitted` and `reason` are carried through unchanged and summarised (`decompile`); a decompile the engine stopped on purpose is a partial result, not a failure (`query.accepted`, export rows). New `hydralysis.decompile_result` turns them into evidence coverage, and two limitation codes join the evidence catalog: `decompile_truncated` (bounds coverage) and `non_code_fragments`. Tested against fake engine replies only; the engine side is on the engine's `trace/issues-eng`.
- Decompile end to end through Hydralysis (hydra-engine issues 6 and 7, engine PROTOCOL-3 8.21). When the RusticQuery script cannot answer ("No pcode could be generated", a timeout, a buffer overflow) `ghidra_query decompile` retries with the engine's own `decompile` command, labelled `fallback` (`via`, `reason`, `engine_s`, `timeout_s`, `job`), so partial C and `fragments` reach the caller. That retry can take minutes, so it runs as a decompile job (`decompile-<id>`, `hydralysis.decompile_job`): the call returns the job at once, `job` with the id reports progress and then the `result`, and the CLI follows it itself (progress on stderr, `--wait SECONDS`, default 3600, 0 = print the job and return). Ranges now match the engine: `max_result_mb` 1..1024 (omitted = the engine's adaptive budget), new `max_result_kb` 1..1048576 (wins over MB; CLI `--max-result-kb`) and `offset` (characters; CLI `--offset`) for paging. Replies carry `partial`, `cut`, `budget`, `offset` and `next_offset` (summarised in `decompile`). Evidence: `decompile_truncated` is a cut by a cap the caller named, new `decompile_budget_limited` a cut by the engine's auto budget, new `decompile_paged` a page with `next_offset`. MCP catalog unchanged (options carry the new fields). Real target (Cyberpunk2077.exe 2.5): see `docs/decompile-e2e.md`.
- Docs: the README links to the engine README's "System requirements" (spec 14.13): minimum, reference, recommended and optional-capability requirements with the recorded i7-13700KF runs, the support matrix and the resource-constrained behaviour (refused or explicitly partial, never different evidence). The 16-agent and multi-project measurements behind the trace daemon-impact gate are in the engine's `docs/release-notes-12.3-hydra.6.md` (four of the 16 agents there are Hydralysis agents).


## 0.7.0

This release (0.7.0) pins Hydra Engine `12.3-hydra.5` (protocol 3), released 2026-11-01. It is a
minor step: it changes the publish queue's reply (`failed`, `unled`, `sealed`, `next`), journals the
subjects a publish actually applied, and moves the engine pin.

The engine and client archives are the `12.3-hydra.5` release files, written by
`tools/bump_hydra.py` together with the pin statements in `README.md` and `THIRD_PARTY.md`.
The client stays 1.1.0 on protocol 3.

### Changes in 0.7.0

- **Warm publish worker pool.** A publish hands its job file to a warm worker (`python -m hydralysis.viewpool --serve`) instead of
  spawning `python -m hydralysis.views <job.json>` for every publish, so the package import (0.06 s of CPU, 0.12-0.17 s
  of wall per worker here) is paid once per process and not once per publish. The worker is still a separate process,
  runs the same `views.run_job` and writes the same job record; one job runs per worker at a time, at most
  `publish_batch_max` workers exist per client, at most one is kept idle and an idle one exits after 2 s. A client with
  every worker busy, or one whose pool cannot start, takes the one-shot worker exactly as before; test-fault runs never
  pool. Output, job records, ownership, cancellation and kill isolation are unchanged.
- **Publish verification through the engine's `decompile` command.** It used 51 `script` calls per
  publish (6.08 ms each) and now uses the command (0.39 ms each) with a window of 8 in flight, same
  text, same 25 functions in listing order, first difference refused. A publish's folder flush
  forces only the files the save wrote (14 -> 5 fsyncs, 27-35 -> 12.5 ms), not the fork's
  already-forced copies; the manifest is still written after every byte of the generation is forced
  and the `CURRENT.log` append remains the commit point.
- **The view finalize journals the subjects the generation applied, not a wildcard.** This fixes the
  self-publish edit conflict: the lazy finalize's `subjects:["*"]` overlapped every subject, so an
  agent's next `type_edit` could conflict with its own publish. The subjects now come from the
  sealed manifest (union across crossed generations); an edit on a subject the publish did not touch
  rebases, and an edit on a published subject still conflicts. No retry loop and no weakened
  validation. `commits.finalize` does the same from its manifest ids.
- **A dead publish worker or leader fails fast, and an unappended generation rolls forward.**
  `status show=queue csid=` answers `state:"failed"` with the job's `job_state`, exact error and a
  `next` when the worker is gone (10 s), and `state:"unled"` when no job and no leader exist for
  10 s. The next publish moves a sealed-but-never-appended generation aside
  (`gen/NNNN.abandoned-<uuid>`) and rebuilds it; nothing is retried or dropped by `status`. The
  job-registry lock no longer covers the warm-worker dispatch, so a slow handover cannot time out
  another publisher after its changeset was sealed; a remaining lock gives a structured `busy` that
  names the sealed changeset.
- **Engine pin `12.3-hydra.5`** (protocol 3), replacing `12.3-hydra.4`.
- `backend status` (and every backend report) reads the CPU architecture from `PROCESSOR_ARCHITEW6432` /
  `PROCESSOR_ARCHITECTURE` on Windows instead of `platform.machine()`, which could start `cmd /c ver` when its WMI
  query failed on a loaded machine; status now starts no process in that case either.
- Publish pipeline: a leader waits for `.commit.lock` in a first-come queue instead of polling; decided changesets are
  settled in their views after the commit lock is released. A changeset with a generation does not wait for a busy
  view (the view's next call replays it from `CURRENT.log`); one decided without a generation (already in master,
  converged) keeps the bounded view wait, since no log row replays it. A lineage the registry already names is found
  without a lock. The `.bak` copy of a sealed record is no longer fsynced (the new version still is).
- New setting `tampered_cache_s` (default `0`, off). The 4.7 tamper check re-hashes every published generation before
  each publish. With a value above 0, a generation whose manifest hash and content files' size, modification time and
  file id are unchanged since its last full re-hash is not re-hashed again, for up to that many seconds. The verified
  signatures are kept in `lineages/<id>/.tamper-checks.json`, so they reach every publish worker (the setting is passed
  to the worker). Weaker than a re-hash: a write into a generation that puts back the size, time and file id is found
  by the next full re-hash, at most `tampered_cache_s` seconds later.
- MCP request handling (H5): three lanes sized from the CPUs the OS grants the process (the affinity mask on
  Windows, `os.process_cpu_count()` elsewhere): `fast` (offline tools, 4..16 workers), `engine` (short engine tools,
  2 per CPU, 8..24, a thread per accepted call) and `long` (`ghidra_run`, `prepare`, 8), so long tools no longer hold
  the threads queries need. Engine + long never pass the engine's 32 parallel requests per connection. Every budget is
  at least the 0.6.0 one. `notifications/cancelled` is honoured: a queued call never starts; a running engine wait in
  this process (pooled attempt, plain hydra.4 call, the wait for a pool entry) sends `cancel` to the engine and returns
  after the grace, freeing its slot; `prepare`, offline and runtime tools run to their end and only their reply is
  dropped. The cancelled request gets no reply (MCP). Everything else on the wire is unchanged.
- Runtime sessions (H9): the worker serves each IPC connection on its own thread; `status` is answered beside a running
  request and is sent without the session request lock when the worker's ready.json says `concurrent_status` (an older
  worker still alive gets the lock as before); every other action stays one at a time. A request that outlasts the
  idle time no longer lets the worker retire as idle.

### Measured for this release

All numbers are from the engine's round-4 reports and the Hydralysis lanes named here.

- Warm publish workers, 16 agents, 15 interleaved runs: **Python CPU 6.57 -> 6.07 s (-7.6 %)** and
  Python processes at peak **45-47 -> 37-39**, with 8 publish jobs over 4 worker pids; tree CPU,
  tree memory and `hy_publish` inside the session noise (round-4 `hyviews` report).
- Publish verification and flush, 16 agents, six interleaved runs: leader `build_ms` **922 -> 690 ms**
  and `hy_publish` p50 **1,274 -> 1,105 ms**, with 3 of 6 runs under 1 s (845/960/994 ms); the
  remaining time is eight concurrent publishes over about 1.5 builds plus the harness' 250 ms poll
  (round-4 `io` report).
- Edit reliability, 13 interleaved sessions per engine: **208 edits, 0 failures** (104 on the exact
  final commit) and **208 publishes, 0 failures** in the two series; 412/412 reply keys and the
  canonical digest in 13/13 final-series runs; the h4 control is 104 edits, 0 failures
  (round-4 `hyedit` report).
- Hydralysis suite: **1,640 test results, 0 failed** alone or only under load; engine-gated
  integration against the `12.3-hydra.5` build: **17/17, OK** (round-4 `hyedit` report).

### Test runs for this release

- Unit suite: 1,640 test results, 0 failed. The one task-plan problem
  (`test_runtime_scenario_fixture`: "ran 23 tests, 1 were planned") is pre-existing and reproduces
  identically on the base worktree; all its tests ran.
- Real-engine suite against the `12.3-hydra.5` build: 17 of 17 engine-gated tests, OK.
- The 16-agent series: 208 edits, 0 failed; 208 publishes, 0 failed; 412/412 reply keys and the
  canonical digest in the final series.
- `tools/bump_hydra.py --release 12.3-hydra.5 --dist <dir> --check` exits 0 on the release
  artifacts, so every pin statement agrees with the archive hashes.

### Limits of this release

- Windows x64 only. Copy-on-write cloning exists only on a ReFS volume; on NTFS a full copy is made.
  Nothing about ReFS is tested for this line (no ReFS volume on the release machine); NTFS is the
  release file system.
- The one-way upgrade: a commit may write a generation that older engines cannot open.
- A harness restart is needed once, for the catalog epoch.
- `hy_publish` is 1.1-1.5 s median at 16 agents under eight concurrent publishes, not below 1 s; a
  publish with no queue is 845-994 ms end to end in the same runs.
- Every limit of PROTOCOL-3.md 6.2 is stated in the engine module README ("Limits of 12.3-hydra.4
  and protocol 3"; the protocol is unchanged in 12.3-hydra.5); the ones this client owns or sees
  first (the history cap of 4096 records or 20 MiB, no rotation of the append logs, abandoned calls
  on hydra.2/3, the leave stall, the trusted quick hint, no semantic dependency tracking in subset
  commits, backups verified through the OS cache, the upgrade gate is not a security boundary) are
  in `README.md`, "Limits of this client with hydra.4".

## 0.6.0

This release (0.6.0, label OD11) pins Hydra Engine `12.3-hydra.4` (protocol 3), released 2026-10-30. Hydralysis
still speaks protocol 2 to a released hydra.3 engine when `hydra_allow_unpinned` is set (the hydra.3 degraded set
below). The pin is the published engine zip, SHA-256 `f0f2844c…`, written by `tools/bump_hydra.py`.

### Changes in 0.6.0

- Adoption of the engine's capabilities: protocol negotiation, engine-written backups and `generation` candidates
  for commits, the script worker for `ghidra_run` (`isolation`), the deadline helper for hydra.2/3 with its
  abandoned-call budget, and the supervisor.
- Catalog epoch 2 (as in 0.5.0, which was not tagged): restart the MCP harness once when updating from 0.4.x.

### Fixed during the release gates

Each fix has a test that failed before it and passes with it.

- **Per-connection view cap.** hydra.4 caps a connection at 4 open programs (`maxViewsPerClient`). On that refusal
  the client now closes its least recently used read-only program on the connection and opens again; writable
  programs are never closed for it. Test `test_query.ClientCap`.
- **Shared manifest vector.** `tests/vectors/canonical-manifest.json` is now the engine's file byte for byte, and
  both sides reproduce each other's hashes. Test `test_lineage.SharedVector`.
- **The hydra.3 degraded set.** Against a protocol 2 engine, the tests of classes that need a hydra.4 feature skip
  one by one with a reason that starts `hydra.3 degraded set:`; against a protocol 3 engine they never skip. The
  classes are listed in `docs/versioning.md`. Test `test_degraded_set`.
- **Bounded pool connect.** Making a connection (up to its `hello`) is bounded by the probe's or the request's
  deadline, with a floor of 5 s, so a suspended engine daemon costs a missed probe instead of a hang. Tests in
  `test_deadline.Mechanism`.
- **View leak.** Superseded working copies are discarded in the engine (after a sync, a publish, a rebase, an
  eviction, a stop and at process exit) instead of staying open as orphaned work until `maxViews` was reached, and a
  copy the daemon still holds for a reader is not reused. Tests `test_view_leak`, `RealEngineViewLeak` (hydra.4).
- **Rename-aware spot check.** The publish spot check accepts an untouched caller whose decompiled text differs
  only by the changeset's renames; any other difference still fails with `candidate_failed`. Test `test_view_leak`.
- **Views are built from their own base generation.** A view behind the head that was rebuilt used to get the head's
  content with its own records on top. It is now built, and read, from the generation it is based on; a base that
  is gone answers `base_unavailable` with the rebase as `next`. A read of a stale view keeps answering from its
  base. Tests `test_view_base`, `RealEngineViewBase` (hydra.4).
- **Fair store lock.** Writers of the store wait in arrival order (a queued lock on Windows) instead of polling, so
  one writer can no longer keep the others waiting until `LockBusy`; the wait stays bounded. Tests
  `LockedIsFair`, `LockedSurvivesAKilledHolder`.
- `stale_view` says that the client rebases (`type_edit kind=rebase`) and that Hydralysis does not retry the edit.

### Test runs for this release

- Unit suite: 1511 of 1511 passed. Real-engine suite against the `12.3-hydra.4` install: 1511 of 1511, 0 failed.
- Against the released hydra.3 (degraded set): 1477 of 1477 on the gate branch; not re-run on the final tree.
- The engine's soak (gate 9.17): its PR lane passed; its one nightly run (16 agents on 4 projects, 1 h 47 min,
  stopped early) failed on the view defect fixed above, which was not re-run in a nightly.

### Limits of this release

- Windows x64 only. Copy-on-write cloning exists only on a ReFS volume; on NTFS a full copy is made. Nothing about
  ReFS is tested for the hydra.4 line (no ReFS volume on the release machine); NTFS is the release file system.
- The one-way upgrade: a commit may write a generation that older engines cannot open.
- A harness restart is needed once, for the catalog epoch.
- Every limit of PROTOCOL-3.md 6.2 is stated in the engine module README ("Limits of 12.3-hydra.4 and protocol 3");
  the ones this client owns or sees first (the history cap of 4096 records or 20 MiB, no rotation of the append
  logs, abandoned calls on hydra.2/3, the leave stall, the trusted quick hint, no semantic dependency tracking in
  subset commits, backups verified through the OS cache, the upgrade gate is not a security boundary) are in
  `README.md`, "Limits of this client with hydra.4".

## 0.5.0 ("qualified", not tagged)

Client only. The 0.5.0 release is pinned to the Hydra Engine `12.3-hydra.3` line (protocol 2); the current tree already carries the `12.3-hydra.4` pin (protocol 3), see 0.6.0 above. A 0.5.0 tag therefore has to be cut from a commit before that pin bump; the tree as it stands is 0.6.0 material. The engine's locking is the engine's;
heavy parallel use is something to measure, not something this release promises.

### Changes in 0.5.0

- The `saved` key of `ghidra_query action=status` and the setting `overlay_save_debounce_s` are removed, and the
  background saver process is gone: a working copy is no longer saved after edits pause, and unsaved changes are
  replayed from the store.
- The per-target `.sync.lock` is replaced by a per-view lock; a wait that runs out answers a structured `busy`
  (with `retryAfterMs`).
- Default views are per agent (`options.as`); callers that share an id share a view.
- `generationKeep` and `viewIdleDeleteS` in `config.example.json` are reserved: no code reads them yet. Generations
  and views are never removed automatically; `backend action=backups options.op=remove` removes one only with
  `confirm:true`.
- Views of one master share one base (built once per master revision, generation and engine release), and each sync
  uses a connection of its own.
- A working copy's folder is checked before it is opened; a damaged one is moved aside and rebuilt from the store.
- The engine daemon this client launches gets `maxLong` and `maxQuick` from the new `expected_agents` setting
  (default 16); a daemon that is already running keeps the limits it started with.
- `ghidra_query action=type_edit options.kind=commit` writes pending records into a new generation of a copy of the
  analysed project; `commit_revert` returns to the generation before. A commit asks for
  `confirm_one_way_upgrade`. These are client features, not engine guarantees.
- `backend action=backups` lists, verifies and (as a dry run unless `confirm:true`) removes backups and
  generations. A block clone protects against a bad commit, not against loss of the volume.
- The engine-side sealing and admission need hydra.4.
- Catalog epoch 2: restart the MCP harness once to see the new tool schema.

### Limits of this release

- Windows x64 only.
- Copy-on-write cloning of a project exists only on a ReFS volume; on NTFS a full copy is made. Nothing about ReFS is
  tested for the hydra.4 line (no ReFS volume on the release machine); NTFS is the release file system.
- The one-way upgrade: a commit may write a generation that older engines cannot open.
- A harness restart is needed once, for the catalog epoch.
