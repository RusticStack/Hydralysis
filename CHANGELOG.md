# Changelog

Hydralysis follows the version policy in [docs/versioning.md](docs/versioning.md): which release pins which
engine, what 0.x means, and how to roll back a pin. Every release states only the claims whose tests pass.
Nothing here is a tag: a release is tagged by the owner.

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
