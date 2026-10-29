# Changelog

Hydralysis follows the version policy in [docs/versioning.md](docs/versioning.md): which release pins which
engine, what 0.x means, and how to roll back a pin. Every release states only the claims whose tests pass.
Nothing here is a tag: a release is tagged by the owner.

## Unreleased (0.5.0, "qualified")

Client only. The 0.5.0 release is pinned to the Hydra Engine `12.3-hydra.3` line (protocol 2); the current tree already carries the `12.3-hydra.4` pin (protocol 3), see below. A 0.5.0 tag therefore has to be cut from a commit before that pin bump; the tree as it stands is 0.6.0 material. The engine's locking is the engine's;
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
- Copy-on-write cloning of a project exists only on a ReFS volume; on NTFS a full copy is made. Both work.
- The one-way upgrade: a commit may write a generation that older engines cannot open.
- A harness restart is needed once, for the catalog epoch.

## 0.6.0 (planned, label OD11)

Pins the Hydra Engine `12.3-hydra.4` (protocol 3). Hydralysis still speaks protocol 2 to a released hydra.3 engine
when `hydra_allow_unpinned` is set. Adoption of the engine's capabilities: protocol negotiation, the deadline helper
for hydra.2/3 with its abandoned-call budget, and the supervisor. The release notes are completed when the owner tags
it, and claim only what the gates against hydra.4 showed.
