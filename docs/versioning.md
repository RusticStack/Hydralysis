# Versioning, pins, upgrade and backup policy

## What a version means

Hydralysis uses `MAJOR.MINOR.PATCH`. While `MAJOR` is 0:

- a MINOR step may change a tool's reply, a setting or an on-disk format; every such change is named in
  `CHANGELOG.md` under "Changes in X.Y.0";
- a PATCH step fixes defects and changes no setting, no reply key and no format;
- the tool catalog carries an epoch. A change of the epoch means MCP clients must be restarted once.

The package version lives in `pyproject.toml` and `src/hydralysis/__init__.py`; both must be equal, and a release tag
`vX.Y.Z` must equal them. A `.devN` suffix marks an unreleased tree. `tests/test_release.py` checks this.

## Which release pins which engine

The engine release, protocol and client archive are pinned in one place, `src/hydralysis/hydra.py` (`RELEASE`,
`PROTOCOL`, `CLIENT_VERSION`, `ASSETS`). Only `tools/bump_hydra.py` changes them, together with the two pin
statements in `README.md` and `THIRD_PARTY.md`.

| Hydralysis | Pinned engine | Protocol | Notes |
|---|---|---|---|
| 0.5.0 "qualified" | `12.3-hydra.3` | 2 | client only; the engine's locking is hydra.3's |
| 0.6.0 (label OD11) | `12.3-hydra.4` | 3 (2 accepted with `hydra_allow_unpinned`) | adoption of the engine's capabilities |
| 0.7.0 | `12.3-hydra.5` | 3 (2 accepted with `hydra_allow_unpinned`) | publish reliability and warm publish workers |
| 0.8.0 | `12.3-hydra.6` | 3 (2 accepted with `hydra_allow_unpinned`) | semantic trace, owner-authorized runtime mode, decompile fallback jobs, adaptive trace sampling |

A pinned client refuses an engine whose release stamp differs, unless `hydra_allow_unpinned` is set; then it accepts
library protocols 2 to 3.

## The hydra.3 degraded set (gate 9.8)

Gate 9.8 of the engine's `PROTOCOL-3.md` runs the whole test suite with the real-engine classes against hydra.4 and
against the released hydra.3 ("degraded set"). On hydra.3 the client runs in the degraded mode of 7.5: protocol 2, no
`capabilities`, the 1.0.0 helper library for deadlines. The degraded set is every test except the classes below, which
need a hydra.4-only feature: on hydra.3 each of their tests skips with a reason that starts `hydra.3 degraded set:`.

| Class | hydra.4 feature it needs |
|---|---|
| `test_backups.RealEngineBackups` | the engine-written backup (`backup` capability, E2) and its upgrade gate |
| `test_backups.RealEngineFaultMatrix` | the E2 commit path: engine-written backups, `generation` candidates |
| `test_userscripts.RealWorker` | E7's killable script worker (`scriptIsolation` 2) |
| `test_view_leak.RealEngineViewLeak` | the governor's `health` view count and `status` program rows (`unsavedEdits`, `writers`) of gate 9.17 |
| `test_view_base.RealEngineViewBase` | the publish path's `generation` candidates and per-agent views of gate 9.17 (H, G) |
| `test_deadline.RealNative` | client library 1.1.0 timing its own wait (already skipped without that library) |
| `test_deadline.RealDegrade` (the hydra.4 side) | the install's library 1.1.0; on hydra.3 that side has no library and skips with its reason |

The decision is the protocol the connection negotiated (`Engine.protocol()`, read from `hello`), made by
`tests/support.py` (`hydra4_missing` in `setUpClass`, the `Hydra4Only` mixin skips each test, so the runner still counts
every planned test), never a release name. An engine that serves protocol 3 never skips these classes: on
hydra.4 a missing capability still fails them. The hydra.3 run sets `HYDRALYSIS_INTEGRATION_UNPINNED=1`, names the
hydra.3 install and its own `ghidra_session.py` (library 1.0.0) as `HYDRALYSIS_INTEGRATION_ENGINE` and `_CLIENT`, and
must otherwise end green.

## Which engine client runs

`hydra.load_client` checks the library's `PROTOCOL`, `CLIENT_VERSION` and `HYDRA_RELEASE` stamps against the pin (see above) and then returns one of two clients that give the same results:

- `hydralysis.engine_client.NativeClient` (Rust, `hydralysis_native.Session`) when the extension is built, `HYDRALYSIS_NATIVE` is not `0`, and the library is `CLIENT_VERSION` 1.1.0 of protocol 3 (the pins in `hydra.py` must equal `hydralysis_native.client_pins()`, else the Python client is used);
- the engine's own `ghidra_session.py`, imported from the install, otherwise: a library 1.0.0 (hydra.2/3, deadlines through the worker-thread helper), no extension, or `HYDRALYSIS_NATIVE=0`.

Both are checked by the same tests: `tests/test_engine_client.py` (a scripted daemon; with `HYDRALYSIS_INTEGRATION_CLIENT` set it also compares the native session with the library's `SocketSession` reply for reply), and the real-engine classes of `test_deadline.py` and `test_engine_integration.py`, which run unchanged under either client (`HYDRALYSIS_NATIVE=0` selects the Python one).

## Rolling back a pin

1. Check out the Hydralysis release that carries the older pin (`git checkout vX.Y.Z`), or run
   `python tools/bump_hydra.py --release <older release> --write` against the older engine's distribution and
   review the diff.
2. Run `python tools/bump_hydra.py --release <older release> --dist <folder> --check`: exit 0 means the pin statements agree.
3. Run `hydralysis backend install`, then `hydralysis backend inspect`.
4. Read "Upgrade and backup" below before opening a project with the older engine.

## Upgrade and backup policy

- A project analysed or committed by a newer engine may not open in an older one. A commit therefore asks for
  `confirm_one_way_upgrade`, and the older generation is kept as a re-hashed backup.
- Hydralysis never removes a generation, backup or view on its own. `backend action=backups options.op=remove`
  removes one only with `confirm:true` and refuses generation 0, the head, every generation the revert chain can reach
  and the base of a live view.
- Before changing the engine pin on a machine with projects you care about, list the backups
  (`options.op=list`) and verify them (`options.op=verify`). A block clone (ReFS) protects against a bad commit, not
  against loss of the volume: keep an independent copy of the project folder on another volume.
- State formats written by newer releases carry a `format` number; a reader that finds a newer `format` refuses and
  says which writer wrote it. It does not guess.
- Restart the MCP harness once after a release that changes the catalog epoch.

## Release process

`.github/workflows/release.yml`:

- `workflow_dispatch` is the dry run: it first runs the unit and engine jobs of `tests.yml` (called as a reusable
  workflow), then builds the sdist and the wheel, installs the wheel in a
  fresh environment, checks that it reports the package version and that `backend inspect` reports `ready: true`, writes
  `SHA256SUMS` and attaches everything as a workflow artifact. Nothing is published.
- A tag push `v*` runs the same steps, requires the tag to equal the package version, and creates a **draft**
  GitHub release with the files and `SHA256SUMS`. The owner decides whether to tag and whether to publish. This
  repository is private; making it public is a separate owner decision that this workflow does not take.
- The unit and engine jobs are defined once, in `tests.yml`; the release workflow calls them instead of copying them.

Release notes come from `CHANGELOG.md` and carry the limits: Windows x64, copy-on-write only on ReFS (a full copy
on NTFS), the one-way upgrade, a harness restart once.
