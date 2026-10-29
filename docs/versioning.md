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
`PROTOCOL`, `CLIENT_VERSION`, `ASSETS`). Only `tools/bump_hydra.py` changes them, together with the three pin
statements in `README.md`, `THIRD_PARTY.md` and `docs/upstream-setup.md`.

| Hydralysis | Pinned engine | Protocol | Notes |
|---|---|---|---|
| 0.5.0 "qualified" | `12.3-hydra.3` | 2 | client only; the engine's locking is hydra.3's |
| 0.6.0 (label OD11) | `12.3-hydra.4` | 3 (2 accepted with `hydra_allow_unpinned`) | adoption of the engine's capabilities |

A pinned client refuses an engine whose release stamp differs, unless `hydra_allow_unpinned` is set; then it accepts
library protocols 2 to 3.

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
