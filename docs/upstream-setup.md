# Upstream setup and lifecycle research

Inspected with `gh` and shallow reference checkouts outside Hydralysis. No
upstream bridge, MCP server or implementation was copied into this repository.

- REA at [`f196ebf80665107aedc16892af25a1e1f9f26f43`](https://github.com/morluto/rea/tree/f196ebf80665107aedc16892af25a1e1f9f26f43):
  [`GhidraInstallation.ts`](https://github.com/morluto/rea/blob/f196ebf80665107aedc16892af25a1e1f9f26f43/src/ghidra/GhidraInstallation.ts#L98-L170)
  checks the native decompiler against host format/architecture;
  [`GhidraInstallationPolicy.ts`](https://github.com/morluto/rea/blob/f196ebf80665107aedc16892af25a1e1f9f26f43/src/ghidra/GhidraInstallationPolicy.ts#L36-L127)
  derives JDK bounds from the installation's own properties. Its
  [`GhidraLauncher.ts`](https://github.com/morluto/rea/blob/f196ebf80665107aedc16892af25a1e1f9f26f43/src/ghidra/GhidraLauncher.ts#L805-L884)
  constructs a new import and deletes the temporary project. Hydralysis keeps
  explicit preparation separate from read-only queries so repeated questions
  reuse saved analysis.
- GhidraMCP at [`1e980252087b2479a21b9ca6d82d5829538651a7`](https://github.com/LaurieWired/GhidraMCP/tree/1e980252087b2479a21b9ca6d82d5829538651a7):
  [`README.md:107–114`](https://github.com/LaurieWired/GhidraMCP/blob/1e980252087b2479a21b9ca6d82d5829538651a7/README.md#L107-L114)
  documents headless binary import and persistent `--project` storage.
  [`headless.py:185–243`](https://github.com/LaurieWired/GhidraMCP/blob/1e980252087b2479a21b9ca6d82d5829538651a7/src/ghidra_mcp/headless.py#L185-L243)
  opens/creates the project, imports only absent programs, and analyses newly
  imported or not-yet-analysed programs. Hydralysis implements its lifecycle with
  its own headless scripts rather than installing that extension/PyGhidra MCP.

Since 0.4.0 analysis runs on [Hydra Engine](https://github.com/RusticStack/hydra-engine)
release 12.3-hydra.2, a Ghidra 12.3 build with a headless session daemon that
keeps programs open between requests and serves several clients. Hydralysis
admits that pinned release and its pinned client (`hydra.py`), validates the
engine and the client's protocol version, and selects a full JDK satisfying
the installation's declared Java bounds. Other releases are reported as
incompatible unless `hydra_allow_unpinned` is set. When requested, a background
setup job installs the pinned engine and client archives and a portable
[Adoptium JDK 25.0.4.1+1](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.4.1%2B1)
privately under the configured root, verifies their full SHA-256 before
extraction, and refuses archive traversal/symlinks or replacement of an
existing installation. It does not edit PATH, user environment, permissions or
installed launch scripts. The archive digests are embedded in `hydra.py` and
`backends.py`; there is no `latest` download or unverified executable
installer. Existing compatible installations are reused.

An analysed project is adopted in place (`prepare action=adopt`): it is
validated and registered, never copied or imported, and a project saved by an
older Ghidra is upgraded in memory only.

An explicit preparation job copies one stable executable, imports and
analyses it once, checks the headless timeout flag, analysed flag and full
program hash, and registers the target only after successful save. Logs and
partial projects survive failure/cancellation. Completed hash reuse and active
job deduplication avoid a new import per question. A separate plan operation
performs read-only preflight without creating a job, installing, importing or
launching the target. Known wrapper/packer sections block the preparation path;
entropy warnings alone do not prove packing. No unpacking or DRM bypass occurs.
