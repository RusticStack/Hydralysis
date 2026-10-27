---
name: hydralysis-ghidra
description: Decompile, trace or correct an already analysed Ghidra project without re-importing the binary. Use when inspect is not enough and you need decompiler text, value flow or types.
---

# Query saved analysis

For an existing analysed project, register it in place: `prepare --adopt <.gpr, its folder or a parent> --exe <path> --target <name>` (or `--sha256` and `--program`). Nothing is copied or imported; the program's stored hash and analysed flag must match. For a new executable, explicit `prepare` owns the one-time import/analysis as a durable job, and `prepare --plan` is read-only. Do not start preparation when the user only asks for tool design or lightweight inspection. After that:

1. `ghidra-query --target <name> <VA>` for decompilation; `--action function`, `functions` or `xrefs` for analysed facts. Addresses are numeric VAs or `rva:`/`va:`. Continue incomplete enumeration with the returned `--cursor`; do not list whole tables by name.
2. Value flow: `--action pcode` gives op/varnode ids; `--action trace` with `{"seed": ..., "direction": "backward", "brief": true}` follows them through memory and into callers. A stop is not a proof of absence.
3. Virtual calls: `vtables` (which tables hold a function), `vcalls` (sites of a slot offset, receivers verified when asked). Field writes: `writes`.
4. Corrections: `type_edit` with a `source`, flat options next to `kind`. Bulk types: `import_types` with a corpus. Undo: `revert` with the overlay ids. Every client reads the corrected program; the analysed project is never written.
5. Two builds: `diff` with `against` the older target, then transfer names or a hook table.
6. A deliberate custom script: `ghidra-run --target <name> Script.java <arguments>`. It runs contained on the warm engine. Check its output and exit.

The engine is Hydra Engine, a Ghidra fork; no stock Ghidra is used or needed. One engine serves every client and keeps programs warm. Concurrent edits are serialized, never corrupt, and `expect_revision` (the `view_revision` from `status` or the last edit) is mandatory on every edit and revert; a stale one is rebased if no later edit touched its subject, else a conflict naming the editor. `backend status` shows it; `backend stop` stops it. A timeout or a truncated page is not a result: narrow the query. Use `export` for durable bulk artifacts and `job` for progress/cancel, rather than sending an entire decompile corpus to MCP output. No project directory component may start with a period.
