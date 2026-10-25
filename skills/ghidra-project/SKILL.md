---
name: rusticre-ghidra
description: Decompile or script an already analysed Ghidra project without re-importing the binary. Use when inspect is not enough and you need decompiler text.
---

# Query saved analysis

For a new executable, explicit `prepare` owns initial setup/import/auto-analysis as a durable job. `prepare --plan` is read-only. Do not start preparation when the user only requests tool design or lightweight inspection. For an existing analysed project, configure `targets` directly; do not reimport it. After that:

1. Close the master. A copy refuses to start while `<project>.lock` exists.
2. Configure `exe` or its full `sha256` alongside `dir`, `name` and `program`. The program's stored executable hash and analysed flag must match before any decompile.
3. `ghidra-query --target <name> <VA>` for decompilation; `--action function`, `functions` or `xrefs` for analysed facts. Addresses are numeric VAs. Continue incomplete enumeration with the returned `--cursor`; do not use whole-table xrefs by name.
4. `--action status` inspects the worker; `--action stop` stops it. Startup has a separate deadline. A failed or timed-out worker is retired automatically, and the next query uses a new snapshot.
5. A deliberate custom batch: configure `scripts`, use `ghidra-scripts --target <name>`, then `ghidra-run --target <name> Script.java <arguments>`. Check `state=done`, `exit=0` and the script body. Failures include full diagnostic paths.

The command is `-process -noanalysis -readOnly` on a snapshot. Two script runs never share a lane; queries serialize per worker. Saved analysis is never imported implicitly. Source metadata detects stale snapshots, which are retained rather than overwritten. Use sourced `type_edit` overlays for persistent type/symbol/function corrections outside the canonical project. Atomic batches and file input support bulk work; worker restart replays the same build-bound history. Use `export` for durable bulk artifacts and `job` for progress/cancel, rather than sending an entire decompile corpus to MCP output. No project directory component may start with a period.
