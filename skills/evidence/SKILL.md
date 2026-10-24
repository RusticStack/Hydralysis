---
name: rusticre-evidence
description: Record a reverse-engineering claim so it survives a Ghidra project refresh. Use when naming a function, citing an offset, or closing a system row.
---

# Evidence

A row is the record. The Ghidra project is a cache and is refreshed from the master.

Required: game, build (the fingerprint line), kind, name, note, source. Source is a file and line, a disassembly line, or a capture line. If you do not have one, the claim stays unwritten and the status stays open.

Store the prologue from `funcof` in `--prologue`. On the next game build, `prologue` prints `PROLOGUE MISMATCH` when the bytes moved. Do not keep the old name.

Do not write renames into the Ghidra project. The lane is opened read-only on purpose. The next refresh would delete them.
