---
name: hydralysis-evidence
description: Record a reverse-engineering claim so it survives a Ghidra refresh or a new build of the binary.
---

# Evidence

Required: target (any name you give this binary), build (the fingerprint line), kind, name, note, source. Source is a disassembly line, a script line, or a capture line. An empty source is refused.

Put the prologue from `inspect` or `function` in `--prologue`. On the next build, `prologue` prints `PROLOGUE MISMATCH` when the bytes moved. Drop the old name.

The Ghidra project is a cache. The row is the record.
