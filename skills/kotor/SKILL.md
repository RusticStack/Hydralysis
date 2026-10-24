---
name: rusticre-kotor
description: Inspect swkotor.exe for the kotor-remaster engine. Use when the question is a function, an xref, or a Ghidra script in the KotOR tree. Format parsers stay in that repo.
---

# KotOR

`swkotor.exe` is a 32-bit exe. `disasm` uses 32-bit mode. `xrefs` searches for the absolute address, not a rip-relative load.

The format work (GFF, 2DA, KEY/BIF, NCS, the save VFS) and the action-table ledger stay in `kotor-remaster`. Do not copy those parsers here. A function the new engine must call is an evidence row whose source is a disassembly line or a Ghidra script body, with the prologue attached.

A full export of every function is a cache. The engine consumes proved formats and the functions those formats call.
