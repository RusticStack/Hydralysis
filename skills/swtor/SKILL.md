---
name: rusticre-swtor
description: Inspect the SWTOR client with the analysed Ghidra project and the existing scripts. Use when the question is an opcode handler, a GOM field, or a native function. The shard server and the capture kit stay in SWTOR-origins.
---

# SWTOR

The protocol docs and `tools/decompile` stay in SWTOR-origins. Native questions go through this package:

1. `fingerprint --exe <swtor.exe>` and cite it.
2. `ghidra-scripts --game swtor`, then `ghidra-run --game swtor Recv.java` with the directive that script already documents (`FN`, `CALLERS`, `STR`, `VTAB`).
3. Put the proved opcode or field in `evidence-add`. The source is the script line or the capture line, not a guess.

Do not re-import the 30 MB client. The master project under the configured `dir` is the analysis. A lane is a copy. If a run reports the project is locked, another lane has it; pick a free lane rather than deleting the master.
