---
name: rusticre-ghidra
description: Decompile or script an already analysed Ghidra project without re-importing the binary. Use when inspect is not enough and you need decompiler text.
---

# Analysed project, then one script

Import and auto-analysis happen once, into the master project named under `targets` in the config. After that:

1. Close the master. A copy refuses to start while `<project>.lock` exists.
2. `ghidra-scripts --target <name>` and read the usage line.
3. `ghidra-run --target <name> Script.java` with that script's arguments.
4. Quote `state=done` and the script body. A timeout is a failed run.

The command is `-process -noanalysis -readOnly` on a lane copy. Two runs never share a lane. Do not re-import. Do not rename symbols inside the copy; the next refresh deletes them. Store names with `evidence-add`.
