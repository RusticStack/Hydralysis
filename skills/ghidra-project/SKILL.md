---
name: rusticre-ghidra
description: Run a Ghidra script against an already analysed project without re-importing the exe. Use when you need a decompile, callers inside Ghidra, or an existing script such as Recv.java.
---

# Analysed project, then a script

Import and auto-analysis happen once, in Ghidra, into a master project named in `rusticre.local.json`. After that:

1. Close the master. A copy refuses to start while Ghidra holds `<project>.lock`.
2. `rusticre ghidra-scripts --game <name>` and read the script's usage line.
3. `rusticre ghidra-run --game <name> Script.java arg arg`.
4. Quote `job=... state=done` and the script body. A timeout or a missing body is a failed run, not a result.

The command is `-process -noanalysis -readOnly` on a lane copy. Two runs never share a lane. If the output is only the Ghidra banner, the script printed nothing; fix the script arguments rather than launching a second analysis.

Do not pass `-import`. Do not raise the tool's memory by editing a `.bat` in the Ghidra install. Set `max_mem` in the config.
