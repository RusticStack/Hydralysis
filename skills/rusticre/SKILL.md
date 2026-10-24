---
name: rusticre
description: Inspect any PE you own with the RusticRE CLI or its twenty-tool MCP server. Use instead of REA, GhidraMCP, or analyzeHeadless.
---

# RusticRE

Call `rusticre`. PE operations take `--exe`; Ghidra operations take a configured `--target`. Quote the full build SHA-256 with every address. PE tools accept explicit `rva:0x...` or `va:0x...`; unprefixed ambiguous addresses are refused. Ghidra queries require numeric VA. A fresh binary needs a separately imported/analysed Ghidra project before decompilation; RusticRE does not yet bootstrap that project.

1. `fingerprint` and `sections` before anything else, so the build is known.
2. One function: `inspect --exe <path> <address>`. That is x64 unwind bounds, prologue, instructions and candidate callers, with no JVM. PE32 bounds and confirmed references need saved analysis.
3. A string, a caller, or a callee that `inspect` did not show: `strings`, `xrefs`, `callers`, `callees`.
4. A hook: `sigscan "48 8B ?? 24 10"`, then `prologue <address> --expect "..."`. A mismatch means do not hook.
5. Decompiler text: `ghidra-query --target <name> <VA>`. It verifies the target hash and analysed flag, opens a snapshot read-only, and reuses its JVM. `--action functions` and `--action xrefs` return bounded pages; continue with the returned `--cursor`. A failed worker is retired; retry once after reading its log. Never re-import to answer a query.
6. A proved name: `evidence-add` with the disassembly line or the script line in `--source`.

Use `ghidra-run` only for a deliberate local script/batch that the bounded query does not cover. Use REA when basic blocks, p-code or value flow are needed; Ghidra for initial analysis and saved project edits. Do not pass `-import` to answer a query. A timeout, truncated output or byte-scan candidate is not a proved result.
