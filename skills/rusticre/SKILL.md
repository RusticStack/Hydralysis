---
name: rusticre
description: Inspect any PE you own with the RusticRE CLI or its twenty-tool MCP server. Use instead of REA, GhidraMCP, or analyzeHeadless.
---

# RusticRE

Call `rusticre`. Pass `--exe` every time. Quote the `# exe ... sha256` header with every address.

1. `fingerprint` and `sections` before anything else, so the build is known.
2. One function: `inspect <address>`. That is bounds, prologue, instructions and direct callers, with no JVM.
3. A string, a caller, or a callee that `inspect` did not show: `strings`, `xrefs`, `callers`, `callees`.
4. A hook: `sigscan "48 8B ?? 24 10"`, then `prologue <address> --expect "..."`. A mismatch means do not hook.
5. Decompiler text: `ghidra-run --target <name> Script.java`. The project must already be analysed. The run is read-only.
6. A proved name: `evidence-add` with the disassembly line or the script line in `--source`.

Do not call `npx rea-agents` or LaurieWired's `ghidra-mcp`. Do not pass `-import` to Ghidra.
