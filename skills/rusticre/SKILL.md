---
name: rusticre
description: Use the RusticRE CLI or its eighteen-tool MCP server to inspect a game exe you own, record a proved claim, or run one read-only Ghidra script. Use when a session would otherwise call REA, GhidraMCP, analyzeHeadless, or a one-off disassembler.
---

# RusticRE

Call `rusticre`. Do not call `npx rea-agents`, LaurieWired's `ghidra-mcp`, or `analyzeHeadless` by hand.

1. `rusticre fingerprint --exe <path>` and quote the header on every address you report.
2. Instructions, a string, a direct caller: `disasm`, `strings`, `xrefs`, `callers`. These do not start a JVM.
3. The function that contains an address, and its prologue: `funcof`, then `prologue --expect "48 8B ?? ..."`.
4. Cyberpunk hashes: `hash` and `addr` against `cyberpunk2077_addresses.json`. Only segment 0001 is an RVA.
5. A decompile or a script such as `Recv.java`: `ghidra-run --game <cyberpunk|kotor|swtor> <Script.java>`. The project must already be analysed. The run is read-only.
6. A proved name goes to `evidence-add` with the log line or the disassembly line in `--source`. A claim with an empty source is refused.
7. What to work on next: `rusticre systems --game <name>`.

`swkotor.exe` is 32-bit. The other two exes are 64-bit. Pass `--exe` every time so a stale path cannot answer for the wrong build.
