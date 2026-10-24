# Prompt

Copy the block below to a model that should review RusticRE and open a pull request.

```text
Repo: https://github.com/RusticStack/RusticRE
Checkout: F:\Projects\RusticRE
Branch: main
Version: 0.2.0

You are reviewing a from-scratch reverse-engineering tool, not extending a game mod.
RusticRE is twenty MCP tools for any PE. It exists so an agent does not load REA's
full server (about 200 tools, including Android, browser, firmware and the rest).

Read README.md, THIRD_PARTY.md, skills/, src/rusticre/api.py and tests/test_rusticre.py.
Run: .\.venv\Scripts\python.exe -m unittest discover -s tests -v
Then run fingerprint, sections, imports, disasm, inspect and sigscan against
C:\Python314\python.exe. Do not launch a game. Do not re-import a Ghidra project.

The tool list was chosen from counted session logs, not from a wishlist:

- Claude Code on one large native project called disasm thousands of times,
  then Ghidra queries, function-of, callers, xrefs, strings, and a CLI dossier
  (rea function) a few hundred times. The Ghidra MCP itself was about 200 calls,
  almost all disassemble, decompile, xrefs, bytes and symbol search.
- OpenCode on another project called headless Ghidra and its own scripts about
  500 times, and the full REA MCP almost never. A five-tool server that reuses
  an analysed project was built because REA re-imported the binary.
- Qoder called REA about ten times (open project, list documents) and used a
  headless function export plus an evidence ledger for the real work.

What you should change, in a pull request against main:

1. Use the tools. If a call is awkward, fix the tool. Do not add a tool for a
   program, a game, or an engine.
2. A new tool must name the session behaviour it replaces, or a hole you hit
   while using these twenty. Android, browser, firmware, Hopper, Frida and
   rename-the-project stay out.
3. Hooks stay sigscan plus prologue. A mismatch must still refuse the site.
4. inspect must stay free of a JVM. Decompiler text stays on ghidra-run, which
   must keep -noanalysis -readOnly and must not re-import.
5. evidence-add must keep refusing a claim with an empty source.
6. Do not vendor REA, Ghidra, or GhidraMCP. Reimplement the operation.

Open the PR with what you ran, what failed, and the diff. If you would rather
keep REA or GhidraMCP for a job, say which call and why, in the PR body, and
do not delete RusticRE's tool to paper over it.
```
