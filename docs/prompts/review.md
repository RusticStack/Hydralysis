# Prompt for a stronger model

Paste the block below. It is a research job with a pull request at the end, not a request to agree with the current twenty tools.

```text
You are improving RusticRE. A weaker model drafted it from session counts.
Treat that draft as a hypothesis. Research, then change the code where the
evidence says the tool list is wrong or a tool is awkward to use.

Repo: https://github.com/RusticStack/RusticRE
Checkout: F:\Projects\RusticRE
Branch: main. Open a new branch and a pull request. Do not push to main.
Author commits as KelpHect <kellhect@gmail.com>. Do not set a different git email.

What it is
RusticRE is a Python CLI and an MCP server for any PE you own (32-bit or 64-bit).
The point is a short tool list an agent can load. REA (npm rea-agents, about 200
tools) was too large: models failed before they could call anything, and most of
those tools are Android, browser, firmware, Hopper, Frida, Objective-C and Swift.
Ghidra is already installed. RusticRE must not re-import a binary to answer one
question, and must not vendor REA, Ghidra, or LaurieWired/GhidraMCP.

Current tools, in src/rusticre/api.py:
fingerprint, sections, imports, exports, disasm, inspect, xrefs, callers,
callees, function, bytes, strings, sigscan, prologue, evidence_add,
evidence_list, ghidra_run, ghidra_scripts, ghidra_lanes, ghidra_jobs.

inspect is meant to be the local stand-in for REA's function dossier: pdata
bounds, prologue, instructions, direct callers, no JVM. Decompiler text is
ghidra_run only, and that command must stay -noanalysis -readOnly on a copy of
an already analysed project. sigscan plus prologue are the hook path: a
prologue mismatch means the site is not safe to hook. evidence_add must refuse
a claim with an empty source.

Do this research before you edit
1. Recount real tool calls. Do not trust the summary below. Count only JSON
   lines that are actual tool calls, not tool catalogs pasted into prompts.
   Claude Code logs:
     C:\Users\KellHect\.claude\projects\C--Users-KellHect-orca-workspaces-CoopCyberpunk-scoter
   Qoder logs:
     C:\Users\KellHect\.qoder\projects\E--Projects-kotor-remaster-kotor-remaster
   OpenCode database, open it read-only:
     C:\Users\KellHect\.local\share\opencode\opencode.db
   Also count shell commands that ran analyzeHeadless, rea, disasm, xref,
   callers, or a Ghidra script. Write the table in the PR body.
2. Read the tool lists the agents were offered and did not need. REA 6.4.0 is
   installed at
     C:\Users\KellHect\orca\workspaces\CoopCyberpunk\scoter\tools\re\rea\node_modules\rea-agents
   OpenCode is configured for rea-agents@6.5.0. LaurieWired/GhidraMCP 2.0 is
   the other server. List which of their tools were called more than a handful
   of times, and which categories were never called.
3. Use RusticRE. From F:\Projects\RusticRE run:
     .\.venv\Scripts\python.exe -m unittest discover -s tests -v
     .\.venv\Scripts\rusticre.exe tools
   Then fingerprint, sections, imports, disasm, inspect, xrefs, callers,
   sigscan and prologue against C:\Python314\python.exe. If a real game exe is
   already on disk, one fingerprint of it is enough. Do not launch a game. Do
   not re-import or write a Ghidra project.
4. Decide the holes from that evidence. Candidates you must test, and reject
   if the sessions and your own run do not support them: a bounded value trace,
   import-by-name cross-references, a vtable run (a row of code pointers), a
   build-to-build byte compare, paging on huge results. Add a tool only when
   you can name the calls it replaces or the failure you hit. Do not add a
   tool for one game, one engine, or one mod loader.

Constraints
- Keep the server small enough that a model which fails on 200 tools can load
  it. Twenty is not sacred. Forty of unused tools is a failure.
- Do not register Android, browser, firmware, Hopper, Frida, or project-rename
  tools.
- inspect stays free of a JVM. ghidra_run stays read-only and does not re-import.
- A prologue mismatch still fails the hook check.
- evidence_add still refuses an empty source.
- No game names, mod names, or address-table formats in the MCP schema.
- Reimplement. Do not copy REA, Ghidra, or GhidraMCP source into this repo.
- Tests must pass. Add a test for every behaviour you change.

Pull request
Branch from main. PR to https://github.com/RusticStack/RusticRE
The body must contain: the recounted call table, the tools you added or cut
and why, the commands you ran and their results, and any job where REA or
GhidraMCP is still the better call. Do not delete a working RusticRE tool to
hide that comparison.

A previous count, which you must remeasure: Claude Code used disassembly
thousands of times and the Ghidra MCP about 200 times, almost all disassemble,
decompile, xrefs, bytes and symbol search. OpenCode drove headless Ghidra by
hand about 500 times and almost never called the REA MCP. Qoder called REA
about ten times. Those numbers are leads, not facts.
```
