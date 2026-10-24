# RusticRE

Twenty reverse-engineering tools for a PE you own. One command, `rusticre`. One MCP server.

Start with `inspect` for cheap PE facts. Use `ghidra-query` for decompiler text and analysed references: it keeps a JVM warm across CLI and MCP calls, opens a copy of saved analysis read-only, and verifies its executable SHA-256. It never imports or analyses a binary.

| Tool | Operation |
| --- | --- |
| `fingerprint`, `sections`, `imports`, `exports` | What this binary is |
| `inspect` | x64 unwind bounds, prologue, instructions, candidate callers |
| `disasm`, `xrefs`, `callers`, `callees`, `function`, `bytes`, `strings` | One question each |
| `sigscan`, `prologue` | Find a hook site, then check the bytes before hooking |
| `evidence-add` | Store a claim only if it has a source |
| `ghidra-query` | Address-based decompile, function ranges, paged functions and references; worker status/stop |
| `ghidra-run`, `ghidra-scripts`, `ghidra-jobs` | Deliberate scripts on saved analysis, discovery and diagnostic history |

`target` is a name you pick in the config for a Ghidra project. It is not a list of games.

## Setup

```text
uv venv --python 3.14 .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\rusticre.exe tools
```

Copy `config.example.json` to `rusticre.local.json` or set `RUSTICRE_CONFIG` for Ghidra operations. Set a target's existing project directory, project name, program name and `exe` (or full `sha256`). The PE tools need only `--exe`. Keep projects, caches and `root` on your development drive.

```text
rusticre inspect --exe F:/binaries/sample.exe 0x1000
rusticre ghidra-query --target sample 0x140001000
rusticre ghidra-query --target sample --action xrefs 0x140001000 --limit 20
rusticre ghidra-query --target sample --action functions --contains Render --limit 20
rusticre ghidra-query --target sample --action functions --cursor <next_cursor>
rusticre ghidra-query --target sample --action status
rusticre ghidra-query --target sample --action stop
```

PE tools accept RVAs or VAs. Ghidra queries use numeric **VAs**; aliases do not trigger name enumeration. Copy `next_cursor` into the same query to continue a functions or xrefs page. Function searches examine at most 2,000 entries per page, even when no name matches. Xref cursors are hexadecimal row offsets; function cursors are addresses. `truncated`, `body_truncated` and `total_characters` disclose incomplete answers. Decompiler text is capped at 32,000 characters.

Close the master before taking or validating a snapshot. Only its named `.gpr` and `.rep` are copied, with source metadata recorded; an ordinary script refuses stale or unowned lanes. Query workers refresh into a new snapshot when the master changes. Workers share one request lock per target, so a simultaneous request reports busy promptly. The default allows two warm workers, each with a 6G maximum heap; idle workers exit after five minutes. `query_startup_s` (180 by default) is separate from the per-query `--timeout` (30 seconds; configurable up to 300). A failed or timed-out query retires its worker and the next call starts a new one. Snapshots and logs are retained for diagnosis; remove them only when you no longer need them.

For a custom batch script, set the target's `scripts` directory and use `ghidra-run --target sample Script.java <arguments> --timeout 600`. A pre-script checks the analysed flag and build hash before the selected script runs with `-process -noanalysis -readOnly`. This path starts a JVM per run. Failures include log and job paths and return a nonzero CLI exit or MCP `isError`. Headless control options cannot be smuggled through script arguments. Custom scripts are trusted local code: read-only project opening prevents saved project edits, not filesystem writes by arbitrary Java/Python.

## Why these twenty

[The research report](docs/research.md) cites the three project repositories, successful calls, oversized answers, dead sessions, lock failures and adoption problems. [Verification](docs/verification.md) separates new measurements from historical reports. The query tool replaces the former lane-listing MCP slot; the count remains twenty. Individual schemas and the combined catalog have regression budgets.

PE `callers` and `xrefs` are byte-pattern **candidates**, not proof of instruction boundaries or a complete call graph. Prefer analysed `ghidra-query --action xrefs` when those distinctions matter. PE32 function boundaries need saved analysis. Packing indicators are warnings; a build-hash mismatch refuses Ghidra output. `prologue` rejects all-wildcard patterns and returns failure on a mismatch. An offline byte match does not install or validate a runtime hook.

REA still earns a call for p-code, basic blocks, full function dossiers and bounded value-flow tracing. Use Ghidra directly for initial analysis, type recovery and saved symbol/comment edits. Other binary formats and live runtime introspection remain outside the default PE server.

`src/rusticre/red4ext.py` parses one vendor's address-table JSON. It is not an MCP tool. A format that belongs to one program stays out of the server until a second program needs the same parser.

## Tests

```text
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests cover protocol exchanges, worker recovery, snapshot ownership, bounded signatures and file-backed reads. They do not launch Ghidra or a game. There is no configured formatter or lint command; `git diff --check` checks patch whitespace.
