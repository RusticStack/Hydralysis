# RusticRE

Twenty reverse-engineering tools for programs you own. One CLI, `rusticre`, and one small MCP server. Ghidra and an optional runtime engine run behind it; REA and GhidraMCP are not dependencies.

Give RusticRE an executable, inspect the proposed work, explicitly prepare its analysis once, then query the saved project read-only. Setup and analysis return durable jobs immediately. Subsequent queries share a warm JVM. A lookup miss preserves the worker; a decompiler failure or timeout retires it with diagnostic paths.

## Start from an executable

Install this package in a virtual environment on your development drive:

```text
uv venv .venv
.venv/Scripts/python.exe -m pip install -e .
.venv/Scripts/rusticre.exe tools
```

Select a data directory with no dot-prefixed path components using `RUSTICRE_ROOT`, or set `root` in `rusticre.local.json`. Windows defaults to `F:/dev-cache/rusticre`; other hosts default to `~/rusticre-workspace`. Existing compatible Ghidra/JDK installations are discovered. Explicit `backend install` can privately install verified portable engines on Windows x64, without administrator privileges or machine configuration changes. Other hosts need configured existing engines. This release supports Ghidra **12.1.4**.

```text
rusticre fingerprint --exe F:/binaries/sample.exe
rusticre prepare --exe F:/binaries/sample.exe --target sample --plan
rusticre backend inspect
rusticre backend install
rusticre job <setup-id>
rusticre prepare --exe F:/binaries/sample.exe --target sample
rusticre job <prepare-id>
rusticre job <prepare-id> --action cancel
```

`--plan` performs no import, download or job creation. `prepare` alone starts the initial import/analysis; it reports stages, logs, failure, timeout and cancellation. Identical builds reuse one job/result. A manually configured existing target is retained for querying rather than imported again. Only successfully analysed, hash-verified saved projects are registered. Known wrapper sections such as `.bind` and UPX block preparation with `needs_unwrapped_artifact`. Select an appropriate unwrapped artifact; RusticRE does not launch or unpack the game for you. Entropy alone is a warning, not a packing verdict.

Existing analysed projects can still be configured through `targets` as shown in [config.example.json](config.example.json). Point `dir` directly at the directory containing the named `.gpr` and `.rep`, and supply `exe` or its full `sha256`. Close the canonical project before snapshotting it. No import occurs when answering a query.

## Ask bounded questions

```text
rusticre inspect --exe F:/binaries/sample.exe rva:0x1000
rusticre ghidra-query --target sample rva:0x1000
rusticre ghidra-query --target sample va:0x140001000 --action dossier
rusticre ghidra-query --target sample --action functions --contains Render --limit 20
rusticre ghidra-query --target sample --action functions --cursor <next_cursor>
rusticre ghidra-query --target sample --action variables 0x140001000
rusticre ghidra-query --target sample --action pcode 0x140001000
rusticre ghidra-query --target sample --action trace 0x140001000 --options-file trace.json
rusticre backend help
```

PE tools accept `rva:` or `va:` prefixes; ambiguous bare addresses are refused. Saved-analysis queries accept the same prefixes and interpret bare addresses as VAs. Their replies include the analysed image base and full executable hash. Function boundaries for PE32 require saved analysis. Cheap byte-based callers/xrefs remain candidates; Ghidra queries use its decoded listing and references.

Query actions include decompilation, function ranges, paged functions/xrefs/types, type layouts, recovered variables, function dossiers, basic blocks, high p-code and bounded value-flow traces. Traces cite instruction/operation identities and report unknown aliasing, indirect calls and runtime reachability. They do not prove original source types or feasible execution paths.

Use `type_edit` for cited structures, prototypes, local types, names, comments, data definitions and exact-byte-checked function definition corrections. Batches accept up to 200 edits, including a JSON file input. They roll back as a unit. Edits persist as build-bound sidecars and replay in worker memory; the canonical project stays unchanged. `--options-file` avoids shell quoting and Windows command length limits. [The protocol](docs/upstream-analysis.md) and on-demand `backend help` describe the options.

Function/xref/type pages and scans disclose truncation and continuation. Default decompiler output is capped at 32,000 characters. Use a file export for bulk work rather than flooding an MCP reply. Workers serialize requests per target, use isolated read-only snapshots, default to two JVMs with 6G maximum heap each, and expire after five idle minutes. Startup has its own 180-second deadline; individual queries have a 30-second default, capped at 300. Logs and failed snapshots are retained.

`ghidra-query --target sample --action export --options-file export.json` writes a durable JSONL artifact. Use `job <export-id>` for status/cancel and `{"resume":"<export-id>"}` to continue the same selection. Progress, hashes and explicit failure/truncation counts survive interruption. Resume refuses changed builds, source analysis, implementation or overlays. See [export options and limits](docs/exports.md); `complete` describes the selected filter, and a count cap does not establish whole-program coverage.

## Verify runtime evidence

```text
rusticre prologue --exe F:/binaries/sample.exe rva:0x1000 --expect "48895C2408"
rusticre prologue --exe F:/binaries/sample.exe --checks-file hooks.json
rusticre backend install --component runtime
rusticre job <setup-id>
rusticre backend help --component runtime
rusticre runtime attach --options-file attach.json
rusticre runtime modules --options-file session.json
```

A prologue table opens one PE and reports all rows; any mismatch fails the CLI/MCP result. Compact, spaced, comma-separated and escaped hexadecimal forms are accepted. Legacy `offset/prologue/names` rows require explicit `--offset-kind rva|va` unless already prefixed.

The optional pinned Frida backend supports verified attach/spawn, modules/threads, bounded module or absolute memory reads, observations and cooperative breakpoints with registers, arguments, return values and backtraces. Hooks require the module's full hash and **matching exact live bytes** before installation. Wildcards and unrestricted injected scripts cannot bypass that gate. Continue, unload and detach release instrumentation; abandoned breakpoint pauses have a watchdog. This backend does not supply CPU instruction stepping or data watchpoints. See [runtime evidence and semantics](docs/upstream-runtime.md).

## Small catalog

| MCP tools | Purpose |
| --- | --- |
| `fingerprint`, `imports` | Identity, packing triage and tables; fingerprint `detail=sections|exports` |
| `inspect`, `disasm`, `function`, `bytes`, `strings`, `xrefs`, `callers`, `callees` | Cheap PE evidence |
| `sigscan`, `prologue` | Locate candidates and verify bytes/tables |
| `evidence_add`, `evidence_list` | Claims with mandatory sources |
| `backend`, `prepare`, `job` | Setup, explicit analysis once, progress and recovery |
| `ghidra_query`, `ghidra_run` | Saved analysis, overlays, exports and deliberate scripts |
| `runtime` | Controlled local runtime sessions |

The CLI retains `sections`, `exports`, `ghidra-scripts` and `ghidra-jobs` aliases. They are not advertised as additional MCP tools. The catalog has regression budgets for tool count, total JSON bytes and individual schemas. [Client setup](docs/clients.md) explains registration and the equivalent CLI path for Qoder. No client configuration or other MCP registration is changed automatically.

`ghidra-run` remains an escape hatch for deliberate trusted local scripts, using `-process -noanalysis -readOnly` on an isolated copy. It starts a JVM per call. Project read-only mode does not prevent arbitrary scripts from writing other filesystem files. Use the warm query actions for routine work.

## Evidence and limits

[Original usage research](docs/research.md), [upstream setup](docs/upstream-setup.md), [analysis research](docs/upstream-analysis.md), and the [KotOR/SWTOR PR review](docs/open-pr-insights.md) explain why these operations earned a place. [Verification](docs/verification-complete-workflow.md) distinguishes actual fixture/corpus results from historical reports and untested scenarios.

RusticRE covers native PE inspection and Ghidra-backed saved analysis. It is not a replacement for every upstream Android/browser/firmware feature. Runtime stepping/watchpoints, graphics debugging, automatic unpacking and universal type recovery remain outside the implemented contract. [KotOR](docs/capabilities-kotor.md) and [Night City Together](docs/capabilities-nct.md) still require their own engine/protocol/resource/framework implementations; those do not become game-specific server tools. No finite test corpus establishes that a remaster or multiplayer framework can be completed automatically.

## Development

```text
.venv/Scripts/python.exe -m unittest discover -s tests -v
git diff --check
```

Unit tests run without launching Ghidra or games. The separately documented native fixture verifies real backend integration. There is no configured formatter or lint command. Only `pefile` and `capstone` are mandatory Python dependencies; engines are discovered or explicitly installed separately.
