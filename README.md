# Hydralysis

*Formerly RusticRE.* The GitHub repository keeps the old name until it is renamed; links to it keep working after that.

Twenty reverse-engineering tools for programs you own. One CLI, `hydralysis`, one small MCP server and a Python API over the same operations. Hydra Engine (a headless Ghidra 12.3 session daemon) and an optional runtime engine run behind it; REA and GhidraMCP are not dependencies.

Register an analysed project in place, or give Hydralysis an executable and explicitly prepare its analysis once. Every later question goes to one shared engine that keeps the program open: a warm decompile takes milliseconds, and any number of CLI calls, MCP sessions and scripts share it. Corrections you make (types, names, prototypes) are cited overlays in a working copy; the analysed project itself is never written.

## Upgrading from RusticRE

Version 0.5.0.dev0 is a rename only: no tool, argument or result changed. Old names keep working for this one release, and each one that is actually used is announced once on stderr and listed under `deprecated` by `backend inspect`.

| Was | Now | Still honoured |
| --- | --- | --- |
| Python package `rusticre`, project `rusticre` | `hydralysis` | no: update imports (`from hydralysis.client import Client`) |
| Command `rusticre` | `hydralysis` | yes, the `rusticre` command is installed beside it |
| `RUSTICRE_*` environment variables | `HYDRALYSIS_*` (`ROOT`, `CONFIG`, `EVIDENCE`, `EXE`, `HYDRA_DIR`, `HARNESS`, `FORBIDDEN_DRIVES`) | yes; a `HYDRALYSIS_*` value wins |
| `rusticre.local.json` | `hydralysis.local.json` | yes, if the new file is absent |
| Data root `%LOCALAPPDATA%\RusticRE` (and the macOS and Linux equivalents) | `Hydralysis` | yes: an existing RusticRE root is used where it is when no Hydralysis root exists. Nothing is moved or copied, so there is one root and one daemon. |
| MCP server name `rusticre`, tool names `mcp__rusticre__*` in Claude Code | server `hydralysis`, tool names `mcp__hydralysis__*` | no: re-register the server under the new name, and update any allow-lists or prompts that name the old tool prefix |

The engine daemon's instance id and the client attribution prefix stay `rusticre` for this release (`hydra.INSTANCE`), so a daemon a RusticRE install left running is reused instead of a second one being started. The Hydra program option and save comments written into existing projects are unchanged too.

## Start from an analysed project or an executable

Install this package in a virtual environment on your development drive:

```text
uv venv .venv
.venv/Scripts/python.exe -m pip install -e .
.venv/Scripts/hydralysis.exe tools
```

Select a data directory with no dot-prefixed path components using `HYDRALYSIS_ROOT`, or set `root` in `hydralysis.local.json` (or the file `HYDRALYSIS_CONFIG` names). The default is per user: `%LOCALAPPDATA%\Hydralysis` on Windows, `~/Library/Application Support/Hydralysis` on macOS, `$XDG_DATA_HOME/hydralysis` (when dot-free) or `~/hydralysis` on Linux. Any drive is accepted; a machine that keeps data off some drives says so with `forbidden_drives` in the config or `HYDRALYSIS_FORBIDDEN_DRIVES=C:,D:`.

```text
hydralysis backend inspect
hydralysis backend install
hydralysis job <setup-id>
```

`backend install` is a background job that installs the pinned Hydra release (**12.3-hydra.2**: the engine and its client) privately under the root, verifying each archive's full SHA-256 before extraction, and finds or installs a full JDK. It needs no administrator rights and changes no machine settings. Existing installs are used when `hydra_dir`, `hydra_client` and `java_home` name them.

An analysed project is adopted where it is, with no copy and no import:

```text
hydralysis prepare --adopt F:/re/MyGame --exe F:/games/MyGame/MyGame.exe --target mygame
hydralysis prepare --adopt F:/re/MyGame/MyGame.gpr --sha256 <full build hash> --program MyGame.exe --target mygame
```

The path may be the `.gpr`, its folder or a parent. The program's stored executable hash and analysed flag must match the build before it is registered. A project saved by an older Ghidra opens with its upgrade done in memory only; the files on disk are not touched, and other tools can keep reading them.

A fresh executable is analysed once, as a job:

```text
hydralysis prepare --exe F:/binaries/sample.exe --target sample --plan
hydralysis prepare --exe F:/binaries/sample.exe --target sample
hydralysis job <prepare-id>
hydralysis job <prepare-id> --action cancel
```

`--plan` performs no import, download or job creation. `prepare` reports stages, logs, failure, timeout and cancellation; identical builds reuse one result. Known wrapper sections such as `.bind` and UPX block preparation with `needs_unwrapped_artifact`. Hydralysis does not launch or unpack the program for you. Entropy alone is a warning, not a packing verdict.

## Ask bounded questions

```text
hydralysis inspect --exe F:/binaries/sample.exe rva:0x1000
hydralysis ghidra-query --target sample rva:0x1000
hydralysis ghidra-query --target sample va:0x140001000 --action dossier
hydralysis ghidra-query --target sample --action functions --contains Render --limit 20
hydralysis ghidra-query --target sample --action functions --cursor <next_cursor>
hydralysis ghidra-query --target sample --action trace 0x140001000 --options-file trace.json
hydralysis backend help
```

PE tools accept `rva:` or `va:` prefixes; ambiguous bare addresses are refused. Saved-analysis queries accept the same prefixes and interpret bare addresses as VAs. Their replies include the analysed image base and full executable hash. Cheap byte-based callers/xrefs (no engine) remain candidates; engine queries use the decoded listing and references.

Query actions:

- Reading: decompilation, function ranges, paged functions/xrefs/types, type layouts, recovered variables, dossiers, basic blocks, high p-code, decoded-listing scans.
- Address maps: import cited, build-specific name/hash-to-RVA maps and resolve them through the same address tools. See [address maps](docs/address-maps.md).
- Value flow: `trace` follows a p-code value backward or forward. It goes through memory: stack slots, stores to a field, out-parameters. It also goes into callers and callees, cheapest path first. `brief` returns only the constants, stops and memory edges it reached. Every step cites its instruction and operation.
- Virtual calls: `vtables` names the tables and slot that hold a function. `vcalls` lists the call sites of a slot offset and can verify each receiver on p-code.
- Field writes: `writes` lists the direct stores to a field offset and says what it does not cover.
- Missed code: `orphans` pages through decoded instructions that no function contains, with what refers to each run's start. Cite one in a `function_create` correction.
- Two builds: `diff` proposes function matches and hook-table candidates as a job. Review correspondence independently before using the destination bytes in a hook table; see [cross-build transfer](docs/crossbuild-transfer.md).

Traces report unknown aliasing, indirect calls and runtime reachability; they do not prove source types or feasible paths.

Function/xref/type pages and scans disclose truncation and continuation. Default decompiler output is capped at 32,000 characters. Each query runs contained (its transaction is rolled back), so a query cannot change what another client reads. Queries have a 30-second default deadline, capped at 300. The engine stops after `hydra_idle_s` idle seconds (default two hours) and keeps programs warm for `hydra_keep_warm_s`.

## Correct the analysis

`type_edit` records cited structures, prototypes, local types, function names, data labels, comments, data definitions and exact-byte-checked function definitions. Batches take up to 200 edits, including a JSON file, and roll back as a unit. `import_types` loads a whole type corpus (JSONL, see [type corpus](docs/type-corpus.md)) as one job and one revertible step. `expect_revision` turns a concurrent edit into a conflict that names its editor.

Edits are bound to the build's hash and applied to a working copy forked from the analysed project. Clients share the default view; `options.view` selects a separate named annotation view, whose edits require the revision reported by status. Views isolate annotations, not access. The working copy is saved in the background after edits pause (`overlay_save_debounce_s`); an unsaved change is replayed from the store, never lost. `revert` removes overlays in one step by rebuilding the working copy. [The protocol](docs/upstream-analysis.md) and `backend help` describe the options.

`ghidra-query --target sample --action export --options-file export.json` writes a durable JSONL artifact. Use `job <export-id>` for status/cancel and `{"resume":"<export-id>"}` to continue the same selection. Resume refuses changed builds, source analysis, implementation or overlays. See [export options and limits](docs/exports.md).

## Verify runtime evidence

```text
hydralysis prologue --exe F:/binaries/sample.exe rva:0x1000 --expect "48895C2408"
hydralysis prologue --exe F:/binaries/sample.exe --checks-file hooks.json
hydralysis backend install --component runtime
hydralysis backend help --component runtime
hydralysis runtime attach --options-file attach.json
```

A prologue table opens one PE and reports all rows; any mismatch fails the CLI/MCP result. A row may list accepted alternatives. Compact, spaced, comma-separated and escaped hexadecimal forms and `??` wildcards are accepted. Legacy `offset/prologue/names` rows require explicit `--offset-kind rva|va` unless already prefixed.

The optional pinned Frida backend supports verified attach/spawn (with working directory and environment), modules/threads and bounded reads. A read can be decoded with a layout or one of the target's analysed types. It also supports observations and cooperative breakpoints with registers, arguments, return values and backtraces.

Probes:

- `capture` copies and decodes arguments and the memory they point to. On 32-bit targets `convention` (`thiscall`, `fastcall`) maps the arguments, and a capture can name a register instead (`ecx`, or `xmm0`..`xmm15` for x64 float arguments).
- `sample` summarizes a per-frame call per time window instead of sending one event per call.
- `patches` compares live code with the file and decodes a detour another tool installed. `accept_patch` probes past it.

Hooks require the module's full hash and **matching exact live bytes** before installation. Wildcards and unrestricted injected scripts cannot bypass that gate. The client that spawned or attached owns the session; others may look but not drive it, and one executable has one driving session. `runtime_lock_check` names a project's own lock command, which is asked before a spawn or attach. Continue, unload and detach release instrumentation; abandoned breakpoint pauses have a watchdog. This backend does not supply CPU instruction stepping or data watchpoints: use the static `writes` action for who writes a field. See [runtime evidence and semantics](docs/upstream-runtime.md).

## Small catalog

| MCP tools | Purpose |
| --- | --- |
| `fingerprint`, `imports` | Identity, packing triage and tables (imports with their IAT slots); fingerprint `detail=sections|exports` |
| `inspect`, `disasm`, `function`, `bytes`, `strings`, `xrefs`, `callers`, `callees` | Cheap PE evidence |
| `sigscan`, `prologue` | Locate candidates and verify bytes/tables |
| `evidence_add`, `evidence_list` | Claims with mandatory sources, attributed to their client, grouped by subsystem, superseded rather than deleted |
| `backend`, `prepare`, `job` | Setup, adoption, explicit analysis once, progress and recovery |
| `ghidra_query`, `ghidra_run` | Saved analysis, overlays, diffs, exports and deliberate scripts |
| `runtime` | Controlled local runtime sessions |

The CLI retains `sections`, `exports`, `ghidra-scripts` and `ghidra-jobs` aliases. They are not advertised as additional MCP tools. The catalog has regression budgets for tool count, total JSON bytes and individual schemas. [Client setup](docs/clients.md) explains registration, the terminal path and the Python API (`hydralysis.client`, `hydralysis call <tool> --args`). No client configuration or other MCP registration is changed automatically.

`ghidra-run` is an escape hatch for deliberate trusted local scripts. The script is staged into Hydralysis's script folder and runs contained on the warm engine, so it cannot change the project. Engine containment does not stop a script from writing other files. Use the query actions for routine work.

## Evidence and limits

[Original usage research](docs/research.md), [upstream setup](docs/upstream-setup.md), [analysis research](docs/upstream-analysis.md), and the [KotOR/SWTOR PR review](docs/open-pr-insights.md) explain why these operations earned a place. [Verification on fixtures](docs/verification-fixtures.md) records the current results; [the 0.3.0 report](docs/verification-complete-workflow.md) predates the engine change.

Hydralysis covers native PE inspection and saved analysis. It is not a replacement for every upstream Android/browser/firmware feature. Runtime stepping/watchpoints, graphics debugging, automatic unpacking and universal type recovery remain outside the implemented contract. [KotOR](docs/capabilities-kotor.md) and [Night City Together](docs/capabilities-nct.md) still require their own engine/protocol/resource/framework implementations; those do not become game-specific server tools. No finite test corpus establishes that a remaster or multiplayer framework can be completed automatically.

## Development

```text
set HYDRALYSIS_TEST_ROOT=D:/hydralysis-data/test-work
.venv/Scripts/python.exe -m unittest discover -s tests -v
git diff --check
```

Unit tests run without launching the engine or games; they work under `HYDRALYSIS_TEST_ROOT` (default `test-work/`). CI runs them on Windows. `tests/test_engine_integration.py` runs the real engine when `HYDRALYSIS_INTEGRATION_ENGINE` and `HYDRALYSIS_INTEGRATION_CLIENT` name a Hydra install and its `ghidra_session.py` (`HYDRALYSIS_INTEGRATION_JAVA` a JDK). It uses its own data root and daemon. [Verification on fixtures](docs/verification-fixtures.md) builds small x64 and x86 programs with known answers and checks each capability against them (`tests/fixtures/verify_fixtures.py`). There is no configured formatter or lint command. Only `pefile` and `capstone` are mandatory Python dependencies; engines are discovered or explicitly installed separately.
