# Hydralysis

*Formerly RusticRE.* The GitHub repository keeps the old name until it is renamed; links to it keep working after that.

Twenty reverse-engineering tools for programs you own. One CLI, `hydralysis`, one small MCP server and a Python API over the same operations. Hydra Engine and an optional runtime engine run behind it; REA and GhidraMCP are not dependencies. Hydra Engine is a fork of Ghidra (12.3 DEV, Apache-2.0, with a headless session daemon), so Hydralysis is built on Ghidra's analysis and decompiler, not independent of them. It uses no stock Ghidra and needs none (see [Third-party sources](THIRD_PARTY.md)).

Register an analysed project in place, or give Hydralysis an executable and explicitly prepare its analysis once. Every later question goes to one shared engine that keeps the program open: a warm decompile takes about a millisecond for a tiny function and tens of milliseconds for a large one (size-dependent; see [Measured, not promised](#measured-not-promised)), and several CLI calls, MCP sessions and scripts share it (tested with up to 4 clients). Corrections you make (types, names, prototypes) are cited overlays in a working copy; the analysed project itself is never written, and nothing yet commits those corrections back to it (see [Correct the analysis](#correct-the-analysis)).

## Upgrading from RusticRE

Version 0.5.0.dev0 renames the project and also makes behaviour changes that are not source compatible: `expect_revision` is now required on every `type_edit` and `revert`, two stock-Ghidra settings are no longer honoured, decompiled C is produced with the program's own decompiler options (it changes for about one function in six), and some answers gain fields (see the last rows of the table). The 20 tools keep their names. The old names from the rename keep working for this one release, and each one that is actually used is announced once on stderr and listed under `deprecated` by `backend inspect`.

| Was | Now | Still honoured |
| --- | --- | --- |
| Python package `rusticre`, project `rusticre` | `hydralysis` | no: update imports (`from hydralysis.client import Client`) |
| Command `rusticre` | `hydralysis` | yes, the `rusticre` command is installed beside it |
| `RUSTICRE_*` environment variables | `HYDRALYSIS_*` (`ROOT`, `CONFIG`, `EVIDENCE`, `EXE`, `HYDRA_DIR`, `HARNESS`, `FORBIDDEN_DRIVES`) | yes; a `HYDRALYSIS_*` value wins |
| `rusticre.local.json` | `hydralysis.local.json` | yes, if the new file is absent |
| Data root `%LOCALAPPDATA%\RusticRE` (and the macOS and Linux equivalents) | `Hydralysis` | yes: an existing RusticRE root is used where it is when no Hydralysis root exists. Nothing is moved or copied, so there is one root and one daemon. |
| MCP server name `rusticre`, tool names `mcp__rusticre__*` in Claude Code | server `hydralysis`, tool names `mcp__hydralysis__*` | no: re-register the server under the new name, and update any allow-lists or prompts that name the old tool prefix |
| `type_edit` and `revert` without `expect_revision` on the shared view (it was only required on named views) | `expect_revision` is **required on every view**; omitting it fails with `expect_revision_required`, which reports `current_revision`/`view_revision` to retry with | no (breaking): read `view_revision` from `status` or the last answer and pass it as `expect_revision`. A stale revision is rebased when no later edit touched the same subject, otherwise it is rejected with a `conflict` |
| Status, edit and revert answers; `backend inspect` | gain `view_revision` and `latest_editor` (status also `overlays.latest_editor`); `backend inspect` gains `ignored` and, when non-empty, `deprecated` | additive: existing fields are unchanged, but strict result parsers must accept the new keys |
| `decompile`, `dossier`, `pcode`, `trace` and every other query that decompiles ran on the decompiler's built-in default options (the script opened `DecompInterface` without `setOptions`) | They run on the program's own decompiler options (`DecompileOptions.grabFromProgram`, set once, before the program is opened), as a headless decompile does. The visible differences: constants and strings in read-only memory are shown as values (`* 1.5 - 0.25` instead of `* DAT_004161c4 - DAT_004161c0`) instead of `DAT_`/`_DAT_` names, array locals are shown whole, and more functions get a `__thiscall` or `__fastcall` signature. Measured on KotOR 1 (8,616 functions): 1,363 answers changed (15.8%), 0 stopped decompiling, 318 more `__thiscall` and 132 more `__fastcall` signatures; the new answers are identical on all 8,616 to a decompile run with the program's own options (see [the golden harness](docs/golden-harness.md#parity-of-the-production-path-with-decompileoptionsgrabfromprogram)) | deliberate and not switchable: an agent that cached or diffed C text from 0.4.x will see it change for those functions. Overlay and type answers are unaffected |
| `ghidra_dir` in the config file and the `GHIDRA_INSTALL_DIR` environment variable, used to find an engine | Hydra Engine only (`hydra_dir`, `HYDRALYSIS_HYDRA_DIR`, or the installed engine); a stock Ghidra is never probed or used | no: both settings are ignored and listed under `ignored` by `backend inspect`; point `hydra_dir` at a Hydra Engine install instead |
| Target registry, working-copy `state.json` and overlay job records were written in place and read back as-is | Written atomically (temp file, flush, replace) and sealed with a SHA-256 over their content; a zero-length, torn or mis-sealed file is read from its `.bak` instead, and when no good copy exists the read fails with `store_corrupt` rather than starting empty. Append-only logs carry a CRC per line: a torn last line is ignored, corruption in the middle is refused as `lineage_corrupt` | yes, automatically: files written by 0.4.x load unchanged and become the `.bak` of the first sealed write. Do not hand-edit sealed files: an edit breaks the seal and the previous `.bak` is read instead |
| A request to the engine whose reply was lost to a dropped connection was sent once more, whatever it was | Only idempotent requests (reads, opens, status, hello, `ghidra_query` read actions) are sent again on a new connection. After a lost reply to anything that changes state (overlay apply, save, fork, edit, rename, comment, import) the call fails with `closed` and `details.ambiguous`, because the change may or may not have been applied: check with `status` before repeating it. Engine errors also carry `retry_after_ms`, `next`, `queue` and `holder_info` when the engine supplies them | no (behaviour change): do not blindly retry an `ambiguous` failure |
| One MCP worker pool served every tool | Tools that talk to the engine (`ghidra_run`, `ghidra_query`, `backend`, `prepare`, `job`, `runtime`) have their own pool of 4, so blocked engine calls no longer delay `fingerprint`, `disasm` and the other PE-only tools. A busy answer names the lane and carries `retryAfterMs` | yes, automatically |
| The tool list had no version | Catalog epoch 2 (address arguments say again that ambiguous unprefixed addresses are refused): `backend` gains `action=doctor` (it answers `not_available` until that feature ships) and `action=backups` (shipped in 0.5.0: `options.op` is `list`, `verify` or `remove`), and `backend`, `ghidra_run` and `job` gain a free-form `options` object (`ghidra_run` options are validated, never silently ignored). `backend status`, `backend help` and `backend inspect`, and the MCP `initialize` result (`_meta["hydralysis/catalog"]`), report `catalog {epoch, hash}` | additive. MCP clients cache the tool list, so restart the harness once to see the new schema |

### Changes in 0.5.0

- The `saved` key of `ghidra_query action=status` and the setting `overlay_save_debounce_s` are removed, and the background saver process is gone: a working copy is no longer saved after edits pause, and unsaved changes are replayed from the store.
- The per-target `.sync.lock` is replaced by a per-view lock; a wait that runs out after 30 s answers a structured `busy` with `retryAfterMs`.
- `generationKeep` and `viewIdleDeleteS` in `config.example.json` are reserved: the retention spec names them, but no code reads them yet. Generations and views are never removed automatically; `backend action=backups options.op=remove` removes one only with `confirm:true`, and it refuses generation 0, the head, every generation the revert chain can reach and the base of a live view.
- Views of one master share one base (built once per master revision, generation and engine release), and each sync uses a connection of its own, so several views built at once in one process no longer fail with `no_project`.
- A working copy's folder is checked (header magic of its newest database version) before it is opened, and a damaged one is moved aside and rebuilt from the store.
- The engine daemon this client launches gets `maxLong` and `maxQuick` from the new `expected_agents` setting (default 16); a daemon that is already running keeps the limits it started with.
- `ghidra_query action=type_edit options.kind=commit` writes the pending records of a view into a new generation of the analysed project: a copy in the Hydralysis root, verified before it is published, with a re-hashed backup of the generation it started from, and the original project is not written. `commit_revert` returns to the generation before. A commit asks for `confirm_one_way_upgrade` because this client cannot tell whether the new generation can still be opened by older engines. These are client features on the hydra.2 and hydra.3 engines, not engine guarantees; the claims about them are the ones the tests in `tests/test_commit.py`, `tests/test_backups.py` and `tests/test_lineage.py` exercise.
- `backend action=backups` lists, verifies and (as a dry run unless `confirm:true`) removes backups and generations; a block clone protects against a bad commit, not against loss of the volume, and the listing counts the independent copies.

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

Function/xref/type pages and scans disclose truncation and continuation. Default decompiler output is capped at 32,000 characters. Each query runs contained: its changes are rolled back and never saved, but while it runs, other clients can see them. RusticQuery's read actions do not modify the program. Queries have a 30-second default deadline, capped at 300. The engine stops after `hydra_idle_s` idle seconds (default two hours) and keeps programs warm for `hydra_keep_warm_s`.

## Correct the analysis

`type_edit` records cited structures, prototypes, local types, function names, data labels, comments, data definitions and exact-byte-checked function definitions. Batches take up to 200 edits, including a JSON file, and roll back as a unit. `import_types` loads a whole type corpus (JSONL, see [type corpus](docs/type-corpus.md)) as one job and one revertible step. `expect_revision` is mandatory on every edit and revert (see Concurrency policy below).

Edits are bound to the build's hash and applied to a working copy forked from the analysed project. Every agent edits in a view of its own. The view of a call is `(lineage, agent id)`: the agent id is `options.as` when the call carries it, otherwise the process default `<MCP client name>@<boot id>`, where the boot id is 16 random hex digits generated when the server process starts (set `HYDRALYSIS_AGENT_ID` to keep one id across restarts). An agent without a view reads the sealed master, and its first edit creates its view (`view_revision` 0); `options.scope:"master"` reads the master even when the agent has a view, and `options.view:"shared"` names the collaboration view that anyone can use explicitly. Callers that present the same agent id share one view, including every sub-agent of one MCP server process that passes no `as`: they see each other's unpublished edits, and `expect_revision` with the subject-aware rebase keeps one from overwriting the other. That is conflict control, not isolation; a harness that starts editing sub-agents must pass a distinct `options.as` for each. Isolation holds between distinct agent ids and between distinct processes, and is shown by the tests, not promised beyond them. A restarted server has a new default id; the orphaned view of the old one is listed as `adoptable` in its first reply and re-attached with `options.as`. `ghidra_query action=status options.show=views` lists the views, and an idle view is closed (its records stay in the store and a later call replays them, answering once with `view_rebuilt`). Every edit needs the revision reported by status (`view_revision`). Views isolate annotations, not access. The working copy is a cache and nothing saves it: an edit is written to the store before it is acknowledged, and a change the engine lost with a restart is replayed from the store at the next query. The store is flushed and sealed; no power-loss test has been run, and corrections are not committed back to the analysed project. `revert` removes overlays in one step by rebuilding the working copy.

**Durability.** Corrections persist in the overlay store under the data root (bound to the build's hash, written atomically, kept across restarts) and are replayed into the working copy. They are not committed into the analysed project, and there is no portable export/import bundle for them yet; both are planned work, not something to rely on today.

**Concurrency policy.** Writers are serialized, and no corruption was seen in the tests listed under [Development](#development); that is a test result, not a guarantee. Hydralysis takes a per-view lock (waiting at most 30 s, then answering a structured `busy`) and the engine holds the program's exclusive lock while one edit applies, so simultaneous edits are applied one at a time. Serialization alone would let the last writer win, so detection is mandatory:

- **Shared view: `expect_revision` is mandatory** on every `type_edit` and `revert`. Leaving it out is an error that names the current revision, so the agent can retry. `view_revision` is in every `status`, edit and revert answer.
- **Stale revisions are subject-aware.** The overlay store keeps a journal of what each revision touched (an address, a struct path, function structure; a type import touches everything). If no edit after your revision touched your edit's subject, it is rebased onto the current revision and the answer says `rebased: true` with `subjects_changed_since`. Otherwise it is a conflict with `current_revision`, `latest_editor` (who and when), `subjects_changed_since` and `overlapping`. Subjects are addresses and type paths; a dependency between them (an `apply` of a struct someone else redefined) is not tracked. A store written before the journal existed, or a journal older than its 1024 newest entries, cannot prove independence and conflicts.
- **Named views: per-agent isolation.** `options.view` gives an agent its own annotations and revision. Views are not merged back into the shared view: *per-agent views by default* is deferred until publish/merge exists, so today agents that must share results use the shared view with the policy above.
- **Cost is attributable.** A work-copy build reports `last_sync.phases_ms` (`master_open`, `fork`, `copy` (the engine's clone or copy time, part of `fork`), `base_upgrade`, `open`, `replay`, `total`; whole milliseconds, field names stable), so a slow named-view first edit can be traced to a phase. The shared base is keyed by master revision and engine release (`hydraVersion` and `ghidraVersion` from `hello`); the engine does not report a database format number, so the release stands in for it, and a base built by an unrecorded release is rebuilt once.

**Limits today.**

- Native commands stay in the quick lane while imports and analyses run in the long lane. Questions asked through Hydralysis are scripts and share the long lane; a full long lane delays them (measured up to about 8 s). Readers of the program being analysed wait for its lock.
- Each program and project has its own lock. They share the daemon's lane slots and import gate, so enough long work anywhere can delay a save or fork elsewhere.
- A disconnected client's requests are cancelled and its uncommitted changes rolled back when its running request ends. A request blocked on a lock, or a script that ignores cancel, keeps its place until the lock frees or the script ends.
- An import waits in the import queue; at the front it still needs a long slot and fails `busy` after `wait` (10 s default).
- `cancel` stops requests waiting for a slot and cooperative scripts; a request waiting for a program lock stays until its `wait` runs out.

Queries run as engine requests that share the engine's long-job slots with imports and exports, so heavy parallel use is something to measure, not assume. [The protocol](docs/upstream-analysis.md) and `backend help` describe the options.

`ghidra-query --target sample --action export --options-file export.json` writes a durable JSONL artifact. Use `job <export-id>` for status/cancel and `{"resume":"<export-id>"}` to continue the same selection. Resume refuses changed builds, source analysis, implementation or overlays. See [export options and limits](docs/exports.md).

## No GUI

There is no GUI. Hydra Engine is headless only; projects it writes cannot be opened by Ghidra 12.2 or 12.1.4. Other processes can read a project directory the engine is not using; record corrections through `type_edit`.

## Measured, not promised

Numbers here come from the owner's KotOR baseline and depend on the function and the machine; treat them as examples, not guarantees. A warm decompile measured 0.7-2.1 ms for a 1-byte function and 35-45 ms for a 6.7 KB function: native decompile about 1 to 45 ms by function size; through Hydralysis about 25 ms on a small program and about 60 ms on KotOR (single runs). The tool counts in [the tool mapping](docs/tool-mapping.md) are sourced there, with what is still unverified marked.

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

The CLI retains `sections`, `exports`, `ghidra-scripts` and `ghidra-jobs` aliases. They are not advertised as additional MCP tools. The catalog has regression budgets for tool count, total JSON bytes and individual schemas: 20 tools in about 8 KB of schema (8,172 bytes as the catalog test counts them; the limit is 8,192). `tests/test_claims.py` checks these numbers against the catalog. [Client setup](docs/clients.md) explains registration, the terminal path and the Python API (`hydralysis.client`, `hydralysis call <tool> --args`). No client configuration or other MCP registration is changed automatically.

`ghidra-run` is an escape hatch for deliberate trusted local scripts. The script is staged into Hydralysis's script folder and runs contained on the warm engine: its changes are rolled back and never saved, but while it runs, other clients can see them. Scripts that use the headless API run unchanged; extensions that need an interactive window do not apply. Engine containment does not stop a script from writing other files. Use the query actions for routine work.

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
