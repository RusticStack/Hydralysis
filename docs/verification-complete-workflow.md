# Workflow verification, 2026-10-25

This report covers the 0.3.0 implementation. The [earlier report](verification.md)
and [KotOR/SWTOR PR reports](open-pr-insights.md) describe historical sessions;
their timings and findings are not measurements reproduced by this run.

The user asked for tool implementation and explicitly deferred full game
decompilation to a later Qoder run. The already-started KotOR II preparation
job `prepare-797dbdf190c0` was cancelled when that instruction arrived; its owned
headless JVM exited. Partial analysis and diagnostics were retained. It was
not registered as completed analysis. No later game import/decompile was started,
and no game was launched or attached for these checks.

## Sources examined

- REA revision `f196ebf80665107aedc16892af25a1e1f9f26f43` and GhidraMCP
  revision `1e980252087b2479a21b9ca6d82d5829538651a7`, fetched with `gh`/Git
  into reference checkouts outside this repository. See [setup](upstream-setup.md),
  [analysis](upstream-analysis.md) and [runtime](upstream-runtime.md).
- [RusticRE PR #3](https://github.com/RusticStack/RusticRE/pull/3) and
  [PR #4](https://github.com/RusticStack/RusticRE/pull/4), including their bodies,
  all comments, changed documents and empty review/inline-review lists. Their
  immutable heads, observed successes/failures, workload sizes and acceptance
  criteria are recorded in [the review](open-pr-insights.md).
- Local project sources and immutable GitHub counterparts for
  [KotOR](capabilities-kotor.md), [Night City Together](capabilities-nct.md) and
  the earlier [SWTOR usage research](research.md). No project-specific parser,
  hook or engine feature was added to RusticRE.

No upstream MCP package or bridge implementation was copied or installed.
Ghidra/JDK and Frida are engines, not those MCP servers.

## Engine setup and owned native fixture

Evidence is retained outside the repository under
`F:\dev-cache\rusticre\complete-20261024`. The date in that directory is the
start of the work, not the date of every subsequent test. Logs include failures
and corrected integration runs; a tool response alone is not treated as success.

| Check | Observed result and evidence |
| --- | --- |
| Existing analysis engine setup | `setup-c48e8c393b35` completed, reusing verified Ghidra 12.1.4 and a compatible full JDK; no download/import. `setup-reuse-smoke.json`. Official release URLs, sizes and SHA-256 values were rechecked against the GitHub release APIs. Archive verification/extraction failures are covered by unit tests; a second fresh network installation of Ghidra/JDK was not performed. |
| Optional runtime installation | `setup-a4d2c5f3d3ab` completed the private, pinned Frida 17.24.3 installation. No upstream MCP was installed. |
| Explicit first preparation | The small owned MSVC x64 fixture completed `prepare-d2ae70cbdaf8`, saved verified analysis and registered `owned-fixture`. Its 151 analysed functions include compiler/CRT support code. `fixture-preparation.json`. This was fixture analysis, not a game import. |
| Saved analysis | Real Java compilation and decompile, function ranges, variables, types/fields, blocks, high p-code and two-function direct-call trace succeeded. `advanced-first.json`, `overlay-smoke.json`, `analysis-integration-final.json`. |
| Overlays and recovery | Wrong expected bytes refused a function correction; a two-child batch with a failing child did not retain its rename. A successful delete/create/prototype batch and body correction replayed after worker restart. Ordinary misses preserved a warm session. |
| Canonical project | SHA-256 comparisons of all eleven canonical project files before/after the integration sequence were identical. Queries used saved snapshots opened with `-process -noanalysis -readOnly`; no new import was started. |
| Fresh MCP and exports | A new stdio MCP process negotiated 0.3.0, listed twenty tools, queried a miss followed by a valid warm decompile, tested dossier/flow, completed a two-function `rustic_`-filtered JSONL export with C/body/output/import digests, reused that artifact on resume, refused changed resume options, listed the job and answered ping. Process exit was 0; canonical hashes stayed unchanged. `mcp-integration-final.json` and `.log` retain the final run. This is a complete filtered fixture selection, not a whole-game export. |
| Data and scans | A known exported-name string, defined data and pointer candidates were read from saved analysis. A literal MOV scan paged with a cursor; a nonmatching scoped scan finished cleanly. |
| Prologue table | A 21-row fixture table matched; changing one row produced a refusal with twenty matches and one failure. A separate fresh CLI call then checked the actual SWTOR `native-hooks.json` envelope against its declared full build: **21/21 matched**, exit 0, binary size/mtime unchanged. `swtor-table-real.json` and `.log` retain command/result. The declared hash/base, aliases, compact bytes and wrong-build refusal are regression-tested. These are offline checks, not installed runtime hooks. |
| Runtime x64 and x86 | Both architectures passed paused spawn and explicit PID attach, module bytes, mismatch refusal, exact-byte observation, registers/arguments/return/backtrace, breakpoint, absolute Sample read, continue, restored hook bytes, detach leaving the fixture alive and graceful stopfile exit. Final IPC runs: `runtime-integration-results.json` / `runtime-integration-smoke-v5-ipc.log` and `runtime-x86-integration-results.json` / `runtime-x86-integration-smoke-v4-ipc.log`. |

The x64 fixture SHA-256 is
`074a4e0361aecea2dedd82ba911322b7d87c98d4f543fe326aae9fe9dcb05385`.
Its source is [tests/fixtures/runtime_fixture.c](../tests/fixtures/runtime_fixture.c).
It was compiled with MSVC 19.44 (`/Od /GS- /MD /Zi`), with all outputs under
the evidence directory. The independently built x86 fixture SHA-256 is
`f98a1d50309926fa8864adfbb81f06a475ac1a6e6ace2e2f1c93eccdfa16949a`;
it was observed as PE32 / Frida `ia32`, with four-byte pointers.
Rebuilding can change its digest/debug path; discover
the rebuilt exports and fingerprint rather than reusing these addresses.

Real runtime tests found and fixed readiness PID confusion, a paused-Windows
main-module shortcut selecting ADVAPI32.dll, and non-enumerable Frida register
properties. The failed logs remain alongside the passing run. Unit tests also
cover termination failure reservations, PID reuse, queued cancellation, dead
workers and malformed protocol/input cases. The additional runtime/query runs
found intermittent Python file-read `PermissionError` failures, including with
unique immutable filenames. Native reads of those same files succeeded at rest;
the earlier native cause was not established. No ACL, Defender or machine
settings were changed. Per-call transport was replaced with authenticated,
bounded loopback frames and absolute deadlines. Durable startup/progress/log
metadata remains on disk. Failed-file-transport artifacts and
`native-file-diagnostic.json` are retained. Those forced failure tests are
different from claiming a real game timeout was reproduced.

Cold metadata reads also use bounded Windows native shared reads, closing their
owned handles before returning and preserving native error codes/filenames.
The corrected cold-start MCP run passed. This is not a guarantee of concurrent
replacement on every filesystem: an explicit replacement while a native read
handle remained open was denied with WinError 5 on this machine and is retained
in `native-held-replacement-diagnostic.json`. That operation was not retried or
hidden, and no security setting was changed.

## Final integration checks

- The complete unit suite passed: **202 tests**, process exit **0**;
  `tests-final.log`. Tests include real local framed-socket admission/deadlines,
  native file/error behavior, a terminated Windows child with a retained process
  handle, and mock-backed engine/session failure and recovery paths.
- Fresh MCP startup, warm queries, typed misses, truncation, credential
  redaction, a complete filtered two-function export, completed resume,
  changed-option refusal, unified job listing and ping passed with process
  exit **0**. Final job `export-108d6f031636` wrote 5,186 JSONL bytes;
  its output SHA-256 is
  `30e03072e741b0daf55cece57a42b6024bfd73c153cf99dd392693e274db25ce`.
- The catalog remained **20 tools**, **7,435 JSON UTF-8 bytes**; the largest
  individual input schema was **489 bytes**. These are serialized byte counts,
  not model token counts or billing savings.
- The 0.3.0 wheel built successfully. ZIP inspection confirmed all required
  backend/worker/IPC/I/O modules and `RusticGuard.java`, `RusticPrepare.java`
  and `RusticQuery.java`. An isolated installation imported 0.3.0 from the
  installed wheel, listed twenty tools, and matched all three packaged Java
  scripts byte-for-byte against the validated sources. Build logs and artifacts
  are under the evidence root.
  The first build attempt lacked setuptools; build dependencies were then
  installed privately under `F:\dev-cache\rusticre-build-tools`, and the
  corrected build exited 0. No global Python installation was changed.
- `git diff --check` passed. No formatter, lint command or CI workflow is
  configured in this repository; none is reported as silently passing.

## Read-only installed-game corpus

`tools/verify_corpus.py` inspected all 17 EXEs found beneath the four installed
directories at `E:\SteamLibrary\steamapps\common`. This included main game
executables, launchers, configuration/update tools and redistributable installers.
All 17 passed their applicable checks. The script recorded full fingerprints,
output digests and input metadata, and verified it created no analysis job.

| Installed directory | Scope and result |
| --- | --- |
| Fallout 3 goty | Five PE32 files: game, launcher, editor and two installer stubs; lightweight checks passed. An installer named x64 is still a PE32 stub; filenames did not determine architecture. |
| Knights of the Old Republic II | `swkotor2.exe`, PE32; lightweight checks passed. No full analysis/decompilation was completed. |
| Star Wars Empire at War | Seven EXEs across base/expansion/support files, including PE32 and PE32+. Four `.bind` wrappers were identified and preparation plans blocked; wrapper code was not presented as game code. |
| swkotor | Four PE32 files. The installed `swkotor.exe` build had no known-wrapper section; that is not proof of unpacked code or absence of DRM. Lightweight checks passed. |

The checks cover fingerprint/packing triage, section/import/export/string tables,
read-only preparation planning and, where not blocked, entry bytes/disassembly,
candidate references/callers/callees, signature search and matching/mismatching
prologues. They establish neither analysis correctness nor runtime compatibility
for every game. All source files retained their original size/mtime; no game
was modified. Full records and hashes are in `corpus-final.json` and
`corpus-final.log`; the earlier corpus run is retained separately.

## Remaining limits

The server still advertises twenty tools. The catalog is measured as JSON UTF-8
bytes, not model tokens or billing. Detailed operation help is fetched on demand.
Types remain recovered/cited assertions; bounded flow does not solve arbitrary
aliasing, indirect targets or reachability. Runtime breaks are cooperative and
affect the hitting thread; CPU single-step, hardware watchpoints and graphics
debugging are not implemented. Automatic unpacking is not provided. Ghidra/JDK
portable installation is Windows x64; other hosts require existing supported
engines and were not validated by this Windows run.

For those unsupported debugger/GUI operations a direct debugger or Ghidra GUI
can still be preferable. REA's non-native/browser/Android/firmware scope remains
outside this small server. The covered preparation, analysis, type/flow, export
and instrumentation workflows require neither upstream MCP. No client MCP
registration was removed or changed by this work.

See the project audits for the separate work still required to reconstruct
KotOR semantics/rendering or independently implement the actual RED4ext,
redscript, Codeware and TweakXL dependencies used by Night City Together.
