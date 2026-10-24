# Verification, 2026-10-24

Run on Windows with Python 3.14, Ghidra 12.1.4 PUBLIC and Adoptium JDK
25.0.4, using the existing installations. Ghidra processes had a 6G heap cap
and four CPU workers. No initial import or auto-analysis was performed.
The two analysed masters were copied into RusticRE-owned snapshots and opened
with `-process -noanalysis -readOnly`. No game or runtime hook was launched.

## Tests and packaging

`python -m unittest discover -s tests -v`: **63 tests passed**, exit 0.
Coverage includes real stdio subprocess exchanges, responsive MCP control
messages during slow calls, queue/output limits, snapshots and locks, stale
analysis, worker death/refusal/timeout recovery, file-backed reads, signature
checks, string-start addresses and Windows batch arguments with spaces and
semicolon-separated script paths. Lifecycle unit tests simulate hung workers;
the real JVM checks below are separate.

`python -m pip wheel --no-deps --cache-dir F:/dev-cache/pip . --wheel-dir
F:/dev-cache/rusticre/audit-20261024/dist` built successfully. Both owned Java
scripts are included in the wheel. `git diff --check` passed. This repository
has no configured formatter/linter or CI workflow.

The serialized `tool_table()` contains **20 tools**, **6,428 UTF-8 bytes** in
total, and a largest individual input schema of **363 bytes**. Tests enforce
20 tools, a catalog below 8 KiB and each schema below 1 KiB. These are byte
counts, not token or billing claims. `ghidra_query` occupies the former
`ghidra_lanes` MCP slot; it does not add a twenty-first tool.

## Real saved-project queries

Local run records are under
`F:\dev-cache\rusticre\audit-20261024`. Raw binary/decompiler output stays there;
only these measurements and build identities are committed.

| Artifact | SHA-256 |
| --- | --- |
| SWTOR client, 30,680,576 bytes | `0f32b9d9562dafce89be662014615e0cc288f042a3fcfbbd8c38271abcd690f5` |
| Current KotOR executable, 4,042,752 bytes | `0290889e0cea6ebc00021c1bdb945704fc4c45afaf7fcebabb0e82ba674437e6` |
| Cyberpunk executable, 66,704,848 bytes | `d36e74c47592e9c656ae250078cb40b2be63c782af5bfbeff2280d43e653fab4` |

`smoke-results.json` / `smoke-v2.log` record the completed query sequence:

| Operation | Observed wall time |
| --- | ---: |
| SWTOR VA `0x1404275e0`, cold decompile | 4.946 s |
| Same VA, three warm decompiles | 0.087 / 0.146 / 0.098 s |
| SWTOR function page / xref page | 0.093 / 0.083 s |
| KotOR cold function page | 4.699 s |
| KotOR VA `0x00401000`, warm decompile / bounds | 0.317 / 0.063 s |

The cold SWTOR call reported `startup_s=4.421` and `query_s=0.354`.
Startup includes snapshot preparation, JVM launch, project open and script
initialization. Query time includes mailbox polling; total wall time also
includes source/build validation. These are a few samples of particular
functions, not a p95 benchmark or a comparative whole-project speedup. An
earlier developmental run is retained in `smoke-results-v1.json`, including
its failed KotOR address lookup. That baseline project did not define a
function at `0x52c0d0`; querying its function page provided a valid entry point.
The server did not fabricate bounds or import another binary to fill the gap.

`verify-results-v1.json` records two successive functions pages and two xrefs
pages, with different results and working continuation cursors. It also records
a real CLI decompile (0.323 s total) and a real newline MCP decompile (0.278 s
for the complete subprocess exchange). Both returned `cold=false` and the same
worker session as the preceding API query. The MCP exchange also initialized,
listed the twenty tools and answered ping.

`verify-results.json` / `verify-resume.log` record:

- A one-second legacy launch deadline produced an explicit timeout, terminated
  the owned process tree and retained diagnostics. This exercised startup
  timeout cleanup, not a real decompiler computation hang. A subsequent guarded
  script succeeded in 5.356 s on another lane.
- A missing-function refusal and a stopped worker were followed by successful
  queries in fresh sessions. Their earlier records are in
  `verify-results-v1.json`.
- A deliberately wrong SHA-256 stopped the custom script before its success
  marker. Ghidra exited **zero**, but RusticRE reported `GhidraJobError` because
  the guard logged a script error. The equivalent query refused the project
  before returning any decompiler text; correcting the build identity restored
  querying in 3.936 s.
- Cyberpunk PE `inspect` and `fingerprint` succeeded in 0.790 and 0.064 s.
  This was an offline inspection at VA `0x1403887d4`, not proof that a historical
  name or hook from another build is valid there.
- Content hashes of both master `.gpr`/`.rep` trees were identical before and
  after the final guarded/recovery sequence. The tree hash combines sorted
  relative filenames and each file's SHA-256. Both query workers were stopped
  at the end.

Reproduce the normal path with a configured target:

```text
rusticre ghidra-query --target sample 0x140001000
rusticre ghidra-query --target sample 0x140001000
rusticre ghidra-query --target sample --action functions --limit 2
rusticre ghidra-query --target sample --action functions --limit 2 --cursor <next_cursor>
rusticre ghidra-query --target sample --action xrefs 0x140001000 --limit 2
rusticre ghidra-query --target sample --action xrefs 0x140001000 --limit 2 --cursor <next_cursor>
rusticre ghidra-query --target sample --action stop
```

## Failures found during this work

The first launch attempt failed with Windows command syntax errors. Quoted
directory properties in `GHIDRA_HEADLESS_JAVA_OPTIONS` were expanded by the
batch launcher inside another quoted argument. The corrected implementation
passes storage properties through `JAVA_TOOL_OPTIONS`, parsed by the JVM.
Logs of those failed launches remain with their snapshots. The first exploratory
harness did not stop on that error and produced repeated failed launches; it
was corrected to fail immediately before further integration checks.

The first guarded-script attempt then failed because an unquoted semicolon in
the script search path became a separate batch argument. The launcher now
quotes every argument in a validated raw Windows command string; a native batch
regression test covers spaces and semicolons. The successful resumed checks
followed inspection of that failure's complete log.

The first wheel attempt without build isolation failed because this venv did
not contain `setuptools.build_meta`. The corrected isolated build used the F:
cache/temp paths and succeeded. A new string fixture initially joined ASCII
and UTF-16 bytes into one valid overlapping wide string; an extra delimiter
made the intended separate-string assertion unambiguous before the final test
pass.

Remaining limits: no real 300-second decompiler hang was induced, and POSIX
process cleanup was reviewed but not exercised on this Windows host. No
Cyberpunk Ghidra worker was opened; the real saved-project tests covered SWTOR
and KotOR. The [research report](research.md) explains where REA value-flow
queries and direct Ghidra analysis/editing still earn a call.

## Fresh KotOR II install

The follow-up test used only the newly installed
`E:\SteamLibrary\steamapps\common\Knights of the Old Republic II\swkotor2.exe`,
with no analysis project prepared for it. It is a 6,588,416-byte PE32 x86,
version 1.0.2, SHA-256
`6a522e71631dcee93467bd2010f3b23d9145326e1e2e89305f13ab104dbbffef`.
The native RusticRE MCP successfully returned its fingerprint, sections,
imports, full strings, raw bytes, disassembly, candidate string references,
signature hit and positive/negative prologue checks. No game was launched,
hook installed or Ghidra import run. Packing triage reported no obvious
indicators; that is not proof the file is unpacked.

This test found a real address bug: the entry RVA `0x51d5a2` exceeds the image
base `0x400000`. The old auto-detection subtracted the image base and inspected
RVA `0x11d5a2`, which is also mapped. The corrected API rejects ambiguous
unprefixed addresses and accepts explicit `rva:0x51d5a2` or `va:0x91d5a2`.
Both returned the same bytes at file offset `0x51c9a2`, independently checked
against pefile's entry-point mapping and the original file bytes. Seven new
regression tests cover this overlap and shared CLI/MCP behavior. Fresh CLI and
newline MCP subprocesses also passed the real-file address test with no backend
configuration. The catalog grew by descriptions of address syntax, not tools.

The decompile attempt through the registered MCP returned
`no ghidra target 'kotor2-fresh-install'; configured: sample`. This is a real
first-use gap, not successful decompilation: current RusticRE requires an
existing analysed project and a Ghidra/JDK installation. Saved analysis is the
prerequisite; functions do not have to have been decompiled previously. A
generic explicit import/analyse-once job, durable status/failure reporting and
target registration are still needed before claiming an end-to-end fresh-start
workflow. Ghidra remains the backend decompiler, distinct from its MCP server.

Local records: `kotor2-native-mcp.json` retains the original native calls and
the wrong-address discovery; `kotor2-fresh-results.json` / `kotor2-fresh.log`
record the corrected subprocess checks; `kotor2-tests.log` records the 63-test
pass. Existing MCP processes need a reload to load this source update.
