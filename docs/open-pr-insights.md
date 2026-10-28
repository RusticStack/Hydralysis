# KotOR and SWTOR usage reviews: requirements before removing the old MCPs

> Historical record: written when this project was called RusticRE (command `rusticre`, variables `RUSTICRE_*`, tool prefix `mcp__rusticre__*`). It is kept as written; the names are `hydralysis`, `HYDRALYSIS_*` and `mcp__hydralysis__*` now.

Reviewed on 2026-10-25 using `gh`: PR bodies, every issue comment, changed
documents, commit lists, review lists and inline review comments. The requested
PRs are in **RusticRE**, rather than in the two game repositories:

- [PR #3, KotOR 1.0.3.0](https://github.com/RusticStack/RusticRE/pull/3),
  head `27e0048d0c6dd9aea40c5133e4f6d77f4f09392d`;
  [immutable review](https://github.com/RusticStack/RusticRE/blob/27e0048d0c6dd9aea40c5133e4f6d77f4f09392d/docs/reviews/2026-10-25-kotor-1.0.3.0.md).
- [PR #4, SWTOR-origins](https://github.com/RusticStack/RusticRE/pull/4),
  head `2e0ae16992218dec1eb4d783de0c1f8c6dff2552`;
  [immutable review](https://github.com/RusticStack/RusticRE/blob/2e0ae16992218dec1eb4d783de0c1f8c6dff2552/docs/reviews/2026-10-25-swt-origins.md).

Both were open and documentation-only at inspection. Neither contains runtime
code, tests or a patch to cherry-pick. Both had no submitted reviews or inline
review comments. No PR was changed or merged during this inspection. The
working branch can incorporate the requirements without taking either branch
or overwriting its historical report.

The earlier documents recommend leaving several capabilities with REA and
Ghidra. Later comments explicitly design their replacement, and the user's
current requirement includes setup, type work, bounded value flow and runtime
research. Treat the earlier scope recommendations as historical advice. Keep
the distinction between removing the **MCP frontends** and retaining the
Ghidra/JDK analysis engine; a wrapper cannot decompile without an engine.

## What was measured, rather than merely proposed

| Review | Recorded result | What it establishes |
| --- | --- | --- |
| [KotOR session record](https://github.com/RusticStack/RusticRE/pull/3#issuecomment-6391102288) | PE32 `swkotor.exe`, SHA-256 `0290889e0cea6ebc00021c1bdb945704fc4c45afaf7fcebabb0e82ba674437e6`; string → xref → saved-project decompile found the module loader and helpers. First cold startup 7.615 s, warm query observations 0.056–0.72 s. | The cheap PE tools and warm analysed-project queries were useful together. These are reported session observations, not a new benchmark or a universal latency guarantee. |
| Same KotOR record | `.cache` in the root caused Ghidra's `Path element starting with '.' is not permitted`; the MCP lacked `RUSTICRE_CONFIG`; an ordinary missing-function reply retired a healthy worker; xref output used bare RVAs whereas queries required VAs. | A correct decompiler is still cumbersome when setup and address handoff are inconsistent, or ordinary misses cost another JVM startup. |
| [SWTOR session record](https://github.com/RusticStack/RusticRE/pull/4#issuecomment-6391510149) | PE32+ `swtor.exe`, SHA-256 `0f32b9d9562dafce89be662014615e0cc288f042a3fcfbbd8c38271abcd690f5`; three checked sites matched pinned prologues in 171–196 ms each. Cold decompile 5,998 ms, warm decompile 294 ms, warm xrefs 236 ms. | Three sites were checked in this review; **do not report all 21 hook sites as verified**. The matching call candidate and analysed call xref support that one reference, not a complete call graph. |
| Same SWTOR record | Compact hexadecimal prologues failed; `va:` failed in `ghidra-query`; a parent directory was mistaken for the directory containing `client.gpr`. No timeout, hang or protocol failure occurred in that review. | The observed failures are normalization and configuration defects. Do not invent a new session failure from a proposed feature or from an unrelated historical timeout. |

Both reviews used existing analysed projects through read-only snapshots. They
did not validate initial preparation, game execution, installed hooks or the
new runtime/type/flow features. The current fixture verification report must
supply those results separately.

## Real workload size changes the required contract

The [KotOR Sprint 0 retrospective](https://github.com/RusticStack/RusticRE/pull/3#issuecomment-6391371195)
reports 10,849 internal functions plus 350 imports, 565 handler renames,
repeated instruction/data-reference scans, and Frida VFS/camera/save
experiments. Its [detailed follow-up](https://github.com/RusticStack/RusticRE/pull/3#issuecomment-6391404622)
explains why bulk artifacts cannot be replaced by many large MCP pages.
The independent
[v4 inventory record](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/14_P0_FUNCTION_CLASSIFICATION.md#L49-L96)
also documents body-range and assembly/body/pseudocode hashes and recovered
function definitions. Whole-program export is an earned generic capability;
the user will initiate game-scale analysis/export later through Qoder.

The [SWTOR retrospective](https://github.com/RusticStack/RusticRE/pull/4#issuecomment-6391510628)
reports a recurring 21-site hook table, 162 catalogued opcodes, 150–160
structure records per area, and one capture with 95,952 field transitions.
These are workload reports from that project, not measurements reproduced by
this audit. They explain the priorities: table verification, one-call handler
evidence, type inventories and bounded field-writer reasoning.

## Implementation requirements and acceptance evidence

The implementation descriptions below refer to this working change. Existence
of a code path is not a passed integration check. Keep the central verification
report as the authority for what actually ran.

| Requirement and source | Small generic shape | Acceptance criterion |
| --- | --- | --- |
| Ordinary misses must preserve warm workers; [KotOR recorded failure](https://github.com/RusticStack/RusticRE/pull/3#issuecomment-6391102288) | Classify an expected address/type miss separately from decompiler, deadline and transport failures. | Missing-function query returns an explicit error; the following valid query reuses the worker. Seed decompiler refusal and timeout still retire it. Never recognize arbitrary Java failures as harmless. |
| Root/config/project validation; same KotOR record and [SWTOR failure](https://github.com/RusticStack/RusticRE/pull/4#issuecomment-6391510149) | Resolve a valid engine/JDK read-only; validate Ghidra project path before copying or launching; preparation owns any explicit install/import. | Dot-prefixed project root fails before snapshot/import; default project root itself is valid on every supported host. Missing target error names the actual expected `.gpr` and `.rep`. Configured existing analysed targets cannot be silently reimported by `prepare`. |
| Consistent address intent; both session records | Accept explicit `rva:`/`va:` across PE and saved-project actions; echo normalized addresses and the build hash. Label PE reference output. | Both prefixed forms resolve to the same known fixture instruction; ambiguous bare input fails; each returned address can be passed to the next tool without guessing. Cheap PE32 `inspect` points to analysed queries for function bounds, without implicitly starting a JVM. |
| Batch prologue verification; [SWTOR removal design](https://github.com/RusticStack/RusticRE/pull/4#issuecomment-6391510426) and [input detail](https://github.com/RusticStack/RusticRE/pull/4#issuecomment-6391510814) | Extend existing `prologue`, normalize compact/space/comma/escaped hex, pass one already-open image to a bounded table verifier; CLI normalizes existing `{offset, names, prologue}` rows. | A 21-row invocation opens/hashes once, returns every row and summary, and fails its exit/result status on one mismatch. All rows validate before reads. Exact-byte runtime hooks remain stricter than wildcard candidate scans. |
| One-call function evidence; both removal designs | Existing `ghidra_query` action `dossier`: bounds, signature, callers/callees, data references, referenced strings, instructions/blocks and C, each bounded. | Explicit truncation and continuation; a large complete artifact is written to a file with byte count/hash/path, not silently discarded or pushed into the model context. Entry references are labelled separately from references to the entire body. |
| File export with durable progress; [KotOR detailed design](https://github.com/RusticStack/RusticRE/pull/3#issuecomment-6391404622) | Asynchronous action/job, stream JSONL and final manifest, deterministic function order and full source/options identity. Reuse the analysed project; never import. | Small fixture export completes with counts and per-function body/assembly/C hashes. Interruption preserves a valid partial artifact and resume point; option/build mismatch refuses resume; import count remains zero. Do not run a game-wide export for this validation. |
| Repeated whole-program scans; same KotOR design | Warm query action over Ghidra's decoded listing/references, with scope, hit/instruction/time caps and a continuation cursor. Raw byte scans remain `sigscan`. | Fixture has known matching/nonmatching instructions and data refs; bounded page stops cleanly and the next request continues without restarting the worker. Regex/input limits prevent a scan from poisoning the session. |
| Types, defined data and vtable lookup; same KotOR design | `types`/`type` inspect recovered layout; a data view returns defined data, pointer targets and bounded references. Sources and inferred status remain explicit. | A fixture structure returns offsets/types; a pointer table resolves its entries. Ambiguous type names return candidates or require exact category paths. A type is not claimed correct merely because the decompiler inferred it. |
| Names/types at realistic volume; [KotOR batch proposal](https://github.com/RusticStack/RusticRE/pull/3#issuecomment-6391404622) | Cited, build-bound `type_edit` batch overlays persist outside the canonical project and replay in a read-only worker. This deliberately uses sidecar persistence instead of the suggested mutable master/promotion lifecycle. | A multi-edit batch rolls back fully if one child fails; successful edits survive worker restart; canonical project hashes remain unchanged. File input avoids command-line limits; histories/replay are bounded and fail explicitly rather than dropping old annotations. Complex arbitrary write-enabled scripts are not implied by overlay support. |
| Value origin/field writers; [SWTOR removal design](https://github.com/RusticStack/RusticRE/pull/4#issuecomment-6391510426) and [KotOR flow proposal](https://github.com/RusticStack/RusticRE/pull/3#issuecomment-6391140924) | `pcode`, `blocks`, `trace` actions on the same query worker; choose an instruction/operation/varnode seed and bounded def-use/direct-call traversal. | Fixture trace cites operations and instructions, obeys node/function/depth/deadline caps, and reports unknown memory aliases/indirect calls. A graph is not a proof of runtime path feasibility. The proposed `--field +offset` convenience is only covered if it can select a demonstrated writer, rather than guessing by offset. |
| Dynamic validation; [KotOR retrospective](https://github.com/RusticStack/RusticRE/pull/3#issuecomment-6391371195) | One generic runtime session lane: verified process identity, modules/threads, bounded reads, exact-byte-gated observation/break, continuation/unload/detach. | Owned fixture demonstrates mismatch refusal before installation, events with context/arguments/returns, validated absolute memory reads, safe breakpoint continuation and hook cleanup. This does not claim instruction stepping, data watchpoints, deterministic gameplay replay or a graphics debugger. |

## Keep these boundaries visible

The old reviews' 20–22-tool suggestions are design proposals, not requirements
to add separate tools. Lifecycle, export, scans, type work and runtime actions
can share a small advertised catalog and fetch detailed help on demand. A
capability earns implementation through the recurring workloads above, rather
than through parity with every upstream endpoint.

Game-specific resource parsers, an action VM, a renderer, protocol decoders and
the projects' evidence comparators remain project code. RusticRE supplies
generic evidence and controlled backend access. Removing the old MCPs does not
make those implementations disappear or make a remaster complete. Likewise,
neither four game-directory preflights nor a successful native fixture proves
all DRM wrappers, executables, runtime scenarios or decompiler semantics.

No game was imported, decompiled, launched or hooked for this PR inspection.
Full game analysis/export is left for the user's later Qoder run. No upstream
MCP needs to be installed for the covered workflow.
