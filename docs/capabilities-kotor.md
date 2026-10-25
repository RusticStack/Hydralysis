# Continuing the KotOR remaster with RusticRE

Audit date: 2026-10-24. Read-only inspection of
`E:\Projects\kotor-remaster\kotor-remaster`, verified by `gh` as
`KelpHect/kotor-remaster`, local commit
`28e5806f5b4b468d7c28d6bda28252cce7c660ea`. No game was launched, hooked,
decompiled or analysed during this audit. No project files were changed.

## Current project boundary

The current [README](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/README.md#L3-L11)
reports P0 foundation complete and no playable engine. Its
[native inventory](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/README.md#L15-L20)
already has 10,849 internal functions decompiled. The
[v4 export record](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/14_P0_FUNCTION_CLASSIFICATION.md#L49-L96)
records exact body ranges, assembly/body/pseudocode hashes and 663 functions
with disjoint ranges. Continue from that analysed project and evidence ledger;
an older baseline can lack the recovered functions. Do not repeat a whole-game
import/decompile simply because RusticRE now owns preparation.

Use the current P0 report and completed recon findings for status. Older unchecked
items in `MASTER_PLAN.md` still list Bearing/MDX questions that the later
[MDX report closes](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/15_MDX_LAYOUT.md#L112-L126).

## Concrete work to tool capability

“Implemented” below means the corresponding RusticRE code path exists. It does
not assert that an original-game scene, native handler, visual effect or runtime
hook has been verified by this audit. Fixture and integration results belong in
the central verification report.

| Pending project work and source | RusticRE operations needed | Coverage and boundary |
| --- | --- | --- |
| Native dispatcher semantics for ACTION 700/469 argument slot 2; [script recon:157–183](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/09_SCRIPTS.md#L157-L183) | `ghidra_query` actions `dossier`, `variables`, `pcode`, bounded forward/backward `trace`, `type`/`type_edit`; checked runtime `observe` for arguments/return values | Static operations and cited type overlays implemented. Native handler semantics still require a scoped evidence run. NCS bytecode/source decompilation remains the project's own compiler/parser work, distinct from x86 C decompilation. |
| Complete action/VM behavior, including actions not exercised by shipped scripts; [VM conformance plan:171–191](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/MASTER_PLAN.md#L171-L191) | `runtime` attach/spawn, verified `observe`/`break`, `read`, threads, bounded event retrieval; deliberate authored script for custom state serialization | Observation and entry-break controls implemented; a deterministic original-versus-new-VM differential harness is still project code. Tool access alone does not implement all 772 actions or prove their side effects. |
| Recover a class layout, vtable, constructor or calling convention; [binary-map plan:161–169](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/MASTER_PLAN.md#L161-L169) | `bytes`/`disasm`, analysed `xrefs`, `dossier`, `types`/`type`/`variables`, cited structure/prototype/application overlays | Implemented. Recovered types remain hypotheses backed by sources, not original source declarations. Indirect calls, memory aliases and runtime path feasibility are explicitly unresolved by the bounded def-use graph. |
| New functions missed by automatic analysis; [v4 discovery:86–96](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/14_P0_FUNCTION_CLASSIFICATION.md#L86-L96) | Byte/pointer candidates, disassembly, analysed references, cited `type_edit` function-create/body/delete corrections, or deliberate `ghidra_run` investigation | The saved v4 project already contains the project's recovered entries. Built-in corrections require exact entry bytes, explicit decoded executable ranges and no overlap with other functions; they persist as build-bound overlays. Never promote an arbitrary prologue candidate to a confirmed function automatically. |
| Fresh-module area-RIM precedence and `streamwaves` request order; [P0 handoff:113–119](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/P0_REPORT.md#L113-L119) | Hash/byte-checked resource-entry probes, bounded runtime events and custom request decoding | Generic probe/session support implemented. The missing gameplay scene and exact request ordering are not measured here. The project's existing VFS comparator remains the oracle. |
| Dialogue-camera object state; [camera recon:170–186](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/12_COORDS_OPEN_ITEMS.md#L170-L186) | Static trace to the constructor/update; verified `break`, threads/context, validated object-memory `read` and observation | Implemented generic primitives. A dialogue/cutscene scenario is still needed; the document distinguishes controller fields from camera fields, so the agent must preserve object identity instead of transplanting an offset by name. |
| Multi-group geometry and supermodel visual chains; [P0 handoff:124–132](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/P0_REPORT.md#L124-L132) | Static type/flow inspection and checked runtime probes around model loading; synthetic fixtures and image comparisons outside the RE server | Generic RE primitives implemented. Synthetic scene construction, rendering and perceptual comparison remain project validation. The shipped MDX corpus is already accounted for; this is not a reason to re-decompile the game. |
| Build an actual mesh/depth/material/animation renderer; [P0 handoff:108–112](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/P0_REPORT.md#L108-L112) | Evidence queries about original behavior; normal C++/shader implementation, GPU validation and frame capture | RusticRE supplies evidence, not the renderer implementation. The source currently clears/draws ImGui only: [Vulkan:964–1005](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/engine/src/render/VulkanBackend.cpp#L964-L1005), [GL:159–182](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/engine/src/render/GlBackend.cpp#L159-L182). apitrace/Mesa/GPU capture are separate backends, not currently installed or controlled by RusticRE's setup. |
| Asset/archive/save round trips, coordinate validation and caches; [tool inventory:11–33](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/tools/README.md#L11-L33) | Existing project parsers/tests plus native RE queries when a format or precedence rule lacks evidence | Keep KEY/BIFF/RIM/ERF/GFF/2DA/TLK/NCS/MDL-specific parsers and converters in the project. They are not new RusticRE MCP tools. The agent runs ordinary code/tests alongside RusticRE. |

## Generic workflow for the next investigation

1. Select the existing, hash-matched analysed v4 program and retain its body/
   provenance ledger. The [artifact record](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/01_ARTIFACTS.md#L10-L35)
   identifies SHA-256 `0290889e0cea6ebc00021c1bdb945704fc4c45afaf7fcebabb0e82ba674437e6`
   and discards the older wrapped program. Do not substitute KotOR II's fresh
   install or a matching filename for that build identity.
2. Use `backend inspect` and `prepare` plan for a new artifact. Start an explicit
   asynchronous preparation only when initial analysis is actually needed;
   observe it through durable jobs. Wrapper/packer markers stop automatic
   preparation. No upstream MCP installation is required.
3. Ask one bounded `dossier`/`pcode`/`trace` question, with pagination and explicit
   unknowns. Save only cited names/types as hash-bound overlays/evidence.
4. For a live-state question, select an owned process/session and exact module
   hash. Built-in observation/entry-break probes require exact expected bytes
   and recheck before installing. Frame the capture around one concrete missing
   scenario and compare it with the project's own expectations.
5. Implement behavior in the new engine from project-owned specifications and
   fixtures. Run its parser/VM/renderer tests using the existing
   [build/test contract](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/engine/docs/BUILD.md#L14-L31).
   Preserve the project's [spec/implementation separation](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/MASTER_PLAN.md#L84-L103).

## Verification limits to keep visible

The implemented runtime `break` pauses at a verified function-entry interceptor
with an automatic pause deadline; it is not a full instruction-step/hardware
data-watchpoint debugger. RusticRE accepts structured probe operations rather
than arbitrary runtime scripts, so every built-in installation goes through
the exact-byte gate. Existing project-owned runtime harnesses remain separate
code with their own evidence and validation requirements.

Generic setup, cached analysis, typed overlays and bounded flow/runtime queries
remove the need to install REA/Ghidra MCPs for their covered operations. That
does not establish completed native-handler semantics, deterministic game replay,
renderer parity or a playable engine. No KotOR-specific tooling is added to the
RusticRE server by this audit.
