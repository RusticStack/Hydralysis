# Capability audit: independently replacing NCT-used framework services

This is an evidence-backed requirements map for the RE tools, not an NCT
feature implementation. The inspected checkout was
`C:\Users\KellHect\orca\projects\CoopCyberpunk`, verified with `gh` as
`KelpHect/NightCityTogether` at
`1364117365c51720db26e5d88272e7cf0d7bbb33`. Its `AGENTS.md` delegates policy to
`CLAUDE.md`. This audit read source and the dated state checkpoint; it did not
launch a game, attach a runtime, import a binary or treat old experiment-log
headings as current acceptance results.

## What the current project actually depends on

The project's [prerequisites](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/CONTRIBUTING.md#L3-L10)
and [install checks](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/devharness/install.ps1#L23-L30)
establish RED4ext, redscript, Codeware and TweakXL as runtime/build inputs.

| Component | Observed subset used by NCT |
| --- | --- |
| RED4ext + SDK | Native plugin load/unload and versioned exports; registration/post-registration callbacks; script directory registration and running-state tick. The concrete call sites are [Plugin.cpp:349–362](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/plugin/src/core/Plugin.cpp#L349-L362) and [its exported ABI:518–544](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/plugin/src/core/Plugin.cpp#L518-L544). The SDK is a [declared submodule](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/.gitmodules#L1-L3). |
| redscript | Script compilation and a modified game script bundle, not just runtime function calls. [check-scripts.ps1:24–41](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/devharness/check-scripts.ps1#L24-L41) stages `scc.exe`, `final.redscripts`, NCT, Codeware and TweakXL script inputs; [the actual invocation](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/devharness/check-scripts.ps1#L43-L54) compiles that copy. |
| Codeware | Session/input/entity lifecycle callbacks, services and dynamic entity creation/deletion. [Session.reds:168–195](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/scripts/NightCityTogether/core/Session.reds#L168-L195) registers session/input callbacks; [Puppets.reds:2305–2328](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/scripts/NightCityTogether/player/Puppets.reds#L2305-L2328) publishes worker-visible spawn state before `DynamicEntitySystem.CreateEntity`; [cleanup:2688–2691](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/scripts/NightCityTogether/player/Puppets.reds#L2688-L2691) deletes the dynamic entities. |
| TweakXL | Loading authored TweakDB records and runtime database edits. The [YAML:1–29](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tweaks/NightCityTogether.yaml#L1-L29) derives puppet records and refers to authored entity templates. [VehicleCam.reds:421–437](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/scripts/NightCityTogether/vehicle/VehicleCam.reds#L421-L437) calls `TweakDBManager.CloneRecord`, `SetFlat` and `UpdateRecord`; [restoration:504–508](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/scripts/NightCityTogether/vehicle/VehicleCam.reds#L504-L508) restores changed flats. |
| Packed resources / WolvenKit tooling | The shipped archive contains authored entities, rigs and animation graphs. [repack.ps1:3–22](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/entities/repack.ps1#L3-L22) describes JSON-to-binary conversion, packing and verification of the packed result. This is an asset-toolchain dependency, not evidence that an archive-loading mod is required. |

ArchiveXL is discussed in
[appearance-name compatibility comments](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/scripts/NightCityTogether/player/Puppets.reds#L4324-L4332),
but it is not among the declared prerequisites/install checks above. The scoped
native/script search found references to other mods' CET-based implementations
in comments, not a declared Cyber Engine Tweaks runtime prerequisite. The
`CETCOMPAT` text in `FaultGuard.hpp` concerns Windows control-flow enforcement,
not the Cyber Engine Tweaks mod. This audit therefore does not invent an
ArchiveXL/CET replacement requirement from those text matches. Broader mod
compatibility could establish one later.

GameNetworkingSockets, logging/JSON/test libraries and miniupnpc are separately
declared in [vcpkg.json:4–10](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/plugin/vcpkg.json#L4-L10).
Replacing RE MCP servers does not imply replacing every ordinary networking or
build dependency.

## RE capabilities those independent implementations need

| Investigation / contract to establish | Generic Hydralysis facilities and the remaining proof obligation |
| --- | --- |
| Loader ABI and engine lifecycle | PE imports/exports, disassembly, saved-project decompile/dossier, blocks and bounded references locate exports and call sites. Guarded runtime probes can observe entry/exit, registers, thread id and backtrace. The independent loader must still implement the discovered version negotiation, startup ordering and teardown contract; a successful probe does not supply that implementation. |
| RTTI registration and native/script marshalling | Type inspection, recovered variables/signatures, p-code/def-use trace and cited type overlays support layout/ABI reconstruction. Runtime module/heap reads and host-side pointer decoding can inspect live reflection structures. [ScriptBridge.cpp:60–75](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/plugin/src/bridge/ScriptBridge.cpp#L60-L75) already reads the engine type system; [native globals:2133–2173](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/plugin/src/bridge/ScriptBridge.cpp#L2133-L2173) bind strings, arrays, handles and typed parameters. An independent replacement needs measured allocator, ownership, holder/persistent-value and call-frame semantics, not merely matching C struct sizes. |
| Script compiler, bundle format and VM binding | Native analysis can trace compiler/VM routines, inspect serializers and build reproducible test programs. Filesystem/authoring tools remain necessary to implement and compare parsers/compilers. Hydralysis's saved type overlays do not compile redscript or guarantee `final.redscripts` compatibility. The existing [compile harness](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/devharness/check-scripts.ps1#L24-L54) provides concrete inputs/outputs an independent compiler must reproduce. |
| Codeware service construction and callbacks | Use runtime context/call-order observations with static xrefs and dataflow, then retain build-bound evidence. [game-systems.md:14–42](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/docs/engine/game-systems.md#L14-L42) records that RTTI-only registration did not construct a system, while the observed construction path populated the game-instance containers and invoked initialization. It also distinguishes post-register callbacks from main-thread updates. Those transitions must be independently proved and implemented; no game-system adapter belongs in Hydralysis. |
| TweakDB and packed assets | Byte identity, type/serializer recovery, pointer inspection and bounded experiments help reconstruct database record/flat representation and resource loading. Format-specific parsers and independent writers still need round-trip/diff validation against fixture resources. The current PE-oriented inspection commands do not claim to decode CR2W/archive formats by themselves. Native analysis and ordinary project-side scripts can supply evidence without adding a tool per engine or archive format. |
| Safe hooks, thread/stage/lifetime and update compatibility | Fingerprints, exact-byte prologue gates, signatures and guarded runtime probes establish build/site identity. Recorded thread/context and enter/return observations help test ownership and scheduling; captured raw argument slots are not asserted source types. [MainTasks.hpp:9–20](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/plugin/src/core/MainTasks.hpp#L9-L20) records why a delay callback could not stand in for a main-thread queue. Fresh builds require fresh layout/byte checks and regressions; an old offset must not silently become a new-build fact. |

The [crash-handling investigation](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/docs/engine/crash-handling.md#L3-L9)
is a particularly important acceptance constraint: it reports that caught
first-chance faults could still leave the game suspended, and debugger
attachment changed that behavior. Therefore a fixture breakpoint test is not
proof that an engine operation is safe outside a debugger. User-directed live
acceptance and crash-free probes remain necessary after the static work.

## Boundary and readiness claim

The tools now expose the missing kinds of native investigation: backend setup,
initial analysis, recovered types and editable analysis overlays, bounded p-code
dataflow, live module/heap observations and verified function probes/breaks.
They do not ship independent RED4ext, redscript, Codeware or TweakXL
implementations, nor does this read-only audit claim those replacements have
been accepted. The core stays generic; engine-specific schemas, experiments,
replacement code and compatibility suites belong with their independent
projects and cite observations back to a particular binary build.

Practical completion is evidence that an agent can answer the required
questions and run bounded experiments through Hydralysis without installing REA
or Ghidra MCP. It is not a promise that any large engine/framework replacement
can be completed automatically from an executable alone. CPU instruction
single-step, original source types, unresolved indirect-call semantics and a
general asset-format decoder are not implied by the exposed native primitives.
