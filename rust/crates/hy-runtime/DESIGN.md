# hy-runtime design: replacing Frida on Windows 11 x64/x86

Status: stages 1-3 implemented for x64 (see Stages and Open items). The x86 stub, the PyO3 surface and the TRACE-1 pump
integration are not done.

## Decision

Frida is replaced by an own implementation (option b). Reasoning:

- (a) crates.io has `frida` / `frida-sys` / `frida-gum` 0.17.x. They are bindings over Frida core and need the Frida
  devkit (a multi-hundred-MB C/C++ library downloaded at build time) and its V8/QuickJS runtime, and Frida injects a
  large agent (frida-agent.dll) into the target. The owner wants the JS agents replaced and the dependency removed, and
  the binding does not give the per-thread ring, TLS gate or exact counted skips of the current design: those live in
  the C CModule, which would still be C-on-Gum. Rejected as not clean.
- (b) Everything the current design uses is ordinary Win32 plus an inline-hook engine, and the hot path already is
  native code (CModule C recorder, inline stubs), not JS. Rust can do all of it, with `iced-x86` for prologue
  relocation (available on crates.io 1.22; `hy-disasm` from the R-hy-query lane can replace it later).

## Architecture

```
hy-runtime (host crate)               hy-agent-dll (cdylib, injected)           hy-agent-proto (layout)
  spawn CREATE_SUSPENDED                 hy_agent_init (remote thread)             section header + rings
  CreateFileMapping Local\hy_agent_<pid> open section, install guarded sites
  LoadLibraryW via CreateRemoteThread    inline hook = jmp rel32 -> stub -> recorder
  run hy_agent_init (export RVA parsed   per-thread SPSC ring in the section
  from the DLL file, any bitness)
  drain rings (acquire/release), count drops
```

### What replaces each Frida facility

| Frida facility (runtime_agents.py) | Replacement |
| --- | --- |
| `frida.spawn` / `attach` / `resume` | `CreateProcessW(CREATE_SUSPENDED)`, `ResumeThread`; attach-to-running via OpenProcess + same remote-thread injection (PID identity check = OpenProcess + GetProcessTimes + QueryFullProcessImageNameW) |
| script load / `rpc.exports` / `send` | DLL injection + shared section for bulk (rings, counters) + a control mailbox in the same section (command slots + event) for rpc; sealed/HMAC IPC stays in the host layer unchanged |
| `Process.enumerateModules/Threads` | Toolhelp32 snapshot (modules, threads); `GetThreadContext` for contexts; `VirtualQueryEx` for ranges (`locate`) |
| `getExportByName` | host parses the module file/export table (`pe_exports`) and the agent compares with its own export walk before arming ("EXPORT MISMATCH; probe refused") |
| `readVolatile` / `Memory.read` | host side `ReadProcessMemory` (kernel returns an error, no fault); agent side `ReadProcessMemory(GetCurrentProcess())` as the CModule does today |
| Interceptor / X86Writer inline stub | agent `hook.rs`: decode >= 5 bytes on instruction boundaries (iced-x86), refuse a branch into the stolen range, allocate the stub within +-2 GB of the site (VirtualAlloc scan), stub = save flags + volatile regs + xmm0-3, call recorder, restore, relocated prologue (BlockEncoder fixes rip-relative operands), `jmp site+len` |
| guarded probe: module/base check, export check, prologue byte compare | init checks `GetModuleHandle` base + RVA, export equality, and `expect` bytes against live code before patching; any mismatch aborts that probe with a code and installs nothing |
| TEB TLS ring, RDTSC, QPC fallback | per-thread ring claimed on first hit (`thread_local` const cell, implicit TLS works for LoadLibrary'd DLLs), TID read from the TEB (`gs:[0x48]` / `fs:[0x24]`), `rdtsc`; QPC calibration and `use_qpc` fallback ported as in TRACE_C |
| adaptive sampling, exact counted skips | per-ring per-site `hits/kept/next` counters exactly as `SCtr` (stage 2) |
| pause/continue, 30 s breakpoint watchdog | agent parks the hitting thread on an event in the section; the host watchdog (port of `trace_watchdog.py`) signals it; whole-process pause = suspend all threads from Toolhelp list |
| memory write / watchpoints | host `WriteProcessMemory` after the allow-list/conformance/undo-log checks (logic ported from `runtime_memory.py`, `runtime_authorize.py`); watchpoints = debug registers via `SetThreadContext` on every thread (including new ones: agent hooks thread creation or the host polls the thread list) with a vectored exception handler in the agent that records and steps (stage 3) |
| `ReadProcessMemory`-based safe reads | unchanged: never SEH inside the target |
| ETW consumer | existing `hydra-etw` crate in the engine repo is integrated, not rewritten |
| TRACE-1 segment output | encoded by the h7 native `trace.rs` encoder; this crate feeds it records (supersedes the Frida callback side) |

### Bitness

A 64-bit host injects x64 targets with the x64 agent. For x86 (WOW64) targets the x86 agent
(`i686-pc-windows-msvc`, installed in this toolchain; compiles today for the non-hook parts) is needed, and the host
must call the 32-bit `LoadLibraryW`. A 64-bit process cannot take 32-bit kernel32's address from its own image, so the
planned approach is: parse the target's 32-bit kernel32 export table from `C:\Windows\SysWOW64\kernel32.dll`
(`pe_exports` already handles PE32) and add the mapped base from the Toolhelp module snapshot
(`TH32CS_SNAPMODULE32`) once the target's loader has run, or start by running the process to its entry with a
breakpoint. The x86 stub (cdecl/stdcall/fastcall frames, ecx/edx args, no shadow space) is a separate assembler
routine; it is NOT implemented yet.

### Differences / hazards accepted

- Install is done while the target is suspended (stage 1) or with all other threads suspended (live arming); a thread
  suspended inside the patched bytes is detected from its `Rip` and the install retries (not yet implemented).
- The stub does not unwind an exception through the hooked frame; a faulting recorder is impossible by construction
  (no unchecked pointers: arguments are captured through `ReadProcessMemory`).
- Section and rings are fixed size (64 rings x 16384 x 32 B = 32 MB); a thread beyond the 64th is counted in
  `H_NO_RING` and never silent.

## Spike results (stage 1, this machine, Windows 11 26300, x64)

`rust/crates/hy-runtime/src/bin/spike.rs` spawns `frameloop.exe` suspended, injects `hy_agent_dll.dll`, hooks
`fx_stage_input` (9 stolen bytes with a rip-relative `xchg`, which exercises relocation), resumes, and drains the ring.

- 100000 frames: 100000 records, 0 dropped, fixture checksums (`consumer_sum`, `callback_sum`, verdicts) identical to
  the unhooked run: the relocated prologue is correct.
- Bare 4-7 us loop frame time (QPC ticks, 6 interleaved rounds x 100000 frames): mean of per-round means 75.5 ticks
  (bare) vs 75.8 ticks (hooked), p50 medians 62.5 vs 64.5 (10 MHz ticks). The difference is inside round-to-round
  noise (bare rounds alone span 63.9 to 89.6). The current Frida inline design measures about 3-4%; this spike is
  not distinguishable from 0 with this method and one hook per frame. A proper `benchmarks/trace_overhead.py`
  comparison (several hooks per frame, adaptive sampling) is stage 2.

## What is implemented (x64)

- Probes (`hy-agent-dll/src/hook.rs`): guarded install (module base, export equality, >= 5 expected prologue bytes
  compared with live code, branch-into-stolen-range refused); stub with flags, rax/rcx/rdx/r8-r11 and xmm0-3 saved;
  up to 8 arguments (registers + shadow-space stack args); optional buffer capture (pointer arg + length arg or fixed,
  max 256, at entry or at return, read with `ReadProcessMemory` on self so a bad pointer is a counted failure, never a
  fault); optional stack walk (`RtlLookupFunctionEntry`/`RtlVirtualUnwind`, callee-saved registers saved only for walk
  sites); return capture by swapping the return address for a shared trampoline and a per-thread shadow stack
  (entries whose frame was unwound without returning are dropped and counted as `unreturned`).
- Records: variable-length (64-byte header + args + stack + buffer) in per-thread byte rings, one release store per
  record, drops counted per ring, never silent. Per ring and site: `hits`, `kept`; `hits - kept` is the exact number
  of skipped hits. The stride (`S_MASK`) lives in the shared site table, so the host can change sampling live.
- Rings are claimed on a thread's first hit and retired by a fiber-local-storage callback at thread exit; the host
  returns a retired ring to the pool once it has read it to the end. Counters are never reset, so nothing is lost on
  reuse.
- Control channel: a mailbox in the section plus two named events (`hy_cmd_<pid>`, `hy_rsp_<pid>`); an agent control
  thread executes ARM_SITE / RETIRE_SITE / DETACH / PING. Install while the target runs: everything that allocates is
  prepared first, then all other threads are suspended (control and calling thread excluded), their instruction
  pointers are checked against the stolen range (an unreadable context counts as unsafe, retry), the 5 bytes are
  written (one atomic 8-byte store when they fit a cache line), threads resume.
- Clock: `rdtsc` unless CPUID says the TSC is not invariant (then QPC); the host refines TSC->QPC from the whole
  interval on each drain.
- Breakpoints: `F_PAUSE` sites park the hitting thread in one of 16 shared slots (frame copy for the host) on a named
  event; the host `continue_breakpoint`s it or the host-side watchdog releases it after a limit (30 s in the product).
  The agent has its own 120 s hard limit so a dead host cannot freeze a target for ever (`EV_AUTO_CONTINUE`).
- Memory write (`memory.rs`): compare-and-swap with reason, size limit, data-memory-only (every page of the span is
  checked with `VirtualQueryEx`), policy gate (`Gate::Fixture` or `Gate::Authorized`), readback, undo log with
  `Diverged`, undo re-checked against the gate.
- Watchpoints (`watch.rs` + agent VEH): debug registers set per thread (suspend, `SetThreadContext`, DR7 readback),
  slot state machine `arming -> armed -> disarming -> clear | tainted`, `Clear` only after every live thread's DR7 reads
  back off; the agent's handler absorbs every single-step once any watch existed; threads created later are covered by
  `sync_watch_threads` (host polling, so a write by a brand-new thread in the first milliseconds can be missed).
- Authorization (`authorize.rs`): port of `runtime_authorize.py` (normalize, lookup, check, stamp predicate, `pe_arch`).
- PID identity (`identity.rs`): (pid, creation time, image path), re-verified before every write/arm/live-arm.

## Measured (this machine, Windows 11 26300, x64, `frameloop`, nine hooks, one argument each)

`src/bin/hy-bench.rs` mirrors `benchmarks/trace_overhead.py` for the recorder alone: capture off versus on, interleaved
rounds, the fixture timing its own frames, overhead = median over rounds of (on - off) / off. It does NOT include the
TRACE-1 encoder or a Python worker, which the Python numbers do. Raw logs: `E:\Projects\Hydra\_logs
\hy-runtime\`
(`overhead-py.log` for the Frida pipeline, `overhead-rust-gate.log` for this agent).

| workload | Frida pipeline (adaptive, 5 rounds) | Rust agent (adaptive, inline gate, 7 rounds) |
| --- | --- | --- |
| tight (about 5-8 us a frame), p50 / mean / wall | 0.0% / +5.7% / +5.7% | +2.9% / +1.1% / -14.5% (noise) |
| paced (200 us of work), p50 / mean / wall | +0.2% / 0.0% / 0.0% | +0.4% / +0.3% / +0.3% |

The bare loop offers 10.9 hits a frame; the adaptive policy keeps about 1.3 of them (exact `hits - kept` counts), the
Frida run keeps 2.7. Round-to-round noise on this machine is larger than the effects (the "off" p50 alone ranged 4.7 to
7.7 us), so the honest reading is: both are within a few percent on the bare loop, and the Rust gate costs roughly 35
ns per skipped hit before the inline gate was added and less after. Before the sampler existed (exact, every hit
recorded) the bare loop measured p50 +10%, mean +7%, wall +5%, which is the cost of recording 10.9 hits a frame.

## Open items

- x86 (WOW64) targets: no x86 stub, no 32-bit `LoadLibraryW` resolution. `hy-agent-dll` refuses to compile for
  non-x86-64 until it exists.
- The worker/tool-surface port (the PyO3 surface and the Frida-shaped device are done; see PORTING.md for what differs).
- Feeding `Session::drain` to the h7 native TRACE-1 pump; the sampler is wired by the caller (`Session::sampling_tick`), there is no timer thread in the host crate yet.
- ETW integration with `hydra-etw`.
- Sealed mailbox / HMAC IPC and the event-log hash chain belong to the storage lane.
- Hooks inside a function reached by a thread that is itself mid-install (agent threads are excluded; a target thread
  created in the few microseconds between the thread snapshot and the patch is covered only by the atomic 8-byte store).

## Stages

1. DONE: DESIGN.md, spawn-suspended + inject + one inline hook + ring to host, measured.
2. DONE (x64): capture/probe parity pieces listed above; live tests on frameloop and `hy-fixture`.
3. DONE (x64): breakpoints with watchdog, CAS write/undo, watchpoints, authorization, PID identity.
4. TODO: PyO3 surface, Rust test double of `Session` for the white-box cases, remaining test port (see TESTMAP.md).
