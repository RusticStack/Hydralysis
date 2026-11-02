# Trace recorder overhead

Measured by `benchmarks/trace_overhead.py` on the real `frameloop` fixture (x64): capture off against capture on with the
declared baseline profile (eight frameloop hooks, about 10 probe hits per frame) and the **default** recorder settings (32 rings of
1 MiB, 10 ms batches, 2 ms backpressure budget, 16-batch acknowledgement window, adaptive sampling at 120 000 kept records
per second, inline hooks). Rounds are interleaved (off, on, off, on, ...), three per workload; the fixture times its own
frames with QueryPerformanceCounter. Figures are medians over the rounds. The script also reports the process-tree CPU
(the target, including the agent's threads, from the job object, plus the Python worker's own CPU while the target ran).
Results: `E:/Projects/Hydra/_logs/perf-agent/` (`ovbase`, `ovnew`/`ovnew2`, `ovfixed`, `ovexact`).

## Before and after (this change)

Mean frame time, capture on against off, median over three interleaved rounds, defaults unless stated.

| Workload | Before (Frida Interceptor, no sampling) | After (default: inline hooks + adaptive sampling) | After, `sampling: fixed:16` | After, `sampling: exact` |
| --- | --- | --- | --- | --- |
| frame16 (16 ms of work per frame) | +0.1% | 0.0% | not run | not run |
| paced (200 us of work per frame, about 10 hits) | +1.8% (p99 +2.3%), 0 dropped | +0.3% (p99 +0.5%), 0 dropped, all hits kept | -0.1% (p99 0.0%), 556 875 skipped and counted | +0.5%, 0 dropped |
| tight (bare loop, about 5 us per frame, about 2 million hits/s) | +129% (p50 +106%), 399 805 of 594 000 hits dropped | +3.3% to +4.0% (p50 +6% to +8%, p99 +2% to +11%), 0 dropped in the final run, about 480 000 skipped and counted | +0.5% (p50 +2.1%) | +8.6%, 433 676 dropped and counted |

* The defaults meet the plan's targets on the declared profile: 0.0% at 60 Hz, 0.3% with 200 us frames, 3% to 4% on the bare loop
  (a stress test, not a game). The bare-loop p50 is above 5% in some rounds: at a 5 us median one 0.1 us tick is 2%, so the
  per-round median is coarse. The mean and the total run time are the stable figures.
* The sampled profile (`fixed:16`, one in 16 hits kept) is at or under 2% on every workload that was run (0.5% on the bare loop, -0.1%
  on 200 us frames).
* Process-tree CPU is higher than the wall overhead because the Python worker and the agent's drain thread work on another
  core: paced 4.11 s -> 4.83 s (+17%) with every hit kept, 4.06 s -> 4.33 s (+6.5%) with `fixed:16`. That is CPU the target does
  not wait for, and it falls with the number of kept records. The bare loop's tree CPU (0.08 s -> 0.17 s) is dominated by the
  one-off cost of setting the session up inside a 0.1 s run.

## What was expensive and what changed

Measured with a stand-alone Frida script on the same fixture (150 000 frames, about 10 hits per frame, mean of the medians of six
interleaved runs; run-to-run noise is about 1.5% of the frame, so read these as ranges):

| Hook form | Mean frame, 5.19 us without hooks | Per hit |
| --- | --- | --- |
| Frida Interceptor with an **empty** native `on_enter` (measured separately) | +2.1 us (+40%) | about 210 ns |
| Interceptor, the real recorder, every hit kept | 9.17 us (+77%) | about 400 ns |
| Interceptor, the real recorder, adaptive sampling | 8.45 us (+63%) | about 330 ns |
| Inline hook, stub only (each hit takes the full path and calls a bare `ret`) | 5.21 us (+0.4%) | within noise |
| Inline hook, gate only (stride 1024, almost nothing recorded) | 5.21 us (+0.4%) | within noise (earlier runs: +2.3%) |
| Inline hook, one hit in 16 recorded | 5.46 us (+5.2%; earlier runs +3.2%) | about 25 ns |
| Inline hook, default adaptive policy | 5.41 us (+4.2%) | about 22 ns |
| Inline hook, every hit recorded | 5.70 us (+9.8%) | about 50 ns |

* **The Frida Interceptor trampoline alone costs about 200 ns per hit** (it saves the whole CPU context, enters Gum and
  walks its invocation stack), and it is paid by a hit that is then skipped, too (the adaptive policy on the Interceptor is
  still +63%). No CModule can bring a 10-hit, 5 us loop under 5% while it is hooked that way: the floor is about 40%.
  The recorder's own work (FLS lookup, QPC, 72-byte record) was the other 150 to 200 ns.
* **Inline hooks** (default for plain call sites; `hooking: "interceptor"` opts out). A 5-byte jump to a per-probe stub
  replaces whole instructions at the entry; the stub's gate finds the thread's ring through the TEB TLS slot (no call), counts
  the hit, decrements the probe's skip countdown, and for a skipped hit runs the relocated prologue and returns. Flags are not
  touched by the gate, so none are saved. A kept hit saves the volatile registers, flags and xmm0-5, calls the recorder, and
  restores. Probes that need the return value, a buffer or a stack walk keep using the Interceptor.
* **TSC stamp.** A kept hit stamps with RDTSC (invariant TSC is checked with CPUID; otherwise QPC is used) into a 32-byte
  record. The drain thread converts to QPC with a ratio refined from the whole interval since the start, and expands the compact
  record into the unchanged 64-byte wire record. The on-disk format and the TRACE-1 schema are unchanged.
* **Cache lines.** The producer's fields and the drain's fields are on separate lines, and the producer caches the drain's
  tail, so a hit does not touch the drain's line until the ring looks full.
* **Backpressure default** is now 2 ms (was 20 ms): sampling is the first line of defence, and a full ring is a short wait,
  then a counted drop.

## The sampling policy

`sampling` is a capture option (and a profile can declare `[host] sampling = "adaptive"|"exact"`, `rate_budget = N`):

* `adaptive` (default): every hit is counted per probe and thread. While the offered rate fits the budget (`rate_budget`,
  120 000 kept records per second for all probes together) every hit is kept. Above it the agent water-fills the budget over
  the probes: probes under their fair share stay exact, the busiest ones keep one hit in a power-of-two stride. Ring overflow
  halves the effective budget; calm periods win it back. The first moments are looked at every 5 ms, later every 25 ms.
* `exact`: nothing is thinned (a full ring still drops, counted, as before).
* `fixed`: one hit in `stride` for every probe not named in `exact` (a list of probe names that stay exact in any mode).

What is reported, never silently: every skipped hit is `hits - kept` per probe (exact, per thread ring, summed), sent with the
counters. The writer turns the increase since the last report into one `core.capture.gap` per probe with `reason: "budget"`,
`sampled: true`, `dropped` (the exact number skipped), the stride, the probe's rate and its hits and kept totals. The
`core.capture.source` activation event carries the declared policy; the health `producer.sampling` carries the live policy,
effective budget, stride changes and a row per probe. A record kept while its probe is thinned is flagged and its event has
`confidence: "sampled"`; an exact record stays `exact`. Skipped hits take no `ring_seq`, so a skip is never mistaken for a
ring overflow. A function that is entered and left is decided at its enter: a skipped enter has no exit, so a pair is whole
or absent.

## Safety of the inline hook

* Only whole instructions covering at least 5 bytes are replaced; any jump, call, return, interrupt or loop among them sends the probe back
  to the Interceptor. RIP-relative operands are fixed by Frida's relocator. The prologue was already compared with the profile's
  accepted bytes before any hook is installed, so a site that another detour owns is refused as before.
* The stub page is allocated within 1.75 GB of the site, never freed, and when the recorder is released every stub's call
  target is pointed at a bare `ret` first, so a thread that is inside a stub when the script is unloaded returns into the target's code.
* Release restores the original bytes only if the 5-byte jump is still there; if another hook has rewritten the site the bytes are
  left alone, the release reports `quiescent: false` and the recorder stays in pass-through.
* Like the Interceptor, the patch is a plain write: a thread executing exactly in the first bytes of the function at that instant is
  not stopped. This is the same exposure Frida has.
* Not covered: a hook placed mid-function whose caller depends on flags (the stub saves flags only on the kept path; the gate
  uses none), and sites in a function that unwinds through its first bytes (the relocated copy has no unwind data, as with Frida).

## What is still not met, and why

* The bare loop with every hit kept (`sampling: exact`) is +8.6% and drops 70% of its records: the recorder keeps up with about 120 000
  records a second end to end, and each kept hit costs about 60 ns in the target. This is the same writer limit as before; the
  default policy exists to keep that case out of the stall/drop path.
* The bare loop under the default is 3% to 4% on the mean in the benchmark and 4% in the stand-alone runs, but the per-round median
  can read 6% to 8%. The gate itself is within the noise (0% to 2%); the rest is the kept records (one hit in 16 to 64 under the
  default budget) at about 50 ns each.
* The 2% sampled target is met on the fixtures (0.5% bare loop, below noise on 200 us frames) only for probes the inline hook can
  take. Sites with a return value, a buffer or a stack walk go through the Interceptor (about 200 ns a hit at least); their
  overhead on a real game depends on their rate, which the adaptive policy bounds but cannot make free.
* Not established: that these ratios hold for a game other than this fixture.
