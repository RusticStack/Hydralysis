# Porting note: Frida scripts to the Rust runtime (`HYDRALYSIS_IMPL=rust`)

Python and Frida stay the default. With the variable set, `runtime_device.get_local_device()` returns `rust_frida.RustDevice`,
which answers the calls `RuntimeAgent` makes to a Frida device.
A configured Frida stand-in wins: a `frida` package that declares `HYDRALYSIS_STAND_IN = True` (tests/fakefrida) is a test double
somebody put on the path on purpose, so `runtime_device` keeps the Frida-shaped device for it even under `HYDRALYSIS_IMPL=rust`;
the Rust device is chosen only when none is configured (the real binding is not a stand-in). Rule and both directions:
`tests/test_runtime_device.py`. Four script templates are recognised **by their text**
(anything else raises `NotImplementedError`): CONTROL, the TRACE recorder, the observe/break probe, the memory agent.

| Frida script | Rust runtime | Where |
| --- | --- | --- |
| CONTROL (`info modules threads module locate read`) | process handle + toolhelp + `NtQuerySystemInformation` + `GetThreadContext` | `rust_frida.ControlScript`, `hy-runtime::threadinfo` |
| TRACE recorder | injected agent DLL, rings in a host-owned mapping, wire batches | `rust_frida.TraceScript` |
| observe / break probe (`_probe_source`) | agent sites 48..63 (the recorder owns 0..47), breakpoints park in the agent | `rust_frida.ObserveScript` |
| memory agent (`writeCas arm rearm disarm readback counters limit`) | `Session::write_cas`, `arm_watch`, `read_dr7` | `rust_frida.MemoryScript` |

## Differences, with the evidence for each

1. **`failure_modes_lose_the_producer_versus_a_clean_stop` (`test_trace_e2e.py`)**. After `taskkill` of the target, Frida
   reports `producer_state == "ended-without-final-counters"`; the Rust runtime reports `"final"`. Cause: Frida's producer
   (the CModule, its counters, its rings) lives inside the target and dies with it. Here the rings and counters live in a
   mapping the host owns, so after a kill the host still drains the rings and reads the counters; a dead process cannot
   count another hit, so they are final. The state names what arrived (the final counters), not how the target ended, and
   claiming "ended without final counters" with the final counters in hand would be the false statement. Everything else in
   that test is unchanged and holds on both: `verify.outcome == "clean"`, `producer.attempted > 100`, and for Rust
   `transport.batches_missing == 0`. The test now says so explicitly (`implementation()` picks the expected word); it is
   not skipped and not loosened for Frida. Not made to match Frida: that would mean discarding true counters.
2. **`entered` / `left`** (counters, release result). `entered` is the sum of kept hits at probes that want their return
   (`with_leave`); `left` is returned records plus frames abandoned by an unwind (`unreturned`). `entered - left` is what is
   still inside a stub **plus** any return record a full ring refused (Frida counts `left` in the stub even then). `busy` is
   always 0 (no stub bookkeeping to count threads inside).
3. **`rate_per_s`**: the sampler's smoothed hits/s per site (the same recurrence as the Frida policy), reported rounded.
   The sampler only owns sites 0..47; observe probes are never thinned by it.
4. **`stall_ticks`**: new per-ring counter in the agent (`R_STALL_TICKS`), converted to QPC ticks by the host.
5. **`threads` register context**: `GetThreadContext` on a thread suspended only for the read (pc, sp, rip, rsp, rbp, rax..r15),
   state from the kernel's thread table (`KTHREAD_STATE`/wait reason mapped to Frida's names). The agent's own control thread is
   reported without registers (it is never suspended).
6. **`trace_module`**: Frida is told by the loader. Here the recorder diffs the module list every sampling interval (25 ms by
   default), so a module mapped and unmapped between two looks is not seen. Load/unload of anything that lives longer is
   reported with the same fields.
7. **Observe/break payloads**: `context` carries `pc` and the argument registers (`rcx rdx r8 r9`), not all registers; no `sp`.
   `backtrace` is the agent's unwind (up to 15). Captures: the first plain pointer capture is read **in the agent at hit
   time**; the other captures (dereference chains, extra captures) are read by the host when the hit is drained, a few
   milliseconds later, so a buffer on a stack that has been reused by then can differ. `value_only` captures are exact. A
   register that is not an argument register answers `{"error": "no register ... on x64"}`. `break` does not also send a
   `return` event (the thread is parked at entry); after `limit` hits the site is thinned to one record in 2^20 so nothing
   parks and the hit counter stays exact.
8. **Memory agent**: the worker applies the fixture/authorization gate first; the Rust call uses the fixture gate, so the
   range must be non-executable data and the compare-and-swap is done by the host (`WriteProcessMemory` after a fresh read),
   not by an in-process write. A hardware watch is programmed by the host into every thread (including a thread the agent
   owns); `rearm` covers threads created later. Watch events carry `pc` only. Debug-register readback is a fresh
   `GetThreadContext` of every thread and is what turns a slot `clear`.
9. **Limits**: 16 observe/break probes at once (sites 48..63); a trace release (`detach_sites`) retires every site, probes
   included; trace `attempted` counts all sites, observe probes included, when both run together.

## Pure leaves of the Python runtime layer (`r/hy-rt2`)

| Python | Rust | Routing |
| --- | --- | --- |
| `runtime_decode.normalize/decode/decode_event/layout_values` | `decode.rs`, `hy-rt-py` `decode_*` | `HYDRALYSIS_IMPL=rust` and `HYDRALYSIS_RUNTIME_HELD=1` (0.37x to 0.63x; see PORT-STATUS.md) |
| `runtime_snapshot.compare/stable_sha256` | `snapshot.rs`, `hy-rt-py` `snapshot_compare/snapshot_stable_sha256` | `HYDRALYSIS_IMPL=rust` (2x to 10x faster) |

Both give the Python's bytes for the shapes a session produces. An input they do not model (a float where Python calls `int()`, a
struct field at a negative offset, an integer beyond 64 bits, a non-finite float, a mask with a `[` class, nesting deeper than 200,
a lone surrogate, a container where Python would call `str()`) raises `hydralysis_rt.Unmodelled` and the Python function answers, so a
`ValueError` text or a quirk is never reimplemented twice. The Python wrappers are `guarded` by a `Seam` over the helpers a white-box
test patches (`scalar`, `_unpack`, `canonical`, `_masked`, ...). Quirks kept on purpose: `normalize` returns the caller's `deref`
list object in Python and a copy in Rust; `normalize` accepts negative struct offsets in Python (the decode of one reads from the end
of the buffer) and the Rust declines to decode them; the `struct.error` text of a short buffer is reproduced
(`unpack_from requires a buffer of at least N bytes ...`). Not routed: `runtime_snapshot.flatten` (only used by the two routed
functions) and `snapshot_id` (0.3x).

`runtime_exports`, `runtime_authorize`, `runtime_ipc`, `runtime_events` (already routed) and the session classes
(`runtime_agents`, `runtime_worker`, `runtime_actions`, `runtime_capture`, `runtime_memory`, `runtime_trace`, `runtime`) were looked at and
not ported: each is a once-per-action check, a socket loop, or Frida RPC orchestration whose time is the target's or the RPC's. The
Rust agent already replaces the four JS templates that the Rust device recognises; the JS that remains (`runtime_agents.py`'s
CModule trace recorder when Frida is the device, the CONTROL helpers for Frida) is the Frida implementation itself and has no Rust
counterpart to be tested against, so it stays.

## What runs where

`cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` cover the Rust side (live tests spawn
`hy-fixture.exe`). The Python side: `tests/test_rust_runtime.py` (`ThroughTheWorker`, `ThroughTheAgent`, `Surface`), and the
existing suites run unchanged with `HYDRALYSIS_IMPL=rust`. The fake-binding suites (`test_runtime*.py` on `tests/fakefrida`)
do not go through the device, so the variable does not change what they test. The MCP suites that start a real worker process
(`test_mcp_runtime.py`, `CaptureOverMCP`, `TwoHarnessesOneGame`) put the fake binding in the worker's backend folder; since a
configured stand-in wins, they stay on the fake under `HYDRALYSIS_IMPL=rust` and test the transport, not the device. Their
Rust-device counterparts are `tests/test_rust_runtime.py` (`ThroughTheWorker`, `ThroughTheAgent`) and
`test_runtime_scenario_fixture.py`; `CaptureOverMCP`'s `hy-fixture.exe hits 5 FILE` branch is therefore no longer reached.
