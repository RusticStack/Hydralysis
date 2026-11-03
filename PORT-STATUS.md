# Hydralysis Python to Rust: port status (branch r/hy-py2rs, from h7/integration 91c528b)

Python stays the default and the specification. The Rust path is selected with `HYDRALYSIS_IMPL=rust`
(plus `HYDRALYSIS_NATIVE=0` to switch the trace routing off). Sizes are bytes of `src/hydralysis/*.py` (1.94 MB in total).
"Hot" means CPU or memory in a real run (an MCP session, a trace capture, a runtime session), judged from the call graph and from
the measurements recorded by the earlier lanes; it was not profiled module by module.

## What is already Rust (routed, in h7/integration)

| Area | Modules | Rust |
|---|---|---|
| Storage and logs | durable, backups, evidence, evidence_bundle (via `_rust_*`), lineage, storelog, backends leaves, localio | hy-core, hy-store |
| Client and engine IPC | client, engine_client (default `hydralysis_native.Session`), query, api (`hyapi`) | hy-query, hy-engine, native |
| Views | views, viewnative, viewgov, revisions, locks (hy-views), commits (disk level) | hy-views |
| Static read plane | staticplane | hy-static |
| Engine leaves | address_maps, red4ext, integrity, analysis (option validation), decompile_result, decompile_job, crossbuild, exporting, export_worker, pe, proc, doctor | hy-engine, hy-pe, native |
| Trace | trace_pump/capture/wire (segment encoder, pump), trace_keys, trace_hashes, trace_schema, trace_watchdog, trace_canon pieces | hy-trace, native/src/trace |
| Trace, ported but held back (measured no faster) | trace_reports, trace.shape | hy-trace |
| Runtime | runtime_device, runtime_events, rust_frida (Rust Frida-shaped device) | hy-runtime, hy-rt-py |

In flight on other lanes (not duplicated here): `r/hy-workcopy` (workcopy file stores, userscripts options/choose/list/stage,
viewpool; its own benchmark says the hosted edit path is slower and stays opt-in), `r/hy-static` (static plane cache),
`r/hy-parityfix` (43 rust-mode failures).

## Ported on this branch

| Module | Rust | Routing | Result |
|---|---|---|---|
| `trace_pairing.pair_report` | `hy-trace::pairing`, `native/src/trace/pairing.rs` | on with `HYDRALYSIS_IMPL=rust` | 5x to 36x faster, byte-identical |
| `trace_bindings.link_events` | `hy-trace::bindings`, `native/src/trace/bindings.rs` | held back (`HYDRALYSIS_TRACE_HELD=1`) | 0.6x at 5k events, 1.5x at 300k, 2x memory: opt-in only |
| `runtime_snapshot.compare`, `.stable_sha256` | `hy-runtime::snapshot`, `hy-rt-py` (`snapshot_compare`, `snapshot_stable_sha256`) | on with `HYDRALYSIS_IMPL=rust` | 2.5x to 3.4x (compare), 2.2x to 10x (stable hash; two runs: 2.1x-5.3x / 3.5x-4.6x, the machine was shared); +4 MB at 200 regions, +50 to +100 MB at 5000 regions |
| `runtime_decode.normalize`, `.decode`, `.decode_event`, `.layout_values` | `hy-runtime::decode`, `hy-rt-py` (`decode_*`) | held back (`HYDRALYSIS_RUNTIME_HELD=1` as well as `HYDRALYSIS_IMPL=rust`) | 0.37x to 0.63x (first run 0.33x-0.57x): a few microseconds of work per call, the argument and answer conversion costs more; opt-in only |

Measurements for the two `runtime_*` rows: `benchmarks/bench_runtime_decode.py` (same method as `bench_trace_ports.py`: fresh child process
per row, median of 5, peak working set, input built before the timer, answers compared by digest); logs
`E:\Projects\Hydra\_logs\h7\rt2\bench-decode.log` and `bench-snapshot.log`, `bench-final.log`. Unrouted in `runtime_snapshot`: `flatten` (only called by the two routed
functions) and `snapshot_id` (0.3x: `json`'s C encoder beats the conversion).

Measurements (`benchmarks/bench_trace_ports.py`, release build, median of 5, fresh child process per row, peak working set
from `GetProcessMemoryInfo`; the input is built before the timer and is the same in both children; log
`E:\Projects\Hydra\_logs\h7\py2rs\bench4.log`; a machine with other lanes running, so read ratios, not absolute times):

| function | size | Python ms / MB | Rust ms / MB | ratio |
|---|---|---|---|---|
| pair_report | 2k events | 9.4 / 30.0 | 1.8 / 31.1 | 5.3x |
| pair_report | 20k | 342 / 42 | 26 / 51 | 13x |
| pair_report | 100k | 7774 / 90 | 216 / 126 | 36x (+36 MB) |
| link_events | 5k | 2.9 / 31.5 | 4.9 / 35.7 | 0.59x |
| link_events | 50k | 91 / 54 | 60 / 82 | 1.5x |
| link_events | 300k | 823 / 194 | 551 / 402 | 1.5x (2x memory) |

`pair_report` wins because the Python scans the owner values once per mirror event (quadratic); the Rust bisects the sorted
owner events (same answer). `link_events` is linear in both; the Rust spends its time copying events out of Python, so it is held back.

## Remaining, ranked by hot-path relevance (not ported)

1. (after `r/hy-rt2`: `runtime_decode` and the pure part of `runtime_snapshot` are ported, see above; the Rust runtime device now has
   live tests for detours/`accept_patch`, decoded captures and samples, cwd/env and the second-harness rule:
   `tests/test_rust_runtime_live.py`.) `runtime_agents.py` (62k), `runtime.py` (48k), `runtime_memory.py` (32k), `runtime_capture.py` (31k),
   `runtime_worker.py` (28k), `runtime_trace.py` (26k), `runtime_actions.py` (20k): the live Frida session code. Event-handling hot path of a runtime
   session, but it is dominated by Frida RPC and the JS agent; hy-runtime/hy-rt-py already cover the event decode and the device.
   The Frida JS agent (`runtime_agents`) is allowed to be converted; that is a separate, larger lane.
2. `workcopy.py` (91k), `userscripts.py` (17k), `viewpool.py` (19k): on `r/hy-workcopy`. `userscripts.run`, `workcopy._sync/_apply`
   are engine-IPC orchestration (heal, save, submit): their time is the engine's, so a Rust port moves no CPU or memory; the lane's
   measurement of the hosted Rust path was 1.9x the CPU of Python.
3. `hydra.py` (86k), `commits.py` (99k), `views.py` (139k): large, but their leaves are already routed (see above); what remains is
   orchestration around those calls.
4. `trace.py` (63k), `trace_reports.py` (29k): command dispatch and report builders; reports ported and held back.
5. Cold tooling, none on a request path: `annotations.py` (bundle export/import, engine-bound), `trace_corpus_diff.py` (used only by
   tests; no `src` caller), `trace_footprint.py` (file hashing: hashlib already C), `trace_dumps.py` (subprocess), `trace_etw.py`,
   `environment.py`, `preparation*.py`, `workflow_help.py`, `mcp.py`, `cli.py`, `paths.py`, `targets.py`.

## Must stay Python

C, C++ and Sleigh (the decompiler and the Ghidra analysis core) are not in this repository's scope. The Frida JS agent may be converted
but needs a Frida-side runtime; not attempted. Test fakes (`tests/fake*.py`) and the Frida stand-in stay Python.
