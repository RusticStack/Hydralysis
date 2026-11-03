# Test map: old (Python / fakefrida) -> new (Rust)

Status after stages 2 and 3. The Python implementation and its tests stay in place until parity is proven. Rust
tests live in `crates/hy-runtime/tests/live.rs` (real processes, real agent DLL), `src/authorize.rs`,
`src/identity.rs`, `src/clock.rs`, `src/watch.rs` (unit) and `crates/hy-agent-proto/src/lib.rs` (wire format).
"Ported" means the case is re-expressed against the Rust runtime and passes; it does not mean the Python test was
removed. Counts are `def test_` per file.

## Ported (behavior re-expressed, passes)

| Old | Rust | Notes |
| --- | --- | --- |
| test_runtime_authorized.py::test_no_authorization_is_a_coded_refusal... (setting lookup) | authorize::tests::lookup_reports_why | message texts differ slightly; codes are identical |
| ...::test_an_entry_for_another_build_does_not_apply | authorize::tests::lookup_reports_why | |
| ...::test_an_address_outside_the_declared_range_is_refused | authorize::tests::normalizes_and_checks, live::cas_write_undo_and_refusals | |
| ...::test_a_size_over_the_authorization_is_refused | authorize::tests::normalizes_and_checks, watch_is_capped_at_the_hardware | |
| ...::test_an_action_not_listed_is_refused | authorize::tests::action_not_listed, live::cas_write_undo_and_refusals | |
| ...::test_executable_ranges_are_refused_even_when_declared | live::cas_write_undo_and_refusals (code page of the target) | |
| ...::test_a_watch_needs_a_stamp_... | authorize::tests::stamp_and_arch | the stamp predicate only; the file lookup stays in the client |
| ...::test_write_undo_and_diverged_inside_the_range | live::cas_write_undo_and_refusals | authorized + fixture gates |
| ...::test_a_watch_arms_and_disarms_to_verified_clear | live::disarm_reads_back_every_thread_and_clears | |
| ...::test_module_relative_ranges_follow_the_module_base | live::cas_write_undo_and_refusals | module + rva range |
| ...::test_normalize_accepts_and_rejects | authorize::tests::invalid_entries | |
| ...::test_pe_arch_and_bind_stamp | authorize::tests::stamp_and_arch | pe_arch only |
| test_runtime_write.py: CAS writes and logs / stale expectation / reason required / executable range / diverged undo / undo restores | live::cas_write_undo_and_refusals | |
| test_runtime_watch.py: arm, hit, thread coverage, disarm readback, state machine | live::watch_records_writes_from_old_and_new_threads_and_disarms_clean, live::disarm_reads_back..., watch::tests | hardware, no Frida |
| test_trace_e2e.py / test_trace_capture.py: argument and return capture on frameloop | live::args_and_return_capture | recorder only, no TRACE-1 encoder |
| ...: sampling with exact counted skips | live::sampling_counts_every_skip_exactly | |
| ...: stack walk | live::stack_walk_reports_the_caller | |
| test_runtime_capture.py: probe guards (module/base, export, prologue bytes) | live::guards_refuse_before_any_byte_is_written | five refusal codes |
| test_runtime.py / capture: export-named probe, buffer capture | live::export_hook_with_buffer_capture | KernelBase!WriteFile |
| capture: install while the target runs, retire | live::arm_and_retire_while_threads_run | |
| agent cost / ring reuse after thread exit | live::thread_exit_frees_the_ring_for_reuse | 300 threads, 64 rings |
| breakpoints, pause/continue | live::breakpoint_parks_until_continued | |
| 30 s breakpoint watchdog | live::watchdog_releases_a_parked_thread | limit is a parameter (250 ms in the test) |
| PID identity (OpenProcess + GetProcessTimes + QueryFullProcessImageNameW) | identity::tests, live::identity_follows_the_process | |
| timestamp calibration | clock::tests | |
| adaptive / fixed / exact sampling policy (runtime_agents.py `policy()`) | sampling::tests | pure logic, ported rule for rule |

## Not ported yet (still Python only)

| Old | Why | Needs |
| --- | --- | --- |
| test_runtime.py (41), test_runtime_capture.py (49), test_runtime_snapshot.py (25), test_runtime_decode.py (8), test_runtime_scenario_fixture.py (23) beyond the rows above | worker/tool-surface logic (actions, snapshot, decode, scenario) rides on the Python RuntimeAgent; fakefrida cases need a Rust trait double of `Session` | PyO3 surface in native/ (`HYDRALYSIS_IMPL=rust`) and the worker port |
| test_runtime_watch.py (33), test_runtime_write.py (19) remaining cases | gate construction from client settings, fixture marker in the file, detached-session handling, `undo` without id | client/worker layer |
| test_runtime_authorized.py::test_the_client_builds_the_gate..., ::test_the_fixture_conformance_flag... | client layer | client port |
| test_trace_capture.py (28), test_trace_gates*.py (53), test_trace_g2*.py (12), test_trace_extras.py (10) | need the TRACE-1 segment encoder/pump (h7 trace-pump lane) fed from `Session::drain` | h7 `trace.rs` integration |
| test_agent_cost.py (24) | measures the Frida agent (JS/CModule sizes, install ms); replaced by `hy-bench` | -- |
| tools/watch_conformance.py | drives the Python worker | port with the client |
| sealed mailbox / HMAC IPC, event-log hash chain, TRACE-1 canonical JSON | storage/IPC lanes (hy-store) | hy-store crates |

## Live scenarios on the Rust device (`tests/test_rust_runtime_live.py`, `r/hy-rt2`)

The claims below were only tested on the Frida stand-in (it wins the device selection in the MCP suites). They now run against
`hy-fixture.exe` (new modes `patched FILE` and `env FILE`; `info` also prints `SPARE`/`SPAREBYTES`).

| Claim | Frida stand-in test | Rust-device test |
| --- | --- | --- |
| a live detour is reported with file bytes and patcher | `test_mcp_runtime.PatchedFunctionOverMCP.test_live_patch_is_reported...` | `Agent.test_a_live_detour_is_reported...`, `MCP.test_live_patch_is_reported_over_mcp` |
| probe past a detour only with `accept_patch` and the original prologue | `PatchedFunctionOverMCP.test_probe_past_a_detour...` | `Agent.test_a_probe_past_a_detour_needs...`, `Agent.test_the_probe_past_a_detour_fires_through_it`, `MCP.test_probe_past_a_detour_only_with_accept_patch_over_mcp` |
| cwd and env of a spawned session, worker-only variables restored | `RuntimeOverMCP.test_spawn_session_lifecycle_honours_cwd_and_env` | `Agent.test_spawn_honours_cwd_and_env...`, `Agent.test_spawn_without_cwd...`, `MCP.test_spawn_honours_cwd_and_env` |
| the second harness reads, cannot drive, detach or attach | `TwoHarnessesOneGame.test_the_second_harness_reads...` | `MCP.test_the_second_harness_reads_but_cannot_drive_or_attach` |
| captured arguments decoded (values, names, registers, unreadable pointers) | `test_runtime_decode` (decoder only) | `Agent.test_captured_arguments_are_decoded_in_the_worker`, `Agent.test_an_unreadable_pointer...` |
| sample window of a numeric capture | (none) | `Agent.test_a_numeric_capture_is_sampled_over_a_window`, `Agent.test_the_sample_option_is_validated` |

The `MCP` class starts the real stdio server with `HYDRALYSIS_IMPL=rust` and a `frida` directory that is not a stand-in, so the worker
takes the Rust device. Differential tests of the two ported leaves: `tests/test_rust_parity_runtime.py`.

## Stage 4: the PyO3 surface (`HYDRALYSIS_IMPL=rust`)

`hy-py` builds `hydralysis_rt` (a PyO3 module over `Session`); `src/hydralysis/rust_frida.py` answers the Frida-shaped calls the
runtime layer makes (`spawn`, `attach`, `resume`, `create_script`, `exports_sync`, `post`), and `runtime_device.get_local_device()`
picks it when the variable says `rust` and no Frida stand-in is configured (a `frida` package declaring `HYDRALYSIS_STAND_IN`, i.e. tests/fakefrida, keeps the Frida-shaped device; `tests/test_runtime_device.py` asserts both directions). The default stays Frida. Served (stage 5): the CONTROL script (with thread states and
registers), the TRACE recorder (arming through the mailbox, wire batches with the acknowledgement window, counters incl.
`entered`/`left`/`rate_per_s`/`stall_ticks`, sampling, release, `trace_module` from the loader's notifications), the observe/break
probe and the memory agent (CAS write, hardware watch with DR7 readback). Differences are in PORTING.md.

Run with `HYDRALYSIS_IMPL=rust` and the pyd on `PYTHONPATH` (or `HYDRALYSIS_RT_PYD`), agent DLL at `HYDRALYSIS_AGENT_DLL`:

| Python test | Result under the Rust runtime | Note |
| --- | --- | --- |
| test_trace_e2e.py (13): frameloop, trace_app, interleave, veh_freeze, deadlock watchdog, exact, thinned, overflow, restart, kill-writer, etw, attach-to-nothing, ingest by hydra-trace | 13 pass | the real worker, TRACE-1 encoder, `hydra-trace` ingest and symbolization |
| test_trace_e2e.py::test_failure_modes_lose_the_producer_versus_a_clean_stop | passes with an explicit expectation | after a kill Frida says `ended-without-final-counters`, the Rust runtime says `final` (the counters live in the host's mapping). The test names the implementation for that one word; see PORTING.md, difference 1 |
| test_runtime_capture.py (49) | 49 pass | `CaptureOverMCP.test_capture_window_snapshot_and_compare_end_to_end` runs a real probe on `hy-fixture.exe hits 5 FILE` instead of the fake binding's invented hits; same assertions (5 seen, 3 recorded, partial coverage, snapshot, compare, verify) |
| test_mcp_runtime.py (15) | pass, unchanged, on the fake binding | real worker process with tests/fakefrida in its backend folder: the stand-in wins over the variable, so these test the MCP transport. Rust-device equivalents: test_rust_runtime `ThroughTheWorker`/`ThroughTheAgent`, test_runtime_scenario_fixture |
| tests/test_runtime_device.py (4) | pass | the selection rule, both directions, in fresh interpreters |
| test_runtime, _snapshot, _write, _watch, _authorized, _decode (141) | pass, unchanged | fake-binding suites: they do not reach the device, the variable does not change what they test |
| tests/test_rust_runtime.py | `ThroughTheWorker` (trace through the worker, incl. `trace_module`, `entered`/`left`, `rate_per_s`), `ThroughTheAgent` (real `RuntimeAgent` on `hy-fixture.exe`: thread state and registers, observe enter/return/limit/counters, wrong prologue refused, break parks until continue, CAS write/undo/DIVERGED, watch arm/readback/disarm clear, watch from old and new threads), `Surface` (the PyO3 calls) | the memory and probe templates are exercised through the worker, not only through `RtSession` |
| tests/test_trace_gates*.py, test_trace_g2_live.py | rust, hydra.6 engine: gates 10 ok, gates3 6 ok, g2_live 3 ok (1 skip), gates4 37 run, 32 ok; the 5 errors are IHangDumps, where the available hydra-trace.exe has no `dump` subcommand (environment, same under unset) | need the trace engine (`HYDRALYSIS_INTEGRATION_ENGINE`/`_CLIENT`, `HYDRA_TRACE_EXE`) |

