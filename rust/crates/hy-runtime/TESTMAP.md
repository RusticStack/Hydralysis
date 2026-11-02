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
| test_trace_e2e.py (13), test_trace_g2_live.py (3) | black-box through the tool surface | PyO3 surface |
| test_agent_cost.py (24) | measures the Frida agent (JS/CModule sizes, install ms); replaced by `hy-bench` | -- |
| tools/watch_conformance.py | drives the Python worker | port with the client |
| sealed mailbox / HMAC IPC, event-log hash chain, TRACE-1 canonical JSON | storage/IPC lanes (hy-store) | hy-store crates |
