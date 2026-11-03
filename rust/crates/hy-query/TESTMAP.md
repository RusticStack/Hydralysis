# hy-query test map (old Python test -> new test)

Classification: **BB** black-box (runs unchanged against `HYDRALYSIS_IMPL=rust`), **WB** white-box (re-expressed in
Rust with the same cases), **PAR** new differential test, **TODO** not yet ported (slice not started).

Status of this lane slice: PE side only (hy-pe, hy-disasm, PE tool bodies, prologue). The engine-facing parts
(query.py, analysis.py, export_worker, exporting, crossbuild, doctor, backends, client, proc, decompile_*) are
TODO; their tests are listed so nothing is silently dropped.

## tests/test_pe.py (WB: patches `Path.read_bytes` and builds `Image` from Python bytes)

| Python test | Rust test (`crates/hy-query/tests/ported.rs`) |
|---|---|
| FileBackedReads.test_string_search_returns_full_string_start_and_wide_text | string_search_returns_full_string_start_and_wide_text |
| FileBackedReads.test_virtual_tail_does_not_alias_next_section | virtual_tail_does_not_alias_next_section |
| FileBackedReads.test_truncated_file_and_negative_reads_are_refused | truncated_file_and_negative_reads_are_refused |
| FileBackedReads.test_disassembly_at_section_end_uses_available_bytes | disassembly_at_section_end_uses_available_bytes |
| FileBackedReads.test_other_pe_architecture_is_not_silently_decoded_as_x64 | other_pe_architecture_is_not_silently_decoded_as_x64 |
| ProvenanceAndCandidates.test_header_keeps_full_build_hash | header_keeps_full_build_hash |
| ProvenanceAndCandidates.test_pefile_nested_resource_groups_supply_file_version | n/a: tests a pefile object shape (`FileInfo` nesting); replaced by the PAR file_version comparison (header carries `version ...`) over real PEs |
| ProvenanceAndCandidates.test_wrapper_indicator_is_a_warning_not_a_packed_verdict | wrapper_indicator_is_a_warning_not_a_packed_verdict |
| ProvenanceAndCandidates.test_callees_does_not_decode_e8_inside_an_immediate | callees_does_not_decode_e8_inside_an_immediate |
| ProvenanceAndCandidates.test_last_possible_call_site_is_included_and_labelled_candidate | last_possible_call_site_is_included_and_labelled_candidate |
| SignatureVerification.test_all_wildcards_cannot_validate_a_hook | all_wildcards_cannot_validate_a_hook |
| SignatureVerification.test_anchored_search_handles_edges_overlap_and_limits | anchored_search_handles_edges_overlap_and_limits |

## tests/test_prologue_table.py (WB: Mock image)

| Python test | Rust test |
|---|---|
| test_common_hook_table_forms_normalize_to_the_same_bytes | common_hook_table_forms_normalize_to_the_same_bytes |
| test_wildcards_are_whole_bytes_and_need_a_literal | wildcards_are_whole_bytes_and_need_a_literal |
| test_twenty_one_rows_share_one_build_fingerprint | twenty_one_rows_share_one_build_fingerprint (the Mock call-count assertions are not expressible; the fingerprint is a `OnceLock`, computed once by construction) |
| test_mismatch_is_retained_among_all_results | mismatch_is_retained_among_all_results |
| test_a_row_may_accept_several_prologues_and_names_the_one_that_matched | a_row_may_accept_several_prologues_and_names_the_one_that_matched |
| test_envelope_image_base_makes_legacy_offsets_unambiguous | TODO (tests `cli._checks_file`, CLI lane) |
| test_all_rows_validate_before_any_bytes_are_read | all_rows_validate_before_any_bytes_are_read (the "read_rva not called" assertion is structural: validation is a separate first pass) |
| test_file_backed_boundary_is_checked_before_reads | file_backed_boundary_is_checked_before_reads |
| test_total_byte_budget_and_row_budget | total_byte_budget_and_row_budget |

## PAR: tests/test_rust_parity.py (python vs rust, byte for byte)

Real x64 and 32-bit system PEs plus the synthetic image: header, fingerprint, sections, imports (limit/pattern),
exports, strings, sigscan, disasm, callees, callers, xrefs, inspect, function_of, string_at, read_rva,
rva_to_offset, available, loaded_bytes (relocations applied), parse_expect, find_pattern, parse_rva; exceptions are
compared by type and message.

## Stage 2: pure-logic ports (decompile_result.py, analysis.validate_options)

| Python test | Class | Status |
|---|---|---|
| test_decompile_partial.py (15) | BB | passes unchanged with `HYDRALYSIS_IMPL=rust` (merge/summarize/coverage/from_error run in Rust) |
| test_decompile_e2e.py (13) | BB | passes unchanged with `HYDRALYSIS_IMPL=rust` |
| test_analysis.py (18) | BB | passes unchanged with `HYDRALYSIS_IMPL=rust` (validate_options in Rust except the documented fallbacks) |
| test_output_size.py (15, 2 skipped) | BB | passes unchanged with `HYDRALYSIS_IMPL=rust` (does not exercise the ported code much) |
| test_query_script.py (9) | BB | passes unchanged with `HYDRALYSIS_IMPL=rust` |
| test_query.py | BB | runs past a 40 s cap under both implementations here (threads / engine stand-ins); not completed in either, so no claim |
| new: tests/test_rust_parity_logic.py | PAR | about 100 hand-written option cases, 1500 seeded random mutations, 700 random replies/merges: Python and Rust agree on value or exception type+message |
| new: crates/hy-query/tests/logic.rs | WB | Rust cases for py_int0, summarize/coverage/limitations/merge/from_error and option validation |

`validate_options` returns `Invalid::Fallback` (Python implementation runs) for: `diff`, batch `file`, `import_types`,
`import_archive`, `scan` with `regex` (Python `re` decides compile errors), an unhashable `kind`, and a function range
wider than 128 bits.

## Stage 3: export, crossbuild, client, proc

| Python test | Class | Status |
|---|---|---|
| test_client.py (28) except ImportSlots | BB | passes unchanged with `HYDRALYSIS_IMPL=rust` (the Client methods run in `hy-query::client` over `api.call`) |
| test_client.py::ImportSlots | WB (patches the pefile object) | re-expressed as `each_import_names_its_iat_slot_and_a_pattern_filters` in tests/ported.rs; it fails under `HYDRALYSIS_IMPL=rust` by construction (nothing to patch), so it is excluded from rust-mode runs |
| test_proc.py (5) | BB | passes unchanged with `HYDRALYSIS_IMPL=rust` (identity/stop/terminate_tree in Rust; spawn + reaper stay Python) |
| test_crossbuild.py (18) | BB | passes unchanged with `HYDRALYSIS_IMPL=rust` (`match` in Rust) |
| test_exporting.py (40) | BB | slow (4-5 min). Python: 1 failure (`test_job_json_is_not_rewritten_for_every_row`, a timing assertion); Rust mode: the same 1 failure when rerun alone. A first full rust run also failed `test_cancel_latency_is_one_bounded_query` while the machine was compiling; it passes on rerun together with the Python-baseline failure above |
| test_export_worker.py | does not exist in the repo (the export worker is covered by test_exporting.py and test_engine_export.py) | n/a |
| new: tests/test_rust_parity_export.py | PAR | replay (21 file shapes + 3000-row parallel file), body_hash on a PE, decompile_row/partial/keys_sha256/parity, 60 random crossbuild.match builds in dict order |
| new: tests/test_rust_parity_client.py | PAR | scripted dispatch through both Clients: answers, exception type/message/result/__cause__, exact calls and argument order, 450-row paging with mismatches |
| new: crates/hy-query/src/proc.rs unit tests | WB | identity tolerance and stop on a real child (Windows) |

## Not yet ported (blocked or TODO)

QueryRunner/open_program (query.py), backends.py, doctor.py, decompile_job.py, the `exporting.start/normalized/provenance`
job orchestration and `export_worker.run` (they use `locks`, `workcopy`, `targets`, `preparation` and `hydra.Engine`);
their tests (test_query, test_backends, test_doctor, test_exporting's job tests, test_cli query verbs, test_engine_*)
stay Python-only and are unchanged.

## Stage 3: backends and doctor leaves (`system.rs`)

| Python | Rust | Test |
|---|---|---|
| `backends._properties`, `_children`, `_native_compatible`, `_machine` | `system::properties/children/native_compatible/machine` | `tests/system.rs`; parity `tests/test_rust_parity_system.py` |
| `doctor._read_json`, `_instances`, `_dir_size`, `_count_key` | `system::read_json_object/instances/dir_size/count_key` | same |
| `tests/test_backends.py`, `tests/test_doctor.py` | black-box, unchanged | pass under `HYDRALYSIS_IMPL=python` and `rust` (14 + 14 each) |

Not ported (stay Python, they sit on `hydra`, `durable`, `locks`, `urllib`, `zipfile`, daemon probes): `backends.inspect/resolved/_stamp/ensure/_download/_extract/_ignored/_engine_candidates/_client_candidates`, `read_json/write_json`, and all `doctor` sections and `diagnose/handle`. `backends.sha256` is covered by `export::sha256_file`.

## Stage 4: the engine-facing core of query.py (`session.rs`) and `decompile_job.rs`

The engine client is the `session::Engine` trait (`key`, `call(command, fields)`, `supports`), so everything below runs
against a fake in Rust. The process-wide globals of query.py (`_keys`, `_opening`, `_in_use`, `_held`, `_lanes`) are one
`session::Registry`; `_holding()` is the RAII guard `Registry::holding()`.

| Python test (tests/test_query.py unless noted) | Rust test (`tests/session.rs`) |
|---|---|
| ClientCap.test_a_fifth_view_closes_the_least_recently_used_read_only_program | a_fifth_view_closes_the_least_recently_used_read_only_program |
| ClientCap.test_a_writable_program_is_never_closed_and_the_refusal_stands_when_nothing_read_only_is_left | same name |
| ClientCap.test_another_busy_is_not_taken_for_the_cap | another_busy_is_not_taken_for_the_cap |
| ProgramsInUse.test_a_program_a_read_is_using_is_not_closed_for_the_cap | same name |
| ProgramsInUse.test_the_marks_end_with_the_read | same name |
| ProgramsInUse.test_when_every_read_only_program_is_in_use_the_least_recently_used_is_closed_as_before | same name |
| ProgramsInUse.test_a_read_holds_its_program_from_the_moment_the_open_hands_it_out | same name |
| ProgramsInUse.test_threads_opening_one_program_send_one_open | same name |
| ProgramsInUse.test_threads_waiting_on_a_refused_open_take_its_refusal_instead_of_waiting_again | same name |
| ProgramsInUse.test_a_refresh_opens_again_after_the_gate | same name |
| test_decompile_e2e.Fallback.test_a_script_failure_is_deferred_to_a_job_unless_inline | same name |
| test_decompile_e2e.Fallback.test_inline_the_engine_command_runs_with_a_long_timeout_and_is_labelled | same name |
| test_decompile_e2e.Fallback.test_explicit_options_reach_the_engine_and_a_slow_answer_defers | same name |
| test_decompile_partial.test_the_command_is_asked_only_when_needed_and_a_refusal_keeps_the_script_answer | same name |
| test_decompile_e2e.Fallback.test_scripted_* (3) | TODO: they test `QueryRunner._scripted` (QueryRunner is not ported) |
| test_decompile_e2e.Job.test_the_worker_runs_the_query_inline_and_stores_the_labelled_result | `tests/decompile_job.rs` same name |
| test_decompile_e2e.Job.test_a_worker_failure_is_recorded | `tests/decompile_job.rs` same name |
| test_decompile_e2e.Job.test_the_cli_follows_a_job_to_its_result | n/a: tests `cli._await_decompile_job` (CLI lane); runs unchanged |
| new (no Python test): wrong build message, cache-key spelling, forget/drop_program/forget_role/drop_rows_under, reader_lanes/readers, accepted/public, run_script (last JSON line, quick lane, truncated, large request file), splitlines, `int()` of `max_characters`; job id validation, interrupted worker, log tail, reuse of a running job | `tests/session.rs`, `tests/decompile_job.rs` |
| new: tests/test_rust_parity_session.py | PAR: `accepted`, `_public`, `reader_lanes`, `engine_decompile` (10 engine behaviours x 10 requests x 9 responses x inline, plus 300 seeded random option mutations), `decompile_job.job_path`, Windows path spelling vs `PureWindowsPath` |

Selection: `HYDRALYSIS_IMPL=rust` routes `query.accepted`, `query._public`, `query.reader_lanes`,
`query.engine_decompile` and `decompile_job.job_path` through PyO3 (`native/src/session.rs`; the Python engine object is
adapted to the trait, a non-EngineError exception it raises propagates unchanged). **`open_program` and its cache stay
Python in both modes**: `query._keys` / `_in_use` / `_opening` are read and cleared by many Python callers and tests
(`forget`, `_drop_program`, `workcopy`, `views`), so a second copy of the state in Rust would split the cache. The Rust
`Registry::open_program` is complete and tested, ready for the day those callers move.

Not ported: `QueryRunner` (reader/pool/route/register/lineage/views/commit/queue/status/stop: they sit on `targets`,
`lineage`, `viewgov`, `views`, `workcopy`, `hydra.Registry` and threads) and the process launch of `decompile_job.start`
(only its dedupe, record and status/run logic are ported, over `Store`/`Processes` traits), `exporting.start/normalized`
and `export_worker.run`.

## PORTING note: quirks kept (stage 4)

- `windows_path` is `str(Path(gpr)).lower()` for drive paths and plain `\server\share` UNC. Exotic UNC spellings
  (`//srv`, `///x`, `//srv//share`) are not modelled (Python keeps odd root forms); no `.gpr` path has them.
- Cache key `(connection, lowercased project path, program, writable)`; a cache hit moves the row to the end (LRU), a
  refresh does not move an existing row; a writable row is never evicted.
- A waiter on an open in flight takes the opener's row or refusal; with `refresh` it opens again itself. An opener that
  panics wakes its waiters, who then open themselves (Python: an interrupted opener).
- The `sha256` check lowercases the engine's value but not the caller's.
- `run_script` takes the last output line starting with `{` using Python `splitlines` boundaries (`py_splitlines`), sends
  the request through Python `json.dumps` spacing, and a missing `output` reads as `''` while a null one reads as `None`.
- `engine_decompile`: `int(options["max_characters"])` follows Python `int()`: floats truncate, bools are 0/1, numeric
  strings parse, `None`/list/dict raise `TypeError`, a malformed string raises `ValueError`; an integer past 64 bits or a
  non-ASCII digit string is `Unsupported` and the Python original answers. An unchanged answer is returned as the very
  same object by the Python wrapper (`assertIs` in the tests). `engine_s` is rounded to 0.1 s.
- `accepted` in Rust mode builds a new dict; the Python original also annotates its argument in place.
- `decompile_job.run` serialises its record updates with a mutex (the Python worker's tick thread and main thread could
  interleave a read-modify-write); the stage text and the final states are otherwise identical.
- Engine errors from Rust-built `EngineError::new` carry a minimal `str()` JSON (`engine_error`, `message`, `command`); the
  PyO3 adapter passes the Python exception's own `str()`.

## Static read plane (lane r/hy-static)

| Python test | Class | Status |
|---|---|---|
| test_query.py (83) | BB | passes with `HYDRALYSIS_IMPL` unset (217 s) and `=rust` (234 s); the engine stand-ins are not real projects, so the plane declines and the engine path answers |
| new: tests/test_static_plane.py (7) | PAR | xrefs of 61 addresses equal the Java oracle through `QueryRunner` with no engine call; paging; engine fallback for function/functions/decompile, a program not in the index, overlays, no switch |
| new: rust/crates/hy-static/tests/oracle_diff.rs (12) | PAR | Java oracle: references to/from, functions, symbols; PE image for bytes; JSON entry point |
| benchmarks/static_plane.py | PAR | real engine: 200 xrefs queries, rows equal |
