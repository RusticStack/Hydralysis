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

## Not yet ported (TODO, black-box unless noted)

test_query.py, test_query_script.py, test_exporting.py, test_export_worker.py, test_crossbuild.py, test_doctor.py,
test_backends.py, test_decompile_e2e.py, test_decompile_partial.py, test_output_size.py, test_cli.py (query verbs),
test_client.py, test_proc.py, test_analysis.py, test_engine_* (real engine; run with HYDRALYSIS_IMPL=rust once the
query/export crates exist), test_sigscan (no such file; covered in test_pe/test_prologue_table).
