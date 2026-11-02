# Test map: lineage, backups, runtime_events, config (lane "lineage" of R-hy-storage)

Classification: **WB** = white-box (re-expressed as a Rust test with the same cases), **BB** = black-box (passes
unchanged against `HYDRALYSIS_IMPL=rust` through the public Python surface once the PyO3 layer is wired; nothing to
port), **N/A** = cannot occur in Rust by construction (reason given), **PENDING** = not yet covered (listed honestly).
Rust tests live in `rust/crates/hy-store/tests/`.

## tests/test_lineage.py

| Python test | Class | Rust test |
|---|---|---|
| SharedVector.test_the_copy_is_byte_identical_to_the_engine_vector | WB | lineage_manifest::the_copy_is_byte_identical_to_the_engine_vector |
| SharedVector.test_lineage_reproduces_the_engine_hashes | WB | lineage_manifest::lineage_reproduces_the_engine_hashes |
| SharedVector.test_the_engine_vector_holds_the_awkward_paths_of_the_spec | WB | lineage_manifest::the_engine_vector_holds_the_awkward_paths_of_the_spec |
| CanonicalForm.test_the_fixed_vector_is_reproduced_byte_for_byte | WB | lineage_manifest::the_fixed_vector_is_reproduced_byte_for_byte |
| CanonicalForm.test_the_vector_holds_the_awkward_paths_of_the_spec | WB | lineage_manifest::the_vector_holds_the_awkward_paths_of_the_spec |
| CanonicalForm.test_what_is_escaped_and_what_is_not | WB | lineage_manifest::what_is_escaped_and_what_is_not |
| CanonicalForm.test_keys_sort_by_code_point_and_there_is_no_whitespace | WB | lineage_manifest::keys_sort_by_code_point_and_there_is_no_whitespace |
| CanonicalForm.test_an_unpaired_surrogate_is_refused_in_a_manifest | N/A | a `serde_json::Value` / Rust `str` cannot hold a lone surrogate; the PyO3 layer must raise `UnicodeEncodeError` when converting a Python object (to do in the binding) |
| CanonicalForm.test_nan_is_refused | N/A (+WB) | lineage_manifest::nan_cannot_enter_a_value (`Number::from_f64(NAN)` is None); binding raises `ValueError` |
| Manifests.test_a_written_manifest_verifies_and_hides_nothing | WB | lineage_manifest::a_written_manifest_verifies_and_hides_nothing |
| Manifests.test_sealing_changes_neither_the_sidecar_hash_nor_the_verification | WB | lineage_manifest::sealing_changes_neither_the_sidecar_hash_nor_the_verification |
| Manifests.test_a_changed_missing_or_added_file_is_tampering | WB | lineage_manifest::a_changed_missing_or_added_file_is_tampering |
| Manifests.test_an_edited_manifest_fails_its_self_hash | WB | lineage_manifest::an_edited_manifest_fails_its_self_hash |
| Manifests.test_a_folder_without_a_manifest_is_invisible | WB | lineage_manifest::a_folder_without_a_manifest_is_invisible |
| Manifests.test_a_newer_manifest_format_is_refused_not_guessed | WB | lineage_manifest::a_newer_manifest_format_is_refused_not_guessed |
| Manifests.test_the_tree_hash_ignores_locks_and_the_manifest_but_not_content | WB | lineage_manifest::the_tree_hash_ignores_locks_and_the_manifest_but_not_content |
| Log.test_creation_is_idempotent_and_generation_zero_is_the_adopted_project | WB | lineage_log::creation_is_idempotent_and_generation_zero_is_the_adopted_project |
| Log.test_lines_chain_by_the_hash_of_the_previous_valid_line | WB | lineage_log::lines_chain_by_the_hash_of_the_previous_valid_line |
| Log.test_a_target_with_a_lineage_resolves_to_the_head_and_keeps_its_key | WB (resolve) + BB (registry assertions: `targets.py` is not ported by this lane) | lineage_log::a_target_with_a_lineage_resolves_to_the_head_and_keeps_its_key |
| Log.test_a_target_without_a_lineage_resolves_exactly_as_before | BB (`targets.resolve` is not this lane's) | `lineage_log::a_target_with_a_lineage_resolves...` covers `lineage.resolve({})` |
| Log.test_configuration_targets_are_not_given_a_lineage_by_the_cache | WB (registry hook) + BB | lineage_log::configuration_targets_are_not_given_a_lineage_by_the_cache, lineage_log::the_registry_mirror_is_written_once_and_only_for_a_registered_target |
| Log.test_generation_numbers_are_never_reused | WB | lineage_log::generation_numbers_are_never_reused |
| Log.test_invalid_ids_are_refused | WB | lineage_log::invalid_ids_are_refused |
| TwoProcessTornTail.test_a_long_lived_writer_appends_again_after_a_killed_writer_left_a_fragment | WB (child = this test binary, fault `log.torn_append:torn:30`, exit 137) | lineage_log::a_long_lived_writer_appends_again_after_a_killed_writer_left_a_fragment |

Added (no Python twin as a unit test; exercised through test_commit / test_doctor there): lineage_log::head_reports_a_torn_tail_and_a_missing_log,
verify_head_and_tampered_see_a_written_generation, the_tamper_cache_answers_while_the_folder_is_unchanged, status_without_and_with_a_lineage.

## tests/test_backups.py

| Python test | Class | Rust test (backups_make.rs unless noted) |
|---|---|---|
| Backups.test_a_backup_is_a_verified_sealed_copy_with_backup_json_written_last | WB | a_backup_is_a_verified_sealed_copy_with_backup_json_written_last |
| Backups.test_the_python_manifest_lists_what_the_engine_gate_checks_raw_sizes_and_no_sidecar | WB | the_manifest_lists_what_the_engine_gate_checks_raw_sizes_and_no_sidecar |
| Backups.test_an_unlisted_sidecar_is_not_an_unlisted_file | WB | an_unlisted_sidecar_is_not_an_unlisted_file |
| Backups.test_the_fork_is_not_writable | WB | the_fork_is_not_writable |
| Backups.test_backups_log_records_each_copy | WB | backups_log_records_each_copy |
| Backups.test_a_backup_never_overwrites_and_a_retry_in_the_same_second_gets_its_own_folder | WB | a_backup_never_overwrites_and_a_retry_in_the_same_second_gets_its_own_folder |
| Backups.test_a_copy_that_does_not_match_its_source_writes_no_manifest_and_stays_invisible | WB (patch of `_fork_into` becomes an `after_fork` hook on the fake engine) | a_copy_that_does_not_match_its_source_writes_no_manifest_and_stays_invisible |
| Backups.test_a_source_that_changes_while_it_is_copied_makes_no_backup | WB | a_source_that_changes_while_it_is_copied_makes_no_backup |
| Backups.test_a_folder_without_a_valid_backup_json_is_not_a_usable_backup | WB | a_folder_without_a_valid_backup_json_is_not_a_usable_backup |
| Backups.test_verify_rehashes_every_file_and_names_what_changed | WB | verify_rehashes_every_file_and_names_what_changed |
| Backups.test_usable_checks_the_manifest_the_log_names | WB | usable_checks_the_manifest_the_log_names |
| Backups.test_a_replaced_backup_is_detected_by_the_log | WB | a_replaced_backup_is_detected_by_the_log |
| Backups.test_a_deleted_backup_is_reported_as_logged_but_missing | WB | a_deleted_backup_is_reported_as_logged_but_missing |
| Backups.test_a_newer_format_is_refused_not_guessed | WB | a_newer_format_is_refused_not_guessed |
| Backups.test_a_legacy_backup_without_a_seal_is_listed_unsealed_and_verify_adopts_it | WB | a_legacy_backup_without_a_seal_is_listed_unsealed_and_verify_adopts_it |
| Backups.test_a_legacy_backup_that_fails_the_rehash_is_labelled_and_never_adopted | WB | a_legacy_backup_that_fails_the_rehash_is_labelled_and_never_adopted |
| Backups.test_the_default_policy | WB | the_default_policy |
| Backups.test_a_secondary_root_is_always_a_full_copy | WB | a_secondary_root_is_always_a_full_copy |
| Backups.test_two_roots_give_two_verified_copies_and_a_failed_secondary_only_warns | WB (patch of `_make_one` becomes `fail_paths` on the fake engine) | two_roots_give_two_verified_copies_and_a_failed_secondary_only_warns |
| Backups.test_a_failed_primary_aborts_and_so_does_a_failed_secondary_the_policy_needs | WB | a_failed_primary_aborts_and_so_does_a_failed_secondary_the_policy_needs |
| Backups.test_a_policy_that_wants_an_independent_copy_refuses_a_block_clone | WB | a_policy_that_wants_an_independent_copy_refuses_a_block_clone |
| Backups.test_a_large_backup_needs_confirmation_and_states_the_cumulative_cost | WB | a_large_backup_needs_confirmation_and_states_the_cumulative_cost |
| Backups.test_the_doctor_warning_threshold_is_in_the_plan | WB | the_doctor_warning_threshold_is_in_the_plan |
| RemoveAndHandler.test_the_handler_needs_a_lineage | BB (`handle()` resolves a target through `targets`/`api`, not ported here; `run_op` is the part below it) | - |
| RemoveAndHandler.test_list_verify_and_remove_through_backend_action_backups | WB for the op layer, BB for the handler | backups_remove::list_verify_and_remove_through_run_op |
| RemoveAndHandler.test_remove_is_a_dry_run_unless_confirmed_and_never_drops_below_the_policy | WB | backups_remove::remove_is_a_dry_run_unless_confirmed_and_never_drops_below_the_policy |
| RemoveAndHandler.test_remove_needs_exactly_one_selector_and_a_boolean_confirm | WB | backups_remove::remove_needs_exactly_one_selector_and_a_boolean_confirm |
| RemoveAndHandler.test_remove_refuses_generation_zero_the_head_the_revert_target_and_a_live_views_base | WB | backups_remove::remove_refuses_generation_zero_the_head_the_revert_target_and_a_live_views_base |
| RemoveAndHandler.test_the_revert_chain_stays_protected_after_a_revert_and_a_rolled_back_generation_is_removable | WB | backups_remove::the_revert_chain_stays_protected_after_a_revert_and_a_rolled_back_generation_is_removable |
| RemoveAndHandler.test_op_remove_is_in_the_option_bags_help_text | BB (`api.OPTION_BAGS`, not this lane) | - |
| EngineBackups.test_the_engine_writes_the_backup_with_purpose_backup_and_the_client_reverifies_it | WB | backups_engine::the_engine_writes_the_backup_with_purpose_backup_and_the_client_reverifies_it |
| EngineBackups.test_the_capabilities_a_real_hydra_4_advertises_select_the_engine_backup_and_the_generation_purpose | WB for the backup half; the `generation` purpose half is commits.py (BB) | backups_engine::the_capabilities_a_real_hydra_4_advertises_select_the_engine_backup |
| EngineBackups.test_an_engine_backup_is_accepted_by_the_gate_and_the_python_one_too | BB (the gate is the engine's / fakehydra's `open_program`) | - |
| EngineBackups.test_the_gate_refuses_without_a_backup_and_with_a_tampered_manifest | BB (engine gate) | - |
| EngineBackups.test_an_engine_backup_that_does_not_verify_is_refused_and_stays_invisible_to_use | WB | backups_engine::an_engine_backup_that_does_not_verify_is_refused_and_stays_invisible_to_use |
| EngineBackups.test_commit_uses_the_engine_backup_and_passes_it_to_the_candidate_open | BB (commits.py) | - |
| EngineBackups.test_an_older_format_project_commits_when_the_candidate_is_a_full_copy | BB (commits.py) | - |
| EngineBackups.test_a_project_at_this_engines_format_gets_no_pre_upgrade_backup | BB (commits.py) | - |
| EngineBackups.test_the_format_the_engine_reports_decides_the_confirmation | BB (commits.py) | - |
| EngineBackups.test_legacy_backup_adoption | WB | backups_engine::legacy_backup_adoption_tells_the_engine_when_it_can_seal |
| EngineBackups.test_a_legacy_backup_with_a_flipped_byte_is_labelled_and_unusable_as_a_source | WB | backups_make::a_legacy_backup_that_fails_the_rehash_is_labelled_and_never_adopted (+ backups_engine::an_engine_backup_that_does_not_verify...) |
| FaultMatrixOnE2.* | BB (commits.py fault matrix; needs the fake engine and commit code) | - |
| CommitHygiene.* | BB (commits.py / query.py) | - |
| RealEngineBackups.*, RealEngineFaultMatrix.* | BB (need the real hydra.4 engine; they call `backups` only through commits/engine) | - |

`backups.handle()` (the `backend action=backups` handler) is not ported: it needs `targets.resolve`, `api._settings` and
`hydra.Engine`, owned by other lanes. The op layer under it is `backups::run_op` (list / verify / remove).

## runtime_events (tests/test_runtime_capture.py `EventChain`, plus users in test_runtime_write / test_runtime_watch)

| Python test | Class | Rust test (events_log.rs) |
|---|---|---|
| EventChain.test_a_clean_log_verifies_and_ends_at_the_loggers_head | WB | a_clean_log_verifies_and_ends_at_the_loggers_head |
| EventChain.test_the_log_is_the_durable_frame_format | WB | the_log_is_the_durable_frame_format |
| EventChain.test_a_flipped_byte_fails_the_crc | WB | a_flipped_byte_fails_the_crc |
| EventChain.test_an_edited_record_with_a_valid_crc_fails_its_hash | WB | an_edited_record_with_a_valid_crc_fails_its_hash |
| EventChain.test_a_removed_record_breaks_the_chain | WB | a_removed_record_breaks_the_chain |
| EventChain.test_reordered_records_are_found | WB | reordered_records_are_found |
| EventChain.test_a_record_rehashed_after_an_edit_still_breaks_the_next_one | WB | a_record_rehashed_after_an_edit_still_breaks_the_next_one |
| EventChain.test_a_torn_tail_is_reported_and_is_not_a_failure | WB | a_torn_tail_is_reported_and_is_not_a_failure |
| EventChain.test_a_flipped_byte_in_the_last_record_is_corrupt_not_torn | WB | a_flipped_byte_in_the_last_record_is_corrupt_not_torn |
| EventChain.test_a_last_line_without_its_lf_is_torn_whether_or_not_it_parses | WB | a_last_line_without_its_lf_is_torn_whether_or_not_it_parses |
| EventChain.test_the_log_for_another_session_does_not_verify | WB | the_log_for_another_session_does_not_verify |
| EventChain.test_counters_stay_true_when_the_record_is_incomplete | WB | counters_stay_true_when_the_record_is_incomplete |
| EventChain.test_a_failed_write_leaves_a_hole_the_chain_reports | WB (`patch os.write` becomes `EventLog::inject_write_failure`) | a_failed_write_leaves_a_hole_the_chain_reports |
| (verify_log `expect` argument, used by capture start/stop in runtime_capture) | WB | expected_hashes_name_the_records_a_capture_starts_and_stops_at |
| test_runtime_capture: test_a_clipped_message_is_counted_by_what_it_said, ...clipped payload..., ...failed_log_write_makes_the_capture_partial, ...full_log_makes_the_capture_partial and every other agent / capture test | BB (runtime agent code; uses EventLog through its public surface) | - |
| test_runtime_write.py, test_runtime_watch.py (call `verify_log`, `iter_records`, `LOG_NAME`) | BB | - |

## config.py / paths.py (root resolution)

There is no dedicated Python test file; behaviour is covered by BB tests (`test_paths`, `test_config` if present, and every
test that builds `settings["root"]`). Rust unit tests: `config::tests::gmtime_epoch_and_leap`, `config::tests::python_str`.
`paths.resolved`'s 2 s TTL cache, `volume_info` and `system_drive` are not ported (not needed by the storage modules).

## Differential tests against Python (lineage_diff_python.rs, run against src/hydralysis with C:\Python315\python.exe)

| Test | What is compared |
|---|---|
| canonical_frame_and_record_hash_match_python_on_random_values | 400 random JSON values (ints, shortest-repr floats, control/BMP/supplementary strings, nesting): `lineage.canonical` bytes, `runtime_events._frame` bytes, `record_hash` |
| tree_files_tree_hash_and_manifest_bytes_match_python | `tree_files`, `tree_hash`, `MANIFEST.json` bytes written by each side, cross-verification both ways, tamper problem lists |
| current_log_is_readable_and_appendable_by_both | `ensure`, alternate `append_current` Rust/Python/Rust/Python (prevHash chain), `history`, `head` |
| event_logs_cross_verify_and_counters_match | each side verifies the other's events.log; counters equal; record shapes and key order equal (ignoring wall-clock `t`) |
| a_rust_backup_verifies_in_python_and_lists_the_same | Python `backups.verify` / `listing` / `policy` on a Rust-made backup equal the Rust results |
