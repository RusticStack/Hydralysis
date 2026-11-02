# TESTMAP: storage core (durable, storelog, store v3, native)

Scope: tests/test_durable.py, tests/test_storelog.py, tests/test_store_v3.py, tests/test_native.py (126 tests).
BB = black-box (passes unchanged against `HYDRALYSIS_IMPL=rust` through the public surface).
WB = white-box (patches Python internals such as os.fsync, os.replace, `_VERIFIED`, `_identity`, `_snapshot`); re-expressed as a Rust test with the same case.

Results: the Python implementation passes all four files. Under `HYDRALYSIS_IMPL=rust` the WB rows fail by construction (they patch Python internals that the Rust layer does not have); every other row passes unchanged (the surrogate case after the shim fix). Evidence, bundle, lineage, backups and events maps: TESTMAP_evidence.md, TESTMAP_lineage.md.

Rust twins: hy-core/tests/durable.rs, hy-core/tests/durable_twins.rs, hy-store/tests/storelog.rs, hy-store/tests/storelog_twins.rs. Differential Python-vs-Rust: tests/test_rust_storage_parity.py.

| Python test | Class | Under HYDRALYSIS_IMPL=rust | Rust twin / note |
|---|---|---|---|
| test_durable::AtomicWrite::test_writes_replaces_and_leaves_no_temporary | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::writes_replaces_and_leaves_no_temporary |
| test_durable::AtomicWrite::test_the_data_is_fsynced_before_the_replace | WB | fails under rust (patches Python internals) | none directly (no fsync hook in Rust): the order is structural in fsio::atomic_write_point (write_new + sync_all, then replace_file); the crash ordering is covered by durable.rs::killing_the_writer_before_the_replace_keeps_the_old_content and ::killing_the_writer_after_the_replace_leaves_the_new_content. GAP: the fsync order itself is not asserted |
| test_durable::AtomicWrite::test_permission_error_is_retried_through_a_monkeypatched_os_replace | WB | fails under rust (patches Python internals) | hy-core/tests/durable.rs::a_denied_replace_is_retried_until_the_holder_lets_go (a real sharing violation instead of a patched os.replace) |
| test_durable::AtomicWrite::test_native_move_is_retried_too_and_backoff_is_capped | WB | fails under rust (patches Python internals) | durable.rs::a_denied_replace_is_retried_until_the_holder_lets_go + durable_twins.rs::the_backoff_starts_at_50ms_doubles_is_capped_at_500ms_and_stays_within_ten_seconds |
| test_durable::AtomicWrite::test_a_replace_that_stays_denied_raises_after_the_budget_and_leaves_the_old_file | WB | fails under rust (patches Python internals) | durable_twins.rs::a_replace_that_stays_denied_raises_after_the_budget_and_leaves_the_old_file |
| test_durable::AtomicWrite::test_other_errors_are_not_retried | WB | fails under rust (patches Python internals) | durable_twins.rs::other_errors_are_not_retried |
| test_durable::AtomicWrite::test_the_native_move_really_replaces_an_existing_file | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::the_native_move_really_replaces_an_existing_file |
| test_durable::AtomicWrite::test_killing_the_writer_between_the_temporary_and_the_replace_keeps_the_old_content | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::killing_the_writer_before_the_replace_keeps_the_old_content |
| test_durable::AtomicWrite::test_killing_the_writer_after_the_replace_leaves_the_new_content | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::killing_the_writer_after_the_replace_leaves_the_new_content |
| test_durable::AtomicWrite::test_a_non_atomic_writer_killed_midway_is_detected_and_the_previous_version_is_returned | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_non_atomic_writer_killed_midway_is_detected_and_the_previous_version_is_returned |
| test_durable::AtomicWrite::test_the_hook_is_inert_without_test_mode | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::the_hook_is_inert_without_test_mode |
| test_durable::SealedJson::test_round_trip_seals_a_canonical_body_and_keeps_the_previous_version | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::round_trip_seals_a_canonical_body_and_keeps_the_previous_version |
| test_durable::SealedJson::test_a_write_over_a_valid_record_fsyncs_the_record_only_not_its_backup | WB | fails under rust (patches Python internals) | none directly (sync=false for the .bak is structural in sealed::keep_previous). GAP: not asserted |
| test_durable::SealedJson::test_zero_length_returns_the_previous_version_not_empty | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::zero_length_and_torn_files_at_every_cut_return_the_old_content_never_empty |
| test_durable::SealedJson::test_a_torn_file_at_every_cut_returns_the_old_content_never_empty | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::zero_length_and_torn_files_at_every_cut_return_the_old_content_never_empty |
| test_durable::SealedJson::test_an_unpaired_surrogate_is_refused_not_sealed | BB | passes under HYDRALYSIS_IMPL=rust | no Rust twin: a lone surrogate cannot exist in a Rust str; the Python shim (_rust_store._refuse_surrogate) and hy-core sealed::classify keep the message and the reason |
| test_durable::SealedJson::test_a_mis_sealed_file_is_rejected | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_mis_sealed_file_is_rejected_and_no_valid_version_raises_store_corrupt_naming_both_paths |
| test_durable::SealedJson::test_a_missing_file_with_a_backup_returns_the_backup | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::zero_length_and_torn_files_at_every_cut_return_the_old_content_never_empty |
| test_durable::SealedJson::test_no_valid_version_raises_store_corrupt_naming_both_paths | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_mis_sealed_file_is_rejected_and_no_valid_version_raises_store_corrupt_naming_both_paths |
| test_durable::SealedJson::test_a_torn_file_with_no_backup_raises_store_corrupt | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::SealedJson::test_a_file_that_was_never_written_is_not_corruption | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_file_that_was_never_written_is_not_corruption |
| test_durable::SealedJson::test_a_pre_seal_record_loads_and_becomes_the_backup_of_the_first_sealed_write | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_pre_seal_record_loads_and_becomes_the_backup_of_the_first_sealed_write |
| test_durable::SealedJson::test_a_bad_file_never_replaces_the_good_backup_and_is_preserved_aside | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_bad_file_never_replaces_the_good_backup_and_is_preserved_aside |
| test_durable::SealedJson::test_oversize_and_reserved_keys_are_refused_before_anything_is_written | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::oversize_and_reserved_keys_are_refused_before_anything_is_written |
| test_durable::SealedJson::test_update_sealed_loses_no_update_across_processes | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::update_sealed_loses_no_update_across_threads (threads; the Python test uses processes and passes under rust) |
| test_durable::StoreIntegration::test_never_written_store_is_the_empty_one | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::StoreIntegration::test_save_then_load_round_trips_and_seals | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::StoreIntegration::test_a_v2_store_written_before_seals_loads_unchanged | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::StoreIntegration::test_torn_zero_length_and_mis_sealed_stores_return_the_previous_edits_never_none | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::StoreIntegration::test_a_missing_store_with_a_backup_returns_the_backup | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::StoreIntegration::test_no_valid_version_is_store_corrupt_not_start_empty | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::StoreIntegration::test_a_store_of_another_build_is_refused_not_replaced_by_the_backup | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::StoreIntegration::test_the_history_limit_message_is_kept | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RecordFiles::test_write_json_seals_and_read_json_unseals_with_the_same_dict | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RecordFiles::test_read_json_falls_back_and_raises_store_corrupt | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RecordFiles::test_target_registry_and_job_records_are_sealed_and_survive_a_torn_file | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RecordFiles::test_a_hand_edited_sealed_record_is_detected | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::DaemonConfig::test_it_is_the_plain_json_the_launcher_reads_with_no_seal_no_backup_and_no_temporary | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::DaemonConfig::test_it_writes_through_durable_atomic_write_and_only_when_the_content_changed | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::DaemonConfig::test_a_writer_killed_before_the_replace_leaves_the_previous_config_whole | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::DaemonConfig::test_a_torn_config_is_rewritten_not_trusted | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RuntimeMailbox::test_a_record_is_sealed_on_disk_and_reads_back_without_its_seal | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RuntimeMailbox::test_a_record_that_was_never_written_is_empty_and_a_pre_seal_record_loads_as_it_is | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RuntimeMailbox::test_a_torn_or_mis_sealed_file_falls_back_to_the_previous_version_and_never_reads_empty | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RuntimeMailbox::test_the_mailbox_error_contract_of_the_readers_is_unchanged | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RuntimeMailbox::test_releasing_the_executable_lock_removes_the_record_and_its_previous_version | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::RuntimeMailbox::test_a_writer_killed_before_the_replace_leaves_the_previous_record_whole | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::AppendLogTests::test_the_line_format_is_crc_hex8_space_json_lf_with_zlib_crc32 | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::the_line_format_is_crc_hex8_space_json_lf_with_zlib_crc32 |
| test_durable::AppendLogTests::test_a_cut_at_every_offset_of_the_last_line_is_read_then_repaired_then_clean | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_cut_at_every_offset_of_the_last_line_is_read_then_repaired_then_clean |
| test_durable::AppendLogTests::test_a_fragment_without_lf_is_never_valid_even_when_its_crc_matches | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_fragment_without_lf_is_never_valid_even_when_its_crc_matches |
| test_durable::AppendLogTests::test_several_invalid_lines_at_the_end_are_one_torn_tail | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::several_invalid_lines_at_the_end_are_one_torn_tail_and_mid_log_corruption_is_refused |
| test_durable::AppendLogTests::test_mid_log_corruption_is_refused_by_the_reader_and_by_the_writer | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::several_invalid_lines_at_the_end_are_one_torn_tail_and_mid_log_corruption_is_refused |
| test_durable::AppendLogTests::test_an_unknown_crc_prefix_or_bad_json_after_a_valid_crc_is_invalid | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::an_unknown_crc_prefix_or_bad_json_after_a_valid_crc_is_invalid |
| test_durable::AppendLogTests::test_a_crash_inside_the_repair_heals_on_the_next_append | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_crash_inside_the_repair_heals_on_the_next_append |
| test_durable::AppendLogTests::test_a_writer_killed_in_the_middle_of_an_append_is_followed_by_a_normal_successful_append | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::a_writer_killed_in_the_middle_of_an_append_is_followed_by_a_normal_successful_append |
| test_durable::AppendLogTests::test_a_failed_append_forces_a_check_before_the_next_one | WB | fails under rust (patches Python internals) | durable_twins.rs::a_failed_append_forces_a_check_before_the_next_one_and_a_foreign_fragment_is_repaired |
| test_durable::AppendLogTests::test_a_fragment_left_by_another_process_after_this_one_verified_is_still_repaired | WB | fails under rust (patches Python internals) | durable_twins.rs::a_fragment_left_by_another_process_after_this_one_verified_is_still_repaired |
| test_durable::AppendLogTests::test_a_foreign_garbage_line_that_ends_in_lf_is_also_repaired_on_the_next_acquisition | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::AppendLogTests::test_the_cheap_check_scans_nothing_when_the_log_is_as_this_process_left_it | WB | fails under rust (patches Python internals) | durable_twins.rs::the_cheap_check_scans_nothing_when_the_log_is_as_this_process_left_it + ::the_writers_first_acquisition_scans_once_and_never_again (scan counter) |
| test_durable::AppendLogTests::test_a_log_larger_than_the_32_mib_localio_budget_is_read_scanned_and_appended_to | WB | fails under rust (patches Python internals) | durable.rs::a_log_larger_than_the_metadata_budget_is_read_scanned_and_appended_to + durable_twins.rs::the_writers_first_acquisition_scans_once_and_never_again |
| test_durable::AppendLogTests::test_the_tail_read_finds_the_last_valid_line_across_garbage_and_long_lines | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::the_tail_read_finds_the_last_valid_line_across_garbage_and_long_lines |
| test_durable::AppendLogTests::test_an_append_to_a_missing_log_creates_it_and_the_caller_may_hold_the_lock | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::an_append_to_a_missing_log_creates_it_and_the_caller_may_hold_the_lock |
| test_durable::AppendLogTests::test_the_writer_lock_excludes_a_second_writer | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::the_writer_lock_excludes_a_second_writer |
| test_durable::AppendLogTests::test_concurrent_writer_processes_lose_no_line_and_tear_none | BB | passes under HYDRALYSIS_IMPL=rust | durable.rs::concurrent_writers_lose_no_line_and_tear_none (threads) |
| test_durable::TwoProcessWriters::test_a_appends_b_is_killed_mid_line_a_appends_again_and_a_repair_is_recorded | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::TwoProcessWriters::test_the_same_with_a_rollback_append_and_with_a_backups_log_append | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::TwoProcessWriters::test_a_foreign_writer_leaves_a_terminated_but_invalid_line_and_a_still_repairs_it | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::TwoProcessWriters::test_control_a_valid_line_from_another_process_needs_no_repair | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::WriteGate::test_owned_files_write_records_only_through_durable | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::WriteGate::test_no_new_write_site_appears_in_the_rest_of_src | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::WriteGate::test_record_helpers_are_the_only_json_writers_and_nothing_dumps_json_to_a_file | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_durable::WriteGate::test_the_follow_up_table_is_counted | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_storelog::Appending::test_a_mutation_is_one_framed_row_and_the_snapshot_is_not_rewritten | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::a_mutation_is_one_framed_row_and_the_snapshot_is_not_rewritten |
| test_storelog::Appending::test_the_row_is_fsynced_before_save_returns | WB | fails under rust (patches Python internals) | none directly (raw_append calls sync_all before returning). GAP: not asserted; durability is exercised by the kill-point twin storelog.rs::kill_points_of_an_append_and_of_a_compaction_... |
| test_storelog::Appending::test_an_unchanged_store_writes_nothing | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::an_unchanged_store_writes_nothing |
| test_storelog::Appending::test_the_budget_is_refused_before_anything_is_written | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::the_budget_is_refused_before_anything_is_written |
| test_storelog::ReviewFixes::test_a_failed_compaction_after_the_row_is_durable_is_not_reported_as_a_failed_write | WB | fails under rust (patches Python internals) | hy-store/tests/storelog.rs::a_failed_compaction_after_the_row_is_durable_is_not_reported_as_a_failed_write (a directory in place of the .bak makes the snapshot write fail) |
| test_storelog::ReviewFixes::test_a_failed_trim_after_the_snapshot_is_not_reported_either | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs failed-compaction twin (a trim failure shares the upkeep path); the Python test patches storelog._trim |
| test_storelog::ReviewFixes::test_a_size_triggered_compaction_is_not_followed_at_once_by_another | WB | fails under rust (patches Python internals) | storelog.rs::a_size_triggered_compaction_is_not_followed_at_once_by_another |
| test_storelog::ReviewFixes::test_a_reader_whose_snapshot_was_replaced_twice_meanwhile_reads_again | WB | fails under rust (patches Python internals) | hy-store/tests/storelog_twins.rs::a_reader_whose_snapshot_was_replaced_meanwhile_reads_again |
| test_storelog::ReviewFixes::test_the_per_process_caches_are_bounded | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::the_per_process_caches_are_bounded |
| test_storelog::Equivalence::test_random_mutation_sequences_load_identically_with_compaction | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::random_mutation_sequences_load_identically_with_compaction + tests/test_rust_storage_parity.py::StoreLog |
| test_storelog::CleanOnce::test_cleaning_a_clean_record_gives_it_back | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_storelog::CleanOnce::test_the_fast_path_writes_what_the_full_clean_writes | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_storelog::LoadCache::test_a_warm_load_does_not_clean_the_records_again_and_gives_a_private_copy | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_storelog::LoadCache::test_a_file_that_becomes_stable_during_the_load_is_still_cached | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_storelog::LoadCache::test_every_write_and_an_in_place_rewrite_of_the_same_size_are_seen | BB | passes under HYDRALYSIS_IMPL=rust | - |
| test_storelog::Recovery::test_a_damaged_main_file_reads_the_newest_state_from_the_backup_and_the_log | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::a_damaged_main_file_reads_the_newest_state_from_the_backup_and_the_log |
| test_storelog::Recovery::test_a_torn_log_tail_is_ignored_and_repaired_by_the_next_append | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::a_torn_log_tail_is_ignored_and_repaired_by_the_next_append |
| test_storelog::Recovery::test_corruption_inside_the_log_is_store_corrupt | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::corruption_inside_the_log_is_store_corrupt |
| test_storelog::Recovery::test_a_snapshot_without_an_anchor_never_takes_a_stale_log | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::a_snapshot_without_an_anchor_never_takes_a_stale_log |
| test_storelog::Recovery::test_another_writer_between_two_of_mine_is_seen | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::another_writer_between_two_of_mine_is_seen |
| test_storelog::Crashes::test_kill_points_of_an_append | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::kill_points_of_an_append_and_of_a_compaction_leave_the_last_acknowledged_state_or_the_new_one |
| test_storelog::Crashes::test_kill_points_of_a_compaction | BB | passes under HYDRALYSIS_IMPL=rust | storelog.rs::kill_points_of_an_append_and_of_a_compaction_leave_the_last_acknowledged_state_or_the_new_one |
| test_store_v3::Migration::test_a_v2_store_loads_upgrades_and_is_kept_once_as_v2_bak | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Migration::test_a_sealed_v2_store_migrates_the_same_way | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Migration::test_a_v1_store_is_kept_as_v1_bak | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Migration::test_a_v2_reader_refuses_the_v3_file_so_it_is_preserved | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Migration::test_a_v2_store_never_silently_empties | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Sealing::test_a_hand_stripped_seal_on_a_v3_store_is_store_corrupt | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Sealing::test_a_stripped_seal_is_not_answered_from_an_older_sealed_copy | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Sealing::test_a_torn_v3_store_falls_back_to_its_backup | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Sealing::test_a_pre_seal_v2_store_still_loads_once | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Sealing::test_has_overlays_and_expected_state_see_the_overlays_when_only_the_backup_is_left | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::CommittedSet::test_a_subset_commit_with_a_skipped_record_below_a_committed_one_replays_the_skipped_one | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::CommittedSet::test_the_marker_of_a_program_built_before_the_commit_no_longer_matches | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::CommittedSet::test_a_v2_style_marker_matches_only_generation_zero_with_an_empty_committed_set | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::CommittedSet::test_a_reverted_commit_makes_its_records_pending_again | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::CommittedSet::test_the_commit_entry_is_validated_on_load | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::CommittedSet::test_the_working_copy_replays_only_the_pending_records | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Effects::test_an_edit_records_its_effects_seq_and_attribution | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Effects::test_a_script_that_reports_no_effects_leaves_the_record_before_unknown | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Effects::test_effects_are_validated | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Effects::test_the_field_vocabulary_derives_from_the_options_alone | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Revert::test_the_earlier_record_of_a_chain_is_refused_with_its_dependents_named | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Revert::test_cascade_removes_the_chain_and_leaves_other_subjects | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Revert::test_the_last_record_of_a_chain_reverts_freely | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Revert::test_a_legacy_record_without_effects_is_a_chain_by_its_options | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Revert::test_reverting_by_batch_id_removes_the_whole_batch | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Revert::test_a_committed_record_is_refused_with_already_committed | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Revert::test_cascade_must_be_a_boolean | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Changes::test_status_show_changes_lists_records_with_effects_and_commit_state | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::Changes::test_status_options_are_validated | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_store_v3::CrashWindow::test_a_kill_between_the_engine_apply_and_the_store_write_is_healed_by_the_marker | BB | passes under HYDRALYSIS_IMPL=rust (workcopy + storelog + durable on the Rust layer) | - |
| test_native::Twin::test_python_twin_matches_the_reference_scan | BB | passes under HYDRALYSIS_IMPL=rust | durable_twins.rs::frame_lines_agree_with_the_per_line_parse + tests/test_rust_storage_parity.py::Logs::test_scan_of_mutated_logs_is_identical |
| test_native::Twin::test_the_native_helper_matches_the_python_twin | BB | passes under HYDRALYSIS_IMPL=rust | as above (hydralysis_native.frame_lines is untouched by this work; the Rust port frame_lines is checked against the per-line parse) |
