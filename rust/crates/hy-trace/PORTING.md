# hy-trace: porting notes

Port of the Hydralysis trace tool's pure logic from Python to Rust, bound into `hydralysis_native` (`native/src/trace/`)
and routed from Python behind `HYDRALYSIS_IMPL=rust`. The Python stays the specification and the fallback: an input the
port does not model raises `hydralysis_native.TraceFallback` and the Python implementation answers (or raises) as it
always did. `HYDRALYSIS_NATIVE=0` turns the routing off again. Windows x64 only.

## What is ported, and what is routed

| Python | Rust | Routed (`HYDRALYSIS_IMPL=rust`) |
|---|---|---|
| `trace_hashes`: `fnv`, `crc_generic`, `murmur3_32`, `Algorithm`, `Dictionary` (add, resolve, collisions, digest), `annotate_constants`, `interpretation`, `interpret_events`, `scan_constants` | `hashes.rs`, `pyfmt.rs`; binding `native/src/trace/hashes.rs` | yes |
| `trace_reports`: `write_survival`, `observed_edges`, `hook_bypass`, `discovery_report`, `field_writers`, `edges_from_dispatch`, `from_engine_rows` | `reports.rs`; binding `native/src/trace/reports.rs` | held back, see Measurements |
| `trace_watchdog`: `Unwinder`, `_walk`, `capture_stacks`, `modules`, `thread_ids` | `unwind.rs`, `capture.rs` (the only `unsafe`, FFI to Win32); binding `native/src/trace/watchdog.rs` | yes (`capture_stacks`) |
| `trace_watchdog.FrameStallWatchdog`, `counter_reader` | not ported | The watchdog is a polling thread over Python callbacks and an injectable clock; the work it triggers (`capture_stacks`) is the ported part. |
| `trace.read_jsonl` (clean files), `trace_schema.validate_event` (the yes answer), `trace_canon.canonical_bytes` (as `check`) | `jsonl.rs`, `schema.rs`, `canon.rs`; binding `native/src/trace/importer.rs` | yes |
| `trace.shape` (with `_collect_ids`, `_size`) | `shape.rs` | held back, see Measurements |
| `trace.py` client layer, argument handling, actions, `offline_verify`, `run_tool` | not ported | Orchestration over the engine connection, files and subprocesses; no pure hot path. `trace_canon.scan` is already Rust for the pump (`native::scan_chain`). |
| `trace_pairing`, `trace_corpus_diff`, `trace_footprint`, `trace_bindings`, `trace_dumps`, `trace_etw` | not ported | Small per-session data, floating point least squares (exactness risk) or file and process plumbing; nothing for the Rust to win. |

`trace_wire`, `trace_capture`, `trace_keys` and `trace_pump` were already Rust (`native/src/trace*.rs`) and are untouched. `runtime_*.py` is untouched.

## Test mapping

Original tests are `tests/test_trace_static.py` (they run against both implementations: `tools/run_tests.py -k test_trace`
with `HYDRALYSIS_IMPL` unset and `=rust`). The Rust tests keep one test per original, named after it.

| Python test | Rust test |
|---|---|
| `HashRegistry.test_builtin_vectors_all_reproduce` | `hashes::tests::builtin_vectors_all_reproduce` |
| `HashRegistry.test_known_values` | `hashes::tests::known_values` |
| `HashRegistry.test_a_profile_codec_needs_vectors_it_reproduces`, `test_corpus_names_feed_the_dictionary` | no Rust twin: `Registry` (profile codec validation with vectors) and `corpus_names` stay Python and use the ported hashes; both tests run in both modes |
| `HashRegistry.test_a_custom_basis_and_a_seeded_murmur` | `hashes::tests::the_unmasked_basis_survives_empty_input_and_widths_are_checked`, `a_case_folded_codec_hashes_the_folded_text` |
| `HashRegistry.test_entries_record_their_sources_and_resolve` | `hashes::tests::entries_record_their_sources_and_resolve` |
| `HashRegistry.test_a_deliberate_collision_is_ambiguous_and_never_resolved` | `hashes::tests::a_deliberate_collision_is_ambiguous_and_never_resolved` |
| `HashRegistry.test_annotating_constants` | `hashes::tests::annotating_constants` |
| `HashRegistry.test_an_interpretation_revision_keeps_the_raw_value_and_changes_with_the_dictionary` | `hashes::tests::an_interpretation_revision_changes_with_the_dictionary`, `the_digest_is_the_python_canonical_text` |
| `HashRegistry.test_a_name_search_finds_the_code_that_uses_its_hash` | `hashes::tests::a_name_search_finds_the_code_that_uses_its_hash`, `overlapping_matches_are_all_found` |
| `Reports.test_a_later_stage_overwrites_on_most_frames_and_the_report_names_it` | `reports::tests::a_later_stage_overwrites_on_most_frames_and_the_report_names_it` |
| `Reports.test_removing_the_overwrite_turns_every_frame_to_survived` | `reports::tests::removing_the_overwrite_turns_every_frame_to_survived` |
| `Reports.test_a_mixed_run_gives_the_ratio` | `reports::tests::a_mixed_run_gives_the_ratio` |
| `Reports.test_a_consumer_that_reads_before_our_write` | `reports::tests::a_consumer_that_reads_before_our_write` |
| `Reports.test_unknown_is_never_pass_gaps_missing_reads_and_unordered_writes` | `reports::tests::unknown_is_never_pass_gaps_missing_reads_and_unordered_writes` |
| `Reports.test_the_report_is_deterministic` | `reports::tests::the_report_is_deterministic` |
| `Reports.test_hooking_one_overload_reports_the_other_as_a_bypass_with_its_path_and_class` | `reports::tests::hooking_one_overload_reports_the_other_as_a_bypass_with_its_path_and_class` |
| `Reports.test_no_bypass_and_no_writes_are_different_answers` | `reports::tests::no_bypass_and_no_writes_are_different_answers` |
| `Reports.test_the_discovery_report_keeps_three_kinds_of_answer_apart` | `reports::tests::the_discovery_report_keeps_three_kinds_of_answer_apart` |
| `test_trace_extras.Watchdog` (live capture of a child) | `capture::tests::a_capture_of_another_process_walks_its_threads_and_resumes_them`, `a_process_that_does_not_exist_is_refused` |
| (no Python unit tests of the unwinder) | `unwind::tests::*` (push and alloc, leaf, unmapped, malformed codes, chained entries, frame-pointer and stack-scan fallback) written from the behavior list |
| (the rest had no unit tests) | `canon::tests`, `schema::tests`, `jsonl::tests`, `shape::tests`, `pyfmt::tests`: characterization tests from the behavior list |

Differential tests against the Python (generated and mutated input, equal down to dict key order):
`tests/test_trace_hashes_native.py`, `tests/test_trace_reports_native.py`, `tests/test_trace_import_native.py`,
`tests/test_trace_watchdog_native.py` (a live capture of a sleeping child by both).

## Deliberate differences

* **A strict input model.** Reports, shape and the schema check accept only plain JSON shapes (None, bool, int in the 64-bit
  range, finite float, str, list, dict with str keys; a tuple only where a report keeps it, `thread_gen`). Anything else
  is `TraceFallback` and runs in Python: integers beyond 64 bits (serde_json would read them as floats), NaN and
  infinity, non-text keys, lone surrogates, tuples in `shape`.
* **Yes from Rust, reasons from Python.** `validate_event` and `read_jsonl` decide in Rust only that an event or a file is
  valid. For a refusal (and for a damaged file) the Python runs and words the reasons, so the messages are the Python's.
* **Schema patterns.** Python `re` patterns are translated to `fancy-regex` for the constructs the TRACE-1 schema uses
  (`^ $ ( ) (?: ) (?! ) [ ] { } * + ?`, escaped punctuation); `$` becomes "end, or before one final newline" as in Python.
  Anything else in a pattern (letter escapes, flags, nested classes, possessive quantifiers) makes the schema
  unsupported and the Python validator is used.
* **Atomic failed add.** A `Dictionary.add` that raises leaves the Rust dictionary unchanged. The Python leaves the name
  half indexed (see Python quirks).
* **Unicode.** Text predicates use Rust's `char` tables where the Python uses its own (digits and spaces outside ASCII in
  `int(text, 0)`, case mapping of folds) except where emulated in `pyfmt.rs` (`str.strip` emptiness, JSON `ensure_ascii`,
  `float.__repr__`, `int(text, 0)` / `int(text, 16)` for ASCII). A non-ASCII digit string is `NotAscii` and falls back.
* **Message text.** `UnicodeEncodeError` text for an unencodable name is rebuilt by the binding with the same arguments.

## Preserved quirks (do not fix by accident)

* `fnv` with an explicit basis returns the unmasked basis for empty input.
* `scan_constants` returns its hits unsorted when it hit the limit (truncated); sorted otherwise. Hits are found at
  overlapping offsets (`find(form, start + 1)`).
* `find_name_users` reports `truncated` as `len(hits) >= limit`.
* The unwinder over-pops a pc inside an epilogue and raises `IndexError`/`struct.error` on unwind data that is cut short;
  the Rust walk reports that as `Malformed` and the binding raises `IndexError`. A thread is resumed first.
* `max()` over equal keys keeps the first; the Rust uses an explicit first-wins loop where `max_by_key` would keep the last.
* Ints sort before strings in report keys; `None` first.
* `capture_stacks` of the calling process would suspend the calling thread for good (both implementations).
* `shape`: a `coverage` of the reply that is an empty dict counts as reported; the event-id pattern accepts one trailing
  newline (Python `$`); `truncated` keeps the first position of a key; key order of the answer is the Python's.

## Python bugs and oddities found (not fixed)

* `Dictionary.add` in Python indexes some algorithms before a later one raises (an unencodable name), leaving a partial entry.
* `Unwinder._unwind_one` raises `IndexError`/`struct.error` instead of treating truncated unwind codes as "stop".
* `scan_constants` truncation returns unsorted hits, so the first hits depend on section order, not RVA order.

## Measurements

CPU seconds (process time of the operation) and the process peak working set, Windows x64, each workload in its own
process, single runs on generated data (the benchmark scripts are `trace_bench*.py` in the session scratchpad; results in
`E:\Projects\Hydra\_logs\h7\trace\bench.jsonl`). The peak includes building the input, which is the same in both modes. The
outputs of the two modes were compared and are identical.

| Workload | Python CPU | Rust CPU | Python peak WS | Rust peak WS |
|---|---|---|---|---|
| Dictionary of 300k names x 4 algorithms: add, 60k resolves, digest, collisions, 60k event interpretations | 9.91 s | 0.91 s | 669 MB | 302 MB |
| `scan_constants` of a 48 MiB image, 40 constants | 0.52 s | 0.09 s | 164 MB | 119 MB |
| 200k single hashes (fnv1a32 / fnv1a64 / murmur3_32) | 0.33 / 0.34 / 0.48 s | 0.19 / 0.20 / 0.20 s | | |
| 200k single CRC-32 | 0.047 s (`zlib`) | not routed (0.17 s through the extension) | | |
| `read_jsonl` of 100k events (22 MB) | 2.33 s | 0.41 s | 204 MB | 177 MB |
| `capture_stacks` of an 8-thread process, 20 captures | 0.94 s | 0.66 s | | |
| Report builders on 120k events (six functions) | 0.11 to 0.28 s each | 0.16 to 0.33 s each | 243 MB | 288 MB |
| `shape` of 300 replies of about 45 KB | 0.45 s | 0.50 s | 58 MB | 59 MB |

The report builders and `shape` are **not faster** in Rust: their cost in Python is walking dicts, and in Rust it is moving
the same dicts across the extension boundary (and back), which costs as much as the logic it replaces. They are ported,
parity tested and exposed (`reports_*`, `trace_shape`), but `trace_native.function` holds them back unless
`HYDRALYSIS_TRACE_HELD=1`, so `HYDRALYSIS_IMPL=rust` does not make them slower. Making them faster needs the events to live
in Rust (parsed from the engine rows or segments there), which changes the API and is not part of this port.

## Verification

See the final report of the port for the exact runs and their results.
