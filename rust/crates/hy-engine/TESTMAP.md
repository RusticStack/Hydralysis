# hy-engine test map (old Python test -> new test)

Classification: **BB** black-box (the Python test runs unchanged with `HYDRALYSIS_IMPL=rust`), **WB** white-box (re-expressed in
Rust with the same cases), **PAR** new differential test (`tests/test_rust_parity_engine.py`: the Python original and the Rust
twin on the same inputs, compared by value or by exception type and message), **PY** stays Python.

hy-engine holds the pure logic of `hydra.py`, `api.py` and the small unrouted leaf modules `address_maps`, `red4ext`,
`integrity`, `jobowner`, `localio` (the bounded shared read) and `paths.forbidden_drives`. The binding is
`native/src/hyapi.rs` (module `hydralysis_native`, functions `engine_*_rs`); the Python side is `src/hydralysis/_rust_engine.py`.
Python stays the specification and the fallback: a Rust function answers `Fallback` for any input it does not model exactly
(integers past 64 bits, `NaN` in JSON, lone surrogates, non-string where the original calls `str()`, a patched seam) and the
wrapper then runs the original.

## Rust test files

| File | Count | Covers |
|---|---|---|
| tests/hydra.rs | 29 | idempotent commands, script action, EngineError text, install inspection, client stamps, daemon config, wedge signal |
| tests/api.rs | 16 | catalog hash and epoch, tool table, instructions, not_available, call validation, hex, prologue arguments, export path, job listing, helpers, address parsing |
| tests/leaf.rs | 19 | address maps, red4ext lookups, integrity scan, job owner, forbidden drives, bounded read |

## Python tests that exercise the ported functions (BB: run in both modes)

| Python test module | Mode | Notes |
|---|---|---|
| test_contracts.py (CATALOG_HISTORY epoch 5) | BB + WB (`the_table_matches_its_epoch_so_a_change_needs_a_new_epoch`) | the Rust table hashes to the pinned epoch hash |
| test_compat.py, test_hydralysis.py, test_paths.py | BB | |
| test_supervisor.py, test_engine_client.py, test_client.py | BB + WB (hydra.rs) | EngineError text, stamps, wedge signal, config |
| test_deadline.py, test_query.py | PY/BB | slow; run on request |
| test_address_maps.py | BB + WB (leaf.rs address map tests) + PAR | |
| test_integrity.py | BB + WB + PAR | |
| test_jobowner.py | BB + WB + PAR | |
| test_localio.py | BB (see quirks) | |
| test_import_cost.py, test_mcp_native.py, test_tool_mapping.py, test_parity_surface.py, test_durable.py, test_locks.py | BB | |

## PAR cases (tests/test_rust_parity_engine.py)

EngineError text of 1500 random answers; `_script_action` over request bodies and `@file` forms; `wedge_signal` over random
replies; `inspect_engine` over many temporary installs; `engine_release` over odd jars; `_client_stamps` over generated library
texts; `daemon_config` over random settings (including key order); catalog hash, tool table (property order), instructions,
`not_available`; `_check_call` over 1500 random calls; hex bytes; `_job_listing`; `_sha256_arg`, `_image_base_arg`, `_md_path`;
`_list`, `_options_bag`, `_script_options`, backups op; address-map `_normalize` over 1500 maps plus a 20000-row map;
red4ext lookups over generated tables and chunk sizes; integrity scan over generated projects; job owner check; forbidden
drives; bounded shared reads; address parsing.

## Quirks kept (Python behaviour reproduced, not fixed)

* `int(text, 0)` accepts PEP 515 underscores after a base prefix (`0x_ff`) and any Unicode decimal digit; hy-query's `py_int0`
  does not, so `api::parse_address` and `api::prologue_image_base` answer `Fallback` for text containing `_` or non-ASCII.
* `str.splitlines`, `str.strip` and `\s` use Python's whitespace set (including `\x1c`-`\x1f`); `pytext` reproduces it. Python
  `re` matches bytes with `(?-u)` rules; the Rust patterns use `(?-u)` where the original reads bytes.
* serde_json turns integers past 64 bits into floats silently; `parse_json`/`has_big_integer` route those inputs to `Fallback`.
* `serde_json` is built with `preserve_order` build-wide, but no Rust here relies on map iteration order: output key order is
  built explicitly.
* `localio.read_bytes` is routed to Rust only while the ctypes seam is untouched: tests that patch `_kernel` or its functions
  (`CloseHandle`, `CreateFileW`) specify the Python reader, so the Python reader serves while a patch is visible.
* `api.catalog_hash` is answered by Rust only for the table `tool_table()` makes (a replaced table runs the original).

## Python behaviour worth reporting (not changed)

* `api._script_options` accepts `{"as": ...}` only through the registered handler, which raises a different `ValueError`
  ("ghidra_run options take isolation and readonly (and as); not as"); the validation in `_script_options` itself lets it
  through. The Rust `script_options_dispatch` models only the validation up to the hand-off.
* `api.not_available(capability, message, **detail)` raises `TypeError` for a detail key named `message` or `capability`.

## Not ported (stays Python)

* Process spawning and the engine client: `hydra.Launcher` start, daemon sockets, client loading (`importlib`), install
  (download and unzip), `bump_hydra.py` pin rewriting. Pins stay in `hydra.py` and are passed to Rust as arguments.
* The tool bodies of `api.py` that call the engine, the image or the stores (`_workflow`, `_addr` after the image lookup,
  `dispatch`, `handler`): they are glue over modules routed elsewhere.
* `localio` Windows error paths (kernel32 error codes and filenames on `PermissionError`): Rust answers `None` and the original
  raises with its native spelling.

## Known failures in rust mode that are not from this crate

* `test_client.ImportSlots.test_each_import_names_its_iat_slot_and_a_pattern_filters`: `pe.py` routes `imports_text` to its own
  Rust path, which ignores the test's mocked `pefile` structure. Fails the same way with this crate's routing disabled.
* `test_localio.test_access_denied_keeps_native_code_and_filename_without_retry`: `durable.read_sealed` is routed to hy-core,
  so `backends.read_json` no longer reaches the patched `localio._kernel`. Fails the same way with this crate's routing disabled.
* `test_durable` (10 tests in `AppendLogTests`, `AtomicWrite`, `SealedJson`): they patch `os.replace`, `os.fsync` and the
  localio budget, which hy-core's `durable` route does not honour. The same 10 fail with this crate's routing disabled.
