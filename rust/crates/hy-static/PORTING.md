# hy-static: the JVM-free static read plane

Not a port of one Python module: a second way to answer some `ghidra_query` questions. `query.py` normally runs
`RusticQuery.java` in the Hydra Engine daemon. With `HYDRALYSIS_IMPL=rust` and `hydralysis_native` built,
`QueryRunner._ask` first asks `hydralysis.staticplane`, which calls `hy_static` (through `native/src/static_plane.rs`).
`hy_static` opens the program's `db.N.gbf` read-only through the vendored `ghidra-progdb`
(`native/vendor/ghidra-fmt`, engine commit 13e7458cc3, see its `VENDORED.md`). A refusal is `None` in Python and the
engine path runs unchanged. Python default is unchanged.

## What is answered natively, what falls back

| Question | Native? | Notes |
| --- | --- | --- |
| `ghidra_query action=xrefs` (to an address, `limit`, `cursor`, `va:`/`rva:`/`0x`) | yes, routed | Same JSON as `RusticQuery`: envelope, `references[from,to,type]`, `truncated`, `next_cursor`. Compared with the Java oracle (2648 lists, 13034 empty) and with the real engine (200 addresses, equal). Lists holding offset, shifted, external or stack references, or from/to outside the default space, are declined. |
| `ghidra_query action=function` (address inside a function) | yes, routed | `{address,name,signature,body,body_truncated}` built from the stored tables: `getFunctionContaining`, `getPrototypeString(false,false)` from the return type and the stored parameters, body ranges. Compared with 405 rows recorded from the real engine: 397 equal, 8 declined, 0 different. |
| `ghidra_query action=functions` (`limit`, `cursor`, `contains`) | yes, routed | Internal functions in entry order with the engine's scan cap and `next_cursor`. A page is declined as a whole when any returned row needs a declined function. Real engine pages: 1 of 3 answered and equal, 2 declined (thiscall rows). |
| `decompile`, `types`, `type`, `data`, `blocks`, every other action | no, engine | Needs what the snapshot does not give exactly: data-type alignment and class names, type order, default value strings, instruction decoding. `hy_static` library calls (`info`, `read_bytes`...) exist, no action routes to them. |
| symbols by stored name, xrefs from, bytes | library calls only (`staticplane.call`) | No `ghidra_query` action asks them. Compared with the oracle (every symbol row; every function; every memory block against the PE the project was analysed from). |
| Views with pending overlays, working copies | engine | `expected_state` is not None. |

Declined, never guessed: language other than `x86:LE:64:default`; database version outside 19..=33; table versions the
progdb crate refuses; address-map entries for spaces other than the language's (overlays); memory blocks outside `ram`;
uninitialised and mapped memory; programs not marked analysed; a hash different from the target's; a project folder with a
journal or unknown files beside the database (a save in progress); a database file whose size or mtime changed while it was
read; default (`FUN_`, `LAB_`, `DAT_`, `PTR_`...) symbol names.

Extra declines for `function`/`functions` (the prototype is Ghidra's, not just the stored rows): thunks (of externals; a thunk
of an internal function takes that function's return type and parameters), custom variable storage, inline, variadic,
calling conventions other than `__fastcall`/`__stdcall`/`__cdecl`/`unknown`/`default` (`__thiscall` adds `this`: automatic
parameters are not ported), return types that are structures, unions, arrays or unresolved (hidden `__return_storage_ptr__`),
non-ASCII names (Java clips UTF-16 units), and database files over 48 MiB (no cache is kept, so the function index is rebuilt
on every call; above that size the engine's warm daemon is faster).

## Handles

The program is opened lazily on every call (`open_file_lazy`: no table is read until asked) and dropped when the call ends.
Nothing is cached between calls, so no file stays open: Windows can rename or replace the project files at any time. The
`db.N.gbf` size and mtime are checked before and after the read.

## Layout resolved

`<name>.gpr` (or its folder, or `<name>.rep`) -> `idata/~index.dat` (folders and items) -> `idata/<bucket>/<id>.prp`
(`CONTENT_TYPE` must be `Program`) -> `idata/<bucket>/~<id>.db/db.<N>.gbf`, highest `N`. Packed `.pdb` files are not read.

## Measured (fixture legacy-12.1.4-analysed, 405 functions; `benchmarks/static_plane.py`, machine shared with other jobs)

Median ms per query through `QueryRunner`, two runs (the second with other agents busy). Answers equal the engine's in every
compared request (200 xrefs, 397 function rows, 4 functions pages; 0 differences).

| action | rust (no JVM) | engine cold daemon | engine warm daemon |
| --- | --- | --- | --- |
| xrefs | 0.92 / 1.21 | 2.4 / 3.1 | 1.6 / 2.4 |
| function | 4.8 / 6.9 | 2.0 / 3.1 | 1.7 / 2.7 |
| functions (limit 200, 1 page answered) | 8.2 / 8.0 | 4.0 / 4.2 | 1.8 / 3.8 |
| functions (filtered, limit 20) | 5.6 / 6.6 | 2.7 / 2.5 | 2.1 / 3.5 |

First query of a fresh process: rust 2.5 / 4.7 ms; engine with no daemon 18.4 / 10.4 s (round 1: 126 s); engine with a warm
daemon 0.03-1.1 s. So xrefs is faster than the warm engine, `function`/`functions` are about 2.5-4x slower per call (the
function index is rebuilt on every call because nothing is cached) but need no JVM and no daemon start. Memory: the Rust
plane grew the Python process by 6 MB (peak 32 MB total); the daemon JVM was at 309 MB (peak 361 MB) for the same fixture.

## Tests

* `tests/oracle_diff.rs`: against `tests/fixtures/oracle/oracleprog-*.txt` (Java) and `flow_fixture.exe`.
* `tests/engine_truth.rs`: against answers recorded from the real engine (`tests/fixtures/engine/*.json`, written by a dumper that asks the live daemon): `function` per function entry, `functions` pages.
* `tests/test_static_plane.py` (Python): routing through `QueryRunner` with an engine stand-in that fails when touched.
* `benchmarks/static_plane.py`: equality with, and time against, the real engine per action (xrefs, function, functions), cold and warm, with memory.
