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
non-ASCII names (Java clips UTF-16 units), database files over 48 MiB when the rows must be
built (building reads the whole symbol and function tables; rows already cached are served at any size), and programs whose
rows alone exceed the cache budget.

## Cache and handles

A process-local cache (`cache.rs`) keeps, per program, what was parsed: the identity, memory blocks and file-bytes ids
(`Meta`) and, after the first function question, every internal function's finished row with its body ranges
(`FunctionData`). Both are plain memory. **No file handle is kept**: the program is opened lazily (`open_file_lazy`) only
when a question must read the file (references, bytes, symbols, or a cache fill), and closed when the call ends; a hit on
`function`/`functions` opens nothing. Windows can rename, replace or delete the project at any time (tested).

* Key: canonical project path plus program path.
* Validation before every use, `stat` only: size and write time of `db.N.gbf`, `~index.dat`, the `.prp` file, and the
  *absence* of `~index.jrn`; write time of the `~<id>.db` folder and of `idata` (they move when a new version, a save file or
  a journal appears). Any difference drops the entry and the files are read again; a project with a save in progress (an
  unknown file beside the database, a journal) is then declined exactly as on a first read. The marks are taken before the
  read and compared after it, so a change during the read is a `Failed`, never an answer.
* Budget: entries are charged by an estimate of their bytes (fixture: about 140 KB for 405 functions) and evicted least
  recently used first. Default 64 MiB; `HYDRALYSIS_STATIC_CACHE_MB` sets it (the global cache reads it once). Function rows that
  alone exceed the budget are not kept, and the plane declines `function`/`functions` for that program version (remembered,
  so the build is not repeated) and the engine answers; budget 0 means the same for function questions, while `xrefs` is still
  answered. `staticplane.cache_stats()` / `cache_clear()` expose counters (entries, bytes, budget, hits, misses, evictions,
  invalidations, builds).

## Routing policy

All three actions are routed to the Rust plane whenever it answers, with no daemon-liveness check: with the cache each is
faster than the warm engine at p50 (table below), and with no daemon running it also saves the engine start. The engine
answers only what the plane declines. The costs that remain are the first `function`/`functions` question per program
version (it builds the rows: 4-5 ms on the fixture, more on big programs, hence the 48 MiB gate) and one cache entry per
program in memory.

## Layout resolved

`<name>.gpr` (or its folder, or `<name>.rep`) -> `idata/~index.dat` (folders and items) -> `idata/<bucket>/<id>.prp`
(`CONTENT_TYPE` must be `Program`) -> `idata/<bucket>/~<id>.db/db.<N>.gbf`, highest `N`. Packed `.pdb` files are not read.

## Measured (fixture legacy-12.1.4-analysed, 405 functions; `benchmarks/static_plane.py --passes 5`)

Median / p95 ms per query through `QueryRunner` (1000 xrefs, 1985 function, 5 and 15 functions requests per column; the
machine is shared with other jobs, so absolute values move by 20-40% between runs). Answers equal the engine's in every
compared request (200 xrefs, 397 function rows, 4 functions pages; 0 differences).

| action | rust (cached) | engine warm daemon | engine cold daemon | rust vs warm |
| --- | --- | --- | --- | --- |
| xrefs | 0.69 / 0.88 | 1.38 / 1.79 | 1.70 / 2.64 | 2.0x faster |
| function | 0.51 / 0.66 | 1.41 / 1.74 | 1.51 / 2.02 | 2.8x faster |
| functions, limit 200 (1 page answered) | 0.56 / 0.56 | 1.64 / 1.73 | 1.60 / 1.65 | 2.9x faster |
| functions, filtered, limit 20 | 0.68 / 0.71 | 1.65 / 1.78 | 1.71 / 1.96 | 2.4x faster |

First question of an action in a fresh process: `function` rust 4.4 ms (builds the rows) against 1.4 ms warm engine;
`xrefs` rust 8 ms (loads the extension, opens the project) against 320 ms warm engine in a fresh client and 4.0 s with a
cold daemon (first query of the process: rust 1.7 ms, engine cold daemon 4.0 s; earlier runs 10-18 s and 126 s). Memory: the
cache held 140 KB; the Rust plane grew the Python process by 4 MB (peak 30 MB); the daemon JVM was at 342 MB (peak 391 MB).
Before the cache (per-call index): `function` 4.8-6.9 ms, `functions` 5.6-8.2 ms, 2.5-4x slower than the warm engine.

## Tests

* `tests/oracle_diff.rs`: against `tests/fixtures/oracle/oracleprog-*.txt` (Java) and `flow_fixture.exe`.
* `tests/cache.rs`: cached answers equal the engine's recorded ones (and the first answer); a changed write time or size invalidates; a save file or journal drops the entry and is declined; the byte budget evicts least recently used, rows over the budget are declined once; no handle (the folder is renamed and deleted while entries are held).
* `tests/engine_truth.rs`: against answers recorded from the real engine (`tests/fixtures/engine/*.json`, written by a dumper that asks the live daemon): `function` per function entry, `functions` pages.
* `tests/test_static_plane.py` (Python): routing through `QueryRunner` with an engine stand-in that fails when touched.
* `benchmarks/static_plane.py`: equality with, and time against, the real engine per action (xrefs, function, functions), cold and warm, with memory.
