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
| `function`, `functions`, `decompile`, every other action | no, engine | The engine row carries `signature` and `body`; the snapshot does not read bodies, parameters or data types. `hy_static` has `functions`/`function_at_entry` (id, entry, name, thunk link, calling convention, flags) as library calls only: not routed. |
| symbols by stored name, xrefs from, bytes | library calls only (`staticplane.call`) | No `ghidra_query` action asks them. Compared with the oracle (every symbol row; every function; every memory block against the PE the project was analysed from). |
| Views with pending overlays, working copies | engine | `expected_state` is not None. |

Declined, never guessed: language other than `x86:LE:64:default`; database version outside 19..=33; table versions the
progdb crate refuses; address-map entries for spaces other than the language's (overlays); memory blocks outside `ram`;
uninitialised and mapped memory; programs not marked analysed; a hash different from the target's; a project folder with a
journal or unknown files beside the database (a save in progress); a database file whose size or mtime changed while it was
read; default (`FUN_`, `LAB_`, `DAT_`, `PTR_`...) symbol names; addresses below `ram` offsets Ghidra prints in another shape
are fine (always 8 digits minimum), other spaces are not.

## Layout resolved

`<name>.gpr` (or its folder, or `<name>.rep`) -> `idata/~index.dat` (folders and items) -> `idata/<bucket>/<id>.prp`
(`CONTENT_TYPE` must be `Program`) -> `idata/<bucket>/~<id>.db/db.<N>.gbf`, highest `N`. Packed `.pdb` files are not read.

## Not adopted: engine commit b14434a76b (`query::Program`)

The coordinator offered it. Not taken: its `open` builds every index up front (all symbols, bodies, variables and both
reference tables), which costs memory and time proportional to program size on every open, while xrefs need one key lookup.
The snapshot plus three marked additions (single-address reference lookup) opens in milliseconds. The facade would add
`function` bodies and parameters, but still not the prototype string, so `function` could not be routed exactly either.
Revisit if a question needs bodies.

## Tests

* `tests/oracle_diff.rs`: against `tests/fixtures/oracle/oracleprog-*.txt` (Java) and `flow_fixture.exe`.
* `tests/test_static_plane.py` (Python): routing through `QueryRunner` with an engine stand-in that fails when touched.
* `benchmarks/static_plane.py`: equality with, and time against, the real engine.
