# ghidra-fmt: vendored Rust readers for Ghidra project databases

Original: `Ghidra/Framework/HydraFormats` of the Hydra Engine (RusticStack/hydra-engine, a fork of
NationalSecurityAgency/ghidra), Apache-2.0 (`LICENSE`, `NOTICE` copied from the engine root).
Source commit: `75f489388b` (`Merge branch 'r/engine-fmt' into h7/integration`), taken with `git archive`, so the
snapshot is the committed tree, not the moving working tree of the lane.

Kept: `ghidra-fmt-bytes`, `-gbf`, `-chain`, `-field`, `-btree`, `-db` and `ghidra-progdb` with their `PORTING.md`.
Dropped: `ghidra-fmt-pack` (packed `.pdb` import/export, not needed to read a project in place), every crate's `tests/`
directory and the engine's `testdata/` and `oracle/` (they need the engine's fixtures; Hydralysis checks the same
reader through `rust/crates/hy-static/tests`, against its own copies of the fixtures and of the Java oracle output).

Changes against the original. `Cargo.toml` here is the engine workspace manifest reduced to these crates, so the crate
manifests (which inherit from it) stay byte-identical. Source files carry no licence header in the original; the licence is
the `LICENSE` in this folder. Three small additions to `ghidra-progdb`, each marked `HYDRALYSIS ADDITION` in the source,
because the snapshot reads whole reference tables and Hydralysis needs a lookup of one address:

- `AddressMap::encode_default(offset)` in `addrmap.rs`: `AddressMapDB.getKey(addr, false)` for the default space;
- `references::read_one` in `references.rs`: one reference list found by key in "TO REFS" / "FROM REFS";
- `ProgramDb::references_to_at` / `references_from_at` in `lib.rs`.

Nothing else is changed. The engine lane that owns the original is adding its own `query` facade and byte reader
(`memread.rs`, `get_into_over` in `ghidra-fmt-chain`) in its working tree; this snapshot has neither, so
`rust/crates/hy-static` reads layered file bytes through `ChainedBuffer::open_with_source`. On the next refresh, replace
the additions by the engine's own lookups if they exist, and keep `rust/crates/hy-static/tests` passing (they compare
against the Java oracle output, not against this code).

To refresh: `git -C <engine> archive <commit> Ghidra/Framework/HydraFormats`, copy the same seven crates, update the
commit above and the row in `THIRD_PARTY.md`, rerun `cargo test -p hy-static` in `rust/`.
