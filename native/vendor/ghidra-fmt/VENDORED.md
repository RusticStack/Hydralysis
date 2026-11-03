# ghidra-fmt: vendored Rust readers for Ghidra project databases

Original: `Ghidra/Framework/HydraFormats` of the Hydra Engine (RusticStack/hydra-engine, a fork of
NationalSecurityAgency/ghidra), Apache-2.0 (`LICENSE`, `NOTICE` copied from the engine root).
Source commit: `13e7458cc3` (`Merge branch 'r/engine-fmt' into h7/integration`; round 1 was `75f489388b`), taken with `git archive`, so the
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

Nothing else is changed. This snapshot has the engine's `query::Program` facade with lazy open (`open_file_lazy`);
`rust/crates/hy-static` uses it for functions, bodies, parameters and data types. The facade's `xrefs_to` builds the whole
reference table on first use, so xrefs keep using the additions above (one key lookup). On the next refresh, drop the
additions if the engine grows an equivalent, and keep `rust/crates/hy-static/tests` passing (they compare against the Java
oracle output and the real engine, not against this code).

To refresh: `git -C <engine> archive <commit> Ghidra/Framework/HydraFormats`, copy the same seven crates, update the
commit above and the row in `THIRD_PARTY.md`, rerun `cargo test -p hy-static` in `rust/`.
