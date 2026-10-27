# Cross-build transfer and hook candidates

`ghidra_query` action `diff` takes `options.against` as the source target and the
requested target as the destination. Both projects must already be analysed. The
JSONL diff records the match method and confidence. A match is a hypothesis: even
identical code can be duplicated, and changed code can match an unrelated function.

If `options.checks` points to a source hook table, both targets must also have their
original executables registered. The table can be a canonical `checks` array or a
`hooks` envelope containing `offset`, `names` and `prologue`. Declare a full
`build_sha256` and `image_base` when known; if present, both must match the source
executable. Use `rva:` or `va:` addresses, or set `offset_kind` to `rva` or `va` in
the envelope. An unqualified legacy offset is accepted only when exactly one of its
VA and RVA interpretations is file-backed. Every source prologue must match the
source bytes; a wrong hash, base, ambiguous address or prologue stops the job before
fingerprinting. Wildcards are recorded as such, not asserted as verified bytes.

The output `checks-destination.json` is a **candidate report**, not a prologue table:
its `candidates` preserve source aliases and records, both build fingerprints,
matching method and confidence, and bytes observed in the destination executable.
The observed bytes do not establish that the candidate is the intended function.
Each correspondence needs independent cited evidence, followed by a separate table
with the independently verified destination addresses and expected bytes. Run the
normal prologue check against the correct destination build and require a successful
live-byte check immediately before installing a hook. The candidate report cannot
be passed directly to `prologue --checks-file` as if it were an approved table.
Unmapped candidates and candidates without file-backed destination bytes are
reported under `unplaced`.

`names.jsonl` contains candidate function names and comments suitable for a reviewed
`import_types` corpus. Review the match and destination function before applying
it; an import is a reversible assertion, not proof of equivalence. When source overlays exist, `overlays-source-review.json` preserves active original
records (including cited signatures, types, attribution and batch records), source
revision and available revert metadata. An edit at a matched function entry carries
a candidate destination address when the source executable is available. Records
without a reliable match remain available for manual review. Reverted overlay bodies
are not retained by the store, only revert metadata. Bulk-import records cite a corpus
hash; their contents are not expanded in this report. This report never applies edits.
Signatures and types present only inside the analysed project, outside cited overlays,
are not exported automatically. The corpus importer accepts manually prepared
definitions and prototypes; correspondence, type layout and signature also need
independent destination-build evidence. No automatic migration is claimed.
