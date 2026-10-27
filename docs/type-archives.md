# Cited type archive imports

`ghidra_query` action `type_edit` accepts an archive as a durable bulk job:

```json
{"kind":"import_archive","archive":"F:/work/types.gdt","paths":["/Example/MyType"],"source":"link to the type archive and how it was produced"}
```

Pass this object as the query `options`. Poll the returned overlay job, and use
its `overlay_id` to revert the imported types as one edit. The selected target
and optional named view determine which working copy receives the types; the
canonical analysed project remains unchanged. Named views require the expected
revision as for other edits.

Hydralysis copies the archive into its own data root, records the full SHA-256 and
size in the cited overlay, and checks the stored bytes on each replay. The
source archive is not needed for replay. A whole-archive import requires equivalent
data organizations. To select up to 200 exact type paths from an archive with a
different organization, supply `paths`. Every selected type and its dependencies
must pass recursive checks for size, alignment, component offsets, bitfields,
pointer widths, arrays, typedefs, enums and signatures; unsupported kinds,
Ghidra archive warnings and conflicting definitions cause the entire edit to
roll back. Archive imports are bounded to 1 GiB and run as jobs.
The source citation and imported types are assertions for the user to review,
not proof of a binary's original source layout.
