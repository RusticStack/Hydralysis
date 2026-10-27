# Cited build-specific address maps

Import a JSON file using `ghidra_query` with `action: "address_map"`, a
registered `target`, and `options: {"path": "<absolute path>"}`. The file has
this shape (replace the example hash and citation with real evidence):

```json
{
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "source": "linker map for this build, row 17",
  "entries": [
    {"name": "example", "hash": "0x1234", "rva": "0x5678"}
  ]
}
```

Each row needs a name or a hexadecimal hash and an explicit hexadecimal RVA;
it can override `source` with a more specific citation. The map's full SHA-256
must match the selected build. Imports are stored by content hash under the
RusticRE root. Use `name:example` or `hash:0x1234` as the address in PE tools
or `ghidra_query`; results include the matching map citations. Names are exact,
and hashes are interpreted as numbers. Conflicting RVAs fail as ambiguous.
An imported row is a cited assertion, not proof that an inferred mapping is
correct or permission to install a hook: check the build and exact live bytes.

Maps are limited to 16 MiB, 100,000 entries and 32 maps per build. Imports do
not modify a Ghidra project or execute the target.
