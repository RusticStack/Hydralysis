# Type corpus: bulk types into an analysed program

`ghidra_query action=type_edit` with `options.kind=import_types` applies a whole type
corpus to a target as one cited overlay: structures, unions, enums, typedefs and function
types, plus `this` types and names for functions. It runs as a durable job (`job status
<id>`), in the target's working copy; the canonical project is never written. Reverting the
overlay (`kind=revert`) removes every type and binding it made.

```text
hydralysis ghidra-query --target game --action type_edit --options-file import.json
import.json: {"kind": "import_types", "corpus": "F:/work/types.jsonl",
              "category": "/reflection", "source": "reflection dump of build 1.2.3 (sha256 ...)"}
```

The corpus is copied once under its SHA-256 (`<root>/corpora/`), and the overlay records only
that hash, so a replay never depends on the file you passed. The job's result carries the
import report's counts; the full report (every unresolved type name with its use count, every
conflict and failure) is `<root>/working/<target>/import-<overlay id>.json`.

## Format

One JSON object per line. Every record has `kind`; types may set `category` (default: the
import's `category`, else `/corpus`).

| `kind` | Fields |
|---|---|
| `struct` | `name`, `size` (bytes), `align`?, `parent`? (embedded at offset 0 as `super_<Parent>` when it fits), `fields`: `[{name, offset, type, size?, comment?}]` |
| `union` | `name`, `fields`: `[{name, type, size?}]` |
| `enum` | `name`, `size` (1, 2, 4 or 8), `members`: `[[name, value], ...]` |
| `typedef` | `name`, `type` |
| `function_type` | `name`, `return`?, `params`: `[{name, type}]` |
| `vtable` | `class`, `address` (`rva:`/`va:`/VA), `slots`?, `names`? (one per slot): every slot's function gets `this` = `class *` and, with a name, `<class>_<name>` |
| `function` | `address`, `name`?, `this`?, `signature`? (a C prototype), `comment`? |

`type` strings: a corpus type name, `int8` ... `uint64`, `float`, `double`, `bool`, `char16`,
`void`, `pointer`, any type Ghidra's parser knows (`int`, `char`, `undefined4`, ...), `T *`
and `T[n]`. A name that is none of these becomes bytes of the field's `size` and is
listed under `unresolved` in the report. A field whose type has another size than `size` is
imported as bytes and reported as a conflict; a field that overlaps another (or the
embedded parent) is skipped and reported.

## Where a corpus comes from

Hydralysis contains no reader for any one engine's reflection format. A project converts its
own dump: the records above are enough for RTTI-style class/property/enum dumps, `.h`
headers turned into records, or facts from a project's engine map (a field the reflection
does not list, a vtable address). Function addresses are not in most reflection dumps; a
`vtable` record (or `function` records) is how methods get their `this` type, which is what
turns `*(param_1 + 0x78)` into `this->state` in a decompile.
