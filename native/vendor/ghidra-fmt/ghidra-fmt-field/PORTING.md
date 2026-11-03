# ghidra-fmt-field porting notes

Source: `db.Field`, `ByteField`, `ShortField`, `IntField`, `LongField`, `BooleanField`,
`StringField`, `BinaryField`, `FixedField`, `FixedField10`, `IndexField`, `LegacyIndexField`,
`PrimitiveField`, `Schema`, `DBRecord`, `SparseRecord`.

## Tests

`Framework/DB/src/test` contains NO unit test for the Field classes or `Schema`; they are only
covered indirectly through the table tests (`DBTestUtils`, `DB*TableTest`, `TableTest`). So there
is nothing to port one-to-one at this level; `src/tests.rs` states the Java semantics directly
(type codes, encodings, ordering, truncation, schema encode/parse, sparse records). The table
tests are ported in `ghidra-fmt-db`. The fixture check (every table schema in both legacy files
parses, and every record re-encodes to identical bytes) is in `ghidra-fmt-db`.

## Mapping

| Java | Rust |
| --- | --- |
| `Field` subclasses | `Field` enum (value) and `FieldType` enum (type) |
| `Field.getField(byte)` | `FieldType::from_code` |
| `getFieldType()` | `FieldType::code` |
| `read(Buffer, off)` / `write` / `readLength` / `length` | `Field::read` / `write` / `read_length` / `length` |
| `compareTo(Field)` / `compareTo(DataBuffer, off)` | `Field::compare` / `compare_to_stored` |
| `Schema` | `Schema` (`from_encoded` = package-private ctor used by `TableRecord`) |
| `DBRecord.read/write/length`, `SparseRecord` | `Schema::read_record/write_record/record_length`, `Record` |

## Behaviours kept from Java on purpose

* Strings compare in UTF-16 code unit order, not code point or byte order.
* Boolean keeps the raw stored byte; any non-zero byte is true and compares by raw value.
* Binary/Fixed10 compare unsigned; a null string/binary sorts before everything.
* A string read from disk keeps its raw bytes and writes them back unchanged.
* `IndexField` truncates long indexed values (stored length >= 64 -> 60 bytes / UTF-16 units);
  a cut surrogate pair becomes `?` as in Java's encoder.
* `LegacyIndexField` (primary nibble 8) is variable length, reads as indexed + long, and writes its
  type code with a LONG primary nibble (0x3X), so it is not re-encoded as 0x8X.
* Schema sparse extension: after the `0xff` indicator exactly one extension block is allowed; a second
  block is read as extension type -1 and refused. Names use `StringTokenizer` semantics (empty
  tokens vanish).
* Fixed length of a schema is the sum of the column lengths (0 when any column is variable or sparse).

## Deliberate differences

* Null state of primitive fields is not modelled (it never reaches storage). Only null
  strings/binaries and absent sparse columns exist.
* Malformed UTF-8 in a string decodes with Rust's replacement rules; the raw bytes are preserved so
  writing is exact, but a comparison of such strings may differ from Java.
* Sparse columns are encoded in ascending order (Java iterates an unordered set).
* Type mismatches return `FieldError::TypeMismatch` instead of `ClassCastException`.

## Not ported

`BinaryCodedField` (application-level coded arrays/strings stored in binary fields),
`DBRecord` mutators/accessors beyond read/write/length, `getMinValue/getMaxValue`,
`copyField/newField`, `hashCode`, `toString`.
