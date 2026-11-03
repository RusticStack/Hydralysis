# ghidra-progdb porting notes

Source: `ghidra.program.database.ProgramDB` (open, version policy, metadata map via
`DBStringMapAdapter`), `map.AddressMapDB` + `AddressMapDBAdapterV1`, `mem.MemoryMapDBAdapterV3`,
`MemoryBlockDB`, `SubMemoryBlock`, `symbol.SymbolDatabaseAdapter` (V4/V5 record layout).
Read-only. Upgrades stay in Java.

## Status

| Java | Rust | State |
| --- | --- | --- |
| `ProgramDB` open: stored version check (`DB_VERSION` 33, `UPGRADE_REQUIRED_BEFORE_VERSION` 19) | `ProgramDb::open`, `ProgError::{NewerVersion, UpgradeRequired, UnsupportedTableVersion}` | done; 19..=33 opens (Java opens 19..32 read-only through old adapters), anything else is refused |
| "Program" string map (`Language ID`, `Compiler Spec ID`, `Image Offset`, `DB Version`, ...) | `ProgramDb::metadata`, `language_id`, `compiler_spec_id`, `image_base_offset` | done |
| `AddressMapDBAdapterV1` + `AddressMapDB.decodeAddress` | `AddressMap::decode` | done for absolute, relocatable (image base, wrap), register, stack, external, variable, hash, `NO_ADDRESS`, `EXT_FROM`. NOT ported: old key type 0, namespace-qualified register/stack/external keys (`OldGenericNamespaceAddress`), segmented spaces, overlay spaces |
| `AddressMapDB.getKey` / encode | none | NOT ported (read-only) |
| `MemoryMapDBAdapterV3`, `MemoryBlockDB.refresh` | `ProgramDb::memory_blocks`, `MemoryBlock`, `SubBlock` | done (sorted by start address). Overlay detection, mapped-block targets and `isInitialized` of mapped blocks (Java asks the source) are NOT ported |
| `FileBytes` table | none | NOT ported (blocks reference it by id only) |
| `SymbolDatabaseAdapterV4/V5` record layout, `SourceType` flag decoding | `ProgramDb::symbols`, `Symbol` | done; `is_primary`/`is_pinned` follow the Java symbol classes. Names of default-named symbols are stored empty (Java computes `FUN_`/`LAB_` names; not ported) |
| `SymbolManager` queries (by name, namespace paths, references) | none | NOT ported |
| `FunctionAdapterV3` ("Function Data"), `ThunkFunctionAdapterV0`, calling convention ids | `ProgramDb::functions`, `Function` | done: id, entry (function symbol address), flags (vararg, inline, noreturn, custom storage, signature source), stack purge / return offset / local size, calling convention name, return storage, thunk link. NOT ported: function body (address set), parameters and locals ("Variable Storage"), stack frame, tags. Thunks inherit most fields in Java; the oracle only compares the link for thunks |
| `FromAdapterV0` ("FROM REFS"), `ToAdapterV1` ("TO REFS"), `RefListV0` entry encoding, `RefListFlagsV0`, `RefTypeFactory` names | `ProgramDb::references_from`, `references_to`, `Reference`, `RefKind`, `ref_type_name` | done: from, to, type, operand index, source, primary, symbol id, offset / shift, the Java class (mem, offset, shifted, external, entry point, stack). NOT ported: TO REFS version 0 (refused), the `Ref Level` column (stored, unused), reference queries by variable |
| `Instructions` (`InstDBAdapterV1`), `Data` (`DataDBAdapterV0`), `Comments` (`CommentsDBAdapterV1`) | `ProgramDb::instructions`, `data`, `comments` | rows only: instruction address, prototype id, flags; data address and data type id; the five comment kinds per address. NOT ported: instruction decoding (mnemonic, operands, length needs the language), data type resolution, code unit properties, equates |
| data types, equates, bookmarks, properties | none | NOT ported |
| older table versions (symbol V0..V3, memory V0..V2, address map V0) | `UnsupportedTableVersion` | refused on purpose: Java upgrades these |

## Address spaces

The database stores space names only. The caller passes `AddressSpaces` (name, id, bits, default
space) taken from the language; the differential test reads them from the oracle output. The
static `EXTERNAL`, `VARIABLE` and `HASH` spaces are added when missing.

## Tests

* `tests/oracle_diff.rs`: for both checked-in v32 fixtures (`legacy-12.1.4`,
  `legacy-12.1.4-analysed`) compares stored version, language, compiler, image base, every memory
  block with its sub blocks (name, start, end, size, flags, comment, source, parts) and every row
  of the symbol table (385 and 2912 rows: id, name, decoded address, parent, type, source,
  primary, pinned), every function (id, entry, thunk link, flags, calling convention, purge, signature
  source), every reference from and to an address (not stack/register destinations: Java refuses
  them), the instruction addresses, defined data (address, type id) and all comments, sorted by
  address like the oracle, with `testdata/oracleprog-*.txt`. Those files come from
  `oracle/OracleProgram.java`, which opens the same files through the stock Ghidra 12.2
  `ProgramDB` (`OpenMode.IMMUTABLE`). See `oracle/README.md` for the command line.
* `tests/versions.rs`: a copy of the fixture with the stored version patched to 33, 19, 34, 18
  and 10 opens or is refused with the expected error.
* There is no v33 fixture in the repository; v33 is covered only by the patched-version test (the
  table layouts of 32 and 33 are the same in the files we have).
* Not covered: refusal of old table versions (no fixture has one), overlay and mapped blocks,
  segmented spaces.
