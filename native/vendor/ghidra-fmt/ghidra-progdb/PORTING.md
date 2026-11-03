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
| Memory content: `MemoryMapDB.getBytes/getByte`, `MemoryBlockDB.getBytes`, `Buffer/FileBytes/Uninitialized/ByteMapped/BitMapped SubMemoryBlock`, `FileBytes.getModifiedBytes` (layered buffers over the originals), `ByteMappingScheme.getBytes`, `BinaryCodedField` int arrays | `ProgramDb::memory()` -> `Memory::{read, read_byte, block_at, blocks}` | done. `read(addr, len)` follows `Memory.getBytes`: reads on across adjacent blocks, returns fewer bytes where memory ends (no block, or a block whose FIRST part is uninitialized), errors (`ProgError::MemoryAccess`) when zero bytes could be read or when an uninitialized part sits inside an initialized block. Checked byte for byte (SHA-256) against Java for every block of both fixtures plus edge reads (block start, end, past the end, before the start). Mapped blocks are ported from the Java source and unit tested against real memory, but no fixture contains one, so they are NOT checked against Java. Not modelled: overlay spaces (address looked up by space name), the Hydra read snapshot, writes. Mapping cycles give an error (Java would overflow the stack) |
| `SymbolDatabaseAdapterV4/V5` record layout, `SourceType` flag decoding | `ProgramDb::symbols`, `Symbol` | done; `is_primary`/`is_pinned` follow the Java symbol classes. Names of default-named symbols are stored empty (Java computes `FUN_`/`LAB_` names; not ported) |
| `SymbolManager` queries: `getSymbols(String)`, `getSymbols(String, Namespace)`, `getSymbols(Namespace)` / `getChildren`, `getSymbols(Address)`, `getPrimarySymbol`, default function and parameter names, `parseDynamicName` | `ProgramDb::symbol_table()` -> `SymbolTable::{get, name, by_name, by_name_in_namespace, children, at, primary_at, address_string}` | done and equal to Java (ids and order) on both fixtures for: every stored name, every default function / parameter name, every (name, namespace) pair, the children of every namespace and the symbols plus primary symbol at every symbol address. Ordering rules are in the `symtab.rs` module docs: by name = id ascending; by name and namespace = stored locator hash then id (low 32 bits of the address key, then id); children = id ascending without default thunks; at address = id ascending with the last primary symbol swapped into slot 0; primary = first id with the Primary column set. NOT ported: dynamic symbols (`LAB_`/`DAT_` names Java invents for referenced addresses without a symbol), default local variable names, default external names (`name()` gives `None`), symbols by path / regex / prefix scans, `getSymbols(AddressSet)` iterators, word-addressable spaces and non-default RAM spaces in `address_string` |
| `FunctionAdapterV3` ("Function Data"), `ThunkFunctionAdapterV0`, calling convention ids | `ProgramDb::functions`, `Function` | done: id, entry (function symbol address), flags (vararg, inline, noreturn, custom storage, signature source), stack purge / return offset / local size, calling convention name, return storage, thunk link. NOT ported: tags, automatic parameters and the storage Java assigns to parameters of functions without custom storage (computed from the calling convention in the compiler spec), computed stack frame values (`getLocalSize`, `getParameterSize`, `getParameterOffset`; need the compiler spec). Thunks inherit most fields in Java; the oracle only compares the link for thunks |
| `AddressRangeMapDB` ("Range Map - SCOPE ADDRESSES"), `NamespaceManager.getAddressSet`, `VariableSymbolDB`, "Variable Storage" | `ProgramDb::function_bodies`, `ProgramDb::variables`, `AddressRange`, `Variable` | done and equal to Java on both fixtures: merged body ranges of every function (including wrapped records and nested namespaces), `StackReturnOffset`, and 1684 stored parameters / locals (symbol id, owner, kind, name, source, ordinal, first-use offset, data type id, stored storage string). Parameter storage is only compared for functions with custom storage. Ordering: bodies are sorted by (space id, offset); `variables()` is in symbol id order, Java orders by `VariableUtilities.compare` (not reproduced) |
| `FromAdapterV0` ("FROM REFS"), `ToAdapterV1` ("TO REFS"), `RefListV0` entry encoding, `RefListFlagsV0`, `RefTypeFactory` names | `ProgramDb::references_from`, `references_to`, `Reference`, `RefKind`, `ref_type_name` | done: from, to, type, operand index, source, primary, symbol id, offset / shift, the Java class (mem, offset, shifted, external, entry point, stack). NOT ported: TO REFS version 0 (refused), the `Ref Level` column (stored, unused), reference queries by variable |
| `Instructions` (`InstDBAdapterV1`), `Data` (`DataDBAdapterV0`), `Comments` (`CommentsDBAdapterV1`) | `ProgramDb::instructions`, `data`, `comments` | rows only: instruction address, prototype id, flags; data address and data type id (resolved through `data_types()`); the five comment kinds per address. NOT ported: instruction decoding (mnemonic, operands, length needs the language), code unit properties, equates |
| `DataTypeManagerDB` read side: "Categories", "Built-in datatypes", "Composite Data Types" + "Component Data Types", "Enumeration Data Types" + "Enumeration Values", "Typedefs", "Pointers", "Arrays", "Function Definitions" + "Function Parameters", "Calling Conventions"; `DataTypeDB.getName/getPathName/getLength` | `ProgramDb::data_types()` / `data_types_with(DataOrganization)` -> `DataTypes::{get, all, components, enum_values, function_def, categories, category_path, by_path}`, `DataType`, `DataTypeKind`, `Component`, `EnumValue`, `FunctionDef`, `ParameterDef`; `query::Program::{data_types, data_type, data_type_by_path, components, enum_values, function_definition, data_type_at}` | done and equal to Java on both fixtures: every category path, 33 / 308 data types (kind, name, path, length, typedef / pointer / array base, array length, built-in class), every defined component (ordinal, offset, type id, field name, comment, length), enum values (Java `getNames` order), function definition return type, flags, calling convention and parameters, and the type path of every defined data row. Computed names: pointer = `base *` + bit width when the stored length is set (`pointerNN` for a null base), array = innermost base + `[n]` per dimension. Lengths: structures/unions stored length (1 when 0), typedef = base, array = n * element (1 when 0 elements), pointer = stored or `DataOrganization.pointer`, function definition -1, built-ins from a table keyed by the Java class (the compiler-dependent ones `int`, `long`, `wchar_t`, pointers come from `DataOrganization`, default Windows x64; dynamic types report -1; an unknown built-in class gives `size = None`). The id tag (`id >> 56`) selects the table. NOT ported: bit-field components (the encoded id is kept raw), packing / alignment / flexible arrays / `getAlignedLength`, source archives and universal ids, settings tables ("Default Settings", "Instance Settings") and parent/child tables, data type queries by name or category listings, data of a type at an address beyond the stored row (component expansion), built-in classes not in the table |
| `EquateManager` ("Equates", "Equate References"), `BookmarkDBManager` ("Bookmark Types", "Bookmarks<typeId>"), `RelocationManager` + `RelocationDBAdapterV6` ("Relocations"), `BinaryCodedField` long arrays | `ProgramDb::{equates, bookmarks, bookmark_types, relocations}`, `Equate`, `EquateReference`, `Bookmark`, `Relocation`, `RelocationStatus`, `Relocation::bytes`, `Memory::original_bytes` | done and equal to Java. Equates (name, value, reference address / operand index / dynamic hash) and relocations with a stored status other than SKIPPED exist only in the synthetic fixture (see below); bookmarks (6, 98) and 778 relocations are in the real ones. Relocation status and length come from the flags byte, values from the long array (null array kept as `None`), and for a status that has bytes the original file bytes are read from the "File Bytes" chain buffers (not the layered ones) when none are stored. NOT ported: relocation tables older than V6 (refused), mapped blocks in `original_bytes` (read as 0), bookmark/equate/relocation writes, `Equate.getDisplayName` enum lookups, bookmark type icons and colors |
| `ProgramRegisterContextDB` ("Range Map - Register_*"), `AddressRangeMapDB` | `ProgramDb::register_values`, `RegisterValueRange` | done and equal to Java for the stored base register ranges (address range, mask and value bytes): 37 GS_OFFSET ranges in the analysed fixture, RAX / GS_OFFSET in the synthetic one (a sub register `AL` write shows up merged into the RAX mask). NOT ported: language and compiler specification default values, per-instruction context ("ContextTable", "Prototypes"), values of sub registers computed from the base value |
| `OptionsDB` ("Property Table"), `DBPropertyMapManager` ("Properties", "Property Map - *") | `ProgramDb::{options, property_maps}`, `ProgramOption`, `PropertyMap`, `PropertyKind`, `PropertyValue` | done and equal to Java: option key, `OptionType` ordinal and stored string value (a date is milliseconds, a custom option its stored XML); registered Int / Long / String / Void maps with every address and value. Options Java only registers with defaults are not stored and not listed. NOT ported: object (`Saveable`) maps beyond their kind and entry addresses, internal maps that are not registered (for example "Property Map - Lengths", "Property Map - CallFixup" is registered and is read), decoding of option values by type |
| `ExternalManagerDB`, `NamespaceManager`, `LibraryDB`, `GhidraClassDB` (all symbol rows) | `ProgramDb::{namespaces, external_libraries, external_locations}`, `SymbolTable::path`, `NamespaceInfo`, `NamespaceKind`, `ExternalLibrary`, `ExternalLocation` | done and equal to Java on all three fixtures: 73 external locations (one library) in each real fixture, libraries and their paths, locations with original imported name / external program address / source / function flag / namespace, namespaces and classes with `::` paths and parents, and the path of every label and function that lives in a namespace. `getExternalLocations(lib)` returns only the library's direct children, as Java does (locations in a namespace below the library are not listed). NOT ported: external location lookups by address or by label, the `<UNKNOWN>` library, the class hierarchy beyond the parent chain (Ghidra stores no inheritance), writes |
| Query facade for bindings | `ghidra_progdb::query::Program` (`open_file`, `open`, `parse_address`, `functions`, `function_at`, `function_containing`, `function_by_id`, `symbols_by_name`, `symbols_at`, `children`, `xrefs_to`, `xrefs_from`, `read_bytes`, plus the lazily read data types, equates, bookmarks, relocations, register values, options, property maps, namespaces, external libraries and locations above) | done. Owned data only, `Send + Sync` whenever the buffer store is. `Program::open` builds the symbol table, the function index and the reference maps up front (errors surface at open; the Symbols table is now read once instead of four times); `Program::open_lazy` / `open_file_lazy` build nothing at open (cost: header, address map, table directory) and each index on first use, with the infallible accessors answering empty and `deferred_error()` keeping the message if a table turns out to be damaged (`prepare()` builds everything and returns the error). Numbers in "Open cost" below. `tests/query.rs` checks it against the oracle output on both fixtures. Module docs state the ordering of every list |
| older table versions (symbol V0..V3, memory V0..V2, address map V0) | `UnsupportedTableVersion` | refused on purpose: Java upgrades these |

## Open cost

Measured on Windows 11 (NTFS, warm file cache, release build, `examples/open_bench.rs` for Rust,
`oracle/OracleOpenBench.java` on stock Ghidra 12.2 / JDK 27 for Java), three runs each, peak
working set sampled from outside every 5-10 ms while the process holds for 250-400 ms after the
work. "open" is the time of `Program::open*` (Rust) and of `new DBHandle` + `new ProgramDB`
(Java, `OpenMode.IMMUTABLE`) after the Ghidra application was initialized. The Java open (1.5-1.7 s)
is mostly class loading and language definitions; application initialization adds 1.04-1.15 s and the
whole Java process is ready after 2.6-2.9 s.

| fixture | program size | Java open | Java peak RSS | Rust eager open | Rust lazy open | Rust eager peak RSS | Rust lazy peak RSS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| legacy-12.1.4 | 385 symbols, 0 instructions, 1.5 MB file | 1.49-1.65 s | 263-309 MB | 2.2-2.8 ms (before the single symbol read: 3.1-4.3 ms) | 0.24-0.52 ms | 6.6 MB (before: 6.7-7.2 MB) | 4.9 MB |
| legacy-12.1.4-analysed | 2912 symbols, 15014 instructions, 9813 reference rows, 3.7 MB file | 1.54-1.67 s | 330-343 MB | 12.2-14.6 ms (before: 15.2-25.5 ms, one 46 ms outlier) | 0.32-0.47 ms | 15.7-15.8 MB (before: 16.1-16.2 MB) | 7.2-7.3 MB |

* After open, the first query that needs an index pays for it: functions (symbol table, function
  index, bodies, variables) 1.2-1.6 ms and 4.1-4.5 ms, references 1.1-1.9 ms and 7.2-7.8 ms, for
  the two fixtures. `read_bytes` and everything outside the symbol / function / reference
  accessors need no index (0.05-0.16 ms). Java answers the same five queries (function count,
  first function's references to and from, 16 bytes, symbols at the entry) in 6.8-8.1 ms and
  10.6-12.8 ms in the same JVM right after the open.
* Eager open grows linearly with the program (about 4-5 ms per 1000 symbols plus reference rows
  here); lazy open does not (it reads the "Program" table, the address map and the table
  directory). A multi-million-symbol program was not measured: no such fixture exists here, so
  larger sizes are an extrapolation of the two points above.
* Memory of an index is dominated by `Address` values (an owned space name per address) in the
  symbol and reference maps; `Address` is public API, so it was not changed. Peak RSS includes
  the process image (about 4.9 MB for an empty run).

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
  address like the oracle, plus the SHA-256 of every memory block's bytes and edge reads, with `testdata/oracleprog-*.txt`. Those files come from
  `oracle/OracleProgram.java`, which opens the same files through the stock Ghidra 12.2
  `ProgramDB` (`OpenMode.IMMUTABLE`). See `oracle/README.md` for the command line.
* The synthetic fixture `testdata/synth/progdb-synth-33.gbf` (1.9 MB, stored version 33, Symbols
  table V5) covers what the real fixtures lack. `oracle/OracleMutate.java` opens a copy of
  `legacy-12.1.4` with the stock `ProgramDB` for upgrade (`OpenMode.UPGRADE`), adds equates,
  bookmarks, relocations, namespaces, classes, external libraries and locations, register values,
  property maps and options, and saves a new buffer file; `testdata/oracleprog-synth-33.txt` is
  the oracle output for it. The Rust test compares every section (including the ones checked on
  the real fixtures, now on a V33 database) line by line.
* `tests/versions.rs`: a copy of the fixture with the stored version patched to 33, 19, 34, 18
  and 10 opens or is refused with the expected error.
* There is no v33 fixture in the repository; v33 is covered only by the patched-version test (the
  table layouts of 32 and 33 are the same in the files we have).
* Not covered: refusal of old table versions (no fixture has one), overlay and mapped blocks,
  segmented spaces.
