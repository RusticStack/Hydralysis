//! A small read-only query facade over a Program database, meant to be bound to other
//! languages. Everything here is owned data (no borrows of the open file), so a [`Program`] can be
//! shared behind a lock and its results can be handed across an FFI boundary.
//!
//! ```no_run
//! use ghidra_progdb::query::Program;
//! use ghidra_progdb::{AddressSpaces, SpaceDef};
//!
//! // The database stores space names only; describe the language's spaces.
//! let spaces = AddressSpaces::new(
//!     vec![SpaceDef { name: "ram".into(), id: 3, bits: 64 }],
//!     "ram",
//! );
//! let program = Program::open_file("db.1.gbf", spaces)?;
//! for f in program.functions() {
//!     println!("{} at {}", f.name.as_deref().unwrap_or("?"), f.entry);
//! }
//! let entry = program.parse_address("ram:140001030")?;
//! let callers = program.xrefs_to(&entry);
//! let first_bytes = program.read_bytes(&entry, 16)?;
//! # Ok::<(), ghidra_progdb::ProgError>(())
//! ```
//!
//! # Semantics
//!
//! Every answer is the answer Java's `ProgramDB` gives (checked by the differential tests against
//! the stock oracle), with the limits listed in `PORTING.md`: no dynamic symbols, no default local
//! variable names, no automatic parameters, no computed stack frame values, no instruction
//! decoding.
//!
//! # Ordering
//!
//! * [`Program::functions`]: function id ascending.
//! * [`Program::symbols_by_name`], [`Program::symbols_at`], [`Program::children`]: the order of
//!   `SymbolManager`, documented in the `symtab` module.
//! * [`Program::xrefs_from`], [`Program::xrefs_to`]: stored order (the order references were added).
//! * [`FunctionInfo::parameters`]: ordinal ascending; [`FunctionInfo::locals`]: symbol id.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use ghidra_fmt_gbf::{BufferFile, BufferStore};

use crate::{
    Address, AddressRange, AddressSpaces, Bookmark, Component, DataType, DataTypes, EnumValue,
    Equate, ExternalLibrary, ExternalLocation, Function, FunctionDef, NamespaceInfo, ProgError,
    ProgramDb, ProgramOption, PropertyMap, Reference, RegisterValueRange, Relocation, Result,
    Symbol, SymbolTable, Variable,
};

/// A function with everything the stored tables say about it.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// The "Function Data" row joined with its symbol address and thunk link.
    pub function: Function,
    /// Name as Java shows it (`FUN_<addr>` for default names); `None` for default external
    /// functions.
    pub name: Option<String>,
    /// Entry point (`None` only if the function symbol is missing).
    pub entry: Address,
    /// Id of the namespace symbol the function lives in (0 is global).
    pub namespace_id: i64,
    /// Merged address ranges of the body.
    pub body: Vec<AddressRange>,
    /// Stored parameters, ordinal ascending. Automatic parameters are not included, and for
    /// functions without custom storage `storage` is whatever was stored, not what Java assigns.
    pub parameters: Vec<Variable>,
    /// Stored local variables, symbol id ascending.
    pub locals: Vec<Variable>,
}

impl std::ops::Deref for FunctionInfo {
    type Target = Function;

    fn deref(&self) -> &Function {
        &self.function
    }
}

/// The function index: every function with its joined data, by entry and by body range.
struct FunctionIndex {
    functions: Vec<FunctionInfo>,
    by_entry: HashMap<Address, usize>,
    /// (space, min, max, index into `functions`), sorted by space then min.
    ranges: Vec<(String, u64, u64, usize)>,
}

/// Both reference directions, by owner address.
struct RefIndex {
    from: HashMap<Address, Vec<Reference>>,
    to: HashMap<Address, Vec<Reference>>,
}

/// An open Program database.
///
/// The query indexes (symbols, functions with bodies and variables, references) are built on
/// first use. [`Program::open`] builds all of them up front so that every error surfaces at
/// open time and the infallible accessors cannot fail afterwards; [`Program::open_lazy`] builds
/// none of them, so opening costs only the header, the address map and the table directory,
/// independent of the size of the program. See [`Program::open_lazy`] for the error behaviour.
pub struct Program<S: BufferStore> {
    db: ProgramDb<S>,
    symbols: OnceLock<SymbolTable>,
    index: OnceLock<FunctionIndex>,
    refs: OnceLock<RefIndex>,
    deferred: OnceLock<String>,
    datatypes: OnceLock<DataTypes>,
    data_at: OnceLock<HashMap<Address, i64>>,
    equates: OnceLock<Vec<Equate>>,
    bookmarks: OnceLock<Vec<Bookmark>>,
    relocations: OnceLock<Vec<Relocation>>,
    register_values: OnceLock<Vec<RegisterValueRange>>,
    options: OnceLock<Vec<ProgramOption>>,
    property_maps: OnceLock<Vec<PropertyMap>>,
    namespaces: OnceLock<Vec<NamespaceInfo>>,
}

/// Join every function with its symbol, body and variables.
fn build_function_index<S: BufferStore>(
    db: &ProgramDb<S>,
    symbols: &SymbolTable,
) -> Result<FunctionIndex> {
    let all = symbols.all();
    let addresses = all
        .iter()
        .filter(|s| s.symbol_type == 5)
        .map(|s| (s.id, s.address.clone()))
        .collect();
    let rows = crate::functions::read_functions(db.database(), &addresses)?;
    let ids: Vec<i64> = rows.iter().map(|f| f.id).collect();
    let bodies = crate::bodies::function_bodies(db.database(), db.address_map(), all, &ids)?;
    let mut parameters: HashMap<i64, Vec<Variable>> = HashMap::new();
    let mut locals: HashMap<i64, Vec<Variable>> = HashMap::new();
    for v in crate::bodies::read_variables(db.database(), all)? {
        let target = if v.is_parameter {
            &mut parameters
        } else {
            &mut locals
        };
        target.entry(v.function_id).or_default().push(v);
    }
    let mut functions = Vec::with_capacity(rows.len());
    for f in rows {
        let sym = symbols.get(f.id);
        let name = sym.and_then(|s| symbols.name(s));
        let namespace_id = sym.map_or(0, |s| symbols.parent_namespace_id(s));
        let entry = f.entry.clone().unwrap_or(Address::NoAddress);
        let mut params = parameters.remove(&f.id).unwrap_or_default();
        params.sort_by_key(|v| (v.ordinal, v.symbol_id));
        let own_locals = locals.remove(&f.id).unwrap_or_default();
        functions.push(FunctionInfo {
            body: bodies.get(&f.id).cloned().unwrap_or_default(),
            function: f,
            name,
            entry,
            namespace_id,
            parameters: params,
            locals: own_locals,
        });
    }
    functions.sort_by_key(|f| f.function.id);
    let mut by_entry = HashMap::new();
    let mut ranges = Vec::new();
    for (i, f) in functions.iter().enumerate() {
        by_entry.entry(f.entry.clone()).or_insert(i);
        for r in &f.body {
            ranges.push((r.space.clone(), r.min, r.max, i));
        }
    }
    ranges.sort();
    Ok(FunctionIndex {
        functions,
        by_entry,
        ranges,
    })
}

/// Compute a value on first use and keep it; nothing is kept when `f` fails.
fn lazy<T>(cell: &OnceLock<T>, f: impl FnOnce() -> Result<T>) -> Result<&T> {
    if let Some(v) = cell.get() {
        return Ok(v);
    }
    let value = f()?;
    Ok(cell.get_or_init(|| value))
}

impl Program<BufferFile> {
    /// Open the `db.N.gbf` file at `path` read-only and build the indexes.
    ///
    /// # Errors
    ///
    /// The errors of [`Program::open`], or the file error when `path` cannot be read.
    pub fn open_file(path: impl AsRef<Path>, spaces: AddressSpaces) -> Result<Self> {
        let file = BufferFile::open(path, true)
            .map_err(|e| ProgError::Db(ghidra_fmt_db::DbError::from(e)))?;
        Self::open(file, spaces)
    }

    /// Open the `db.N.gbf` file at `path` read-only without building any index
    /// (see [`Program::open_lazy`]).
    ///
    /// # Errors
    ///
    /// The errors of [`Program::open_lazy`], or the file error when `path` cannot be read.
    pub fn open_file_lazy(path: impl AsRef<Path>, spaces: AddressSpaces) -> Result<Self> {
        let file = BufferFile::open(path, true)
            .map_err(|e| ProgError::Db(ghidra_fmt_db::DbError::from(e)))?;
        Self::open_lazy(file, spaces)
    }
}

impl<S: BufferStore> Program<S> {
    /// Open the Program database in `store` and build the indexes.
    ///
    /// `spaces` describes the language's address spaces (see [`AddressSpaces`]).
    ///
    /// # Errors
    ///
    /// See [`ProgramDb::open`]; also any error reading the tables the indexes are built from.
    pub fn open(store: S, spaces: AddressSpaces) -> Result<Self> {
        let program = Self::open_lazy(store, spaces)?;
        program.prepare()?;
        Ok(program)
    }

    /// Open the Program database in `store` without building any index.
    ///
    /// Opening reads the "Program" metadata, the address map and the table directory only, so it
    /// costs the same for a small and for a huge program. Each index is built by the first call
    /// that needs it: the symbol table (`symbol_table`, `symbols_by_name`, `symbols_at`,
    /// `children`, `namespaces`, `symbol_path`), the function index (`functions`, `function_at`,
    /// `function_containing`, `function_by_id`; it also builds the symbol table) and the
    /// reference maps (`xrefs_to`, `xrefs_from`). `read_bytes` and the data type, equate,
    /// bookmark, relocation, register value, option and property map accessors never build one.
    ///
    /// Those accessors keep their infallible signatures, so a damaged table found while building
    /// an index cannot be returned from them: the index stays empty, the accessor answers as if
    /// there were nothing, and the error text is kept for [`Program::deferred_error`]. Call
    /// [`Program::prepare`] to build everything now and get the error as a `Result` instead.
    ///
    /// # Errors
    ///
    /// See [`ProgramDb::open`].
    pub fn open_lazy(store: S, spaces: AddressSpaces) -> Result<Self> {
        Ok(Self {
            db: ProgramDb::open(store, spaces)?,
            symbols: OnceLock::new(),
            index: OnceLock::new(),
            refs: OnceLock::new(),
            deferred: OnceLock::new(),
            datatypes: OnceLock::new(),
            data_at: OnceLock::new(),
            equates: OnceLock::new(),
            bookmarks: OnceLock::new(),
            relocations: OnceLock::new(),
            register_values: OnceLock::new(),
            options: OnceLock::new(),
            property_maps: OnceLock::new(),
            namespaces: OnceLock::new(),
        })
    }

    /// Build the symbol table, the function index and the reference maps now.
    ///
    /// # Errors
    ///
    /// Any error reading the tables the indexes are built from; nothing is kept for an index
    /// that failed, so a later call tries again.
    pub fn prepare(&self) -> Result<()> {
        self.symbols_built()?;
        self.index_built()?;
        self.refs_built()?;
        Ok(())
    }

    /// The first error an infallible accessor met while building an index lazily, if any.
    pub fn deferred_error(&self) -> Option<&str> {
        self.deferred.get().map(String::as_str)
    }

    fn defer(&self, e: &ProgError) {
        let _ = self.deferred.set(e.to_string());
    }

    fn symbols_built(&self) -> Result<&SymbolTable> {
        lazy(&self.symbols, || self.db.symbol_table())
    }

    fn index_built(&self) -> Result<&FunctionIndex> {
        let symbols = self.symbols_built()?;
        lazy(&self.index, || build_function_index(&self.db, symbols))
    }

    fn refs_built(&self) -> Result<&RefIndex> {
        lazy(&self.refs, || {
            let mut from: HashMap<Address, Vec<Reference>> = HashMap::new();
            for (owner, list) in self.db.references_from()? {
                from.entry(owner).or_default().extend(list);
            }
            let mut to: HashMap<Address, Vec<Reference>> = HashMap::new();
            for (owner, list) in self.db.references_to()? {
                to.entry(owner).or_default().extend(list);
            }
            Ok(RefIndex { from, to })
        })
    }

    /// The symbol table for the infallible accessors: an empty one after a failure.
    fn symbols_or_empty(&self) -> &SymbolTable {
        match self.symbols_built() {
            Ok(t) => t,
            Err(e) => {
                self.defer(&e);
                self.symbols
                    .get_or_init(|| SymbolTable::empty(self.db.address_map().spaces().clone()))
            }
        }
    }

    fn index_or_empty(&self) -> &FunctionIndex {
        match self.index_built() {
            Ok(i) => i,
            Err(e) => {
                self.defer(&e);
                self.index.get_or_init(|| FunctionIndex {
                    functions: Vec::new(),
                    by_entry: HashMap::new(),
                    ranges: Vec::new(),
                })
            }
        }
    }

    fn refs_or_empty(&self) -> &RefIndex {
        match self.refs_built() {
            Ok(r) => r,
            Err(e) => {
                self.defer(&e);
                self.refs.get_or_init(|| RefIndex {
                    from: HashMap::new(),
                    to: HashMap::new(),
                })
            }
        }
    }

    /// The underlying reader, for anything the facade does not cover.
    pub fn db(&self) -> &ProgramDb<S> {
        &self.db
    }

    /// The symbol table with its `SymbolManager` queries.
    pub fn symbol_table(&self) -> &SymbolTable {
        self.symbols_or_empty()
    }

    /// The "Language ID" of the program, when stored.
    pub fn language_id(&self) -> Option<&str> {
        self.db.language_id()
    }

    /// Parse `space:hex` (for example `ram:140001030`) or a bare hexadecimal offset in the default
    /// space (`140001030`, `0x140001030`).
    ///
    /// # Errors
    ///
    /// [`ProgError::UnknownSpace`] for a space that was not described, [`ProgError::Corrupt`]
    /// for text that is not an address (the variant is reused to avoid a second error type).
    pub fn parse_address(&self, text: &str) -> Result<Address> {
        let spaces = self.db.address_map().spaces();
        let (space, digits) = match text.rsplit_once(':') {
            Some((s, d)) => (s, d),
            None => (spaces.default_space.as_str(), text),
        };
        let def = spaces
            .find(space)
            .ok_or_else(|| ProgError::UnknownSpace(space.to_owned()))?;
        let digits = digits.strip_prefix("0x").unwrap_or(digits);
        let offset = u64::from_str_radix(digits, 16)
            .map_err(|_| ProgError::Corrupt(format!("not an address: {text:?}")))?;
        if def.bits < 64 && offset >> def.bits != 0 {
            return Err(ProgError::Corrupt(format!(
                "offset {offset:#x} is outside space {space}"
            )));
        }
        Ok(Address::Space {
            space: space.to_owned(),
            offset,
        })
    }

    /// Every function, id ascending (`FunctionManager.getFunctions` plus external functions).
    pub fn functions(&self) -> &[FunctionInfo] {
        &self.index_or_empty().functions
    }

    /// The function whose entry point is `addr` (`FunctionManager.getFunctionAt`).
    pub fn function_at(&self, addr: &Address) -> Option<&FunctionInfo> {
        let index = self.index_or_empty();
        index.by_entry.get(addr).map(|&i| &index.functions[i])
    }

    /// The function whose body contains `addr` (`FunctionManager.getFunctionContaining`).
    pub fn function_containing(&self, addr: &Address) -> Option<&FunctionInfo> {
        let Address::Space { space, offset } = addr else {
            return None;
        };
        let index = self.index_or_empty();
        let at = index
            .ranges
            .partition_point(|(s, min, _, _)| (s.as_str(), *min) <= (space.as_str(), *offset));
        // bodies of different functions do not overlap, but nested ranges are possible in odd
        // databases, so look back over a few candidates
        index.ranges[..at]
            .iter()
            .rev()
            .take(8)
            .find(|(s, min, max, _)| s == space && *min <= *offset && *offset <= *max)
            .map(|&(_, _, _, i)| &index.functions[i])
    }

    /// The function with this id.
    pub fn function_by_id(&self, id: i64) -> Option<&FunctionInfo> {
        let functions = &self.index_or_empty().functions;
        functions
            .binary_search_by_key(&id, |f| f.function.id)
            .ok()
            .map(|i| &functions[i])
    }

    /// Symbols with this name (`SymbolManager.getSymbols(String)`).
    pub fn symbols_by_name(&self, name: &str) -> Vec<&Symbol> {
        self.symbols_or_empty().by_name(name)
    }

    /// Symbols at an address, primary first (`SymbolManager.getSymbols(Address)`).
    pub fn symbols_at(&self, addr: &Address) -> Vec<&Symbol> {
        self.symbols_or_empty().at(addr)
    }

    /// The symbols directly inside a namespace (0 is the global namespace).
    pub fn children(&self, namespace_id: i64) -> Vec<&Symbol> {
        self.symbols_or_empty().children(namespace_id)
    }

    /// References pointing at `addr` (`ReferenceManager.getReferencesTo`), stored order.
    pub fn xrefs_to(&self, addr: &Address) -> &[Reference] {
        self.refs_or_empty().to.get(addr).map_or(&[], Vec::as_slice)
    }

    /// References made from `addr` (`ReferenceManager.getReferencesFrom`), stored order.
    pub fn xrefs_from(&self, addr: &Address) -> &[Reference] {
        self.refs_or_empty()
            .from
            .get(addr)
            .map_or(&[], Vec::as_slice)
    }

    /// Up to `len` bytes at `addr` (`Memory.getBytes`): fewer where memory ends.
    ///
    /// # Errors
    ///
    /// [`ProgError::MemoryAccess`] when no byte can be read (unmapped or uninitialized memory).
    pub fn read_bytes(&self, addr: &Address, len: usize) -> Result<Vec<u8>> {
        self.db.memory()?.read(addr, len)
    }

    /// Every data type of the program, read on first use (`DataTypeManagerDB`), sized for
    /// Windows x64; use [`ProgramDb::data_types_with`] for another data organization.
    ///
    /// # Errors
    ///
    /// The error reading the data type tables (nothing is cached on failure).
    pub fn data_types(&self) -> Result<&DataTypes> {
        if let Some(d) = self.datatypes.get() {
            return Ok(d);
        }
        let read = self.db.data_types()?;
        Ok(self.datatypes.get_or_init(|| read))
    }

    /// The data type with this id (`DataTypeManager.getDataType(long)`): name, path and size.
    ///
    /// # Errors
    ///
    /// See [`Program::data_types`].
    pub fn data_type(&self, id: i64) -> Result<Option<&DataType>> {
        Ok(self.data_types()?.get(id))
    }

    /// The data type with this path, for example `/PE/IMAGE_DOS_HEADER`.
    ///
    /// # Errors
    ///
    /// See [`Program::data_types`].
    pub fn data_type_by_path(&self, path: &str) -> Result<Option<&DataType>> {
        Ok(self.data_types()?.by_path(path))
    }

    /// Defined components of a structure or union, ordinal order.
    ///
    /// # Errors
    ///
    /// See [`Program::data_types`].
    pub fn components(&self, id: i64) -> Result<&[Component]> {
        Ok(self.data_types()?.components(id))
    }

    /// Values of an enum, by value then name.
    ///
    /// # Errors
    ///
    /// See [`Program::data_types`].
    pub fn enum_values(&self, id: i64) -> Result<&[EnumValue]> {
        Ok(self.data_types()?.enum_values(id))
    }

    /// Details of a function definition data type.
    ///
    /// # Errors
    ///
    /// See [`Program::data_types`].
    pub fn function_definition(&self, id: i64) -> Result<Option<&FunctionDef>> {
        Ok(self.data_types()?.function_def(id))
    }

    /// The data type of the defined data starting at `addr` (`Listing.getDataAt(addr).getDataType`),
    /// resolved to its name, path and size.
    ///
    /// # Errors
    ///
    /// See [`Program::data_types`]; also the error reading the "Data" table.
    pub fn data_type_at(&self, addr: &Address) -> Result<Option<&DataType>> {
        let types = self.data_types()?;
        let rows = match self.data_at.get() {
            Some(r) => r,
            None => {
                let read: HashMap<Address, i64> = self
                    .db
                    .data()?
                    .into_iter()
                    .map(|d| (d.address, d.datatype_id))
                    .collect();
                self.data_at.get_or_init(|| read)
            }
        };
        Ok(rows.get(addr).and_then(|&id| types.get(id)))
    }

    /// Every equate with its references, in record key order (`EquateTable.getEquates`).
    ///
    /// # Errors
    ///
    /// The error reading the equate tables (nothing is cached on failure).
    pub fn equates(&self) -> Result<&[Equate]> {
        lazy(&self.equates, || self.db.equates()).map(Vec::as_slice)
    }

    /// The equate with this name.
    ///
    /// # Errors
    ///
    /// See [`Program::equates`].
    pub fn equate_by_name(&self, name: &str) -> Result<Option<&Equate>> {
        Ok(self.equates()?.iter().find(|e| e.name == name))
    }

    /// The equates applied at `addr`, with the operand each is applied to
    /// (`EquateTable.getEquates(Address)`).
    ///
    /// # Errors
    ///
    /// See [`Program::equates`].
    pub fn equates_at(&self, addr: &Address) -> Result<Vec<(&Equate, i16)>> {
        Ok(self
            .equates()?
            .iter()
            .flat_map(|e| {
                e.references
                    .iter()
                    .filter(|r| &r.address == addr)
                    .map(move |r| (e, r.op_index))
            })
            .collect())
    }

    /// Every bookmark in id order.
    ///
    /// # Errors
    ///
    /// The error reading the bookmark tables.
    pub fn bookmarks(&self) -> Result<&[Bookmark]> {
        lazy(&self.bookmarks, || self.db.bookmarks()).map(Vec::as_slice)
    }

    /// The bookmarks at `addr`, id order.
    ///
    /// # Errors
    ///
    /// See [`Program::bookmarks`].
    pub fn bookmarks_at(&self, addr: &Address) -> Result<Vec<&Bookmark>> {
        Ok(self
            .bookmarks()?
            .iter()
            .filter(|b| &b.address == addr)
            .collect())
    }

    /// Every relocation in index order (by address).
    ///
    /// # Errors
    ///
    /// The error reading the "Relocations" table.
    pub fn relocations(&self) -> Result<&[Relocation]> {
        lazy(&self.relocations, || self.db.relocations()).map(Vec::as_slice)
    }

    /// The relocations at `addr` (`RelocationTable.getRelocations(Address)`).
    ///
    /// # Errors
    ///
    /// See [`Program::relocations`].
    pub fn relocations_at(&self, addr: &Address) -> Result<Vec<&Relocation>> {
        Ok(self
            .relocations()?
            .iter()
            .filter(|r| &r.address == addr)
            .collect())
    }

    /// `Relocation.getBytes`: the stored bytes or, for a status that has bytes, the original
    /// file bytes at the relocation address.
    ///
    /// # Errors
    ///
    /// A damaged "File Bytes" table.
    pub fn relocation_bytes(&self, r: &Relocation) -> Result<Option<Vec<u8>>> {
        let spaces = self.db.address_map().spaces();
        let pointer = spaces
            .find(&spaces.default_space)
            .map_or(8, |s| (s.bits / 8) as i32);
        r.bytes(&self.db.memory()?, pointer)
    }

    /// The register value ranges stored in the database ("Range Map - Register_*"): registers by
    /// name, ranges in address key order. Defaults from the language are not included.
    ///
    /// # Errors
    ///
    /// The error reading the range map tables.
    pub fn register_values(&self) -> Result<&[RegisterValueRange]> {
        lazy(&self.register_values, || self.db.register_values()).map(Vec::as_slice)
    }

    /// The stored value ranges of register `name` that contain `addr`.
    ///
    /// # Errors
    ///
    /// See [`Program::register_values`].
    pub fn register_values_at(
        &self,
        name: &str,
        addr: &Address,
    ) -> Result<Vec<&RegisterValueRange>> {
        let Address::Space { space, offset } = addr else {
            return Ok(Vec::new());
        };
        Ok(self
            .register_values()?
            .iter()
            .filter(|v| {
                v.register == name
                    && &v.range.space == space
                    && v.range.min <= *offset
                    && *offset <= v.range.max
            })
            .collect())
    }

    /// The program options (`Program Information.*`, analysis options, ...), sorted by key.
    ///
    /// # Errors
    ///
    /// The error reading the "Property Table".
    pub fn options(&self) -> Result<&[ProgramOption]> {
        lazy(&self.options, || self.db.options()).map(Vec::as_slice)
    }

    /// The option with this key, for example `Program Information.Executable Format`.
    ///
    /// # Errors
    ///
    /// See [`Program::options`].
    pub fn option(&self, key: &str) -> Result<Option<&ProgramOption>> {
        Ok(self.options()?.iter().find(|o| o.key == key))
    }

    /// The registered user and analysis property maps, sorted by name.
    ///
    /// # Errors
    ///
    /// The error reading the property map tables.
    pub fn property_maps(&self) -> Result<&[PropertyMap]> {
        lazy(&self.property_maps, || self.db.property_maps()).map(Vec::as_slice)
    }

    /// The property map with this name.
    ///
    /// # Errors
    ///
    /// See [`Program::property_maps`].
    pub fn property_map(&self, name: &str) -> Result<Option<&PropertyMap>> {
        Ok(self.property_maps()?.iter().find(|m| m.name == name))
    }

    /// Libraries, namespaces and classes in symbol id order, with their `::` paths.
    ///
    /// # Errors
    ///
    /// The error reading the symbol table.
    pub fn namespaces(&self) -> Result<&[NamespaceInfo]> {
        lazy(&self.namespaces, || {
            let symbols = self.symbols_built()?;
            Ok(crate::externals::namespaces(symbols, symbols.all()))
        })
        .map(Vec::as_slice)
    }

    /// `Symbol.getName(true)` of the symbol with this id: the `::` path from the outermost
    /// namespace.
    pub fn symbol_path(&self, id: i64) -> Option<String> {
        let symbols = self.symbols_or_empty();
        symbols.get(id).map(|s| symbols.path(s))
    }

    /// The external libraries sorted by name, with their associated program paths.
    ///
    /// # Errors
    ///
    /// The error reading the symbol table.
    pub fn external_libraries(&self) -> Result<Vec<ExternalLibrary>> {
        self.db.external_libraries()
    }

    /// The external locations directly under a library, symbol id ascending.
    ///
    /// # Errors
    ///
    /// The error reading the symbol table.
    pub fn external_locations(&self, library: &str) -> Result<Vec<ExternalLocation>> {
        self.db.external_locations(library)
    }
}
