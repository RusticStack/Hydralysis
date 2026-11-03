//! An open analysed program: the facade over `ghidra-progdb`.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use ghidra_fmt_chain::{ByteSource, ChainedBuffer};
use ghidra_fmt_gbf::BufferFile;
use ghidra_progdb::{Address, AddressSpaces, MemoryBlock, ProgramDb, RefKind, SourceType, SpaceDef, SubBlockKind};

use crate::error::{Error, Result};
use crate::layout::{self, Located};

/// The only language this plane answers for: the Windows x64 programs Hydralysis analyses.
pub const LANGUAGE: &str = "x86:LE:64:default";

/// The largest read `read_bytes` answers.
pub const MAX_READ: usize = 64 << 20;

/// The address spaces of `x86:LE:64:default`, as `OracleProgram` printed them from the stock language.
fn x86_64_spaces() -> AddressSpaces {
    let def = |name: &str, id: i32, bits: u32| SpaceDef { name: name.to_owned(), id, bits };
    AddressSpaces::new(
        vec![
            def("EXTERNAL", 42, 32),
            def("const", 48, 64),
            def("stack", 53, 64),
            def("HASH", 126, 60),
            def("OTHER", 183, 64),
            def("unique", 291, 32),
            def("ram", 433, 64),
            def("register", 548, 32),
        ],
        "ram",
    )
}

/// What a program says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramInfo {
    /// The domain file name.
    pub name: String,
    /// The path in the project.
    pub program_path: String,
    /// `Language ID`.
    pub language: String,
    /// `Compiler Spec ID`.
    pub compiler: String,
    /// The image base (an offset in the `ram` space).
    pub image_base: u64,
    /// `Executable SHA256` of the program information.
    pub sha256: String,
    /// The stored database version.
    pub db_version: i32,
}

/// One cross reference as `getReferencesTo` / `getReferencesFrom` return it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xref {
    /// The from address; `None` is `Address.EXT_FROM_ADDRESS` (an entry point), which prints as `Entry Point`.
    pub from: Option<u64>,
    /// The to address.
    pub to: u64,
    /// `ReferenceType.toString()`.
    pub ref_type: &'static str,
    /// The operand index.
    pub op_index: i8,
    /// The source (`DEFAULT`, `ANALYSIS`, `USER_DEFINED`, ...).
    pub source: &'static str,
    /// The primary flag.
    pub primary: bool,
    /// The Java class the reference decodes to (`MemReferenceDB` or `EntryPointReferenceDB`).
    pub kind: &'static str,
}

impl Xref {
    /// `Address.toString()` of the from address.
    pub fn from_text(&self) -> String {
        self.from.map_or_else(|| "Entry Point".to_owned(), address_text)
    }

    /// `Address.toString()` of the to address.
    pub fn to_text(&self) -> String {
        address_text(self.to)
    }
}

/// `Address.toString()` for the default RAM space: lower case hex, at least eight digits, no space name.
pub fn address_text(offset: u64) -> String {
    format!("{offset:08x}")
}

/// A function with the fields the database keeps in "Function Data" and "Symbols".
///
/// The body, the parameters and the prototype are stored apart and are not read here, so this is not the
/// engine's `function` row (which carries `signature` and `body`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInfo {
    /// Function (and symbol) id.
    pub id: i64,
    /// Entry point.
    pub entry: u64,
    /// The name, `FUN_<entry>` when it is a default name.
    pub name: String,
    /// True when the stored name is empty (a default name).
    pub default_named: bool,
    /// The id of the function this one is a thunk of.
    pub thunk_of: Option<i64>,
    /// Calling convention name.
    pub calling_convention: String,
    /// `NoReturn` flag.
    pub no_return: bool,
    /// `Inline` flag.
    pub inline: bool,
    /// `VarArgs` flag.
    pub var_args: bool,
}

/// A symbol row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    /// Symbol id.
    pub id: i64,
    /// Stored name (empty when default).
    pub name: String,
    /// The address space name.
    pub space: String,
    /// Offset in the default space; `None` for other spaces.
    pub address: Option<u64>,
    /// `SymbolType` id (0 label, 5 function, ...).
    pub symbol_type: u8,
    /// Parent namespace symbol id (0 is the global namespace).
    pub parent_id: i64,
    /// `SourceType` name.
    pub source: &'static str,
}

struct FileBytesEntry {
    original: Vec<i32>,
    layered: Vec<i32>,
    size: i64,
}

struct SymbolIndex {
    rows: Vec<SymbolInfo>,
    by_name: HashMap<String, Vec<usize>>,
}

/// An analysed program opened read-only from a project folder.
pub struct StaticProgram {
    db: ProgramDb<BufferFile>,
    located: Located,
    info: ProgramInfo,
    blocks: Vec<MemoryBlock>,
    file_bytes: BTreeMap<i64, FileBytesEntry>,
    symbols: OnceLock<std::result::Result<SymbolIndex, Error>>,
    functions: OnceLock<std::result::Result<Vec<FunctionInfo>, Error>>,
}

impl StaticProgram {
    /// Open `program` of the project at `project` (the `.gpr`, the project folder or its `.rep`).
    ///
    /// # Errors
    ///
    /// `Unsupported` when the layout, the language, the database version, a table version or an address space is
    /// outside what this plane reads exactly; `Failed` when the files cannot be read.
    pub fn open(project: &Path, program: &str) -> Result<Self> {
        let located = layout::locate(project, program)?;
        let store = BufferFile::open(&located.gbf, true)?;
        let db = ProgramDb::open(store, x86_64_spaces())?;
        let language = db.language_id().unwrap_or_default().to_owned();
        if language != LANGUAGE {
            return Err(Error::unsupported(format!("language {language:?} (only {LANGUAGE} is read)")));
        }
        for entry in db.address_map().entries() {
            let known = db.address_map().spaces().find(&entry.space_name).is_some();
            if !known && !entry.deleted {
                return Err(Error::unsupported(format!("address space {:?} (overlay or unknown space)", entry.space_name)));
            }
        }
        let options = options_of(&db)?;
        let flag = |key: &str| options.get(&format!("Program Information.{key}"));
        if flag("Analyzed").map(String::as_str) != Some("true") {
            return Err(Error::unsupported("the program is not marked analysed"));
        }
        let sha256 = flag("Executable SHA256").cloned().ok_or_else(|| Error::unsupported("the program has no Executable SHA256"))?;
        let info = ProgramInfo {
            name: located.name.clone(),
            program_path: located.program_path.clone(),
            language,
            compiler: db.compiler_spec_id().unwrap_or_default().to_owned(),
            image_base: db.image_base_offset() as u64,
            sha256,
            db_version: db.stored_version(),
        };
        let blocks = db.memory_blocks()?;
        let default = db.address_map().spaces().default_space.clone();
        for block in &blocks {
            if !matches!(&block.start, Address::Space { space, .. } if *space == default) {
                return Err(Error::unsupported(format!("memory block {:?} is outside the default space", block.name)));
            }
        }
        let file_bytes = read_file_bytes(&db)?;
        Ok(Self { db, located, info, blocks, file_bytes, symbols: OnceLock::new(), functions: OnceLock::new() })
    }

    /// The program identity.
    pub fn info(&self) -> &ProgramInfo {
        &self.info
    }

    /// Where the database file is, and its stamp when it was found.
    pub fn located(&self) -> &Located {
        &self.located
    }

    /// The memory blocks, by start address.
    pub fn blocks(&self) -> &[MemoryBlock] {
        &self.blocks
    }

    fn space_address(&self, offset: u64) -> Address {
        Address::Space { space: self.db.address_map().spaces().default_space.clone(), offset }
    }

    fn default_offset(&self, address: &Address) -> Option<u64> {
        match address {
            Address::Space { space, offset } if *space == self.db.address_map().spaces().default_space => Some(*offset),
            _ => None,
        }
    }

    fn xref_of(&self, r: &ghidra_progdb::Reference) -> Result<Xref> {
        // Offset, shifted, external and stack references carry more than from/to/type, and their to address is
        // not the key they are stored under; declined rather than shown partly.
        if !matches!(r.kind, RefKind::Memory | RefKind::EntryPoint) {
            return Err(Error::unsupported(format!("reference of kind {}", r.kind.class_name())));
        }
        let from = match &r.from {
            Address::ExtFrom => None,
            other => Some(self.default_offset(other).ok_or_else(|| Error::unsupported("reference from outside the default space"))?),
        };
        let to = self.default_offset(&r.to).ok_or_else(|| Error::unsupported("reference to outside the default space"))?;
        Ok(Xref {
            from,
            to,
            ref_type: r.ref_type_name(),
            op_index: r.op_index,
            source: r.source.name(),
            primary: r.primary,
            kind: r.kind.class_name(),
        })
    }

    /// `ReferenceManager.getReferencesTo(address)` in stored order.
    pub fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        let refs = self.db.references_to_at(&self.space_address(address))?;
        refs.iter().map(|r| self.xref_of(r)).collect()
    }

    /// `ReferenceManager.getReferencesFrom(address)` in stored order.
    pub fn xrefs_from(&self, address: u64) -> Result<Vec<Xref>> {
        let refs = self.db.references_from_at(&self.space_address(address))?;
        refs.iter().map(|r| self.xref_of(r)).collect()
    }

    fn symbol_index(&self) -> Result<&SymbolIndex> {
        self.symbols
            .get_or_init(|| {
                let mut rows = Vec::new();
                let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
                for s in self.db.symbols()? {
                    let address = self.default_offset(&s.address);
                    let space = match &s.address {
                        Address::Space { space, .. } => space.clone(),
                        other => other.to_string(),
                    };
                    if !s.name.is_empty() {
                        by_name.entry(s.name.clone()).or_default().push(rows.len());
                    }
                    rows.push(SymbolInfo {
                        id: s.id,
                        name: s.name,
                        space,
                        address,
                        symbol_type: s.symbol_type,
                        parent_id: s.parent_id,
                        source: s.source.name(),
                    });
                }
                Ok(SymbolIndex { rows, by_name })
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Every symbol row, in id order.
    pub fn symbols(&self) -> Result<&[SymbolInfo]> {
        Ok(&self.symbol_index()?.rows)
    }

    /// Symbols whose stored name is `name`, in id order. Default-named symbols (`FUN_...`, `LAB_...`) store no
    /// name, so asking for a name of that shape is declined instead of answered with nothing.
    pub fn symbols_named(&self, name: &str) -> Result<Vec<SymbolInfo>> {
        if looks_default(name) {
            return Err(Error::unsupported("default symbol names are computed from the address, not stored"));
        }
        let index = self.symbol_index()?;
        Ok(index.by_name.get(name).map(|rows| rows.iter().map(|&i| index.rows[i].clone()).collect()).unwrap_or_default())
    }

    /// Every function, in entry address order.
    pub fn functions(&self) -> Result<&[FunctionInfo]> {
        self.functions.get_or_init(|| self.build_functions()).as_deref().map_err(Clone::clone)
    }

    fn build_functions(&self) -> Result<Vec<FunctionInfo>> {
        let symbols = self.symbol_index()?;
        let by_id: HashMap<i64, &SymbolInfo> = symbols.rows.iter().map(|s| (s.id, s)).collect();
        let mut out = Vec::new();
        for f in self.db.functions()? {
            let Some(sym) = by_id.get(&f.id) else {
                return Err(Error::failed("function without a symbol"));
            };
            // `FunctionManager.getFunctions(true)` leaves out functions in the external space.
            if sym.space == "EXTERNAL" {
                continue;
            }
            let entry = sym.address.ok_or_else(|| Error::unsupported("function entry outside the default space"))?;
            let default_named = sym.name.is_empty() && sym.source == SourceType::Default.name();
            if sym.name.is_empty() && !default_named {
                return Err(Error::failed("function symbol without a name"));
            }
            let name = if default_named { format!("FUN_{}", address_text(entry)) } else { sym.name.clone() };
            out.push(FunctionInfo {
                id: f.id,
                entry,
                name,
                default_named,
                thunk_of: f.thunk_target,
                calling_convention: f.calling_convention.clone(),
                no_return: f.has_no_return(),
                inline: f.is_inline(),
                var_args: f.has_var_args(),
            });
        }
        out.sort_by_key(|f| f.entry);
        Ok(out)
    }

    /// The function whose entry point is `address`, if there is one.
    ///
    /// `FunctionManager.getFunctionContaining` also answers for addresses inside a body; the body is stored apart
    /// and is not read, so `None` here means "no function starts at this address", not "none contains it".
    pub fn function_at_entry(&self, address: u64) -> Result<Option<FunctionInfo>> {
        let functions = self.functions()?;
        Ok(functions.binary_search_by_key(&address, |f| f.entry).ok().map(|i| functions[i].clone()))
    }

    /// Read `len` bytes at `address` from initialised memory, as `Memory.getBytes` does.
    ///
    /// # Errors
    ///
    /// `Unsupported` when any of the bytes lies outside initialised file-backed or buffer-backed memory (an
    /// uninitialised, mapped or missing block): the engine decides what that read means.
    pub fn read_bytes(&self, address: u64, len: usize) -> Result<Vec<u8>> {
        if len > MAX_READ {
            return Err(Error::unsupported("read larger than the plane answers"));
        }
        let store = self.db.database().store();
        let mut out = vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            let at = address.checked_add(done as u64).ok_or_else(|| Error::unsupported("read wraps the address space"))?;
            let block = self.block_containing(at).ok_or_else(|| Error::unsupported("bytes outside every memory block"))?;
            let Address::Space { offset: start, .. } = &block.start else {
                return Err(Error::unsupported("memory block without a start address"));
            };
            let in_block = (at - start) as i64;
            let sub = block
                .sub_blocks
                .iter()
                .find(|s| s.start_offset <= in_block && in_block < s.start_offset + s.length)
                .ok_or_else(|| Error::unsupported("memory block with a gap between parts"))?;
            let in_sub = in_block - sub.start_offset;
            let want = (len - done).min((sub.length - in_sub) as usize);
            let dest = &mut out[done..done + want];
            match sub.kind {
                SubBlockKind::FileBytes => {
                    let fb = self
                        .file_bytes
                        .get(&i64::from(sub.source_id))
                        .ok_or_else(|| Error::failed("memory part names a missing file bytes id"))?;
                    read_layered(&self.located.gbf, fb, sub.source_offset + in_sub, dest)?;
                }
                SubBlockKind::Buffer => {
                    let buffer = ChainedBuffer::open(store, sub.source_id)?;
                    let from = i32::try_from(in_sub).map_err(|_| Error::failed("buffer offset out of range"))?;
                    buffer.get_into(store, from, dest)?;
                }
                SubBlockKind::Uninitialized => {
                    return Err(Error::unsupported("uninitialised memory"));
                }
                SubBlockKind::BitMapped | SubBlockKind::ByteMapped => {
                    return Err(Error::unsupported("mapped memory"));
                }
            }
            done += want;
        }
        Ok(out)
    }

    fn block_containing(&self, address: u64) -> Option<&MemoryBlock> {
        self.blocks.iter().find(|b| match &b.start {
            Address::Space { offset, .. } => address >= *offset && address - offset < b.length as u64,
            _ => false,
        })
    }
}

/// Name prefixes of the labels Ghidra computes (`SymbolUtilities.getDefault*Name`) and does not store.
const DEFAULT_PREFIXES: &[&str] = &[
    "FUN", "LAB", "SUB", "EXT", "DAT", "UNK", "PTR", "OFF", "ADDR", "BYTE", "WORD", "DWORD", "QWORD", "FLOAT", "DOUBLE", "ARRAY", "STRING",
    "UNICODE",
];

/// Names Ghidra computes from an address instead of storing: `FUN_140001000`, `LAB_...`, `PTR_FUN_...`.
fn looks_default(name: &str) -> bool {
    let Some((first, _)) = name.split_once('_') else {
        return false;
    };
    let Some((_, last)) = name.rsplit_once('_') else {
        return false;
    };
    DEFAULT_PREFIXES.contains(&first) && last.len() >= 8 && last.chars().all(|c| c.is_ascii_hexdigit())
}

/// The `Property Table` (the program's `DBOptions`): `Program Information.<name>` to its string value.
fn options_of(db: &ProgramDb<BufferFile>) -> Result<BTreeMap<String, String>> {
    let table = db.database().table("Property Table").map_err(|_| Error::unsupported("no Property Table"))?;
    if table.schema().version() != 0 {
        return Err(Error::unsupported("Property Table of another version"));
    }
    let names = table.schema().field_names();
    if names.first().map(String::as_str) != Some("Value") {
        return Err(Error::unsupported("Property Table of another shape"));
    }
    let mut out = BTreeMap::new();
    for rec in table.records()? {
        let rec = rec?;
        let key = match &rec.key {
            ghidra_fmt_field::Field::String(Some(s)) => s.as_str().to_owned(),
            _ => continue,
        };
        if let Some(Some(ghidra_fmt_field::Field::String(Some(v)))) = rec.values.first() {
            out.insert(key, v.as_str().to_owned());
        }
    }
    Ok(out)
}

fn int_array(field: Option<&ghidra_fmt_field::Field>) -> Result<Vec<i32>> {
    let Some(ghidra_fmt_field::Field::Binary(Some(data))) = field else {
        return Err(Error::failed("file bytes without buffer ids"));
    };
    // BinaryCodedField: type byte (4 = int[]), a null marker byte, then big-endian ints.
    if data.len() < 2 || data[0] != 4 || data[1] != 0 || (data.len() - 2) % 4 != 0 {
        return Err(Error::failed("file bytes buffer ids are not an int array"));
    }
    Ok(data[2..].as_chunks::<4>().0.iter().map(|c| i32::from_be_bytes(*c)).collect())
}

fn read_file_bytes(db: &ProgramDb<BufferFile>) -> Result<BTreeMap<i64, FileBytesEntry>> {
    let mut out = BTreeMap::new();
    let Ok(table) = db.database().table("File Bytes") else {
        return Ok(out);
    };
    if table.schema().version() != 0 {
        return Err(Error::unsupported("File Bytes table of another version"));
    }
    let names = table.schema().field_names();
    let col =
        |name: &str| names.iter().position(|n| n == name).ok_or_else(|| Error::unsupported(format!("File Bytes without column {name}")));
    let (size_col, orig_col, layer_col) = (col("Size")?, col("Chain Buffer IDs")?, col("Layered Chain Buffer IDs")?);
    for rec in table.records()? {
        let rec = rec?;
        let id = rec.key.long_value().ok_or_else(|| Error::failed("file bytes key"))?;
        let size = match rec.values.get(size_col) {
            Some(Some(ghidra_fmt_field::Field::Long(v))) => *v,
            _ => return Err(Error::failed("file bytes without size")),
        };
        let original = int_array(rec.values.get(orig_col).and_then(Option::as_ref))?;
        let layered = int_array(rec.values.get(layer_col).and_then(Option::as_ref))?;
        if original.len() != layered.len() || original.is_empty() {
            return Err(Error::failed("file bytes buffer lists disagree"));
        }
        out.insert(id, FileBytesEntry { original, layered, size });
    }
    Ok(out)
}

/// The original bytes of a file-bytes buffer, as the data source of its layered twin.
struct Original {
    store: Arc<BufferFile>,
    buffer: ChainedBuffer,
}

impl ByteSource for Original {
    fn len(&self) -> i64 {
        i64::from(self.buffer.len())
    }

    fn read(&self, offset: i64, out: &mut [u8]) -> ghidra_fmt_chain::Result<()> {
        let offset = i32::try_from(offset).map_err(|_| ghidra_fmt_chain::ChainError::OutOfBounds)?;
        self.buffer.get_into(&*self.store, offset, out)
    }
}

/// `FileBytes.getModifiedBytes`: the layered buffers, whose never-written parts read through to the originals
/// (`new ChainedBuffer(bufferMgr, id, original, 0)` in Java).
fn read_layered(gbf: &Path, fb: &FileBytesEntry, offset: i64, out: &mut [u8]) -> Result<()> {
    if offset < 0 || offset + out.len() as i64 > fb.size {
        return Err(Error::failed("file bytes read out of range"));
    }
    // The source keeps its own handle: it outlives the borrow the chained buffer reads with.
    let store = Arc::new(BufferFile::open(gbf, true)?);
    let first = ChainedBuffer::open(&*store, fb.layered[0])?;
    let max = i64::from(first.len());
    if max <= 0 {
        return Err(Error::failed("empty file bytes buffer"));
    }
    let mut done = 0usize;
    let mut at = offset;
    while done < out.len() {
        let index = (at / max) as usize;
        let local = (at % max) as i32;
        let (Some(&layered_id), Some(&original_id)) = (fb.layered.get(index), fb.original.get(index)) else {
            return Err(Error::failed("file bytes read past its buffers"));
        };
        let original = Original { store: Arc::clone(&store), buffer: ChainedBuffer::open(&*store, original_id)? };
        // The chain crate takes `Arc<dyn ByteSource>` (no `Send` bound); this one never leaves the thread.
        #[allow(clippy::arc_with_non_send_sync)]
        let source: Arc<dyn ByteSource> = Arc::new(original);
        let layered = ChainedBuffer::open_with_source(&*store, layered_id, Some((source, 0)))?;
        let n = (max - i64::from(local)).min((out.len() - done) as i64) as usize;
        layered.get_into(&*store, local, &mut out[done..done + n])?;
        done += n;
        at += n as i64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_names_are_recognised() {
        assert!(looks_default("FUN_140001000"));
        assert!(looks_default("LAB_14000100a"));
        assert!(looks_default("DAT_140001000"));
        assert!(looks_default("PTR_FUN_140010078"));
        assert!(!looks_default("switchD_14000e2eb"));
        assert!(!looks_default("thunk_FUN_140001000"));
        assert!(!looks_default("main"));
        assert!(!looks_default("my_func"));
        assert!(!looks_default("__security_cookie"));
    }

    #[test]
    fn addresses_print_like_ghidra() {
        assert_eq!(address_text(0x1400_0100a), "14000100a");
        assert_eq!(address_text(0x1000), "00001000");
    }
}
