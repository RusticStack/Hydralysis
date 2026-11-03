//! Namespaces, classes and the external manager (`NamespaceManager`, `ExternalManagerDB`). All of
//! it lives in the symbol table: a library is a symbol of type 1, a namespace type 3, a class
//! type 4, and an external location is a label or function symbol at an `EXTERNAL` space
//! address whose parent chain ends in a library.

use crate::symbols::SourceType;
use crate::{Address, AddressMap, Symbol, SymbolTable};

/// What kind of namespace a symbol is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceKind {
    /// An external library (`Library`).
    Library,
    /// A plain namespace.
    Namespace,
    /// A class (`GhidraClass`).
    Class,
}

impl NamespaceKind {
    /// `SymbolType.toString()`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Library => "Library",
            Self::Namespace => "Namespace",
            Self::Class => "Class",
        }
    }
}

/// A library, namespace or class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceInfo {
    /// Symbol id.
    pub id: i64,
    /// Kind.
    pub kind: NamespaceKind,
    /// `Namespace.getName(true)`: names from the outermost namespace, joined with `::`.
    pub path: String,
    /// Parent namespace id (0 is the global namespace).
    pub parent_id: i64,
}

/// An external library with its associated program path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLibrary {
    /// Symbol id.
    pub id: i64,
    /// Library name.
    pub name: String,
    /// Associated program path (`getExternalLibraryPath`), when set.
    pub path: Option<String>,
}

/// An external location (`ExternalLocation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLocation {
    /// Symbol id.
    pub symbol_id: i64,
    /// Name of the library the location belongs to.
    pub library: String,
    /// Label (`getLabel`).
    pub label: String,
    /// Original imported (mangled) name, when set.
    pub original_imported_name: Option<String>,
    /// The program address in the external program (`getAddress`), when set and parsable.
    pub program_address: Option<Address>,
    /// The address in the `EXTERNAL` space (`getExternalSpaceAddress`).
    pub external_address: Address,
    /// Source of the symbol.
    pub source: SourceType,
    /// True for a function, false for a data label.
    pub is_function: bool,
    /// Path of the parent namespace.
    pub namespace_path: String,
}

impl SymbolTable {
    /// `Symbol.getName(true)`: the names from the outermost namespace to the symbol, joined with
    /// `::` (the global namespace is not part of the path).
    pub fn path(&self, sym: &Symbol) -> String {
        let mut names = vec![self.name(sym).unwrap_or_default()];
        let mut parent = self.parent_namespace_id(sym);
        let mut guard = 0;
        while parent != 0 && guard < 256 {
            let Some(p) = self.get(parent) else { break };
            names.push(self.name(p).unwrap_or_default());
            parent = self.parent_namespace_id(p);
            guard += 1;
        }
        names.reverse();
        names.join("::")
    }
}

pub(crate) fn namespaces(symbols: &SymbolTable, all: &[Symbol]) -> Vec<NamespaceInfo> {
    let mut out: Vec<NamespaceInfo> = all
        .iter()
        .filter_map(|s| {
            let kind = match s.symbol_type {
                1 => NamespaceKind::Library,
                3 => NamespaceKind::Namespace,
                4 => NamespaceKind::Class,
                _ => return None,
            };
            Some(NamespaceInfo {
                id: s.id,
                kind,
                path: symbols.path(s),
                parent_id: s.parent_id,
            })
        })
        .collect();
    out.sort_by_key(|n| n.id);
    out
}

pub(crate) fn libraries(all: &[Symbol]) -> Vec<ExternalLibrary> {
    let mut out: Vec<ExternalLibrary> = all
        .iter()
        .filter(|s| s.symbol_type == 1)
        .map(|s| ExternalLibrary {
            id: s.id,
            name: s.name.clone(),
            path: s.library_path.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// External locations directly under a library (`ExternalManager.getExternalLocations(name)`
/// walks the library's own children only), symbol id ascending.
pub(crate) fn locations(
    symbols: &SymbolTable,
    map: &AddressMap,
    library: &Symbol,
) -> Vec<ExternalLocation> {
    let mut out: Vec<ExternalLocation> = symbols
        .children(library.id)
        .into_iter()
        .filter(|s| matches!(s.symbol_type, 0 | 5) && s.is_external_address())
        .map(|s| ExternalLocation {
            symbol_id: s.id,
            library: library.name.clone(),
            label: symbols.name(s).unwrap_or_default(),
            original_imported_name: s.original_imported_name.clone(),
            program_address: s
                .external_program_address
                .as_deref()
                .and_then(|a| parse_program_address(map, a)),
            external_address: s.address.clone(),
            source: s.source,
            is_function: s.symbol_type == 5,
            namespace_path: symbols.path(library),
        })
        .collect();
    out.sort_by_key(|l| l.symbol_id);
    out
}

/// `AddressFactory.getAddress(String)` for the strings `Address.toString()` writes: `space:hex`
/// or a bare hexadecimal offset in the default space.
fn parse_program_address(map: &AddressMap, text: &str) -> Option<Address> {
    let spaces = map.spaces();
    let (space, digits) = match text.rsplit_once(':') {
        Some((s, d)) => (s, d),
        None => (spaces.default_space.as_str(), text),
    };
    let def = spaces.find(space)?;
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    let offset = u64::from_str_radix(digits, 16).ok()?;
    if def.bits < 64 && offset >> def.bits != 0 {
        return None;
    }
    Some(Address::Space {
        space: space.to_owned(),
        offset,
    })
}
