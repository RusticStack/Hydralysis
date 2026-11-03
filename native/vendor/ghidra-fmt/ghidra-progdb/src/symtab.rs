//! Symbol queries with the ordering of `SymbolManager`: by id, by stored name, by name and
//! namespace, children of a namespace and symbols at an address.
//!
//! Orderings (all come from the index tables of the "Symbols" table, which sort by indexed value
//! and then by symbol id):
//!
//! * `by_name` (`getSymbols(String)`): index "Name", so symbol id ascending.
//! * `by_name_in_namespace` (`getSymbols(String, Namespace)`): the "Locator Hash" index, which
//!   sorts by the stored hash and then by id. For one name and namespace the upper 32 bits are
//!   equal, so this is the low 32 bits of the address key (unsigned), then id.
//! * `children` (`getSymbols(Namespace)`, `getChildren`): index "Namespace", id ascending, with
//!   default-named thunk functions left out.
//! * `at` (`getSymbols(Address)`): index "Address", id ascending; the primary symbol is swapped
//!   into slot 0 when it is not already first (the last primary one wins).
//! * `primary_at` (`getPrimarySymbol`): index "Primary", first id.
//!
//! Dynamic symbols (the `LAB_`, `DAT_`, ... names Java invents for addresses that have references
//! but no symbol) and default external names are not ported. Default function names (`FUN_`,
//! `thunk_`) and default parameter names (`param_N`) are; default local variable names are not and
//! [`SymbolTable::name`] gives `None` for them.

use std::collections::{BTreeMap, HashMap};

use ghidra_fmt_db::Database;
use ghidra_fmt_gbf::BufferStore;

use crate::symbols::{SourceType, Symbol};
use crate::{Address, AddressMap, AddressSpaces, Cols, Result};

const MIN_LABEL_ADDRESS_DIGITS: usize = 8;

/// All symbols of a program, indexed for the `SymbolManager` queries.
#[derive(Debug, Clone)]
pub struct SymbolTable {
    symbols: Vec<Symbol>,
    by_id: HashMap<i64, usize>,
    by_address: HashMap<Address, Vec<usize>>,
    children: BTreeMap<i64, Vec<usize>>,
    thunks: HashMap<i64, i64>,
    spaces: AddressSpaces,
}

impl SymbolTable {
    pub(crate) fn build<S: BufferStore>(
        db: &Database<S>,
        map: &AddressMap,
        mut symbols: Vec<Symbol>,
    ) -> Result<Self> {
        symbols.sort_by_key(|s| s.id);
        let mut thunks = HashMap::new();
        if let Ok(t) = db.table("Thunk Functions") {
            let c = Cols::new(t.schema());
            for rec in t.records()? {
                let rec = rec?;
                if let (Some(k), Some(target)) =
                    (rec.key.long_value(), c.long(&rec, "Linked Function ID")?)
                {
                    thunks.insert(k, target);
                }
            }
        }
        let mut by_id = HashMap::new();
        let mut by_address: HashMap<Address, Vec<usize>> = HashMap::new();
        let mut children: BTreeMap<i64, Vec<usize>> = BTreeMap::new();
        for (i, s) in symbols.iter().enumerate() {
            by_id.insert(s.id, i);
            by_address.entry(s.address.clone()).or_default().push(i);
            children.entry(s.parent_id).or_default().push(i);
        }
        Ok(Self {
            symbols,
            by_id,
            by_address,
            children,
            thunks,
            spaces: map.spaces().clone(),
        })
    }

    /// A table without symbols (what the lazy facade answers from after a failed read).
    pub(crate) fn empty(spaces: AddressSpaces) -> Self {
        Self {
            symbols: Vec::new(),
            by_id: HashMap::new(),
            by_address: HashMap::new(),
            children: BTreeMap::new(),
            thunks: HashMap::new(),
            spaces,
        }
    }

    /// Every symbol in id order.
    pub fn all(&self) -> &[Symbol] {
        &self.symbols
    }

    /// The symbol with this id (`SymbolManager.getSymbol(long)`).
    pub fn get(&self, id: i64) -> Option<&Symbol> {
        self.by_id.get(&id).map(|&i| &self.symbols[i])
    }

    /// True when the symbol is a function that is a thunk.
    pub fn is_thunk(&self, sym: &Symbol) -> bool {
        sym.symbol_type == 5 && self.thunks.contains_key(&sym.id)
    }

    /// `SymbolManager.isDefaultThunk`.
    fn is_default_thunk(&self, sym: &Symbol) -> bool {
        sym.source == SourceType::Default && self.is_thunk(sym)
    }

    /// `Symbol.getName` where this port can compute it.
    ///
    /// Stored names are returned as stored. Default-sourced functions give `FUN_<address>` (or
    /// the thunked function's name, with `thunk_` in front when that is a default non-thunk
    /// function), default parameters `param_<ordinal+1>`. Default locals and default external
    /// names give `None`.
    pub fn name(&self, sym: &Symbol) -> Option<String> {
        self.name_at_depth(sym, 0)
    }

    fn name_at_depth(&self, sym: &Symbol, depth: u32) -> Option<String> {
        if sym.source != SourceType::Default {
            return Some(sym.name.clone());
        }
        match sym.symbol_type {
            5 => {
                if sym.is_external_address() {
                    return None;
                }
                if depth < 16
                    && let Some(target) = self.thunks.get(&sym.id).and_then(|&t| self.get(t))
                    && target.symbol_type == 5
                {
                    let name = self.name_at_depth(target, depth + 1)?;
                    let plain_default =
                        target.source == SourceType::Default && !self.is_thunk(target);
                    return Some(if plain_default {
                        format!("thunk_{name}")
                    } else {
                        name
                    });
                }
                Some(format!("FUN_{}", self.address_string(&sym.address)))
            }
            6 => Some(format!("param_{}", sym.variable_offset.unwrap_or(0) + 1)),
            _ => None,
        }
    }

    /// `SymbolUtilities.getAddressString`: the address as Ghidra prints it, with `:` replaced by
    /// `_` and at least 8 hex digits (fewer for small spaces). The space name is shown for
    /// spaces other than the default one (Java shows it for every non-RAM-type space).
    pub fn address_string(&self, addr: &Address) -> String {
        match addr {
            Address::Space { space, offset } => {
                let bits = self.spaces.find(space).map_or(64, |s| s.bits) as usize;
                let max_digits = (bits.saturating_sub(1)) / 4 + 1;
                let width = MIN_LABEL_ADDRESS_DIGITS.min(max_digits);
                let hex = format!("{offset:0width$x}");
                if *space == self.spaces.default_space {
                    hex
                } else {
                    format!("{space}_{hex}")
                }
            }
            Address::NoAddress => "NO_ADDRESS".to_owned(),
            Address::ExtFrom => "EXT_FROM".to_owned(),
        }
    }

    /// `SymbolUtilities.parseDynamicName`: the address a name like `FUN_140001030` stands for.
    fn parse_dynamic_name(&self, name: &str) -> Option<Address> {
        if name.starts_with('_') {
            return None;
        }
        let pieces: Vec<&str> = name.split('_').collect();
        if pieces.len() < 2 {
            return None;
        }
        let digits = pieces[pieces.len() - 1];
        if digits.len() < MIN_LABEL_ADDRESS_DIGITS {
            return None;
        }
        let mut space = self.spaces.default_space.clone();
        // the largest run of middle pieces that names a space wins
        let end = pieces.len() - 2;
        'search: for start in 1..=end {
            for stop in (start..=end).rev() {
                let candidate = pieces[start..=stop].join("_");
                if self.spaces.find(&candidate).is_some() {
                    space = candidate;
                    break 'search;
                }
            }
        }
        let offset = u64::from_str_radix(digits, 16).ok()?;
        let bits = self.spaces.find(&space)?.bits;
        if bits < 64 && offset >> bits != 0 {
            return None;
        }
        Some(Address::Space { space, offset })
    }

    /// `SymbolManager.getSymbolForDynamicName`.
    fn symbol_for_dynamic_name(&self, name: &str) -> Option<&Symbol> {
        let addr = self.parse_dynamic_name(name)?;
        let primary = self.primary_at(&addr)?;
        (primary.source == SourceType::Default && self.name(primary).as_deref() == Some(name))
            .then_some(primary)
    }

    /// `SymbolManager.getSymbols(String name)`: every symbol with this stored name in any
    /// namespace (id order); when there is none, the default-named symbol the name stands for.
    pub fn by_name(&self, name: &str) -> Vec<&Symbol> {
        let found: Vec<&Symbol> = self
            .symbols
            .iter()
            .filter(|s| !name.is_empty() && s.name == name && s.hash.is_some())
            .collect();
        if found.is_empty() {
            return self.symbol_for_dynamic_name(name).into_iter().collect();
        }
        found
    }

    /// `SymbolManager.getSymbols(String name, Namespace namespace)`; namespace id 0 is the global
    /// namespace.
    pub fn by_name_in_namespace(&self, name: &str, namespace_id: i64) -> Vec<&Symbol> {
        let ns = self.get(namespace_id);
        let brute_force = match ns {
            // default parameter and local names are generated, so look at every child
            Some(n) if n.symbol_type == 5 => {
                is_default_param_name(name) || name.starts_with("local_")
            }
            // default external names likewise
            Some(n) if n.is_external_address() => name.starts_with("EXT_"),
            _ => false,
        };
        if brute_force {
            return self
                .children(namespace_id)
                .into_iter()
                .filter(|s| self.name(s).as_deref() == Some(name))
                .collect();
        }
        let mut list: Vec<&Symbol> = self
            .symbols
            .iter()
            .filter(|s| {
                !name.is_empty()
                    && s.name == name
                    && s.parent_id == namespace_id
                    && s.hash.is_some()
            })
            .collect();
        list.sort_by_key(|s| (s.hash, s.id));
        if let Some(dynamic) = self.symbol_for_dynamic_name(name)
            && self.parent_namespace_id(dynamic) == namespace_id
        {
            list.push(dynamic);
        }
        list
    }

    /// `Symbol.getParentNamespace().getID()`: a default thunk reports the namespace of the function it
    /// thunks.
    pub fn parent_namespace_id(&self, sym: &Symbol) -> i64 {
        if sym.symbol_type == 5
            && sym.source == SourceType::Default
            && let Some(target) = self.thunks.get(&sym.id).and_then(|&t| self.get(t))
            && target.symbol_type == 5
        {
            return target.parent_id;
        }
        sym.parent_id
    }

    /// `SymbolManager.getSymbols(Namespace)` / `getChildren`: the symbols whose stored parent is
    /// `namespace_id`, id order, default thunks left out.
    pub fn children(&self, namespace_id: i64) -> Vec<&Symbol> {
        self.children
            .get(&namespace_id)
            .into_iter()
            .flatten()
            .map(|&i| &self.symbols[i])
            .filter(|s| !self.is_default_thunk(s))
            .collect()
    }

    /// `SymbolManager.getSymbols(Address)` for addresses that have symbols (dynamic symbols are
    /// not produced): id order, with the primary symbol swapped into slot 0.
    pub fn at(&self, addr: &Address) -> Vec<&Symbol> {
        let mut list: Vec<&Symbol> = self
            .by_address
            .get(addr)
            .into_iter()
            .flatten()
            .map(|&i| &self.symbols[i])
            .collect();
        if self.is_memory_address(addr) {
            let mut primary = 0;
            for (i, s) in list.iter().enumerate() {
                if i != 0 && s.is_primary() {
                    primary = i;
                }
            }
            if primary != 0 {
                list.swap(0, primary);
            }
        }
        list
    }

    /// `SymbolManager.getPrimarySymbol(Address)` (no dynamic symbols).
    pub fn primary_at(&self, addr: &Address) -> Option<&Symbol> {
        if matches!(addr, Address::Space { space, .. } if *space == "EXTERNAL") {
            return self.at(addr).into_iter().next();
        }
        if !self.is_memory_address(addr) {
            return None;
        }
        self.by_address
            .get(addr)?
            .iter()
            .map(|&i| &self.symbols[i])
            .find(|s| s.primary_column)
    }

    fn is_memory_address(&self, addr: &Address) -> bool {
        matches!(addr, Address::Space { space, .. }
            if space != "EXTERNAL"
                && space != "VARIABLE"
                && space != "HASH"
                && *space != self.spaces.stack_space
                && *space != self.spaces.register_space)
    }
}

/// `SymbolUtilities.isDefaultParameterName` (restricted to non-empty names).
fn is_default_param_name(name: &str) -> bool {
    name.strip_prefix("param_")
        .is_some_and(|tail| tail.parse::<i32>().is_ok())
}
