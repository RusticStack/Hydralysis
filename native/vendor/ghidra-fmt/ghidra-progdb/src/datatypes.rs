//! Read side of `DataTypeManagerDB`: categories, built-in type references, structures and unions
//! with their components, enums, typedefs, function definitions, pointers and arrays, and the
//! resolution of a data type id to name, path and size.
//!
//! Ids: `id >> 56` is the table (`0` built-in, `1` composite, `2` component, `3` array, `4`
//! pointer, `5` typedef, `6` function definition, `7` parameter, `8` enum, `9` bit field), the low
//! bits are the record key. `0` is `DataType.DEFAULT`, `-1` is "no type", `-2` is the bad type.
//!
//! Built-in types are Java classes (`ghidra.program.model.data.IntegerDataType`, ...); the
//! database stores the class name only. Sizes of the common ones are known here; the ones that
//! depend on the compiler (`int`, `long`, `wchar_t`, pointers) come from [`DataOrganization`],
//! which the caller can set. Dynamic built-ins (strings, PE structures) have no fixed size and
//! report `None`.

use std::collections::{BTreeMap, HashMap};

use ghidra_fmt_db::Database;
use ghidra_fmt_field::Field;
use ghidra_fmt_gbf::BufferStore;

use crate::{Cols, Result};

const KIND_SHIFT: u32 = 56;

/// Sizes the database does not store: they come from the compiler specification's
/// `DataOrganization` in Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataOrganization {
    /// Pointer size in bytes.
    pub pointer: i32,
    /// `int` and `unsigned int`.
    pub int: i32,
    /// `long` and `unsigned long`.
    pub long: i32,
    /// `long long`.
    pub long_long: i32,
    /// `wchar_t`.
    pub wchar: i32,
}

impl DataOrganization {
    /// Windows x64 (LLP64): 8 byte pointers, 4 byte `long`, 2 byte `wchar_t`.
    pub const WINDOWS_X64: Self = Self {
        pointer: 8,
        int: 4,
        long: 4,
        long_long: 8,
        wchar: 2,
    };
}

/// What kind of data type a row describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataTypeKind {
    /// A Java built-in type referenced by class name.
    BuiltIn,
    /// A structure.
    Structure,
    /// A union.
    Union,
    /// An enum.
    Enum,
    /// A typedef.
    TypeDef,
    /// A pointer.
    Pointer,
    /// An array.
    Array,
    /// A function definition.
    FunctionDefinition,
    /// `DataType.DEFAULT` (id 0).
    Default,
    /// A bit field (id tag 9); only its id is decoded.
    BitField,
}

impl DataTypeKind {
    /// The name the oracle prints.
    pub fn name(self) -> &'static str {
        match self {
            Self::BuiltIn => "BUILTIN",
            Self::Structure => "STRUCT",
            Self::Union => "UNION",
            Self::Enum => "ENUM",
            Self::TypeDef => "TYPEDEF",
            Self::Pointer => "POINTER",
            Self::Array => "ARRAY",
            Self::FunctionDefinition => "FUNCDEF",
            Self::Default => "DEFAULT",
            Self::BitField => "BITFIELD",
        }
    }
}

/// One data type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataType {
    /// Data type id.
    pub id: i64,
    /// Kind.
    pub kind: DataTypeKind,
    /// Name as Java shows it (computed for pointers and arrays).
    pub name: String,
    /// Id of the category (0 is the root).
    pub category_id: i64,
    /// Category path, `/` for the root.
    pub category_path: String,
    /// `DataType.getPathName`: category path and name.
    pub path: String,
    /// Length in bytes (`DataType.getLength`); `None` when it depends on something this port does
    /// not know (a dynamic built-in, an unknown built-in class, a type built on those).
    pub size: Option<i32>,
    /// Comment (composites, enums, function definitions).
    pub comment: Option<String>,
    /// Java class name of a built-in type.
    pub class_name: Option<String>,
    /// Target of a typedef or pointer, element of an array.
    pub base: Option<i64>,
    /// Array: number of elements.
    pub elements: Option<i32>,
    /// Pointer: stored length (`<= 0` means the language's pointer size).
    pub pointer_length: Option<i32>,
}

/// A defined component of a structure or union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// Ordinal within the parent.
    pub ordinal: i32,
    /// Byte offset (structures; 0 for unions).
    pub offset: i32,
    /// Data type id of the component.
    pub datatype_id: i64,
    /// Field name, when set.
    pub name: Option<String>,
    /// Comment, when set.
    pub comment: Option<String>,
    /// Component length in bytes.
    pub length: i32,
}

/// A value of an enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumValue {
    /// Name.
    pub name: String,
    /// Value.
    pub value: i64,
    /// Comment, when set.
    pub comment: Option<String>,
}

/// A parameter of a function definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterDef {
    /// Ordinal.
    pub ordinal: i32,
    /// Name, when set.
    pub name: Option<String>,
    /// Data type id.
    pub datatype_id: i64,
    /// Comment, when set.
    pub comment: Option<String>,
}

/// The details of a function definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDef {
    /// Return type id.
    pub return_type: i64,
    /// Parameters in ordinal order.
    pub parameters: Vec<ParameterDef>,
    /// Takes variable arguments.
    pub var_args: bool,
    /// Does not return.
    pub no_return: bool,
    /// Calling convention name (`default`, `unknown` or a stored name).
    pub calling_convention: String,
}

/// Every data type of a program.
#[derive(Debug, Clone)]
pub struct DataTypes {
    types: BTreeMap<i64, DataType>,
    components: HashMap<i64, Vec<Component>>,
    enum_values: HashMap<i64, Vec<EnumValue>>,
    functions: HashMap<i64, FunctionDef>,
    categories: BTreeMap<i64, (String, i64)>,
}

fn kind_of(id: i64) -> i64 {
    id >> KIND_SHIFT
}

/// Raw (pre-resolution) description of a type.
struct Raw {
    kind: DataTypeKind,
    name: Option<String>,
    category: i64,
    comment: Option<String>,
    class_name: Option<String>,
    base: Option<i64>,
    elements: Option<i32>,
    stored_length: i32,
    pointer_length: Option<i32>,
}

pub(crate) fn read<S: BufferStore>(db: &Database<S>, org: DataOrganization) -> Result<DataTypes> {
    let mut conventions: BTreeMap<u8, String> = BTreeMap::new();
    if let Ok(t) = db.table("Calling Conventions") {
        for rec in t.records()? {
            let rec = rec?;
            if let (Field::Byte(id), Some(Field::String(Some(name)))) =
                (&rec.key, rec.values.first().and_then(Option::as_ref))
            {
                conventions.insert(*id as u8, name.as_str().to_owned());
            }
        }
    }
    let mut categories = BTreeMap::new();
    if let Ok(t) = db.table("Categories") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            let id = rec.key.long_value().unwrap_or(0);
            categories.insert(
                id,
                (
                    c.string(&rec, "Name")?.unwrap_or_default(),
                    c.long(&rec, "Parent ID")?.unwrap_or(0),
                ),
            );
        }
    }

    let mut raw: BTreeMap<i64, Raw> = BTreeMap::new();
    let blank = |kind| Raw {
        kind,
        name: None,
        category: 0,
        comment: None,
        class_name: None,
        base: None,
        elements: None,
        stored_length: 0,
        pointer_length: None,
    };
    if let Ok(t) = db.table("Built-in datatypes") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            let id = rec.key.long_value().unwrap_or(0);
            raw.insert(
                id,
                Raw {
                    name: c.string(&rec, "Name")?,
                    class_name: c.string(&rec, "Class Name")?,
                    category: c.long(&rec, "Category ID")?.unwrap_or(0),
                    ..blank(DataTypeKind::BuiltIn)
                },
            );
        }
    }
    if let Ok(t) = db.table("Composite Data Types") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            let id = rec.key.long_value().unwrap_or(0);
            let union = c.boolean(&rec, "Is Union")?.unwrap_or(false);
            raw.insert(
                id,
                Raw {
                    name: c.string(&rec, "Name")?,
                    comment: c.string(&rec, "Comment")?,
                    category: c.long(&rec, "Category ID")?.unwrap_or(0),
                    stored_length: c.int(&rec, "Length")?.unwrap_or(0),
                    ..blank(if union {
                        DataTypeKind::Union
                    } else {
                        DataTypeKind::Structure
                    })
                },
            );
        }
    }
    if let Ok(t) = db.table("Enumeration Data Types") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            let id = rec.key.long_value().unwrap_or(0);
            raw.insert(
                id,
                Raw {
                    name: c.string(&rec, "Name")?,
                    comment: c.string(&rec, "Comment")?,
                    category: c.long(&rec, "Category ID")?.unwrap_or(0),
                    stored_length: i32::from(c.byte(&rec, "Size")?.unwrap_or(0)),
                    ..blank(DataTypeKind::Enum)
                },
            );
        }
    }
    if let Ok(t) = db.table("Typedefs") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            let id = rec.key.long_value().unwrap_or(0);
            raw.insert(
                id,
                Raw {
                    name: c.string(&rec, "Name")?,
                    category: c.long(&rec, "Category ID")?.unwrap_or(0),
                    base: c.long(&rec, "Data Type ID")?,
                    ..blank(DataTypeKind::TypeDef)
                },
            );
        }
    }
    if let Ok(t) = db.table("Pointers") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            let id = rec.key.long_value().unwrap_or(0);
            raw.insert(
                id,
                Raw {
                    category: c.long(&rec, "Category ID")?.unwrap_or(0),
                    base: c.long(&rec, "Data Type ID")?,
                    pointer_length: Some(i32::from(c.byte(&rec, "Length")?.unwrap_or(0))),
                    ..blank(DataTypeKind::Pointer)
                },
            );
        }
    }
    if let Ok(t) = db.table("Arrays") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            let id = rec.key.long_value().unwrap_or(0);
            raw.insert(
                id,
                Raw {
                    category: c.long(&rec, "Cat ID")?.unwrap_or(0),
                    base: c.long(&rec, "Data Type ID")?,
                    elements: c.int(&rec, "Dimension")?,
                    stored_length: c.int(&rec, "Length")?.unwrap_or(0),
                    ..blank(DataTypeKind::Array)
                },
            );
        }
    }
    let mut functions = HashMap::new();
    if let Ok(t) = db.table("Function Definitions") {
        let c = Cols::new(t.schema());
        let mut params: HashMap<i64, Vec<ParameterDef>> = HashMap::new();
        if let Ok(p) = db.table("Function Parameters") {
            let pc = Cols::new(p.schema());
            for rec in p.records()? {
                let rec = rec?;
                params
                    .entry(pc.long(&rec, "Parent ID")?.unwrap_or(0))
                    .or_default()
                    .push(ParameterDef {
                        ordinal: pc.int(&rec, "Ordinal")?.unwrap_or(0),
                        name: pc.string(&rec, "Name")?,
                        datatype_id: pc.long(&rec, "Data Type ID")?.unwrap_or(-1),
                        comment: pc.string(&rec, "Comment")?,
                    });
            }
        }
        for rec in t.records()? {
            let rec = rec?;
            let id = rec.key.long_value().unwrap_or(0);
            raw.insert(
                id,
                Raw {
                    name: c.string(&rec, "Name")?,
                    comment: c.string(&rec, "Comment")?,
                    category: c.long(&rec, "Category ID")?.unwrap_or(0),
                    ..blank(DataTypeKind::FunctionDefinition)
                },
            );
            let flags = c.byte(&rec, "Flags")?.unwrap_or(0);
            let cc = c.byte(&rec, "Call Conv ID")?.unwrap_or(0) as u8;
            let mut list = params.remove(&id).unwrap_or_default();
            list.sort_by_key(|p| p.ordinal);
            functions.insert(
                id,
                FunctionDef {
                    return_type: c.long(&rec, "Return Type ID")?.unwrap_or(-1),
                    parameters: list,
                    var_args: flags & 0x1 != 0,
                    no_return: flags & 0x2 != 0,
                    calling_convention: match cc {
                        1 => "default".to_owned(),
                        0 => "unknown".to_owned(),
                        n => conventions
                            .get(&n)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_owned()),
                    },
                },
            );
        }
    }

    let mut components: HashMap<i64, Vec<Component>> = HashMap::new();
    if let Ok(t) = db.table("Component Data Types") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            components
                .entry(c.long(&rec, "Parent")?.unwrap_or(0))
                .or_default()
                .push(Component {
                    ordinal: c.int(&rec, "Ordinal")?.unwrap_or(0),
                    offset: c.int(&rec, "Offset")?.unwrap_or(0),
                    datatype_id: c.long(&rec, "Data Type ID")?.unwrap_or(-1),
                    name: c.string(&rec, "Field Name")?,
                    comment: c.string(&rec, "Comment")?,
                    length: c.int(&rec, "Component Size")?.unwrap_or(0),
                });
        }
        for list in components.values_mut() {
            list.sort_by_key(|x| x.ordinal);
        }
    }
    let mut enum_values: HashMap<i64, Vec<EnumValue>> = HashMap::new();
    if let Ok(t) = db.table("Enumeration Values") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            enum_values
                .entry(c.long(&rec, "Enum ID")?.unwrap_or(0))
                .or_default()
                .push(EnumValue {
                    name: c.string(&rec, "Name")?.unwrap_or_default(),
                    value: c.long(&rec, "Value")?.unwrap_or(0),
                    comment: c.string(&rec, "Comment")?,
                });
        }
        // EnumDB.getNames: by value, then name
        for list in enum_values.values_mut() {
            list.sort_by(|a, b| (a.value, &a.name).cmp(&(b.value, &b.name)));
        }
    }

    let resolver = Resolver {
        raw: &raw,
        categories: &categories,
        org,
    };
    let mut types = BTreeMap::new();
    types.insert(
        0,
        DataType {
            id: 0,
            kind: DataTypeKind::Default,
            name: "undefined".to_owned(),
            category_id: 0,
            category_path: "/".to_owned(),
            path: "/undefined".to_owned(),
            size: Some(1),
            comment: None,
            class_name: None,
            base: None,
            elements: None,
            pointer_length: None,
        },
    );
    for (&id, r) in &raw {
        let name = resolver.name(id, 0);
        let category_path = resolver.category_path(r.category);
        let path = if category_path == "/" {
            format!("/{name}")
        } else {
            format!("{category_path}/{name}")
        };
        types.insert(
            id,
            DataType {
                id,
                kind: r.kind,
                size: resolver.size(id, 0),
                name,
                category_id: r.category,
                category_path,
                path,
                comment: r.comment.clone(),
                class_name: r.class_name.clone(),
                base: r.base,
                elements: r.elements,
                pointer_length: r.pointer_length,
            },
        );
    }
    Ok(DataTypes {
        types,
        components,
        enum_values,
        functions,
        categories,
    })
}

struct Resolver<'a> {
    raw: &'a BTreeMap<i64, Raw>,
    categories: &'a BTreeMap<i64, (String, i64)>,
    org: DataOrganization,
}

impl Resolver<'_> {
    fn category_path(&self, mut id: i64) -> String {
        let mut parts = Vec::new();
        let mut guard = 0;
        while id != 0 && guard < 256 {
            let Some((name, parent)) = self.categories.get(&id) else {
                break;
            };
            parts.push(name.clone());
            id = *parent;
            guard += 1;
        }
        if parts.is_empty() {
            return "/".to_owned();
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    /// `DataType.getName` of a resolved id (`undefined` for the default type).
    fn name(&self, id: i64, depth: u32) -> String {
        if id == 0 {
            return "undefined".to_owned();
        }
        let Some(r) = self.raw.get(&id) else {
            return String::new();
        };
        if depth > 64 {
            return String::new();
        }
        match r.kind {
            DataTypeKind::Pointer => {
                let len = r.pointer_length.unwrap_or(0);
                let len_str = if len > 0 {
                    (len * 8).to_string()
                } else {
                    String::new()
                };
                match r.base.filter(|b| self.known(*b)) {
                    Some(b) => format!("{} *{len_str}", self.name(b, depth + 1)),
                    None => format!("pointer{len_str}"),
                }
            }
            DataTypeKind::Array => {
                let mut dims = String::new();
                let mut cur = id;
                let mut base_id = 0;
                for _ in 0..64 {
                    let Some(a) = self.raw.get(&cur) else { break };
                    dims.push_str(&format!("[{}]", a.elements.unwrap_or(0)));
                    let b = a.base.unwrap_or(0);
                    base_id = b;
                    if self
                        .raw
                        .get(&b)
                        .is_some_and(|x| x.kind == DataTypeKind::Array)
                    {
                        cur = b;
                    } else {
                        break;
                    }
                }
                let base_name = self.name(base_id, depth + 1);
                format!("{base_name}{dims}")
            }
            _ => r.name.clone().unwrap_or_default(),
        }
    }

    fn known(&self, id: i64) -> bool {
        id == 0 || self.raw.contains_key(&id)
    }

    fn size(&self, id: i64, depth: u32) -> Option<i32> {
        if id == 0 {
            return Some(1);
        }
        if depth > 64 {
            return None;
        }
        let r = self.raw.get(&id)?;
        match r.kind {
            DataTypeKind::BuiltIn => builtin_size(r.class_name.as_deref()?, self.org),
            DataTypeKind::Structure | DataTypeKind::Union => Some(if r.stored_length == 0 {
                1
            } else {
                r.stored_length
            }),
            DataTypeKind::Enum => Some(r.stored_length),
            DataTypeKind::TypeDef => self.size(r.base?, depth + 1),
            DataTypeKind::Pointer => {
                let len = r.pointer_length.unwrap_or(0);
                Some(if len > 0 { len } else { self.org.pointer })
            }
            DataTypeKind::Array => {
                let n = r.elements.unwrap_or(0);
                if n == 0 {
                    return Some(1);
                }
                let base = r.base.unwrap_or(0);
                let element = self.size(base, depth + 1)?;
                Some(n.wrapping_mul(element))
            }
            DataTypeKind::FunctionDefinition => Some(-1),
            DataTypeKind::Default | DataTypeKind::BitField => None,
        }
    }
}

/// Fixed sizes of the built-in classes that need no compiler information.
fn builtin_size(class: &str, org: DataOrganization) -> Option<i32> {
    let simple = class.rsplit('.').next()?;
    Some(match simple {
        "ByteDataType"
        | "CharDataType"
        | "UnsignedCharDataType"
        | "SignedCharDataType"
        | "BooleanDataType"
        | "Undefined1DataType"
        | "UndefinedDataType" => 1,
        "WordDataType"
        | "ShortDataType"
        | "UnsignedShortDataType"
        | "Undefined2DataType"
        | "WideChar16DataType" => 2,
        "Undefined3DataType" => 3,
        "DWordDataType" | "FloatDataType" | "Undefined4DataType" | "IBO32DataType"
        | "WideChar32DataType" => 4,
        "Undefined5DataType" => 5,
        "Undefined6DataType" => 6,
        "Undefined7DataType" => 7,
        "QWordDataType"
        | "DoubleDataType"
        | "Undefined8DataType"
        | "IBO64DataType"
        | "LongLongDataType"
        | "UnsignedLongLongDataType" => 8,
        "GuidDataType" => 16,
        "VoidDataType" => 0,
        "ImageBaseOffset32DataType" => 4,
        "ImageBaseOffset64DataType" => 8,
        // dynamic types report -1
        "StringDataType"
        | "TerminatedStringDataType"
        | "UnicodeDataType"
        | "TerminatedUnicodeDataType"
        | "String32DataType"
        | "Unicode32DataType"
        | "PERichTableDataType"
        | "PEx64UnwindInfoDataType" => -1,
        "IntegerDataType" | "UnsignedIntegerDataType" => org.int,
        "LongDataType" | "UnsignedLongDataType" => org.long,
        "WideCharDataType" => org.wchar,
        "PointerDataType" => org.pointer,
        "Pointer8DataType" => 1,
        "Pointer16DataType" => 2,
        "Pointer32DataType" => 4,
        "Pointer64DataType" => 8,
        _ => return None,
    })
}

impl DataTypes {
    /// The type with this id (`DataTypeManager.getDataType(long)`).
    pub fn get(&self, id: i64) -> Option<&DataType> {
        self.types.get(&id)
    }

    /// Every stored type in id order (the default type first).
    pub fn all(&self) -> impl Iterator<Item = &DataType> {
        self.types.values()
    }

    /// Defined components of a structure or union, ordinal order.
    pub fn components(&self, id: i64) -> &[Component] {
        self.components.get(&id).map_or(&[], Vec::as_slice)
    }

    /// Values of an enum, by value then name.
    pub fn enum_values(&self, id: i64) -> &[EnumValue] {
        self.enum_values.get(&id).map_or(&[], Vec::as_slice)
    }

    /// Details of a function definition.
    pub fn function_def(&self, id: i64) -> Option<&FunctionDef> {
        self.functions.get(&id)
    }

    /// The path of a category (`/` for the root).
    pub fn category_path(&self, id: i64) -> Option<String> {
        if id != 0 && !self.categories.contains_key(&id) {
            return None;
        }
        let mut parts = Vec::new();
        let mut cur = id;
        while cur != 0 {
            let (name, parent) = self.categories.get(&cur)?;
            parts.push(name.clone());
            cur = *parent;
            if parts.len() > 256 {
                return None;
            }
        }
        parts.reverse();
        Some(if parts.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", parts.join("/"))
        })
    }

    /// Every category as (id, path), the root (id 0, path `/`) first.
    pub fn categories(&self) -> Vec<(i64, String)> {
        let mut out = vec![(0, "/".to_owned())];
        out.extend(
            self.categories
                .keys()
                .filter_map(|&id| self.category_path(id).map(|p| (id, p))),
        );
        out
    }

    /// The type with this slash path, for example `/PE/IMAGE_DOS_HEADER`.
    pub fn by_path(&self, path: &str) -> Option<&DataType> {
        self.types.values().find(|t| t.path == path)
    }

    /// The table tag of an id (`id >> 56`).
    pub fn id_kind_tag(id: i64) -> i64 {
        kind_of(id)
    }
}
