//! `db.Schema`.

use std::collections::BTreeSet;

use crate::{Field, FieldError, FieldType, Result};

const NAME_SEPARATOR: char = ';';
/// Marks the start of schema extension data in the encoded field types.
pub const FIELD_EXTENSION_INDICATOR: u8 = 0xff;
const SPARSE_FIELD_LIST_EXTENSION: i8 = 1;

/// Table schema: key type and name, column types and names, optional sparse columns.
#[derive(Debug, Clone)]
pub struct Schema {
    version: i32,
    key_type: FieldType,
    key_name: String,
    fields: Vec<FieldType>,
    field_names: Vec<String>,
    sparse: Option<BTreeSet<usize>>,
    is_variable_length: bool,
    fixed_length: usize,
    force_variable_key_nodes: bool,
}

impl Schema {
    /// Build a schema (`new Schema(version, keyField, keyName, fields, fieldNames, sparseColumns)`).
    pub fn new(
        version: i32,
        key_type: FieldType,
        key_name: &str,
        fields: Vec<FieldType>,
        field_names: Vec<String>,
        sparse_columns: &[usize],
    ) -> Result<Self> {
        if fields.len() != field_names.len() {
            return Err(FieldError::IllegalArgument(
                "fieldNames and fields lengths differ",
            ));
        }
        let mut is_variable_length = false;
        let mut fixed_length = 0;
        for (f, n) in fields.iter().zip(&field_names) {
            is_variable_length |= f.is_variable_length();
            fixed_length += f.instance_length();
            if n.contains(NAME_SEPARATOR) {
                return Err(FieldError::IllegalArgument(
                    "field names may not contain ';'",
                ));
            }
        }
        let mut schema = Self {
            version,
            key_type,
            key_name: key_name.to_owned(),
            fields,
            field_names,
            sparse: None,
            is_variable_length,
            fixed_length,
            force_variable_key_nodes: false,
        };
        schema.initialize_sparse(sparse_columns)?;
        if schema.is_variable_length {
            schema.fixed_length = 0;
        }
        Ok(schema)
    }

    /// Rebuild a schema from the master table encoding (`Schema(version, keyType, fieldTypes, names)`).
    pub fn from_encoded(
        version: i32,
        encoded_key_type: u8,
        encoded_field_types: &[u8],
        packed_names: &str,
    ) -> Result<Self> {
        let key_type = FieldType::from_code(encoded_key_type)?;
        // StringTokenizer: empty tokens are skipped
        let mut names = packed_names
            .split(NAME_SEPARATOR)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let key_name = names
            .next()
            .ok_or(FieldError::IllegalArgument("no key name in packed names"))?;
        let field_names: Vec<String> = names.collect();

        let mut fields = Vec::new();
        let mut index = 0;
        let mut is_variable_length = false;
        let mut fixed_length = 0;
        while index < encoded_field_types.len() {
            let b = encoded_field_types[index];
            index += 1;
            if b == FIELD_EXTENSION_INDICATOR {
                break;
            }
            let f = FieldType::from_code(b)?;
            is_variable_length |= f.is_variable_length();
            fixed_length += f.instance_length();
            fields.push(f);
        }
        let mut schema = Self {
            version,
            key_type,
            key_name,
            fields,
            field_names,
            sparse: None,
            is_variable_length,
            fixed_length,
            force_variable_key_nodes: false,
        };
        while index < encoded_field_types.len() {
            let ext = encoded_field_types[index] as i8;
            index += 1;
            if ext != SPARSE_FIELD_LIST_EXTENSION {
                return Err(FieldError::UnsupportedSchema(format!(
                    "Unsupported field extension type: {ext}"
                )));
            }
            let mut cols = Vec::new();
            while index < encoded_field_types.len()
                && encoded_field_types[index] != FIELD_EXTENSION_INDICATOR
            {
                // signed byte widened to int, as in Java (negative values are rejected below)
                cols.push(i32::from(encoded_field_types[index] as i8));
                index += 1;
            }
            schema.initialize_sparse_signed(&cols)?;
        }
        if schema.is_variable_length {
            schema.fixed_length = 0;
        }
        if schema.field_names.len() != schema.fields.len() {
            return Err(FieldError::IllegalArgument(
                "fieldNames and column types differ in length",
            ));
        }
        Ok(schema)
    }

    fn initialize_sparse(&mut self, cols: &[usize]) -> Result<()> {
        let signed: Vec<i32> = cols
            .iter()
            .map(|&c| i32::try_from(c).unwrap_or(i32::MAX))
            .collect();
        self.initialize_sparse_signed(&signed)
    }

    fn initialize_sparse_signed(&mut self, cols: &[i32]) -> Result<()> {
        if cols.is_empty() {
            return Ok(());
        }
        let mut set = BTreeSet::new();
        for &c in cols {
            if c < 0 || c > i32::from(i8::MAX) || c as usize >= self.fields.len() {
                return Err(FieldError::UnsupportedSchema(format!(
                    "Sparse column entry out of range: {c}"
                )));
            }
            set.insert(c as usize);
        }
        if set.len() != cols.len() {
            return Err(FieldError::UnsupportedSchema(
                "Sparse column set contains duplicate entry".into(),
            ));
        }
        self.sparse = Some(set);
        self.is_variable_length = true; // sparse records are variable length
        Ok(())
    }

    /// Schema version.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Key type.
    pub fn key_type(&self) -> &FieldType {
        &self.key_type
    }

    /// Key column name.
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// Column types.
    pub fn fields(&self) -> &[FieldType] {
        &self.fields
    }

    /// Column names.
    pub fn field_names(&self) -> &[String] {
        &self.field_names
    }

    /// True when any column is variable length or the schema is sparse.
    pub fn is_variable_length(&self) -> bool {
        self.is_variable_length
    }

    /// Record length for fixed-length schemas, 0 otherwise.
    pub fn fixed_length(&self) -> usize {
        self.fixed_length
    }

    /// True when the schema has sparse columns.
    pub fn has_sparse_columns(&self) -> bool {
        self.sparse.is_some()
    }

    /// True when column `i` is sparse.
    pub fn is_sparse_column(&self, i: usize) -> bool {
        self.sparse.as_ref().is_some_and(|s| s.contains(&i))
    }

    /// Tables keyed by `LongField` use the long-key node family.
    pub fn use_long_key_nodes(&self) -> bool {
        !self.force_variable_key_nodes && self.key_type == FieldType::Long
    }

    /// Variable-length-key node family.
    pub fn use_variable_key_nodes(&self) -> bool {
        self.force_variable_key_nodes || self.key_type.is_variable_length()
    }

    /// Fixed-length-key node family.
    pub fn use_fixed_key_nodes(&self) -> bool {
        !self.use_variable_key_nodes() && !self.use_long_key_nodes()
    }

    /// Legacy hack: a fixed-length primitive key stored in var-key nodes
    /// (`forceUseOfVariableLengthKeyNodes`).
    pub fn force_use_of_variable_length_key_nodes(&mut self) {
        self.force_variable_key_nodes = true;
    }

    /// True after [`Schema::force_use_of_variable_length_key_nodes`].
    pub fn forces_variable_length_key_nodes(&self) -> bool {
        self.force_variable_key_nodes
    }

    /// `getEncodedKeyFieldType`.
    pub fn encoded_key_field_type(&self) -> u8 {
        self.key_type.code()
    }

    /// `getEncodedFieldTypes`. Sparse columns are listed in ascending order (Java iterates an
    /// unordered `Set.copyOf`).
    pub fn encoded_field_types(&self) -> Vec<u8> {
        let mut out: Vec<u8> = self.fields.iter().map(FieldType::code).collect();
        if let Some(s) = &self.sparse {
            out.push(FIELD_EXTENSION_INDICATOR);
            out.push(SPARSE_FIELD_LIST_EXTENSION as u8);
            out.extend(s.iter().map(|&c| c as u8));
        }
        out
    }

    /// `getPackedFieldNames`.
    pub fn packed_field_names(&self) -> String {
        let mut s = format!("{}{NAME_SEPARATOR}", self.key_name);
        for n in &self.field_names {
            s.push_str(n);
            s.push(NAME_SEPARATOR);
        }
        s
    }

    /// Structural equality as `Schema.equals`: version, key type, column types, sparse set.
    /// Names are not compared.
    pub fn same_as(&self, other: &Schema) -> bool {
        self.version == other.version
            && self.key_type == other.key_type
            && self.fields == other.fields
            && self.sparse == other.sparse
    }

    /// An empty value of column `i`'s type is not constructible generically; this returns the
    /// column type for validation of values being stored.
    pub(crate) fn check_value(&self, col: usize, value: &Field) -> Result<()> {
        if self
            .fields
            .get(col)
            .is_some_and(|t| *t == value.field_type())
        {
            Ok(())
        } else {
            Err(FieldError::TypeMismatch)
        }
    }
}
