//! Read path of `db.DBHandle`, `db.MasterTable`, `db.TableRecord`, `db.Table` and the
//! secondary index tables (`db.FieldIndexTable`).
//!
//! A [`Database`] owns a [`BufferStore`] (a saved `.gbf` as [`ghidra_fmt_gbf::BufferFile`], or an
//! in-memory store), reads the database parameters and the master table, and hands out
//! [`Table`] views. Tables are read through the B-tree family their schema selects.

use std::fmt;

use ghidra_fmt_btree::{
    BtreeError, NodeType,
    fieldkey::FieldKeyTree,
    keywrite::{FixedKeyWriter, LongKeyWriter},
    longkey::LongKeyTree,
    varwrite::VarKeyWriter,
};
use ghidra_fmt_chain::{ChainError, DbParms};
use ghidra_fmt_field::{Field, FieldError, FieldType, IndexValue, JString, Record, Schema};
use ghidra_fmt_gbf::{BufferStore, BufferStoreMut, GbfError};

/// Database errors.
#[derive(Debug)]
pub enum DbError {
    /// Block file failure.
    Gbf(GbfError),
    /// Chained buffer / parameter failure.
    Chain(ChainError),
    /// B-tree failure.
    Btree(BtreeError),
    /// Field or schema failure.
    Field(FieldError),
    /// Structurally invalid database.
    Corrupt(String),
    /// No table with that name.
    TableNotFound(String),
    /// A table with that name exists already.
    TableExists(String),
    /// Not supported by this port (for example writing field-key tables).
    Unsupported(&'static str),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gbf(e) => write!(f, "{e}"),
            Self::Chain(e) => write!(f, "{e}"),
            Self::Btree(e) => write!(f, "{e}"),
            Self::Field(e) => write!(f, "{e}"),
            Self::Corrupt(m) => write!(f, "corrupt database: {m}"),
            Self::TableNotFound(n) => write!(f, "table not found: {n}"),
            Self::TableExists(n) => write!(f, "Table already exists: {n}"),
            Self::Unsupported(w) => write!(f, "unsupported: {w}"),
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gbf(e) => Some(e),
            Self::Chain(e) => Some(e),
            Self::Btree(e) => Some(e),
            Self::Field(e) => Some(e),
            _ => None,
        }
    }
}

macro_rules! from_err {
    ($t:ty, $v:ident) => {
        impl From<$t> for DbError {
            fn from(e: $t) -> Self {
                Self::$v(e)
            }
        }
    };
}
from_err!(GbfError, Gbf);
from_err!(ChainError, Chain);
from_err!(BtreeError, Btree);
from_err!(FieldError, Field);

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, DbError>;

/// Column layout of a master table record (`TableRecord`).
pub fn master_schema() -> Schema {
    let fields = vec![
        FieldType::String,
        FieldType::Int,
        FieldType::Int,
        FieldType::Byte,
        FieldType::Binary,
        FieldType::String,
        FieldType::Int,
        FieldType::Long,
        FieldType::Int,
    ];
    let names = [
        "TableName",
        "SchemaVersion",
        "RootBufferId",
        "KeyType",
        "FieldTypes",
        "FieldNames",
        "IndexColumn",
        "MaxKey",
        "RecordCount",
    ]
    .map(str::to_owned)
    .to_vec();
    // `new Schema(0, "TableNum", fields, names)`: a long key, no sparse columns.
    match Schema::new(0, FieldType::Long, "TableNum", fields, names, &[]) {
        Ok(s) => s,
        Err(_) => unreachable!("static master schema is valid"),
    }
}

/// One master table row (`db.TableRecord`).
#[derive(Debug, Clone)]
pub struct TableRecord {
    /// Table number (master table key).
    pub table_num: i64,
    /// Table name; index tables carry the name of the table they index.
    pub name: String,
    /// Parsed schema.
    pub schema: Schema,
    /// Root buffer id, `-1` for a table that never stored a record.
    pub root_buffer_id: i32,
    /// Indexed column, `-1` for a primary table.
    pub indexed_column: i32,
    /// Largest long key ever used.
    pub max_key: i64,
    /// Record count.
    pub record_count: i32,
}

fn col_str(r: &Record, i: usize) -> Result<String> {
    match r.values.get(i) {
        Some(Some(Field::String(Some(s)))) => Ok(s.as_str().to_owned()),
        Some(Some(Field::String(None))) => Ok(String::new()),
        _ => Err(DbError::Corrupt(format!(
            "master column {i} is not a string"
        ))),
    }
}

fn col_int(r: &Record, i: usize) -> Result<i32> {
    match r.values.get(i) {
        Some(Some(Field::Int(v))) => Ok(*v),
        _ => Err(DbError::Corrupt(format!("master column {i} is not an int"))),
    }
}

impl TableRecord {
    fn from_record(store: &dyn BufferStore, r: &Record) -> Result<Self> {
        let table_num = r
            .key
            .long_value()
            .ok_or_else(|| DbError::Corrupt("master key is not a long".into()))?;
        let version = col_int(r, 1)?;
        let root = col_int(r, 2)?;
        let key_type = match r.values.get(3) {
            Some(Some(Field::Byte(v))) => *v as u8,
            _ => return Err(DbError::Corrupt("master key type column".into())),
        };
        let types: &[u8] = match r.values.get(4) {
            Some(Some(Field::Binary(Some(b)))) => b,
            Some(Some(Field::Binary(None))) => &[],
            _ => return Err(DbError::Corrupt("master field types column".into())),
        };
        let mut schema = Schema::from_encoded(version, key_type, types, &col_str(r, 5)?)?;
        force_var_key_nodes_if_needed(store, &mut schema, root)?;
        let max_key = match r.values.get(7) {
            Some(Some(Field::Long(v))) => *v,
            _ => return Err(DbError::Corrupt("master max key column".into())),
        };
        Ok(Self {
            table_num,
            name: col_str(r, 0)?,
            schema,
            root_buffer_id: root,
            indexed_column: col_int(r, 6)?,
            max_key,
            record_count: col_int(r, 8)?,
        })
    }
}

/// `TableRecord.forceUseOfVariableLengthKeyNodesIfNeeded`: a legacy table with a primitive
/// fixed-length key (other than long, index and fixed) may have been stored in var-key nodes.
fn force_var_key_nodes_if_needed(
    store: &dyn BufferStore,
    schema: &mut Schema,
    root: i32,
) -> Result<()> {
    if root < 0 {
        return Ok(());
    }
    let kt = schema.key_type();
    if kt.is_variable_length()
        || matches!(
            kt,
            FieldType::Long
                | FieldType::Index { .. }
                | FieldType::LegacyIndex { .. }
                | FieldType::Fixed10
        )
    {
        return Ok(());
    }
    let buf = store.get_buffer(root)?;
    let data = buf
        .data
        .as_deref()
        .ok_or_else(|| DbError::Corrupt(format!("table root buffer {root} is empty")))?;
    let t = data.first().copied().unwrap_or(0xff);
    if t == NodeType::VarKeyInterior as u8 || t == NodeType::VarKeyRec as u8 {
        schema.force_use_of_variable_length_key_nodes();
    }
    Ok(())
}

/// Writer of one table tree, by node family.
enum Tree {
    Long(LongKeyWriter),
    Fixed(FixedKeyWriter),
    Var(VarKeyWriter),
}

impl Tree {
    fn put<S: BufferStoreMut>(&mut self, s: &mut S, key: &Field, data: &[u8]) -> Result<bool> {
        Ok(match self {
            Self::Long(w) => w.put(s, key.long_value().ok_or(FieldError::TypeMismatch)?, data)?,
            Self::Fixed(w) => w.put(s, key, data)?,
            Self::Var(w) => w.put(s, key, data)?,
        })
    }

    fn delete<S: BufferStoreMut>(&mut self, s: &mut S, key: &Field) -> Result<bool> {
        Ok(match self {
            Self::Long(w) => w.delete(s, key.long_value().ok_or(FieldError::TypeMismatch)?)?,
            Self::Fixed(w) => w.delete(s, key)?,
            Self::Var(w) => w.delete(s, key)?,
        })
    }

    fn root(&self) -> i32 {
        match self {
            Self::Long(w) => w.root(),
            Self::Fixed(w) => w.root(),
            Self::Var(w) => w.root(),
        }
    }
}

/// An open database.
pub struct Database<S: BufferStore> {
    store: S,
    params: DbParms,
    tables: Vec<TableRecord>,
    master_root: i32,
    next_table_num: i64,
}

impl<S: BufferStore> Database<S> {
    /// Open the database stored in `store` (`new DBHandle(bufferFile)`).
    pub fn open(store: S) -> Result<Self> {
        let params = DbParms::read(&store)?;
        let root = params.master_table_root()?;
        let schema = master_schema();
        let mut tables = Vec::new();
        if root >= 0 {
            let tree = LongKeyTree::new(&store, root, None);
            for rec in tree.records()? {
                let rec = rec?;
                let (r, _) = schema.read_record(Field::Long(rec.key), &rec.data, 0)?;
                tables.push(TableRecord::from_record(&store, &r)?);
            }
        }
        let next_table_num = tables.last().map_or(0, |t| t.table_num + 1);
        Ok(Self {
            store,
            params,
            tables,
            master_root: root,
            next_table_num,
        })
    }

    /// Give back the store (to save it, for example).
    pub fn into_store(self) -> S {
        self.store
    }

    /// The underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Database id (`getDatabaseId`).
    pub fn database_id(&self) -> Result<i64> {
        Ok(self.params.database_id()?)
    }

    /// All master table rows, index tables included, ordered by table number.
    pub fn table_records(&self) -> &[TableRecord] {
        &self.tables
    }

    /// Primary tables, ordered by table number.
    pub fn tables(&self) -> impl Iterator<Item = Table<'_, S>> {
        self.tables
            .iter()
            .filter(|t| t.indexed_column == -1)
            .map(|record| Table { db: self, record })
    }

    /// Every table including index tables, ordered by table number.
    pub fn all_tables(&self) -> impl Iterator<Item = Table<'_, S>> {
        self.tables.iter().map(|record| Table { db: self, record })
    }

    /// Primary table by name (`getTable`).
    pub fn table(&self, name: &str) -> Result<Table<'_, S>> {
        self.tables()
            .find(|t| t.name() == name)
            .ok_or_else(|| DbError::TableNotFound(name.to_owned()))
    }

    /// Secondary index tables of `name`, ordered by table number.
    pub fn index_tables(&self, name: &str) -> Vec<Table<'_, S>> {
        self.tables
            .iter()
            .filter(|t| t.indexed_column >= 0 && t.name == name)
            .map(|record| Table { db: self, record })
            .collect()
    }
}

impl<S: BufferStoreMut> Database<S> {
    /// Create an empty database in `store`, which must hold no buffers (`new DBHandle(size)`):
    /// buffer 0 becomes the parameter buffer, the master table is empty and the database id is
    /// `database_id` (Java draws it from `UniversalIdGenerator`).
    pub fn create(mut store: S, database_id: i64) -> Result<Self> {
        let mut params = DbParms::create(&mut store)?;
        params.set(&mut store, 0, -1)?;
        params.set(&mut store, 1, (database_id >> 32) as i32)?;
        params.set(&mut store, 2, database_id as i32)?;
        Ok(Self {
            store,
            params,
            tables: Vec::new(),
            master_root: -1,
            next_table_num: 0,
        })
    }

    fn master_row(t: &TableRecord) -> Record {
        let s = &t.schema;
        Record {
            key: Field::Long(t.table_num),
            values: vec![
                Some(Field::String(Some(JString::new(&t.name)))),
                Some(Field::Int(s.version())),
                Some(Field::Int(t.root_buffer_id)),
                Some(Field::Byte(s.encoded_key_field_type() as i8)),
                Some(Field::Binary(Some(s.encoded_field_types()))),
                Some(Field::String(Some(JString::new(&s.packed_field_names())))),
                Some(Field::Int(t.indexed_column)),
                Some(Field::Long(t.max_key)),
                Some(Field::Int(t.record_count)),
            ],
        }
    }

    /// Write master table row `i` (`Table.putRecord` on the master table).
    fn put_master_row(&mut self, i: usize) -> Result<()> {
        let row = Self::master_row(&self.tables[i]);
        let mut data = Vec::new();
        master_schema().write_record(&row, &mut data)?;
        let mut w = LongKeyWriter::new(self.master_root, None);
        w.put(&mut self.store, self.tables[i].table_num, &data)?;
        self.master_root = w.root();
        Ok(())
    }

    /// Define a new primary table without indexes (`DBHandle.createTable(name, schema)`).
    pub fn create_table(&mut self, name: &str, schema: Schema) -> Result<()> {
        self.create_indexed_table(name, schema, &[])
    }

    /// Define a new primary table and one index table per entry of `indexed_columns`
    /// (`DBHandle.createTable(name, schema, indexedColumns)`): the primary table's master row is
    /// written first, then the index tables' rows in column order.
    pub fn create_indexed_table(
        &mut self,
        name: &str,
        schema: Schema,
        indexed_columns: &[usize],
    ) -> Result<()> {
        if self
            .tables
            .iter()
            .any(|t| t.indexed_column == -1 && t.name == name)
        {
            return Err(DbError::TableExists(name.to_owned()));
        }
        let mut index_schemas = Vec::new();
        for &col in indexed_columns {
            let indexed = schema
                .fields()
                .get(col)
                .ok_or(DbError::Unsupported("indexed column out of range"))?
                .clone();
            let key = FieldType::Index {
                indexed: Box::new(indexed),
                primary: Box::new(schema.key_type().clone()),
            };
            index_schemas.push((col, Schema::new(0, key, "IndexKey", vec![], vec![], &[])?));
        }
        self.push_table(name, schema, -1)?;
        for (col, s) in index_schemas {
            self.push_table(name, s, col as i32)?;
        }
        Ok(())
    }

    fn push_table(&mut self, name: &str, schema: Schema, indexed_column: i32) -> Result<()> {
        self.tables.push(TableRecord {
            table_num: self.next_table_num,
            name: name.to_owned(),
            schema,
            root_buffer_id: -1,
            indexed_column,
            max_key: i64::MIN,
            record_count: 0,
        });
        self.next_table_num += 1;
        let i = self.tables.len() - 1;
        self.put_master_row(i)?;
        self.params.set(&mut self.store, 0, self.master_root)?;
        Ok(())
    }

    fn table_index(&self, name: &str) -> Result<usize> {
        let i = self
            .tables
            .iter()
            .position(|t| t.indexed_column == -1 && t.name == name)
            .ok_or_else(|| DbError::TableNotFound(name.to_owned()))?;
        Ok(i)
    }

    /// Positions of the index tables of table `i`, in the order `Table.indexedColumns` visits
    /// them (`IntObjectHashtable.getKeys`: by hash list, `column % 13`, then insertion order).
    fn index_positions(&self, i: usize) -> Vec<usize> {
        let name = &self.tables[i].name;
        let mut v: Vec<(i32, usize)> = self
            .tables
            .iter()
            .enumerate()
            .filter(|(_, t)| t.indexed_column >= 0 && &t.name == name)
            .map(|(p, t)| (t.indexed_column, p))
            .collect();
        v.sort_by_key(|(col, p)| (col % 13, *p));
        v.into_iter().map(|(_, p)| p).collect()
    }

    fn tree_for(&self, i: usize) -> Result<Tree> {
        let t = &self.tables[i];
        let fixed = (!t.schema.is_variable_length()).then(|| t.schema.fixed_length());
        Ok(if t.schema.use_long_key_nodes() {
            Tree::Long(LongKeyWriter::new(t.root_buffer_id, fixed))
        } else if t.schema.use_fixed_key_nodes() {
            Tree::Fixed(FixedKeyWriter::new(
                t.root_buffer_id,
                t.schema.key_type(),
                fixed,
            )?)
        } else {
            Tree::Var(VarKeyWriter::new(t.root_buffer_id, t.schema.key_type()))
        })
    }

    /// Put one record into table `i` and track root, count and (long keys) maximum key.
    fn put_raw(&mut self, i: usize, record: &Record) -> Result<bool> {
        let mut data = Vec::new();
        self.tables[i].schema.write_record(record, &mut data)?;
        let mut w = self.tree_for(i)?;
        let inserted = w.put(&mut self.store, &record.key, &data)?;
        let t = &mut self.tables[i];
        t.root_buffer_id = w.root();
        if let Field::Long(k) = record.key
            && t.schema.use_long_key_nodes()
            && t.max_key < k
        {
            t.max_key = k;
        }
        if inserted {
            t.record_count += 1;
        }
        Ok(inserted)
    }

    fn delete_raw(&mut self, i: usize, key: &Field) -> Result<bool> {
        let mut w = self.tree_for(i)?;
        let existed = w.delete(&mut self.store, key)?;
        let t = &mut self.tables[i];
        t.root_buffer_id = w.root();
        if existed {
            t.record_count -= 1;
        }
        Ok(existed)
    }

    /// The index entry key for `record` in the index table at `idx` (`None` for a null value in
    /// a sparse column, which `FieldIndexTable` does not index).
    fn index_key(&self, primary: usize, idx: usize, record: &Record) -> Result<Option<Field>> {
        let col = self.tables[idx].indexed_column as usize;
        let schema = &self.tables[primary].schema;
        let value = record.values.get(col).and_then(Option::as_ref);
        if schema.is_sparse_column(col) && value.is_none_or(Field::is_null) {
            return Ok(None);
        }
        let value = value
            .cloned()
            .ok_or(DbError::Corrupt("record lacks an indexed column".into()))?;
        Ok(Some(Field::new_index(value, record.key.clone(), false)?))
    }

    fn index_add(&mut self, primary: usize, record: &Record) -> Result<()> {
        for idx in self.index_positions(primary) {
            if let Some(k) = self.index_key(primary, idx, record)? {
                self.put_raw(
                    idx,
                    &Record {
                        key: k,
                        values: vec![],
                    },
                )?;
            }
        }
        Ok(())
    }

    fn index_delete(&mut self, primary: usize, record: &Record) -> Result<()> {
        for idx in self.index_positions(primary) {
            if let Some(k) = self.index_key(primary, idx, record)? {
                self.delete_raw(idx, &k)?;
            }
        }
        Ok(())
    }

    /// `Table.updatedRecord`: for each index whose column changed, delete the old entry and add
    /// the new one.
    fn index_update(&mut self, primary: usize, old: &Record, new: &Record) -> Result<()> {
        for idx in self.index_positions(primary) {
            let col = self.tables[idx].indexed_column as usize;
            let a = old.values.get(col).and_then(Option::as_ref);
            let b = new.values.get(col).and_then(Option::as_ref);
            if a != b {
                if let Some(k) = self.index_key(primary, idx, old)? {
                    self.delete_raw(idx, &k)?;
                }
                if let Some(k) = self.index_key(primary, idx, new)? {
                    self.put_raw(
                        idx,
                        &Record {
                            key: k,
                            values: vec![],
                        },
                    )?;
                }
            }
        }
        Ok(())
    }

    fn current_record(&self, i: usize, key: &Field) -> Result<Option<Record>> {
        Table {
            db: self,
            record: &self.tables[i],
        }
        .get(key)
    }

    /// Insert or replace a record (`Table.putRecord`), maintaining the index tables in the order
    /// Java does: an update changes the index entries first, an insert adds them afterwards.
    pub fn put_record(&mut self, table: &str, record: &Record) -> Result<()> {
        let i = self.table_index(table)?;
        let indexed = !self.index_positions(i).is_empty();
        let old = if indexed {
            self.current_record(i, &record.key)?
        } else {
            None
        };
        if let Some(old) = &old {
            self.index_update(i, old, record)?;
        }
        let inserted = self.put_raw(i, record)?;
        if inserted && indexed {
            self.index_add(i, record)?;
        }
        Ok(())
    }

    /// Delete the record with long `key` (`Table.deleteRecord`); returns whether it existed.
    pub fn delete_record(&mut self, table: &str, key: i64) -> Result<bool> {
        self.delete_record_field(table, &Field::Long(key))
    }

    /// Delete the record with `key` (`Table.deleteRecord(Field)`); index entries go first.
    pub fn delete_record_field(&mut self, table: &str, key: &Field) -> Result<bool> {
        let i = self.table_index(table)?;
        if !self.index_positions(i).is_empty() {
            let Some(old) = self.current_record(i, key)? else {
                return Ok(false);
            };
            self.index_delete(i, &old)?;
        }
        self.delete_raw(i, key)
    }

    /// End of a transaction (`MasterTable.flush`): store every table root, maximum key and
    /// record count in the master table.
    pub fn commit(&mut self) -> Result<()> {
        for i in 0..self.tables.len() {
            self.put_master_row(i)?;
        }
        // Java does not refresh the parameter here. The root cannot change because the rows
        // already exist, but keep the two in step should it ever.
        if self.params.master_table_root()? != self.master_root {
            self.params.set(&mut self.store, 0, self.master_root)?;
        }
        Ok(())
    }
}

/// A table (primary or secondary index) of an open database.
pub struct Table<'a, S: BufferStore> {
    db: &'a Database<S>,
    record: &'a TableRecord,
}

impl<S: BufferStore> Clone for Table<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<S: BufferStore> Copy for Table<'_, S> {}

/// Iterator over the decoded records of a table.
pub struct Records<'a> {
    inner: Box<dyn Iterator<Item = Result<Record>> + 'a>,
}

impl Iterator for Records<'_> {
    type Item = Result<Record>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl<'a, S: BufferStore> Table<'a, S> {
    /// Master table row of this table.
    pub fn table_record(&self) -> &'a TableRecord {
        self.record
    }

    /// Table name.
    pub fn name(&self) -> &'a str {
        &self.record.name
    }

    /// Schema.
    pub fn schema(&self) -> &'a Schema {
        &self.record.schema
    }

    /// Record count as stored in the master table (`getRecordCount`).
    pub fn record_count(&self) -> i32 {
        self.record.record_count
    }

    /// Largest long key ever used (`getMaxKey`; `Long.MIN_VALUE` when none).
    pub fn max_key(&self) -> i64 {
        self.record.max_key
    }

    /// Indexed column of an index table, `-1` for a primary table.
    pub fn indexed_column(&self) -> i32 {
        self.record.indexed_column
    }

    fn fixed_len(&self) -> Option<usize> {
        let s = self.schema();
        (!s.is_variable_length()).then(|| s.fixed_length())
    }

    /// Iterate all records in key order (`Table.iterator`).
    pub fn records(&self) -> Result<Records<'a>> {
        let root = self.record.root_buffer_id;
        let schema = self.schema();
        if root < 0 {
            return Ok(Records {
                inner: Box::new(std::iter::empty()),
            });
        }
        let store = self.db.store();
        let fixed_len = self.fixed_len();
        if schema.use_long_key_nodes() {
            let tree = LongKeyTree::new(store, root, fixed_len);
            let it = tree.records()?.map(move |r| {
                let r = r?;
                let (rec, _) = schema.read_record(Field::Long(r.key), &r.data, 0)?;
                Ok(rec)
            });
            Ok(Records {
                inner: Box::new(it),
            })
        } else {
            let tree = FieldKeyTree::new(store, root, Some(schema.key_type().clone()), fixed_len);
            let it = tree.records()?.map(move |r| {
                let r = r?;
                let (rec, _) = schema.read_record(r.key, &r.data, 0)?;
                Ok(rec)
            });
            Ok(Records {
                inner: Box::new(it),
            })
        }
    }

    /// Record with primary key `key` (`getRecord`).
    pub fn get(&self, key: &Field) -> Result<Option<Record>> {
        let root = self.record.root_buffer_id;
        if root < 0 {
            return Ok(None);
        }
        let schema = self.schema();
        let store = self.db.store();
        let fixed_len = self.fixed_len();
        if schema.use_long_key_nodes() {
            let Some(k) = key.long_value() else {
                return Err(FieldError::TypeMismatch.into());
            };
            match LongKeyTree::new(store, root, fixed_len).get(k)? {
                Some(r) => Ok(Some(schema.read_record(Field::Long(r.key), &r.data, 0)?.0)),
                None => Ok(None),
            }
        } else {
            let tree = FieldKeyTree::new(store, root, Some(schema.key_type().clone()), fixed_len);
            match tree.get(key)? {
                Some(r) => Ok(Some(schema.read_record(r.key, &r.data, 0)?.0)),
                None => Ok(None),
            }
        }
    }

    /// Entries of an index table in key order: indexed value and primary key.
    pub fn index_entries(&self) -> Result<Vec<IndexValue>> {
        if self.record.indexed_column < 0 {
            return Err(DbError::Corrupt(format!(
                "{} is not an index table",
                self.name()
            )));
        }
        let mut out = Vec::new();
        for r in self.records()? {
            match r?.key {
                Field::Index(v) => out.push(*v),
                _ => {
                    return Err(DbError::Corrupt(
                        "index table key is not an index field".into(),
                    ));
                }
            }
        }
        Ok(out)
    }

    /// Primary keys of the records of this primary table whose column `column` equals `value`,
    /// found through the secondary index (`None` when `column` has no index table).
    pub fn find_primary_keys(&self, column: usize, value: &Field) -> Result<Option<Vec<Field>>> {
        let Some(index) = self
            .db
            .index_tables(self.name())
            .into_iter()
            .find(|t| t.indexed_column() as usize == column)
        else {
            return Ok(None);
        };
        let mut keys = Vec::new();
        for e in index.index_entries()? {
            // stored values may be truncated: compare after forming the key the same way
            let probe = Field::new_index(value.clone(), e.primary.clone(), e.legacy)?;
            if let Field::Index(p) = probe
                && p.indexed.compare(&e.indexed)?.is_eq()
            {
                keys.push(e.primary);
            }
        }
        Ok(Some(keys))
    }
}

#[cfg(test)]
mod tests;
