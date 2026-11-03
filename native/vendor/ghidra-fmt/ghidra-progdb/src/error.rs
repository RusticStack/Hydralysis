//! Errors of the Program database reader.

use std::fmt;

use ghidra_fmt_db::DbError;

/// Everything that can go wrong opening or reading a Program database.
#[derive(Debug)]
pub enum ProgError {
    /// The underlying database could not be read.
    Db(DbError),
    /// A table every Program database has is missing.
    MissingTable(String),
    /// The database was written by a newer Ghidra than this port knows
    /// (`VersionException.NEWER_VERSION`).
    NewerVersion {
        /// Version stored in the database.
        stored: i32,
        /// Newest version this port reads.
        supported: i32,
    },
    /// The database is older than the oldest version Java opens without an upgrade; the upgrade
    /// itself stays in Java.
    UpgradeRequired {
        /// Version stored in the database.
        stored: i32,
        /// Oldest readable version.
        minimum: i32,
    },
    /// A table has a schema version this port does not read (Java would use an older read-only
    /// adapter or upgrade).
    UnsupportedTableVersion {
        /// Table name.
        table: String,
        /// Version found.
        version: i32,
    },
    /// An address key this port cannot decode (old-style keys and namespace addresses).
    UnsupportedAddressKey(i64),
    /// The address map refers to a space the caller did not describe.
    UnknownSpace(String),
    /// Structurally invalid contents.
    Corrupt(String),
    /// A memory read Java refuses with `MemoryAccessException` (no block, uninitialized
    /// bytes, nothing mapped, cyclic mapping).
    MemoryAccess(String),
}

impl fmt::Display for ProgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(e) => write!(f, "{e}"),
            Self::MissingTable(t) => write!(f, "not a Program database: table {t} is missing"),
            Self::NewerVersion { stored, supported } => write!(
                f,
                "program database version {stored} is newer than the supported version {supported}"
            ),
            Self::UpgradeRequired { stored, minimum } => write!(
                f,
                "program database version {stored} is older than {minimum} and must be upgraded by Ghidra first"
            ),
            Self::UnsupportedTableVersion { table, version } => write!(
                f,
                "table {table} has version {version}, which needs a Ghidra upgrade before this reader can use it"
            ),
            Self::UnsupportedAddressKey(k) => {
                write!(f, "unsupported address key {k:#x}")
            }
            Self::UnknownSpace(n) => write!(f, "address space {n:?} was not described"),
            Self::Corrupt(m) => write!(f, "corrupt program database: {m}"),
            Self::MemoryAccess(m) => write!(f, "memory access: {m}"),
        }
    }
}

impl std::error::Error for ProgError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Db(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DbError> for ProgError {
    fn from(e: DbError) -> Self {
        Self::Db(e)
    }
}

impl From<ghidra_fmt_chain::ChainError> for ProgError {
    fn from(e: ghidra_fmt_chain::ChainError) -> Self {
        Self::Db(DbError::from(e))
    }
}
