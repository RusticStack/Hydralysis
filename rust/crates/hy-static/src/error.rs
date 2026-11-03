//! The two ways the static plane fails to answer.

use std::fmt;

/// Why a question was not answered from the database files.
///
/// Both variants mean "ask the engine instead"; they differ in what they tell the caller. `Unsupported` is a
/// property of the question or of the program (a feature this reader does not port), `Failed` is a property of
/// the files at this moment (unreadable, changing, damaged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// This reader cannot answer exactly: an unported table version, address space, record kind or layout.
    Unsupported(String),
    /// The files could not be read or are inconsistent right now.
    Failed(String),
}

impl Error {
    /// An `Unsupported` error.
    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self::Unsupported(reason.into())
    }

    /// A `Failed` error.
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed(reason.into())
    }

    /// `unsupported` or `failed`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unsupported(_) => "unsupported",
            Self::Failed(_) => "failed",
        }
    }

    /// The reason text.
    pub fn reason(&self) -> &str {
        match self {
            Self::Unsupported(r) | Self::Failed(r) => r,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind(), self.reason())
    }
}

impl std::error::Error for Error {}

impl From<ghidra_progdb::ProgError> for Error {
    fn from(e: ghidra_progdb::ProgError) -> Self {
        use ghidra_progdb::ProgError as P;
        match e {
            P::NewerVersion { .. }
            | P::UpgradeRequired { .. }
            | P::UnsupportedTableVersion { .. }
            | P::UnsupportedAddressKey(_)
            | P::UnknownSpace(_)
            | P::MissingTable(_) => Self::Unsupported(e.to_string()),
            other => Self::Failed(other.to_string()),
        }
    }
}

impl From<ghidra_fmt_gbf::GbfError> for Error {
    fn from(e: ghidra_fmt_gbf::GbfError) -> Self {
        Self::Failed(e.to_string())
    }
}

impl From<ghidra_fmt_chain::ChainError> for Error {
    fn from(e: ghidra_fmt_chain::ChainError) -> Self {
        Self::Failed(e.to_string())
    }
}

impl From<ghidra_fmt_db::DbError> for Error {
    fn from(e: ghidra_fmt_db::DbError) -> Self {
        Self::Failed(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Failed(e.to_string())
    }
}

/// Result alias of this crate.
pub type Result<T> = std::result::Result<T, Error>;
