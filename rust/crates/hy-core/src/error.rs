//! Error types. Display strings equal the Python exceptions' `str()` so messages stay identical.

use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Operating-system error (FileNotFoundError, PermissionError, ... in Python).
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Python `ValueError`: a refusal with a message.
    #[error("{0}")]
    Value(String),
    /// `durable.StoreCorrupt` (code `store_corrupt`).
    #[error("{}", store_corrupt_message(path, backup, reasons))]
    StoreCorrupt { path: String, backup: String, reasons: Vec<(String, String)> },
    /// `durable.LineageCorrupt` (code `lineage_corrupt`).
    #[error("lineage_corrupt: {path} has an invalid line at byte {offset} followed by a valid line; reads stop at the last good line, appends are refused until it is repaired")]
    LineageCorrupt { path: String, offset: u64, records: Vec<serde_json::Value> },
    /// `locks.LockBusy` (a ValueError in Python).
    #[error("{what} is busy ({lock}); retry shortly")]
    LockBusy { what: String, path: String, lock: String, waited_s: f64, retry_after_ms: u64 },
    /// `durable.FaultInjected`.
    #[error("{0}")]
    FaultInjected(String),
    /// JSON decode failure.
    #[error("{0}")]
    Json(String),
}

fn store_corrupt_message(path: &str, backup: &str, reasons: &[(String, String)]) -> String {
    let detail: Vec<String> = reasons.iter().map(|(name, reason)| format!("{name}: {reason}")).collect();
    format!(
        "store_corrupt: no valid version of {path} (previous version {backup}); {}. Nothing was started empty; preserve both files and repair them.",
        detail.join("; ")
    )
}

impl Error {
    pub fn value(message: impl Into<String>) -> Self {
        Error::Value(message.into())
    }

    /// The machine-readable code Python exposes as `.code`, when the error has one.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Error::StoreCorrupt { .. } => Some("store_corrupt"),
            Error::LineageCorrupt { .. } => Some("lineage_corrupt"),
            _ => None,
        }
    }

    pub fn store_corrupt(path: &Path, backup: &Path, reasons: Vec<(String, String)>) -> Self {
        Error::StoreCorrupt { path: path.display().to_string(), backup: backup.display().to_string(), reasons }
    }

    pub fn lineage_corrupt(path: &Path, offset: u64, records: Vec<serde_json::Value>) -> Self {
        Error::LineageCorrupt { path: path.display().to_string(), offset, records }
    }

    pub fn lock_busy(what: &str, path: &Path, waited_s: f64) -> Self {
        let lock = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        Error::LockBusy {
            what: what.to_string(),
            path: path.display().to_string(),
            lock,
            waited_s: (waited_s * 1000.0).round() / 1000.0,
            retry_after_ms: 1000,
        }
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::Json(error.to_string())
    }
}

/// Convenience: `PathBuf` of a UTF-8 string.
pub fn p(text: &str) -> PathBuf {
    PathBuf::from(text)
}
