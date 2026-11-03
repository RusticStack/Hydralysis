//! Hydralysis semantic-trace tool logic, ported from `hydralysis.trace`, `trace_hashes`, `trace_reports` and
//! `trace_watchdog` (and the small helpers beside them). Pure logic: the PyO3 binding is `native/src/trace/port.rs`.
//!
//! Every function takes and returns plain values (`serde_json::Value` where the Python took dicts). Where the Python is
//! loose about types (a frame that is an int or a string, a `thread_gen` that is a number or a pair), these functions
//! accept the shapes the producers emit and answer [`Error::Unsupported`] for anything else, so the caller can run the
//! Python implementation, which stays the specification. See `PORTING.md`.

#[cfg(windows)]
pub mod capture;
pub mod hashes;
pub mod pyfmt;
pub mod reports;
pub mod unwind;

/// Why a call did not produce an answer.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Error {
    /// The Python `HashError`: a stable `code` and its message.
    #[error("{message}")]
    Hash { code: &'static str, message: String },
    /// The text cannot be encoded as the algorithm's encoding (`UnicodeEncodeError` in Python).
    #[error("'{encoding}' codec can't encode a character of {text:?} at position {position}")]
    Encode { encoding: &'static str, text: String, position: usize },
    /// The input has a shape this port does not model; the Python implementation answers (or raises) instead.
    #[error("unsupported input: {0}")]
    Unsupported(String),
}

impl Error {
    pub fn hash(code: &'static str, message: impl Into<String>) -> Self {
        Self::Hash { code, message: message.into() }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
