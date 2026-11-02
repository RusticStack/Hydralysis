//! Errors of the view machinery. Display strings equal the Python exceptions' `str()`.

use serde_json::{Map, Value, json};

/// A refusal or terminal outcome with a stable `code` (`views.ViewError`); `payload()` is what the caller receives.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct ViewError {
    pub code: String,
    pub message: String,
    pub detail: Map<String, Value>,
}

impl ViewError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            detail: Map::new(),
        }
    }

    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.detail.insert(key.into(), value);
        self
    }

    pub fn payload(&self) -> Value {
        let mut out = Map::new();
        out.insert("error".into(), json!(self.code));
        out.insert("message".into(), json!(self.message));
        out.extend(self.detail.clone());
        Value::Object(out)
    }
}

/// A build that did not produce a generation (`views.PublishFailure`). `counted` failures count against the
/// changeset that caused them.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct PublishFailure {
    pub code: String,
    pub message: String,
    pub counted: bool,
    pub csid: Option<String>,
    pub detail: Map<String, Value>,
}

impl PublishFailure {
    pub fn payload(&self) -> Value {
        let mut out = Map::new();
        out.insert("error".into(), json!(self.code));
        out.insert("message".into(), json!(self.message));
        out.insert("counted".into(), json!(self.counted));
        out.insert("csid".into(), json!(self.csid));
        out.extend(self.detail.clone());
        Value::Object(out)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    View(#[from] ViewError),
    #[error(transparent)]
    Core(#[from] hy_core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// A Python `ValueError(message)`.
    pub fn value(message: impl Into<String>) -> Self {
        Error::Core(hy_core::Error::value(message))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Core(error.into())
    }
}
