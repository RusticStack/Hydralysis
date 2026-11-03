/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! Errors, with the Python client's two error families kept apart.
//!
//! `SessionError` is the Python exception of the same name: an `ok:false` answer, a closed
//! connection, a deadline that passed, or an incompatible engine. `Error` adds the transport
//! and parsing failures that Python raises as `OSError`, `ValueError` or `KeyError`.

use std::fmt;

use serde_json::Value;

/// The error codes of the *client* library, beside the engine's own (`busy`, `not_found`, ...).
pub mod code {
    /// The engine answered `ok:false`; the code is the engine's and arrives in
    /// [`super::SessionError::code`].
    pub const SESSION: &str = "session";
    /// The connection reached end of input (`ghidra_session.SessionError("closed", ...)`).
    pub const CLOSED: &str = "closed";
    /// A client-side deadline passed; a `cancel` was sent (`deadline_exceeded`).
    pub const DEADLINE_EXCEEDED: &str = "deadline_exceeded";
    /// The engine speaks a protocol this client does not (`IncompatibleError`).
    pub const INCOMPATIBLE: &str = "incompatible";
    /// The endpoint file, or an argument to [`crate::session::Endpoint::parse`], is unusable.
    pub const BAD_ENDPOINT: &str = "bad_endpoint";
    /// A reply line started with `{` but was not a JSON object, or a `result` was missing.
    pub const BAD_REPLY: &str = "bad_reply";
    /// A socket or file failed.
    pub const IO: &str = "io";
    /// An argument is unusable (Python `ValueError`).
    pub const INVALID: &str = "invalid";
}

/// An `ok:false` answer, a closed connection, a passed deadline or an incompatible engine.
///
/// Mirrors `ghidra_session.SessionError`: `code` is the protocol code when the engine sent one,
/// and one of the module's client codes otherwise. `details` and `trace` are the engine's.
#[derive(Debug, Clone)]
pub struct SessionError {
    /// The protocol's error code, or a [`code`] constant.
    pub code: String,
    /// The engine's message.
    pub message: String,
    /// `error.details` of the answer, `{}` when there was none.
    pub details: Value,
    /// `error.trace` of the answer, when the engine sent one.
    pub trace: Option<Value>,
}

impl SessionError {
    /// Builds one with no details; `details` is set to an empty object.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: Value::Object(serde_json::Map::new()),
            trace: None,
        }
    }

    /// Builds one from an `ok:false` answer's `error` object.
    ///
    /// A missing `code`/`message` becomes `failed` and the empty string, which is what
    /// `e.get("code")`/`e.get("message")` hand to the Python constructor as `None`/`None`.
    #[must_use]
    pub fn from_error_object(error: &Value) -> Self {
        let code = error
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("failed")
            .to_owned();
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let details = error
            .get("details")
            .filter(|v| !v.is_null())
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        let trace = error.get("trace").filter(|v| !v.is_null()).cloned();
        Self {
            code,
            message,
            details,
            trace,
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `str(SessionError)` in Python: "code: message".
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SessionError {}

/// The client's error type: a [`SessionError`] or a failure below the protocol.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The engine answered `ok:false`; or the session closed, timed out, or is incompatible.
    Session(SessionError),
    /// A socket, the endpoint file, or an output file failed.
    Io(std::io::Error),
    /// A line that started with `{` was not valid JSON (Python raises `ValueError` here).
    Json(serde_json::Error),
    /// The endpoint file or its fields are unusable (`EndpointError`).
    Endpoint(String),
    /// A reply line was valid JSON but not the object the protocol promises.
    BadReply(String),
    /// An argument is unusable; Python raises `ValueError` for these.
    Invalid(String),
}

impl Error {
    /// The error's code: the engine's own for an `ok:false` answer, else a client code.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Session(e) => &e.code,
            Self::Io(_) => code::IO,
            Self::Json(_) | Self::BadReply(_) => code::BAD_REPLY,
            Self::Invalid(_) => code::INVALID,
            Self::Endpoint(_) => code::BAD_ENDPOINT,
        }
    }

    /// The message a person would read (Python's `str(e)`).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Session(e) => e.message.clone(),
            other => other.to_string(),
        }
    }

    /// The `details` object of an engine answer; `{}` for every other failure.
    #[must_use]
    pub fn details(&self) -> Value {
        match self {
            Self::Session(e) => e.details.clone(),
            _ => Value::Object(serde_json::Map::new()),
        }
    }

    /// Builds a `closed` session error; the message is the Python client's.
    #[must_use]
    pub fn closed() -> Self {
        Self::Session(SessionError::new(
            code::CLOSED,
            "the session connection ended",
        ))
    }

    /// Builds a `deadline_exceeded` session error with the Python client's details.
    #[must_use]
    pub fn deadline_exceeded(deadline_s: f64, target: u64, cancel_id: Option<u64>) -> Self {
        let mut details = serde_json::Map::new();
        details.insert("deadlineS".to_owned(), json_number(deadline_s));
        details.insert("target".to_owned(), Value::from(target));
        details.insert(
            "cancelId".to_owned(),
            cancel_id.map_or(Value::Null, Value::from),
        );
        Self::Session(SessionError {
            code: code::DEADLINE_EXCEEDED.to_owned(),
            message: format!("no answer to request {target} within {deadline_s} s; cancel sent"),
            details: Value::Object(details),
            trace: None,
        })
    }
}

/// A finite `f64` as a JSON number, `null` otherwise (deadlines are finite by construction).
fn json_number(x: f64) -> Value {
    serde_json::Number::from_f64(x).map_or(Value::Null, Value::Number)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(e) => fmt::Display::fmt(e, f),
            Self::Io(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "{e}"),
            Self::Endpoint(m) | Self::BadReply(m) | Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Endpoint(_) | Self::BadReply(_) | Self::Invalid(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<SessionError> for Error {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}

/// `Result` with the client's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_error_displays_python_style() {
        let e = SessionError::new("busy", "program p1:/x is held");
        assert_eq!(e.to_string(), "busy: program p1:/x is held");
    }

    #[test]
    fn error_object_without_code_or_message_keeps_pythons_none_text() {
        let e = SessionError::from_error_object(&serde_json::json!({}));
        assert_eq!(e.code, "failed");
        assert_eq!(e.message, "");
        assert_eq!(e.details, serde_json::json!({}));
        assert!(e.trace.is_none());
    }

    #[test]
    fn deadline_details_carry_the_python_field_names() {
        let e = Error::deadline_exceeded(2.5, 7, None);
        let details = e.details();
        assert_eq!(details["deadlineS"], serde_json::json!(2.5));
        assert_eq!(details["target"], serde_json::json!(7));
        assert_eq!(details["cancelId"], serde_json::Value::Null);
    }
}
