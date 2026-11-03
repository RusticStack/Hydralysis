//! How a ported function ends when it does not return a value.
//!
//! The Python originals raise exceptions the callers (and tests) match by type and message, or they run on inputs the
//! Rust code does not model exactly. [`Failure::Raise`] carries the exception the original raises; [`Failure::Fallback`]
//! means "the original must run instead" (a Python `int` past 64 bits, a JSON constant `NaN`, a non-string where the
//! original calls `str()`, ...). The PyO3 binding turns the first into the Python exception and the second into `None`.

use std::fmt;

/// The Python exception class a [`Raise`] stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    ValueError,
    TypeError,
    PermissionError,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::ValueError => "ValueError",
            Kind::TypeError => "TypeError",
            Kind::PermissionError => "PermissionError",
        }
    }
}

/// An exception the Python original raises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Raise {
    pub kind: Kind,
    pub message: String,
}

/// Why a ported function produced no value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Raise(Raise),
    Fallback(String),
}

pub type Res<T> = Result<T, Failure>;

impl Failure {
    pub fn value(message: impl Into<String>) -> Self {
        Failure::Raise(Raise { kind: Kind::ValueError, message: message.into() })
    }

    pub fn type_error(message: impl Into<String>) -> Self {
        Failure::Raise(Raise { kind: Kind::TypeError, message: message.into() })
    }

    pub fn permission(message: impl Into<String>) -> Self {
        Failure::Raise(Raise { kind: Kind::PermissionError, message: message.into() })
    }

    pub fn fallback(why: impl Into<String>) -> Self {
        Failure::Fallback(why.into())
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Raise(r) => write!(f, "{}: {}", r.kind.name(), r.message),
            Failure::Fallback(why) => write!(f, "fallback: {why}"),
        }
    }
}

impl std::error::Error for Failure {}

impl From<hy_query::session::DecompileError> for Failure {
    /// The error of a Python `int(value)` (`hy_query::session::py_int`): its own exceptions, or "not modelled".
    fn from(error: hy_query::session::DecompileError) -> Self {
        use hy_query::session::DecompileError as E;
        match error {
            E::Value(m) => Failure::value(m),
            E::Type(m) => Failure::type_error(m),
            E::Unsupported(m) => Failure::fallback(m),
            other => Failure::fallback(format!("{other:?}")),
        }
    }
}
