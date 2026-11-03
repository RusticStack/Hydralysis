//! Long-key write path; the implementation is shared with the fixed-key family and lives in
//! [`crate::keywrite`].

pub use crate::keywrite::LongKeyWriter;

#[cfg(test)]
mod tests;
