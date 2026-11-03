//! The static read plane: answers about an analysed Ghidra project straight from its database files.
//!
//! Hydralysis normally asks the Hydra Engine daemon (a JVM) about functions, symbols, cross references and
//! bytes. The engine repository has Rust crates that read the Program database byte-compatibly
//! (`native/vendor/ghidra-fmt`, see `VENDORED.md` there). This crate opens a program of a project folder read-only
//! through them and answers the questions whose answer is stored plainly in the database; for everything else it
//! returns [`Error::Unsupported`] and the caller asks the engine. It never guesses: an unsupported database
//! version, language, address space (overlays, segmented), memory kind, reference kind or table shape is a
//! refusal, not a partial answer.
//!
//! What is answered, and what is not, is in `PORTING.md` next to this file.

mod answer;
mod error;
mod layout;
mod program;

pub use answer::{ACTIONS, answer, answer_in_project};
pub use error::{Error, Result};
pub use layout::{Located, Stamp, locate};
pub use program::{FunctionInfo, LANGUAGE, MAX_READ, ProgramInfo, StaticProgram, SymbolInfo, Xref, address_text};
