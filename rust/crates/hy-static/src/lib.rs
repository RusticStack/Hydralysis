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
pub mod cache;
mod call;
mod error;
mod index;
mod layout;
mod program;
mod rows;

pub use answer::{ACTIONS, INDEX_FILE_MAX, answer, answer_in_project, answer_in_project_with};
pub use cache::{Cache, Stats};
pub use call::{call, call_json};
pub use error::{Error, Result};
pub use layout::{Located, Mark, Stamp, locate, mark_of};
pub use program::{FunctionInfo, LANGUAGE, MAX_READ, Meta, ProgramInfo, StaticProgram, SymbolInfo, Xref, address_text};
