//! Hydralysis engine discovery, pin checks and tool-surface shaping: the pure logic of `hydralysis/hydra.py`,
//! `hydralysis/api.py` and a few small leaf modules, in Rust.
//!
//! Every function here is a behaviour twin of a Python function (named in its doc comment). Inputs the Rust code does not
//! model exactly end in [`failure::Failure::Fallback`]: the PyO3 binding then returns "run the original".

pub mod address_map;
pub mod api;
pub mod failure;
pub mod hydra;
pub mod integrity;
pub mod pytext;
pub mod red4ext;
pub mod small;

pub use failure::{Failure, Kind, Raise, Res};
