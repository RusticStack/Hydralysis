//! Hydralysis project-mutation machinery, ported from `hydralysis.{locks,jobowner,viewgov,views,...}`.
//!
//! Ported so far: [`locks`], [`jobowner`], [`viewgov`], and the stage-1 record formats: [`layout`] (paths, ids),
//! [`records`] (view records), [`queue`] (changeset queue records and status), [`options`] (option validation).
//! See `TESTMAP.md` for the test map and what remains.

pub mod classify;
pub mod commits;
pub mod error;
pub mod generations;
pub mod gens;
pub mod jobowner;
pub mod layout;
pub mod lifecycle;
pub mod locks;
pub mod options;
pub mod proc;
pub mod publish;
pub mod queue;
pub mod records;
pub mod revisions;
pub mod settle;
pub mod store;
pub mod viewgov;
pub mod views;

pub use error::{Error, PublishFailure, Result, ViewError};
