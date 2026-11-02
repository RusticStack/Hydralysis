//! Hydralysis project-mutation machinery, ported from `hydralysis.{locks,jobowner,viewgov,...}`.
//!
//! Ported so far: [`locks`], [`jobowner`], [`viewgov`]. See `TESTMAP.md` for the test map and what remains.

pub mod jobowner;
pub mod locks;
pub mod viewgov;
