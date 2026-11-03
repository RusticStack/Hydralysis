//! Hydralysis shared core (Rust port of `hydralysis.durable`, `hydralysis.locks`, `hydralysis.localio`).
//!
//! * [`json`]: canonical / Python-compatible JSON encoding (byte identical to `json.dumps`).
//! * [`fsio`]: atomic replace with write-through, bounded shared reads, fsync rules.
//! * [`sealed`]: sealed JSON records with a `.bak` previous version.
//! * [`appendlog`]: CRC-framed JSON-line logs with torn-tail repair.
//! * [`lock`]: cross-process queued file locks.
//! * [`fault`]: the crash-injection test hook.

pub mod appendlog;
pub mod error;
pub mod fault;
pub mod fsio;
pub mod json;
pub mod lock;
pub mod sealed;

pub use error::{Error, Result};
pub use serde_json::{Map, Value};
