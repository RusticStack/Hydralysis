//! Hydralysis storage layer (Rust port of storelog, lineage, backups, evidence, evidence_bundle, runtime_events).
//! Every module works on `serde_json::Value` at its public edge so the PyO3 binding and the other Rust lanes can
//! call it with the same shapes the Python code uses.

pub mod backups;
pub mod bundle;
pub mod config;
pub mod events;
pub mod evidence;
pub mod lineage;
pub mod storelog;
