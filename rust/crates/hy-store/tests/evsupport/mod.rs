//! Shared helpers for the evidence and bundle tests.
#![allow(dead_code)]

use hy_store::evidence::{self, Claim, Ctx, Filter, Verify};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const WHEN: &str = "2026-01-01T00:00:00Z";

pub fn ctx(harness: &str) -> Ctx {
    Ctx { who: Some(("rusticre:1".into(), harness.into())), now: Some(WHEN.into()) }
}

/// A scratch directory under `HYDRALYSIS_TEST_ROOT` (as tests/support.py does), else the system temp directory.
pub fn work() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    builder.prefix("evtest-");
    match std::env::var_os("HYDRALYSIS_TEST_ROOT").filter(|v| !v.is_empty()) {
        Some(root) => {
            std::fs::create_dir_all(&root).expect("test root");
            builder.tempdir_in(root).expect("tempdir")
        }
        None => builder.tempdir().expect("tempdir"),
    }
}

/// `{"game": "cp", "build": "2.31", "kind": "field", "name": "speed", "note": "n", "source": "s"}` with changes.
pub fn base() -> Claim {
    Claim::new("cp", "2.31", "field", "speed", "n", "s")
}

pub fn add(db: &Path, claim: Claim) -> hy_store::evidence::Result<String> {
    evidence::add_claim(db, &claim, &ctx("writer"))
}

pub fn rows(db: &Path, game: &str, include_superseded: bool) -> Vec<Value> {
    let filter = Filter { game: game.into(), include_superseded, limit: 1_000_000, ..Filter::default() };
    evidence::query(db, &filter, Verify::On).expect("query")
}

pub fn raw(db: &Path, sql: &str, args: &[&dyn rusqlite::ToSql]) {
    let connection = rusqlite::Connection::open(db).expect("open");
    connection.execute(sql, args).expect("execute");
}

pub fn path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}
