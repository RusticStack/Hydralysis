//! `hydralysis/integrity.py` (read-only part): the header-magic scan of a Ghidra project's database versions.
//!
//! A save killed between the final-named rename and the header write leaves a newest version whose first eight bytes are
//! zero. `scan` reads eight bytes per version file and nothing else; the quarantine (which moves files) stays in Python.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::failure::{Failure, Res};

/// The first eight bytes of a Ghidra database file (`integrity.GBF_MAGIC`).
pub const GBF_MAGIC: [u8; 8] = [0x2f, 0x30, 0x31, 0x2c, 0x34, 0x29, 0x2c, 0x2a];

/// `db.<digits>.gbf` (`re.fullmatch(r"db\.(\d+)\.gbf", name)`): the number.
fn version_number(name: &str) -> Res<Option<u128>> {
    let Some(digits) = name.strip_prefix("db.").and_then(|rest| rest.strip_suffix(".gbf")) else {
        return Ok(None);
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    digits.parse::<u128>().map(Some).map_err(|_| Failure::fallback("version number past 128 bits"))
}

/// `Path.glob` name matching on Windows: case-insensitive.
fn lower(name: &std::ffi::OsStr) -> String {
    name.to_string_lossy().to_lowercase()
}

fn sorted_children(folder: &Path, keep: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let Ok(listing) = fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut found: Vec<(String, PathBuf)> =
        listing.flatten().filter(|item| keep(&lower(&item.file_name()))).map(|item| (lower(&item.file_name()), item.path())).collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.into_iter().map(|(_, path)| path).collect()
}

/// `rep.glob("<group>/*/~*.db")`, directories only, sorted as `Path` sorts on Windows.
fn databases_in(rep: &Path, group: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    for bucket in sorted_children(&rep.join(group), |_| true) {
        if !bucket.is_dir() {
            continue;
        }
        found.extend(sorted_children(&bucket, |name| name.starts_with('~') && name.ends_with(".db")));
    }
    found.sort_by_key(|path| path.to_string_lossy().to_lowercase());
    found
}

fn valid_header(path: &Path) -> bool {
    let mut head = [0u8; 8];
    File::open(path).and_then(|mut handle| handle.read_exact(&mut head)).is_ok() && head == GBF_MAGIC
}

/// `integrity.scan`: per database, its versions and whether each has the magic. FOLDER is `project_folder(path)`.
pub fn scan(folder: &Path) -> Res<Value> {
    let mut databases = 0u64;
    let mut versions_total = 0u64;
    let mut newest_invalid: Vec<Value> = Vec::new();
    let mut empty: Vec<Value> = Vec::new();
    let mut usable = true;
    let shown = |path: &Path| Value::String(path.to_string_lossy().into_owned());
    let reps = sorted_children(folder, |name| name.ends_with(".rep"));
    let mut all_databases: Vec<PathBuf> = Vec::new();
    for rep in reps.iter().filter(|rep| rep.is_dir()) {
        all_databases.extend(databases_in(rep, "idata"));
        all_databases.extend(databases_in(rep, "user"));
    }
    for database in all_databases.iter().filter(|db| db.is_dir()) {
        databases += 1;
        let mut versions: Vec<(u128, String, PathBuf)> = Vec::new();
        let listing = fs::read_dir(database).map_err(|e| Failure::fallback(format!("cannot list a database: {e}")))?;
        for item in listing.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            if let Some(number) = version_number(&name)?
                && item.path().is_file()
            {
                versions.push((number, name.to_lowercase(), item.path()));
            }
        }
        versions.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        versions_total += versions.len() as u64;
        let Some((number, _, newest)) = versions.last() else {
            empty.push(shown(database));
            continue;
        };
        if !valid_header(newest) {
            let fallback = versions[..versions.len() - 1].iter().rev().find(|item| valid_header(&item.2));
            let name_of = |path: &Path| path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            newest_invalid.push(json!({
                "database": shown(database),
                "file": name_of(newest),
                "version": number,
                "previous_valid": fallback.map_or(Value::Null, |item| Value::String(name_of(&item.2))),
            }));
            if fallback.is_none() {
                usable = false;
            }
        }
    }
    let mut report = Map::new();
    report.insert("project".into(), shown(folder));
    report.insert("databases".into(), databases.into());
    report.insert("versions".into(), versions_total.into());
    let ok = newest_invalid.is_empty();
    report.insert("newest_invalid".into(), Value::Array(newest_invalid));
    report.insert("empty".into(), Value::Array(empty));
    report.insert("usable".into(), usable.into());
    report.insert("ok".into(), ok.into());
    Ok(Value::Object(report))
}
