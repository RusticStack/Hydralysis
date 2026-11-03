//! Settings, lineage folder layout and the changeset-queue paths (`lineage.py` layout half, `views.py` queue paths).
//!
//! TODO(hy-store): `lineages_root`/`lineage_dir`/`generation_dir` belong to the storage lane's lineage module; the
//! versions here have the same semantics and are to be switched when it lands.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use serde_json::{Map, Value};

use crate::error::{Error, Result};

pub type Settings = Map<String, Value>;

/// `compat.env(name)`: `HYDRALYSIS_<name>`, else `RUSTICRE_<name>`; an empty value counts as unset.
pub fn env(name: &str) -> Option<String> {
    for prefix in ["HYDRALYSIS_", "RUSTICRE_"] {
        if let Ok(v) = std::env::var(format!("{prefix}{name}"))
            && !v.is_empty()
        {
            return Some(v);
        }
    }
    None
}

fn default_root() -> PathBuf {
    let home = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default();
    let root_for = |cased: &str, plain: &str| -> PathBuf {
        if cfg!(windows) {
            match std::env::var("LOCALAPPDATA") {
                Ok(v) if !v.is_empty() => PathBuf::from(v).join(cased),
                _ => Path::new(&home).join("AppData").join("Local").join(cased),
            }
        } else if cfg!(target_os = "macos") {
            Path::new(&home).join("Library").join("Application Support").join(cased)
        } else {
            Path::new(&home).join(plain)
        }
    };
    let current = root_for("Hydralysis", "hydralysis");
    let legacy = root_for("RusticRE", "rusticre");
    if !current.exists() && legacy.exists() { legacy } else { current }
}

/// The data root (`paths.root_path`, without the forbidden-drive and dot-prefix checks: TODO(hy-store paths)).
pub fn root_path(settings: &Settings) -> PathBuf {
    match settings.get("root").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(s) => PathBuf::from(s),
        None => env("ROOT").map(PathBuf::from).unwrap_or_else(default_root),
    }
}

pub fn lineages_root(settings: &Settings) -> PathBuf {
    let base = match settings.get("generations_root").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(s) => PathBuf::from(s),
        None => root_path(settings),
    };
    base.join("lineages")
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn is_lineage_id(id: &str) -> bool {
    id.len() == 10 && id.starts_with("L-") && id[2..].bytes().all(is_lower_hex)
}

pub fn lineage_dir(settings: &Settings, lineage_id: &str) -> Result<PathBuf> {
    if !is_lineage_id(lineage_id) {
        return Err(Error::value("invalid lineage id"));
    }
    Ok(lineages_root(settings).join(lineage_id))
}

pub fn generation_dir(settings: &Settings, lineage_id: &str, number: u64) -> Result<PathBuf> {
    Ok(lineage_dir(settings, lineage_id)?.join("gen").join(format!("{number:04}")))
}

/// `c-` plus 4..16 lowercase hex digits (`views._CSID`).
pub fn is_csid(text: &str) -> bool {
    text.strip_prefix("c-").is_some_and(|rest| (4..=16).contains(&rest.len()) && rest.bytes().all(is_lower_hex))
}

/// `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}` (`views._VIEW`).
pub fn is_view_name(text: &str) -> bool {
    let b = text.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

fn csid_path(settings: &Settings, lineage_id: &str, csid: &str, folder: &str) -> Result<PathBuf> {
    if !is_csid(csid) {
        return Err(Error::value("invalid changeset id"));
    }
    Ok(lineage_dir(settings, lineage_id)?.join(folder).join(format!("{csid}.json")))
}

pub fn pending_path(s: &Settings, lineage_id: &str, csid: &str) -> Result<PathBuf> {
    csid_path(s, lineage_id, csid, "pending")
}
pub fn done_path(s: &Settings, lineage_id: &str, csid: &str) -> Result<PathBuf> {
    csid_path(s, lineage_id, csid, "done")
}
/// Results of changesets that made no generation; `done/` holds only what the log names.
pub fn declined_path(s: &Settings, lineage_id: &str, csid: &str) -> Result<PathBuf> {
    csid_path(s, lineage_id, csid, "declined")
}
pub fn failure_path(s: &Settings, lineage_id: &str, csid: &str) -> Result<PathBuf> {
    Ok(lineage_dir(s, lineage_id)?.join("failures").join(format!("{csid}.json")))
}
pub fn publish_lock_path(s: &Settings, lineage_id: &str) -> Result<PathBuf> {
    Ok(lineage_dir(s, lineage_id)?.join("publish.lock"))
}
pub fn dir(s: &Settings, lineage_id: &str, name: &str) -> Result<PathBuf> {
    Ok(lineage_dir(s, lineage_id)?.join(name))
}

/// A changeset id that sorts in the order changesets were sealed: microseconds since the epoch (13 hex digits), then
/// twelve random bits (3 hex digits).
pub fn new_csid() -> String {
    let micros = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros()).unwrap_or(0);
    let mut r = [0u8; 2];
    getrandom::fill(&mut r).expect("OS randomness");
    format!("c-{micros:013x}{:03x}", u16::from_le_bytes(r) & 0xfff)
}

/// Seconds since the epoch, as `time.time()`.
pub fn now_f64() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// `lineage.now_iso()`: `%Y-%m-%dT%H:%M:%SZ` in UTC.
pub fn now_iso() -> String {
    iso_of(now_f64() as i64)
}

pub fn iso_of(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// The ids (`c-...`) of the records in `folder`, sorted. A missing folder has none.
pub fn ids_in(folder: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".json").filter(|id| is_csid(id)).map(str::to_string))
        .collect();
    found.sort();
    found
}

/// 16 random hex digits, new at every start of this process (D59, revision 8).
pub static BOOT_ID: LazyLock<String> = LazyLock::new(|| {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("OS randomness");
    hex::encode(b)
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csid_shape_and_order() {
        assert!(is_csid("c-0000000000000000"));
        assert!(!is_csid("c-123"));
        assert!(!is_csid("c-ABCD"));
        let a = new_csid();
        assert!(is_csid(&a) && a.len() == 18, "{a}");
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(new_csid() > a);
    }

    #[test]
    fn view_names_and_lineage_ids() {
        assert!(is_view_name("alice.at.x-1_2"));
        assert!(!is_view_name(".x") && !is_view_name("") && !is_view_name(&"a".repeat(65)));
        assert!(is_lineage_id("L-0123abcd") && !is_lineage_id("L-0123abcg") && !is_lineage_id("L-0123abc"));
    }

    #[test]
    fn iso_matches_python_gmtime() {
        assert_eq!(iso_of(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_of(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso_of(951_782_400), "2000-02-29T00:00:00Z");
    }
}
