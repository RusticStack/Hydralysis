//! Configuration, data-root resolution and the Python-ish helpers the storage modules share
//! (`hydralysis.config`, the root parts of `hydralysis.paths`, `compat.env`, `backends.read_json/write_json`).

use hy_core::json::{self, Layout, Options};
use hy_core::sealed::{self, ReadOptions};
use hy_core::{Error, Result};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

pub const PRIMARY_PREFIX: &str = "HYDRALYSIS_";
pub const LEGACY_PREFIX: &str = "RUSTICRE_";
pub const PRIMARY_CONFIG: &str = "hydralysis.local.json";
pub const LEGACY_CONFIG: &str = "rusticre.local.json";

// ---------------------------------------------------------------------------------------------- Python-ish helpers

/// `str(value)` of a JSON value as Python would print it (None, True, 1.0, 'text' inside containers).
pub fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => py_repr(other),
    }
}

/// `repr(value)`.
pub fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                json::float_repr(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => {
            let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
            let mut out = String::new();
            out.push(quote);
            for c in s.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c == quote => {
                        out.push('\\');
                        out.push(c);
                    }
                    c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push(quote);
            out
        }
        Value::Array(items) => format!("[{}]", items.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(map) => {
            format!(
                "{{{}}}",
                map.iter().map(|(k, v)| format!("{}: {}", py_repr(&Value::String(k.clone())), py_repr(v))).collect::<Vec<_>>().join(", ")
            )
        }
    }
}

/// Python truthiness of a JSON value.
pub fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `(year, month, day, hour, minute, second)` of a Unix time in UTC (`time.gmtime`).
pub fn gmtime(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, (rem / 3600) as u32, (rem % 3600 / 60) as u32, (rem % 60) as u32)
}

pub fn unix_now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

/// `time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(secs))`.
pub fn iso_at(secs: i64) -> String {
    let (y, mo, d, h, mi, s) = gmtime(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

pub fn now_iso() -> String {
    iso_at(unix_now() as i64)
}

/// `json.dumps(value, **)` helper with the default `(", ", ": ")` layout, sorted keys, ASCII.
pub fn dumps_sorted(value: &Value) -> String {
    String::from_utf8(json::dumps(value, Options { layout: Layout::Spaced, sort_keys: true, ensure_ascii: true })).unwrap_or_default()
}

/// `json.dumps(value, indent=2)`.
pub fn dumps_indent2(value: &Value) -> Vec<u8> {
    json::dumps(value, Options { layout: Layout::Pretty(2), sort_keys: false, ensure_ascii: true })
}

// ---------------------------------------------------------------------------------------------------------- compat

static RECORDS: LazyLock<Mutex<Vec<(String, Value)>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Record one deprecated name in use; the first time only, it is also announced on stderr.
pub fn note(key: &str, old: &str, new: &str, detail: &str) {
    let Ok(mut records) = RECORDS.lock() else { return };
    if records.iter().any(|(k, _)| k == key) {
        return;
    }
    let mut row = Map::new();
    row.insert("deprecated".into(), Value::String(old.into()));
    row.insert("use".into(), Value::String(new.into()));
    if !detail.is_empty() {
        row.insert("detail".into(), Value::String(detail.into()));
    }
    records.push((key.to_string(), Value::Object(row)));
    eprintln!("hydralysis: {old} is deprecated (formerly RusticRE); use {new}. It is still honoured for this release.");
}

pub fn deprecations() -> Vec<Value> {
    RECORDS.lock().map(|r| r.iter().map(|(_, v)| v.clone()).collect()).unwrap_or_default()
}

/// `compat.env(name)`: HYDRALYSIS_<name>, else RUSTICRE_<name> (recorded as deprecated). Empty counts as unset.
pub fn env(name: &str) -> Option<String> {
    env_from(name, &|key| std::env::var(key).ok())
}

pub fn env_from(name: &str, get: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    if let Some(value) = get(&format!("{PRIMARY_PREFIX}{name}")).filter(|v| !v.is_empty()) {
        return Some(value);
    }
    if let Some(legacy) = get(&format!("{LEGACY_PREFIX}{name}")).filter(|v| !v.is_empty()) {
        note(&format!("env:{name}"), &format!("{LEGACY_PREFIX}{name}"), &format!("{PRIMARY_PREFIX}{name}"), "");
        return Some(legacy);
    }
    None
}

pub fn config_names() -> [&'static str; 2] {
    [PRIMARY_CONFIG, LEGACY_CONFIG]
}

// -------------------------------------------------------------------------------------------------------- read_json

/// `backends.read_json`: a sealed record (or `{}` when never written); a bad file falls back to `.bak`.
pub fn read_json(path: &Path) -> Result<Map<String, Value>> {
    match sealed::read_sealed_info(path, &ReadOptions::default(), Some(Value::Object(Map::new())))?.0 {
        Value::Object(map) => Ok(map),
        _ => Ok(Map::new()),
    }
}

/// `backends.write_json`: sealed, previous version kept as `.bak`, atomic and fsynced.
pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    sealed::write_sealed_default(path, value).map(|_| ())
}

// ------------------------------------------------------------------------------------------------------------ paths

#[cfg(windows)]
fn strip_verbatim(text: String) -> String {
    if let Some(rest) = text.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else if let Some(rest) = text.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        text
    }
}

#[cfg(not(windows))]
fn strip_verbatim(text: String) -> String {
    text
}

/// `Path(path).expanduser().resolve()`: absolute, symlinks resolved as far as the path exists, `..` removed.
pub fn resolved(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let expanded: PathBuf = if let Some(rest) = text.strip_prefix('~').filter(|r| r.is_empty() || r.starts_with(['/', '\\'])) {
        match std::env::home_dir() {
            Some(home) => home.join(rest.trim_start_matches(['/', '\\'])),
            None => path.to_path_buf(),
        }
    } else {
        path.to_path_buf()
    };
    let absolute = std::path::absolute(&expanded).unwrap_or(expanded);
    let mut existing = absolute.clone();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = std::fs::canonicalize(&existing) {
            let mut out = PathBuf::from(strip_verbatim(real.to_string_lossy().into_owned()));
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (existing.file_name().map(std::ffi::OsString::from), existing.parent().map(Path::to_path_buf)) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                existing = parent;
            }
            _ => return absolute,
        }
    }
}

/// `paths.validate_project_path`: Ghidra rejects dot-prefixed path components.
pub fn validate_project_path(directory: &Path) -> Result<PathBuf> {
    let path = resolved(directory);
    if path.components().any(|c| matches!(c, std::path::Component::Normal(n) if n.to_string_lossy().starts_with('.'))) {
        return Err(Error::value(format!(
            "Ghidra project paths cannot contain dot-prefixed directories: {}; choose a dot-free data root/project directory",
            path.display()
        )));
    }
    Ok(path)
}

fn root_for(cased: &str, plain: &str, environ: &dyn Fn(&str) -> Option<String>, home: &Path) -> PathBuf {
    if cfg!(windows) {
        match environ("LOCALAPPDATA").filter(|v| !v.is_empty()) {
            Some(local) => PathBuf::from(local).join(cased),
            None => home.join("AppData").join("Local").join(cased),
        }
    } else if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support").join(cased)
    } else {
        match environ("XDG_DATA_HOME") {
            Some(data) if data.starts_with('/') && !data.split('/').any(|p| p.starts_with('.')) => PathBuf::from(data).join(plain),
            _ => home.join(plain),
        }
    }
}

/// `paths.default_root` with injectable environment, home and existence check (tests).
pub fn default_root_with(environ: &dyn Fn(&str) -> Option<String>, home: &Path, exists: &dyn Fn(&Path) -> bool) -> PathBuf {
    let current = root_for("Hydralysis", "hydralysis", environ, home);
    let legacy = root_for("RusticRE", "rusticre", environ, home);
    if !exists(&current) && exists(&legacy) {
        note(
            "root",
            &legacy.to_string_lossy(),
            &current.to_string_lossy(),
            "existing RusticRE data root in use; not moved or copied. Set HYDRALYSIS_ROOT to keep using it explicitly",
        );
        return legacy;
    }
    current
}

pub fn default_root() -> Result<PathBuf> {
    let home = std::env::home_dir().ok_or_else(|| Error::value("Could not determine home directory."))?;
    Ok(default_root_with(&|k| std::env::var(k).ok(), &home, &|p| p.exists()))
}

/// `paths.forbidden_drives`.
pub fn forbidden_drives(settings: &Value) -> Result<Vec<String>> {
    let value = match settings.get("forbidden_drives") {
        Some(v) if !v.is_null() => v.clone(),
        _ => Value::String(env("FORBIDDEN_DRIVES").unwrap_or_default()),
    };
    let items: Vec<String> = match &value {
        Value::String(s) => s.replace(';', ",").split(',').filter(|i| !i.trim().is_empty()).map(str::to_string).collect(),
        Value::Array(list) if list.iter().all(Value::is_string) => list.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => return Err(Error::value("forbidden_drives must be a list of drive names such as [\"C:\"]")),
    };
    Ok(items.iter().map(|i| i.trim().to_uppercase().trim_end_matches(['\\', '/']).to_string()).collect())
}

fn drive_of(path: &Path) -> String {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return text[..2].to_string();
    }
    if let Some(rest) = text.strip_prefix("\\\\") {
        let mut parts = rest.split('\\');
        if let (Some(server), Some(share)) = (parts.next(), parts.next()) {
            return format!("\\\\{server}\\{share}");
        }
    }
    String::new()
}

fn checked_root(raw: &str, banned: &[String]) -> Result<PathBuf> {
    let root = resolved(Path::new(raw));
    let drive = drive_of(&root);
    if cfg!(windows) && !drive.is_empty() && banned.contains(&drive.to_uppercase()) {
        return Err(Error::value(format!(
            "Hydralysis data root {} is on {drive}, which this configuration forbids (forbidden_drives={}); set root or HYDRALYSIS_ROOT to an allowed location",
            root.display(),
            banned.join(",")
        )));
    }
    validate_project_path(&root)
}

/// `paths.root_path(settings)`.
pub fn root_path(settings: &Value) -> Result<PathBuf> {
    let raw = match settings.get("root").filter(|v| py_truthy(v)) {
        Some(v) => py_str(v),
        None => match env("ROOT") {
            Some(v) => v,
            None => default_root()?.to_string_lossy().into_owned(),
        },
    };
    let banned = forbidden_drives(settings)?;
    checked_root(&raw, &banned)
}

/// `paths.root_source`: `env`, `config`, `default` or `legacy`.
pub fn root_source(settings: &Value) -> &'static str {
    if env("ROOT").is_some() {
        return "env";
    }
    if settings.get("root").is_some_and(py_truthy) {
        return "config";
    }
    let Some(home) = std::env::home_dir() else { return "default" };
    let get = |k: &str| std::env::var(k).ok();
    let current = root_for("Hydralysis", "hydralysis", &get, &home);
    let legacy = root_for("RusticRE", "rusticre", &get, &home);
    if !current.exists() && legacy.exists() { "legacy" } else { "default" }
}

// ---------------------------------------------------------------------------------------------------------- config

pub fn user_config_dir() -> Result<PathBuf> {
    default_root().map_err(|e| Error::value(format!("no per-user folder: {e}; set HYDRALYSIS_CONFIG and HYDRALYSIS_ROOT")))
}

/// The configuration file and where it was found: `env`, `user` or `none`.
pub fn config_source() -> (Option<PathBuf>, &'static str) {
    if let Some(path) = env("CONFIG") {
        return (Some(PathBuf::from(path)), "env");
    }
    let Ok(folder) = user_config_dir() else { return (None, "none") };
    for name in config_names() {
        let candidate = folder.join(name);
        if candidate.is_file() {
            if name == LEGACY_CONFIG {
                note("config-file", &candidate.to_string_lossy(), PRIMARY_CONFIG, "");
            }
            return (Some(candidate), "user");
        }
    }
    (None, "none")
}

pub fn config_path() -> Option<PathBuf> {
    config_source().0
}

/// A configuration file in the working directory that is NOT used, or None.
pub fn ignored_cwd_config() -> Option<PathBuf> {
    let here = std::env::current_dir().ok()?;
    config_names().iter().map(|n| here.join(n)).find(|p| p.is_file())
}

/// The configuration file as written (an empty object when there is none).
pub fn read_settings() -> Result<Map<String, Value>> {
    let Some(path) = config_path().filter(|p| p.is_file()) else { return Ok(Map::new()) };
    let text = std::fs::read_to_string(&path)?;
    match serde_json::from_str::<Value>(&text)? {
        Value::Object(map) => Ok(map),
        _ => Err(Error::value("Hydralysis config must be a JSON object")),
    }
}

/// `config.load()`.
pub fn load() -> Result<Value> {
    let mut settings = read_settings()?;
    if let Some(root) = env("ROOT") {
        settings.insert("root".into(), Value::String(root));
    }
    let settings_value = Value::Object(settings.clone());
    let root = root_path(&settings_value)?;
    let installed = read_json(&root.join("backend.json"))?;
    let prepared = match read_json(&root.join("targets.json"))?.get("targets") {
        Some(Value::Object(t)) => t.clone(),
        _ => Map::new(),
    };
    let mut result = Map::new();
    result.insert("root".into(), Value::String(root.to_string_lossy().into_owned()));
    result.insert("max_mem".into(), Value::String("6G".into()));
    result.insert("max_cpu".into(), Value::from(4));
    for (k, v) in installed {
        result.insert(k, v);
    }
    for (k, v) in &settings {
        result.insert(k.clone(), v.clone());
    }
    let explicit = ["targets", "projects"].iter().filter_map(|k| settings.get(*k)).find(|v| py_truthy(v));
    let mut targets = prepared;
    if let Some(Value::Object(map)) = explicit {
        for (k, v) in map {
            targets.insert(k.clone(), v.clone());
        }
    }
    result.insert("targets".into(), Value::Object(targets));
    Ok(Value::Object(result))
}

/// `config.evidence_path(explicit)`.
pub fn evidence_path(explicit: &str) -> Result<PathBuf> {
    if !explicit.is_empty() {
        return Ok(PathBuf::from(explicit));
    }
    if let Some(path) = env("EVIDENCE") {
        return Ok(PathBuf::from(path));
    }
    let settings = load()?;
    if let Some(path) = settings.get("evidence").filter(|v| py_truthy(v)) {
        return Ok(PathBuf::from(py_str(path)));
    }
    Ok(PathBuf::from(py_str(&settings["root"])).join("evidence.db"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gmtime_epoch_and_leap() {
        assert_eq!(iso_at(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_at(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn python_str() {
        assert_eq!(py_str(&serde_json::json!(50.0)), "50.0");
        assert_eq!(py_str(&serde_json::json!(null)), "None");
        assert_eq!(py_str(&serde_json::json!(["a", true])), "['a', True]");
    }
}
