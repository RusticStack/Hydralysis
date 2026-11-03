//! The evidence ledger (Rust port of `hydralysis.evidence`, evidence v2).
//!
//! A claim is a row: target, build, address, prologue and the line that proves it. The public edge works on
//! `serde_json::Value` (decoded rows, claim content, coverage objects) so a PyO3 layer and other Rust lanes see the
//! shapes the Python code uses. Ids, the canonical form (keys in UTF-16 order), the SQLite schema and every error
//! message equal the Python implementation.
//!
//! Known deviations (also in TESTMAP_evidence.md): integers beyond 64 bits parse as floats (the "float" refusal
//! instead of the "2**53" one); the text that follows "is not JSON:" is serde's, not Python's; `repr()` of non-ASCII
//! characters approximates Python's `isprintable`.

use rusqlite::{Connection, OptionalExtension, types::ValueRef};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MODEL: &str = "hydralysis.evidence/2";
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS claims (
    id INTEGER PRIMARY KEY,
    game TEXT NOT NULL,
    build TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    address TEXT NOT NULL DEFAULT '',
    prologue TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL,
    source TEXT NOT NULL,
    created TEXT NOT NULL
);
";
/// Columns added after the first release; existing ledgers are upgraded in place (insertion order matters).
pub const COLUMNS: &[(&str, &str)] = &[
    ("subsystem", "TEXT NOT NULL DEFAULT ''"),
    ("client", "TEXT NOT NULL DEFAULT ''"),
    ("harness", "TEXT NOT NULL DEFAULT ''"),
    ("supersedes", "INTEGER"),
    ("superseded_by", "INTEGER"),
    ("evidence_id", "TEXT"),
    ("coverage", "TEXT NOT NULL DEFAULT ''"),
    ("limitations", "TEXT NOT NULL DEFAULT ''"),
    ("parameters", "TEXT NOT NULL DEFAULT ''"),
    ("confidence", "TEXT NOT NULL DEFAULT ''"),
    ("authority", "TEXT NOT NULL DEFAULT ''"),
    ("subject_sha256", "TEXT NOT NULL DEFAULT ''"),
    ("from_capture", "TEXT NOT NULL DEFAULT ''"),
    ("evidence_links", "TEXT NOT NULL DEFAULT ''"),
    ("provenance", "TEXT NOT NULL DEFAULT ''"),
    ("from_trace", "TEXT NOT NULL DEFAULT ''"),
];
pub const LEGACY_FIELDS: &[&str] = &[
    "id",
    "game",
    "build",
    "kind",
    "name",
    "address",
    "prologue",
    "note",
    "source",
    "created",
    "subsystem",
    "client",
    "harness",
    "supersedes",
    "superseded_by",
];
pub const FIELDS: &[&str] = &[
    "id",
    "game",
    "build",
    "kind",
    "name",
    "address",
    "prologue",
    "note",
    "source",
    "created",
    "subsystem",
    "client",
    "harness",
    "supersedes",
    "superseded_by",
    "evidence_id",
    "coverage",
    "limitations",
    "parameters",
    "confidence",
    "authority",
    "subject_sha256",
    "from_capture",
    "evidence_links",
    "provenance",
    "from_trace",
];
pub const BUSY_TIMEOUT_MS: u64 = 15000;

pub const CONFIDENCES: &[&str] = &["observed", "derived", "inferred"];
pub const AUTHORITIES: &[&str] =
    &["shipped-artifact", "controlled-replay", "historical-reference", "external-service", "analyst-inference"];
pub const DEFAULT_CONFIDENCE: &str = "inferred";
pub const DEFAULT_AUTHORITY: &str = "analyst-inference";
pub const COVERAGE_STATES: &[&str] = &["complete", "partial", "unknown"];
pub const NOT_REPORTED: &str = "coverage_not_reported";
pub const MAX_TRACE_EVENTS: usize = 64;
const SAFE_INT: u64 = (1 << 53) - 1;
/// Content keys a claim may carry or omit.
pub const OPTIONAL_KEYS: &[&str] = &["from_trace"];
/// `CONTENT_KEYS` of Python: the keys of `build_content` with no optional field.
pub const CONTENT_KEYS: &[&str] = &[
    "model",
    "subject",
    "game",
    "build",
    "kind",
    "name",
    "address",
    "prologue",
    "subsystem",
    "note",
    "source",
    "parameters",
    "confidence",
    "authority",
    "coverage",
    "limitations",
    "from_capture",
    "evidence_links",
];

/// (field, ledger column(s)) of the REA reference record.
pub const REA_FIELD_MAP: &[(&str, &str)] = &[
    ("evidence_id", "evidence_id"),
    ("subject", "subject_sha256"),
    ("provider", "client,harness"),
    ("analysis_profile", "build"),
    ("predicate_type", "kind"),
    ("parameters", "parameters"),
    ("normalized_result", "name,address,prologue,note"),
    ("confidence", "confidence"),
    ("authority", "authority"),
    ("limitations", "limitations"),
    ("relationship_coverage", "coverage"),
    ("locations", "address"),
    ("evidence_links", "evidence_links"),
];
pub const REA_FIELD_GAPS: &[(&str, &str)] = &[
    ("operation", "not modeled: `source` names how the claim was obtained and `kind` what it is"),
    ("raw_result", "deliberately absent: a claim carries no payload bytes; a bounded capture travels in captures/"),
    ("environment", "not part of the identity: a bundle records the exporting environment in environment.json"),
    ("caller_input_path", "not applicable: a claim has no caller path"),
];

// ---- errors ---------------------------------------------------------------------------------------------------

/// A stored row or a bundle record whose content no longer matches its evidence_id.
#[derive(Debug, Clone)]
pub struct EvidenceIntegrityError {
    pub message: String,
    pub code: String,
    pub evidence_id: String,
    pub row_id: Option<i64>,
}

impl EvidenceIntegrityError {
    pub fn new(message: impl Into<String>, code: &str, evidence_id: impl Into<String>) -> Self {
        Self { message: message.into(), code: code.to_string(), evidence_id: evidence_id.into(), row_id: None }
    }
}

impl std::fmt::Display for EvidenceIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// Python `ValueError`.
    #[error("{0}")]
    Value(String),
    #[error("{0}")]
    Integrity(EvidenceIntegrityError),
    #[error("{0}")]
    Bundle(crate::bundle::BundleError),
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Core(#[from] hy_core::Error),
}

pub type Result<T> = std::result::Result<T, EvidenceError>;

impl EvidenceError {
    pub fn value(message: impl Into<String>) -> Self {
        EvidenceError::Value(message.into())
    }
    /// The stable code for errors that carry one.
    pub fn code(&self) -> Option<&str> {
        match self {
            EvidenceError::Integrity(e) => Some(&e.code),
            EvidenceError::Bundle(e) => Some(&e.code),
            _ => None,
        }
    }
    pub fn as_integrity(&self) -> Option<&EvidenceIntegrityError> {
        match self {
            EvidenceError::Integrity(e) => Some(e),
            _ => None,
        }
    }
}

impl From<EvidenceIntegrityError> for EvidenceError {
    fn from(error: EvidenceIntegrityError) -> Self {
        EvidenceError::Integrity(error)
    }
}

// ---- Python-flavoured helpers -----------------------------------------------------------------------------------

/// Python truthiness of a JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

pub fn py_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_i64() || n.is_u64() => "int",
        Value::Number(_) => "float",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn py_strip_is_empty(s: &str) -> bool {
    s.chars().all(py_isspace)
}

/// `repr(str)`.
pub fn py_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x7f => out.push(c),
            c if c.is_control() || (c.is_whitespace()) => {
                let n = c as u32;
                if n <= 0xff {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n <= 0xffff {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `repr(value)` of a decoded JSON value.
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
                hy_core::json::float_repr(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => py_repr_str(s),
        Value::Array(a) => format!("[{}]", a.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => {
            format!("{{{}}}", o.iter().map(|(k, v)| format!("{}: {}", py_repr_str(k), py_repr(v))).collect::<Vec<_>>().join(", "))
        }
    }
}

/// `str(value)`.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => py_repr(other),
    }
}

/// Python's `$` also matches before one trailing newline.
fn dollar(text: &str) -> &str {
    text.strip_suffix('\n').unwrap_or(text)
}

fn ident_tail(s: &str, extra: &[char], max_tail: usize, first: fn(char) -> bool) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if first(c) => {}
        _ => return false,
    }
    let rest: Vec<char> = chars.collect();
    rest.len() <= max_tail && rest.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(c))
}

fn lower_start(c: char) -> bool {
    c.is_ascii_lowercase()
}

/// `^(?:[a-z][a-z0-9_.-]{0,31}:)?[a-z][a-z0-9_]{0,63}$`
fn code_ok(text: &str) -> bool {
    let text = dollar(text);
    match text.split_once(':') {
        Some((prefix, name)) => ident_tail(prefix, &['_', '.', '-'], 31, lower_start) && ident_tail(name, &['_'], 63, lower_start),
        None => ident_tail(text, &['_'], 63, lower_start),
    }
}

fn is_hex64(text: &str) -> bool {
    let text = dollar(text);
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `^ev_[0-9a-f]{64}$`
pub fn is_evidence_id(value: &Value) -> bool {
    matches!(value, Value::String(s) if is_evidence_id_str(s))
}

pub fn is_evidence_id_str(text: &str) -> bool {
    dollar(text)
        .strip_prefix("ev_")
        .is_some_and(|rest| rest.len() == 64 && rest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

fn alnum_start(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `^[A-Za-z0-9_][A-Za-z0-9_<extra>]{0,max_tail}` over the whole text (no `$` newline allowance).
pub(crate) fn id_like(text: &str, extra: &[char], max_tail: usize) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if alnum_start(c) => {}
        _ => return false,
    }
    let rest: Vec<char> = chars.collect();
    rest.len() <= max_tail && rest.iter().all(|c| c.is_ascii_alphanumeric() || *c == '_' || extra.contains(c))
}

/// `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$`
pub fn is_capture_id(text: &str) -> bool {
    id_like(dollar(text), &['.', '-'], 79)
}

// ---- time and identity --------------------------------------------------------------------------------------------

/// `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")`.
pub fn now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    format_utc(secs)
}

pub fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// The writer's identity (`hydra.identity()`): client `rusticre:<pid>`, harness from `HYDRALYSIS_HARNESS`
/// (else `RUSTICRE_HARNESS`, else `cli`).
pub fn default_who() -> (String, String) {
    let harness = ["HYDRALYSIS_HARNESS", "RUSTICRE_HARNESS"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| "cli".into());
    (format!("rusticre:{}", std::process::id()), harness)
}

/// Who writes and when. Both default to the real values; tests pin them.
#[derive(Debug, Clone, Default)]
pub struct Ctx {
    pub who: Option<(String, String)>,
    pub now: Option<String>,
}

impl Ctx {
    pub fn who(&self) -> (String, String) {
        self.who.clone().unwrap_or_else(default_who)
    }
    pub fn now(&self) -> String {
        self.now.clone().unwrap_or_else(now)
    }
}

// ---- canonical form and identity ----------------------------------------------------------------------------------

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn emit(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > SAFE_INT {
                    return Err(EvidenceError::value(
                        "an integer beyond 2**53-1 cannot be committed to an evidence id; write it as a string",
                    ));
                }
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                if u > SAFE_INT {
                    return Err(EvidenceError::value(
                        "an integer beyond 2**53-1 cannot be committed to an evidence id; write it as a string",
                    ));
                }
                out.extend_from_slice(u.to_string().as_bytes());
            } else {
                return Err(EvidenceError::value(
                    "a float cannot be committed to an evidence id (its text differs between implementations); write it as an integer or a string",
                ));
            }
        }
        Value::String(s) => hy_core::json::write_string(out, s, false),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                emit(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| utf16_cmp(a.0, b.0));
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                hy_core::json::write_string(out, key, false);
                out.push(b':');
                emit(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// RFC 8785 style canonical JSON: keys in UTF-16 order, no spaces; floats and unsafe integers are refused.
pub fn canonical_json(value: &Value) -> Result<String> {
    let mut out = Vec::with_capacity(256);
    emit(value, &mut out)?;
    Ok(String::from_utf8(out).unwrap_or_default())
}

pub fn canonical_digest(value: &Value) -> Result<String> {
    Ok(hy_core::sealed::sha256_hex(canonical_json(value)?.as_bytes()))
}

pub fn compute_evidence_id(content: &Value) -> Result<String> {
    Ok(format!("ev_{}", canonical_digest(content)?))
}

// ---- coverage and limitations -------------------------------------------------------------------------------------

pub fn limitation_entry(code: &str) -> Option<&'static (&'static str, bool, &'static str)> {
    LIMITATIONS.iter().find(|entry| entry.0 == code)
}

pub fn check_limitation_code(code: &Value) -> Result<String> {
    let text = match code {
        Value::String(s) if code_ok(s) => s,
        _ => {
            return Err(EvidenceError::value(format!(
                "limitation code {} is not a lowercase identifier (optionally `namespace:code`)",
                py_repr(code)
            )));
        }
    };
    if !text.contains(':') && limitation_entry(text).is_none() {
        let mut names: Vec<&str> = LIMITATIONS.iter().map(|e| e.0).collect();
        names.sort_unstable();
        return Err(EvidenceError::value(format!(
            "unknown limitation code {}; use one of {}, or write your own as `namespace:code`",
            py_repr_str(text),
            names.join(", ")
        )));
    }
    Ok(text.clone())
}

/// True when the code says the claim covers less than the whole subject (a namespaced code is assumed to).
pub fn bounds_coverage(code: &str) -> bool {
    limitation_entry(code).is_none_or(|entry| entry.1)
}

/// The Coverage object: complete, partial (with limitation codes) or unknown (with a reason).
pub fn normalize_coverage(value: Option<&Value>) -> Result<Value> {
    let default = || json!({"status": "unknown", "reason": NOT_REPORTED});
    let value = match value {
        None | Some(Value::Null) => return Ok(default()),
        Some(v) => v,
    };
    let object = match value {
        Value::String(s) => {
            let mut m = Map::new();
            m.insert("status".into(), Value::String(s.clone()));
            m
        }
        Value::Object(o) => o.clone(),
        _ => return Err(EvidenceError::value("coverage must be an object with a status")),
    };
    let status = match object.get("status") {
        Some(Value::String(s)) if COVERAGE_STATES.contains(&s.as_str()) => s.clone(),
        _ => return Err(EvidenceError::value(format!("coverage.status must be one of {}", COVERAGE_STATES.join(", ")))),
    };
    let mut extra: Vec<&str> =
        object.keys().map(String::as_str).filter(|k| !["status", "limitations", "reason", "diagnostics"].contains(k)).collect();
    if !extra.is_empty() {
        extra.sort_unstable();
        return Err(EvidenceError::value(format!("coverage has no field {}", extra.join(", "))));
    }
    let mut result = Map::new();
    result.insert("status".into(), Value::String(status.clone()));
    match status.as_str() {
        "partial" => {
            let codes = match object.get("limitations") {
                Some(Value::Array(a)) if !a.is_empty() => a,
                _ => return Err(EvidenceError::value("partial coverage lists at least one limitation code")),
            };
            let mut set = BTreeSet::new();
            for code in codes {
                set.insert(check_limitation_code(code)?);
            }
            result.insert("limitations".into(), Value::Array(set.into_iter().map(Value::String).collect()));
        }
        "unknown" => {
            let reason = match object.get("reason") {
                Some(v) if truthy(v) => v.clone(),
                _ => Value::String(NOT_REPORTED.into()),
            };
            match &reason {
                Value::String(s) if !py_strip_is_empty(s) => {}
                _ => return Err(EvidenceError::value("unknown coverage needs a reason")),
            }
            result.insert("reason".into(), reason);
        }
        _ => {
            if object.get("limitations").is_some_and(truthy) || object.get("reason").is_some_and(truthy) {
                return Err(EvidenceError::value("complete coverage carries no limitations or reason"));
            }
        }
    }
    if let Some(diagnostics) = object.get("diagnostics").filter(|d| truthy(d)) {
        match diagnostics {
            Value::Array(items) if items.iter().all(|i| matches!(i, Value::String(s) if !s.is_empty())) => {
                result.insert("diagnostics".into(), diagnostics.clone());
            }
            _ => return Err(EvidenceError::value("coverage.diagnostics is a list of non-empty strings")),
        }
    }
    Ok(Value::Object(result))
}

pub fn derived_limitations(coverage: &Value) -> Vec<String> {
    match coverage["status"].as_str() {
        Some("partial") => {
            coverage["limitations"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
        }
        Some("unknown") => vec!["coverage_unknown".into()],
        _ => Vec::new(),
    }
}

/// The sorted, unique codes of a row: those it states plus those its coverage implies. Complete means complete.
pub fn merge_limitations(coverage: &Value, limitations: &[Value]) -> Result<Vec<String>> {
    let mut codes = BTreeSet::new();
    for code in limitations {
        codes.insert(check_limitation_code(code)?);
    }
    codes.extend(derived_limitations(coverage));
    if coverage["status"] == "complete" {
        let bounding: Vec<&str> = codes.iter().map(String::as_str).filter(|c| bounds_coverage(c)).collect();
        if !bounding.is_empty() {
            return Err(EvidenceError::value(format!(
                "coverage is complete but the claim states {}, which bounds what it covers; say partial",
                bounding.join(", ")
            )));
        }
    }
    Ok(codes.into_iter().collect())
}

// ---- the content that an evidence id commits ------------------------------------------------------------------------

fn is_int(value: &Value) -> bool {
    matches!(value, Value::Number(n) if n.is_i64() || n.is_u64())
}

/// The normal form of a trace citation: `{session, events (sorted, unique, at most 64), revision[, interpretation]}`.
pub fn check_from_trace(value: &Value) -> Result<Value> {
    let usage = || EvidenceError::value("from_trace is {session, events, revision[, interpretation]}");
    let Value::Object(map) = value else { return Err(usage()) };
    if map.keys().any(|k| !["session", "events", "revision", "interpretation"].contains(&k.as_str())) {
        return Err(usage());
    }
    let session = match map.get("session") {
        Some(Value::String(s)) if id_like(dollar(s), &['.', '-'], 79) => s.clone(),
        _ => {
            return Err(EvidenceError::value("from_trace.session must be a trace session id (letters, digits, `_`, `.`, `-`, at most 80)"));
        }
    };
    let events = match map.get("events") {
        Some(Value::Array(a)) if (1..=MAX_TRACE_EVENTS).contains(&a.len()) => a,
        _ => return Err(EvidenceError::value(format!("from_trace.events lists 1..{MAX_TRACE_EVENTS} event ids"))),
    };
    if !events.iter().all(|e| matches!(e, Value::String(s) if id_like(dollar(s), &['.', ':', '-'], 119))) {
        return Err(EvidenceError::value("from_trace.events holds event ids (letters, digits and `_.:-`)"));
    }
    let revision = map.get("revision").cloned().unwrap_or(Value::Null);
    let interpretation = map.get("interpretation").cloned().unwrap_or(Value::Null);
    for (name, item) in [("revision", &revision), ("interpretation", &interpretation)] {
        if name == "interpretation" && item.is_null() {
            continue;
        }
        let ok = is_int(item) && item.as_i64().is_none_or(|i| i >= 0) && item.as_u64().is_none_or(|u| u <= SAFE_INT);
        if !ok {
            return Err(EvidenceError::value(format!("from_trace.{name} must be a non-negative integer")));
        }
    }
    let sorted: BTreeSet<&str> = events.iter().filter_map(Value::as_str).collect();
    let mut result = Map::new();
    result.insert("session".into(), Value::String(session));
    result.insert("events".into(), Value::Array(sorted.into_iter().map(|s| Value::String(s.into())).collect()));
    result.insert("revision".into(), revision);
    if !interpretation.is_null() {
        result.insert("interpretation".into(), interpretation);
    }
    Ok(Value::Object(result))
}

/// Whether CONTENT has exactly the fields of the evidence model (the optional ones may be absent).
pub fn content_keys_ok(content: &Map<String, Value>) -> bool {
    CONTENT_KEYS.iter().all(|k| content.contains_key(*k))
        && content.keys().all(|k| CONTENT_KEYS.contains(&k.as_str()) || OPTIONAL_KEYS.contains(&k.as_str()))
}

/// The fields of one claim as `build_content` takes them.
#[derive(Debug, Clone, Default)]
pub struct Claim {
    pub game: String,
    pub build: String,
    pub kind: String,
    pub name: String,
    pub note: String,
    pub source: String,
    pub address: String,
    pub prologue: String,
    pub subsystem: String,
    pub supersedes: Option<i64>,
    pub coverage: Option<Value>,
    pub limitations: Vec<Value>,
    pub parameters: Option<Value>,
    /// `None` is `inferred`.
    pub confidence: Option<String>,
    /// `None` is `analyst-inference`.
    pub authority: Option<String>,
    pub subject_sha256: String,
    pub from_capture: String,
    pub provenance: Option<Value>,
    pub from_trace: Option<Value>,
}

impl Claim {
    /// The five required fields; everything else defaults.
    pub fn new(game: &str, build: &str, kind: &str, name: &str, note: &str, source: &str) -> Self {
        Claim {
            game: game.into(),
            build: build.into(),
            kind: kind.into(),
            name: name.into(),
            note: note.into(),
            source: source.into(),
            ..Claim::default()
        }
    }
}

/// The validated semantic content of one claim; `compute_evidence_id` hashes exactly this.
pub fn build_content(claim: &Claim, evidence_links: &[String]) -> Result<Value> {
    for (field, value) in [
        ("game", &claim.game),
        ("build", &claim.build),
        ("kind", &claim.kind),
        ("name", &claim.name),
        ("note", &claim.note),
        ("source", &claim.source),
    ] {
        if py_strip_is_empty(value) {
            return Err(EvidenceError::value(format!("{field} is required; a claim without evidence is not stored")));
        }
    }
    let confidence = claim.confidence.as_deref().unwrap_or(DEFAULT_CONFIDENCE);
    if !CONFIDENCES.contains(&confidence) {
        return Err(EvidenceError::value(format!("confidence must be one of {}", CONFIDENCES.join(", "))));
    }
    let authority = claim.authority.as_deref().unwrap_or(DEFAULT_AUTHORITY);
    if !AUTHORITIES.contains(&authority) {
        return Err(EvidenceError::value(format!("authority must be one of {}", AUTHORITIES.join(", "))));
    }
    let parameters = match &claim.parameters {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(v @ Value::Object(_)) => v.clone(),
        Some(_) => return Err(EvidenceError::value("parameters must be a JSON object")),
    };
    if !claim.subject_sha256.is_empty() && !is_hex64(&claim.subject_sha256) {
        return Err(EvidenceError::value("subject_sha256 must be 64 lowercase hex digits"));
    }
    if !claim.from_capture.is_empty() && !is_capture_id(&claim.from_capture) {
        return Err(EvidenceError::value("from_capture must be a capture id (letters, digits, `_`, `.`, `-`, at most 80)"));
    }
    let links: BTreeSet<&String> = evidence_links.iter().collect();
    for link in &links {
        if !is_evidence_id_str(link) {
            return Err(EvidenceError::value(format!("evidence_links holds ev_ ids; {} is not one", py_repr_str(link))));
        }
    }
    let status = normalize_coverage(claim.coverage.as_ref())?;
    let limitations = merge_limitations(&status, &claim.limitations)?;
    let mut content = Map::new();
    content.insert("model".into(), json!(MODEL));
    content.insert("subject".into(), if claim.subject_sha256.is_empty() { Value::Null } else { json!({"sha256": claim.subject_sha256}) });
    for (key, value) in [
        ("game", &claim.game),
        ("build", &claim.build),
        ("kind", &claim.kind),
        ("name", &claim.name),
        ("address", &claim.address),
        ("prologue", &claim.prologue),
        ("subsystem", &claim.subsystem),
        ("note", &claim.note),
        ("source", &claim.source),
    ] {
        content.insert(key.into(), Value::String(value.clone()));
    }
    content.insert("parameters".into(), parameters);
    content.insert("confidence".into(), json!(confidence));
    content.insert("authority".into(), json!(authority));
    content.insert("coverage".into(), status);
    content.insert("limitations".into(), json!(limitations));
    content.insert("from_capture".into(), if claim.from_capture.is_empty() { Value::Null } else { json!(claim.from_capture) });
    content.insert("evidence_links".into(), json!(links));
    if let Some(trace) = claim.from_trace.as_ref().filter(|t| truthy(t)) {
        content.insert("from_trace".into(), check_from_trace(trace)?);
    }
    let content = Value::Object(content);
    canonical_json(&content)?; // refuses a float, an unsafe integer before anything is stored
    Ok(content)
}

// ---- rows ---------------------------------------------------------------------------------------------------------

/// A stored row: the columns of `FIELDS` as JSON values (NULL stays `null`).
pub type Row = Map<String, Value>;

fn loads(value: &Value, default: Value) -> Result<Value> {
    match value {
        Value::Null => Ok(default),
        Value::String(s) if s.is_empty() => Ok(default),
        Value::String(s) => serde_json::from_str(s).map_err(|e| EvidenceError::value(e.to_string())),
        Value::Number(_) | Value::Bool(_) if !truthy(value) => Ok(default),
        other => Err(EvidenceError::value(format!("the JSON object must be str, bytes or bytearray, not {}", py_type_name(other)))),
    }
}

fn field<'a>(row: &'a Row, name: &str) -> &'a Value {
    row.get(name).unwrap_or(&Value::Null)
}

/// The semantic content of a stored row, decoded without re-validating it (so a damaged row stays visible).
pub fn content_of_row(row: &Row) -> Result<Value> {
    let mut content = Map::new();
    content.insert("model".into(), json!(MODEL));
    let subject = field(row, "subject_sha256");
    content.insert("subject".into(), if truthy(subject) { json!({"sha256": subject}) } else { Value::Null });
    for key in ["game", "build", "kind", "name", "address", "prologue", "subsystem", "note", "source"] {
        content.insert(key.into(), field(row, key).clone());
    }
    content.insert("parameters".into(), loads(field(row, "parameters"), json!({}))?);
    let pick = |name: &str, default: &str| if truthy(field(row, name)) { field(row, name).clone() } else { json!(default) };
    content.insert("confidence".into(), pick("confidence", DEFAULT_CONFIDENCE));
    content.insert("authority".into(), pick("authority", DEFAULT_AUTHORITY));
    let coverage = loads(field(row, "coverage"), Value::Null)?;
    content.insert("coverage".into(), if truthy(&coverage) { coverage } else { normalize_coverage(None)? });
    content.insert(
        "limitations".into(),
        if truthy(field(row, "limitations")) { loads(field(row, "limitations"), Value::Null)? } else { json!(["coverage_unknown"]) },
    );
    content
        .insert("from_capture".into(), if truthy(field(row, "from_capture")) { field(row, "from_capture").clone() } else { Value::Null });
    content.insert("evidence_links".into(), loads(field(row, "evidence_links"), json!([]))?);
    if truthy(field(row, "from_trace")) {
        content.insert("from_trace".into(), loads(field(row, "from_trace"), Value::Null)?);
    }
    Ok(Value::Object(content))
}

pub fn verify_content(content: &Value, evidence_id: &Value) -> Result<()> {
    if !is_evidence_id(evidence_id) {
        return Err(EvidenceIntegrityError::new(
            format!("{} is not an evidence id", py_repr(evidence_id)),
            "evidence_id_malformed",
            py_str(evidence_id),
        )
        .into());
    }
    let id = evidence_id.as_str().unwrap_or_default();
    let actual = match compute_evidence_id(content) {
        Ok(a) => a,
        Err(EvidenceError::Value(message)) => {
            return Err(EvidenceIntegrityError::new(
                format!("evidence {id} has content that cannot be committed: {message}"),
                "evidence_mismatch",
                id,
            )
            .into());
        }
        Err(other) => return Err(other),
    };
    if actual != id {
        return Err(EvidenceIntegrityError::new(
            format!("evidence {id} does not match its content (the content hashes to {actual})"),
            "evidence_mismatch",
            id,
        )
        .into());
    }
    Ok(())
}

const STRING_FIELDS: &[&str] =
    &["game", "build", "kind", "name", "address", "prologue", "subsystem", "note", "source", "confidence", "authority"];

/// Strictly validate content that arrives from outside (a bundle): the claim rules, exact types, then the id.
pub fn check_content(content: &Value, evidence_id: &Value) -> Result<()> {
    let id_text = py_str(evidence_id);
    let bad = |message: String| -> EvidenceError {
        EvidenceIntegrityError::new(
            format!("evidence {id_text} has content the evidence model refuses: {message}"),
            "evidence_content_invalid",
            id_text.clone(),
        )
        .into()
    };
    let Value::Object(map) = content else { return Err(bad("its fields are not those of the evidence model".into())) };
    if !content_keys_ok(map) {
        return Err(bad("its fields are not those of the evidence model".into()));
    }
    if map["model"] != json!(MODEL) {
        return Err(bad(format!("model is {}, not {}", py_repr(&map["model"]), py_repr_str(MODEL))));
    }
    for name in STRING_FIELDS {
        if !map[*name].is_string() {
            return Err(bad(format!("{name} must be a string, not a {}", py_type_name(&map[*name]))));
        }
    }
    let subject = &map["subject"];
    let sha = match subject {
        Value::Null => String::new(),
        Value::Object(o) if o.len() == 1 && o.get("sha256").is_some_and(Value::is_string) => {
            o["sha256"].as_str().unwrap_or_default().to_string()
        }
        _ => return Err(bad("subject must be null or {sha256}".into())),
    };
    if !map["from_capture"].is_null() && !map["from_capture"].is_string() {
        return Err(bad("from_capture must be a string or null".into()));
    }
    if !map["parameters"].is_object() {
        return Err(bad("parameters must be an object".into()));
    }
    if !map["coverage"].is_object() {
        return Err(bad("coverage must be an object".into()));
    }
    for name in ["limitations", "evidence_links"] {
        match &map[name] {
            Value::Array(items) if items.iter().all(Value::is_string) => {}
            _ => return Err(bad(format!("{name} must be a list of strings"))),
        }
    }
    let text = |name: &str| map[name].as_str().unwrap_or_default().to_string();
    let rebuilt = (|| -> Result<bool> {
        let claim = Claim {
            game: text("game"),
            build: text("build"),
            kind: text("kind"),
            name: text("name"),
            note: text("note"),
            source: text("source"),
            address: text("address"),
            prologue: text("prologue"),
            subsystem: text("subsystem"),
            coverage: Some(map["coverage"].clone()),
            limitations: map["limitations"].as_array().cloned().unwrap_or_default(),
            parameters: Some(map["parameters"].clone()),
            confidence: Some(text("confidence")),
            authority: Some(text("authority")),
            subject_sha256: sha,
            from_capture: map["from_capture"].as_str().unwrap_or_default().to_string(),
            from_trace: map.get("from_trace").cloned(),
            ..Claim::default()
        };
        let links: Vec<String> =
            map["evidence_links"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let rebuilt = build_content(&claim, &links)?;
        Ok(canonical_json(&rebuilt)? == canonical_json(content)?)
    })();
    match rebuilt {
        Err(EvidenceError::Value(message)) => return Err(bad(message)),
        Err(other) => return Err(other),
        Ok(false) => {
            return Err(bad(
                "it is not in the normal form the model writes (sorted unique codes and links, no empty subject or from_capture)".into(),
            ));
        }
        Ok(true) => {}
    }
    verify_content(content, evidence_id)
}

fn provenance(value: Option<&Value>) -> Result<Value> {
    match value {
        None | Some(Value::Null) => Ok(json!({})),
        Some(v @ Value::Object(_)) => {
            canonical_json(v)?;
            Ok(v.clone())
        }
        Some(_) => Err(EvidenceError::value("provenance is an object such as {view, sequence, generation}")),
    }
}

/// A record's volatile meta, validated: an object whose provenance, when present, is an object.
pub fn check_meta(meta: Option<&Value>) -> Result<Value> {
    let bad = |message: String| -> EvidenceError { EvidenceIntegrityError::new(message, "bundle_meta_invalid", "").into() };
    let meta = match meta {
        None | Some(Value::Null) => return Ok(json!({})),
        Some(m) => m,
    };
    let Value::Object(map) = meta else { return Err(bad("meta must be an object".into())) };
    for name in ["created", "client", "harness"] {
        if map.get(name).is_some_and(|v| !v.is_string()) {
            return Err(bad(format!("meta.{name} must be a string")));
        }
    }
    match provenance(map.get("provenance")) {
        Ok(_) => Ok(meta.clone()),
        Err(EvidenceError::Value(message)) => Err(bad(format!("meta.provenance: {message}"))),
        Err(other) => Err(other),
    }
}

// ---- the database -----------------------------------------------------------------------------------------------

fn is_busy(error: &rusqlite::Error) -> bool {
    match error {
        rusqlite::Error::SqliteFailure(e, message) => {
            matches!(e.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                || message.as_deref().is_some_and(|m| m.to_lowercase().contains("locked") || m.to_lowercase().contains("busy"))
        }
        _ => false,
    }
}

/// Switch an old (rollback-journal) ledger to WAL, retrying the switch until the busy deadline.
fn enter_wal(db: &Connection) -> Result<()> {
    let deadline = Instant::now() + Duration::from_millis(BUSY_TIMEOUT_MS);
    loop {
        let attempt = (|| -> rusqlite::Result<()> {
            let mode: String = db.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
            if mode.eq_ignore_ascii_case("wal") {
                return Ok(());
            }
            db.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))?;
            Ok(())
        })();
        match attempt {
            Ok(()) => return Ok(()),
            Err(error) if is_busy(&error) && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => return Err(error.into()),
        }
    }
}

fn present_columns(db: &Connection) -> rusqlite::Result<BTreeSet<String>> {
    let mut statement = db.prepare("PRAGMA table_info(claims)")?;
    let names = statement.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<BTreeSet<_>>>()?;
    Ok(names)
}

/// Open (creating and upgrading in place) the ledger at PATH: WAL mode, busy timeout, schema, v2 columns, indexes
/// and the backfill of rows that have no evidence id.
pub fn connect(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let db = Connection::open(path)?;
    db.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    enter_wal(&db)?;
    db.execute_batch(SCHEMA)?;
    let present = present_columns(&db)?;
    if COLUMNS.iter().any(|(name, _)| !present.contains(*name)) {
        // Writers that open an old ledger at once upgrade it one at a time.
        db.execute_batch("BEGIN IMMEDIATE")?;
        let outcome = (|| -> rusqlite::Result<()> {
            let present = present_columns(&db)?;
            for (column, declaration) in COLUMNS {
                if !present.contains(*column) {
                    db.execute_batch(&format!("ALTER TABLE claims ADD COLUMN {column} {declaration}"))?;
                }
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => db.execute_batch("COMMIT")?,
            Err(error) => {
                let _ = db.execute_batch("ROLLBACK");
                return Err(error.into());
            }
        }
    }
    db.execute_batch("CREATE INDEX IF NOT EXISTS claims_lookup ON claims (game, subsystem, build, address)")?;
    db.execute_batch("CREATE INDEX IF NOT EXISTS claims_evidence_id ON claims (evidence_id)")?;
    backfill(&db)?;
    Ok(db)
}

fn value_of(reference: ValueRef<'_>) -> Value {
    match reference {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number),
        ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::String(String::from_utf8_lossy(b).into_owned()),
    }
}

fn read_rows(db: &Connection, sql: &str, params: &[&dyn rusqlite::ToSql], fields: &[&str]) -> rusqlite::Result<Vec<Row>> {
    let mut statement = db.prepare(sql)?;
    let rows = statement.query_map(params, |r| {
        let mut row = Row::new();
        for (index, name) in fields.iter().enumerate() {
            row.insert((*name).to_string(), value_of(r.get_ref(index)?));
        }
        Ok(row)
    })?;
    rows.collect()
}

fn select_all(db: &Connection, sql_tail: &str, params: &[&dyn rusqlite::ToSql]) -> rusqlite::Result<Vec<Row>> {
    let sql = format!("SELECT {} FROM claims {sql_tail}", FIELDS.join(", "));
    read_rows(db, &sql, params, FIELDS)
}

fn json_dumps_sorted(value: &Value) -> String {
    let options = hy_core::json::Options { layout: hy_core::json::Layout::Spaced, sort_keys: true, ensure_ascii: true };
    String::from_utf8(hy_core::json::dumps(value, options)).unwrap_or_default()
}

fn json_dumps(value: &Value) -> String {
    let options = hy_core::json::Options { layout: hy_core::json::Layout::Spaced, sort_keys: false, ensure_ascii: true };
    String::from_utf8(hy_core::json::dumps(value, options)).unwrap_or_default()
}

fn in_transaction<T>(db: &Connection, body: impl FnOnce() -> Result<T>) -> Result<T> {
    db.execute_batch("BEGIN IMMEDIATE")?;
    match body() {
        Ok(value) => {
            db.execute_batch("COMMIT")?;
            Ok(value)
        }
        Err(error) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

/// Give every row without an id its v2 fields and its id. Cheap when there is nothing to do.
fn backfill(db: &Connection) -> Result<()> {
    let pending: Option<i64> =
        db.query_row("SELECT 1 FROM claims WHERE evidence_id IS NULL OR evidence_id = '' LIMIT 1", [], |r| r.get(0)).optional()?;
    if pending.is_none() {
        return Ok(());
    }
    in_transaction(db, || {
        // Another writer may have finished while this one waited for the lock.
        let rows = select_all(db, "WHERE evidence_id IS NULL OR evidence_id = '' ORDER BY id", &[])?;
        for row in rows {
            let loaded = loads(field(&row, "coverage"), Value::Null)?;
            let coverage = if truthy(&loaded) { loaded } else { normalize_coverage(None)? };
            let stored = loads(field(&row, "limitations"), Value::Null)?;
            let limitations = if truthy(&stored) { stored } else { json!(merge_limitations(&coverage, &[])?) };
            let mut links = loads(field(&row, "evidence_links"), Value::Null)?;
            if links.is_null() {
                links = json!([]);
                if let Some(old_id) = field(&row, "supersedes").as_i64() {
                    let old: Option<Option<String>> = db
                        .query_row("SELECT evidence_id FROM claims WHERE id = ?", [old_id], |r| r.get::<_, Option<String>>(0))
                        .optional()?;
                    if let Some(Some(evidence_id)) = old.filter(|o| o.as_deref().is_some_and(|s| !s.is_empty())) {
                        links = json!([evidence_id]);
                    }
                }
            }
            let pick = |name: &str, default: &str| -> String {
                if truthy(field(&row, name)) { py_str(field(&row, name)) } else { default.to_string() }
            };
            let coverage_text = json_dumps_sorted(&coverage);
            let limitations_text = json_dumps(&limitations);
            let parameters = pick("parameters", "{}");
            let confidence = pick("confidence", DEFAULT_CONFIDENCE);
            let authority = pick("authority", DEFAULT_AUTHORITY);
            let links_text = json_dumps(&links);
            let provenance_text = pick("provenance", "{}");
            let mut filled = row.clone();
            filled.insert("coverage".into(), json!(coverage_text));
            filled.insert("limitations".into(), json!(limitations_text));
            filled.insert("parameters".into(), json!(parameters));
            filled.insert("confidence".into(), json!(confidence));
            filled.insert("authority".into(), json!(authority));
            filled.insert("evidence_links".into(), json!(links_text));
            filled.insert("provenance".into(), json!(provenance_text));
            let content = content_of_row(&filled)?;
            let evidence_id = compute_evidence_id(&content)?;
            db.execute(
                "UPDATE claims SET coverage=?, limitations=?, parameters=?, confidence=?, authority=?, evidence_links=?, provenance=?, evidence_id=? WHERE id=?",
                rusqlite::params![coverage_text, limitations_text, parameters, confidence, authority, links_text, provenance_text, evidence_id, field(&row, "id").as_i64()],
            )?;
        }
        Ok(())
    })
}

/// The bookkeeping that is stored beside a claim's content (not part of its identity).
struct Stamp<'a> {
    created: &'a str,
    client: &'a str,
    harness: &'a str,
    provenance: &'a Value,
    supersedes: Option<i64>,
}

fn insert(db: &Connection, content: &Value, evidence_id: &str, stamp: &Stamp<'_>) -> Result<i64> {
    let Stamp { created, client, harness, provenance, supersedes } = *stamp;
    let text = |name: &str| content[name].as_str().unwrap_or_default().to_string();
    let subject = content["subject"].get("sha256").and_then(Value::as_str).unwrap_or_default().to_string();
    let from_capture = if truthy(&content["from_capture"]) { text("from_capture") } else { String::new() };
    let from_trace = match content.get("from_trace") {
        Some(t) if truthy(t) => json_dumps_sorted(t),
        _ => String::new(),
    };
    db.execute(
        "INSERT INTO claims (game, build, kind, name, address, prologue, note, source, created, subsystem, client, harness, supersedes, evidence_id, coverage, limitations, parameters, confidence, authority, subject_sha256, from_capture, evidence_links, provenance, from_trace) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            text("game"), text("build"), text("kind"), text("name"), text("address"), text("prologue"), text("note"), text("source"),
            created, text("subsystem"), client, harness, supersedes, evidence_id,
            json_dumps_sorted(&content["coverage"]), json_dumps(&content["limitations"]), json_dumps_sorted(&content["parameters"]),
            text("confidence"), text("authority"), subject, from_capture, json_dumps(&content["evidence_links"]),
            json_dumps_sorted(provenance), from_trace
        ],
    )?;
    Ok(db.last_insert_rowid())
}

/// Store one claim; returns the message Python's `add_claim` returns.
pub fn add_claim(path: &Path, claim: &Claim, ctx: &Ctx) -> Result<String> {
    build_content(claim, &[])?; // refuse a bad claim before a database is opened
    let prov = provenance(claim.provenance.as_ref())?;
    let (client, harness) = ctx.who();
    let db = connect(path)?;
    let supersedes = claim.supersedes;
    let (row_id, evidence_id) = match in_transaction(&db, || {
        // one transaction: the check, the new claim and the old one's link land together
        let mut links: Vec<String> = Vec::new();
        let mut old_superseded_by: Option<Option<i64>> = None;
        if let Some(target) = supersedes {
            let old: Option<(Option<i64>, Option<String>)> = db
                .query_row("SELECT superseded_by, evidence_id FROM claims WHERE id = ?", [target], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            let Some((superseded_by, old_evidence_id)) = old else {
                return Err(EvidenceError::value(format!("no claim {target} to supersede")));
            };
            links = vec![old_evidence_id.unwrap_or_else(|| "None".into())];
            old_superseded_by = Some(superseded_by);
        }
        let content = build_content(claim, &links)?;
        let evidence_id = compute_evidence_id(&content)?;
        let same: Option<i64> =
            db.query_row("SELECT id FROM claims WHERE evidence_id = ? ORDER BY id LIMIT 1", [&evidence_id], |r| r.get(0)).optional()?;
        if let Some(id) = same {
            // restating a stored claim is a no-op even when its predecessor is already superseded
            return Ok(Err(format!("claim {id} already stored {} {} {} evidence_id={evidence_id}", claim.game, claim.kind, claim.name)));
        }
        if let (Some(target), Some(Some(by))) = (supersedes, old_superseded_by) {
            return Err(EvidenceError::value(format!("claim {target} is already superseded by claim {by}")));
        }
        let row_id = insert(
            &db,
            &content,
            &evidence_id,
            &Stamp { created: &ctx.now(), client: &client, harness: &harness, provenance: &prov, supersedes },
        )?;
        if let Some(target) = supersedes {
            db.execute("UPDATE claims SET superseded_by = ? WHERE id = ?", [row_id, target])?;
        }
        Ok(Ok((row_id, evidence_id)))
    })? {
        Err(message) => return Ok(message),
        Ok(done) => done,
    };
    let tail = match supersedes {
        Some(n) if n != 0 => format!(" (supersedes {n})"),
        _ => String::new(),
    };
    Ok(format!("claim {row_id} stored {} {} {}{tail} evidence_id={evidence_id}", claim.game, claim.kind, claim.name))
}

/// A stored row as a dictionary with the JSON columns decoded.
pub fn decode_row(row: &Row) -> Value {
    let mut result = Map::new();
    for name in FIELDS {
        result.insert((*name).to_string(), field(row, name).clone());
    }
    for (key, default) in [
        ("coverage", Value::Null),
        ("limitations", Value::Null),
        ("parameters", json!({})),
        ("evidence_links", json!([])),
        ("provenance", json!({})),
    ] {
        let raw = result[key].clone();
        result.insert(key.to_string(), loads(&raw, default).unwrap_or_else(|_| json!({"unreadable": raw})));
    }
    let capture = result["from_capture"].clone();
    result.insert("from_capture".into(), if truthy(&capture) { capture } else { Value::Null });
    let trace = field(row, "from_trace");
    result.insert("from_trace".into(), if truthy(trace) { loads(trace, Value::Null).unwrap_or(Value::Null) } else { Value::Null });
    let subject = result["subject_sha256"].clone();
    result.insert("subject_sha256".into(), if truthy(&subject) { subject } else { Value::Null });
    Value::Object(result)
}

/// Recompute the id of a stored row and refuse it when it does not match.
pub fn verify_row(row: &Row) -> Result<()> {
    let row_id = field(row, "id").as_i64();
    let id_text = py_str(field(row, "id"));
    let stored = field(row, "evidence_id");
    let stored_text = if truthy(stored) { py_str(stored) } else { String::new() };
    let content = match content_of_row(row) {
        Ok(c) => c,
        Err(EvidenceError::Value(message)) => {
            let mut error = EvidenceIntegrityError::new(
                format!("claim {id_text} has a damaged evidence field ({message})"),
                "evidence_unreadable",
                stored_text,
            );
            error.row_id = row_id;
            return Err(error.into());
        }
        Err(other) => return Err(other),
    };
    let id_value = if truthy(stored) { stored.clone() } else { json!("") };
    match verify_content(&content, &id_value) {
        Err(EvidenceError::Integrity(inner)) => {
            let mut error = EvidenceIntegrityError::new(format!("claim {id_text}: {}", inner.message), &inner.code, inner.evidence_id);
            error.row_id = row_id;
            Err(error.into())
        }
        other => other,
    }
}

/// Row selection (`_select`).
#[derive(Debug, Clone)]
pub struct Filter {
    pub game: String,
    pub subsystem: String,
    pub address: String,
    pub build: String,
    pub include_superseded: bool,
    pub limit: i64,
    pub evidence_id: String,
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            game: String::new(),
            subsystem: String::new(),
            address: String::new(),
            build: String::new(),
            include_superseded: false,
            limit: 50,
            evidence_id: String::new(),
        }
    }
}

pub fn select_rows(path: &Path, filter: &Filter) -> Result<Vec<Row>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let mut clauses: Vec<String> = Vec::new();
    let mut args: Vec<String> = Vec::new();
    for (column, value) in [
        ("game", &filter.game),
        ("subsystem", &filter.subsystem),
        ("address", &filter.address),
        ("build", &filter.build),
        ("evidence_id", &filter.evidence_id),
    ] {
        if !value.is_empty() {
            clauses.push(format!("{column} = ?"));
            args.push(value.clone());
        }
    }
    if !filter.include_superseded {
        clauses.push("superseded_by IS NULL".into());
    }
    let mut tail = String::new();
    if !clauses.is_empty() {
        tail.push_str(&format!("WHERE {} ", clauses.join(" AND ")));
    }
    tail.push_str("ORDER BY id DESC LIMIT ?");
    let mut params: Vec<&dyn rusqlite::ToSql> = args.iter().map(|a| a as &dyn rusqlite::ToSql).collect();
    params.push(&filter.limit);
    let db = connect(path)?;
    Ok(select_all(&db, &tail, &params)?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verify {
    Off,
    On,
    Mark,
}

/// Rows newest first. Each is verified against its evidence_id; `Verify::Mark` flags instead of failing.
pub fn query(path: &Path, filter: &Filter, verify: Verify) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    for row in select_rows(path, filter)? {
        let mut item = decode_row(&row);
        if verify != Verify::Off {
            match verify_row(&row) {
                Ok(()) => {}
                Err(EvidenceError::Integrity(_)) if verify == Verify::Mark => {
                    item["integrity"] = json!("mismatch");
                }
                Err(error) => return Err(error),
            }
        }
        result.push(item);
    }
    Ok(result)
}

/// The oldest row with this evidence id, verified, or None.
pub fn get_claim(path: &Path, evidence_id: &str) -> Result<Option<Value>> {
    let filter = Filter { evidence_id: evidence_id.into(), include_superseded: true, limit: 1_000_000, ..Filter::default() };
    Ok(query(path, &filter, Verify::On)?.pop())
}

/// Recompute every id; the result lists each row that does not match instead of stopping at the first.
pub fn verify_ledger(path: &Path) -> Result<Value> {
    if !path.is_file() {
        return Ok(json!({"checked": 0, "failed": []}));
    }
    let db = connect(path)?;
    let rows = select_all(&db, "ORDER BY id", &[])?;
    drop(db);
    let mut failed = Vec::new();
    for row in &rows {
        match verify_row(row) {
            Ok(()) => {}
            Err(EvidenceError::Integrity(e)) => {
                failed
                    .push(json!({"id": field(row, "id"), "evidence_id": field(row, "evidence_id"), "code": e.code, "message": e.message}));
            }
            Err(other) => return Err(other),
        }
    }
    Ok(json!({"checked": rows.len(), "failed": failed}))
}

/// Every row of the selection (superseded ones too) as `{evidence_id, content, meta}`, verified, sorted by id.
pub fn records_for_bundle(path: &Path, game: &str, subsystem: &str, build: &str) -> Result<Vec<Value>> {
    let filter = Filter {
        game: game.into(),
        subsystem: subsystem.into(),
        build: build.into(),
        include_superseded: true,
        limit: 1_000_000,
        ..Filter::default()
    };
    let mut result: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for row in select_rows(path, &filter)?.into_iter().rev() {
        verify_row(&row)?;
        let meta = json!({
            "created": field(&row, "created"), "client": field(&row, "client"), "harness": field(&row, "harness"),
            "provenance": loads(field(&row, "provenance"), json!({}))?,
        });
        let key = py_str(field(&row, "evidence_id"));
        // The same claim stated twice (a legacy ledger) is one record; the earliest statement is its meta.
        result.entry(key).or_insert_with(
            || json!({"evidence_id": field(&row, "evidence_id"), "content": content_of_row(&row).unwrap_or(Value::Null), "meta": meta}),
        );
    }
    Ok(result.into_values().collect())
}

/// Store verified bundle records. Idempotent: a record whose id is present is skipped. All or nothing.
pub fn import_records(path: &Path, records: &[Value], ctx: &Ctx) -> Result<Value> {
    let mut by_id: std::collections::BTreeMap<String, &Value> = std::collections::BTreeMap::new();
    for record in records {
        let id = record.get("evidence_id").ok_or_else(|| EvidenceError::value("KeyError: 'evidence_id'"))?;
        let content = record.get("content").ok_or_else(|| EvidenceError::value("KeyError: 'content'"))?;
        check_content(content, id)?; // nothing reaches the ledger unvalidated
        check_meta(record.get("meta"))?;
        by_id.insert(py_str(id), record);
    }
    let db = connect(path)?;
    let (mut added, mut already, mut diverged, mut dangling) = (0u64, 0u64, 0u64, 0u64);
    in_transaction(&db, || {
        let mut local: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        let mut pending: Vec<String> = by_id.keys().cloned().collect();
        while !pending.is_empty() {
            let mut deferred = Vec::new();
            for evidence_id in &pending {
                let record = by_id[evidence_id];
                let links: Vec<String> = record["content"]["evidence_links"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                // A record whose superseded claim is in this bundle waits until that claim is stored.
                if links.iter().any(|l| by_id.contains_key(l) && !local.contains_key(l)) {
                    deferred.push(evidence_id.clone());
                    continue;
                }
                let present: Option<i64> = db
                    .query_row("SELECT id FROM claims WHERE evidence_id = ? ORDER BY id LIMIT 1", [evidence_id], |r| r.get(0))
                    .optional()?;
                if let Some(id) = present {
                    local.insert(evidence_id.clone(), id);
                    already += 1;
                    continue;
                }
                let mut old_id: Option<i64> = None;
                for link in &links {
                    if let Some(id) = local.get(link) {
                        old_id = Some(*id);
                    } else {
                        let old: Option<i64> = db
                            .query_row("SELECT id FROM claims WHERE evidence_id = ? ORDER BY id LIMIT 1", [link], |r| r.get(0))
                            .optional()?;
                        match old {
                            None => dangling += 1,
                            Some(id) => old_id = Some(id),
                        }
                    }
                }
                let meta = record.get("meta").filter(|m| m.is_object()).cloned().unwrap_or_else(|| json!({}));
                let text = |name: &str| meta.get(name).filter(|v| truthy(v)).map(py_str);
                let created = text("created").unwrap_or_else(|| ctx.now());
                let prov = provenance(meta.get("provenance"))?;
                let (client, harness) = (text("client").unwrap_or_default(), text("harness").unwrap_or_default());
                let stamp = Stamp { created: &created, client: &client, harness: &harness, provenance: &prov, supersedes: old_id };
                let row_id = insert(&db, &record["content"], evidence_id, &stamp)?;
                local.insert(evidence_id.clone(), row_id);
                added += 1;
                if let Some(old) = old_id {
                    let taken: Option<Option<i64>> =
                        db.query_row("SELECT superseded_by FROM claims WHERE id = ?", [old], |r| r.get(0)).optional()?;
                    match taken {
                        Some(None) => {
                            db.execute("UPDATE claims SET superseded_by = ? WHERE id = ?", [row_id, old])?;
                        }
                        Some(Some(by)) if by != row_id => diverged += 1,
                        _ => {}
                    }
                }
            }
            if deferred.len() == pending.len() {
                return Err(EvidenceIntegrityError::new("evidence_links form a cycle", "evidence_link_cycle", "").into());
            }
            pending = deferred;
        }
        Ok(())
    })?;
    Ok(json!({"added": added, "already_present": already, "history_diverged": diverged, "dangling_links": dangling}))
}

fn str_of(value: &Value) -> String {
    py_str(value)
}

/// The human listing (`list_claims`).
pub fn list_claims(path: &Path, game: &str, limit: i64, filter: &Filter) -> Result<String> {
    let filter = Filter { game: game.into(), limit, ..filter.clone() };
    let rows = query(path, &filter, Verify::Mark)?;
    if rows.is_empty() {
        return Ok("no claims yet".into());
    }
    let mut lines = Vec::new();
    for row in &rows {
        let coverage = if truthy(&row["coverage"]) { row["coverage"].clone() } else { json!({}) };
        let mut extra = String::new();
        if truthy(&row["subsystem"]) {
            extra.push_str(&format!(" subsystem={}", str_of(&row["subsystem"])));
        }
        if truthy(&row["supersedes"]) {
            extra.push_str(&format!(" supersedes=#{}", str_of(&row["supersedes"])));
        }
        if truthy(&row["superseded_by"]) {
            extra.push_str(&format!(" SUPERSEDED by #{}", str_of(&row["superseded_by"])));
        }
        if truthy(&row["client"]) {
            extra.push_str(&format!(" by={}/{}", str_of(&row["client"]), str_of(&row["harness"])));
        }
        let status = coverage.get("status").map_or_else(|| "?".to_string(), str_of);
        extra.push_str(&format!(" coverage={status}"));
        if truthy(&row["limitations"]) {
            let joined = match &row["limitations"] {
                Value::Array(a) => a.iter().map(str_of).collect::<Vec<_>>().join(","),
                Value::Object(o) => o.keys().cloned().collect::<Vec<_>>().join(","),
                other => str_of(other),
            };
            extra.push_str(&format!(" limitations={joined}"));
        }
        if row.get("integrity").is_some_and(truthy) {
            extra.push_str(" INTEGRITY FAILED: the row does not match its evidence_id");
        }
        lines.push(format!(
            "#{} {} {} {} {} addr={} prologue={}{}",
            str_of(&row["id"]),
            str_of(&row["game"]),
            str_of(&row["build"]),
            str_of(&row["kind"]),
            str_of(&row["name"]),
            str_of(&row["address"]),
            str_of(&row["prologue"]),
            extra
        ));
        lines.push(format!("  evidence_id: {}", str_of(&row["evidence_id"])));
        lines.push(format!("  note: {}", str_of(&row["note"])));
        lines.push(format!("  source: {}", str_of(&row["source"])));
    }
    Ok(lines.join("\n"))
}

fn cell(value: &Value) -> String {
    if !truthy(value) {
        return String::new();
    }
    str_of(value).replace('|', "\\|").replace('\n', " ")
}

/// One subsystem's claims as Markdown (current first, superseded after) plus JSONL.
pub fn export(path: &Path, out: &Path, game: &str, subsystem: &str) -> Result<Value> {
    let filter = Filter { game: game.into(), subsystem: subsystem.into(), include_superseded: true, limit: 1_000_000, ..Filter::default() };
    let rows = query(path, &filter, Verify::On)?;
    let (current, old): (Vec<&Value>, Vec<&Value>) = rows.iter().partition(|row| row["superseded_by"].is_null());
    hy_core::fsio::create_parent(out)?;
    let title = format!(
        "{}{}",
        if subsystem.is_empty() { "all subsystems" } else { subsystem },
        if game.is_empty() { String::new() } else { format!(" ({game})") }
    );
    let mut lines: Vec<String> = vec![
        format!("# Evidence: {title}"),
        String::new(),
        "Generated from the Hydralysis evidence ledger; every row cites its source.".into(),
        String::new(),
        "| # | build | kind | name | address | note | source | by | coverage | evidence_id |".into(),
        "|---|---|---|---|---|---|---|---|---|---|".into(),
    ];
    let mut sorted = current.clone();
    sorted.sort_by(|a, b| str_of(&a["address"]).cmp(&str_of(&b["address"])).then(a["id"].as_i64().cmp(&b["id"].as_i64())));
    for row in sorted {
        let first: Vec<String> =
            ["id", "build", "kind", "name", "address", "note", "source", "harness"].iter().map(|k| cell(&row[*k])).collect();
        let status = cell(row["coverage"].get("status").unwrap_or(&Value::Null));
        lines.push(format!("| {} | {} |", first.join(" | "), [status, cell(&row["evidence_id"])].join(" | ")));
    }
    if !old.is_empty() {
        lines.extend([
            "".into(),
            "## Superseded".into(),
            "".into(),
            "| # | build | name | address | superseded by |".into(),
            "|---|---|---|---|---|".into(),
        ]);
        for row in &old {
            let c: Vec<String> = ["id", "build", "name", "address", "superseded_by"].iter().map(|k| cell(&row[*k])).collect();
            lines.push(format!("| {} | {} | {} | {} | #{} |", c[0], c[1], c[2], c[3], c[4]));
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    // Python's write_text translates "\n" on Windows.
    let text = if cfg!(windows) { text.replace('\n', "\r\n") } else { text };
    std::fs::write(out, text)?;
    let jsonl = out.with_extension("jsonl");
    let mut data = Vec::new();
    for row in &rows {
        data.extend_from_slice(json_dumps(row).as_bytes());
        data.push(b'\n');
    }
    std::fs::write(&jsonl, data)?;
    Ok(
        json!({"markdown": out.display().to_string(), "jsonl": jsonl.display().to_string(), "current": current.len(), "superseded": old.len()}),
    )
}

/// Convenience for callers that hold a path as text.
pub fn path_of(text: &str) -> PathBuf {
    PathBuf::from(text)
}

/// The closed catalog of limitation codes: (code, does it bound what the claim covers, what it means).
pub const LIMITATIONS: &[(&str, bool, &str)] = &[
    ("coverage_unknown", true, "The writer did not say how much of the subject this claim covers."),
    (
        "event_ring_overflow",
        true,
        "The event ring keeps at most 1,000 events and 256 KiB; evicted events cannot be recovered (dropped_events counts them).",
    ),
    ("hit_limit_reached", true, "A probe stops recording at its hit limit (1 to 200); later hits are not recorded."),
    ("payload_clipped", true, "An oversized payload was clipped; only a prefix was captured."),
    ("sampled", true, "The probe reported a rate, minimum and maximum per window, not every call."),
    (
        "indirect_calls_unresolved",
        true,
        "Calls through a register or a table were not resolved; the callers and callees listed are those direct references.",
    ),
    (
        "decompile_truncated",
        true,
        "The decompile stopped at a size bound (truncated, reason, bytes_emitted); the rest of the function body was not emitted.",
    ),
    (
        "decompile_budget_limited",
        true,
        "The engine's adaptive response budget (no cap was named) stopped the decompile; only the front of the C text (cut, budget) was recovered. Ask again with max_result_mb for a larger bound.",
    ),
    ("decompile_paged", true, "This is one page of the C text (offset, next_offset); the text after next_offset was not read."),
    (
        "non_code_fragments",
        false,
        "Part of the function body is data or unclassified bytes (decompile fragments), not instructions; the C shows only the code fragments.",
    ),
    ("analysis_incomplete", true, "Analysis of the subject had not finished when this was read."),
    ("static_only", false, "Static analysis only: no process ran, so runtime behavior is not covered."),
    (
        "module_file_hash_only",
        false,
        "The check covers the module's backing file SHA-256 and the live bytes of the selected site, not the complete relocated image.",
    ),
    (
        "calling_convention_unproven",
        false,
        "A verified site does not prove a calling convention or that the function is semantically the intended one.",
    ),
    ("single_run", false, "One run of one scenario; other inputs or timing may behave differently."),
    ("fixture_only", false, "Observed on a synthetic fixture, not on the game."),
    ("volatile_state", false, "The value depends on process state that changes from run to run."),
    ("no_stack", false, "The event has no captured call stack, so it cannot be tied to a function."),
    ("not_code", false, "The captured address is not in executable code."),
    ("module_unknown", false, "The address belongs to no module the trace observed."),
    ("no_symbol", false, "The address is in a known module but resolves to no function in the program revision."),
    ("producer_lost", true, "A source stopped or jumped in its numbering without a gap record: events are missing."),
    ("ring_overflow", true, "A capture ring overflowed; the dropped count travelled out of band and the events are gone."),
    ("read_failure", true, "A non-faulting read of target memory failed; the value was not captured."),
    ("observer_inactive", true, "No observer was active over the interval, so absence of events is not coverage."),
    ("clock_uncalibrated", false, "Two clock domains were joined without a calibration, so their order is not comparable."),
    ("lifetime_unresolved", false, "The creation or retirement of an identity was not observed."),
    ("alignment_ambiguous", false, "A diff alignment matched more than one candidate; the match was not chosen silently."),
    ("budget_reached", true, "A query, explanation or check stopped at its event or byte budget; the rest was not read."),
    ("artifact_evicted", false, "A payload artifact the claim depends on was evicted by retention."),
    ("payload_not_authorized", false, "The payload bytes were not authorized for export, so the claim cannot be replayed from them."),
    ("etw_not_elevated", true, "ETW kernel providers were not consumed because the collector was not elevated."),
    ("optional_hook_refused", true, "An optional hook did not verify against the build and was disabled; its events are not captured."),
];
