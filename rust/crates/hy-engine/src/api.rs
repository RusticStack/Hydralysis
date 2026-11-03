//! The pure parts of `hydralysis/api.py`: the advertised catalog (tool table, epoch hash, instructions, the
//! `not_available` reply), the argument validation of `call`, and the shaping of the tool answers that need no engine.
//!
//! The tool table is `native/hydralysis-mcp/catalog.json`, which `tools/gen_mcp_catalog.py` writes from `api.py` (the
//! native MCP host answers `tools/list` from it); `tests/test_mcp_native.py` fails when it is stale. The tool handlers
//! themselves (PE reads, the engine, jobs, evidence) are not ported: they call modules that are other lanes' work.

use std::sync::OnceLock;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::failure::{Failure, Res};
use crate::pytext::{self, Dumps, py_int_value, py_strip};

const RAW_CATALOG: &str = include_str!("../../../../native/hydralysis-mcp/catalog.json");

/// The checked-in catalog (`catalog.json`).
pub struct Catalog {
    pub version: String,
    pub epoch: i64,
    pub hash: String,
    pub instructions: String,
    pub tool_names: Vec<String>,
    pub tools: Value,
}

/// The embedded catalog, parsed once.
pub fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let value: Value = serde_json::from_str(RAW_CATALOG).expect("catalog.json is valid JSON");
        let text = |key: &str| value[key].as_str().unwrap_or_default().to_string();
        Catalog {
            version: text("version"),
            epoch: value["epoch"].as_i64().unwrap_or(0),
            hash: text("hash"),
            instructions: text("instructions"),
            tool_names: value["tool_names"]
                .as_array()
                .map(|names| names.iter().filter_map(|n| n.as_str().map(str::to_string)).collect())
                .unwrap_or_default(),
            tools: value["tools"].clone(),
        }
    })
}

/// `api.catalog_hash(table)`: SHA-256 over the canonical JSON of the advertised tools
/// (`sort_keys`, `(",", ":")`, `ensure_ascii`).
pub fn catalog_hash(table: &Value) -> String {
    let canonical = pytext::dumps(table, Dumps::CanonicalAscii);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `api.catalog_hash()` of the table this build carries, computed once.
pub fn default_catalog_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| catalog_hash(&catalog().tools))
}

/// `api.tool_table()` as compact JSON text (the caller parses it into fresh dicts).
pub fn tool_table_json() -> &'static str {
    static TEXT: OnceLock<String> = OnceLock::new();
    TEXT.get_or_init(|| pytext::dumps(&catalog().tools, Dumps::CompactAscii))
}

/// `api.instructions()` for the package VERSION.
pub fn instructions(version: &str) -> String {
    format!(
        "Hydralysis {version}. Twenty-one tools for any PE you own. prepare adopts an analysed project in place, \
or imports/analyses a new executable exactly once as a durable job, and registers its build; \
backend discovers/installs the engines, never their MCPs. job reports progress. \
runtime manages verified debugging/instrumentation sessions. inspect is the function \
picture (bounds, prologue, instructions, callers) and does not start a JVM. \
sigscan and prologue are how a hook site is found and checked. ghidra_run \
runs one of your scripts contained, so it cannot change the project. \
Prefer ghidra_query for bounded address-based decompilation and references; \
one warm engine serves CLI, MCP and script clients; export writes bulk artifacts as a job. \
Addresses there are VAs or explicit rva:/va:. \
For PE addresses use rva:0x... or va:0x... when the interpretation is ambiguous. \
trace records and queries what a program did (cited, bounded, with coverage gaps); capture itself is runtime. \
Do not re-import the binary. evidence_add stores a claim only with a source."
    )
}

/// `api.not_available(capability, message, **detail)`: the reply of a carrier whose capability is not there yet.
/// EPOCH is `api.CATALOG_EPOCH`; the hash is that of the table in CATALOG_HASH.
pub fn not_available(capability: &str, message: &str, detail: &Map<String, Value>, epoch: i64, catalog_hash: &str) -> String {
    let mut reply = Map::new();
    reply.insert("not_available".into(), capability.into());
    reply.insert("message".into(), message.into());
    for (key, value) in detail {
        reply.insert(key.clone(), value.clone());
    }
    let mut entry = Map::new();
    entry.insert("epoch".into(), epoch.into());
    entry.insert("hash".into(), catalog_hash.into());
    reply.insert("catalog".into(), Value::Object(entry));
    pytext::dumps(&Value::Object(reply), Dumps::Indent2)
}

// ---- the head of `api.call` -------------------------------------------------------------------------------------

/// The backward-compatible terminal commands that are not MCP tools (`api.CLI_ONLY`).
pub const CLI_ONLY: [&str; 4] = ["sections", "exports", "ghidra_scripts", "ghidra_jobs"];

/// The `(key, maximum)` pairs `call` bounds before it looks at the tool (`limit`, `count`, `size`).
pub const BOUNDS: [(&str, i64); 3] = [("limit", 200), ("count", 200), ("size", 65536)];

/// `api.call`'s checks before dispatch: the arguments are an object, the tool exists, `limit`, `count` and `size` are in
/// range. ARGS is the JSON `null` for Python's `None`.
pub fn validate_call(name: &Value, args: &Value, tool_names: &[String]) -> Res<()> {
    let object = match args {
        Value::Null => None,
        Value::Object(map) => Some(map),
        _ => return Err(Failure::value("tool arguments must be an object")),
    };
    let Value::String(name) = name else {
        return Err(Failure::fallback("tool name is not a string"));
    };
    if !tool_names.iter().any(|known| known == name) && !CLI_ONLY.contains(&name.as_str()) {
        return Err(Failure::value(format!("unknown tool {name}")));
    }
    let Some(args) = object else {
        return Ok(());
    };
    for (key, maximum) in BOUNDS {
        let Some(value) = args.get(key) else {
            continue;
        };
        if matches!(value, Value::Bool(_)) {
            return Err(Failure::value(format!("{key} must be 1..{maximum}")));
        }
        let number = py_int_value(value)?;
        if !(1..=maximum).contains(&number) {
            return Err(Failure::value(format!("{key} must be 1..{maximum}")));
        }
    }
    Ok(())
}

// ---- shaping of tool answers ------------------------------------------------------------------------------------

/// `" ".join("%02X" % byte for byte in data)`.
pub fn hex_bytes_upper_spaced(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(data.len().saturating_mul(3));
    for (index, &byte) in data.iter().enumerate() {
        if index > 0 {
            out.push(b' ');
        }
        out.push(DIGITS[usize::from(byte >> 4)]);
        out.push(DIGITS[usize::from(byte & 15)]);
    }
    // only ASCII was pushed
    String::from_utf8(out).unwrap_or_default()
}

/// The `sha256` argument of `prologue`: a full hexadecimal build hash, returned lowercased.
pub fn prologue_sha256(value: &Value) -> Res<String> {
    match value {
        Value::String(text) if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(text.to_ascii_lowercase()),
        _ => Err(Failure::value("sha256 must be a full hexadecimal build hash")),
    }
}

/// The `image_base` argument of `prologue`: `int(str(value), 0)`.
pub fn prologue_image_base(value: &Value) -> Res<i128> {
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
        _ => return Err(Failure::fallback("image_base is not a string or integer")),
    };
    if text.contains('_') || !text.is_ascii() {
        return Err(Failure::fallback("underscore or non-ASCII digits in image_base"));
    }
    match hy_query::decompile::py_int0(&text) {
        Some(parsed) => Ok(parsed),
        None => match pytext::py_repr_simple(&text) {
            Some(shown) => Err(Failure::value(format!("invalid literal for int() with base 0: {shown}"))),
            None => Err(Failure::fallback("unusual image_base text")),
        },
    }
}

/// `evidence_list export`: the path is absolute and ends in `.md` (Windows path rules).
pub fn export_path_ok(path: &str) -> Res<bool> {
    let bytes = path.as_bytes();
    let is_sep = |b: u8| b == b'\\' || b == b'/';
    if bytes.len() >= 2 && is_sep(bytes[0]) && is_sep(bytes[1]) {
        return Err(Failure::fallback("UNC or device path"));
    }
    if path.contains('\0') || !path.is_ascii() {
        return Err(Failure::fallback("unusual export path"));
    }
    let absolute = bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && is_sep(bytes[2]);
    // a drive letter followed by anything else (`C:foo`) or a further colon is a shape pathlib treats specially
    if path[bytes.len().min(2)..].contains(':') {
        return Err(Failure::fallback("colon in export path"));
    }
    let name = path.rsplit(['\\', '/']).find(|part| !part.is_empty() && *part != ".").unwrap_or("");
    let name = if absolute && name.len() == 2 && name.ends_with(':') { "" } else { name };
    let suffix = match name.rfind('.') {
        Some(i) if 0 < i && i < name.len() - 1 => &name[i..],
        _ => "",
    };
    Ok(absolute && suffix == ".md")
}

/// The family of record a job id names (`api._workflow`, action `status`/`cancel`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    Export,
    Decompile,
    Overlay,
    Script,
    Install,
}

impl JobKind {
    pub fn name(self) -> &'static str {
        match self {
            JobKind::Export => "export",
            JobKind::Decompile => "decompile",
            JobKind::Overlay => "overlay",
            JobKind::Script => "script",
            JobKind::Install => "install",
        }
    }
}

/// Which store a job id belongs to, by its prefix. `cancel` knows no `decompile-` records: it treats them as installs.
pub fn job_kind(job_id: &str) -> JobKind {
    if job_id.starts_with("export-") {
        JobKind::Export
    } else if job_id.starts_with("decompile-") {
        JobKind::Decompile
    } else if job_id.starts_with("overlay-") {
        JobKind::Overlay
    } else if job_id.starts_with("job-") {
        JobKind::Script
    } else {
        JobKind::Install
    }
}

/// `re.fullmatch(r"job-[0-9a-f]{12}", job_id)`.
pub fn script_job_id_ok(job_id: &str) -> bool {
    job_id
        .strip_prefix("job-")
        .is_some_and(|rest| rest.len() == 12 && rest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

/// The projected fields of a job listing, in this order (`api._workflow`, job status without an id).
pub const JOB_FIELDS: [&str; 18] = [
    "id",
    "job_id",
    "kind",
    "component",
    "state",
    "stage",
    "target",
    "game",
    "script",
    "owner",
    "created_at",
    "started_at",
    "elapsed_s",
    "duration_s",
    "completed",
    "failed",
    "complete",
    "log_path",
];

/// The sort key of a job record: `created_at`, else `started_at`, else 0, as a number.
fn job_time(record: &Value) -> Res<f64> {
    let Some(value) = record.get("created_at").or_else(|| record.get("started_at")) else {
        return Ok(0.0);
    };
    match value {
        Value::Bool(b) => Ok(f64::from(u8::from(*b))),
        Value::Number(n) => match n.as_i64() {
            Some(i) if i.abs() <= 1 << 53 => Ok(i as f64),
            Some(_) => Err(Failure::fallback("timestamp beyond exact float range")),
            None => n.as_f64().ok_or_else(|| Failure::fallback("timestamp not a float")),
        },
        _ => Err(Failure::fallback("timestamp is not a number")),
    }
}

/// The answer of `job` without an id: the newest LIMIT records, projected onto [`JOB_FIELDS`], as the
/// `indent=2` JSON text the tool returns. RECORDS are the already collected job dicts, newest-first order not assumed.
pub fn job_listing(records: &[Value], limit: usize) -> Res<String> {
    let mut keyed: Vec<(f64, &Value)> = Vec::with_capacity(records.len());
    for record in records {
        if !record.is_object() {
            return Err(Failure::fallback("job record is not an object"));
        }
        keyed.push((job_time(record)?, record));
    }
    // reverse=True keeps the order of equal keys
    keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut jobs = Vec::new();
    for (_, record) in keyed.into_iter().take(limit) {
        let mut projected = Map::new();
        for field in JOB_FIELDS {
            if let Some(value) = record.get(field) {
                projected.insert(field.into(), value.clone());
            }
        }
        jobs.push(Value::Object(projected));
    }
    let mut answer = Map::new();
    answer.insert("jobs".into(), Value::Array(jobs));
    answer.insert("detail".into(), "Pass an id to job status for bounded logs and full metadata.".into());
    Ok(pytext::dumps(&Value::Object(answer), Dumps::Indent2))
}

/// `api._list`: None is `[]`, a string splits on whitespace, anything iterable becomes a list.
pub fn list_of(value: &Value) -> Res<Vec<Value>> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(text) => {
            Ok(text.split(pytext::is_py_space).filter(|part| !part.is_empty()).map(|part| Value::String(part.into())).collect())
        }
        Value::Array(items) => Ok(items.clone()),
        Value::Object(map) => Ok(map.keys().map(|key| Value::String(key.clone())).collect()),
        _ => Err(Failure::fallback("not iterable in a way this port models")),
    }
}

/// `api._options_bag`: the tool's `options` object, `{}` when absent; anything else is refused.
pub fn options_bag(args: &Map<String, Value>) -> Res<Map<String, Value>> {
    match args.get("options") {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(options)) => Ok(options.clone()),
        Some(_) => Err(Failure::value("options must be an object")),
    }
}

/// `api._script_options` up to the hand-off: what `ghidra_run options` validates before the capability is asked.
/// `Ok(true)` means "dispatch `scriptIsolation`", `Ok(false)` "run the script as before".
pub fn script_options_dispatch(options: &Value) -> Res<bool> {
    let map = match options {
        Value::Null => return Ok(false),
        Value::Object(map) => map,
        _ => return Err(Failure::value("options must be an object")),
    };
    if map.is_empty() {
        return Ok(false);
    }
    match map.get("isolation") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if matches!(s.as_str(), "private" | "shared" | "exclusive") => {}
        Some(Value::String(_)) => return Err(Failure::value("ghidra_run options.isolation must be private, shared or exclusive")),
        // a non-string compared against the three names: not equal, not in the tuple
        Some(_) => return Err(Failure::value("ghidra_run options.isolation must be private, shared or exclusive")),
    }
    if let Some(readonly) = map.get("readonly")
        && !readonly.is_boolean()
    {
        return Err(Failure::value("ghidra_run options.readonly must be a boolean"));
    }
    Ok(true)
}

/// `backend action=backups`: `options.op` is list, verify or remove (default list).
pub fn backups_op(options: &Map<String, Value>) -> Res<String> {
    match options.get("op") {
        None => Ok("list".into()),
        Some(Value::String(op)) if matches!(op.as_str(), "list" | "verify" | "remove") => Ok(op.clone()),
        Some(Value::String(_)) => Err(Failure::value("backups options.op must be list, verify or remove")),
        Some(_) => Err(Failure::value("backups options.op must be list, verify or remove")),
    }
}

// ---- addresses --------------------------------------------------------------------------------------------------

/// What `api._addr` makes of an address text before it asks the image which RVAs are mapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// `name:` or `hash:` text: the address-map lookup (settings, files) decides.
    Mapped,
    /// A parsed address: its RVA, and for an unprefixed text the integer it spelled (the VA/RVA ambiguity check).
    Parsed { rva: i64, bare: Option<i128> },
}

/// The first half of `api._addr` for the text `str(args["address"])` and the image BASE.
pub fn parse_address(text: &str, base: u64) -> Res<Address> {
    let text = py_strip(text);
    if text.starts_with("name:") || text.starts_with("hash:") {
        return Ok(Address::Mapped);
    }
    // `int(text, 0)` also takes PEP 515 underscores after a prefix and any Unicode decimal digit; hy-query's reading of those
    // differs, so the original decides
    if text.contains('_') || !text.is_ascii() {
        return Err(Failure::fallback("underscore or non-ASCII digits in an address"));
    }
    let rva = hy_query::prologue::parse_rva(text, base).map_err(|e| match e {
        hy_query::PeError::Value(message) => Failure::value(message),
        other => Failure::fallback(format!("{other:?}")),
    })?;
    let bare = if text.contains(':') {
        None
    } else {
        Some(hy_query::decompile::py_int0(text).ok_or_else(|| Failure::fallback("int(text, 0) after parse_rva"))?)
    };
    Ok(Address::Parsed { rva, bare })
}

/// The refusal of an unprefixed address that is both a mapped RVA and a mapped VA.
pub fn ambiguous_address(text: &str, value: i128, rva: i64) -> String {
    let text = py_strip(text);
    format!("ambiguous address {text}: RVA {value:#x} and VA {value:#x} (RVA {rva:#x}) both map to this image; use rva:{text} or va:{text}")
}
