//! Port of `hydralysis/analysis.py::validate_options` (the compact advanced-query options).
//!
//! Everything that is pure validation is native. The branches that touch the file system or Python's `re`
//! (`diff`, batch `file`, `import_types`, `import_archive`, `scan regex`) return [`Invalid::Fallback`]; the Python
//! caller then runs its own implementation, so behaviour is unchanged there.

use serde_json::{Map, Value, json};

#[derive(Debug, PartialEq, Eq)]
pub enum Invalid {
    /// The exact `ValueError` message.
    Value(String),
    /// This input needs the Python implementation (file system, Python regex).
    Fallback,
}

type Res<T> = Result<T, Invalid>;

fn bad<T>(msg: impl Into<String>) -> Res<T> {
    Err(Invalid::Value(msg.into()))
}

const MAX_OVERLAYS: usize = 4096;
const MAX_BATCH_BYTES: usize = 256 * 1024;
const MAX_BATCH_EDITS: usize = 200;
const MAX_RESULT_MB: i128 = 1024;
const MAX_RESULT_KB: i128 = 1_048_576;
const TYPE_KINDS: [&str; 12] = [
    "struct",
    "signature",
    "variable",
    "apply",
    "rename",
    "label",
    "comment",
    "function_create",
    "function_body",
    "function_delete",
    "batch",
    "import_types",
];
const BATCH_PROVENANCE: [&str; 3] = ["input_file", "input_file_sha256", "input_file_bytes"];

fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

fn is_addr(s: &str) -> bool {
    // `(?:0x)?[0-9a-fA-F]+` fullmatch
    let hex = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_hexdigit());
    hex(s) || s.strip_prefix("0x").is_some_and(hex)
}

fn text(v: Option<&Value>, name: &str, maximum: usize, required: bool) -> Res<String> {
    match v {
        Some(Value::String(s)) if s.chars().count() <= maximum && !s.contains('\0') => {
            if required && s.chars().all(py_space) {
                return bad(format!("{name} is required"));
            }
            Ok(s.clone())
        }
        _ => bad(format!(
            "{name} must be text of at most {maximum} characters"
        )),
    }
}

fn integer(v: Option<&Value>, name: &str, low: i128, high: i128) -> Res<i64> {
    if let Some(Value::Number(n)) = v {
        let value = n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from));
        if let Some(x) = value
            && low <= x
            && x <= high
        {
            return Ok(x as i64);
        }
    }
    bad(format!("{name} must be an integer in {low}..{high}"))
}

fn is_bool(v: &Value) -> bool {
    v.is_boolean()
}

fn sha_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn digest(v: Option<&Value>) -> Res<String> {
    match v {
        Some(Value::String(s)) if sha_ok(s) => Ok(s.to_lowercase()),
        _ => bad("overlay requires a full SHA-256"),
    }
}

/// `str(value)` of the JSON types an address option may arrive as (None when it cannot be an address).
fn str_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        other => format!("{other}"),
    }
}

fn keys_outside(obj: &Map<String, Value>, allowed: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = obj
        .keys()
        .filter(|k| !allowed.contains(&k.as_str()))
        .cloned()
        .collect();
    v.sort();
    v
}

fn offset_ok(s: &str) -> bool {
    if let Some(h) = s.strip_prefix("0x") {
        return (1..=6).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit());
    }
    (1..=7).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

/// Python `json.dumps(value, ensure_ascii=False)` (default separators), for the 256 KiB batch bound.
pub(crate) fn py_dumps(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\u{8}' => out.push_str("\\b"),
                    '\u{c}' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                py_dumps(x, out);
            }
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, x)) in o.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                py_dumps(&Value::String(k.clone()), out);
                out.push_str(": ");
                py_dumps(x, out);
            }
            out.push('}');
        }
    }
}

/// `json.dumps(value, ensure_ascii=False)` as a new string.
pub fn py_dumps_string(v: &Value) -> String {
    let mut s = String::new();
    py_dumps(v, &mut s);
    s
}

fn allowed_for(action: &str, record: bool) -> Option<Vec<&'static str>> {
    let mut v: Vec<&'static str> = match action {
        "decompile" => vec!["max_characters", "max_result_mb", "max_result_kb", "offset"],
        "data" => vec!["table"],
        "scan" => vec!["end", "mnemonic", "operand", "regex"],
        "status" => vec!["show", "since", "state"],
        "types" | "variables" | "dossier" | "blocks" | "vtables" => vec![],
        "type" => vec!["path"],
        "pcode" => vec!["nodes"],
        "diff" => vec!["against", "against_view", "checks"],
        "vcalls" => vec![
            "offset",
            "receiver_from",
            "receiver_type",
            "receiver_global",
            "vtable",
        ],
        "writes" => vec!["offset", "receiver_type"],
        "orphans" => vec!["referenced_only"],
        "trace" => vec![
            "seed",
            "direction",
            "depth",
            "nodes",
            "functions",
            "argument",
            "brief",
            "callers",
            "debug",
        ],
        "type_edit" => {
            let mut b = vec![
                "kind",
                "source",
                "path",
                "size",
                "fields",
                "prototype",
                "variable",
                "type",
                "name",
                "comment",
                "expect",
                "ranges",
                "edits",
                "file",
                "expect_revision",
                "ids",
                "cascade",
                "corpus",
                "category",
                "archive",
                "paths",
            ];
            if record {
                b.extend(BATCH_PROVENANCE);
                b.extend([
                    "corpus_sha256",
                    "corpus_bytes",
                    "corpus_input",
                    "archive_sha256",
                    "archive_bytes",
                ]);
            }
            b
        }
        _ => return None,
    };
    v.shrink_to_fit();
    Some(v)
}

/// `validate_options(action, options, _record=record)`. `options` is None or an object (checked by the caller).
pub fn validate_options(
    action: &str,
    options: Option<&Map<String, Value>>,
    record: bool,
) -> Res<Value> {
    let empty = Map::new();
    let options = options.unwrap_or(&empty);
    let Some(allowed) = allowed_for(action, record) else {
        if !options.is_empty() {
            return bad(format!("options are not supported for {action}"));
        }
        return Ok(json!({}));
    };
    let unknown = keys_outside(options, &allowed);
    if !unknown.is_empty() {
        return bad(format!("unknown {action} options: {}", unknown.join(", ")));
    }
    let mut out = options.clone();
    match action {
        "decompile" => {
            let v = integer(
                Some(out.get("max_characters").unwrap_or(&json!(32000))),
                "max_characters",
                1,
                2_097_152,
            )?;
            out.insert("max_characters".into(), json!(v));
            if out.contains_key("max_result_mb") {
                let v = integer(out.get("max_result_mb"), "max_result_mb", 1, MAX_RESULT_MB)?;
                out.insert("max_result_mb".into(), json!(v));
            }
            if out.contains_key("max_result_kb") {
                let v = integer(out.get("max_result_kb"), "max_result_kb", 1, MAX_RESULT_KB)?;
                out.insert("max_result_kb".into(), json!(v));
            }
            if out.contains_key("offset") {
                let v = integer(out.get("offset"), "offset", 0, (1 << 31) - 1)?;
                out.insert("offset".into(), json!(v));
            }
        }
        "data" => {
            if out.get("table").is_some_and(|t| !is_bool(t)) {
                return bad("data table must be a boolean");
            }
        }
        "scan" => {
            if out.contains_key("end") {
                let v = text(out.get("end"), "scan end", 128, true)?;
                if !is_addr(&v) {
                    return bad("scan end must be a numeric Ghidra VA");
                }
            }
            for name in ["mnemonic", "operand"] {
                if out.contains_key(name) {
                    let v = text(out.get(name), &format!("scan {name}"), 256, false)?;
                    out.insert(name.into(), json!(v));
                }
            }
            if out.contains_key("regex") {
                let v = text(out.get("regex"), "scan regex", 256, true)?;
                out.insert("regex".into(), json!(v));
                return Err(Invalid::Fallback); // Python `re` decides whether it compiles (and words the error)
            }
        }
        "orphans" => {
            if out.get("referenced_only").is_some_and(|t| !is_bool(t)) {
                return bad("orphans referenced_only must be a boolean");
            }
        }
        "vcalls" | "writes" => {
            let offset = text(
                Some(out.get("offset").unwrap_or(&json!(""))),
                "offset",
                32,
                true,
            )?;
            if !offset_ok(&offset) {
                return bad("vcalls offset is the slot's byte offset, such as 0xc0");
            }
            for name in ["receiver_from", "receiver_global", "vtable"] {
                if let Some(v) = out.get(name) {
                    let s = str_of(v);
                    let s = s.strip_prefix("rva:").unwrap_or(&s);
                    let s = s.strip_prefix("va:").unwrap_or(s);
                    if !is_addr(s) {
                        return bad(format!("{name} must be an address"));
                    }
                }
            }
            if out.contains_key("receiver_type") {
                let v = text(out.get("receiver_type"), "receiver_type", 256, true)?;
                out.insert("receiver_type".into(), json!(v));
            }
        }
        "diff" => return Err(Invalid::Fallback),
        "type" => {
            if out.contains_key("path") {
                let v = text(out.get("path"), "path", 512, true)?;
                out.insert("path".into(), json!(v));
            }
        }
        "pcode" | "trace" => {
            let v = integer(
                Some(out.get("nodes").unwrap_or(&json!(80))),
                "nodes",
                1,
                200,
            )?;
            out.insert("nodes".into(), json!(v));
            if action == "trace" {
                let seed = text(
                    Some(out.get("seed").unwrap_or(&json!(""))),
                    "seed",
                    512,
                    false,
                )?;
                out.insert("seed".into(), json!(seed));
                let direction = out
                    .get("direction")
                    .cloned()
                    .unwrap_or_else(|| json!("backward"));
                if direction != json!("backward") && direction != json!("forward") {
                    return bad("direction must be backward or forward");
                }
                out.insert("direction".into(), direction);
                for (name, default, lo, hi) in [
                    ("depth", 5, 1, 32),
                    ("functions", 1, 1, 8),
                    ("callers", 0, 0, 4),
                ] {
                    let v = integer(Some(out.get(name).unwrap_or(&json!(default))), name, lo, hi)?;
                    out.insert(name.into(), json!(v));
                }
                if out.contains_key("argument") {
                    let v = integer(out.get("argument"), "argument", 0, 15)?;
                    out.insert("argument".into(), json!(v));
                }
                if out.get("brief").is_some_and(|t| !is_bool(t)) {
                    return bad("brief must be a boolean");
                }
            }
        }
        "status" => {
            if out.get("show").is_some_and(|s| s != &json!("changes")) {
                return bad("status show must be changes");
            }
            if (out.contains_key("since") || out.contains_key("state"))
                && out.get("show") != Some(&json!("changes"))
            {
                return bad("status since and state belong to show=changes");
            }
            if out.contains_key("since") {
                integer(out.get("since"), "since", 0, 1 << 31)?;
            }
            if let Some(s) = out.get("state")
                && !["pending", "committed", "all"]
                    .iter()
                    .any(|k| s == &json!(k))
            {
                return bad("status state must be pending, committed or all");
            }
        }
        "type_edit" => return type_edit(out, record),
        _ => {}
    }
    Ok(Value::Object(out))
}

fn type_edit(mut out: Map<String, Value>, record: bool) -> Res<Value> {
    let kind = out.get("kind").cloned();
    if out.contains_key("expect_revision") {
        integer(out.get("expect_revision"), "expect_revision", 0, 1 << 31)?;
    }
    if kind == Some(json!("revert")) {
        if !keys_outside(
            &out,
            &["kind", "ids", "expect_revision", "source", "cascade"],
        )
        .is_empty()
        {
            return bad(
                "revert takes ids (overlay or batch ids), optional expect_revision and cascade",
            );
        }
        if out.get("cascade").is_some_and(|t| !is_bool(t)) {
            return bad("cascade must be a boolean");
        }
        let ok = match out.get("ids") {
            Some(Value::Array(ids)) => {
                (1..=MAX_OVERLAYS).contains(&ids.len())
                    && ids.iter().all(|i| {
                        i.as_str().is_some_and(|s| {
                            s.len() == 32
                                && s.bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        })
                    })
            }
            _ => false,
        };
        if !ok {
            return bad(format!(
                "revert ids must be 1..{MAX_OVERLAYS} overlay or batch ids"
            ));
        }
        return Ok(Value::Object(out));
    }
    if matches!(kind, Some(Value::Array(_) | Value::Object(_))) {
        return Err(Invalid::Fallback); // Python raises TypeError (unhashable) here; keep that behaviour
    }
    let kind_s = match &kind {
        Some(Value::String(s)) if TYPE_KINDS.contains(&s.as_str()) || s == "import_archive" => {
            s.clone()
        }
        _ => return bad("unknown type_edit kind"),
    };
    let kind_fields: Vec<&str> = match kind_s.as_str() {
        "struct" => vec!["path", "size", "fields"],
        "signature" => vec!["prototype"],
        "variable" => vec!["variable", "type", "name"],
        "apply" => vec!["type"],
        "rename" | "label" => vec!["name"],
        "comment" => vec!["comment"],
        "function_create" | "function_body" => vec!["expect", "ranges", "name"],
        "function_delete" => vec!["expect"],
        "batch" => {
            let mut b = vec!["edits", "file"];
            if record {
                b.extend(BATCH_PROVENANCE);
            }
            b
        }
        "import_types" | "import_archive" => return Err(Invalid::Fallback),
        _ => unreachable!(),
    };
    let mut allowed: Vec<&str> = vec!["kind", "source", "expect_revision"];
    allowed.extend(&kind_fields);
    if !keys_outside(&out, &allowed).is_empty() {
        return bad(format!("options do not belong to type_edit kind {kind_s}"));
    }
    let source = text(
        Some(out.get("source").unwrap_or(&json!(""))),
        "source",
        4096,
        true,
    )?;
    out.insert("source".into(), json!(source));
    if kind_s == "batch" {
        return batch(&out, record);
    }
    let required: &[&str] = match kind_s.as_str() {
        "struct" => &["path"],
        "signature" => &["prototype"],
        "variable" => &["variable", "type"],
        "apply" => &["type"],
        "rename" | "label" => &["name"],
        "comment" => &["comment"],
        _ => &[],
    };
    for name in ["path", "prototype", "variable", "type", "name", "comment"] {
        if out.contains_key(name) || required.contains(&name) {
            let max = if name == "prototype" || name == "comment" {
                8192
            } else {
                512
            };
            let v = text(
                Some(out.get(name).unwrap_or(&json!(""))),
                name,
                max,
                required.contains(&name),
            )?;
            out.insert(name.into(), json!(v));
        }
    }
    if kind_s == "struct" {
        let path = out["path"].as_str().unwrap_or("").to_string();
        if !path.starts_with('/') || path.ends_with('/') {
            return bad("struct path must be an absolute category/type path");
        }
        let size = integer(out.get("size"), "size", 1, 1024 * 1024)?;
        out.insert("size".into(), json!(size));
        let fields = match out.get("fields") {
            None => Vec::new(),
            Some(Value::Array(a)) if a.len() <= 64 => a.clone(),
            _ => return bad("fields must be an array of at most 64 components"),
        };
        let mut clean_fields = Vec::new();
        let mut names = std::collections::HashSet::new();
        for field in &fields {
            let Some(f) = field
                .as_object()
                .filter(|f| keys_outside(f, &["offset", "type", "name", "length"]).is_empty())
            else {
                return bad("each field accepts offset, type, name and optional length");
            };
            let offset = integer(f.get("offset"), "field offset", 0, i128::from(size) - 1)?;
            let mut clean = Map::new();
            clean.insert("offset".into(), json!(offset));
            clean.insert(
                "type".into(),
                json!(text(
                    Some(f.get("type").unwrap_or(&json!(""))),
                    "field type",
                    512,
                    true
                )?),
            );
            let name = text(
                Some(f.get("name").unwrap_or(&json!(""))),
                "field name",
                512,
                true,
            )?;
            clean.insert("name".into(), json!(name));
            if f.contains_key("length") {
                let l = integer(
                    f.get("length"),
                    "field length",
                    1,
                    i128::from(size) - i128::from(offset),
                )?;
                clean.insert("length".into(), json!(l));
            }
            if !names.insert(name) {
                return bad("structure fields must have unique names");
            }
            clean_fields.push(Value::Object(clean));
        }
        out.insert("fields".into(), Value::Array(clean_fields));
    }
    if kind_s.starts_with("function_") {
        let expect = text(
            Some(out.get("expect").unwrap_or(&json!(""))),
            "expect",
            192,
            true,
        )?;
        let bytes: Vec<&str> = expect.split_whitespace().collect();
        if !(1..=64).contains(&bytes.len())
            || bytes
                .iter()
                .any(|b| !(b.len() == 2 && b.bytes().all(|c| c.is_ascii_hexdigit())))
        {
            return bad("function edits require 1..64 exact expected bytes; wildcards are refused");
        }
        out.insert(
            "expect".into(),
            json!(
                bytes
                    .iter()
                    .map(|b| b.to_uppercase())
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        );
        if kind_s != "function_delete" {
            let ranges = match out.get("ranges") {
                Some(Value::Array(r)) if (1..=64).contains(&r.len()) => r.clone(),
                _ => return bad("function ranges must contain 1..64 inclusive VA ranges"),
            };
            let mut clean = Vec::new();
            let mut occupied: Vec<(u128, u128)> = Vec::new();
            for item in &ranges {
                let Some(o) = item
                    .as_object()
                    .filter(|o| o.len() == 2 && o.contains_key("start") && o.contains_key("end"))
                else {
                    return bad("each function range requires start and end VAs");
                };
                let mut parsed = [0u128; 2];
                for (i, key) in ["start", "end"].iter().enumerate() {
                    let v = text(o.get(*key), &format!("range {key}"), 128, true)?;
                    if !is_addr(&v) {
                        return bad("range addresses must be numeric Ghidra VAs");
                    }
                    parsed[i] = u128::from_str_radix(v.strip_prefix("0x").unwrap_or(&v), 16)
                        .map_err(|_| Invalid::Fallback)?;
                }
                let [start, end] = parsed;
                if end < start || occupied.iter().any(|&(ps, pe)| start <= pe && end >= ps) {
                    return bad("function ranges must be ordered and non-overlapping");
                }
                occupied.push((start, end));
                clean.push(json!({"start": format!("{start:#x}"), "end": format!("{end:#x}")}));
            }
            out.insert("ranges".into(), Value::Array(clean));
        }
    }
    Ok(Value::Object(out))
}

fn batch(value: &Map<String, Value>, recorded: bool) -> Res<Value> {
    if value.contains_key("edits") == value.contains_key("file") {
        return bad("batch requires exactly one of edits or file");
    }
    if value.contains_key("file") {
        return Err(Invalid::Fallback); // reads the file
    }
    let source = value["source"].clone();
    let mut result = Map::new();
    result.insert("kind".into(), json!("batch"));
    result.insert("source".into(), source.clone());
    let edits = value["edits"].clone();
    if !recorded {
        let mut s = String::new();
        py_dumps(&edits, &mut s);
        if s.len() > MAX_BATCH_BYTES {
            return bad("batch input exceeds 256 KiB");
        }
    }
    let present: Vec<&str> = BATCH_PROVENANCE
        .iter()
        .copied()
        .filter(|k| value.contains_key(*k))
        .collect();
    if !present.is_empty() {
        if !recorded || present.len() != BATCH_PROVENANCE.len() {
            return bad("batch provenance must be a complete normalized record");
        }
        result.insert(
            "input_file".into(),
            json!(text(value.get("input_file"), "input_file", 32768, true)?),
        );
        result.insert(
            "input_file_sha256".into(),
            json!(digest(value.get("input_file_sha256"))?),
        );
        result.insert(
            "input_file_bytes".into(),
            json!(integer(
                value.get("input_file_bytes"),
                "input_file_bytes",
                1,
                MAX_BATCH_BYTES as i128
            )?),
        );
    }
    let list = match &edits {
        Value::Array(a) if (1..=MAX_BATCH_EDITS).contains(&a.len()) => a,
        _ => return bad("batch must contain 1..200 edits"),
    };
    let mut clean = Vec::new();
    for (index, item) in list.iter().enumerate() {
        let Some(o) = item.as_object().filter(|o| {
            keys_outside(o, &["address", "options"]).is_empty() && o.contains_key("options")
        }) else {
            return bad(format!("batch edit {index} requires address and options"));
        };
        let Some(child) = o["options"]
            .as_object()
            .filter(|c| c.get("kind") != Some(&json!("batch")))
        else {
            return bad("nested batches are refused");
        };
        let mut merged = Map::new();
        merged.insert("source".into(), source.clone());
        for (k, v) in child {
            merged.insert(k.clone(), v.clone());
        }
        let child = validate_options("type_edit", Some(&merged), recorded)?;
        let address = text(
            Some(o.get("address").unwrap_or(&json!(""))),
            "batch address",
            128,
            false,
        )?;
        if !address.is_empty() && !is_addr(&address) {
            return bad("batch addresses must be numeric Ghidra VAs");
        }
        if child["kind"] != json!("struct") && address.is_empty() {
            return bad(format!("batch edit {index} requires a Ghidra VA"));
        }
        clean.push(json!({"address": address, "options": child}));
    }
    result.insert("edits".into(), Value::Array(clean));
    Ok(Value::Object(result))
}
