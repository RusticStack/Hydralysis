//! `hydralysis/address_maps.py`: validation and normalisation of a source-cited name/hash to RVA map.
//!
//! The file system parts (the lock, the stored record, the directory listing, `Path.resolve`) stay in Python; this is the
//! per-row loop, which costs up to 100000 iterations of regex matches and conversions.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::failure::{Failure, Res};
use crate::pytext::{self, Dumps, py_strip};

/// The most bytes read from the source file (`address_maps.MAX_BYTES`).
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
/// The most rows of one map (`address_maps.MAX_ROWS`).
pub const MAX_ROWS: usize = 100_000;
/// The most bytes of the normalised record, as `json.dumps(record, indent=2)` writes it.
pub const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;

/// The build digest must be 64 lowercase hexadecimal digits (`re.fullmatch(r"[0-9a-f]{64}", digest)`).
pub fn digest_ok(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `address_maps._record_hash`: SHA-256 of the record without `record_sha256`, `sort_keys` and compact separators.
pub fn record_hash(record: &Map<String, Value>) -> String {
    let data: Map<String, Value> =
        record.iter().filter(|(key, _)| key.as_str() != "record_sha256").map(|(k, v)| (k.clone(), v.clone())).collect();
    let text = pytext::dumps_with(&Value::Object(data), pytext::Layout::Compact, true, false);
    sha256_hex(text.as_bytes())
}

/// `_HASH`: `0x` and 1 to 32 hexadecimal digits; the digits.
fn hash_digits(text: &str) -> Option<&str> {
    let digits = text.strip_prefix("0x")?;
    ((1..=32).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_hexdigit())).then_some(digits)
}

/// `_RVA`: optional `rva:`, `0x` and 1 to 8 hexadecimal digits; the digits.
fn rva_digits(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("rva:").unwrap_or(text);
    let digits = rest.strip_prefix("0x")?;
    ((1..=8).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_hexdigit())).then_some(digits)
}

/// A cited source: text, not blank, at most 4096 characters.
fn source_ok(value: &Value) -> Option<&str> {
    match value {
        Value::String(text) if !py_strip(text).is_empty() && text.chars().count() <= 4096 => Some(text),
        _ => None,
    }
}

/// The result of [`normalise`].
#[derive(Debug)]
pub struct Normalised {
    /// `hashlib.sha256(raw).hexdigest()`.
    pub map_sha256: String,
    pub entries: usize,
    /// The record that is stored, `record_sha256` included.
    pub record: Map<String, Value>,
}

/// `address_maps.import_map` up to the write: validate RAW (the file's bytes) against DIGEST and build the stored record.
/// FILE is `str(Path(path).resolve())`.
pub fn normalise(raw: &[u8], digest: &str, file: &str) -> Res<Normalised> {
    if !digest_ok(digest) {
        return Err(Failure::value("address map requires the full build SHA-256"));
    }
    if raw.len() > MAX_BYTES {
        return Err(Failure::value("address map exceeds 16 MiB"));
    }
    // `json.loads(bytes)` sniffs UTF-16/32 and a BOM; only plain UTF-8 is modelled
    if raw.starts_with(&[0xff, 0xfe]) || raw.starts_with(&[0xfe, 0xff]) || raw.iter().take(4).any(|&b| b == 0) {
        return Err(Failure::fallback("not plain UTF-8 JSON"));
    }
    let body = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw);
    let Ok(text) = std::str::from_utf8(body) else {
        return Err(Failure::value("address map must be UTF-8 JSON"));
    };
    let value = pytext::parse_json(text)?;
    let Value::Object(map) = &value else {
        return Err(Failure::value("address map takes sha256, source and entries"));
    };
    if map.keys().any(|key| !matches!(key.as_str(), "sha256" | "source" | "entries")) {
        return Err(Failure::value("address map takes sha256, source and entries"));
    }
    // `str(value.get("sha256", "")).lower() != digest`
    match map.get("sha256") {
        Some(Value::String(found)) if found.to_lowercase() == digest => {}
        None | Some(Value::String(_)) => return Err(Failure::value("address map build SHA-256 mismatch")),
        Some(_) => return Err(Failure::fallback("sha256 is not text")),
    }
    let Some(source) = map.get("source").and_then(source_ok) else {
        return Err(Failure::value("address map requires a cited source"));
    };
    let entries = match map.get("entries") {
        Some(Value::Array(rows)) if (1..=MAX_ROWS).contains(&rows.len()) => rows,
        _ => return Err(Failure::value("address map requires 1..100000 entries")),
    };
    let mut cleaned = Vec::with_capacity(entries.len());
    for row in entries {
        let Value::Object(row) = row else {
            return Err(Failure::value("address map entries take name, hash, rva and optional source"));
        };
        if row.keys().any(|key| !matches!(key.as_str(), "name" | "hash" | "rva" | "source")) {
            return Err(Failure::value("address map entries take name, hash, rva and optional source"));
        }
        let name = match row.get("name") {
            None => "",
            Some(Value::String(name)) if name.chars().count() <= 512 && !name.contains(char::from(0)) => name,
            Some(_) => return Err(Failure::value("address map name must be text of at most 512 characters")),
        };
        let hashed = match row.get("hash") {
            None => "",
            Some(Value::String(text)) if text.is_empty() || hash_digits(text).is_some() => text,
            Some(_) => return Err(Failure::value("address map hash must be hexadecimal, e.g. 0x1234")),
        };
        if name.is_empty() && hashed.is_empty() {
            return Err(Failure::value("address map entry needs a name or hash"));
        }
        let Some(rva) = (match row.get("rva") {
            Some(Value::String(text)) => rva_digits(text),
            _ => None,
        }) else {
            return Err(Failure::value("address map rva must be hexadecimal, e.g. 0x1234"));
        };
        let row_source = match row.get("source") {
            None => source,
            Some(found) => match source_ok(found) {
                Some(text) => text,
                None => return Err(Failure::value("address map entry requires a cited source")),
            },
        };
        let hash_text = match hash_digits(hashed) {
            Some(digits) => format!("{:#x}", u128::from_str_radix(digits, 16).map_err(|_| Failure::fallback("hash past 128 bits"))?),
            None => String::new(),
        };
        let rva_text = format!("{:#x}", u64::from_str_radix(rva, 16).map_err(|_| Failure::fallback("rva past 64 bits"))?);
        let mut entry = Map::new();
        entry.insert("name".into(), name.into());
        entry.insert("hash".into(), hash_text.into());
        entry.insert("rva".into(), rva_text.into());
        entry.insert("source".into(), row_source.into());
        cleaned.push(Value::Object(entry));
    }
    let map_sha256 = sha256_hex(raw);
    let count = cleaned.len();
    let mut record = Map::new();
    record.insert("sha256".into(), digest.into());
    record.insert("map_sha256".into(), map_sha256.clone().into());
    record.insert("file".into(), file.into());
    record.insert("source".into(), source.into());
    record.insert("entries".into(), Value::Array(cleaned));
    let hash = record_hash(&record);
    record.insert("record_sha256".into(), hash.into());
    if pytext::dumps(&Value::Object(record.clone()), Dumps::Indent2).len() > MAX_RECORD_BYTES {
        return Err(Failure::value("normalized address map exceeds 32 MiB"));
    }
    Ok(Normalised { map_sha256, entries: count, record })
}
