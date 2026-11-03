//! `hydralysis/address_maps.py`: validation and normalisation of a source-cited name/hash to RVA map.
//!
//! The file system parts (the lock, the stored record, the directory listing, `Path.resolve`) stay in Python; this is the
//! per-row loop, which costs up to 100000 iterations of regex matches and conversions.
//!
//! The rows are validated straight from the parsed input and written out as text three ways without building a second tree
//! of JSON values: the record's canonical form (for `record_sha256`), the size it would have with `indent=2` (for the 32 MiB
//! bound) and the compact record the caller loads. The orders and separators are the ones Python's `json.dumps` uses; the
//! unit tests compare all three with the generic serialiser.

use std::io::Write;

use hy_core::json::write_string;
use serde::Deserializer;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
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

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `address_maps._record_hash`: SHA-256 of the record without `record_sha256`, `sort_keys` and compact separators.
pub fn record_hash(record: &Map<String, Value>) -> String {
    let data: Map<String, Value> =
        record.iter().filter(|(key, _)| key.as_str() != "record_sha256").map(|(k, v)| (k.clone(), v.clone())).collect();
    let text = pytext::dumps_with(&Value::Object(data), pytext::Layout::Compact, true, false);
    hex_of(&Sha256::digest(text.as_bytes()))
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

/// At most LIMIT characters; counting is skipped when the bytes already settle it.
fn at_most_chars(text: &str, limit: usize) -> bool {
    text.len() <= limit || text.chars().count() <= limit
}

/// A cited source: text, not blank, at most 4096 characters.
fn source_ok(value: &Value) -> Option<&str> {
    match value {
        Value::String(text) if !py_strip(text).is_empty() && at_most_chars(text, 4096) => Some(text),
        _ => None,
    }
}

/// One validated row: the name, the hash and RVA as numbers (`hex(int(..))` spells them), the cited source (`None`: the
/// file's own).
struct Entry {
    name: String,
    hash: Option<u128>,
    rva: u64,
    source: Option<String>,
}

fn push_hash(out: &mut Vec<u8>, hash: Option<u128>) {
    out.push(b'"');
    if let Some(value) = hash {
        let _ = write!(out, "{value:#x}");
    }
    out.push(b'"');
}

fn push_rva(out: &mut Vec<u8>, rva: u64) {
    let _ = write!(out, "\"{rva:#x}\"");
}

/// The row in the record's own key order, as `json.dumps(..., ensure_ascii=True)` writes it.
fn push_entry(out: &mut Vec<u8>, entry: &Entry, file_source: &str) {
    out.extend_from_slice(br#"{"name":"#);
    write_string(out, &entry.name, true);
    out.extend_from_slice(br#","hash":"#);
    push_hash(out, entry.hash);
    out.extend_from_slice(br#","rva":"#);
    push_rva(out, entry.rva);
    out.extend_from_slice(br#","source":"#);
    write_string(out, entry.source.as_deref().unwrap_or(file_source), true);
    out.push(b'}');
}

/// The row with sorted keys and `ensure_ascii=False`, for the record hash.
fn push_entry_canonical(out: &mut Vec<u8>, entry: &Entry, file_source: &str) {
    out.extend_from_slice(br#"{"hash":"#);
    push_hash(out, entry.hash);
    out.extend_from_slice(br#","name":"#);
    write_string(out, &entry.name, false);
    out.extend_from_slice(br#","rva":"#);
    push_rva(out, entry.rva);
    out.extend_from_slice(br#","source":"#);
    write_string(out, entry.source.as_deref().unwrap_or(file_source), false);
    out.push(b'}');
}

/// The bytes of one row with `indent=2` at the depth it has inside the record (in an `entries` list).
fn indent2_entry_len(entry: &Entry, file_source: &str, scratch: &mut Vec<u8>) -> usize {
    // 6 ("    {\n") + 14 + 2 (name) + 14 + 2 (hash) + 13 + 2 (rva) + 16 + 1 (source) + 5 ("    }") without the values
    let mut total = 75;
    scratch.clear();
    write_string(scratch, &entry.name, true);
    total += scratch.len();
    scratch.clear();
    push_hash(scratch, entry.hash);
    total += scratch.len();
    scratch.clear();
    push_rva(scratch, entry.rva);
    total += scratch.len();
    scratch.clear();
    write_string(scratch, entry.source.as_deref().unwrap_or(file_source), true);
    total + scratch.len()
}

/// What [`normalise_text`] makes.
#[derive(Debug)]
pub struct Text {
    /// `hashlib.sha256(raw).hexdigest()`.
    pub map_sha256: String,
    pub entries: usize,
    /// The stored record, `record_sha256` included, as compact JSON in the record's key order.
    pub record_json: String,
    /// The bytes `json.dumps(record, ensure_ascii=True, indent=2)` would take (bounded by [`MAX_RECORD_BYTES`]).
    pub indent2_bytes: usize,
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

/// `address_maps.import_map` up to the write, as a record tree.
pub fn normalise(raw: &[u8], digest: &str, file: &str) -> Res<Normalised> {
    let done = normalise_text(raw, digest, file)?;
    let Value::Object(record) = pytext::parse_json(&done.record_json)? else {
        return Err(Failure::fallback("record is not an object"));
    };
    Ok(Normalised { map_sha256: done.map_sha256, entries: done.entries, record })
}

/// What the file says about `entries`.
enum Rows {
    Absent,
    /// Something that is not a list.
    NotList,
    /// A list: how many rows, the validated rows (none past the first bad one or the row limit) and the first bad row.
    List {
        count: usize,
        entries: Vec<Entry>,
        error: Option<Failure>,
    },
}

/// The parts of the file the checks need, read in one pass; the rows are validated as they stream by so that the whole
/// file is never held as a tree of values.
struct Document {
    unknown_key: bool,
    sha256: Option<Value>,
    source: Option<Value>,
    rows: Rows,
}

fn unreadable() -> Failure {
    Failure::fallback("json not parsed by serde")
}

fn read_document(text: &str) -> Res<Document> {
    let first = text.bytes().find(|byte| !matches!(byte, b' ' | 9 | 10 | 13));
    if first != Some(b'{') {
        // valid JSON that is not an object, or not JSON at all (the original decides)
        serde_json::from_str::<IgnoredAny>(text).map_err(|_| unreadable())?;
        return Err(Failure::value("address map takes sha256, source and entries"));
    }
    let mut reader = serde_json::Deserializer::from_str(text);
    let document = reader.deserialize_map(DocumentVisitor).map_err(|_| unreadable())?;
    reader.end().map_err(|_| unreadable())?;
    Ok(document)
}

struct DocumentVisitor;

impl<'de> Visitor<'de> for DocumentVisitor {
    type Value = Document;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an address map object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Document, A::Error> {
        let mut document = Document { unknown_key: false, sha256: None, source: None, rows: Rows::Absent };
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "sha256" => document.sha256 = Some(map.next_value::<Value>()?),
                "source" => document.source = Some(map.next_value::<Value>()?),
                "entries" => document.rows = map.next_value_seed(RowsSeed)?,
                _ => {
                    document.unknown_key = true;
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(document)
    }
}

struct RowsSeed;

impl<'de> DeserializeSeed<'de> for RowsSeed {
    type Value = Rows;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Rows, D::Error> {
        deserializer.deserialize_any(RowsVisitor)
    }
}

struct RowsVisitor;

impl<'de> Visitor<'de> for RowsVisitor {
    type Value = Rows;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Rows, A::Error> {
        let mut count = 0;
        let mut entries = Vec::new();
        let mut error = None;
        loop {
            if error.is_none() && count < MAX_ROWS {
                let Some(row) = seq.next_element::<Value>()? else { break };
                count += 1;
                match clean_row(&row) {
                    Ok(entry) => entries.push(entry),
                    Err(failure) => error = Some(failure),
                }
            } else {
                // only counted: past the first bad row nothing is validated, and past the limit nothing is kept
                if seq.next_element::<IgnoredAny>()?.is_none() {
                    break;
                }
                count += 1;
            }
        }
        Ok(Rows::List { count, entries, error })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Rows, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Rows::NotList)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Rows, E> {
        Ok(Rows::NotList)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Rows, E> {
        Ok(Rows::NotList)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Rows, E> {
        Ok(Rows::NotList)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Rows, E> {
        Ok(Rows::NotList)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Rows, E> {
        Ok(Rows::NotList)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Rows, E> {
        Ok(Rows::NotList)
    }
}

/// One row of `entries` as the original validates it.
fn clean_row(row: &Value) -> Res<Entry> {
    let Value::Object(row) = row else {
        return Err(Failure::value("address map entries take name, hash, rva and optional source"));
    };
    if row.len() > 4 || row.keys().any(|key| !matches!(key.as_str(), "name" | "hash" | "rva" | "source")) {
        return Err(Failure::value("address map entries take name, hash, rva and optional source"));
    }
    let name = match row.get("name") {
        None => "",
        Some(Value::String(name)) if at_most_chars(name, 512) && !name.contains(char::from(0)) => name,
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
    let source = match row.get("source") {
        None => None,
        Some(found) => match source_ok(found) {
            Some(text) => Some(text.to_owned()),
            None => return Err(Failure::value("address map entry requires a cited source")),
        },
    };
    let hash = match hash_digits(hashed) {
        Some(digits) => Some(u128::from_str_radix(digits, 16).map_err(|_| Failure::fallback("hash past 128 bits"))?),
        None => None,
    };
    let rva = u64::from_str_radix(rva, 16).map_err(|_| Failure::fallback("rva past 64 bits"))?;
    Ok(Entry { name: name.to_owned(), hash, rva, source })
}

/// `address_maps.import_map` up to the write: validate RAW (the file's bytes) against DIGEST and build the stored record.
/// FILE is `str(Path(path).resolve())`.
pub fn normalise_text(raw: &[u8], digest: &str, file: &str) -> Res<Text> {
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
    if pytext::has_big_integer(text.as_bytes()) {
        return Err(Failure::fallback("integer past 64 bits"));
    }
    let document = read_document(text)?;
    if document.unknown_key {
        return Err(Failure::value("address map takes sha256, source and entries"));
    }
    // `str(value.get("sha256", "")).lower() != digest`
    match &document.sha256 {
        Some(Value::String(found)) if found.to_lowercase() == digest => {}
        None | Some(Value::String(_)) => return Err(Failure::value("address map build SHA-256 mismatch")),
        Some(_) => return Err(Failure::fallback("sha256 is not text")),
    }
    let Some(source) = document.source.as_ref().and_then(source_ok) else {
        return Err(Failure::value("address map requires a cited source"));
    };
    let cleaned = match document.rows {
        Rows::List { count, entries, error } if (1..=MAX_ROWS).contains(&count) => match error {
            Some(failure) => return Err(failure),
            None => entries,
        },
        _ => return Err(Failure::value("address map requires 1..100000 entries")),
    };
    let map_sha256 = hex_of(&Sha256::digest(raw));

    // `record_sha256`: the canonical form (sorted keys, no spaces, not ASCII-escaped) of everything but the hash itself
    let mut hasher = Sha256::new();
    let mut scratch: Vec<u8> = Vec::with_capacity(1 << 16);
    scratch.extend_from_slice(br#"{"entries":["#);
    for (index, entry) in cleaned.iter().enumerate() {
        if index > 0 {
            scratch.push(b',');
        }
        push_entry_canonical(&mut scratch, entry, source);
        if scratch.len() >= 1 << 16 {
            hasher.update(&scratch);
            scratch.clear();
        }
    }
    scratch.extend_from_slice(br#"],"file":"#);
    write_string(&mut scratch, file, false);
    scratch.extend_from_slice(br#","map_sha256":""#);
    scratch.extend_from_slice(map_sha256.as_bytes());
    scratch.extend_from_slice(br#"","sha256":""#);
    scratch.extend_from_slice(digest.as_bytes());
    scratch.extend_from_slice(br#"","source":"#);
    write_string(&mut scratch, source, false);
    scratch.push(b'}');
    hasher.update(&scratch);
    let record_sha256 = hex_of(&hasher.finalize());

    // the size `json.dumps(record, ensure_ascii=True, indent=2)` would have: the frame of the record with an empty list,
    // plus the rows (`[]` becomes `[`, newline, the rows joined by `,` newline, newline, two spaces, `]`: rows + 4 more bytes)
    let mut frame = Map::new();
    frame.insert("sha256".into(), digest.into());
    frame.insert("map_sha256".into(), map_sha256.clone().into());
    frame.insert("file".into(), file.into());
    frame.insert("source".into(), source.into());
    frame.insert("entries".into(), Value::Array(Vec::new()));
    frame.insert("record_sha256".into(), record_sha256.clone().into());
    let mut size = pytext::dumps(&Value::Object(frame), Dumps::Indent2).len() + 4 + 2 * (cleaned.len() - 1);
    for entry in &cleaned {
        size += indent2_entry_len(entry, source, &mut scratch);
    }
    if size > MAX_RECORD_BYTES {
        return Err(Failure::value("normalized address map exceeds 32 MiB"));
    }

    // the record the caller loads
    let mut out: Vec<u8> = Vec::with_capacity(cleaned.len() * 96 + 512);
    out.extend_from_slice(br#"{"sha256":""#);
    out.extend_from_slice(digest.as_bytes());
    out.extend_from_slice(br#"","map_sha256":""#);
    out.extend_from_slice(map_sha256.as_bytes());
    out.extend_from_slice(br#"","file":"#);
    write_string(&mut out, file, true);
    out.extend_from_slice(br#","source":"#);
    write_string(&mut out, source, true);
    out.extend_from_slice(br#","entries":["#);
    for (index, entry) in cleaned.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        push_entry(&mut out, entry, source);
    }
    out.extend_from_slice(br#"],"record_sha256":""#);
    out.extend_from_slice(record_sha256.as_bytes());
    out.extend_from_slice(b"\"}");
    let record_json = String::from_utf8(out).map_err(|_| Failure::fallback("record text is not UTF-8"))?;
    Ok(Text { map_sha256, entries: cleaned.len(), record_json, indent2_bytes: size })
}
