//! Hash-keyed identities (semantic trace spec 15.6), ported from `hydralysis.trace_hashes`.
//!
//! * [`Codec`] / [`Algorithm`]: FNV-1/1a (any basis and prime), CRC-32, a generic bitwise CRC, Murmur3 x86 32, each with
//!   a case fold and an encoding.
//! * [`Dictionary`]: names with their sources and an index `(algorithm, hash) -> names`. Two names with one hash under one
//!   algorithm are `ambiguous`; no name is ever chosen. Names are stored once; the index holds numbers, not strings.
//! * [`annotate_constants`], [`Dictionary::interpretation`], [`scan_constants`]: the static and trace use.
//!
//! Text forms of hashes are lowercase `0x...` without padding ([`format_hash`]).

use crate::pyfmt::{has_visible, write_json_string};
use crate::{Error, Result};
use memchr::memmem;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

pub const MAX_NAME: usize = 512;
pub const MAX_ENTRIES: usize = 5_000_000;

/// `format_hash`: `0x%x`.
pub fn format_hash(value: u64) -> String {
    format!("{value:#x}")
}

// ---- primitive algorithms -------------------------------------------------------------------------------------------

/// The FNV variant: `1` multiplies then xors, `1a` xors then multiplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FnvVariant {
    V1,
    V1a,
}

/// FNV over DATA. `basis` and `prime` default per width; with no data the (unmasked) basis is the answer, as in Python.
pub fn fnv(data: &[u8], bits: i64, variant: FnvVariant, basis: Option<u64>, prime: Option<u64>) -> Result<u64> {
    let (default_basis, default_prime, mask) = match bits {
        32 => (0x811C_9DC5_u64, 0x0100_0193_u64, 0xFFFF_FFFF_u64),
        64 => (0xCBF2_9CE4_8422_2325, 0x0100_0000_01B3, u64::MAX),
        _ => return Err(Error::hash("bad_width", "FNV is defined here for 32 and 64 bits")),
    };
    let mut value = basis.unwrap_or(default_basis);
    let step = prime.unwrap_or(default_prime);
    match variant {
        FnvVariant::V1a => {
            for &byte in data {
                value = (value ^ u64::from(byte)).wrapping_mul(step) & mask;
            }
        }
        FnvVariant::V1 => {
            for &byte in data {
                value = value.wrapping_mul(step) & mask ^ u64::from(byte);
            }
        }
    }
    Ok(value)
}

/// CRC-32 (IEEE), `zlib.crc32`.
pub fn crc32(data: &[u8]) -> u64 {
    u64::from(crc32fast::hash(data))
}

/// The Rocksoft parameters of [`crc_generic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrcParams {
    pub width: i64,
    pub poly: u64,
    pub init: u64,
    pub xorout: u64,
    pub refin: bool,
    pub refout: bool,
}

impl CrcParams {
    /// The defaults of `crc_generic`: CRC-32/ISO-HDLC.
    pub fn with_width(width: i64) -> Self {
        Self { width, poly: 0x04C1_1DB7, init: 0xFFFF_FFFF, xorout: 0xFFFF_FFFF, refin: true, refout: true }
    }
}

/// A bitwise CRC, for a profile whose CRC is not the IEEE one.
pub fn crc_generic(data: &[u8], p: &CrcParams) -> Result<u64> {
    if !(8..=64).contains(&p.width) {
        return Err(Error::hash("bad_width", "CRC width is 8..64"));
    }
    let width = p.width as u32;
    let top = 1u64 << (width - 1);
    let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
    let mut register = p.init & mask;
    for &byte in data {
        let byte = if p.refin { byte.reverse_bits() } else { byte };
        register ^= u64::from(byte) << (width - 8);
        for _ in 0..8 {
            register = if register & top != 0 { ((register << 1) ^ p.poly) & mask } else { (register << 1) & mask };
        }
    }
    if p.refout {
        register = register.reverse_bits() >> (64 - width);
    }
    Ok((register ^ p.xorout) & mask)
}

/// Murmur3 x86 32.
pub fn murmur3_32(data: &[u8], seed: u64) -> u64 {
    const C1: u32 = 0xCC9E_2D51;
    const C2: u32 = 0x1B87_3593;
    let mut value = seed as u32;
    let (blocks, tail) = data.as_chunks::<4>();
    for block in blocks {
        let mut word = u32::from_le_bytes(*block);
        word = word.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        value ^= word;
        value = value.rotate_left(13).wrapping_mul(5).wrapping_add(0xE654_6B64);
    }
    if !tail.is_empty() {
        let mut word = 0u32;
        for &byte in tail.iter().rev() {
            word = (word << 8) | u32::from(byte);
        }
        word = word.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        value ^= word;
    }
    value ^= data.len() as u32;
    value ^= value >> 16;
    value = value.wrapping_mul(0x85EB_CA6B);
    value ^= value >> 13;
    value = value.wrapping_mul(0xC2B2_AE35);
    value ^= value >> 16;
    u64::from(value)
}

// ---- algorithms -----------------------------------------------------------------------------------------------------

/// The function of an algorithm, as data (a profile codec is a parameterised built-in, never code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Fnv { variant: FnvVariant, bits: i64, basis: Option<u64>, prime: Option<u64> },
    Crc32,
    Crc(CrcParams),
    Murmur3 { seed: u64 },
}

impl Codec {
    pub fn hash(&self, data: &[u8]) -> Result<u64> {
        match *self {
            Codec::Fnv { variant, bits, basis, prime } => fnv(data, bits, variant, basis, prime),
            Codec::Crc32 => Ok(crc32(data)),
            Codec::Crc(ref params) => crc_generic(data, params),
            Codec::Murmur3 { seed } => Ok(murmur3_32(data, seed)),
        }
    }
}

/// Case folding applied to text before it is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fold {
    None,
    Lower,
    Upper,
}

impl Fold {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "none" => Some(Self::None),
            "lower" => Some(Self::Lower),
            "upper" => Some(Self::Upper),
            _ => Option::None,
        }
    }
}

/// The byte encoding of text before it is hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Ascii,
    Latin1,
}

impl Encoding {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "utf-8" => Some(Self::Utf8),
            "utf-16le" => Some(Self::Utf16Le),
            "ascii" => Some(Self::Ascii),
            "latin-1" => Some(Self::Latin1),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Utf16Le => "utf-16le",
            Self::Ascii => "ascii",
            Self::Latin1 => "latin-1",
        }
    }
}

/// A named hash function with a declared width, a case fold and an encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Algorithm {
    pub name: String,
    /// The declared width (`Algorithm.bits`); [`annotate_constants`] skips constants that do not fit it.
    pub bits: i64,
    pub codec: Codec,
    pub fold: Fold,
    pub encoding: Encoding,
}

/// The text cannot be encoded (`ascii` or `latin-1` and a character outside them).
fn encode_error(encoding: Encoding, text: &str, position: usize) -> Error {
    Error::Encode { encoding: encoding.name(), text: text.to_owned(), position }
}

impl Algorithm {
    /// Hash TEXT: fold, encode, hash.
    pub fn hash_text(&self, text: &str) -> Result<u64> {
        let folded;
        let text = match self.fold {
            Fold::None => text,
            Fold::Lower => {
                folded = text.to_lowercase();
                &folded
            }
            Fold::Upper => {
                folded = text.to_uppercase();
                &folded
            }
        };
        match self.encoding {
            Encoding::Utf8 => self.codec.hash(text.as_bytes()),
            Encoding::Ascii => match text.char_indices().find(|(_, c)| !c.is_ascii()) {
                None => self.codec.hash(text.as_bytes()),
                Some((at, _)) => Err(encode_error(self.encoding, text, text[..at].chars().count())),
            },
            Encoding::Latin1 => {
                let mut bytes = Vec::with_capacity(text.len());
                for (position, c) in text.chars().enumerate() {
                    match u8::try_from(u32::from(c)) {
                        Ok(byte) => bytes.push(byte),
                        Err(_) => return Err(encode_error(self.encoding, text, position)),
                    }
                }
                self.codec.hash(&bytes)
            }
            Encoding::Utf16Le => {
                let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
                self.codec.hash(&bytes)
            }
        }
    }
}

// ---- the dictionary -------------------------------------------------------------------------------------------------

/// The answer for one hash under one algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub algorithm: String,
    pub hash: u64,
    /// `(name, sorted sources)`, names sorted.
    pub names: Vec<(String, Vec<String>)>,
}

impl Resolution {
    /// `unknown`, `resolved` (one name) or `ambiguous`.
    pub fn status(&self) -> &'static str {
        match self.names.len() {
            0 => "unknown",
            1 => "resolved",
            _ => "ambiguous",
        }
    }

    pub fn names_value(&self) -> Value {
        Value::Array(self.names.iter().map(|(name, sources)| json!({"name": name, "sources": sources})).collect())
    }

    pub fn to_value(&self) -> Value {
        json!({"algorithm": self.algorithm, "hash": format_hash(self.hash), "status": self.status(), "names": self.names_value()})
    }
}

enum Slot {
    One(u32),
    Many(Vec<u32>),
}

/// Names with their sources. A hash that two different names produce is ambiguous; no name is chosen.
pub struct Dictionary {
    /// The algorithms hashed on `add`, without repeats.
    algorithms: Vec<Algorithm>,
    /// The algorithm list as given (repeats kept): the digest covers it.
    listed: Vec<String>,
    names: Vec<Arc<str>>,
    name_ids: HashMap<Arc<str>, u32>,
    name_sources: Vec<Vec<u32>>,
    source_text: Vec<Arc<str>>,
    source_ids: HashMap<Arc<str>, u32>,
    index: HashMap<(u16, u64), Slot>,
    digest: Option<String>,
}

impl Dictionary {
    /// `listed` is the dictionary's algorithm list (it may repeat a name); every name in it must be in `algorithms`.
    pub fn new(algorithms: Vec<Algorithm>, listed: Vec<String>) -> Self {
        Self {
            algorithms,
            listed,
            names: Vec::new(),
            name_ids: HashMap::new(),
            name_sources: Vec::new(),
            source_text: Vec::new(),
            source_ids: HashMap::new(),
            index: HashMap::new(),
            digest: None,
        }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn algorithm_names(&self) -> &[String] {
        &self.listed
    }

    fn algorithm_slot(&self, name: &str) -> Result<usize> {
        self.algorithms
            .iter()
            .position(|a| a.name == name)
            .ok_or_else(|| Error::hash("unknown_algorithm", format!("algorithm {name} is not in this dictionary")))
    }

    fn source_id(&mut self, source: &str) -> u32 {
        if let Some(&id) = self.source_ids.get(source) {
            return id;
        }
        let text: Arc<str> = Arc::from(source);
        let id = self.source_text.len() as u32;
        self.source_text.push(Arc::clone(&text));
        self.source_ids.insert(text, id);
        id
    }

    /// Add NAME with its SOURCE. Errors leave the dictionary unchanged.
    pub fn add(&mut self, name: &str, source: &str) -> Result<()> {
        let length = name.chars().count();
        if length == 0 || length > MAX_NAME || name.contains('\0') {
            return Err(Error::hash("bad_name", format!("a dictionary name is 1..{MAX_NAME} characters without NUL")));
        }
        if !has_visible(source) {
            return Err(Error::hash("source_required", "every dictionary entry records its source"));
        }
        let source = self.source_id(source);
        let id = match self.name_ids.get(name) {
            Some(&id) => id,
            None => {
                if self.names.len() >= MAX_ENTRIES {
                    return Err(Error::hash("dictionary_full", format!("the dictionary holds at most {MAX_ENTRIES} names")));
                }
                let hashes = self.algorithms.iter().map(|a| a.hash_text(name)).collect::<Result<Vec<u64>>>()?;
                let id = self.names.len() as u32;
                let text: Arc<str> = Arc::from(name);
                self.names.push(Arc::clone(&text));
                self.name_ids.insert(text, id);
                self.name_sources.push(Vec::new());
                for (slot, hash) in hashes.into_iter().enumerate() {
                    match self.index.entry((slot as u16, hash)) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(Slot::One(id));
                        }
                        std::collections::hash_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                            Slot::One(existing) => {
                                if *existing != id {
                                    let pair = vec![*existing, id];
                                    entry.insert(Slot::Many(pair));
                                }
                            }
                            Slot::Many(list) => {
                                if !list.contains(&id) {
                                    list.push(id);
                                }
                            }
                        },
                    }
                }
                id
            }
        };
        let sources = &mut self.name_sources[id as usize];
        if !sources.contains(&source) {
            sources.push(source);
        }
        self.digest = None;
        Ok(())
    }

    /// `add` for each of NAMES under SOURCE, stopping at the first refusal (the earlier names stay added).
    pub fn add_many<'a>(&mut self, names: impl IntoIterator<Item = &'a str>, source: &str) -> Result<usize> {
        let mut count = 0;
        for name in names {
            self.add(name, source)?;
            count += 1;
        }
        Ok(count)
    }

    fn sources_of(&self, id: u32) -> Vec<String> {
        let mut sources: Vec<String> = self.name_sources[id as usize].iter().map(|&s| self.source_text[s as usize].to_string()).collect();
        sources.sort();
        sources
    }

    fn resolution(&self, slot: usize, hash: u64) -> Resolution {
        let ids: &[u32] = match self.index.get(&(slot as u16, hash)) {
            None => &[],
            Some(Slot::One(id)) => std::slice::from_ref(id),
            Some(Slot::Many(list)) => list,
        };
        let mut names: Vec<(String, Vec<String>)> =
            ids.iter().map(|&id| (self.names[id as usize].to_string(), self.sources_of(id))).collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        Resolution { algorithm: self.algorithms[slot].name.clone(), hash, names }
    }

    /// The answer for one hash under one algorithm of this dictionary.
    pub fn resolve(&self, algorithm: &str, hash: u64) -> Result<Resolution> {
        Ok(self.resolution(self.algorithm_slot(algorithm)?, hash))
    }

    /// Every `(algorithm, hash)` with more than one name, ordered by algorithm name then hash.
    pub fn collisions(&self) -> Vec<Resolution> {
        let mut keys: Vec<(&str, usize, u64)> = self
            .index
            .iter()
            .filter(|(_, slot)| matches!(slot, Slot::Many(_)))
            .map(|(&(slot, hash), _)| (self.algorithms[usize::from(slot)].name.as_str(), usize::from(slot), hash))
            .collect();
        keys.sort_unstable_by(|a, b| a.0.cmp(b.0).then(a.2.cmp(&b.2)));
        keys.into_iter().map(|(_, slot, hash)| self.resolution(slot, hash)).collect()
    }

    /// The SHA-256 (hex) of the canonical text of the content: algorithms, names and sources. The Python builds the same
    /// text with `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
    pub fn digest(&mut self) -> String {
        if let Some(cached) = &self.digest {
            return cached.clone();
        }
        let mut hasher = Sha256::new();
        let mut buffer = String::with_capacity(1 << 16);
        let mut algorithms: Vec<&String> = self.listed.iter().collect();
        algorithms.sort();
        buffer.push_str("{\"algorithms\":[");
        for (n, name) in algorithms.iter().enumerate() {
            if n > 0 {
                buffer.push(',');
            }
            write_json_string(name, &mut buffer);
        }
        buffer.push_str("],\"entries\":[");
        let mut order: Vec<u32> = (0..self.names.len() as u32).collect();
        order.sort_unstable_by(|&a, &b| self.names[a as usize].cmp(&self.names[b as usize]));
        for (n, &id) in order.iter().enumerate() {
            if n > 0 {
                buffer.push(',');
            }
            buffer.push('[');
            write_json_string(&self.names[id as usize], &mut buffer);
            buffer.push_str(",[");
            for (k, source) in self.sources_of(id).iter().enumerate() {
                if k > 0 {
                    buffer.push(',');
                }
                write_json_string(source, &mut buffer);
            }
            buffer.push_str("]]");
            if buffer.len() >= 1 << 16 {
                hasher.update(buffer.as_bytes());
                buffer.clear();
            }
        }
        buffer.push_str("]}");
        hasher.update(buffer.as_bytes());
        let digest = hex(&hasher.finalize());
        self.digest = Some(digest.clone());
        digest
    }

    /// The names with their sources, names sorted (the Python `sources` mapping).
    pub fn entries(&self) -> Vec<(String, Vec<String>)> {
        let mut order: Vec<u32> = (0..self.names.len() as u32).collect();
        order.sort_unstable_by(|&a, &b| self.names[a as usize].cmp(&self.names[b as usize]));
        order.into_iter().map(|id| (self.names[id as usize].to_string(), self.sources_of(id))).collect()
    }

    /// `interpretation`: a trace interpretation revision naming hashed ids. Raw values are kept; nothing is rewritten.
    pub fn interpretation(&mut self, algorithm: &str, values: &[u64], parent: Option<&str>) -> Result<Interpretation> {
        // (an unknown algorithm is only an error once there is a value to resolve, as in Python)
        let rows: Vec<Resolution> = if values.is_empty() {
            Vec::new()
        } else {
            let slot = self.algorithm_slot(algorithm)?;
            values.iter().map(|&v| self.resolution(slot, v)).collect()
        };
        let dictionary_sha256 = self.digest();
        let mut text = String::new();
        text.push_str("{\"algorithm\":");
        write_json_string(algorithm, &mut text);
        text.push_str(",\"dictionary\":");
        write_json_string(&dictionary_sha256, &mut text);
        text.push_str(",\"values\":[");
        for (n, row) in rows.iter().enumerate() {
            if n > 0 {
                text.push(',');
            }
            write_json_string(&format_hash(row.hash), &mut text);
        }
        text.push_str("]}");
        let revision = hex(&Sha256::digest(text.as_bytes()));
        Ok(Interpretation {
            revision: format!("hn_{}", &revision[..32]),
            parent: parent.map(str::to_owned),
            algorithm: algorithm.to_owned(),
            dictionary_sha256,
            rows,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A `hash-names/1` revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interpretation {
    pub revision: String,
    pub parent: Option<String>,
    pub algorithm: String,
    pub dictionary_sha256: String,
    pub rows: Vec<Resolution>,
}

impl Interpretation {
    pub fn counts(&self) -> Value {
        let count = |status: &str| self.rows.iter().filter(|r| r.status() == status).count();
        json!({"resolved": count("resolved"), "ambiguous": count("ambiguous"), "unknown": count("unknown")})
    }

    /// The revision without its rows, in the Python key order.
    pub fn header(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("kind".into(), json!("hash-names/1"));
        out.insert("revision".into(), json!(self.revision));
        out.insert("parent".into(), json!(self.parent));
        out.insert("algorithm".into(), json!(self.algorithm));
        out.insert("dictionary_sha256".into(), json!(self.dictionary_sha256));
        out.insert("raw_preserved".into(), json!(true));
        out
    }
}

// ---- static use -----------------------------------------------------------------------------------------------------

/// The dictionary's answer for one constant: its status and the non-unknown answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantNote {
    pub value: u64,
    pub status: &'static str,
    pub answers: Vec<Resolution>,
}

/// `annotate_constants` for NUMBERS under ALGORITHMS (`(name, declared bits)`; each must be in the dictionary).
pub fn annotate_constants(dictionary: &Dictionary, numbers: &[u64], algorithms: &[(String, i64)]) -> Result<Vec<ConstantNote>> {
    let mut out = Vec::with_capacity(numbers.len());
    for &number in numbers {
        let mut found = Vec::new();
        for (algorithm, bits) in algorithms {
            if *bits < 0 {
                return Err(Error::unsupported("negative algorithm width"));
            }
            if *bits < 64 && number >> bits != 0 {
                continue;
            }
            let answer = dictionary.resolve(algorithm, number)?;
            if answer.status() != "unknown" {
                found.push(answer);
            }
        }
        let mut names: Vec<&str> = found.iter().flat_map(|a| a.names.iter().map(|(n, _)| n.as_str())).collect();
        names.sort_unstable();
        names.dedup();
        let status = if names.is_empty() {
            "unknown"
        } else if names.len() == 1 && found.iter().all(|a| a.status() == "resolved") {
            "resolved"
        } else {
            "ambiguous"
        };
        out.push(ConstantNote { value: number, status, answers: found });
    }
    Ok(out)
}

/// One section of an image as the scan reads it.
pub struct SectionBytes<'a> {
    pub name: String,
    pub virtual_address: u64,
    pub raw: &'a [u8],
    pub executable: bool,
}

/// One place an image carries a hash constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantHit {
    pub value: u64,
    pub bits: i64,
    pub rva: u64,
    pub section: String,
    pub executable: bool,
    pub function: Option<u64>,
}

impl ConstantHit {
    pub fn to_value(&self) -> Value {
        let mut hit = Map::new();
        hit.insert("value".into(), json!(format_hash(self.value)));
        hit.insert("bits".into(), json!(self.bits));
        hit.insert("rva".into(), json!(format!("rva:{:#x}", self.rva)));
        hit.insert("section".into(), json!(self.section));
        hit.insert("context".into(), json!(if self.executable { "code-immediate" } else { "data" }));
        if let Some(function) = self.function {
            hit.insert("function".into(), json!(format!("rva:{function:#x}")));
        }
        Value::Object(hit)
    }
}

/// `scan_constants`: where the image carries the constants (little-endian, overlapping matches allowed), bounded by
/// LIMIT. BOUNDS names the containing function of an RVA in code (the image's own tables); FUNCTIONS are analysed
/// `[start, end)` ranges tried when BOUNDS has none. The result is `(hits, truncated)`; when it is not truncated the hits
/// are sorted by `(rva, value text)`, when it is they stay in the order found, as in Python.
pub fn scan_constants(
    sections: &[SectionBytes<'_>],
    hashes: &[(u64, i64)],
    limit: usize,
    functions: Option<&[(u64, u64)]>,
    bounds: &mut dyn FnMut(u64) -> Option<(u64, u64)>,
) -> Result<(Vec<ConstantHit>, bool)> {
    let mut hits: Vec<ConstantHit> = Vec::new();
    let mut truncated = false;
    'sections: for section in sections {
        for &(value, bits) in hashes {
            let size = usize::try_from(bits / 8).unwrap_or(0);
            if bits < 0 || !(1..=8).contains(&size) || (size < 8 && value >> (size * 8) != 0) {
                return Err(Error::unsupported("hash width"));
            }
            let form = &value.to_le_bytes()[..size];
            let finder = memmem::Finder::new(form);
            let mut start = 0;
            while start <= section.raw.len() {
                let Some(found) = finder.find(&section.raw[start..]) else { break };
                let at = start + found;
                start = at + 1;
                if hits.len() >= limit {
                    truncated = true;
                    break 'sections;
                }
                let rva = section.virtual_address + at as u64;
                let mut hit =
                    ConstantHit { value, bits, rva, section: section.name.clone(), executable: section.executable, function: None };
                let mut found_bounds = if section.executable { bounds(rva) } else { None };
                if found_bounds.is_none() && section.executable {
                    found_bounds = functions.and_then(|ranges| ranges.iter().copied().find(|&(a, b)| a <= rva && rva < b));
                }
                hit.function = found_bounds.map(|(a, _)| a);
                hits.push(hit);
            }
        }
    }
    if !truncated {
        hits.sort_by(|a, b| a.rva.cmp(&b.rva).then_with(|| format_hash(a.value).cmp(&format_hash(b.value))));
    }
    Ok((hits, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn algorithm(name: &str, bits: i64, codec: Codec) -> Algorithm {
        Algorithm { name: name.into(), bits, codec, fold: Fold::None, encoding: Encoding::Utf8 }
    }

    fn fnv1a(bits: i64) -> Codec {
        Codec::Fnv { variant: FnvVariant::V1a, bits, basis: None, prime: None }
    }

    // test_trace_static.HashRegistry.test_builtin_vectors_all_reproduce
    #[test]
    fn builtin_vectors_all_reproduce() {
        let v1_32 = Codec::Fnv { variant: FnvVariant::V1, bits: 32, basis: None, prime: None };
        let v1_64 = Codec::Fnv { variant: FnvVariant::V1, bits: 64, basis: None, prime: None };
        let table: Vec<(Codec, Vec<(&str, u64)>)> = vec![
            (fnv1a(32), vec![("", 0x811C_9DC5), ("a", 0xE40C_292C), ("foobar", 0xBF9C_F968)]),
            (fnv1a(64), vec![("", 0xCBF2_9CE4_8422_2325), ("a", 0xAF63_DC4C_8601_EC8C), ("foobar", 0x8594_4171_F739_67E8)]),
            (v1_32, vec![("", 0x811C_9DC5), ("a", 0x050C_5D7E), ("foobar", 0x31F0_B262)]),
            (v1_64, vec![("", 0xCBF2_9CE4_8422_2325), ("a", 0xAF63_BD4C_8601_B7BE), ("foobar", 0x340D_8765_A4DD_A9C2)]),
            (Codec::Crc32, vec![("", 0), ("123456789", 0xCBF4_3926)]),
            (Codec::Murmur3 { seed: 0 }, vec![("", 0), ("test", 0xBA6B_D213), ("Hello, world!", 0xC036_3E43)]),
        ];
        for (codec, vectors) in table {
            for (text, expected) in vectors {
                assert_eq!(codec.hash(text.as_bytes()).unwrap(), expected, "{codec:?} {text:?}");
            }
        }
    }

    // test_trace_static.HashRegistry.test_known_values
    #[test]
    fn known_values() {
        assert_eq!(murmur3_32(b"The quick brown fox jumps over the lazy dog", 0x9747_B28C), 0x2FA8_26CD);
        assert_eq!(murmur3_32(b"", 1), 0x514E_28B7);
        let params = CrcParams { width: 16, poly: 0x1021, init: 0xFFFF, xorout: 0, refin: false, refout: false };
        assert_eq!(crc_generic(b"123456789", &params).unwrap(), 0x29B1);
        // The default parameters are CRC-32/ISO-HDLC, which is zlib's.
        assert_eq!(crc_generic(b"123456789", &CrcParams::with_width(32)).unwrap(), 0xCBF4_3926);
    }

    #[test]
    fn the_unmasked_basis_survives_empty_input_and_widths_are_checked() {
        assert_eq!(fnv(b"", 32, FnvVariant::V1a, Some(0x1_2345_6789), None).unwrap(), 0x1_2345_6789);
        assert!(matches!(fnv(b"a", 16, FnvVariant::V1a, None, None), Err(Error::Hash { code: "bad_width", .. })));
        assert!(matches!(crc_generic(b"a", &CrcParams::with_width(7)), Err(Error::Hash { code: "bad_width", .. })));
    }

    // test_trace_static.HashRegistry.test_a_profile_codec_needs_vectors_it_reproduces (the case-folded codec)
    #[test]
    fn a_case_folded_codec_hashes_the_folded_text() {
        let folded = Algorithm { fold: Fold::Lower, ..algorithm("casefold64", 64, fnv1a(64)) };
        let plain = algorithm("fnv1a64", 64, fnv1a(64));
        assert_eq!(folded.hash_text("A").unwrap(), 0xAF63_DC4C_8601_EC8C);
        assert_eq!(folded.hash_text("ABC").unwrap(), plain.hash_text("abc").unwrap());
        let narrow = Algorithm { encoding: Encoding::Ascii, ..plain.clone() };
        assert!(matches!(narrow.hash_text("caf\u{e9}"), Err(Error::Encode { .. })));
        let wide = Algorithm { encoding: Encoding::Utf16Le, ..plain };
        assert_eq!(wide.hash_text("a").unwrap(), fnv(b"a\0", 64, FnvVariant::V1a, None, None).unwrap());
    }

    fn build() -> Dictionary {
        let algorithms =
            vec![algorithm("crc32", 32, Codec::Crc32), algorithm("fnv1a32", 32, fnv1a(32)), algorithm("fnv1a64", 64, fnv1a(64))];
        let mut dictionary = Dictionary::new(algorithms, vec!["fnv1a64".into(), "fnv1a32".into(), "crc32".into()]);
        for name in ["Player", "Enemy", "Weapon", "Door", "Inventory"] {
            dictionary.add(name, "fixture word list").unwrap();
        }
        dictionary
    }

    // test_trace_static.HashRegistry.test_entries_record_their_sources_and_resolve
    #[test]
    fn entries_record_their_sources_and_resolve() {
        let mut dictionary = build();
        let weapon = fnv(b"Weapon", 64, FnvVariant::V1a, None, None).unwrap();
        let answer = dictionary.resolve("fnv1a64", weapon).unwrap();
        assert_eq!(answer.status(), "resolved");
        assert_eq!(answer.names, vec![("Weapon".to_string(), vec!["fixture word list".to_string()])]);
        assert_eq!(dictionary.resolve("fnv1a64", 0x1234).unwrap().status(), "unknown");
        assert!(matches!(dictionary.add("x", " "), Err(Error::Hash { code: "source_required", .. })));
        assert!(matches!(dictionary.add("", "src"), Err(Error::Hash { code: "bad_name", .. })));
        assert!(matches!(dictionary.add("a\0b", "src"), Err(Error::Hash { code: "bad_name", .. })));
        assert!(matches!(dictionary.resolve("nope", 1), Err(Error::Hash { code: "unknown_algorithm", .. })));
        assert_eq!(dictionary.len(), 5);
    }

    // test_trace_static.HashRegistry.test_a_deliberate_collision_is_ambiguous_and_never_resolved
    #[test]
    fn a_deliberate_collision_is_ambiguous_and_never_resolved() {
        let crc16 = Codec::Crc(CrcParams { width: 16, poly: 0x1021, init: 0xFFFF, xorout: 0, refin: false, refout: false });
        let algorithm16 = algorithm("crc16", 16, crc16);
        let mut seen: HashMap<u64, String> = HashMap::new();
        let mut pair = None;
        for index in 0..5000 {
            // (a CRC detects every short burst, so names that differ in a few characters never collide: scatter them)
            let scattered = Sha256::digest(format!("{index}").as_bytes());
            let name = hex(&scattered)[..12].to_owned();
            let value = algorithm16.hash_text(&name).unwrap();
            if let Some(other) = seen.insert(value, name.clone()) {
                pair = Some((other, name, value));
                break;
            }
        }
        let (first, second, value) = pair.expect("a 16-bit CRC collides within 5000 names");
        let mut dictionary = Dictionary::new(vec![algorithm16], vec!["crc16".into()]);
        dictionary.add(&first, "list one").unwrap();
        dictionary.add(&second, "list two").unwrap();
        let answer = dictionary.resolve("crc16", value).unwrap();
        assert_eq!(answer.status(), "ambiguous");
        let mut sorted = [first, second];
        sorted.sort();
        assert_eq!(answer.names.iter().map(|n| n.0.clone()).collect::<Vec<_>>(), sorted);
        assert_eq!(dictionary.collisions().len(), 1);
        let note = annotate_constants(&dictionary, &[value], &[("crc16".into(), 16)]).unwrap();
        assert_eq!(note[0].status, "ambiguous");
    }

    // test_trace_static.HashRegistry.test_annotating_constants
    #[test]
    fn annotating_constants() {
        let dictionary = build();
        let hit = fnv(b"Enemy", 64, FnvVariant::V1a, None, None).unwrap();
        let rows = annotate_constants(&dictionary, &[hit, 0xDEAD], &[("fnv1a64".into(), 64)]).unwrap();
        assert_eq!(rows.iter().map(|r| r.status).collect::<Vec<_>>(), ["resolved", "unknown"]);
        assert_eq!(rows[0].answers[0].names[0].0, "Enemy");
        // a constant wider than the algorithm is not asked about it
        let wide = annotate_constants(&dictionary, &[hit], &[("fnv1a32".into(), 32)]).unwrap();
        assert_eq!(wide[0].status, "unknown");
    }

    // test_trace_static.HashRegistry.test_an_interpretation_revision_keeps_the_raw_value_and_changes_with_the_dictionary
    #[test]
    fn an_interpretation_revision_changes_with_the_dictionary() {
        let mut dictionary = build();
        let door = fnv(b"Door", 64, FnvVariant::V1a, None, None).unwrap();
        let first = dictionary.interpretation("fnv1a64", &[0x77, door], None).unwrap();
        let again = dictionary.interpretation("fnv1a64", &[0x77, door], None).unwrap();
        assert_eq!(first.revision, again.revision);
        assert_eq!(first.counts(), json!({"resolved": 1, "ambiguous": 0, "unknown": 1}));
        dictionary.add("Window", "later list").unwrap();
        let changed = dictionary.interpretation("fnv1a64", &[0x77, door], None).unwrap();
        assert_ne!(first.revision, changed.revision);
        assert!(first.revision.starts_with("hn_") && first.revision.len() == 35);
    }

    #[test]
    fn the_digest_is_the_python_canonical_text() {
        let mut dictionary = Dictionary::new(vec![algorithm("fnv1a64", 64, fnv1a(64))], vec!["fnv1a64".into()]);
        dictionary.add("b", "s2").unwrap();
        dictionary.add("a\u{e9}", "s1").unwrap();
        dictionary.add("b", "s1").unwrap();
        let expected = "{\"algorithms\":[\"fnv1a64\"],\"entries\":[[\"a\\u00e9\",[\"s1\"]],[\"b\",[\"s1\",\"s2\"]]]}";
        assert_eq!(dictionary.digest(), hex(&Sha256::digest(expected.as_bytes())));
        // the digest is cached and a later add changes it
        let before = dictionary.digest();
        dictionary.add("c", "s1").unwrap();
        assert_ne!(before, dictionary.digest());
    }

    // test_trace_static.HashRegistry.test_a_name_search_finds_the_code_that_uses_its_hash
    #[test]
    fn a_name_search_finds_the_code_that_uses_its_hash() {
        let value = fnv(b"Inventory", 64, FnvVariant::V1a, None, None).unwrap();
        let mut code = vec![0x90u8; 8];
        code.extend([0x48, 0xB8]);
        code.extend(value.to_le_bytes());
        code.push(0xC3);
        code.extend([0x90u8; 8]);
        let mut data = vec![0u8; 16];
        data.extend(value.to_le_bytes());
        let sections = [
            SectionBytes { name: ".text".into(), virtual_address: 0x1000, raw: &code, executable: true },
            SectionBytes { name: ".data".into(), virtual_address: 0x2000, raw: &data, executable: false },
        ];
        let mut bounds = |rva: u64| (0x1000..0x1020).contains(&rva).then_some((0x1000, 0x1020));
        let (hits, truncated) = scan_constants(&sections, &[(value, 64)], 50, None, &mut bounds).unwrap();
        assert!(!truncated);
        let rows: Vec<_> = hits.iter().map(|h| (h.section.as_str(), h.rva, h.executable)).collect();
        assert_eq!(rows, [(".text", 0x100a, true), (".data", 0x2010, false)]);
        assert_eq!(hits[0].function, Some(0x1000));
        assert_eq!(hits[0].to_value()["context"], "code-immediate");
        let (one, truncated) = scan_constants(&sections, &[(value, 64)], 1, None, &mut bounds).unwrap();
        assert_eq!((one.len(), truncated), (1, true));
        // no pdata: the analysed function ranges name the function
        let mut none = |_: u64| None;
        let (hits, _) = scan_constants(&sections, &[(value, 64)], 50, Some(&[(0x1000, 0x1100)]), &mut none).unwrap();
        assert_eq!(hits[0].function, Some(0x1000));
    }

    #[test]
    fn overlapping_matches_are_all_found() {
        let raw = [0u8; 6];
        let sections = [SectionBytes { name: ".d".into(), virtual_address: 0, raw: &raw, executable: false }];
        let mut none = |_: u64| None;
        let (hits, _) = scan_constants(&sections, &[(0, 32)], 50, None, &mut none).unwrap();
        assert_eq!(hits.iter().map(|h| h.rva).collect::<Vec<_>>(), [0, 1, 2]);
    }
}
