//! Port of `hydralysis/prologue.py`: expect-prologue parsing, wildcard matching, anchor search, table compare.

use hy_pe::{Image, PeError, Result};
use serde_json::{Map, Value, json};

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(PeError::Value(msg.into()))
}

/// A byte or a wildcard (`??` / `?`).
pub type Expect = Vec<Option<u8>>;

fn is_hex_run(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `parse_expect`: whitespace/comma/`\x` separated bytes, `0x` prefixes, packed hex runs, `?`/`??` wildcards.
pub fn parse_expect(text: &str) -> Result<Expect> {
    let cleaned = text
        .replace(',', " ")
        .replace("\\x", " ")
        .replace("\\X", " ");
    let parts: Vec<&str> = cleaned.split_whitespace().collect();
    if parts.is_empty() {
        return err("expect prologue is empty");
    }
    let mut out: Expect = Vec::new();
    for part in parts {
        if part == "?" || part == "??" {
            out.push(None);
            continue;
        }
        let part = part
            .strip_prefix("0x")
            .or_else(|| part.strip_prefix("0X"))
            .unwrap_or(part);
        if part.len() <= 2 && is_hex_run(part) {
            out.push(Some(u8::from_str_radix(part, 16).unwrap()));
            continue;
        }
        let bytes = part.as_bytes();
        let mut ok = !part.is_empty() && part.len() % 2 == 0 && part.is_ascii();
        if ok {
            for pair in bytes.chunks(2) {
                if !(pair == b"??" || pair.iter().all(u8::is_ascii_hexdigit)) {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            return err(format!(
                "prologue requires whole hexadecimal bytes or ?? wildcards: {part}"
            ));
        }
        for pair in bytes.chunks(2) {
            out.push(if pair == b"??" {
                None
            } else {
                Some(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            });
        }
    }
    if out.iter().all(Option::is_none) {
        return err("expect prologue must contain at least one concrete byte");
    }
    Ok(out)
}

pub fn format_bytes(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn matches(data: &[u8], expect: &[Option<u8>]) -> bool {
    if expect.is_empty() || expect.iter().all(Option::is_none) || data.len() < expect.len() {
        return false;
    }
    expect
        .iter()
        .enumerate()
        .all(|(i, want)| want.is_none_or(|w| data[i] == w))
}

/// `find_pattern`: all start offsets (first `limit`) of `pattern` in `haystack`, anchored on its longest literal run.
pub fn find_pattern(haystack: &[u8], pattern: &[Option<u8>], limit: usize) -> Result<Vec<usize>> {
    if pattern.is_empty() || limit == 0 {
        return Ok(Vec::new());
    }
    if pattern.iter().all(Option::is_none) {
        return err("signature must contain at least one concrete byte");
    }
    let (mut anchor_start, mut anchor): (usize, Vec<u8>) = (0, Vec::new());
    let (mut run_start, mut run): (usize, Vec<u8>) = (0, Vec::new());
    for (i, v) in pattern
        .iter()
        .copied()
        .chain(std::iter::once(None))
        .enumerate()
    {
        match v {
            None => {
                if run.len() > anchor.len() {
                    anchor_start = run_start;
                    anchor = std::mem::take(&mut run);
                }
                run.clear();
            }
            Some(b) => {
                if run.is_empty() {
                    run_start = i;
                }
                run.push(b);
            }
        }
    }
    let concrete: Vec<(usize, u8)> = pattern
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.map(|b| (i, b)))
        .collect();
    let mut hits = Vec::new();
    let stop =
        haystack.len() as i64 - pattern.len() as i64 + anchor_start as i64 + anchor.len() as i64;
    let mut start = anchor_start as i64;
    let finder = memchr::memmem::Finder::new(&anchor);
    while start <= stop - anchor.len() as i64 {
        let window = &haystack[start as usize..stop as usize];
        let Some(rel) = finder.find(window) else {
            break;
        };
        let found = start as usize + rel;
        let index = found - anchor_start;
        if concrete.iter().all(|&(o, v)| haystack[index + o] == v) {
            hits.push(index);
            if hits.len() >= limit {
                break;
            }
        }
        start = found as i64 + 1;
    }
    Ok(hits)
}

/// Fingerprint dict as ordered JSON (same key order as the Python dict).
pub fn fingerprint_json(image: &Image) -> Value {
    let f = image.fingerprint();
    let mut m = Map::new();
    m.insert("exe".into(), json!(f.exe));
    m.insert("size".into(), json!(f.size));
    m.insert("timeDateStamp".into(), json!(f.time_date_stamp));
    m.insert("sha256".into(), json!(f.sha256));
    m.insert("image_base".into(), json!(f.image_base));
    m.insert("machine".into(), json!(f.machine));
    m.insert("bits".into(), json!(f.bits));
    m.insert("entry_point_rva".into(), json!(f.entry_point_rva));
    if let Some(v) = &f.file_version {
        m.insert("file_version".into(), json!(v));
    }
    if let Some(v) = &f.entry_point_section {
        m.insert("entry_point_section".into(), json!(v));
    }
    m.insert("analysis_warnings".into(), json!(f.analysis_warnings));
    m.insert("packing_status".into(), json!(f.packing_status));
    Value::Object(m)
}

/// `compare_table`: verify bounded rows against an open PE; never modifies bytes.
pub fn compare_table(
    image: &Image,
    rows: &Value,
    resolve_address: &mut dyn FnMut(&str) -> std::result::Result<i64, String>,
) -> Result<Value> {
    let Some(rows) = rows.as_array().filter(|r| (1..=200).contains(&r.len())) else {
        return err("prologue table needs 1..200 rows");
    };
    struct Prepared {
        name: String,
        address: String,
        rva: i64,
        patterns: Vec<Expect>,
    }
    let mut prepared = Vec::new();
    let mut total = 0usize;
    for (index, row) in rows.iter().enumerate() {
        let Some(obj) = row.as_object().filter(|o| {
            o.keys()
                .all(|k| matches!(k.as_str(), "address" | "expect" | "name"))
        }) else {
            return err(format!(
                "prologue row {index} accepts address, expect and optional name only"
            ));
        };
        let address = obj
            .get("address")
            .and_then(Value::as_str)
            .filter(|a| !a.trim().is_empty() && a.chars().count() <= 128);
        let Some(address) = address else {
            return err(format!("prologue row {index} needs an address string"));
        };
        let alternatives: Vec<&Value> = match obj.get("expect") {
            Some(Value::Array(a)) => a.iter().collect(),
            Some(v) => vec![v],
            None => vec![&Value::Null],
        };
        let strs: Option<Vec<&str>> = alternatives
            .iter()
            .map(|v| v.as_str().filter(|s| s.chars().count() <= 32768))
            .collect();
        let strs = match strs {
            Some(s) if (1..=16).contains(&s.len()) => s,
            _ => {
                return err(format!(
                    "prologue row {index} needs an expect string or a list of 1..16 accepted alternatives"
                ));
            }
        };
        let name = match obj.get("name") {
            None => "",
            Some(Value::String(s)) if s.chars().count() <= 256 => s.as_str(),
            _ => {
                return err(format!(
                    "prologue row {index} name must be at most 256 characters"
                ));
            }
        };
        let patterns: Vec<Expect> = strs
            .iter()
            .map(|s| parse_expect(s))
            .collect::<Result<_>>()?;
        let longest = patterns.iter().map(Vec::len).max().unwrap_or(0);
        if longest > 4096 {
            return err(format!("prologue row {index} exceeds 4096 bytes"));
        }
        total += patterns.iter().map(Vec::len).sum::<usize>();
        if total > 65536 {
            return err("prologue table exceeds 65536 total bytes");
        }
        let rva = resolve_address(address).map_err(PeError::Value)?;
        if rva < 0 {
            return err(format!("prologue row {index} resolved to an invalid RVA"));
        }
        if image.rva_to_offset(rva).is_none() || longest > image.available(rva) {
            return err(format!(
                "prologue row {index} is outside a file-backed section"
            ));
        }
        prepared.push(Prepared {
            name: name.to_string(),
            address: address.to_string(),
            rva,
            patterns,
        });
    }
    let fingerprint = fingerprint_json(image);
    let mut results = Vec::new();
    let mut matched = 0usize;
    for p in &prepared {
        let longest = p.patterns.iter().map(Vec::len).max().unwrap_or(0);
        let actual = image.read_rva(p.rva, longest as i64)?;
        let which = p.patterns.iter().position(|pat| matches(actual, pat));
        matched += usize::from(which.is_some());
        let show = |pat: &Expect| {
            pat.iter()
                .map(|v| v.map_or("??".to_string(), |b| format!("{b:02X}")))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let mut row = Map::new();
        row.insert("name".into(), json!(p.name));
        row.insert("input_address".into(), json!(p.address));
        row.insert("rva".into(), json!(format!("rva:{:#x}", p.rva)));
        row.insert(
            "va".into(),
            json!(format!("va:{:#x}", image.base + p.rva as u64)),
        );
        row.insert(
            "expect".into(),
            if p.patterns.len() > 1 {
                json!(p.patterns.iter().map(show).collect::<Vec<_>>())
            } else {
                json!(show(&p.patterns[0]))
            },
        );
        row.insert("actual".into(), json!(format_bytes(actual)));
        row.insert("match".into(), json!(which.is_some()));
        if p.patterns.len() > 1 {
            row.insert("matched_alternative".into(), json!(which));
        }
        results.push(Value::Object(row));
    }
    let mut out = Map::new();
    out.insert("fingerprint".into(), fingerprint);
    out.insert("rows".into(), Value::Array(results));
    out.insert(
        "summary".into(),
        json!({"checked": prepared.len(), "matched": matched, "failed": prepared.len() - matched}),
    );
    out.insert("matched".into(), json!(matched == prepared.len()));
    Ok(Value::Object(out))
}

/// `compare`: one-line match/mismatch text.
pub fn compare(data: &[u8], expect_text: &str) -> Result<String> {
    let expect = parse_expect(expect_text)?;
    let got = &data[..data.len().min(expect.len())];
    Ok(if matches(got, &expect) {
        format!("PROLOGUE MATCH {}", format_bytes(got))
    } else {
        format!(
            "PROLOGUE MISMATCH expect {expect_text} got {}",
            format_bytes(got)
        )
    })
}

/// `parse_rva`: `rva:` / `va:` prefixed or bare, VAs reduced by the image base.
pub fn parse_rva(text: &str, image_base: u64) -> Result<i64> {
    let lower = text.trim().to_lowercase();
    let (prefix, rest) = match lower.split_once(':') {
        Some((p, r)) => {
            if p != "rva" && p != "va" {
                return err("address prefix must be rva: or va:");
            }
            (p, r)
        }
        None => ("", lower.as_str()),
    };
    // Python int(text, 0): 0x/0o/0b prefixes, decimal otherwise, optional sign and underscores
    let rest = rest.trim();
    let (neg, digits) = match rest.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, rest.strip_prefix('+').unwrap_or(rest)),
    };
    let digits = digits.replace('_', "");
    let parsed = if let Some(h) = digits.strip_prefix("0x") {
        i128::from_str_radix(h, 16)
    } else if let Some(o) = digits.strip_prefix("0o") {
        i128::from_str_radix(o, 8)
    } else if let Some(b) = digits.strip_prefix("0b") {
        i128::from_str_radix(b, 2)
    } else {
        digits.parse::<i128>()
    };
    let Ok(mut value) = parsed else {
        return err(format!("invalid literal for int() with base 0: '{rest}'"));
    };
    if neg {
        value = -value;
    }
    if value < 0 {
        return err("address must be non-negative");
    }
    let base = i128::from(image_base);
    let out = match prefix {
        "rva" => value,
        "va" => {
            if value < base {
                return err("VA is below this image's base");
            }
            value - base
        }
        _ => {
            if value >= base {
                value - base
            } else {
                value
            }
        }
    };
    i64::try_from(out).map_err(|_| PeError::Value("address out of range".into()))
}
