//! PE-side tool bodies: the text-producing methods of `hydralysis.pe.Image`.
//!
//! Every function returns the exact string the Python method returns (header line first), or the
//! `ValueError` text as `PeError::Value`.

use std::fmt::Write as _;

use hy_disasm::Decoder;
use hy_pe::{Image, PeError, Result, Section};

use crate::prologue::{find_pattern, parse_expect};

const LIMIT_MSG: &str = "[limit reached; results may be incomplete]";

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(PeError::Value(msg.into()))
}

/// Python `"%#x" % n` (negative values print as `-0x..`).
pub fn hex(n: i128) -> String {
    if n < 0 { format!("-{:#x}", -n) } else { format!("{n:#x}") }
}

fn decoder(img: &Image) -> Result<Decoder> {
    if img.machine != 0x14C && img.machine != 0x8664 {
        return err(format!("instruction decoding supports x86/x64 only; PE machine is {:#x}", img.machine));
    }
    Decoder::new(img.bits).map_err(|e| PeError::Value(e.to_string()))
}

fn join(lines: Vec<String>) -> String {
    lines.join("\n")
}

/// `_rip_note`: annotate a RIP-relative operand with its target and any string there.
fn rip_note(img: &Image, address: u64, size: usize, op_str: &str) -> String {
    let Some((_, after)) = op_str.split_once("rip") else {
        return String::new();
    };
    let disp_text: String = after.split(']').next().unwrap_or("").chars().filter(|c| *c != ' ').collect();
    let (neg, digits) = match disp_text.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, disp_text.strip_prefix('+').unwrap_or(&disp_text)),
    };
    let digits = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")).unwrap_or(digits);
    let Ok(mut disp) = i128::from_str_radix(digits, 16) else {
        return String::new();
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') {
        return String::new();
    }
    if neg {
        disp = -disp;
    }
    let dest = i128::from(address) + size as i128 + disp;
    let text = i64::try_from(dest).ok().and_then(|d| img.string_at(d));
    let mut note = format!("  ; -> rva:{}", hex(dest));
    if let Some(t) = text {
        let _ = write!(note, " \"{t}\"");
    }
    note
}

pub fn disasm(img: &Image, rva: i64, count: i64) -> Result<String> {
    let md = decoder(img)?;
    if count <= 0 {
        return err("instruction count must be positive");
    }
    let want = (count.saturating_mul(16)).min(img.available(rva) as i64);
    let blob = img.read_rva(rva, want)?;
    let mut lines = vec![img.header()];
    let insns = md.decode(blob, rva as u64, count as usize).map_err(|e| PeError::Value(e.to_string()))?;
    if insns.is_empty() {
        lines.push(format!("(no instructions at {})", hex(i128::from(rva))));
    }
    for i in &insns {
        let note = rip_note(img, i.address, i.size, &i.op_str);
        lines.push(format!("rva:{:#010x}: {} {}{}", i.address, i.mnemonic, i.op_str, note));
    }
    Ok(join(lines))
}

fn limit_cmp(len: usize, limit: i64) -> bool {
    len as i64 >= limit
}

pub fn callers(img: &Image, target: i64, limit: i64) -> Result<String> {
    decoder(img)?;
    let mut hits: Vec<String> = Vec::new();
    'outer: for section in img.executable_sections() {
        let raw = img.section_data(section);
        let mut index = 0usize;
        while index < raw.len() {
            let Some(rel_pos) = raw[index..].iter().position(|&b| b == 0xE8 || b == 0xE9) else {
                break;
            };
            index += rel_pos;
            if index + 5 <= raw.len() {
                let rel = i32::from_le_bytes(raw[index + 1..index + 5].try_into().unwrap());
                let site = i64::from(section.virtual_address) + index as i64;
                let dest = site + 5 + i64::from(rel);
                if dest == target {
                    let kind = if raw[index] == 0xE8 { "E8 call candidate" } else { "E9 jump candidate" };
                    hits.push(format!("rva:{} {kind} -> rva:{}", hex(site.into()), hex(dest.into())));
                    if limit_cmp(hits.len(), limit) {
                        break 'outer;
                    }
                }
            }
            index += 1;
        }
    }
    let mut lines = vec![
        img.header(),
        format!("{} byte candidate(s) -> {}; instruction boundaries unverified; limit {}", hits.len(), hex(target.into()), limit),
    ];
    lines.extend(hits.iter().cloned());
    if limit_cmp(hits.len(), limit) {
        lines.push(LIMIT_MSG.to_string());
    }
    Ok(join(lines))
}

pub fn xrefs(img: &Image, target: i64, limit: i64) -> Result<String> {
    if img.bits == 32 {
        return xrefs_abs(img, target, limit);
    }
    let mut hits: Vec<String> = Vec::new();
    'outer: for section in img.sections.iter().filter(|s| s.is_executable()) {
        let raw = img.section_data(section);
        let base = i64::from(section.virtual_address);
        let mut i = 0usize;
        while i + 1 < raw.len() {
            if (raw[i] == 0x48 || raw[i] == 0x4C) && (raw[i + 1] == 0x8D || raw[i + 1] == 0x8B) {
                if i + 7 <= raw.len() && (raw[i + 2] & 0xC7) == 0x05 {
                    let disp = i32::from_le_bytes(raw[i + 3..i + 7].try_into().unwrap());
                    let site = base + i as i64;
                    let dest = site + 7 + i64::from(disp);
                    if dest == target {
                        hits.push(format!("rva:{} -> rva:{}", hex(site.into()), hex(dest.into())));
                    }
                    if limit_cmp(hits.len(), limit) {
                        break 'outer;
                    }
                }
                i += 2;
            } else {
                i += 1;
            }
        }
    }
    let text = img.string_at(target).unwrap_or_default();
    let mut lines = vec![
        img.header(),
        format!(
            "{} RIP-relative byte candidate(s) -> {} {}; instruction boundaries unverified; limit {}",
            hits.len(),
            hex(target.into()),
            text,
            limit
        ),
    ];
    lines.extend(hits.iter().cloned());
    if limit_cmp(hits.len(), limit) {
        lines.push(LIMIT_MSG.to_string());
    }
    Ok(join(lines))
}

fn xrefs_abs(img: &Image, target: i64, limit: i64) -> Result<String> {
    let abs = img.base as i128 + i128::from(target);
    let Ok(abs) = u32::try_from(abs) else {
        return Err(PeError::Overflow(if abs < 0 { "can't convert negative int to unsigned" } else { "int too big to convert" }.into()));
    };
    let needle = abs.to_le_bytes();
    let finder = memchr::memmem::Finder::new(&needle);
    let mut hits: Vec<String> = Vec::new();
    for section in img.sections.iter().filter(|s| s.is_executable()) {
        let raw = img.section_data(section);
        let mut start = 0usize;
        while (hits.len() as i64) < limit {
            let Some(found) = raw.get(start..).and_then(|w| finder.find(w)).map(|f| f + start) else {
                break;
            };
            hits.push(format!("rva:{} -> rva:{}", hex((i64::from(section.virtual_address) + found as i64).into()), hex(target.into())));
            start = found + 1;
        }
    }
    let mut lines = vec![
        img.header(),
        format!("{} absolute byte candidate(s) -> {}; instruction boundaries unverified; limit {}", hits.len(), hex(target.into()), limit),
    ];
    lines.extend(hits.iter().cloned());
    if limit_cmp(hits.len(), limit) {
        lines.push(LIMIT_MSG.to_string());
    }
    Ok(join(lines))
}

fn printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// ASCII runs of >= 4 printable bytes (regex `[\x20-\x7e]{4,}`), as `(start, end)`.
fn ascii_runs(raw: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if printable(raw[i]) {
            let s = i;
            while i < raw.len() && printable(raw[i]) {
                i += 1;
            }
            if i - s >= 4 {
                out.push((s, i));
            }
        } else {
            i += 1;
        }
    }
    out
}

/// UTF-16LE ASCII runs (regex `(?:[\x20-\x7e]\x00){4,}`), unaligned, leftmost non-overlapping.
fn wide_runs(raw: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < raw.len() {
        let mut k = 0;
        while i + 2 * k + 1 < raw.len() && printable(raw[i + 2 * k]) && raw[i + 2 * k + 1] == 0 {
            k += 1;
        }
        if k >= 4 {
            out.push((i, i + 2 * k));
            i += 2 * k;
        } else {
            i += 1;
        }
    }
    out
}

pub fn find_strings(img: &Image, pattern: &str, limit: i64) -> Result<String> {
    let regex = regex::Regex::new(pattern).map_err(|e| PeError::Value(e.to_string()))?;
    let mut lines = vec![img.header()];
    let mut count = 0i64;
    for section in &img.sections {
        let raw = img.section_data(section);
        for encoding in ["ascii", "utf-16le"] {
            let runs = if encoding == "ascii" { ascii_runs(raw) } else { wide_runs(raw) };
            for (s, e) in runs {
                let text: String = if encoding == "ascii" {
                    String::from_utf8_lossy(&raw[s..e]).into_owned()
                } else {
                    raw[s..e].iter().step_by(2).map(|&b| b as char).collect()
                };
                if !regex.is_match(&text) {
                    continue;
                }
                let rva = i64::from(section.virtual_address) + s as i64;
                let chars = text.chars().count();
                let clipped = if chars > 512 { format!("{} [text truncated]", text.chars().take(512).collect::<String>()) } else { text };
                lines.push(format!("rva:{rva:#x} {encoding} {clipped}"));
                count += 1;
                if count >= limit {
                    lines.push(LIMIT_MSG.to_string());
                    return Ok(join(lines));
                }
            }
        }
    }
    if count == 0 {
        lines.push("(no match)".to_string());
    }
    Ok(join(lines))
}

fn marks(s: &Section) -> String {
    let mut m = String::new();
    if s.characteristics & 0x2000_0000 != 0 {
        m.push('x');
    }
    if s.characteristics & 0x4000_0000 != 0 {
        m.push('r');
    }
    if s.characteristics & 0x8000_0000 != 0 {
        m.push('w');
    }
    m
}

pub fn sections_text(img: &Image) -> String {
    let mut lines = vec![img.header(), format!("bits {}", img.bits)];
    for s in &img.sections {
        lines.push(format!(
            "{:<8} rva={:#x} vsize={:#x} raw={:#x} {}",
            s.name,
            s.virtual_address,
            s.virtual_size,
            s.size_of_raw_data,
            marks(s)
        ));
    }
    join(lines)
}

pub fn imports_text(img: &Image, limit: i64, pattern: &str) -> Result<String> {
    let wanted = if pattern.is_empty() {
        None
    } else {
        Some(regex::RegexBuilder::new(pattern).case_insensitive(true).build().map_err(|e| PeError::Value(e.to_string()))?)
    };
    let mut lines = vec![img.header()];
    let mut count = 0i64;
    for imp in img.imports() {
        let label = match &imp.name {
            Some(n) => n.clone(),
            None => format!("ord:{}", imp.ordinal.unwrap_or(0)),
        };
        if let Some(re) = &wanted
            && !re.is_match(&format!("{} {}", imp.dll, label))
        {
            continue;
        }
        lines.push(format!("rva:{:#x} {} {}", imp.slot_rva, imp.dll, label));
        count += 1;
        if count >= limit {
            lines.push(LIMIT_MSG.to_string());
            return Ok(join(lines));
        }
    }
    if count == 0 {
        lines.push("(no imports)".to_string());
    }
    Ok(join(lines))
}

pub fn exports_text(img: &Image, limit: i64) -> String {
    let mut lines = vec![img.header()];
    let symbols = img.exports();
    if symbols.is_empty() {
        lines.push("(no exports)".to_string());
        return join(lines);
    }
    let mut count = 0i64;
    for item in symbols {
        let name = item.name.unwrap_or_else(|| format!("ord:{}", item.ordinal));
        lines.push(format!("rva:{:#x} {}", item.address, name));
        count += 1;
        if count >= limit {
            break;
        }
    }
    if count >= limit {
        lines.push(LIMIT_MSG.to_string());
    }
    join(lines)
}

pub fn sigscan(img: &Image, pattern: &str, limit: i64) -> Result<String> {
    let expect = parse_expect(pattern)?;
    let mut hits: Vec<String> = Vec::new();
    for section in img.executable_sections() {
        let raw = img.section_data(section);
        let room = (limit - hits.len() as i64).max(0) as usize;
        for offset in find_pattern(raw, &expect, room)? {
            hits.push(format!("rva:{:#x}", i64::from(section.virtual_address) + offset as i64));
            if limit_cmp(hits.len(), limit) {
                break;
            }
        }
        if limit_cmp(hits.len(), limit) {
            break;
        }
    }
    let mut lines = vec![img.header(), format!("{} hit(s) for {}", hits.len(), pattern)];
    lines.extend(hits.iter().cloned());
    if limit_cmp(hits.len(), limit) {
        lines.push(LIMIT_MSG.to_string());
    }
    Ok(join(lines))
}

pub fn callees(img: &Image, rva: i64, limit: i64) -> Result<String> {
    let md = decoder(img)?;
    let (begin, end, scope) = match img.function_bounds(rva)? {
        None => (
            rva,
            rva + (0x200usize).min(img.available(rva)) as i64,
            format!("no pdata; linear decode from caller-supplied start {} (unverified), at most 0x200 bytes", hex(rva.into())),
        ),
        Some((b, e)) => (i64::from(b), i64::from(e), format!("function {:#x}-{:#x}", b, e)),
    };
    let blob = img.read_rva(begin, (end - begin).max(0))?;
    let mut hits: Vec<String> = Vec::new();
    for insn in md.decode(blob, begin as u64, usize::MAX).map_err(|e| PeError::Value(e.to_string()))? {
        if let Some(target) = insn.direct_call {
            hits.push(format!("rva:{:#x} call rva:{}", insn.address, hex(target.into())));
            if limit_cmp(hits.len(), limit) {
                break;
            }
        }
    }
    let mut lines = vec![
        img.header(),
        scope,
        format!("{} decoded direct call(s); linear decode is not a complete control-flow graph; limit {}", hits.len(), limit),
    ];
    lines.extend(hits.iter().cloned());
    if limit_cmp(hits.len(), limit) {
        lines.push(LIMIT_MSG.to_string());
    }
    Ok(join(lines))
}

pub fn function_of(img: &Image, rva: i64) -> Result<String> {
    let found = img.function_bounds(rva)?;
    let mut lines = vec![img.header()];
    let Some((begin, end)) = found else {
        if !img.has_exception_directory() {
            return err("this exe has no exception directory; function bounds need pdata");
        }
        lines.push(format!("no pdata function contains {}", hex(rva.into())));
        return Ok(join(lines));
    };
    let first = img.read_rva(i64::from(begin), i64::from((end - begin).min(32)))?;
    lines.push(format!("function {:#x}-{:#x} size {:#x}", begin, end, end - begin));
    lines.push(format!("prologue {}", crate::prologue::format_bytes(first)));
    Ok(join(lines))
}

/// A section of a combined answer without the repeated image header.
fn body(text: &str) -> String {
    text.lines().filter(|l| !l.starts_with('#')).collect::<Vec<_>>().join("\n")
}

pub fn inspect(img: &Image, rva: i64) -> Result<String> {
    let first = if img.function_bounds(rva)?.is_some() {
        function_of(img, rva)?
    } else {
        format!(
            "{}\nno pdata function contains rva:{}; use ghidra_query action=function for analysed bounds",
            img.header(),
            hex(rva.into())
        )
    };
    Ok(join(vec![
        first,
        disasm(img, rva, 16)?,
        "--- call candidates ---".to_string(),
        body(&callers(img, rva, 12)?),
        "--- data references ---".to_string(),
        body(&xrefs(img, rva, 12)?),
    ]))
}
