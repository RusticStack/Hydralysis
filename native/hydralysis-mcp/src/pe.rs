//! Offline PE reads, a port of hydralysis/pe.py (pefile `fast_load` semantics) for the well-formed images the native
//! tools handle. Anything this module would have to guess about (a malformed header, a layout pefile adjusts, an
//! ordinal import, a version resource it cannot parse the way pefile does) returns `None` or `Err(Delegate::at())`, and the
//! host answers that call through the Python worker instead, so the Python behaviour (and its error text) stays the
//! reference.

use sha2::{Digest, Sha256};
use std::cell::OnceCell;

/// The call must be answered by the Python implementation.
#[derive(Debug)]
pub struct Delegate;

impl Delegate {
    /// A delegation; with `HYDRALYSIS_MCP_TRACE` set the source line that gave up is written to stderr.
    #[track_caller]
    pub fn at() -> Delegate {
        if std::env::var_os("HYDRALYSIS_MCP_TRACE").is_some() {
            eprintln!(
                "hydralysis-mcp: delegated at pe.rs:{}",
                std::panic::Location::caller().line()
            );
        }
        Delegate
    }
}

pub type Res<T> = Result<T, Delegate>;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub va: u32,
    pub vsize: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub chars: u32,
    next_va: Option<u32>,
}

impl Section {
    pub fn executable(&self) -> bool {
        self.chars & 0x2000_0000 != 0
    }
}

#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub exe: String,
    pub size: usize,
    pub time_date_stamp: u32,
    pub sha256: String,
    pub image_base: u64,
    pub machine: u16,
    pub bits: u32,
    pub entry: u32,
    pub file_version: Option<String>,
    pub entry_section: Option<String>,
    pub warnings: Vec<String>,
}

pub struct Image {
    pub name: String,
    pub data: Vec<u8>,
    pub base: u64,
    pub machine: u16,
    pub bits: u32,
    pub timestamp: u32,
    pub entry: u32,
    pub sections: Vec<Section>,
    dirs: [(u32, u32); 16],
    /// Section and file alignment need no pefile adjustment (the only layout the pefile-based reads handle).
    strict: bool,
    fingerprint: OnceCell<Option<Fingerprint>>,
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

impl Image {
    /// Parse the headers, or `None` when pefile might see something this parser does not model.
    pub fn parse(name: String, data: Vec<u8>) -> Option<Image> {
        if data.len() < 0x40 || &data[..2] != b"MZ" {
            return None;
        }
        let pe = u32_at(&data, 0x3c)? as usize;
        if pe < 0x40 || data.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let machine = u16_at(&data, pe + 4)?;
        let count = u16_at(&data, pe + 6)? as usize;
        let timestamp = u32_at(&data, pe + 8)?;
        let optional_size = u16_at(&data, pe + 20)? as usize;
        let optional = pe + 24;
        let magic = u16_at(&data, optional)?;
        let (bits, base, entries_at, dirs_at, expected) = match magic {
            0x10b => (
                32,
                u32_at(&data, optional + 28)? as u64,
                optional + 92,
                optional + 96,
                224,
            ),
            0x20b => (
                64,
                u64_at(&data, optional + 24)?,
                optional + 108,
                optional + 112,
                240,
            ),
            _ => return None,
        };
        if optional_size != expected || u32_at(&data, entries_at)? != 16 || count == 0 || count > 96
        {
            return None;
        }
        let entry = u32_at(&data, optional + 16)?;
        let sect_align = u32_at(&data, optional + 32)?;
        let file_align = u32_at(&data, optional + 36)?;
        let mut dirs = [(0u32, 0u32); 16];
        for (index, slot) in dirs.iter_mut().enumerate() {
            *slot = (
                u32_at(&data, dirs_at + 8 * index)?,
                u32_at(&data, dirs_at + 8 * index + 4)?,
            );
        }
        let table = optional + optional_size;
        let mut sections: Vec<Section> = Vec::with_capacity(count);
        for index in 0..count {
            let at = table + 40 * index;
            let raw_name = data.get(at..at + 8)?;
            let end = raw_name
                .iter()
                .rposition(|byte| *byte != 0)
                .map_or(0, |last| last + 1);
            sections.push(Section {
                name: String::from_utf8(raw_name[..end].to_vec()).ok()?,
                vsize: u32_at(&data, at + 8)?,
                va: u32_at(&data, at + 12)?,
                raw_size: u32_at(&data, at + 16)?,
                raw_ptr: u32_at(&data, at + 20)?,
                chars: u32_at(&data, at + 36)?,
                next_va: None,
            });
        }
        for index in 0..count.saturating_sub(1) {
            sections[index].next_va = Some(sections[index + 1].va);
        }
        let strict = sect_align >= 0x1000
            && file_align >= 0x200
            && sections
                .iter()
                .all(|section| section.raw_ptr & 0x1ff == 0 && section.va & 0xfff == 0);
        Some(Image {
            name,
            data,
            base,
            machine,
            bits,
            timestamp,
            entry,
            sections,
            dirs,
            strict,
            fingerprint: OnceCell::new(),
        })
    }

    // ---- the reads of pe.py -------------------------------------------------------------------------------------

    pub fn rva_to_offset(&self, rva: u64) -> Option<usize> {
        for section in &self.sections {
            let start = u64::from(section.va);
            if start <= rva && rva < start + u64::from(section.raw_size) {
                let offset = rva - start + u64::from(section.raw_ptr);
                return if offset < self.data.len() as u64 {
                    Some(offset as usize)
                } else {
                    None
                };
            }
        }
        None
    }

    pub fn available(&self, rva: u64) -> usize {
        for section in &self.sections {
            let start = u64::from(section.va);
            if start <= rva && rva < start + u64::from(section.raw_size) {
                let relative = (rva - start) as i64;
                let by_section = i64::from(section.raw_size) - relative;
                let by_file = self.data.len() as i64 - i64::from(section.raw_ptr) - relative;
                return by_section.min(by_file).max(0) as usize;
            }
        }
        0
    }

    pub fn section_data(&self, section: &Section) -> &[u8] {
        let start = (section.raw_ptr as usize).min(self.data.len());
        let end = (start + section.raw_size as usize).min(self.data.len());
        &self.data[start..end]
    }

    /// `Image.read_rva`; `Err` is the ValueError of the Python version.
    pub fn read_rva(&self, rva: u64, size: usize) -> Result<&[u8], ()> {
        let offset = self.rva_to_offset(rva).ok_or(())?;
        if size > self.available(rva) {
            return Err(());
        }
        Ok(&self.data[offset..offset + size])
    }

    pub fn string_at(&self, rva: u64) -> Option<String> {
        let raw = self.read_rva(rva, 80.min(self.available(rva))).ok()?;
        let end = raw.iter().position(|byte| *byte == 0)?;
        if end < 4 {
            return None;
        }
        let text = &raw[..end];
        if text.iter().any(|byte| !(32..127).contains(byte)) {
            return None;
        }
        Some(String::from_utf8_lossy(text).into_owned())
    }

    pub fn executable_sections(&self) -> Vec<&Section> {
        let found: Vec<&Section> = self
            .sections
            .iter()
            .filter(|section| section.executable())
            .collect();
        if found.is_empty() {
            self.sections.iter().take(1).collect()
        } else {
            found
        }
    }

    // ---- fingerprint and header -----------------------------------------------------------------------------------

    /// The fingerprint, or `None` when the image needs the Python reader (a version resource that is not plain).
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        self.fingerprint
            .get_or_init(|| self.compute_fingerprint())
            .as_ref()
    }

    fn compute_fingerprint(&self) -> Option<Fingerprint> {
        let file_version = self.file_version().ok()?;
        let mut warnings = Vec::new();
        let mut entry_section: Option<&Section> = None;
        let entry = u64::from(self.entry);
        for section in &self.sections {
            let start = u64::from(section.va);
            if start <= entry && entry < start + u64::from(section.vsize.max(section.raw_size)) {
                entry_section = Some(section);
            }
            if matches!(
                section.name.to_lowercase().as_str(),
                ".bind"
                    | "upx0"
                    | "upx1"
                    | "upx2"
                    | ".aspack"
                    | ".adata"
                    | ".vmp0"
                    | ".vmp1"
                    | ".themida"
            ) {
                warnings.push(format!(
                    "section {} is a known wrapper/packer indicator",
                    section.name
                ));
            }
        }
        match entry_section {
            None => warnings.push("entry point is outside the section table".to_string()),
            Some(section) => {
                if !section.executable() {
                    warnings.push("entry point is in a non-executable section".to_string());
                }
                let raw =
                    &self.section_data(section)[..self.section_data(section).len().min(65536)];
                if !raw.is_empty() {
                    let entropy = entropy(raw);
                    if entropy >= 7.5 {
                        warnings.push(format!(
                            "entry section entropy {entropy:.2} bits/byte in first {} raw bytes; compressed/encrypted data is possible",
                            raw.len()
                        ));
                    }
                }
            }
        }
        Some(Fingerprint {
            exe: self.name.clone(),
            size: self.data.len(),
            time_date_stamp: self.timestamp,
            sha256: hex_digest(&self.data),
            image_base: self.base,
            machine: self.machine,
            bits: self.bits,
            entry: self.entry,
            file_version: file_version.filter(|text| !text.is_empty()),
            entry_section: entry_section.map(|section| section.name.clone()),
            warnings,
        })
    }

    /// pe.py `header()`.
    pub fn header(&self) -> Option<String> {
        let info = self.fingerprint()?;
        let mut line = format!(
            "# exe {} size {} tds {:#x} sha256 {}",
            info.exe, info.size, info.time_date_stamp, info.sha256
        );
        if let Some(version) = &info.file_version {
            line.push_str(" version ");
            line.push_str(version);
        }
        line.push_str(&format!(
            "\n# bits {} image_base {:#x} entry_rva {:#x}",
            info.bits, info.image_base, info.entry
        ));
        line.push_str("\n# instruction/reference/string addresses are RVAs; pass them as rva:0x... to any Hydralysis tool");
        if !info.warnings.is_empty() {
            line.push_str("\n# CAUTION: possible packed/wrapped or unusual image: ");
            line.push_str(&info.warnings.join("; "));
            line.push_str(". Verify the analysed project's executable SHA-256 before trusting decompiler text.");
        }
        Some(line)
    }

    /// `json.dumps(fingerprint(), indent=2)`.
    pub fn fingerprint_json(&self) -> Option<String> {
        use serde_json::{json, Map, Value};
        let info = self.fingerprint()?;
        let mut map = Map::new();
        map.insert("exe".into(), json!(info.exe));
        map.insert("size".into(), json!(info.size));
        map.insert(
            "timeDateStamp".into(),
            json!(format!("{:#x}", info.time_date_stamp)),
        );
        map.insert("sha256".into(), json!(info.sha256));
        map.insert(
            "image_base".into(),
            json!(format!("{:#x}", info.image_base)),
        );
        map.insert("machine".into(), json!(format!("{:#x}", info.machine)));
        map.insert("bits".into(), json!(info.bits));
        map.insert(
            "entry_point_rva".into(),
            json!(format!("{:#x}", info.entry)),
        );
        if let Some(version) = &info.file_version {
            map.insert("file_version".into(), json!(version));
        }
        if let Some(name) = &info.entry_section {
            map.insert("entry_point_section".into(), json!(name));
        }
        map.insert("analysis_warnings".into(), json!(info.warnings));
        let packing = if info.warnings.is_empty() {
            "no obvious indicators; not proof of unpacked code"
        } else {
            "suspected; indicators are not proof"
        };
        map.insert("packing_status".into(), json!(packing));
        Some(crate::pyjson::dumps_indent(&Value::Object(map)))
    }

    pub fn sections_text(&self) -> Option<String> {
        let mut lines = vec![self.header()?, format!("bits {}", self.bits)];
        for section in &self.sections {
            let mut marks = String::new();
            if section.chars & 0x2000_0000 != 0 {
                marks.push('x');
            }
            if section.chars & 0x4000_0000 != 0 {
                marks.push('r');
            }
            if section.chars & 0x8000_0000 != 0 {
                marks.push('w');
            }
            lines.push(format!(
                "{:<8} rva={:#x} vsize={:#x} raw={:#x} {}",
                section.name, section.va, section.vsize, section.raw_size, marks
            ));
        }
        Some(lines.join("\n"))
    }

    // ---- function, bytes, strings, sigscan, callers, xrefs --------------------------------------------------------

    fn bounds(&self, rva: u64) -> Res<Option<(u32, u32)>> {
        if self.machine != 0x8664 {
            return Ok(None);
        }
        let (dir_rva, dir_size) = self.dirs[3];
        if dir_rva == 0 || dir_size < 12 {
            return Ok(None);
        }
        let blob = self
            .read_rva(u64::from(dir_rva), dir_size as usize)
            .map_err(|()| Delegate::at())?;
        let (mut low, mut high) = (0usize, blob.len() / 12);
        while low < high {
            let mid = (low + high) / 2;
            let begin = u32_at(blob, mid * 12).ok_or_else(Delegate::at)?;
            let end = u32_at(blob, mid * 12 + 4).ok_or_else(Delegate::at)?;
            if rva < u64::from(begin) {
                high = mid;
            } else if rva >= u64::from(end) {
                low = mid + 1;
            } else {
                return Ok(Some((begin, end)));
            }
        }
        Ok(None)
    }

    pub fn function_of(&self, rva: u64) -> Res<String> {
        let header = self.header().ok_or_else(Delegate::at)?;
        match self.bounds(rva)? {
            None => {
                let (dir_rva, dir_size) = self.dirs[3];
                if dir_rva == 0 || dir_size < 12 {
                    return Err(Delegate::at());
                }
                Ok(format!("{header}\nno pdata function contains {rva:#x}"))
            }
            Some((begin, end)) => {
                let first = self
                    .read_rva(u64::from(begin), 32.min((end - begin) as usize))
                    .map_err(|()| Delegate::at())?;
                Ok(format!(
                    "{header}\nfunction {begin:#x}-{end:#x} size {:#x}\nprologue {}",
                    end - begin,
                    hex_bytes(first)
                ))
            }
        }
    }

    pub fn bytes_text(&self, rva: u64, size: usize) -> Res<String> {
        let header = self.header().ok_or_else(Delegate::at)?;
        let data = self.read_rva(rva, size).map_err(|()| Delegate::at())?;
        Ok(format!("{header}\n{}", hex_bytes(data)))
    }

    pub fn find_strings(&self, pattern: &regex::Regex, limit: usize) -> Res<String> {
        let mut lines = vec![self.header().ok_or_else(Delegate::at)?];
        let mut count = 0usize;
        for section in &self.sections {
            let raw = self.section_data(section);
            for wide in [false, true] {
                let mut index = 0usize;
                while index < raw.len() {
                    let Some((length, text)) = string_at(raw, index, wide) else {
                        index += 1;
                        continue;
                    };
                    let start = index;
                    index += length;
                    if !pattern.is_match(&text) {
                        continue;
                    }
                    let rva = u64::from(section.va) + start as u64;
                    let clipped = if text.len() > 512 {
                        format!("{} [text truncated]", &text[..512])
                    } else {
                        text
                    };
                    lines.push(format!(
                        "rva:{rva:#x} {} {clipped}",
                        if wide { "utf-16le" } else { "ascii" }
                    ));
                    count += 1;
                    if count >= limit {
                        lines.push("[limit reached; results may be incomplete]".to_string());
                        return Ok(lines.join("\n"));
                    }
                }
            }
        }
        if count == 0 {
            lines.push("(no match)".to_string());
        }
        Ok(lines.join("\n"))
    }

    pub fn sigscan(&self, pattern: &[Option<u8>], text: &str, limit: usize) -> Res<String> {
        if pattern.iter().all(Option::is_none) {
            return Err(Delegate::at());
        }
        let mut hits: Vec<String> = Vec::new();
        'sections: for section in self.executable_sections() {
            let raw = self.section_data(section);
            for offset in find_pattern(raw, pattern, limit - hits.len()) {
                hits.push(format!("rva:{:#x}", u64::from(section.va) + offset as u64));
                if hits.len() >= limit {
                    break 'sections;
                }
            }
        }
        let mut lines = vec![
            self.header().ok_or_else(Delegate::at)?,
            format!("{} hit(s) for {text}", hits.len()),
        ];
        let reached = hits.len() >= limit;
        lines.extend(hits);
        if reached {
            lines.push("[limit reached; results may be incomplete]".to_string());
        }
        Ok(lines.join("\n"))
    }

    pub fn callers(&self, target: u64, limit: usize) -> Res<String> {
        if self.machine != 0x14c && self.machine != 0x8664 {
            return Err(Delegate::at());
        }
        let mut hits: Vec<String> = Vec::new();
        'sections: for section in self.executable_sections() {
            let raw = self.section_data(section);
            for (index, byte) in raw.iter().enumerate() {
                if *byte != 0xe8 && *byte != 0xe9 {
                    continue;
                }
                if index + 5 > raw.len() {
                    continue;
                }
                let rel = i64::from(i32::from_le_bytes(
                    raw[index + 1..index + 5]
                        .try_into()
                        .map_err(|_| Delegate::at())?,
                ));
                let site = i64::from(section.va) + index as i64;
                let dest = site + 5 + rel;
                if dest == target as i64 {
                    let kind = if *byte == 0xe8 {
                        "E8 call candidate"
                    } else {
                        "E9 jump candidate"
                    };
                    hits.push(format!("rva:{site:#x} {kind} -> rva:{dest:#x}"));
                    if hits.len() >= limit {
                        break 'sections;
                    }
                }
            }
        }
        let mut lines = vec![
            self.header().ok_or_else(Delegate::at)?,
            format!("{} byte candidate(s) -> {target:#x}; instruction boundaries unverified; limit {limit}", hits.len()),
        ];
        let reached = hits.len() >= limit;
        lines.extend(hits);
        if reached {
            lines.push("[limit reached; results may be incomplete]".to_string());
        }
        Ok(lines.join("\n"))
    }

    pub fn xrefs(&self, target: u64, limit: usize) -> Res<String> {
        let header = self.header().ok_or_else(Delegate::at)?;
        let mut hits: Vec<String> = Vec::new();
        let label = if self.bits == 32 {
            let needle = u32::try_from(self.base + target)
                .map_err(|_| Delegate::at())?
                .to_le_bytes();
            'sections32: for section in self.sections.iter().filter(|section| section.executable())
            {
                let raw = self.section_data(section);
                let mut start = 0usize;
                while hits.len() < limit {
                    let Some(found) = raw[start.min(raw.len())..]
                        .windows(4)
                        .position(|window| window == needle)
                    else {
                        break;
                    };
                    let found = start + found;
                    hits.push(format!(
                        "rva:{:#x} -> rva:{target:#x}",
                        u64::from(section.va) + found as u64
                    ));
                    start = found + 1;
                }
                if hits.len() >= limit {
                    break 'sections32;
                }
            }
            format!("{} absolute byte candidate(s) -> {target:#x}; instruction boundaries unverified; limit {limit}", hits.len())
        } else {
            'sections64: for section in self.sections.iter().filter(|section| section.executable())
            {
                let raw = self.section_data(section);
                for index in 0..raw.len().saturating_sub(1) {
                    if !matches!(raw[index], 0x48 | 0x4c) || !matches!(raw[index + 1], 0x8d | 0x8b)
                    {
                        continue;
                    }
                    if index + 7 <= raw.len() && raw[index + 2] & 0xc7 == 0x05 {
                        let disp = i64::from(i32::from_le_bytes(
                            raw[index + 3..index + 7]
                                .try_into()
                                .map_err(|_| Delegate::at())?,
                        ));
                        let site = i64::from(section.va) + index as i64;
                        let dest = site + 7 + disp;
                        if dest == target as i64 {
                            hits.push(format!("rva:{site:#x} -> rva:{dest:#x}"));
                        }
                    }
                    if hits.len() >= limit {
                        break 'sections64;
                    }
                }
            }
            let text = self.string_at(target).unwrap_or_default();
            format!("{} RIP-relative byte candidate(s) -> {target:#x} {text}; instruction boundaries unverified; limit {limit}", hits.len())
        };
        let reached = hits.len() >= limit;
        let mut lines = vec![header, label];
        lines.extend(hits);
        if reached {
            lines.push("[limit reached; results may be incomplete]".to_string());
        }
        Ok(lines.join("\n"))
    }

    // ---- pefile-shaped reads: imports and the version resource -----------------------------------------------------

    /// pefile `get_section_by_rva`.
    fn pef_section(&self, rva: u64) -> Option<&Section> {
        for section in &self.sections {
            let start = u64::from(section.va);
            let mut size = if (self.data.len() as i64) - i64::from(section.raw_ptr)
                < i64::from(section.raw_size)
            {
                u64::from(section.vsize)
            } else {
                u64::from(section.vsize.max(section.raw_size))
            };
            if let Some(next) = section.next_va {
                if next > section.va && start + size > u64::from(next) {
                    size = u64::from(next) - start;
                }
            }
            if start <= rva && rva < start + size {
                return Some(section);
            }
        }
        None
    }

    /// pefile `get_data(rva, length)` for an RVA inside a section; `Err` for anything pefile would answer differently.
    fn pef_data(&self, rva: u64, length: u64) -> Res<&[u8]> {
        if !self.strict {
            return Err(Delegate::at());
        }
        let section = self.pef_section(rva).ok_or_else(Delegate::at)?;
        let offset = rva - u64::from(section.va) + u64::from(section.raw_ptr);
        let end = (offset + length).min(u64::from(section.raw_ptr) + u64::from(section.raw_size));
        let start = (offset as usize).min(self.data.len());
        let end = (end as usize).min(self.data.len());
        Ok(&self.data[start..end.max(start)])
    }

    /// pefile `get_offset_from_rva` for an RVA inside a section.
    fn rva_to_pef_offset(&self, rva: u64) -> Res<usize> {
        if !self.strict {
            return Err(Delegate::at());
        }
        let section = self.pef_section(rva).ok_or_else(Delegate::at)?;
        Ok((rva - u64::from(section.va) + u64::from(section.raw_ptr)) as usize)
    }

    fn pef_string(&self, rva: u64, max_length: u64) -> Res<Vec<u8>> {
        let data = self.pef_data(rva, max_length)?;
        let end = data
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(data.len());
        Ok(data[..end].to_vec())
    }

    /// The imports as `(slot rva, dll, name)`, in pefile's order.
    pub fn imports(&self) -> Res<Vec<(u64, String, String)>> {
        let (dir_rva, _) = self.dirs[1];
        let mut out = Vec::new();
        if dir_rva == 0 {
            return Ok(out);
        }
        let is64 = self.bits == 64;
        let (thunk_size, ordinal_flag) = if is64 {
            (8u64, 1u64 << 63)
        } else {
            (4u64, 1u64 << 31)
        };
        let mut total_symbols = 0u32;
        let mut rva = u64::from(dir_rva);
        loop {
            let descriptor = self.pef_data(rva, 20)?;
            if descriptor.len() < 20 {
                break;
            }
            if descriptor.iter().all(|byte| *byte == 0) {
                break;
            }
            let original_first = u64::from(u32_at(descriptor, 0).ok_or_else(Delegate::at)?);
            let name_rva = u64::from(u32_at(descriptor, 12).ok_or_else(Delegate::at)?);
            let first_thunk = u64::from(u32_at(descriptor, 16).ok_or_else(Delegate::at)?);
            let file_offset = self.rva_to_pef_offset(rva)?;
            rva += 20;
            // pefile bounds a table that lies before its descriptor by the distance back to it.
            let max_length: i64 = if rva > original_first || rva > first_thunk {
                (rva as i64 - original_first as i64).max(rva as i64 - first_thunk as i64)
            } else {
                self.data.len().saturating_sub(file_offset) as i64
            };
            let tables = [original_first, first_thunk]
                .into_iter()
                .map(|start| {
                    self.thunk_table(
                        start,
                        thunk_size,
                        ordinal_flag,
                        max_length,
                        &mut total_symbols,
                    )
                })
                .collect::<Res<Vec<_>>>()?;
            let table = if !tables[0].is_empty() {
                &tables[0]
            } else {
                &tables[1]
            };
            if table.is_empty() {
                return Err(Delegate::at());
            }
            let dll = self.pef_string(name_rva, 0x200)?;
            if dll.is_empty() {
                return Err(Delegate::at());
            }
            let dll = if dll.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || b"!#$%&'()-@^_`{}~+,.;=[]:\\/".contains(byte)
            }) {
                String::from_utf8(dll).map_err(|_| Delegate::at())?
            } else {
                "*invalid*".to_string()
            };
            for (index, entry) in table.iter().enumerate() {
                if entry & ordinal_flag != 0 || entry > &0x7fff_ffff {
                    return Err(Delegate::at());
                }
                let hint = self.pef_data(*entry, 2)?;
                if hint.len() < 2 {
                    return Err(Delegate::at());
                }
                let name = self.pef_string(*entry + 2, 0x200)?;
                let terminated = self.pef_data(*entry + 2, 0x200)?.contains(&0);
                if name.is_empty()
                    || !terminated
                    || !name
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._?@$()<>".contains(byte))
                {
                    return Err(Delegate::at());
                }
                out.push((
                    first_thunk + index as u64 * thunk_size,
                    dll.clone(),
                    String::from_utf8(name).map_err(|_| Delegate::at())?,
                ));
            }
        }
        Ok(out)
    }

    /// pefile `get_import_table` for a clean table (no ordinals, no repeated or overlapping entries); the entries.
    fn thunk_table(
        &self,
        start: u64,
        size: u64,
        ordinal_flag: u64,
        max_length: i64,
        total: &mut u32,
    ) -> Res<Vec<u64>> {
        let mut table = Vec::new();
        let mut rva = start;
        let mut seen = std::collections::HashSet::new();
        let mut repeated = 0u32;
        let (mut low, mut high) = (u64::MAX, 0u64);
        while rva != 0 {
            if rva as i64 >= start as i64 + max_length {
                return Err(Delegate::at());
            }
            if repeated >= 15 {
                return Err(Delegate::at());
            }
            *total += 1;
            if *total > 0x2000 {
                return Err(Delegate::at());
            }
            let thunk = self.pef_data(rva, size)?;
            if (thunk.len() as u64) != size {
                return Err(Delegate::at());
            }
            let entry = if size == 8 {
                u64_at(thunk, 0).ok_or_else(Delegate::at)?
            } else {
                u64::from(u32_at(thunk, 0).ok_or_else(Delegate::at)?)
            };
            if entry >= start && entry <= rva && entry != 0 {
                return Err(Delegate::at());
            }
            if entry != 0 {
                if entry & ordinal_flag != 0 {
                    return Err(Delegate::at());
                }
                if !seen.insert(entry) {
                    repeated += 1;
                }
                low = low.min(entry);
                high = high.max(entry);
                if high - low > 128 * 1024 * 1024 {
                    return Err(Delegate::at());
                }
            }
            if entry == 0 {
                break;
            }
            table.push(entry);
            rva += size;
        }
        Ok(table)
    }

    pub fn imports_text(&self, limit: usize, pattern: Option<&regex::Regex>) -> Res<String> {
        let imports = self.imports()?;
        let mut lines = vec![self.header().ok_or_else(Delegate::at)?];
        let mut count = 0usize;
        for (slot, dll, label) in imports {
            if pattern.is_some_and(|wanted| !wanted.is_match(&format!("{dll} {label}"))) {
                continue;
            }
            lines.push(format!("rva:{slot:#x} {dll} {label}"));
            count += 1;
            if count >= limit {
                lines.push("[limit reached; results may be incomplete]".to_string());
                return Ok(lines.join("\n"));
            }
        }
        if count == 0 {
            lines.push("(no imports)".to_string());
        }
        Ok(lines.join("\n"))
    }

    /// pe.py `_file_version`: the FileVersion (else ProductVersion) string of the version resource, or `""`.
    fn file_version(&self) -> Res<Option<String>> {
        let (dir_rva, _) = self.dirs[2];
        if dir_rva == 0 {
            return Ok(None);
        }
        let versions = self.version_resources(u64::from(dir_rva))?;
        let mut map: Vec<(String, String)> = Vec::new();
        for resource in versions {
            for (key, value) in resource {
                let lower = key.to_lowercase();
                if lower == "fileversion" || lower == "productversion" {
                    match map.iter_mut().find(|(name, _)| *name == lower) {
                        Some(slot) => slot.1 = value,
                        None => map.push((lower, value)),
                    }
                }
            }
        }
        if map.is_empty() {
            return Ok(Some(String::new()));
        }
        let pick = |name: &str| {
            map.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        Ok(Some(
            pick("fileversion")
                .or_else(|| pick("productversion"))
                .unwrap_or_default(),
        ))
    }

    /// For each RT_VERSION data entry, its string-table entries (`(key, value)` in table order).
    fn version_resources(&self, base: u64) -> Res<Vec<Vec<(String, String)>>> {
        let directory = |rva: u64| -> Res<(Vec<(u32, u32)>, u64)> {
            let header = self.pef_data(rva, 16)?;
            if header.len() < 16 {
                return Err(Delegate::at());
            }
            let total = u64::from(u16_at(header, 12).ok_or_else(Delegate::at)?)
                + u64::from(u16_at(header, 14).ok_or_else(Delegate::at)?);
            let mut entries = Vec::new();
            for index in 0..total {
                let raw = self.pef_data(rva + 16 + 8 * index, 8)?;
                if raw.len() < 8 {
                    return Err(Delegate::at());
                }
                entries.push((
                    u32_at(raw, 0).ok_or_else(Delegate::at)?,
                    u32_at(raw, 4).ok_or_else(Delegate::at)?,
                ));
            }
            Ok((entries, total))
        };
        let (root, _) = directory(base)?;
        let mut found = root.iter().filter(|(name, _)| name & 0xffff == 16);
        let Some(&(name, offset)) = found.next() else {
            return Ok(Vec::new());
        };
        if found.next().is_some() || name & 0x8000_0000 != 0 || offset & 0x8000_0000 == 0 {
            return Err(Delegate::at());
        }
        let (ids, _) = directory(base + u64::from(offset & 0x7fff_ffff))?;
        let Some(&(_, lang_offset)) = ids.first() else {
            return Err(Delegate::at());
        };
        if lang_offset & 0x8000_0000 == 0 {
            return Err(Delegate::at());
        }
        let (langs, _) = directory(base + u64::from(lang_offset & 0x7fff_ffff))?;
        let mut out = Vec::new();
        for (_, data_offset) in langs {
            if data_offset & 0x8000_0000 != 0 {
                return Err(Delegate::at());
            }
            let entry = self.pef_data(base + u64::from(data_offset), 16)?;
            if entry.len() < 16 {
                return Err(Delegate::at());
            }
            let (to_data, size) = (
                u32_at(entry, 0).ok_or_else(Delegate::at)?,
                u32_at(entry, 4).ok_or_else(Delegate::at)?,
            );
            out.push(self.parse_version_information(u64::from(to_data), u64::from(size))?);
        }
        Ok(out)
    }

    /// pefile `get_string_u_at_rva` restricted to ASCII text: the characters up to the first aligned UTF-16 NUL.
    fn pef_ustring(&self, rva: u64, max_length: u64) -> Res<Vec<u8>> {
        if max_length == 0 {
            return Ok(Vec::new());
        }
        let _ = self.pef_data(rva, 2)?;
        let max_bytes = (max_length << 1) as usize;
        let mut requested = max_bytes.min(256);
        let mut data = self.pef_data(rva, requested as u64)?.to_vec();
        let mut search_from = 0usize;
        let null_index;
        loop {
            let found = data
                .get(search_from..)
                .and_then(|rest| rest.windows(2).position(|pair| pair == [0, 0]))
                .map(|at| at + search_from);
            match found {
                None => {
                    if data.len() < requested || data.len() == max_bytes {
                        null_index = data.len() >> 1;
                        break;
                    }
                    let extra = self
                        .pef_data(rva + data.len() as u64, (max_bytes - data.len()) as u64)?
                        .to_vec();
                    data.extend_from_slice(&extra);
                    search_from = requested;
                    requested = max_bytes;
                }
                Some(at) if at % 2 == 0 => {
                    null_index = at >> 1;
                    break;
                }
                Some(at) => search_from = at + 1,
            }
        }
        // pefile maps every UTF-16 code unit to one character and encodes the text as UTF-8; a surrogate has no UTF-8
        // form (pefile has its own error handler for it), so those go to Python.
        let mut text = Vec::with_capacity(null_index);
        for index in 0..null_index {
            let unit = u16_at(&data, index * 2).ok_or_else(Delegate::at)?;
            let ch = char::from_u32(u32::from(unit)).ok_or_else(Delegate::at)?;
            let mut buffer = [0u8; 4];
            text.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
        }
        Ok(text)
    }

    fn parse_version_information(&self, to_data: u64, size: u64) -> Res<Vec<(String, String)>> {
        if !self.strict || !to_data.is_multiple_of(4) {
            return Err(Delegate::at());
        }
        let align =
            |offset: i64| -> i64 { ((offset + to_data as i64 + 3) & !3) - (to_data as i64 & !3) };
        let section = self.pef_section(to_data).ok_or_else(Delegate::at)?;
        let start = (to_data - u64::from(section.va) + u64::from(section.raw_ptr)) as usize;
        let raw = self.data.get(start..).unwrap_or(&[]);
        let raw = &raw[..raw.len().min(size as usize)];
        let header = |at: i64| -> Option<(u16, u16, u16)> {
            let at = usize::try_from(at).ok()?;
            Some((u16_at(raw, at)?, u16_at(raw, at + 2)?, u16_at(raw, at + 4)?))
        };
        let Some((info_length, _, _)) = header(0) else {
            return Ok(Vec::new());
        };
        let section_end = u64::from(section.va) + u64::from(section.raw_size.max(section.vsize));
        let ustr = to_data + 6;
        if ustr >= section_end {
            return Err(Delegate::at());
        }
        let name = self.pef_ustring(ustr, (section_end - ustr) >> 1)?;
        if name != b"VS_VERSION_INFO" {
            return Ok(Vec::new());
        }
        let fixed = align(6 + 2 * (name.len() as i64 + 1));
        if usize::try_from(fixed)
            .ok()
            .and_then(|at| raw.get(at..))
            .is_none_or(|rest| rest.len() < 52)
        {
            return Ok(Vec::new());
        }
        let mut offset = align(fixed + 52);
        let mut entries: Vec<(String, String)> = Vec::new();
        loop {
            let Some((length, value_length, kind)) = header(offset) else {
                return Ok(Vec::new());
            };
            let key = self.pef_ustring(to_data + offset as u64 + 6, 1 << 16)?;
            if key.starts_with(b"StringFileInfo") && (kind == 0 || kind == 1) && value_length == 0 {
                let mut table = align(offset + 6 + 2 * (key.len() as i64 + 1));
                while let Some((table_length, _, _)) = header(table) {
                    let lang = self.pef_ustring(to_data + table as u64 + 6, 1 << 16)?;
                    let mut entry = align(table + 6 + 2 * (lang.len() as i64 + 1));
                    while entry < table + i64::from(table_length) {
                        let Some((string_length, string_value_length, _)) = header(entry) else {
                            break;
                        };
                        let name = self.pef_ustring(to_data + entry as u64 + 6, 1 << 16)?;
                        let value_at = align(2 * (name.len() as i64 + 1) + entry + 6);
                        let value = self.pef_ustring(
                            to_data + value_at as u64,
                            u64::from(string_value_length),
                        )?;
                        entry = if string_length == 0 {
                            table + i64::from(table_length)
                        } else {
                            align(i64::from(string_length) + entry)
                        };
                        let name = String::from_utf8(name).map_err(|_| Delegate::at())?;
                        let value = String::from_utf8(value).map_err(|_| Delegate::at())?;
                        match entries.iter_mut().find(|(known, _)| *known == name) {
                            Some(slot) => slot.1 = value,
                            None => entries.push((name, value)),
                        }
                    }
                    let next = align(i64::from(table_length) + table);
                    if next == table {
                        break;
                    }
                    table = next;
                    if table >= i64::from(length) {
                        break;
                    }
                }
            }
            offset = align(i64::from(length) + offset);
            if length == 0 || offset >= i64::from(info_length) {
                break;
            }
        }
        Ok(entries)
    }
}

/// The string at `index` of a section's raw bytes (printable ASCII, or UTF-16LE of it), at least 4 characters.
fn string_at(raw: &[u8], index: usize, wide: bool) -> Option<(usize, String)> {
    let printable = |byte: u8| (0x20..=0x7e).contains(&byte);
    if wide {
        let mut length = 0usize;
        while index + length + 1 < raw.len()
            && printable(raw[index + length])
            && raw[index + length + 1] == 0
        {
            length += 2;
        }
        if length < 8 {
            return None;
        }
        let text = raw[index..index + length]
            .iter()
            .step_by(2)
            .map(|byte| *byte as char)
            .collect();
        Some((length, text))
    } else {
        let mut length = 0usize;
        while index + length < raw.len() && printable(raw[index + length]) {
            length += 1;
        }
        if length < 4 {
            return None;
        }
        Some((
            length,
            raw[index..index + length]
                .iter()
                .map(|byte| *byte as char)
                .collect(),
        ))
    }
}

/// prologue.py `find_pattern`: every offset where the concrete bytes match, in order, at most `limit`.
pub fn find_pattern(haystack: &[u8], pattern: &[Option<u8>], limit: usize) -> Vec<usize> {
    let mut hits = Vec::new();
    if pattern.is_empty() || limit == 0 || haystack.len() < pattern.len() {
        return hits;
    }
    let (anchor_at, anchor_byte) = pattern
        .iter()
        .enumerate()
        .find_map(|(at, byte)| byte.map(|byte| (at, byte)))
        .unwrap_or((0, 0));
    let last = haystack.len() - pattern.len();
    let mut start = 0usize;
    while start <= last {
        let Some(found) = haystack[start + anchor_at..=last + anchor_at]
            .iter()
            .position(|byte| *byte == anchor_byte)
        else {
            break;
        };
        let index = start + found;
        if pattern
            .iter()
            .enumerate()
            .all(|(at, byte)| byte.is_none_or(|byte| haystack[index + at] == byte))
        {
            hits.push(index);
            if hits.len() >= limit {
                break;
            }
        }
        start = index + 1;
    }
    hits
}

/// prologue.py `parse_expect`; `None` where Python would raise (the call is delegated).
pub fn parse_expect(text: &str) -> Option<Vec<Option<u8>>> {
    if !text.is_ascii() {
        return None;
    }
    let replaced = text
        .replace(',', " ")
        .replace("\\x", " ")
        .replace("\\X", " ");
    let mut out: Vec<Option<u8>> = Vec::new();
    let mut parts = 0;
    for part in replaced.split_ascii_whitespace() {
        parts += 1;
        if part == "?" || part == "??" {
            out.push(None);
            continue;
        }
        let part = part
            .strip_prefix("0x")
            .or_else(|| part.strip_prefix("0X"))
            .unwrap_or(part);
        if part.len() <= 2 && !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            out.push(Some(u8::from_str_radix(part, 16).ok()?));
            continue;
        }
        if part.is_empty() || part.len() % 2 != 0 {
            return None;
        }
        for pair in part.as_bytes().chunks(2) {
            if pair == b"??" {
                out.push(None);
            } else if pair.iter().all(u8::is_ascii_hexdigit) {
                out.push(Some(
                    u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?,
                ));
            } else {
                return None;
            }
        }
    }
    if parts == 0 || out.iter().all(Option::is_none) {
        return None;
    }
    Some(out)
}

/// A parsed address: the RVA it means, and for an unprefixed number the number itself.
pub struct Address {
    pub rva: u64,
    pub unprefixed: Option<u64>,
}

/// pe.py `parse_rva`; `None` where the text is not a plain `rva:`/`va:`/number address (Python decides those).
pub fn parse_rva(text: &str, base: u64) -> Option<Address> {
    let lowered = text.trim().to_lowercase();
    let (prefix, number) = match lowered.split_once(':') {
        Some((prefix, number)) => (prefix, number),
        None => ("", lowered.as_str()),
    };
    if !prefix.is_empty() && prefix != "rva" && prefix != "va" {
        return None;
    }
    let value: u64 = if let Some(hex) = number.strip_prefix("0x") {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) || hex.len() > 15 {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()?
    } else if number == "0"
        || (!number.starts_with('0')
            && !number.is_empty()
            && number.bytes().all(|byte| byte.is_ascii_digit())
            && number.len() <= 18)
    {
        number.parse().ok()?
    } else {
        return None;
    };
    let rva = match prefix {
        "rva" => value,
        "va" if value >= base => value - base,
        "va" => return None,
        _ if value >= base => value - base,
        _ => value,
    };
    Some(Address {
        rva,
        unprefixed: if prefix.is_empty() { Some(value) } else { None },
    })
}

fn entropy(raw: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    let mut order: Vec<u8> = Vec::new();
    for byte in raw {
        if counts[*byte as usize] == 0 {
            order.push(*byte);
        }
        counts[*byte as usize] += 1;
    }
    let total = raw.len() as f64;
    let mut sum = 0.0f64;
    for byte in order {
        let share = counts[byte as usize] as f64 / total;
        sum += share * share.log2();
    }
    -sum
}

pub fn hex_bytes(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    for (index, byte) in data.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

fn hex_digest(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
