//! Zero-copy PE32 / PE32+ reader.
//!
//! Replaces the `pefile` usage of `hydralysis/pe.py`. The file is memory-mapped (or borrowed from a `Vec`) and
//! every accessor slices it in place. Semantics follow the Python `Image` class exactly (first-matching-section
//! RVA lookup, file-backed reads only, clamped raw slices) so the tool text built on top is byte-identical.

mod fingerprint;
mod imports;
mod ordlookup;
mod version;

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

pub use fingerprint::Fingerprint;
pub use imports::{Export, Import};

/// Errors. `Value` carries the exact `ValueError` text the Python tools raise.
#[derive(Debug, thiserror::Error)]
pub enum PeError {
    #[error("{0}")]
    Value(String),
    /// Python `OverflowError` (an address that does not fit the 4-byte needle).
    #[error("{0}")]
    Overflow(String),
    #[error("not a PE file: {0}")]
    Format(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, PeError>;

pub(crate) fn value<T>(msg: impl Into<String>) -> Result<T> {
    Err(PeError::Value(msg.into()))
}

pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

enum Bytes {
    Map(Mmap),
    Owned(Vec<u8>),
}

impl Bytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            Bytes::Map(m) => m,
            Bytes::Owned(v) => v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    /// Name with trailing NULs removed, decoded lossily as UTF-8 (Python `decode("utf-8", "replace")`).
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn is_executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }
}

pub struct Image {
    file_name: String,
    bytes: Bytes,
    pub base: u64,
    pub machine: u16,
    pub bits: u32,
    pub time_date_stamp: u32,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub sections: Vec<Section>,
    /// Index of the last `.text` section, else of the first section.
    pub text: usize,
    dirs: Vec<(u32, u32)>,
    fingerprint: std::sync::OnceLock<Fingerprint>,
    relocs: std::sync::OnceLock<Vec<(u32, u8)>>,
    /// JSON text of `_address_resolution` evidence (set by the caller; printed in the header).
    pub address_resolution: Option<String>,
}

pub(crate) fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o.checked_add(2)?)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}
pub(crate) fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o.checked_add(4)?)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
pub(crate) fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o.checked_add(8)?)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Python `data[start:start+len]`: clamped, never panics.
pub(crate) fn clamp(d: &[u8], start: usize, len: usize) -> &[u8] {
    let s = start.min(d.len());
    let e = start.saturating_add(len).min(d.len());
    &d[s..e]
}

impl Image {
    /// Memory-map `path` and parse the headers. The mapping stays valid for the life of the `Image`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        // SAFETY: the map is read-only; callers must not truncate the file while an Image is alive
        // (same contract as any mmap reader; Python read the whole file instead).
        let map = unsafe { Mmap::map(&file)? };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self::parse(name, Bytes::Map(map))
    }

    pub fn from_vec(file_name: impl Into<String>, data: Vec<u8>) -> Result<Self> {
        Self::parse(file_name.into(), Bytes::Owned(data))
    }

    fn parse(file_name: String, bytes: Bytes) -> Result<Self> {
        let d = bytes.as_slice();
        let trunc = || PeError::Format("truncated headers".into());
        if d.get(..2) != Some(b"MZ") {
            return Err(PeError::Format("DOS Header magic not found.".into()));
        }
        let e_lfanew = u32_at(d, 0x3C).ok_or_else(trunc)? as usize;
        if d.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
            return Err(PeError::Format("PE Signature not found".into()));
        }
        let fh = e_lfanew + 4;
        let machine = u16_at(d, fh).ok_or_else(trunc)?;
        let nsec = u16_at(d, fh + 2).ok_or_else(trunc)? as usize;
        let time_date_stamp = u32_at(d, fh + 4).ok_or_else(trunc)?;
        let opt_size = u16_at(d, fh + 16).ok_or_else(trunc)? as usize;
        let opt = fh + 20;
        let magic = u16_at(d, opt).ok_or_else(trunc)?;
        let bits = if magic == 0x10B { 32 } else { 64 };
        let entry_point_rva = u32_at(d, opt + 16).ok_or_else(trunc)?;
        let (base, ndirs_off, dirs_off) = if magic == 0x20B {
            (u64_at(d, opt + 24).ok_or_else(trunc)?, opt + 108, opt + 112)
        } else {
            (
                u64::from(u32_at(d, opt + 28).ok_or_else(trunc)?),
                opt + 92,
                opt + 96,
            )
        };
        let size_of_image = u32_at(d, opt + 56).ok_or_else(trunc)?;
        let size_of_headers = u32_at(d, opt + 60).ok_or_else(trunc)?;
        let ndirs = (u32_at(d, ndirs_off).ok_or_else(trunc)? as usize).min(16);
        let mut dirs = Vec::with_capacity(16);
        for i in 0..ndirs {
            let o = dirs_off + i * 8;
            match (u32_at(d, o), u32_at(d, o + 4)) {
                (Some(a), Some(b)) => dirs.push((a, b)),
                _ => break,
            }
        }
        let sec_table = opt + opt_size;
        let mut sections = Vec::with_capacity(nsec);
        for i in 0..nsec.min(96) {
            let o = sec_table + i * 40;
            let Some(raw) = d.get(o..o + 40) else { break };
            let mut name_bytes = &raw[..8];
            while let [rest @ .., 0] = name_bytes {
                name_bytes = rest;
            }
            let g = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
            sections.push(Section {
                name: String::from_utf8_lossy(name_bytes).into_owned(),
                virtual_size: g(8),
                virtual_address: g(12),
                size_of_raw_data: g(16),
                pointer_to_raw_data: g(20),
                characteristics: g(36),
            });
        }
        if sections.is_empty() {
            return value("PE has no sections");
        }
        // Python's loop keeps the LAST ".text"; without one it falls back to the first section.
        let text = sections
            .iter()
            .rposition(|s| s.name == ".text")
            .unwrap_or(0);
        Ok(Self {
            file_name,
            bytes,
            base,
            machine,
            bits,
            time_date_stamp,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            sections,
            text,
            dirs,
            fingerprint: std::sync::OnceLock::new(),
            relocs: std::sync::OnceLock::new(),
            address_resolution: None,
        })
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// The whole file.
    pub fn data(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn data_directory(&self, index: usize) -> (u32, u32) {
        self.dirs.get(index).copied().unwrap_or((0, 0))
    }

    /// Raw bytes of a section, clamped to the file (Python `data[ptr:ptr+size]`).
    pub fn section_data(&self, s: &Section) -> &[u8] {
        clamp(
            self.data(),
            s.pointer_to_raw_data as usize,
            s.size_of_raw_data as usize,
        )
    }

    /// Sections with the execute bit, or the first section when none has it.
    pub fn executable_sections(&self) -> Vec<&Section> {
        let found: Vec<&Section> = self.sections.iter().filter(|s| s.is_executable()).collect();
        if found.is_empty() {
            self.sections.iter().take(1).collect()
        } else {
            found
        }
    }

    /// File offset of `rva`, only inside the raw (file-backed) part of the first section that contains it.
    pub fn rva_to_offset(&self, rva: i64) -> Option<usize> {
        for s in &self.sections {
            let start = i64::from(s.virtual_address);
            let size = i64::from(s.size_of_raw_data);
            if start <= rva && rva < start + size {
                let offset = rva - start + i64::from(s.pointer_to_raw_data);
                return (0 <= offset && (offset as usize) < self.data().len())
                    .then_some(offset as usize);
            }
        }
        None
    }

    /// Bytes readable from `rva` before leaving the file-backed section.
    pub fn available(&self, rva: i64) -> usize {
        let len = self.data().len() as i64;
        for s in &self.sections {
            let relative = rva - i64::from(s.virtual_address);
            if 0 <= relative && relative < i64::from(s.size_of_raw_data) {
                let a = i64::from(s.size_of_raw_data) - relative;
                let b = len - i64::from(s.pointer_to_raw_data) - relative;
                return a.min(b).max(0) as usize;
            }
        }
        0
    }

    /// `read_rva`: errors carry the Python `ValueError` texts.
    pub fn read_rva(&self, rva: i64, size: i64) -> Result<&[u8]> {
        if rva < 0 || size < 0 {
            return value("RVA and size must be non-negative");
        }
        let Some(offset) = self.rva_to_offset(rva) else {
            return value(format!(
                "rva {:#x} is not in a section of {}",
                rva, self.file_name
            ));
        };
        if size as usize > self.available(rva) {
            return value(format!(
                "read at rva {:#x} size {:#x} crosses the file-backed section boundary",
                rva, size
            ));
        }
        Ok(clamp(self.data(), offset, size as usize))
    }

    /// Printable-ASCII C string of at least 4 characters at `rva` (`Image.string_at`).
    pub fn string_at(&self, rva: i64) -> Option<String> {
        self.string_at_limit(rva, 80)
    }

    pub fn string_at_limit(&self, rva: i64, limit: usize) -> Option<String> {
        let want = limit.min(self.available(rva)) as i64;
        let raw = self.read_rva(rva, want).ok()?;
        let end = raw.iter().position(|&b| b == 0)?;
        if end < 4 {
            return None;
        }
        let text = &raw[..end];
        if text.iter().any(|b| !(32..127).contains(b)) {
            return None;
        }
        Some(String::from_utf8_lossy(text).into_owned())
    }

    /// Every base relocation `(rva, width)` sorted; parsed once.
    fn relocations(&self) -> &[(u32, u8)] {
        self.relocs.get_or_init(|| {
            let (rva, size) = self.data_directory(5);
            let mut found = Vec::new();
            if rva != 0
                && size != 0
                && let Some(off) = self.map_rva_loose(u64::from(rva))
            {
                {
                    let d = self.data();
                    let end = off.saturating_add(size as usize).min(d.len());
                    let mut p = off;
                    while p + 8 <= end {
                        let page = u32_at(d, p).unwrap_or(0);
                        let blk = u32_at(d, p + 4).unwrap_or(0) as usize;
                        if blk < 8 {
                            break;
                        }
                        let stop = (p + blk).min(end);
                        let mut e = p + 8;
                        while e + 2 <= stop {
                            let w = u16_at(d, e).unwrap_or(0);
                            let (ty, off12) = (w >> 12, u32::from(w & 0xFFF));
                            match ty {
                                3 => found.push((page.wrapping_add(off12), 4)),
                                10 => found.push((page.wrapping_add(off12), 8)),
                                _ => {}
                            }
                            e += 2;
                        }
                        p += blk;
                    }
                }
            }
            found.sort_unstable();
            found
        })
    }

    /// File bytes as the loader leaves them at `load_base`: base relocations applied.
    pub fn loaded_bytes(&self, rva: i64, size: i64, load_base: u64) -> Result<Vec<u8>> {
        let delta = load_base.wrapping_sub(self.base);
        let mut data = self.read_rva(rva, size)?.to_vec();
        if delta == 0 {
            return Ok(data);
        }
        let relocs = self.relocations();
        let from = relocs.partition_point(|&(r, w)| (i64::from(r), i64::from(w)) < (rva - 8, 0));
        for &(at, width) in &relocs[from..] {
            let at = i64::from(at);
            if at >= rva + size {
                break;
            }
            if at + i64::from(width) <= rva {
                continue;
            }
            let word = self.read_rva(at, i64::from(width))?;
            let mut v = 0u64;
            for (i, b) in word.iter().enumerate() {
                v |= u64::from(*b) << (8 * i);
            }
            let v = if width == 4 {
                u64::from((v as u32).wrapping_add(delta as u32))
            } else {
                v.wrapping_add(delta)
            };
            let fixed = v.to_le_bytes();
            for (i, byte) in fixed.iter().enumerate().take(width as usize) {
                let pos = at + i as i64;
                if rva <= pos && pos < rva + size {
                    data[(pos - rva) as usize] = *byte;
                }
            }
        }
        Ok(data)
    }

    /// Lenient RVA -> file offset for directory structures (header region maps 1:1, then section ranges).
    pub(crate) fn map_rva_loose(&self, rva: u64) -> Option<usize> {
        for s in &self.sections {
            let start = u64::from(s.virtual_address);
            let span = u64::from(s.size_of_raw_data.max(s.virtual_size));
            if start <= rva && rva < start + span {
                let off = (rva - start + u64::from(s.pointer_to_raw_data & !0x1FF)) as usize;
                return (off < self.data().len()).then_some(off);
            }
        }
        (rva < u64::from(self.size_of_headers) && (rva as usize) < self.data().len())
            .then_some(rva as usize)
    }

    /// NUL-terminated bytes at `rva` (at most `max`), via the loose mapping.
    pub(crate) fn c_bytes_at(&self, rva: u64, max: usize) -> Option<&[u8]> {
        let off = self.map_rva_loose(rva)?;
        let s = clamp(self.data(), off, max);
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        Some(&s[..end])
    }

    /// pdata RUNTIME_FUNCTION `(begin, end, unwind)` at `index` of the exception-directory blob.
    pub fn runtime_function(blob: &[u8], index: usize) -> (u32, u32, u32) {
        let o = index * 12;
        (
            u32_at(blob, o).unwrap_or(0),
            u32_at(blob, o + 4).unwrap_or(0),
            u32_at(blob, o + 8).unwrap_or(0),
        )
    }

    /// `[begin, end)` of the pdata function containing `rva`, x64 images only.
    pub fn function_bounds(&self, rva: i64) -> Result<Option<(u32, u32)>> {
        if self.machine != 0x8664 {
            return Ok(None);
        }
        let (dir_rva, dir_size) = self.data_directory(3);
        if dir_rva == 0 || dir_size < 12 {
            return Ok(None);
        }
        let blob = self.read_rva(i64::from(dir_rva), i64::from(dir_size))?;
        let (mut lo, mut hi) = (0usize, blob.len() / 12);
        while lo < hi {
            let mid = usize::midpoint(lo, hi);
            let (begin, end, _) = Self::runtime_function(blob, mid);
            if rva < i64::from(begin) {
                hi = mid;
            } else if rva >= i64::from(end) {
                lo = mid + 1;
            } else {
                return Ok(Some((begin, end)));
            }
        }
        Ok(None)
    }

    /// Does the image have a usable exception directory (>= 12 bytes)?
    pub fn has_exception_directory(&self) -> bool {
        let (rva, size) = self.data_directory(3);
        !(rva == 0 || size < 12)
    }
}
