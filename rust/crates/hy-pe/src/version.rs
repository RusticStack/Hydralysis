//! `VS_VERSION_INFO` string table: FileVersion / ProductVersion.

use crate::{Image, clamp, u16_at, u32_at};

fn align4(x: usize) -> usize {
    (x + 3) & !3
}

fn wstr(d: &[u8], off: usize) -> (String, usize) {
    let mut units = Vec::new();
    let mut o = off;
    while let Some(u) = u16_at(d, o) {
        o += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), o)
}

impl Image {
    /// `(file offset, size)` of every RT_VERSION leaf.
    fn version_blocks(&self) -> Vec<(usize, usize)> {
        let (rva, _size) = self.data_directory(2);
        let mut out = Vec::new();
        if rva == 0 {
            return out;
        }
        let Some(root) = self.map_rva_loose(u64::from(rva)) else {
            return out;
        };
        let d = self.data();
        let entries = |dir: usize| -> Vec<(u32, u32)> {
            let n = u16_at(d, dir + 12).unwrap_or(0) as usize + u16_at(d, dir + 14).unwrap_or(0) as usize;
            (0..n.min(256)).filter_map(|i| Some((u32_at(d, dir + 16 + i * 8)?, u32_at(d, dir + 20 + i * 8)?))).collect()
        };
        for (id, off) in entries(root) {
            if id != 16 || off & 0x8000_0000 == 0 {
                continue;
            }
            for (_, off2) in entries(root + (off & 0x7FFF_FFFF) as usize) {
                if off2 & 0x8000_0000 == 0 {
                    continue;
                }
                for (_, off3) in entries(root + (off2 & 0x7FFF_FFFF) as usize) {
                    if off3 & 0x8000_0000 != 0 {
                        continue;
                    }
                    let leaf = root + off3 as usize;
                    if let (Some(data_rva), Some(size)) = (u32_at(d, leaf), u32_at(d, leaf + 4))
                        && let Some(o) = self.map_rva_loose(u64::from(data_rva))
                    {
                        out.push((o, size as usize));
                    }
                }
            }
        }
        out
    }

    /// FileVersion, else ProductVersion (case-insensitive key, last duplicate wins).
    pub fn file_version(&self) -> Option<String> {
        let d = self.data();
        let (mut file, mut product) = (None, None);
        for (start, size) in self.version_blocks() {
            let block = clamp(d, start, size);
            let (key, after) = wstr(block, 6);
            if key != "VS_VERSION_INFO" {
                continue;
            }
            let value_len = u16_at(block, 2).unwrap_or(0) as usize;
            let mut p = align4(after + value_len);
            let total = u16_at(block, 0).unwrap_or(0) as usize;
            let end = total.min(block.len());
            while p + 6 <= end {
                let len = u16_at(block, p).unwrap_or(0) as usize;
                if len < 6 {
                    break;
                }
                let (name, after_name) = wstr(block, p + 6);
                if name.starts_with("StringFileInfo") {
                    let mut t = align4(after_name);
                    let info_end = (p + len).min(end);
                    while t + 6 <= info_end {
                        let tlen = u16_at(block, t).unwrap_or(0) as usize;
                        if tlen < 6 {
                            break;
                        }
                        let (_lang, after_lang) = wstr(block, t + 6);
                        let mut e = align4(after_lang);
                        let table_end = (t + tlen).min(info_end);
                        while e + 6 <= table_end {
                            let elen = u16_at(block, e).unwrap_or(0) as usize;
                            if elen < 6 {
                                break;
                            }
                            let (k, after_k) = wstr(block, e + 6);
                            let (v, _) = wstr(block, align4(after_k));
                            match k.to_lowercase().as_str() {
                                "fileversion" => file = Some(v),
                                "productversion" => product = Some(v),
                                _ => {}
                            }
                            e = align4(e + elen);
                        }
                        t = align4(t + tlen);
                    }
                }
                p = align4(p + len);
            }
        }
        file.or(product)
    }
}
