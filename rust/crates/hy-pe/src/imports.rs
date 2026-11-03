//! Import / export directory parsing (the pefile subset the tools print).

use crate::{Image, clamp, u16_at, u32_at, u64_at};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub dll: String,
    /// `Some(name)`, or `None` for an import by ordinal.
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    /// RVA of the IAT slot (`FirstThunk + idx * pointer size`).
    pub slot_rva: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub ordinal: u32,
    pub address: u32,
    pub name: Option<String>,
}

const MAX_NAME: usize = 0x200;

fn valid_function_name(s: &[u8], relaxed: bool) -> bool {
    let extra: &[u8] = if relaxed {
        b"!\"#$%&'()*+,-./:<>?[\\]^_`{|}~@"
    } else {
        b"._?@$()<>"
    };
    s.iter()
        .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

fn valid_dos_filename(s: &[u8]) -> bool {
    s.iter()
        .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'()-@^_`{}~+,.;=[]\\/ ".contains(c))
}

impl Image {
    /// Imports in directory order. Descriptors without usable entries are skipped like pefile does.
    pub fn imports(&self) -> Vec<Import> {
        let (dir_rva, _size) = self.data_directory(1);
        let mut out = Vec::new();
        if dir_rva == 0 {
            return out;
        }
        let d = self.data();
        let ptr = if self.bits == 64 { 8usize } else { 4 };
        let ord_flag: u64 = if self.bits == 64 { 1 << 63 } else { 1 << 31 };
        let mut rva = u64::from(dir_rva);
        let mut errors = 0;
        while let Some(off) = self.map_rva_loose(rva) {
            let Some(desc) = d.get(off..off + 20) else {
                break;
            };
            if desc.iter().all(|&b| b == 0) {
                break;
            }
            let g = |i: usize| u32::from_le_bytes(desc[i..i + 4].try_into().unwrap());
            let (oft, name_rva, ft) = (g(0), g(12), g(16));
            rva += 20;
            let mut cursor = u64::from(if oft != 0 { oft } else { ft });
            let mut entries: Vec<(Option<String>, Option<u16>, u64)> = Vec::new();
            let mut idx = 0u64;
            while cursor != 0 {
                let Some(toff) = self.map_rva_loose(cursor) else {
                    break;
                };
                let thunk = if ptr == 8 {
                    u64_at(d, toff)
                } else {
                    u32_at(d, toff).map(u64::from)
                };
                let Some(thunk) = thunk else { break };
                if thunk == 0 {
                    break;
                }
                let slot = u64::from(ft) + idx * ptr as u64;
                idx += 1;
                cursor += ptr as u64;
                if thunk & ord_flag != 0 {
                    if thunk & 0x7FFF_FFFF > 0xFFFF {
                        entries.clear();
                        break;
                    }
                    entries.push((None, Some((thunk & 0xFFFF) as u16), slot));
                } else {
                    let hint_name = thunk
                        & if ptr == 8 {
                            0x7FFF_FFFF_FFFF_FFFF
                        } else {
                            0x7FFF_FFFF
                        };
                    if self
                        .map_rva_loose(hint_name)
                        .and_then(|o| u16_at(d, o))
                        .is_none()
                    {
                        break;
                    }
                    let name = self.c_bytes_at(hint_name + 2, MAX_NAME).unwrap_or(b"");
                    if !valid_function_name(name, false) {
                        continue;
                    }
                    entries.push((Some(String::from_utf8_lossy(name).into_owned()), None, slot));
                }
            }
            if entries.is_empty() {
                errors += 1;
                if errors > 5 {
                    break;
                }
                continue;
            }
            let mut dll = self
                .c_bytes_at(u64::from(name_rva), MAX_NAME)
                .unwrap_or(b"")
                .to_vec();
            if !valid_dos_filename(&dll) {
                dll = b"*invalid*".to_vec();
            }
            if dll.is_empty() {
                continue;
            }
            let dll = String::from_utf8_lossy(&dll).into_owned();
            for (mut name, ordinal, slot_rva) in entries {
                if name.is_none()
                    && let Some(o) = ordinal
                {
                    name = crate::ordlookup::lookup(&dll, o);
                }
                out.push(Import {
                    dll: dll.clone(),
                    name,
                    ordinal,
                    slot_rva,
                });
            }
        }
        out
    }

    /// Exports: named entries in name-table order, then unnamed ordinals (pefile order).
    pub fn exports(&self) -> Vec<Export> {
        let (rva, _size) = self.data_directory(0);
        let mut out = Vec::new();
        if rva == 0 {
            return out;
        }
        let d = self.data();
        let Some(off) = self.map_rva_loose(u64::from(rva)) else {
            return out;
        };
        let Some(h) = d.get(off..off + 40) else {
            return out;
        };
        let g = |i: usize| u32::from_le_bytes(h[i..i + 4].try_into().unwrap());
        let (base, nfunc, nnames, aof, aon, aoo) = (g(16), g(20), g(24), g(28), g(32), g(36));
        let slice = |r: u32, count: u32, width: usize| -> Option<&[u8]> {
            let o = self.map_rva_loose(u64::from(r))?;
            Some(clamp(d, o, (count as usize).saturating_mul(width)))
        };
        let (Some(names), Some(ords), Some(funcs)) = (
            slice(aon, nnames, 4),
            slice(aoo, nnames, 2),
            slice(aof, nfunc, 4),
        ) else {
            return out;
        };
        let mut named = std::collections::HashSet::new();
        for i in 0..nnames as usize {
            let Some(ordinal) = u16_at(ords, i * 2) else {
                break;
            };
            if (ordinal as usize) * 4 >= funcs.len() {
                return Vec::new();
            }
            let address = u32_at(funcs, ordinal as usize * 4).unwrap_or(0);
            if address == 0 {
                continue;
            }
            let Some(name_rva) = u32_at(names, i * 4) else {
                continue;
            };
            let name = self
                .c_bytes_at(u64::from(name_rva), MAX_NAME)
                .unwrap_or(b"");
            if !valid_function_name(name, true) {
                break;
            }
            named.insert(base.wrapping_add(u32::from(ordinal)));
            out.push(Export {
                ordinal: base.wrapping_add(u32::from(ordinal)),
                address,
                name: Some(String::from_utf8_lossy(name).into_owned()),
            });
        }
        for idx in 0..nfunc {
            if named.contains(&base.wrapping_add(idx)) {
                continue;
            }
            let Some(address) = u32_at(funcs, idx as usize * 4) else {
                break;
            };
            if address == 0 {
                continue;
            }
            out.push(Export {
                ordinal: base.wrapping_add(idx),
                address,
                name: None,
            });
        }
        out
    }
}
