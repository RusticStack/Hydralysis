//! Build fingerprint and the `# ...` header every tool answer starts with.

use sha2::{Digest, Sha256};

use crate::Image;

/// Same fields, same order, as the Python `Image.fingerprint()` dict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub exe: String,
    pub size: usize,
    pub time_date_stamp: String,
    pub sha256: String,
    pub image_base: String,
    pub machine: String,
    pub bits: u32,
    pub entry_point_rva: String,
    pub file_version: Option<String>,
    pub entry_point_section: Option<String>,
    pub analysis_warnings: Vec<String>,
    pub packing_status: String,
}

const PACKER_SECTIONS: [&str; 9] = [
    ".bind", "upx0", "upx1", "upx2", ".aspack", ".adata", ".vmp0", ".vmp1", ".themida",
];

/// Shannon entropy, summed in first-seen byte order like Python's `Counter`.
fn entropy(raw: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    let mut order: Vec<u8> = Vec::new();
    for &b in raw {
        if counts[b as usize] == 0 {
            order.push(b);
        }
        counts[b as usize] += 1;
    }
    let n = raw.len() as f64;
    let mut sum = 0.0f64;
    for b in order {
        let p = counts[b as usize] as f64 / n;
        sum += p * p.log2();
    }
    -sum
}

impl Image {
    pub fn fingerprint(&self) -> &Fingerprint {
        self.fingerprint.get_or_init(|| {
            let entry = u64::from(self.entry_point_rva);
            let mut warnings = Vec::new();
            let mut entry_section = None;
            for (i, s) in self.sections.iter().enumerate() {
                let start = u64::from(s.virtual_address);
                if start <= entry && entry < start + u64::from(s.virtual_size.max(s.size_of_raw_data)) {
                    entry_section = Some(i);
                }
                if PACKER_SECTIONS.contains(&s.name.to_lowercase().as_str()) {
                    warnings.push(format!("section {} is a known wrapper/packer indicator", s.name));
                }
            }
            match entry_section {
                None => warnings.push("entry point is outside the section table".to_string()),
                Some(i) => {
                    let s = &self.sections[i];
                    if s.characteristics & 0x2000_0000 == 0 {
                        warnings.push("entry point is in a non-executable section".to_string());
                    }
                    let data = self.section_data(s);
                    let raw = &data[..data.len().min(65536)];
                    if !raw.is_empty() {
                        let e = entropy(raw);
                        if e >= 7.5 {
                            warnings.push(format!(
                                "entry section entropy {:.2} bits/byte in first {} raw bytes; compressed/encrypted data is possible",
                                e,
                                raw.len()
                            ));
                        }
                    }
                }
            }
            let packing_status = if warnings.is_empty() {
                "no obvious indicators; not proof of unpacked code"
            } else {
                "suspected; indicators are not proof"
            };
            Fingerprint {
                exe: self.file_name().to_string(),
                size: self.data().len(),
                time_date_stamp: format!("{:#x}", self.time_date_stamp),
                sha256: hex(&Sha256::digest(self.data())),
                image_base: format!("{:#x}", self.base),
                machine: format!("{:#x}", self.machine),
                bits: self.bits,
                entry_point_rva: format!("{:#x}", self.entry_point_rva),
                file_version: self.file_version().filter(|v| !v.is_empty()),
                entry_point_section: entry_section.map(|i| self.sections[i].name.clone()),
                analysis_warnings: warnings,
                packing_status: packing_status.to_string(),
            }
        })
    }

    /// The `# exe ...` provenance header (`Image.header()`).
    pub fn header(&self) -> String {
        let info = self.fingerprint();
        let extra = info
            .file_version
            .as_ref()
            .map(|v| format!(" version {v}"))
            .unwrap_or_default();
        let mut line = format!(
            "# exe {} size {} tds {} sha256 {}{}",
            info.exe, info.size, info.time_date_stamp, info.sha256, extra
        );
        line.push_str(&format!(
            "\n# bits {} image_base {} entry_rva {}",
            info.bits, info.image_base, info.entry_point_rva
        ));
        line.push_str("\n# instruction/reference/string addresses are RVAs; pass them as rva:0x... to any Hydralysis tool");
        if let Some(evidence) = &self.address_resolution {
            line.push_str("\n# address map evidence: ");
            line.push_str(evidence);
        }
        if !info.analysis_warnings.is_empty() {
            line.push_str("\n# CAUTION: possible packed/wrapped or unusual image: ");
            line.push_str(&info.analysis_warnings.join("; "));
            line.push_str(". Verify the analysed project's executable SHA-256 before trusting decompiler text.");
        }
        line
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
