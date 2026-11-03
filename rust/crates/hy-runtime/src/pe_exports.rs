//! Minimal PE export lookup by name from a file image (any bitness), used to compute the RVA of the agent's entry.

fn u16at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// Returns `(rva_of_export, is_64bit)`.
pub fn find_export(image: &[u8], name: &str) -> Option<(u32, bool)> {
    let pe = u32at(image, 0x3c)? as usize;
    if image.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let nsec = u16at(image, pe + 6)? as usize;
    let opt_size = u16at(image, pe + 20)? as usize;
    let opt = pe + 24;
    let is64 = u16at(image, opt)? == 0x20b;
    let dd = opt + if is64 { 112 } else { 96 };
    let exp_rva = u32at(image, dd)?;
    let sec = opt + opt_size;
    let to_off = |rva: u32| -> Option<usize> {
        for i in 0..nsec {
            let s = sec + i * 40;
            let (vsize, va, raw_size, raw) = (u32at(image, s + 8)?, u32at(image, s + 12)?, u32at(image, s + 16)?, u32at(image, s + 20)?);
            if rva >= va && rva < va + vsize.max(raw_size) {
                return Some((rva - va + raw) as usize);
            }
        }
        None
    };
    let e = to_off(exp_rva)?;
    let nnames = u32at(image, e + 24)? as usize;
    let (funcs, names, ords) = (u32at(image, e + 28)?, u32at(image, e + 32)?, u32at(image, e + 36)?);
    let (f_off, n_off, o_off) = (to_off(funcs)?, to_off(names)?, to_off(ords)?);
    for i in 0..nnames {
        let no = to_off(u32at(image, n_off + 4 * i)?)?;
        let end = image[no..].iter().position(|&c| c == 0)? + no;
        if &image[no..end] == name.as_bytes() {
            let ord = u16at(image, o_off + 2 * i)? as usize;
            return Some((u32at(image, f_off + 4 * ord)?, is64));
        }
    }
    None
}

/// File offset of `rva` in a PE image, if a section maps it.
pub fn rva_to_offset(image: &[u8], rva: u32) -> Option<usize> {
    let pe = u32at(image, 0x3c)? as usize;
    let nsec = u16at(image, pe + 6)? as usize;
    let sec = pe + 24 + u16at(image, pe + 20)? as usize;
    for i in 0..nsec {
        let s = sec + i * 40;
        let (vsize, va, raw_size, raw) = (u32at(image, s + 8)?, u32at(image, s + 12)?, u32at(image, s + 16)?, u32at(image, s + 20)?);
        if rva >= va && rva < va + vsize.max(raw_size) {
            return Some((rva - va + raw) as usize);
        }
    }
    None
}

/// `len` bytes of the image at `rva` (what a probe's `expect` must equal).
pub fn bytes_at_rva(image: &[u8], rva: u32, len: usize) -> Option<&[u8]> {
    let o = rva_to_offset(image, rva)?;
    image.get(o..o + len)
}
