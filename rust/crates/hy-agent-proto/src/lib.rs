//! Layout of the shared section the host creates and the injected agent fills.
//!
//! Section name: `Local\hy_agent_<pid>`. Layout: a 4 KiB header, then `MAX_RINGS` rings. Every field is
//! little-endian and naturally aligned; the agent and the host are always the same architecture family
//! (an x86 agent in an x86 target still uses 64-bit fields here).

pub const MAGIC: u64 = 0x4859_5f41_4745_4e54;
pub const HEADER_SIZE: usize = 4096;
pub const MAX_RINGS: usize = 64;
pub const RING_RECS: usize = 1 << 14;
pub const REC_SIZE: usize = 32;
/// head at +0 (owner writes), dropped counter at +8, tid at +12; tail at +64 (host writes); records from +128.
pub const RING_HDR: usize = 128;
pub const RING_SIZE: usize = RING_HDR + RING_RECS * REC_SIZE;
pub const SECTION_SIZE: usize = HEADER_SIZE + MAX_RINGS * RING_SIZE;

// Header offsets.
pub const H_MAGIC: usize = 0; // u64
pub const H_STATUS: usize = 8; // u32: 0 starting, 1 ready, 2 failed
pub const H_NEXT_RING: usize = 12; // u32 atomic claim counter
pub const H_ERROR: usize = 16; // u32 failure code
pub const H_NO_RING: usize = 20; // u32 hits from threads that found no free ring
pub const H_NSITES: usize = 24; // u32 host -> agent: number of site requests
pub const H_SITES: usize = 64; // [SiteReq; nsites]
pub const SITE_REQ_SIZE: usize = 16; // u64 rva, u32 expect_len, u32 flags (expect bytes follow in H_EXPECT)
pub const H_EXPECT: usize = 1024; // expected prologue bytes, 16 per site

pub const REC_KIND_HIT: u16 = 1;

pub fn ring_offset(index: usize) -> usize {
    HEADER_SIZE + index * RING_SIZE
}

/// One hit record (32 bytes): tsc, tid, site, kind, arg0, ret_addr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rec {
    pub tsc: u64,
    pub tid: u32,
    pub site: u16,
    pub kind: u16,
    pub arg0: u64,
    pub ret: u64,
}

impl Rec {
    pub fn encode(&self, out: &mut [u8; REC_SIZE]) {
        out[0..8].copy_from_slice(&self.tsc.to_le_bytes());
        out[8..12].copy_from_slice(&self.tid.to_le_bytes());
        out[12..14].copy_from_slice(&self.site.to_le_bytes());
        out[14..16].copy_from_slice(&self.kind.to_le_bytes());
        out[16..24].copy_from_slice(&self.arg0.to_le_bytes());
        out[24..32].copy_from_slice(&self.ret.to_le_bytes());
    }
    pub fn decode(b: &[u8; REC_SIZE]) -> Rec {
        let u64at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Rec {
            tsc: u64at(0),
            tid: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            site: u16::from_le_bytes(b[12..14].try_into().unwrap()),
            kind: u16::from_le_bytes(b[14..16].try_into().unwrap()),
            arg0: u64at(16),
            ret: u64at(24),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rec_roundtrip() {
        let r = Rec {
            tsc: 1,
            tid: 2,
            site: 3,
            kind: 1,
            arg0: 4,
            ret: 5,
        };
        let mut b = [0u8; REC_SIZE];
        r.encode(&mut b);
        assert_eq!(Rec::decode(&b), r);
    }
}
