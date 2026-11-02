//! Layout of the shared section the host creates and the injected agent fills (version 2).
//!
//! Section name `Local\hy_agent_<pid>`. Little-endian, naturally aligned.
//!
//! ```text
//! 0x00000  header           (status, counters, clock calibration)
//! 0x00100  site table       MAX_SITES x SITE_SIZE   host writes the request, agent writes state / error
//! 0x04400  mailbox          control command / response
//! 0x04800  pause slots      MAX_PAUSE x PAUSE_SIZE  breakpoint parking
//! 0x06800  event ring       EVENT_SLOTS x EVENT_SIZE  watch hits, breakpoint hits, auto-continues
//! 0x0A800  watch table      MAX_WATCH x WATCH_SIZE
//! 0x10000  rings            MAX_RINGS x RING_SIZE   one single-producer byte ring per recording thread
//! ```

pub const MAGIC: u64 = 0x4859_5f41_4745_4e54;
pub const HEADER_SIZE: usize = 0x10000;
pub const MAX_RINGS: usize = 32;
pub const RING_DATA: usize = 1 << 20;
pub const RING_HDR: usize = 4096;
pub const RING_SIZE: usize = RING_HDR + RING_DATA;
pub const SECTION_SIZE: usize = HEADER_SIZE + MAX_RINGS * RING_SIZE;

// Header.
pub const H_MAGIC: usize = 0; // u64
pub const H_STATUS: usize = 8; // u32: 0 starting, 1 ready, 2 failed
pub const H_ERROR: usize = 12; // u32
pub const H_NRINGS: usize = 16; // u32 high-water mark of claimed rings
pub const H_NO_RING: usize = 20; // u32 hits from threads that found no free ring
pub const H_NSITES: usize = 24; // u32 (host -> agent, informational)
pub const H_USE_QPC: usize = 28; // u32 agent: 1 when timestamps are QueryPerformanceCounter ticks
pub const H_TSC0: usize = 32; // u64 agent clock sample at init
pub const H_QPC0: usize = 40; // u64
pub const H_QPC_FREQ: usize = 48; // u64
pub const H_SHUTDOWN: usize = 56; // u32 host -> agent: stop the control thread
pub const H_AGENT_TID: usize = 60; // u32 control thread id (never suspended by the agent)
pub const H_EVENT_HEAD: usize = 64; // u32 next event slot to claim
pub const H_WATCH_SEEN: usize = 68; // u32 nonzero once any watch was ever armed (single-steps are ours from then on)
pub const H_VEH_FOREIGN: usize = 72; // u32 single-steps seen while no watch was armed
pub const H_STALL_BUDGET: usize = 80; // u64 how long a hit may wait for a full ring, in the record clock's ticks

// Site table.
pub const SITES_OFF: usize = 0x100;
pub const MAX_SITES: usize = 64;
pub const SITE_SIZE: usize = 256;
pub const S_RVA: usize = 0; // u64
pub const S_BASE: usize = 8; // u64 expected module base, 0 = unchecked
pub const S_EXPECT_LEN: usize = 16; // u32
pub const S_FLAGS: usize = 20; // u32
pub const S_NARGS: usize = 24; // u32 0..=8
pub const S_MASK: usize = 28; // u32 sampling stride - 1 (power of two minus one); host may change it at any time
pub const S_BUF_PTR_ARG: usize = 32; // i32 argument index holding the buffer pointer, -1 none
pub const S_BUF_LEN_ARG: usize = 36; // i32 argument index holding the length, -1 use S_BUF_FIXED
pub const S_BUF_FIXED: usize = 40; // u32
pub const S_BUF_MAX: usize = 44; // u32 <= BUF_MAX
pub const S_STACK_DEPTH: usize = 48; // u32 <= MAX_STACK
pub const S_STATE: usize = 52; // u32 agent: see SITE_*
pub const S_ERR: usize = 56; // u32 agent: ERR_*
pub const S_EXPECT: usize = 64; // [u8; 32]
pub const S_MODULE: usize = 96; // [u8; 64] utf-8 module file name, empty = main module
pub const S_EXPORT: usize = 160; // [u8; 64] utf-8 export name, empty = none

pub const SITE_UNUSED: u32 = 0;
pub const SITE_ARMED: u32 = 1;
pub const SITE_FAILED: u32 = 2;
pub const SITE_RETIRED: u32 = 3;

pub const F_RETURN: u32 = 1; // record at return: retval, last error, end time
pub const F_STACK: u32 = 2; // walk the stack
pub const F_PAUSE: u32 = 4; // park the thread (breakpoint)
pub const F_BUF_ON_RETURN: u32 = 8; // read the buffer when the call returns
pub const F_BUF_WIDE: u32 = 32; // the buffer is a UTF-16 string: read up to the terminator
pub const F_BUF_CSTR: u32 = 64; // the buffer is a NUL-terminated byte string
pub const F_INSTRUCTION: u32 = 16; // mid-function site: no return / args semantics beyond registers

pub const BUF_MAX: usize = 256;
pub const MAX_STACK: usize = 15;
pub const MAX_ARGS: usize = 8;
pub const SHADOW_DEPTH: usize = 16;

// Errors (S_ERR / H_ERROR). 0 = none.
pub const ERR_NO_MODULE: u32 = 1;
pub const ERR_MODULE_BASE: u32 = 2;
pub const ERR_EXPORT_MISMATCH: u32 = 3;
pub const ERR_BYTES_MISMATCH: u32 = 10;
pub const ERR_DECODE: u32 = 11;
pub const ERR_NO_STUB_ROOM: u32 = 12;
pub const ERR_ENCODE: u32 = 13;
pub const ERR_PROTECT: u32 = 14;
pub const ERR_SUSPEND: u32 = 15;
pub const ERR_THREAD_IN_SITE: u32 = 16;
pub const ERR_BAD_SITE: u32 = 17;
pub const ERR_UNSUPPORTED_ARCH: u32 = 100;
pub const ERR_SECTION: u32 = 101;

// Mailbox.
pub const MAILBOX_OFF: usize = 0x4400;
pub const MB_CMD: usize = 0; // u32
pub const MB_SEQ: usize = 4; // u32 host increments after writing the command
pub const MB_RSEQ: usize = 8; // u32 agent copies SEQ here when done
pub const MB_RESULT: usize = 12; // u32 0 = ok, else ERR_*
pub const MB_ARGS: usize = 16; // [u64; 6]
pub const CMD_PING: u32 = 1;
pub const CMD_ARM_SITE: u32 = 2; // args[0] = site index
pub const CMD_RETIRE_SITE: u32 = 3; // args[0] = site index
pub const CMD_DETACH: u32 = 4; // retire every site

// Pause slots.
pub const PAUSE_OFF: usize = 0x4800;
pub const MAX_PAUSE: usize = 16;
pub const PAUSE_SIZE: usize = 512;
pub const P_STATE: usize = 0; // u32: 0 free, 1 parked, 2 released (agent frees it after waking)
pub const P_TID: usize = 4;
pub const P_SITE: usize = 8;
pub const P_ACTION: usize = 12; // u32 host: 1 continue, 2 continue (auto, watchdog)
pub const P_TSC: usize = 16; // u64 when parked
pub const P_FRAME: usize = 64; // [u64; 32]: the stub frame (r11 r10 r9 r8 rdx rcx rax flags retaddr + shadow/stack args)
pub const P_FRAME_WORDS: usize = 32;
pub const PAUSE_HARD_LIMIT_MS: u32 = 120_000;

// Events.
pub const EVENT_OFF: usize = 0x6800;
pub const EVENT_SLOTS: usize = 256;
pub const EVENT_SIZE: usize = 64;
pub const E_SEQ: usize = 0; // u32, written last (release): slot seq = claim index + 1
pub const E_KIND: usize = 4; // u16
pub const E_SITE: usize = 6; // u16
pub const E_TID: usize = 8; // u32
pub const E_SLOT: usize = 12; // u32
pub const E_TSC: usize = 16; // u64
pub const E_DATA: usize = 24; // [u64; 5]
pub const EV_BREAKPOINT: u16 = 1;
pub const EV_AUTO_CONTINUE: u16 = 2; // agent hard limit reached
pub const EV_WATCH_HIT: u16 = 3; // data = [rip, dr6, address, slot bitmap, 0]
pub const EV_UNRETURNED: u16 = 4; // shadow entries dropped because the frame was unwound without a return

// Watch table.
pub const WATCH_OFF: usize = 0xA800;
pub const MAX_WATCH: usize = 4;
pub const WATCH_SIZE: usize = 64;
pub const W_ADDR: usize = 0; // u64
pub const W_LEN: usize = 8; // u32
pub const W_KIND: usize = 12; // u32 1 write, 3 read/write
pub const W_ARMED: usize = 16; // u32
pub const W_HITS: usize = 20; // u32 agent counter
pub const W_LIMIT: usize = 24; // u32 events recorded at most
pub const W_SEEN: usize = 28; // u32

// Rings. Ring header: head@0 (producer), dropped@8, tid@12, state@16, read_failed@20, attempted@24, ring_seq@28,
// unreturned@32, stalls@36; tail@64 (consumer); per-site counters from RING_CTR.
pub const R_HEAD: usize = 0;
pub const R_DROPPED: usize = 8;
pub const R_TID: usize = 12;
pub const R_STATE: usize = 16;
pub const R_READ_FAILED: usize = 20;
pub const R_ATTEMPTED: usize = 24;
pub const R_SEQ: usize = 28;
pub const R_UNRETURNED: usize = 32;
pub const R_STALLS: usize = 36; // times a hit waited for the drain
pub const R_SHED: usize = 40; // 1 while the ring sheds (drops at once) after a stall ran out of patience
pub const R_TAIL: usize = 64;
pub const RING_CTR: usize = 256;
pub const CTR_SIZE: usize = 32; // hits u64, kept u64, next u64, pad
pub const RING_FREE: u32 = 0;
pub const RING_OWNED: u32 = 1;
pub const RING_RETIRED: u32 = 2;

// Record header (64 bytes), then args, stack, buffer; total padded to 8.
pub const REC_HDR: usize = 64;
pub const K_PAD: u8 = 0;
pub const K_HIT: u8 = 1;
pub const RF_RETURNED: u8 = 1;
pub const RF_HAS_RETURN: u8 = 2;
pub const RF_BUF_FAILED: u8 = 4;
pub const RF_BUF_TRUNC: u8 = 16; // the buffer was cut at the site's maximum
pub const RF_BUF_WIDE: u8 = 32; // the buffer is a UTF-16 string
pub const RF_SAMPLED: u8 = 64; // kept while the sampling policy was thinning the site
pub const RF_NO_SHADOW: u8 = 8; // wanted a return record but the shadow stack was full: entry data only

pub fn site_offset(i: usize) -> usize {
    SITES_OFF + i * SITE_SIZE
}
pub fn ring_offset(i: usize) -> usize {
    HEADER_SIZE + i * RING_SIZE
}
pub fn pause_offset(i: usize) -> usize {
    PAUSE_OFF + i * PAUSE_SIZE
}
pub fn event_offset(i: usize) -> usize {
    EVENT_OFF + (i % EVENT_SLOTS) * EVENT_SIZE
}
pub fn watch_offset(i: usize) -> usize {
    WATCH_OFF + i * WATCH_SIZE
}

/// One decoded hit.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Hit {
    pub site: u16,
    pub ring: u16,
    pub flags: u8,
    pub tsc: u64,
    pub tid: u32,
    pub ring_seq: u32,
    pub ret_addr: u64,
    pub tsc_end: u64,
    pub retval: u64,
    pub last_error: u32,
    pub buf_addr: u64,
    pub args: Vec<u64>,
    pub stack: Vec<u64>,
    pub buf: Vec<u8>,
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Encode a record into `out` (cleared first). Used by the test double and the agent's tests; the agent's hot
/// path writes the same bytes in place.
pub fn encode_hit(h: &Hit, out: &mut Vec<u8>) {
    out.clear();
    out.resize(REC_HDR, 0);
    let total = (REC_HDR + h.args.len() * 8 + h.stack.len() * 8 + h.buf.len() + 7) & !7;
    out[0..2].copy_from_slice(&(total as u16).to_le_bytes());
    out[2] = K_HIT;
    out[3] = h.flags;
    out[4..6].copy_from_slice(&h.site.to_le_bytes());
    out[6..8].copy_from_slice(&h.ring.to_le_bytes());
    out[8..16].copy_from_slice(&h.tsc.to_le_bytes());
    out[16..20].copy_from_slice(&h.tid.to_le_bytes());
    out[20..24].copy_from_slice(&h.ring_seq.to_le_bytes());
    out[24..32].copy_from_slice(&h.ret_addr.to_le_bytes());
    out[32..40].copy_from_slice(&h.tsc_end.to_le_bytes());
    out[40..48].copy_from_slice(&h.retval.to_le_bytes());
    out[48..52].copy_from_slice(&h.last_error.to_le_bytes());
    out[52] = h.args.len() as u8;
    out[53] = h.stack.len() as u8;
    out[54..56].copy_from_slice(&(h.buf.len() as u16).to_le_bytes());
    out[56..64].copy_from_slice(&h.buf_addr.to_le_bytes());
    for a in &h.args {
        out.extend_from_slice(&a.to_le_bytes());
    }
    for a in &h.stack {
        out.extend_from_slice(&a.to_le_bytes());
    }
    out.extend_from_slice(&h.buf);
    out.resize(total, 0);
}

/// Decode one record at the start of `b`; returns `(size, Some(hit))`, or `(size, None)` for a padding record.
/// `None` for the whole result when `b` is malformed.
pub fn decode_record(b: &[u8]) -> Option<(usize, Option<Hit>)> {
    if b.len() < 8 {
        return None;
    }
    let size = rd16(b, 0) as usize;
    if size < 8 || !size.is_multiple_of(8) || size > b.len() {
        return None;
    }
    if b[2] == K_PAD {
        return Some((size, None));
    }
    if size < REC_HDR {
        return None;
    }
    let (nargs, nstack, buflen) = (b[52] as usize, b[53] as usize, rd16(b, 54) as usize);
    if REC_HDR + nargs * 8 + nstack * 8 + buflen > size {
        return None;
    }
    let mut o = REC_HDR;
    let args = (0..nargs).map(|i| rd64(b, o + i * 8)).collect();
    o += nargs * 8;
    let stack = (0..nstack).map(|i| rd64(b, o + i * 8)).collect();
    o += nstack * 8;
    let hit = Hit {
        site: rd16(b, 4),
        ring: rd16(b, 6),
        flags: b[3],
        tsc: rd64(b, 8),
        tid: rd32(b, 16),
        ring_seq: rd32(b, 20),
        ret_addr: rd64(b, 24),
        tsc_end: rd64(b, 32),
        retval: rd64(b, 40),
        last_error: rd32(b, 48),
        buf_addr: rd64(b, 56),
        args,
        stack,
        buf: b[o..o + buflen].to_vec(),
    };
    Some((size, Some(hit)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_roundtrip() {
        let h = Hit {
            site: 3,
            ring: 1,
            flags: RF_RETURNED | RF_HAS_RETURN,
            tsc: 11,
            tid: 7,
            ring_seq: 9,
            ret_addr: 0x1000,
            tsc_end: 12,
            retval: 5,
            last_error: 2,
            buf_addr: 0x2000,
            args: vec![1, 2, 3],
            stack: vec![0x10, 0x20],
            buf: vec![1, 2, 3, 4, 5],
        };
        let mut b = Vec::new();
        encode_hit(&h, &mut b);
        assert_eq!(b.len() % 8, 0);
        let (size, got) = decode_record(&b).unwrap();
        assert_eq!(size, b.len());
        assert_eq!(got.unwrap(), h);
    }

    #[test]
    fn pad_and_malformed() {
        let mut p = vec![0u8; 16];
        p[0] = 16;
        assert_eq!(decode_record(&p).unwrap(), (16, None));
        assert!(decode_record(&[1, 0, 0, 0, 0, 0, 0, 0]).is_none());
        let mut bad = vec![0u8; REC_HDR];
        bad[0] = REC_HDR as u8;
        bad[2] = K_HIT;
        bad[52] = 8; // claims args beyond the record
        assert!(decode_record(&bad).is_none());
    }

    // The layout is checked at compile time.
    const _: () = {
        assert!(SITES_OFF + MAX_SITES * SITE_SIZE <= MAILBOX_OFF);
        assert!(MAILBOX_OFF + 128 <= PAUSE_OFF);
        assert!(PAUSE_OFF + MAX_PAUSE * PAUSE_SIZE <= EVENT_OFF);
        assert!(EVENT_OFF + EVENT_SLOTS * EVENT_SIZE <= WATCH_OFF);
        assert!(WATCH_OFF + MAX_WATCH * WATCH_SIZE <= HEADER_SIZE);
        assert!(RING_CTR + MAX_SITES * CTR_SIZE <= RING_HDR);
        assert!(S_EXPORT + 64 <= SITE_SIZE);
        assert!(P_FRAME + P_FRAME_WORDS * 8 <= PAUSE_SIZE);
    };
}
