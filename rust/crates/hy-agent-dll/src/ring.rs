//! Per-thread single-producer byte rings carved out of the host-shared section, and the record writer.
//!
//! The hot path is lock-free and allocation-free: a record is reserved in the calling thread's own ring, written in
//! place, and published with one release store of `head`. A full ring drops and counts (never silent).
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use hy_agent_proto as p;
use std::cell::{Cell, UnsafeCell};

pub static SECTION: AtomicUsize = AtomicUsize::new(0);
pub static FLS_INDEX: AtomicU32 = AtomicU32::new(u32::MAX);
pub static USE_QPC: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
pub fn section() -> *mut u8 {
    SECTION.load(Ordering::Relaxed) as *mut u8
}

thread_local! {
    static RING: Cell<usize> = const { Cell::new(0) };
    pub static SHADOW: UnsafeCell<Shadow> = const { UnsafeCell::new(Shadow::new()) };
}

/// A hit captured at entry whose record is completed when the call returns.
pub struct Entry {
    pub site: u16,
    pub rec_flags: u8,
    pub nargs: u8,
    pub nstack: u8,
    pub buflen: u16,
    pub tid: u32,
    pub tsc: u64,
    pub ret_addr: u64,
    pub buf_addr: u64,
    pub slot: usize,
    pub buf_ptr: u64,
    pub buf_len: u32,
    pub buf_on_return: bool,
    pub args: [MaybeUninit<u64>; p::MAX_ARGS],
    pub stack: [MaybeUninit<u64>; p::MAX_STACK],
    pub buf: [MaybeUninit<u8>; p::BUF_MAX],
}

impl Entry {
    pub const fn empty() -> Entry {
        Entry {
            site: 0,
            rec_flags: 0,
            nargs: 0,
            nstack: 0,
            buflen: 0,
            tid: 0,
            tsc: 0,
            ret_addr: 0,
            buf_addr: 0,
            slot: 0,
            buf_ptr: 0,
            buf_len: 0,
            buf_on_return: false,
            args: [MaybeUninit::uninit(); p::MAX_ARGS],
            stack: [MaybeUninit::uninit(); p::MAX_STACK],
            buf: [MaybeUninit::uninit(); p::BUF_MAX],
        }
    }
}

pub struct Shadow {
    pub depth: usize,
    pub ents: [Entry; p::SHADOW_DEPTH],
}

impl Shadow {
    pub const fn new() -> Shadow {
        const E: Entry = Entry::empty();
        Shadow {
            depth: 0,
            ents: [E; p::SHADOW_DEPTH],
        }
    }
}

#[inline(always)]
unsafe fn a32<'a>(base: *mut u8, off: usize) -> &'a AtomicU32 {
    unsafe { &*(base.add(off) as *const AtomicU32) }
}

#[inline(always)]
pub fn teb_tid() -> u32 {
    let v: usize;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x48]", out(reg) v, options(nostack, readonly, preserves_flags));
    }
    v as u32
}

#[inline(always)]
pub fn teb_last_error() -> u32 {
    let v: u32;
    unsafe {
        core::arch::asm!("mov {:e}, gs:[0x68]", out(reg) v, options(nostack, readonly, preserves_flags));
    }
    v
}

#[inline(always)]
pub fn now() -> u64 {
    if USE_QPC.load(Ordering::Relaxed) != 0 {
        let mut q = 0i64;
        unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut q) };
        q as u64
    } else {
        unsafe { core::arch::x86_64::_rdtsc() }
    }
}

/// This thread's ring, claiming a free one on the first hit. Null when every ring is taken (counted).
#[inline(always)]
pub unsafe fn my_ring() -> *mut u8 {
    let r = RING.with(|c| c.get());
    if r != 0 {
        r as *mut u8
    } else {
        unsafe { claim() }
    }
}

#[cold]
#[inline(never)]
unsafe fn claim() -> *mut u8 {
    unsafe {
        let sec = section();
        if sec.is_null() {
            return core::ptr::null_mut();
        }
        for i in 0..p::MAX_RINGS {
            let r = sec.add(p::ring_offset(i));
            if a32(r, p::R_STATE)
                .compare_exchange(
                    p::RING_FREE,
                    p::RING_OWNED,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                (r.add(p::R_TID) as *mut u32).write(teb_tid());
                for s in 0..p::MAX_SITES {
                    (r.add(p::RING_CTR + s * p::CTR_SIZE + 16) as *mut u64).write(0); // next
                }
                RING.with(|c| c.set(r as usize));
                let n = a32(sec, p::H_NRINGS);
                n.fetch_max(i as u32 + 1, Ordering::AcqRel);
                // A fiber-local-storage slot with a callback retires the ring when the thread exits.
                let idx = FLS_INDEX.load(Ordering::Relaxed);
                if idx != u32::MAX {
                    windows_sys::Win32::System::Threading::FlsSetValue(idx, r as *const _);
                }
                return r;
            }
        }
        a32(sec, p::H_NO_RING).fetch_add(1, Ordering::Relaxed);
        core::ptr::null_mut()
    }
}

/// FLS callback: the owning thread is gone; the host frees the ring once it has read it to the end.
pub unsafe extern "system" fn fls_callback(data: *const core::ffi::c_void) {
    if !data.is_null() {
        unsafe { a32(data as *mut u8, p::R_STATE).store(p::RING_RETIRED, Ordering::Release) };
    }
}

#[inline(always)]
pub unsafe fn bump32(ring: *mut u8, off: usize) {
    unsafe {
        let q = ring.add(off) as *mut u32;
        q.write_volatile(q.read_volatile().wrapping_add(1));
    }
}

/// Reserve `total` bytes (multiple of 8). Returns the write pointer and the head to publish, or null when full.
#[inline(always)]
unsafe fn reserve(ring: *mut u8, total: usize) -> (*mut u8, u32) {
    unsafe {
        let head = a32(ring, p::R_HEAD).load(Ordering::Relaxed);
        let tail = a32(ring, p::R_TAIL).load(Ordering::Acquire);
        let off = head as usize & (p::RING_DATA - 1);
        let to_end = p::RING_DATA - off;
        let pad = if to_end < total { to_end } else { 0 };
        if (head.wrapping_sub(tail) as usize) + pad + total > p::RING_DATA {
            bump32(ring, p::R_DROPPED);
            return (core::ptr::null_mut(), 0);
        }
        let data = ring.add(p::RING_HDR);
        if pad != 0 {
            let w = data.add(off);
            (w as *mut u16).write(pad as u16);
            *w.add(2) = p::K_PAD;
            return (data, head.wrapping_add((pad + total) as u32));
        }
        (data.add(off), head.wrapping_add(total as u32))
    }
}

/// Complete and publish `e` (the entry data) with the return data (zeros / `returned = false` for entry-only).
#[inline(always)]
pub unsafe fn emit(
    ring: *mut u8,
    e: &Entry,
    returned: bool,
    tsc_end: u64,
    retval: u64,
    last_error: u32,
) {
    unsafe {
        let nargs = e.nargs as usize;
        let nstack = e.nstack as usize;
        let buflen = e.buflen as usize;
        let total = (p::REC_HDR + nargs * 8 + nstack * 8 + buflen + 7) & !7;
        let (w, new_head) = reserve(ring, total);
        if w.is_null() {
            return;
        }
        let seq = a32(ring, p::R_SEQ).load(Ordering::Relaxed);
        a32(ring, p::R_SEQ).store(seq.wrapping_add(1), Ordering::Relaxed);
        let mut flags = e.rec_flags;
        if returned {
            flags |= p::RF_RETURNED;
        }
        (w as *mut u16).write(total as u16);
        *w.add(2) = p::K_HIT;
        *w.add(3) = flags;
        (w.add(4) as *mut u16).write(e.site);
        (w.add(6) as *mut u16).write(ring_index(ring));
        (w.add(8) as *mut u64).write(e.tsc);
        (w.add(16) as *mut u32).write(e.tid);
        (w.add(20) as *mut u32).write(seq);
        (w.add(24) as *mut u64).write(e.ret_addr);
        (w.add(32) as *mut u64).write(tsc_end);
        (w.add(40) as *mut u64).write(retval);
        (w.add(48) as *mut u32).write(last_error);
        *w.add(52) = nargs as u8;
        *w.add(53) = nstack as u8;
        (w.add(54) as *mut u16).write(buflen as u16);
        (w.add(56) as *mut u64).write(e.buf_addr);
        let mut o = p::REC_HDR;
        core::ptr::copy_nonoverlapping(e.args.as_ptr() as *const u8, w.add(o), nargs * 8);
        o += nargs * 8;
        core::ptr::copy_nonoverlapping(e.stack.as_ptr() as *const u8, w.add(o), nstack * 8);
        o += nstack * 8;
        core::ptr::copy_nonoverlapping(e.buf.as_ptr() as *const u8, w.add(o), buflen);
        a32(ring, p::R_HEAD).store(new_head, Ordering::Release);
    }
}

#[inline(always)]
fn ring_index(ring: *mut u8) -> u16 {
    ((ring as usize - section() as usize - p::HEADER_SIZE) / p::RING_SIZE) as u16
}

/// Per-ring per-site counters: every hit counted, the kept ones too. `hits - kept` is the exact skipped count.
#[inline(always)]
pub unsafe fn ctr(ring: *mut u8, site: usize) -> *mut u64 {
    unsafe { ring.add(p::RING_CTR + site * p::CTR_SIZE) as *mut u64 }
}

/// An out-of-band event (breakpoint, watch hit, auto-continue); lock-free multi-producer.
pub unsafe fn push_event(kind: u16, site: u16, slot: u32, data: [u64; 5]) {
    unsafe {
        let sec = section();
        if sec.is_null() {
            return;
        }
        let idx = a32(sec, p::H_EVENT_HEAD).fetch_add(1, Ordering::AcqRel) as usize;
        let e = sec.add(p::event_offset(idx));
        (e.add(p::E_KIND) as *mut u16).write(kind);
        (e.add(p::E_SITE) as *mut u16).write(site);
        (e.add(p::E_TID) as *mut u32).write(teb_tid());
        (e.add(p::E_SLOT) as *mut u32).write(slot);
        (e.add(p::E_TSC) as *mut u64).write(now());
        for (i, d) in data.iter().enumerate() {
            (e.add(p::E_DATA + 8 * i) as *mut u64).write(*d);
        }
        a32(e, p::E_SEQ).store(idx as u32 + 1, Ordering::Release);
    }
}
