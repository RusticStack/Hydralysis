//! Per-thread single-producer rings carved out of the host-shared section.
use hy_agent_proto as proto;
use std::cell::Cell;
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

static SECTION: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

pub fn set_section(p: *mut u8) {
    SECTION.store(p, Ordering::Release);
}

thread_local! {
    static RING: Cell<*mut u8> = const { Cell::new(core::ptr::null_mut()) };
}

#[cold]
unsafe fn claim(sec: *mut u8) -> *mut u8 {
    unsafe {
        let next = &*(sec.add(proto::H_NEXT_RING) as *const AtomicU32);
        let i = next.fetch_add(1, Ordering::AcqRel) as usize;
        if i >= proto::MAX_RINGS {
            let c = &*(sec.add(proto::H_NO_RING) as *const AtomicU32);
            c.fetch_add(1, Ordering::Relaxed);
            return core::ptr::null_mut();
        }
        let r = sec.add(proto::ring_offset(i));
        (r.add(12) as *mut u32).write(windows_sys::Win32::System::Threading::GetCurrentThreadId());
        RING.with(|c| c.set(r));
        r
    }
}

/// The hot path: one record, no lock, no allocation. A full ring drops and counts.
#[inline]
pub unsafe fn record(site: u16, arg0: u64, ret: u64) {
    unsafe {
        let sec = SECTION.load(Ordering::Relaxed);
        if sec.is_null() {
            return;
        }
        let mut r = RING.with(|c| c.get());
        if r.is_null() {
            r = claim(sec);
            if r.is_null() {
                return;
            }
        }
        let head = &*(r as *const AtomicU32);
        let tail = &*(r.add(64) as *const AtomicU32);
        let h = head.load(Ordering::Relaxed);
        if h.wrapping_sub(tail.load(Ordering::Acquire)) >= proto::RING_RECS as u32 {
            let d = &*(r.add(8) as *const AtomicU32);
            d.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let slot = r.add(proto::RING_HDR + (h as usize & (proto::RING_RECS - 1)) * proto::REC_SIZE);
        let w = slot as *mut u64;
        #[cfg(target_arch = "x86_64")]
        let tsc = core::arch::x86_64::_rdtsc();
        #[cfg(target_arch = "x86")]
        let tsc = core::arch::x86::_rdtsc();
        w.write(tsc);
        let tid = teb_tid();
        (slot.add(8) as *mut u32).write(tid);
        (slot.add(12) as *mut u16).write(site);
        (slot.add(14) as *mut u16).write(proto::REC_KIND_HIT);
        w.add(2).write(arg0);
        w.add(3).write(ret);
        head.store(h.wrapping_add(1), Ordering::Release);
    }
}

/// Thread id straight from the TEB (ClientId.UniqueThread): no call, no import.
#[inline(always)]
fn teb_tid() -> u32 {
    let v: usize;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, gs:[0x48]", out(reg) v, options(nostack, readonly, preserves_flags));
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::asm!("mov {}, fs:[0x24]", out(reg) v, options(nostack, readonly, preserves_flags));
    }
    v as u32
}
