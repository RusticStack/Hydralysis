//! Breakpoints: park the hitting thread in a shared slot until the host continues it (or the hard limit passes).
use crate::ring;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use hy_agent_proto as p;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;

pub static EVENTS: [AtomicUsize; p::MAX_PAUSE] = [const { AtomicUsize::new(0) }; p::MAX_PAUSE];
const CLAIMING: u32 = 3;

fn st<'a>(slot: *mut u8, off: usize) -> &'a AtomicU32 {
    unsafe { &*(slot.add(off) as *const AtomicU32) }
}

/// Park the current thread. `fr` is the stub frame (copied for the host to inspect).
pub unsafe fn park(site: u16, fr: *const u64) {
    unsafe {
        let sec = ring::section();
        for (i, event) in EVENTS.iter().enumerate() {
            let slot = sec.add(p::pause_offset(i));
            if st(slot, p::P_STATE)
                .compare_exchange(0, CLAIMING, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            (slot.add(p::P_TID) as *mut u32).write(ring::teb_tid());
            (slot.add(p::P_SITE) as *mut u32).write(site as u32);
            (slot.add(p::P_ACTION) as *mut u32).write(0);
            (slot.add(p::P_TSC) as *mut u64).write(ring::now());
            core::ptr::copy_nonoverlapping(fr, slot.add(p::P_FRAME) as *mut u64, p::P_FRAME_WORDS);
            let ev = event.load(Ordering::Relaxed) as HANDLE;
            if !ev.is_null() {
                ResetEvent(ev);
            }
            st(slot, p::P_STATE).store(1, Ordering::Release);
            ring::push_event(
                p::EV_BREAKPOINT,
                site,
                i as u32,
                [*fr.add(8), *fr.add(5), *fr.add(4), 0, 0],
            );
            if !ev.is_null() {
                let r = WaitForSingleObject(ev, p::PAUSE_HARD_LIMIT_MS);
                if r == WAIT_TIMEOUT && st(slot, p::P_ACTION).load(Ordering::Acquire) == 0 {
                    ring::push_event(p::EV_AUTO_CONTINUE, site, i as u32, [0; 5]);
                }
            }
            st(slot, p::P_STATE).store(0, Ordering::Release);
            return;
        }
    }
}
