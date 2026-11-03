//! Vectored exception handler for hardware watchpoints. The host arms the debug registers (SetThreadContext on
//! every thread); this handler absorbs the single-step trap, records the hit and clears DR6.
use crate::ring;
use core::sync::atomic::{AtomicU32, Ordering};
use hy_agent_proto as p;
use windows_sys::Win32::System::Diagnostics::Debug::*;

const SINGLE_STEP: i32 = 0x8000_0004u32 as i32;
const CONTINUE_EXECUTION: i32 = -1;
const CONTINUE_SEARCH: i32 = 0;

pub unsafe extern "system" fn veh(ep: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let rec = (*ep).ExceptionRecord;
        if (*rec).ExceptionCode != SINGLE_STEP {
            return CONTINUE_SEARCH;
        }
        let sec = ring::section();
        if sec.is_null() {
            return CONTINUE_SEARCH;
        }
        // Once any watch existed every single-step is ours: a trap raised just before a disarm is delivered after it
        // and must still be absorbed, or the thread dies with 0x80000004.
        let seen = &*(sec.add(p::H_WATCH_SEEN) as *const AtomicU32);
        if seen.load(Ordering::Acquire) == 0 {
            (&*(sec.add(p::H_VEH_FOREIGN) as *const AtomicU32)).fetch_add(1, Ordering::Relaxed);
            return CONTINUE_SEARCH;
        }
        let ctx = (*ep).ContextRecord;
        let dr6 = (*ctx).Dr6;
        let bits = (dr6 & 0xF) as u32;
        for s in 0..p::MAX_WATCH {
            if bits & (1 << s) == 0 {
                continue;
            }
            let w = sec.add(p::watch_offset(s));
            let hits = &*(w.add(p::W_HITS) as *const AtomicU32);
            let n = hits.fetch_add(1, Ordering::AcqRel);
            let limit = (w.add(p::W_LIMIT) as *const u32).read_volatile();
            if limit == 0 || n < limit {
                let addr = (w.add(p::W_ADDR) as *const u64).read_volatile();
                ring::push_event(p::EV_WATCH_HIT, 0, s as u32, [(*ctx).Rip, dr6, addr, bits as u64, 0]);
            }
        }
        (*ctx).Dr6 = 0;
        CONTINUE_EXECUTION
    }
}
