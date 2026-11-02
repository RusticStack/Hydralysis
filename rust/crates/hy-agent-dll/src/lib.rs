//! Injected agent. The host loads this DLL into a target it spawned suspended (or attached to), then runs
//! `hy_agent_init` in a remote thread. Init maps the host's section, starts the control thread and arms the
//! requested sites (every guard checked before a byte is written). Hits are recorded into the calling thread's ring.
#![allow(clippy::missing_safety_doc)]
#![cfg(windows)]

#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "hy-agent-dll currently implements the x86-64 hook engine only; the x86 stub is not written yet"
);

mod hook;
mod pause;
mod ring;
mod threads;
mod watch;

use core::sync::atomic::{AtomicU32, Ordering};
use hy_agent_proto as p;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Performance::*;
use windows_sys::Win32::System::Threading::*;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _h: *mut core::ffi::c_void,
    _reason: u32,
    _res: *mut core::ffi::c_void,
) -> i32 {
    TRUE
}

static PREPARED: Mutex<Vec<Option<hook::Prepared>>> = Mutex::new(Vec::new());

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn a32<'a>(base: *mut u8, off: usize) -> &'a AtomicU32 {
    unsafe { &*(base.add(off) as *const AtomicU32) }
}

fn cstr_field(base: *const u8, off: usize, max: usize) -> String {
    unsafe {
        let s = core::slice::from_raw_parts(base.add(off), max);
        let n = s.iter().position(|&c| c == 0).unwrap_or(max);
        String::from_utf8_lossy(&s[..n]).into_owned()
    }
}

/// Validate every guard of site `idx` and install its hook. Writes the site's state and error back.
unsafe fn arm_site(idx: usize) -> u32 {
    unsafe {
        if idx >= p::MAX_SITES {
            return p::ERR_BAD_SITE;
        }
        let sec = ring::section();
        let cfg = sec.add(p::site_offset(idx));
        let fail = |code: u32| {
            (cfg.add(p::S_ERR) as *mut u32).write_volatile(code);
            a32(cfg, p::S_STATE).store(p::SITE_FAILED, Ordering::Release);
            code
        };
        if a32(cfg, p::S_STATE).load(Ordering::Acquire) == p::SITE_ARMED {
            return 0;
        }
        let rva = (cfg.add(p::S_RVA) as *const u64).read_unaligned() as usize;
        let want_base = (cfg.add(p::S_BASE) as *const u64).read_unaligned() as usize;
        let expect_len =
            ((cfg.add(p::S_EXPECT_LEN) as *const u32).read_unaligned() as usize).min(32);
        let module = cstr_field(cfg, p::S_MODULE, 64);
        let export = cstr_field(cfg, p::S_EXPORT, 64);
        let handle = if module.is_empty() {
            GetModuleHandleW(core::ptr::null())
        } else {
            GetModuleHandleW(wide(&module).as_ptr())
        } as usize;
        if handle == 0 {
            return fail(p::ERR_NO_MODULE);
        }
        if want_base != 0 && handle != want_base {
            return fail(p::ERR_MODULE_BASE);
        }
        let addr = handle + rva;
        if !export.is_empty() {
            let mut name = export.clone().into_bytes();
            name.push(0);
            let found = GetProcAddress(handle as _, name.as_ptr())
                .map(|f| f as usize)
                .unwrap_or(0);
            if found != addr {
                return fail(p::ERR_EXPORT_MISMATCH);
            }
        }
        // A hook needs its bytes proven: the file's prologue must equal what is live.
        if expect_len < 5 {
            return fail(p::ERR_BAD_SITE);
        }
        let mut live = [0u8; 32];
        let mut got = 0usize;
        if ReadProcessMemory(
            -1isize as _,
            addr as *const _,
            live.as_mut_ptr().cast(),
            expect_len,
            &mut got,
        ) == 0
            || got != expect_len
        {
            return fail(p::ERR_BYTES_MISMATCH);
        }
        let expect = core::slice::from_raw_parts(cfg.add(p::S_EXPECT), expect_len);
        if live[..expect_len] != *expect {
            return fail(p::ERR_BYTES_MISMATCH);
        }
        let prepared = match hook::prepare(idx as u16, cfg, addr) {
            Ok(x) => x,
            Err(c) => return fail(c),
        };
        if let Err(c) = hook::commit(&prepared) {
            return fail(c);
        }
        let mut g = PREPARED.lock().unwrap();
        if g.len() < p::MAX_SITES {
            g.resize_with(p::MAX_SITES, || None);
        }
        g[idx] = Some(prepared);
        (cfg.add(p::S_ERR) as *mut u32).write_volatile(0);
        a32(cfg, p::S_STATE).store(p::SITE_ARMED, Ordering::Release);
        0
    }
}

unsafe fn retire_site(idx: usize) -> u32 {
    unsafe {
        if idx >= p::MAX_SITES {
            return p::ERR_BAD_SITE;
        }
        let cfg = ring::section().add(p::site_offset(idx));
        let g = PREPARED.lock().unwrap();
        let Some(Some(pr)) = g.get(idx) else {
            return p::ERR_BAD_SITE;
        };
        if a32(cfg, p::S_STATE).load(Ordering::Acquire) != p::SITE_ARMED {
            return 0;
        }
        match hook::retire(pr) {
            Ok(()) => {
                a32(cfg, p::S_STATE).store(p::SITE_RETIRED, Ordering::Release);
                0
            }
            Err(c) => c,
        }
    }
}

unsafe fn open_event(name: String) -> HANDLE {
    unsafe { OpenEventW(EVENT_ALL_ACCESS, FALSE, wide(&name).as_ptr()) }
}

unsafe extern "system" fn control_main(_arg: *mut core::ffi::c_void) -> u32 {
    unsafe {
        let sec = ring::section();
        let pid = GetCurrentProcessId();
        let cmd_ev = open_event(format!("Local\\hy_cmd_{pid}"));
        let rsp_ev = open_event(format!("Local\\hy_rsp_{pid}"));
        (sec.add(p::H_AGENT_TID) as *mut u32).write_volatile(GetCurrentThreadId());
        let mb = sec.add(p::MAILBOX_OFF);
        loop {
            if a32(sec, p::H_SHUTDOWN).load(Ordering::Acquire) != 0 {
                return 0;
            }
            WaitForSingleObject(cmd_ev, 200);
            let seq = a32(mb, p::MB_SEQ).load(Ordering::Acquire);
            if seq == a32(mb, p::MB_RSEQ).load(Ordering::Acquire) {
                continue;
            }
            let cmd = (mb.add(p::MB_CMD) as *const u32).read_volatile();
            let a0 = (mb.add(p::MB_ARGS) as *const u64).read_volatile() as usize;
            let result = match cmd {
                p::CMD_PING => 0,
                p::CMD_ARM_SITE => arm_site(a0),
                p::CMD_RETIRE_SITE => retire_site(a0),
                p::CMD_DETACH => {
                    let mut r = 0;
                    for i in 0..p::MAX_SITES {
                        let code = retire_site(i);
                        if code != 0 && code != p::ERR_BAD_SITE {
                            r = code;
                        }
                    }
                    r
                }
                _ => p::ERR_BAD_SITE,
            };
            (mb.add(p::MB_RESULT) as *mut u32).write_volatile(result);
            a32(mb, p::MB_RSEQ).store(seq, Ordering::Release);
            SetEvent(rsp_ev);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hy_agent_init(_param: *mut core::ffi::c_void) -> u32 {
    unsafe {
        let pid = GetCurrentProcessId();
        let h = OpenFileMappingW(
            FILE_MAP_ALL_ACCESS,
            FALSE,
            wide(&format!("Local\\hy_agent_{pid}")).as_ptr(),
        );
        if h.is_null() {
            return p::ERR_SECTION;
        }
        let base = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, p::SECTION_SIZE).Value as *mut u8;
        if base.is_null() || (base as *const u64).read() != p::MAGIC {
            return p::ERR_SECTION;
        }
        ring::SECTION.store(base as usize, Ordering::Release);

        // Clock: rdtsc unless the CPU does not promise an invariant TSC; calibration pair for the host.
        let invariant = core::arch::x86_64::__cpuid(0x8000_0007).edx & (1 << 8) != 0;
        ring::USE_QPC.store(u32::from(!invariant), Ordering::Release);
        let (mut q0, mut q1, mut f) = (0i64, 0i64, 0i64);
        QueryPerformanceFrequency(&mut f);
        QueryPerformanceCounter(&mut q0);
        let t = core::arch::x86_64::_rdtsc();
        QueryPerformanceCounter(&mut q1);
        (base.add(p::H_USE_QPC) as *mut u32).write(u32::from(!invariant));
        (base.add(p::H_TSC0) as *mut u64).write(t);
        (base.add(p::H_QPC0) as *mut u64).write(((q0 + q1) / 2) as u64);
        (base.add(p::H_QPC_FREQ) as *mut u64).write(f as u64);

        // How long a hit may wait for a full ring (200 us), in the record clock's ticks: measured over ~2 ms.
        {
            let (mut qa, mut qb) = (0i64, 0i64);
            QueryPerformanceCounter(&mut qa);
            let ta = core::arch::x86_64::_rdtsc();
            Sleep(2);
            QueryPerformanceCounter(&mut qb);
            let tb = core::arch::x86_64::_rdtsc();
            let us = ((qb - qa) as f64 / f as f64 * 1e6).max(1.0);
            let per_us = if invariant {
                (tb - ta) as f64 / us
            } else {
                f as f64 / 1e6
            };
            (base.add(p::H_STALL_BUDGET) as *mut u64).write((per_us * 200.0) as u64);
        }
        let tls = TlsAlloc();
        if tls < 64 {
            ring::TLS_IDX.store(tls, Ordering::Release);
        }
        ring::FLS_INDEX.store(FlsAlloc(Some(ring::fls_callback)), Ordering::Release);
        match hook::make_return_stub() {
            Ok(a) => hook::RET_STUB.store(a, Ordering::Release),
            Err(c) => return c,
        }
        for i in 0..p::MAX_PAUSE {
            pause::EVENTS[i].store(
                open_event(format!("Local\\hy_bp_{pid}_{i}")) as usize,
                Ordering::Release,
            );
        }
        AddVectoredExceptionHandler(1, Some(watch::veh));
        let t = CreateThread(
            core::ptr::null(),
            0,
            Some(control_main),
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        );
        if t.is_null() {
            return p::ERR_SECTION;
        }
        CloseHandle(t);
        // Wait for the control thread to publish its id, so site arming never suspends it.
        for _ in 0..2000 {
            if (base.add(p::H_AGENT_TID) as *const u32).read_volatile() != 0 {
                break;
            }
            Sleep(1);
        }

        let n = (base.add(p::H_NSITES) as *const u32).read() as usize;
        for i in 0..n.min(p::MAX_SITES) {
            arm_site(i);
        }
        a32(base, p::H_STATUS).store(1, Ordering::Release);
        0
    }
}
