//! Injected agent. The host loads this DLL into a suspended target, then runs `hy_agent_init` in a remote
//! thread. Init maps the host's section, installs every requested inline hook (prologue bytes compared first),
//! and publishes status. Hits are recorded into the calling thread's own single-producer ring.
#![allow(clippy::missing_safety_doc)]

#[cfg(target_arch = "x86_64")]
mod hook;
mod ring;

use hy_agent_proto as proto;
use windows_sys::Win32::Foundation::{FALSE, TRUE};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{FILE_MAP_ALL_ACCESS, MapViewOfFile, OpenFileMappingW};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _h: *mut core::ffi::c_void,
    _reason: u32,
    _res: *mut core::ffi::c_void,
) -> i32 {
    TRUE
}

fn name_for_pid() -> Vec<u16> {
    let pid = unsafe { GetCurrentProcessId() };
    format!("Local\\hy_agent_{pid}\0").encode_utf16().collect()
}

unsafe fn rd_u32(base: *mut u8, off: usize) -> u32 {
    unsafe { (base.add(off) as *const u32).read_volatile() }
}
unsafe fn wr_u32(base: *mut u8, off: usize, v: u32) {
    unsafe { (base.add(off) as *mut u32).write_volatile(v) }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn hy_agent_init(_param: *mut core::ffi::c_void) -> u32 {
    unsafe {
        let name = name_for_pid();
        let h = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name.as_ptr());
        if h.is_null() {
            return 1;
        }
        let view = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, proto::SECTION_SIZE);
        let base = view.Value as *mut u8;
        if base.is_null() {
            return 2;
        }
        ring::set_section(base);
        let main = GetModuleHandleW(core::ptr::null()) as usize;
        let n = rd_u32(base, proto::H_NSITES) as usize;
        let mut code = 0u32;
        for i in 0..n.min(32) {
            let req = base.add(proto::H_SITES + i * proto::SITE_REQ_SIZE);
            let rva = (req as *const u64).read_unaligned();
            let len = (req.add(8) as *const u32).read_unaligned() as usize;
            let exp = core::slice::from_raw_parts(base.add(proto::H_EXPECT + i * 16), len.min(16));
            #[cfg(target_arch = "x86_64")]
            if let Err(c) = hook::install(i as u16, main + rva as usize, exp) {
                code = c;
                break;
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                let _ = (main, rva, exp);
                code = 100;
            }
        }
        wr_u32(base, proto::H_ERROR, code);
        wr_u32(base, proto::H_STATUS, if code == 0 { 1 } else { 2 });
        code
    }
}
