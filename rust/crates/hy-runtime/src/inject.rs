//! Remote-thread DLL injection into a process this host created suspended.
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

fn last() -> io::Error {
    io::Error::last_os_error()
}

fn at(stage: &str) -> io::Error {
    let e = io::Error::last_os_error();
    if std::env::var_os("HY_DEBUG_INJECT").is_some() {
        eprintln!("inject: {stage} failed: {e}");
    }
    e
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Run `start(param)` in a new remote thread and wait for it. Returns the thread's exit code.
///
/// # Safety
/// `start` must be a valid thread entry point in the target process.
pub unsafe fn run_remote(process: HANDLE, start: usize, param: *const core::ffi::c_void, timeout_ms: u32) -> io::Result<u32> {
    unsafe {
        let f: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 = core::mem::transmute(start);
        let t = CreateRemoteThread(process, core::ptr::null(), 0, Some(f), param, 0, core::ptr::null_mut());
        if t.is_null() {
            return Err(at("CreateRemoteThread"));
        }
        let w = WaitForSingleObject(t, timeout_ms);
        let mut code = 0u32;
        GetExitCodeThread(t, &mut code);
        CloseHandle(t);
        if w != WAIT_OBJECT_0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "remote thread did not finish"));
        }
        Ok(code)
    }
}

/// Load `dll` into the target (LoadLibraryW via remote thread); returns the remote module base.
///
/// kernel32 sits at the same base in every process of a boot session, so the host's `LoadLibraryW` address is valid
/// in the target even before its loader has run (same bitness only; an x86 target needs the x86 `LoadLibraryW`).
///
/// # Safety
/// `process` must be a handle to a process the caller spawned, with full access.
pub unsafe fn load_library(process: HANDLE, pid: u32, dll: &Path) -> io::Result<usize> {
    unsafe {
        let path: Vec<u16> = dll.as_os_str().encode_wide().chain(Some(0)).collect();
        let bytes = path.len() * 2;
        let remote = VirtualAllocEx(process, core::ptr::null(), bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if remote.is_null() {
            return Err(at("VirtualAllocEx"));
        }
        if WriteProcessMemory(process, remote, path.as_ptr().cast(), bytes, core::ptr::null_mut()) == 0 {
            return Err(at("WriteProcessMemory"));
        }
        let k32 = GetModuleHandleW(wide("kernel32.dll").as_ptr());
        let ll = GetProcAddress(k32, c"LoadLibraryW".as_ptr().cast()).ok_or_else(last)? as usize;
        let code = run_remote(process, ll, remote, 10_000)?;
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        if code == 0 {
            return Err(io::Error::other("LoadLibraryW failed in the target"));
        }
        module_base(pid, dll.file_name().and_then(|n| n.to_str()).unwrap_or(""))
    }
}

pub fn module_base(pid: u32, name: &str) -> io::Result<usize> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return Err(at("CreateToolhelp32Snapshot"));
        }
        let mut e: MODULEENTRY32W = core::mem::zeroed();
        e.dwSize = core::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut ok = Module32FirstW(snap, &mut e);
        let mut found = Err(io::Error::new(io::ErrorKind::NotFound, "module not in target"));
        while ok != 0 {
            let n = String::from_utf16_lossy(&e.szModule[..e.szModule.iter().position(|&c| c == 0).unwrap_or(0)]);
            if n.eq_ignore_ascii_case(name) {
                found = Ok(e.modBaseAddr as usize);
                break;
            }
            ok = Module32NextW(snap, &mut e);
        }
        CloseHandle(snap);
        found
    }
}
