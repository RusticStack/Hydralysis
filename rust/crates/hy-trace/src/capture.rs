//! Frame-stall capture from a separate process (Windows x64), ported from `hydralysis.trace_watchdog.capture_stacks`.
//!
//! Each thread of the target is suspended for the few microseconds it takes to read its registers, its stack is walked with
//! [`Unwinder`] and it is resumed. Only `OpenProcess`, `OpenThread`, `SuspendThread`, `GetThreadContext` and
//! `ReadProcessMemory` are used: nothing is written into the target and it needs no cooperation, which is the point (a stalled
//! frame loop cannot run an in-process recorder). All `unsafe` in this crate is in this file and is the FFI to those calls.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext, ReadProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleBaseNameW, GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::{OpenProcess, OpenThread, ResumeThread, SuspendThread};

use crate::unwind::{Frame, Malformed, Memory, Module, Regs, Unwinder};

// QUERY_INFORMATION | VM_READ | VM_OPERATION (no write is used) | QUERY_LIMITED_INFORMATION
const PROCESS_ACCESS: u32 = 0x0400 | 0x0010 | 0x0008 | 0x1000;
// SUSPEND_RESUME | GET_CONTEXT | QUERY_INFORMATION | QUERY_LIMITED_INFORMATION
const THREAD_ACCESS: u32 = 0x0002 | 0x0008 | 0x0040 | 0x0800;
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
const LIST_MODULES_ALL: u32 = 0x3;
const MODULE_SLOTS: usize = 2048;

/// An owned handle, closed on drop.
struct Handle(HANDLE);

impl Handle {
    fn open_process(pid: u32) -> Option<Self> {
        // SAFETY: OpenProcess has no preconditions; a null return is the failure case.
        let handle = unsafe { OpenProcess(PROCESS_ACCESS, 0, pid) };
        (!handle.is_null()).then(|| Self(handle))
    }

    fn open_thread(tid: u32) -> Option<Self> {
        // SAFETY: as above.
        let handle = unsafe { OpenThread(THREAD_ACCESS, 0, tid) };
        (!handle.is_null()).then(|| Self(handle))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// The target process as a [`Memory`]: bounded `ReadProcessMemory` reads that the kernel may refuse.
pub struct Process {
    handle: Handle,
}

impl Process {
    /// `None` when the process cannot be opened; [`last_error`] then says why.
    pub fn open(pid: u32) -> Option<Self> {
        Handle::open_process(pid).map(|handle| Self { handle })
    }

    /// The modules of the process sorted by `(base, size, name)`, as the original's `modules()`.
    pub fn modules(&self) -> Vec<Module> {
        let mut slots = vec![std::ptr::null_mut(); MODULE_SLOTS];
        let mut needed = 0u32;
        let bytes = (MODULE_SLOTS * size_of::<HANDLE>()) as u32;
        // SAFETY: SLOTS holds BYTES bytes and NEEDED is a valid out-pointer; the call fails (and writes nothing) on a bad handle.
        unsafe { EnumProcessModulesEx(self.handle.0, slots.as_mut_ptr(), bytes, &mut needed, LIST_MODULES_ALL) };
        let count = (needed as usize / size_of::<HANDLE>()).min(MODULE_SLOTS);
        let mut out = Vec::new();
        for &module in &slots[..count] {
            // SAFETY: MODULEINFO is plain data and INFO is a valid out-pointer of the stated size.
            let mut info: MODULEINFO = unsafe { std::mem::zeroed() };
            let ok = unsafe { GetModuleInformation(self.handle.0, module, &mut info, size_of::<MODULEINFO>() as u32) };
            if ok == 0 {
                continue;
            }
            let mut name = [0u16; 260];
            // SAFETY: NAME is a valid buffer of 260 wide characters.
            let written = unsafe { GetModuleBaseNameW(self.handle.0, module, name.as_mut_ptr(), 260) } as usize;
            out.push(Module {
                base: info.lpBaseOfDll as usize as u64,
                size: u64::from(info.SizeOfImage),
                name: String::from_utf16_lossy(&name[..written.min(260)]),
            });
        }
        out.sort();
        out
    }
}

impl Memory for Process {
    fn read(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        let mut got = 0usize;
        // SAFETY: BUFFER has SIZE bytes and GOT is a valid out-pointer; an unreadable range is reported as a zero return.
        let ok = unsafe { ReadProcessMemory(self.handle.0, address as usize as *const _, buffer.as_mut_ptr().cast(), size, &mut got) };
        if ok == 0 || got == 0 {
            return None;
        }
        buffer.truncate(got);
        Some(buffer)
    }
}

/// The last Win32 error of the calling thread.
pub fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

/// The ids of the threads of PID, in the snapshot's order.
pub fn thread_ids(pid: u32) -> Vec<u32> {
    // SAFETY: CreateToolhelp32Snapshot has no preconditions; the invalid handle is checked.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let mut out = Vec::new();
    if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
        return out;
    }
    let snapshot = Handle(snapshot);
    // SAFETY: THREADENTRY32 is plain data; its size field is set as the API requires.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut more = unsafe { Thread32First(snapshot.0, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            out.push(entry.th32ThreadID);
        }
        more = unsafe { Thread32Next(snapshot.0, &mut entry) } != 0;
    }
    out
}

/// What the capture of one thread found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadCapture {
    /// The thread could not be opened or suspended (`reason` says which).
    Unreadable { tid: u32, reason: String },
    /// The thread was suspended; `frames` is empty when `GetThreadContext` failed (`captured` false).
    Read { tid: u32, captured: bool, frames: Vec<Frame>, suspended_before: u32 },
}

/// The result of [`capture_stacks`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capture {
    Refused { reason: String },
    Captured { pid: u32, threads: Vec<ThreadCapture>, modules: usize },
}

/// All thread stacks of PID. Each thread is suspended only for the register read. PID must not be the calling process (the
/// calling thread would suspend itself). A malformed unwind table raises
/// [`Malformed`] (the original's `IndexError`), after the thread in hand has been resumed.
pub fn capture_stacks(pid: u32, depth: usize, scan_bytes: usize) -> Result<Capture, Malformed> {
    let Some(process) = Process::open(pid) else {
        return Ok(Capture::Refused { reason: format!("OpenProcess failed ({})", last_error()) });
    };
    let modules = process.modules();
    let mut unwinder = Unwinder::new(&process, &modules);
    let mut threads = Vec::new();
    for tid in thread_ids(pid) {
        let Some(thread) = Handle::open_thread(tid) else {
            threads.push(ThreadCapture::Unreadable { tid, reason: format!("OpenThread failed ({})", last_error()) });
            continue;
        };
        // SAFETY: CONTEXT is plain data (16-byte aligned by its type); the flags select the control and integer registers.
        let mut context: CONTEXT = unsafe { std::mem::zeroed() };
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        // SAFETY: the handle is a thread handle with suspend rights.
        let before = unsafe { SuspendThread(thread.0) }; // the previous suspend count: above 0, somebody else suspended it
        if before == u32::MAX {
            threads.push(ThreadCapture::Unreadable { tid, reason: "SuspendThread failed".to_owned() });
            continue;
        }
        // SAFETY: CONTEXT is valid for writes and the thread is suspended.
        let ok = unsafe { GetThreadContext(thread.0, &mut context) } != 0;
        let walked = if ok {
            let regs: Regs = [
                context.Rax,
                context.Rcx,
                context.Rdx,
                context.Rbx,
                context.Rsp,
                context.Rbp,
                context.Rsi,
                context.Rdi,
                context.R8,
                context.R9,
                context.R10,
                context.R11,
                context.R12,
                context.R13,
                context.R14,
                context.R15,
            ];
            unwinder.walk_stack(&regs, context.Rip, depth, scan_bytes)
        } else {
            Ok(Vec::new())
        };
        // SAFETY: resumes the thread suspended above, also when the walk failed.
        unsafe { ResumeThread(thread.0) };
        threads.push(ThreadCapture::Read { tid, captured: ok, frames: walked?, suspended_before: before });
    }
    Ok(Capture::Captured { pid, threads, modules: modules.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_has_threads_and_modules() {
        let pid = std::process::id();
        assert!(!thread_ids(pid).is_empty());
        let process = Process::open(pid).expect("opens itself");
        let modules = process.modules();
        assert!(!modules.is_empty());
        assert!(modules.windows(2).all(|pair| pair[0] <= pair[1]), "sorted by base");
        let first = &modules[0];
        assert!(process.read(first.base, 2).is_some_and(|head| head == b"MZ"));
        assert!(process.read(0, 8).is_none(), "the null page is unreadable");
    }

    /// A target that stays alive for a few seconds. (Never the test process itself: suspending the calling thread cannot be
    /// undone by that thread.)
    struct Target(std::process::Child);

    impl Target {
        fn start() -> Self {
            let child = std::process::Command::new("ping")
                .args(["-n", "30", "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("ping is part of Windows");
            std::thread::sleep(std::time::Duration::from_millis(300));
            Self(child)
        }
    }

    impl Drop for Target {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn a_capture_of_another_process_walks_its_threads_and_resumes_them() {
        let target = Target::start();
        let Capture::Captured { threads, modules, pid } = capture_stacks(target.0.id(), 16, 1024).expect("sound unwind tables") else {
            panic!("child refused");
        };
        assert_eq!(pid, target.0.id());
        assert!(modules > 0 && !threads.is_empty());
        let walked: Vec<_> = threads
            .iter()
            .filter_map(|thread| match thread {
                ThreadCapture::Read { captured: true, frames, suspended_before, .. } => Some((frames, *suspended_before)),
                _ => None,
            })
            .collect();
        assert!(!walked.is_empty(), "{threads:?}");
        assert!(walked.iter().all(|(frames, before)| *before == 0 && frames.first().is_some_and(|f| f.how == "rip")));
        // a second capture finds the threads running again (suspend count back to 0)
        let again = capture_stacks(target.0.id(), 4, 64).unwrap();
        assert!(matches!(again, Capture::Captured { .. }));
    }

    #[test]
    fn a_process_that_does_not_exist_is_refused() {
        match capture_stacks(0xFFFF_FF00, 4, 64).unwrap() {
            Capture::Refused { reason } => assert!(reason.starts_with("OpenProcess failed (")),
            other => panic!("{other:?}"),
        }
    }
}
