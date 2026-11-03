//! Stopping the other threads of this process while a hook is patched.
use hy_agent_proto as p;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Threading::*;

#[repr(C, align(16))]
struct Ctx(CONTEXT);

pub struct Stopped {
    handles: Vec<(HANDLE, u64)>,
    /// Keeps the thread-id buffer alive until after `Drop::drop` has resumed every thread: freeing it while other
    /// threads are suspended could block forever on a heap lock one of them holds. Fields drop after `drop` returns.
    _tids: Vec<u32>,
}

impl Stopped {
    /// True when any stopped thread's instruction pointer lies in `[lo, hi)`, or could not be read (unproven = unsafe).
    pub fn any_in(&self, lo: usize, hi: usize) -> bool {
        self.handles.iter().any(|&(_, rip)| rip == u64::MAX || (rip as usize >= lo && (rip as usize) < hi))
    }
}

impl Drop for Stopped {
    fn drop(&mut self) {
        for &(h, _) in &self.handles {
            unsafe {
                ResumeThread(h);
                CloseHandle(h);
            }
        }
    }
}

/// Suspend every thread except the caller and the agent's control thread. Everything that allocates happens before
/// the first suspension (the snapshot is taken first, the handle list reserved), so a suspended thread holding the
/// heap lock cannot block this thread.
pub fn suspend_others() -> Result<Stopped, ()> {
    unsafe {
        let me = GetCurrentThreadId();
        let control = {
            let sec = crate::ring::section();
            if sec.is_null() { 0 } else { (sec.add(p::H_AGENT_TID) as *const u32).read_volatile() }
        };
        let pid = GetCurrentProcessId();
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Err(());
        }
        let mut tids: Vec<u32> = Vec::with_capacity(256);
        let mut e: THREADENTRY32 = core::mem::zeroed();
        e.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
        let mut ok = Thread32First(snap, &mut e);
        while ok != 0 {
            if e.th32OwnerProcessID == pid && e.th32ThreadID != me && e.th32ThreadID != control {
                tids.push(e.th32ThreadID);
            }
            ok = Thread32Next(snap, &mut e);
        }
        CloseHandle(snap);
        let mut out = Stopped { handles: Vec::with_capacity(tids.len()), _tids: Vec::new() };
        for &tid in &tids {
            let h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, 0, tid);
            if h.is_null() {
                continue;
            }
            if SuspendThread(h) == u32::MAX {
                CloseHandle(h);
                continue;
            }
            let mut c: Ctx = core::mem::zeroed();
            c.0.ContextFlags = CONTEXT_CONTROL_AMD64;
            // A context that cannot be read proves nothing: u64::MAX makes `any_in` refuse the patch.
            let rip = if GetThreadContext(h, &mut c.0) != 0 { c.0.Rip } else { u64::MAX };
            out.handles.push((h, rip));
        }
        out._tids = tids;
        Ok(out)
    }
}

const CONTEXT_CONTROL_AMD64: CONTEXT_FLAGS = 0x0010_0001;
