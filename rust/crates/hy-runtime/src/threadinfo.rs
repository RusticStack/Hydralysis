//! What Frida's `Process.enumerateThreads()` reports: each thread's scheduler state and, for a thread that can be
//! stopped for a moment, its register context. The state comes from the system's own process/thread table
//! (`NtQuerySystemInformation`), the registers from `GetThreadContext` on a thread suspended only for the read.
use crate::session::Session;
use hy_agent_proto as proto;
use std::collections::HashMap;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::*;

const CONTEXT_AMD64_CONTROL_INTEGER: CONTEXT_FLAGS = 0x0010_0003;
const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtQuerySystemInformation(class: u32, buf: *mut u8, len: u32, returned: *mut u32) -> i32;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Running,
    Stopped,
    Waiting,
    Uninterruptible,
    Halted,
}

impl ThreadState {
    /// The names Frida uses.
    pub fn as_str(self) -> &'static str {
        match self {
            ThreadState::Running => "running",
            ThreadState::Stopped => "stopped",
            ThreadState::Waiting => "waiting",
            ThreadState::Uninterruptible => "uninterruptible",
            ThreadState::Halted => "halted",
        }
    }

    /// From the kernel's `KTHREAD_STATE` and `KWAIT_REASON` (Suspended = 5, WrSuspended = 35).
    pub fn from_kernel(state: u32, wait_reason: u32) -> ThreadState {
        match state {
            4 => ThreadState::Halted,
            5 if wait_reason == 5 || wait_reason == 35 => ThreadState::Stopped,
            5 => ThreadState::Waiting,
            6 => ThreadState::Uninterruptible,
            _ => ThreadState::Running,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ThreadReport {
    pub tid: u32,
    pub state: ThreadState,
    /// `(name, value)` in Frida's order; empty when the thread could not be stopped to read.
    pub regs: Vec<(&'static str, u64)>,
}

/// The fixed part of `SYSTEM_PROCESS_INFORMATION` on x64 (the thread array follows it) and one `SYSTEM_THREAD_INFORMATION`.
const PROCESS_INFO_SIZE: usize = 0x100;
const THREAD_INFO_SIZE: usize = 0x50;

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// Scheduler state of every thread of `pid` in a `SystemProcessInformation` buffer.
pub fn parse_thread_states(buf: &[u8], pid: u32) -> HashMap<u32, ThreadState> {
    let mut out = HashMap::new();
    let mut at = 0usize;
    while let (Some(next), Some(count), Some(owner)) =
        (u32_at(buf, at), u32_at(buf, at + 4), u64_at(buf, at + 0x50))
    {
        if owner == u64::from(pid) {
            for i in 0..count as usize {
                let t = at + PROCESS_INFO_SIZE + i * THREAD_INFO_SIZE;
                if let (Some(tid), Some(state), Some(reason)) = (
                    u64_at(buf, t + 48),
                    u32_at(buf, t + 68),
                    u32_at(buf, t + 72),
                ) {
                    out.insert(tid as u32, ThreadState::from_kernel(state, reason));
                }
            }
            break;
        }
        if next == 0 {
            break;
        }
        at += next as usize;
    }
    out
}

fn system_process_buffer() -> Option<Vec<u8>> {
    let mut size = 1usize << 20;
    for _ in 0..8 {
        let mut buf = vec![0u8; size];
        let mut needed = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                buf.as_mut_ptr(),
                size as u32,
                &mut needed,
            )
        };
        if status >= 0 {
            return Some(buf);
        }
        if status != STATUS_INFO_LENGTH_MISMATCH {
            return None;
        }
        size = (needed as usize + (64 << 10)).max(size * 2);
    }
    None
}

/// CONTEXT must sit on a 16-byte boundary; the windows-sys type does not promise it.
#[repr(C, align(16))]
struct Ctx(CONTEXT);

fn read_regs(tid: u32) -> Vec<(&'static str, u64)> {
    unsafe {
        let h = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            0,
            tid,
        );
        if h.is_null() {
            return Vec::new();
        }
        let mut regs = Vec::new();
        if SuspendThread(h) != u32::MAX {
            let mut c: Ctx = core::mem::zeroed();
            c.0.ContextFlags = CONTEXT_AMD64_CONTROL_INTEGER;
            let ok = GetThreadContext(h, &mut c.0) != 0;
            ResumeThread(h);
            if ok {
                let x = &c.0;
                regs = vec![
                    ("pc", x.Rip),
                    ("sp", x.Rsp),
                    ("rip", x.Rip),
                    ("rsp", x.Rsp),
                    ("rbp", x.Rbp),
                    ("rax", x.Rax),
                    ("rbx", x.Rbx),
                    ("rcx", x.Rcx),
                    ("rdx", x.Rdx),
                    ("rsi", x.Rsi),
                    ("rdi", x.Rdi),
                    ("r8", x.R8),
                    ("r9", x.R9),
                    ("r10", x.R10),
                    ("r11", x.R11),
                    ("r12", x.R12),
                    ("r13", x.R13),
                    ("r14", x.R14),
                    ("r15", x.R15),
                ];
            }
        }
        CloseHandle(h);
        regs
    }
}

impl Session {
    /// Every thread with its scheduler state and registers. The agent's own control thread is never suspended: it
    /// is reported without registers.
    pub fn thread_report(&self) -> Vec<ThreadReport> {
        let states = system_process_buffer()
            .map(|b| parse_thread_states(&b, self.pid))
            .unwrap_or_default();
        let agent = self.rd32(proto::H_AGENT_TID);
        self.threads()
            .into_iter()
            .map(|tid| ThreadReport {
                tid,
                state: states.get(&tid).copied().unwrap_or(ThreadState::Running),
                regs: if tid == agent {
                    Vec::new()
                } else {
                    read_regs(tid)
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(next: u32, pid: u64, threads: &[(u64, u32, u32)]) -> Vec<u8> {
        let mut b = vec![0u8; PROCESS_INFO_SIZE + threads.len() * THREAD_INFO_SIZE];
        b[0..4].copy_from_slice(&next.to_le_bytes());
        b[4..8].copy_from_slice(&(threads.len() as u32).to_le_bytes());
        b[0x50..0x58].copy_from_slice(&pid.to_le_bytes());
        for (i, &(tid, state, reason)) in threads.iter().enumerate() {
            let t = PROCESS_INFO_SIZE + i * THREAD_INFO_SIZE;
            b[t + 48..t + 56].copy_from_slice(&tid.to_le_bytes());
            b[t + 68..t + 72].copy_from_slice(&state.to_le_bytes());
            b[t + 72..t + 76].copy_from_slice(&reason.to_le_bytes());
        }
        b
    }

    #[test]
    fn kernel_states_map_to_frida_names() {
        assert_eq!(ThreadState::from_kernel(2, 0).as_str(), "running");
        assert_eq!(ThreadState::from_kernel(1, 0).as_str(), "running");
        assert_eq!(ThreadState::from_kernel(5, 6).as_str(), "waiting");
        assert_eq!(ThreadState::from_kernel(5, 5).as_str(), "stopped");
        assert_eq!(ThreadState::from_kernel(6, 0).as_str(), "uninterruptible");
        assert_eq!(ThreadState::from_kernel(4, 0).as_str(), "halted");
    }

    #[test]
    fn the_right_process_entry_is_found_in_a_chain() {
        let first = process(0, 4, &[(8, 5, 6)]);
        let mut chain = first.clone();
        let next = chain.len() as u32;
        chain[0..4].copy_from_slice(&next.to_le_bytes());
        chain.extend(process(0, 1234, &[(100, 2, 0), (101, 5, 6), (102, 5, 5)]));
        let states = parse_thread_states(&chain, 1234);
        assert_eq!(states.len(), 3);
        assert_eq!(states[&100], ThreadState::Running);
        assert_eq!(states[&101], ThreadState::Waiting);
        assert_eq!(states[&102], ThreadState::Stopped);
        assert!(parse_thread_states(&chain, 99).is_empty());
        assert!(parse_thread_states(&[1, 2, 3], 1234).is_empty());
    }

    #[test]
    fn this_process_is_in_the_real_table() {
        let buf = system_process_buffer().expect("NtQuerySystemInformation answers");
        let me = std::process::id();
        let states = parse_thread_states(&buf, me);
        assert!(!states.is_empty(), "the test process has threads");
        let tid = unsafe { GetCurrentThreadId() };
        assert_eq!(states.get(&tid), Some(&ThreadState::Running));
    }
}
