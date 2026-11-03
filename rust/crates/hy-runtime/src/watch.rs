//! Hardware watchpoints through the debug registers. The host sets DR0-3/DR7 on every thread (SetThreadContext on a
//! suspended thread); the agent's vectored handler records the hits. A slot is a state machine
//! `arming -> armed -> disarming -> clear | tainted` that reaches `clear` only through a DR7 readback of every
//! thread. Port of the watch half of `runtime_memory.py`.
use crate::authorize::Action;
use crate::memory::{Gate, MemError};
use crate::session::Session;
use hy_agent_proto as proto;
use std::collections::HashSet;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::*;

pub const SLOTS: usize = proto::MAX_WATCH;
pub const DISARM_ATTEMPTS: usize = 5;
pub const DISARM_PAUSE: Duration = Duration::from_millis(20);
const CONTEXT_DEBUG_REGISTERS_AMD64: CONTEXT_FLAGS = 0x0010_0010;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Arming,
    Armed,
    Disarming,
    Clear,
    Tainted,
}

impl Phase {
    /// The legal moves (the state machine of the Python worker).
    pub fn can_move_to(self, to: Phase) -> bool {
        use Phase::*;
        matches!(
            (self, to),
            (Arming, Armed)
                | (Arming, Disarming)
                | (Armed, Disarming)
                | (Disarming, Clear)
                | (Disarming, Tainted)
                | (Tainted, Disarming)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Write,
    ReadWrite,
}

#[derive(Clone, Debug)]
pub struct WatchSlot {
    pub address: u64,
    pub size: u32,
    pub kind: Kind,
    pub phase: Phase,
    pub threads: HashSet<u32>,
}

#[derive(Default)]
pub struct WatchState {
    pub slots: [Option<WatchSlot>; SLOTS],
}

fn dr7_bits(slot: usize, size: u32, kind: Kind) -> u64 {
    let rw: u64 = if kind == Kind::Write { 0b01 } else { 0b11 };
    let len: u64 = match size {
        1 => 0b00,
        2 => 0b01,
        4 => 0b11,
        _ => 0b10,
    };
    (1u64 << (2 * slot)) | (rw << (16 + 4 * slot)) | (len << (18 + 4 * slot))
}

fn dr7_mask(slot: usize) -> u64 {
    (0b11u64 << (2 * slot)) | (0xFu64 << (16 + 4 * slot))
}

/// CONTEXT must sit on a 16-byte boundary; the windows-sys type does not promise it.
#[repr(C, align(16))]
struct Ctx(CONTEXT);

struct Thread(HANDLE);
impl Drop for Thread {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Set or clear one slot on a thread. Returns the DR7 read back afterwards, `None` when the thread is gone.
fn program_thread(
    tid: u32,
    slot: usize,
    program: Option<(u64, u64)>,
) -> Result<Option<u64>, std::io::Error> {
    unsafe {
        let h = OpenThread(
            THREAD_SUSPEND_RESUME
                | THREAD_GET_CONTEXT
                | THREAD_SET_CONTEXT
                | THREAD_QUERY_INFORMATION,
            0,
            tid,
        );
        if h.is_null() {
            let e = std::io::Error::last_os_error();
            return if e.raw_os_error() == Some(87) {
                Ok(None)
            } else {
                Err(e)
            };
        }
        let t = Thread(h);
        if SuspendThread(t.0) == u32::MAX {
            return Ok(None);
        }
        let result = (|| {
            let mut c: Ctx = core::mem::zeroed();
            let ctx = &mut c.0;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            if GetThreadContext(t.0, ctx) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let dr = [
                &mut ctx.Dr0 as *mut u64,
                &mut ctx.Dr1,
                &mut ctx.Dr2,
                &mut ctx.Dr3,
            ];
            match program {
                Some((addr, bits)) => {
                    dr[slot].write(addr);
                    ctx.Dr7 = (ctx.Dr7 & !dr7_mask(slot)) | bits;
                }
                None => {
                    ctx.Dr7 &= !dr7_mask(slot);
                    dr[slot].write(0);
                }
            }
            ctx.Dr6 = 0;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            if SetThreadContext(t.0, ctx) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut b: Ctx = core::mem::zeroed();
            let back = &mut b.0;
            back.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            if GetThreadContext(t.0, back) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Some(back.Dr7))
        })();
        ResumeThread(t.0);
        result
    }
}

/// Read DR7 of a thread without changing it. `None` when the thread is gone or cannot be suspended.
fn read_thread_dr7(tid: u32) -> Option<u64> {
    unsafe {
        let h = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            0,
            tid,
        );
        if h.is_null() {
            return None;
        }
        let t = Thread(h);
        if SuspendThread(t.0) == u32::MAX {
            return None;
        }
        let mut c: Ctx = core::mem::zeroed();
        c.0.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
        let ok = GetThreadContext(t.0, &mut c.0) != 0;
        ResumeThread(t.0);
        ok.then_some(c.0.Dr7)
    }
}

impl Session {
    /// Arm a hardware watch. Needs the policy gate; size 1/2/4/8, naturally aligned, data memory only.
    pub fn arm_watch(
        &mut self,
        gate: &Gate,
        address: u64,
        size: u32,
        kind: Kind,
        limit: u32,
    ) -> Result<usize, MemError> {
        if ![1, 2, 4, 8].contains(&size) || !address.is_multiple_of(size as u64) {
            return Err(MemError::BadRequest(
                "a watch is 1, 2, 4 or 8 bytes and naturally aligned".into(),
            ));
        }
        self.identity
            .verify()
            .map_err(|e| MemError::BadRequest(e.to_string()))?;
        if let Gate::Authorized(a) = gate {
            let module = self.module_of(address);
            a.check(Action::Watch, address, size as u64, module.as_ref())
                .map_err(MemError::Refused)?;
        }
        self.require_data_span(address, size as u64)?;
        let slot = (0..SLOTS)
            .find(|&i| {
                self.watch.slots[i]
                    .as_ref()
                    .is_none_or(|w| w.phase == Phase::Clear)
            })
            .ok_or_else(|| {
                MemError::BadRequest("all four debug-register slots are in use".into())
            })?;
        self.watch.slots[slot] = Some(WatchSlot {
            address,
            size,
            kind,
            phase: Phase::Arming,
            threads: HashSet::new(),
        });
        // The agent's handler owns every single-step from now on; publish the slot before any register is set.
        let w = proto::watch_offset(slot);
        self.wr32(w + proto::W_HITS, 0);
        self.wr32(w + proto::W_LIMIT, limit);
        self.wr32(w + proto::W_LEN, size);
        self.wr32(w + proto::W_KIND, if kind == Kind::Write { 1 } else { 3 });
        unsafe { (self.view.add(w + proto::W_ADDR) as *mut u64).write_volatile(address) };
        self.wr32(w + proto::W_ARMED, 1);
        self.wr32(proto::H_WATCH_SEEN, 1);
        let bits = dr7_bits(slot, size, kind);
        for tid in self.threads() {
            match program_thread(tid, slot, Some((address, bits))) {
                Ok(Some(dr7)) if dr7 & bits == bits => {
                    self.watch.slots[slot].as_mut().unwrap().threads.insert(tid);
                }
                Ok(None) => {}
                other => {
                    let why = match other {
                        Ok(Some(dr7)) => format!("thread {tid} read back DR7 {dr7:#x}"),
                        Err(e) => format!("thread {tid}: {e}"),
                        Ok(None) => unreachable!(),
                    };
                    let _ = self.disarm_watch(slot);
                    return Err(MemError::BadRequest(format!("arming failed: {why}")));
                }
            }
        }
        self.watch.slots[slot].as_mut().unwrap().phase = Phase::Armed;
        Ok(slot)
    }

    /// Program the armed slots into threads created since the last call (the agent cannot, so the host polls).
    pub fn sync_watch_threads(&mut self) {
        let tids = self.threads();
        for slot in 0..SLOTS {
            let Some(w) = self.watch.slots[slot]
                .as_ref()
                .filter(|w| w.phase == Phase::Armed)
            else {
                continue;
            };
            let (addr, bits) = (w.address, dr7_bits(slot, w.size, w.kind));
            for &tid in tids
                .iter()
                .filter(|t| !w.threads.contains(t))
                .collect::<Vec<_>>()
            {
                if let Ok(Some(dr7)) = program_thread(tid, slot, Some((addr, bits)))
                    && dr7 & bits == bits
                {
                    self.watch.slots[slot].as_mut().unwrap().threads.insert(tid);
                }
            }
        }
    }

    /// Disarm a slot. `Clear` only after a DR7 readback of every live thread shows the slot off; otherwise `Tainted`
    /// (a tainted target must not be detached: an armed register with no handler kills the thread with 0x80000004).
    pub fn disarm_watch(&mut self, slot: usize) -> Result<Phase, MemError> {
        let Some(w) = self.watch.slots.get_mut(slot).and_then(|w| w.as_mut()) else {
            return Err(MemError::BadRequest(format!("slot {slot} is not in use")));
        };
        if !w.phase.can_move_to(Phase::Disarming) {
            return Err(MemError::BadRequest(format!(
                "slot {slot} is {:?}",
                w.phase
            )));
        }
        w.phase = Phase::Disarming;
        let mask = dr7_mask(slot);
        let mut clean = false;
        for attempt in 0..DISARM_ATTEMPTS {
            clean = true;
            for tid in self.threads() {
                match program_thread(tid, slot, None) {
                    Ok(Some(dr7)) if dr7 & mask == 0 => {}
                    Ok(None) => {}
                    _ => clean = false,
                }
            }
            if clean {
                break;
            }
            if attempt + 1 < DISARM_ATTEMPTS {
                std::thread::sleep(DISARM_PAUSE);
            }
        }
        let phase = if clean { Phase::Clear } else { Phase::Tainted };
        self.watch.slots[slot].as_mut().unwrap().phase = phase;
        if clean {
            self.wr32(proto::watch_offset(slot) + proto::W_ARMED, 0);
        }
        Ok(phase)
    }

    /// DR7 of every thread of the target, read fresh: `(readable rows as (tid, dr7), tids that could not be read)`.
    /// A thread that exited between the listing and the read is not "unreadable": it is gone.
    pub fn read_dr7(&self) -> (Vec<(u32, u64)>, Vec<u32>) {
        let (mut rows, mut unreadable) = (Vec::new(), Vec::new());
        for tid in self.threads() {
            match read_thread_dr7(tid) {
                Some(dr7) => rows.push((tid, dr7)),
                None if self.threads().contains(&tid) => unreadable.push(tid),
                None => {}
            }
        }
        (rows, unreadable)
    }

    /// The threads a slot has been programmed into (sorted).
    pub fn watch_threads(&self, slot: usize) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .watch
            .slots
            .get(slot)
            .and_then(|w| w.as_ref())
            .map(|w| w.threads.iter().copied().collect())
            .unwrap_or_default();
        v.sort_unstable();
        v
    }

    pub fn watch_hits(&self, slot: usize) -> u32 {
        self.rd32(proto::watch_offset(slot) + proto::W_HITS)
    }

    /// True when any slot is tainted: detach is refused unless the owner forces it.
    pub fn watch_tainted(&self) -> bool {
        self.watch
            .slots
            .iter()
            .flatten()
            .any(|w| w.phase == Phase::Tainted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_edges() {
        use Phase::*;
        assert!(Arming.can_move_to(Armed));
        assert!(Armed.can_move_to(Disarming));
        assert!(Disarming.can_move_to(Clear));
        assert!(Disarming.can_move_to(Tainted));
        assert!(Tainted.can_move_to(Disarming));
        assert!(!Clear.can_move_to(Armed));
        assert!(!Armed.can_move_to(Clear));
    }

    #[test]
    fn dr7_encoding() {
        // slot 1, 4 bytes, write: L1 = bit 2; RW1 = 01 at 20; LEN1 = 11 at 22.
        assert_eq!(
            dr7_bits(1, 4, Kind::Write),
            (1 << 2) | (0b01 << 20) | (0b11 << 22)
        );
        assert_eq!(
            dr7_bits(0, 8, Kind::ReadWrite),
            1 | (0b11 << 16) | (0b10 << 18)
        );
        assert_eq!(
            dr7_mask(2) & dr7_bits(2, 2, Kind::Write),
            dr7_bits(2, 2, Kind::Write)
        );
    }
}

#[cfg(test)]
mod abi {
    #[test]
    fn context_is_16_aligned() {
        assert_eq!(core::mem::align_of::<super::Ctx>(), 16);
        assert_eq!(
            core::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::CONTEXT>(),
            1232
        );
    }
}
