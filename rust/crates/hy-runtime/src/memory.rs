//! Runtime memory write: compare-and-swap with a required reason, refused in executable ranges, with an undo log
//! that reports DIVERGED instead of overwriting what changed since. Port of the `write` half of
//! `runtime_memory.py`; the policy gate is `Gate` (fixture mode, or an owner authorization).
use crate::authorize::{Action, Authorization, ModuleRef, Refusal};
use crate::session::Session;
use std::io;

pub const MAX_WRITE: usize = 64;
pub const MIN_REASON: usize = 8;

/// Which mode admitted the request. The caller (the tool surface) decides this from settings and the build's hash;
/// the runtime never infers it from the target.
#[derive(Clone, Debug)]
pub enum Gate {
    Fixture,
    Authorized(Authorization),
}

impl Gate {
    pub fn mode(&self) -> &'static str {
        match self {
            Gate::Fixture => "fixture",
            Gate::Authorized(_) => "authorized",
        }
    }
}

#[derive(Debug)]
pub enum MemError {
    Refused(Refusal),
    ExecutableRange(u64),
    BadRequest(String),
    /// The bytes at the address were not what the caller expected.
    CasMismatch {
        found: Vec<u8>,
    },
    /// The bytes changed since our write: undo refuses to clobber them.
    Diverged {
        found: Vec<u8>,
    },
    Readback {
        found: Vec<u8>,
    },
    UnknownUndo(u32),
    Os(io::Error),
}

impl std::fmt::Display for MemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemError::Refused(r) => write!(f, "{r}"),
            MemError::ExecutableRange(a) => write!(f, "EXECUTABLE RANGE at {a:#x}; refused"),
            MemError::BadRequest(s) => write!(f, "{s}"),
            MemError::CasMismatch { found } => {
                write!(f, "compare failed: memory holds {found:02x?}")
            }
            MemError::Diverged { found } => write!(f, "DIVERGED: memory now holds {found:02x?}; not overwritten"),
            MemError::Readback { found } => write!(f, "readback mismatch: {found:02x?}"),
            MemError::UnknownUndo(i) => write!(f, "no undo entry {i}"),
            MemError::Os(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for MemError {}
impl From<io::Error> for MemError {
    fn from(e: io::Error) -> Self {
        MemError::Os(e)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UndoState {
    Applied,
    Undone,
}

#[derive(Clone, Debug)]
pub struct UndoEntry {
    pub id: u32,
    pub address: u64,
    pub old: Vec<u8>,
    pub new: Vec<u8>,
    pub reason: String,
    pub mode: &'static str,
    pub state: UndoState,
}

#[derive(Default)]
pub struct MemoryState {
    pub log: Vec<UndoEntry>,
}

const EXEC: u32 = 0x10 | 0x20 | 0x40 | 0x80; // PAGE_EXECUTE, _READ, _READWRITE, _WRITECOPY

impl Session {
    pub(crate) fn module_of(&self, address: u64) -> Option<ModuleRef> {
        self.modules()
            .ok()?
            .into_iter()
            .find(|m| address >= m.base && address < m.base + m.size as u64)
            .map(|m| ModuleRef { name: m.name, base: m.base })
    }

    /// Refuse when any byte of the span lies in an executable (or unmapped) region.
    pub(crate) fn require_data_span(&self, address: u64, len: u64) -> Result<(), MemError> {
        let mut at = address;
        let end = address + len;
        while at < end {
            let (base, size, protect) = self.query(at)?;
            if protect == 0 {
                return Err(MemError::BadRequest(format!("{at:#x} is not committed memory")));
            }
            if protect & EXEC != 0 {
                return Err(MemError::ExecutableRange(at));
            }
            at = base + size;
        }
        Ok(())
    }

    fn gate_check(&self, gate: &Gate, action: Action, address: u64, size: u64) -> Result<(), MemError> {
        if let Gate::Authorized(a) = gate {
            let module = self.module_of(address);
            a.check(action, address, size, module.as_ref()).map_err(MemError::Refused)?;
        }
        Ok(())
    }

    /// Compare-and-swap `expect` -> `value` at `address`. Returns the undo id.
    pub fn write_cas(&mut self, gate: &Gate, address: u64, expect: &[u8], value: &[u8], reason: &str) -> Result<u32, MemError> {
        if value.is_empty() || value.len() > MAX_WRITE || expect.len() != value.len() {
            return Err(MemError::BadRequest(format!("expect and value must be the same size, 1..{MAX_WRITE} bytes")));
        }
        if reason.trim().chars().count() < MIN_REASON {
            return Err(MemError::BadRequest(format!("a write needs a reason of at least {MIN_REASON} characters")));
        }
        self.identity.verify().map_err(|e| MemError::BadRequest(e.to_string()))?;
        self.gate_check(gate, Action::Write, address, value.len() as u64)?;
        self.require_data_span(address, value.len() as u64)?;
        let found = self.read_memory(address, value.len())?;
        if found != expect {
            return Err(MemError::CasMismatch { found });
        }
        self.write_raw(address, value)?;
        let back = self.read_memory(address, value.len())?;
        if back != value {
            return Err(MemError::Readback { found: back });
        }
        let id = self.memory.log.last().map_or(1, |e| e.id + 1);
        self.memory.log.push(UndoEntry {
            id,
            address,
            old: expect.to_vec(),
            new: value.to_vec(),
            reason: reason.trim().to_string(),
            mode: gate.mode(),
            state: UndoState::Applied,
        });
        Ok(id)
    }

    /// Undo write `id` unless the memory changed since (then `Diverged`, nothing written). Range-checked like a write.
    pub fn undo_write(&mut self, gate: &Gate, id: u32) -> Result<(), MemError> {
        let idx = self.memory.log.iter().position(|e| e.id == id && e.state == UndoState::Applied).ok_or(MemError::UnknownUndo(id))?;
        let (address, old, new) = {
            let e = &self.memory.log[idx];
            (e.address, e.old.clone(), e.new.clone())
        };
        self.identity.verify().map_err(|e| MemError::BadRequest(e.to_string()))?;
        self.gate_check(gate, Action::Write, address, old.len() as u64)?;
        self.require_data_span(address, old.len() as u64)?;
        let found = self.read_memory(address, old.len())?;
        if found != new {
            return Err(MemError::Diverged { found });
        }
        self.write_raw(address, &old)?;
        self.memory.log[idx].state = UndoState::Undone;
        Ok(())
    }

    pub fn undo_log(&self) -> &[UndoEntry] {
        &self.memory.log
    }
}
