//! Stack walking by the x64 unwind tables, ported from `hydralysis.trace_watchdog.Unwinder` and `_walk`.
//!
//! The walk reads another process's memory through a [`Memory`] (a `ReadProcessMemory` in production, a byte map in tests)
//! and applies each function's unwind codes the way `RtlVirtualUnwind` does (push, allocation, frame register, saved
//! registers, chained entries), so the frames are the real caller chain and not a scan for words that look like return
//! addresses. A leaf function (no table entry) is a return address at the stack pointer. Only when a module has no
//! exception directory at all does a frame fall back to the frame-pointer chain and then a stack scan, and such a frame says
//! so in `how`: `rip`, `unwind`, `leaf`, `no-table`, `unmapped`, `rbp-chain`, `stack-scan`.
//!
//! Not handled, as in the original: a pc inside an epilogue (the unwind codes then over-pop). It shows as one wrong frame,
//! never as a fault, because every read is bounded and the kernel may refuse it.

use std::collections::HashMap;

/// Reads from the target. `None` when the read failed or came back short.
pub trait Memory {
    fn read(&self, address: u64, size: usize) -> Option<Vec<u8>>;
}

/// A loaded module: `(base, size, name)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Module {
    pub base: u64,
    pub size: u64,
    pub name: String,
}

/// The sixteen general registers in `REG_NAMES` order: rax rcx rdx rbx rsp rbp rsi rdi r8..r15.
pub type Regs = [u64; 16];
pub const RSP: usize = 4;
pub const RBP: usize = 5;

/// One frame of a walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub pc: u64,
    pub at: Option<String>,
    pub how: &'static str,
}

/// The unwind data of a function is truncated: the original raises `IndexError` or `struct.error` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unwind codes run past the unwind info")]
pub struct Malformed;

const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_EPILOG: u8 = 6;
const UWOP_SPARE: u8 = 7;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;
const UNW_FLAG_CHAININFO: u8 = 4;
const MAX_CHAIN: usize = 8;

/// `RUNTIME_FUNCTION`: `(begin, end, unwind info)` RVAs.
type Row = (u32, u32, u32);

struct Table {
    starts: Vec<u32>,
    rows: Vec<Row>,
}

/// Where a pc lives.
enum Entry {
    Unmapped,
    NoTable,
    Leaf,
    Function(u64, Row),
}

/// `base+size` ranges of the module list, `name+0x<offset>` for an address inside one.
pub fn resolve(address: u64, modules: &[Module]) -> Option<String> {
    modules.iter().find(|m| m.base <= address && address - m.base < m.size).map(|m| format!("{}+{:#x}", m.name, address - m.base))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Walks stacks with the target's own `.pdata`, read through MEMORY.
pub struct Unwinder<'a, M: Memory> {
    memory: &'a M,
    modules: &'a [Module],
    tables: HashMap<u64, Option<Table>>,
}

impl<'a, M: Memory> Unwinder<'a, M> {
    /// MODULES must be sorted, as `modules()` of the original returns them.
    pub fn new(memory: &'a M, modules: &'a [Module]) -> Self {
        Self { memory, modules, tables: HashMap::new() }
    }

    fn u64(&self, address: u64) -> Option<u64> {
        let data = self.memory.read(address, 8)?;
        data.get(..8).map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    fn module_at(&self, address: u64) -> Option<&Module> {
        self.modules.iter().find(|m| m.base <= address && address - m.base < m.size)
    }

    /// The exception table of the module at BASE; `None` when it has no exception directory.
    fn load_table(&self, base: u64) -> Option<Table> {
        let head = self.memory.read(base, 0x1000)?;
        if head.len() < 0x40 || &head[..2] != b"MZ" {
            return None;
        }
        let lfanew = u32_at(&head, 0x3C)? as usize;
        if lfanew + 0x108 > head.len() || &head[lfanew..lfanew + 4] != b"PE\0\0" {
            return None;
        }
        if u16_at(&head, lfanew + 24)? != 0x20B {
            return None;
        }
        let directory = lfanew + 24 + 112 + 3 * 8; // DataDirectory[3] = the exception table
        let rva = u32_at(&head, directory)?;
        let length = u32_at(&head, directory + 4)?;
        if rva == 0 || length == 0 {
            return None;
        }
        let raw = self.memory.read(base + u64::from(rva), length as usize).filter(|r| !r.is_empty())?;
        let mut rows: Vec<Row> = (0..raw.len().saturating_sub(11))
            .step_by(12)
            .filter_map(|i| Some((u32_at(&raw, i)?, u32_at(&raw, i + 4)?, u32_at(&raw, i + 8)?)))
            .collect();
        rows.sort_unstable();
        Some(Table { starts: rows.iter().map(|r| r.0).collect(), rows })
    }

    fn entry_for(&mut self, address: u64) -> Entry {
        let Some(module) = self.module_at(address) else { return Entry::Unmapped };
        let base = module.base;
        if !self.tables.contains_key(&base) {
            let table = self.load_table(base);
            self.tables.insert(base, table);
        }
        let Some(table) = self.tables.get(&base).and_then(Option::as_ref) else { return Entry::NoTable };
        let Ok(rva) = u32::try_from(address - base) else { return Entry::Leaf };
        let index = table.starts.partition_point(|&start| start <= rva);
        match index.checked_sub(1).map(|i| table.rows[i]) {
            Some(row) if row.0 <= rva && rva < row.1 => Entry::Function(base, row),
            _ => Entry::Leaf,
        }
    }

    /// Apply the unwind codes of ROW to REGS. `Ok(None)` when memory could not be read, else the return address.
    fn unwind_one(&self, base: u64, row: Row, pc: u64, regs: &mut Regs) -> Result<Option<u64>, Malformed> {
        let (begin, _end, mut info_rva) = row;
        let mut offset = pc.wrapping_sub(base + u64::from(begin));
        let mut rsp = regs[RSP];
        let mut frame_base = rsp;
        for _ in 0..MAX_CHAIN {
            let at = base + u64::from(info_rva);
            let Some(header) = self.memory.read(at, 4).filter(|h| h.len() >= 4) else { return Ok(None) };
            let (version_flags, prolog, count, frame) = (header[0], header[1], usize::from(header[2]), header[3]);
            let flags = version_flags >> 3;
            let codes_raw = if count > 0 {
                match self.memory.read(at + 4, 2 * count) {
                    Some(raw) if raw.len() >= 2 * count => raw,
                    _ => return Ok(None),
                }
            } else {
                Vec::new()
            };
            let in_prolog = offset < u64::from(prolog);
            let frame_reg = usize::from(frame & 15);
            let frame_off = u64::from(frame >> 4) * 16;
            let codes: Vec<(u8, u8, u8)> = codes_raw.as_chunks::<2>().0.iter().map(|c| (c[0], c[1] & 15, c[1] >> 4)).collect();
            let mut applied_fp = false;
            if frame_reg != 0 && !in_prolog {
                rsp = regs[frame_reg].wrapping_sub(frame_off);
                frame_base = rsp;
                applied_fp = true;
            } else if frame_reg != 0 {
                // inside the prolog: the frame register is set only if its SET_FPREG code (offset) has run
                for &(code_offset, op, _) in &codes {
                    if op == UWOP_SET_FPREG && u64::from(code_offset) <= offset {
                        rsp = regs[frame_reg].wrapping_sub(frame_off);
                        frame_base = rsp;
                        applied_fp = true;
                    }
                }
            }
            let word = |slot: usize| -> Result<u64, Malformed> {
                let at = 2 * (slot + 1);
                codes_raw.get(at..at + 2).map(|b| u64::from(b[0]) | (u64::from(b[1]) << 8)).ok_or(Malformed)
            };
            let dword = |slot: usize| -> Result<u64, Malformed> {
                let at = 2 * (slot + 1);
                codes_raw.get(at..at + 4).map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))).ok_or(Malformed)
            };
            let mut slot = 0;
            while slot < codes.len() {
                let (code_offset, op, opinfo) = codes[slot];
                let width = match op {
                    UWOP_ALLOC_LARGE if opinfo == 0 => 2,
                    UWOP_ALLOC_LARGE => 3,
                    UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 | UWOP_EPILOG | UWOP_SPARE => 2,
                    UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => 3,
                    _ => 1,
                };
                if in_prolog && u64::from(code_offset) > offset {
                    slot += width;
                    continue;
                }
                match op {
                    UWOP_PUSH_NONVOL => {
                        let Some(value) = self.u64(rsp) else { return Ok(None) };
                        regs[usize::from(opinfo)] = value;
                        rsp = rsp.wrapping_add(8);
                    }
                    UWOP_ALLOC_LARGE => {
                        let size = if opinfo == 0 { word(slot)? * 8 } else { dword(slot)? };
                        rsp = rsp.wrapping_add(size);
                    }
                    UWOP_ALLOC_SMALL => rsp = rsp.wrapping_add(u64::from(opinfo) * 8 + 8),
                    UWOP_SET_FPREG => {
                        if !applied_fp {
                            rsp = regs[frame_reg].wrapping_sub(frame_off);
                        }
                    }
                    UWOP_SAVE_NONVOL | UWOP_SAVE_NONVOL_FAR => {
                        let where_ = if op == UWOP_SAVE_NONVOL { word(slot)? * 8 } else { dword(slot)? };
                        let Some(value) = self.u64(frame_base.wrapping_add(where_)) else { return Ok(None) };
                        regs[usize::from(opinfo)] = value;
                    }
                    UWOP_PUSH_MACHFRAME => {
                        // an error code (opinfo 1), then rip, cs, eflags, rsp, ss
                        rsp = rsp.wrapping_add(if opinfo == 0 { 8 } else { 16 });
                        let (Some(new_rip), Some(new_rsp)) = (self.u64(rsp), self.u64(rsp.wrapping_add(24))) else {
                            return Ok(None);
                        };
                        regs[RSP] = new_rsp;
                        return Ok(Some(new_rip));
                    }
                    _ => {}
                }
                slot += width;
            }
            if flags & UNW_FLAG_CHAININFO != 0 {
                let chain_at = at + 4 + ((count as u64 + 1) & !1) * 2;
                let Some(chained) = self.memory.read(chain_at, 12).filter(|c| c.len() >= 12) else { return Ok(None) };
                info_rva = u32_at(&chained, 8).unwrap_or(0);
                offset = 1 << 30; // the chained entry's prolog is complete
                continue;
            }
            break;
        }
        let Some(ret) = self.u64(rsp) else { return Ok(None) };
        regs[RSP] = rsp.wrapping_add(8);
        Ok(Some(ret))
    }

    /// Frames of one thread from its registers: the first is the thread's own pc.
    pub fn walk(&mut self, regs: &Regs, rip: u64, depth: usize) -> Result<Vec<Frame>, Malformed> {
        let mut regs = *regs;
        let mut pc = rip;
        let mut frames = Vec::new();
        for index in 0..depth {
            let entry = self.entry_for(if index == 0 { pc } else { pc.wrapping_sub(1) });
            let at = resolve(pc, self.modules);
            let first = |how: &'static str| if index == 0 { "rip" } else { how };
            let ret = match entry {
                Entry::Unmapped => {
                    if index == 0 || frames.is_empty() {
                        frames.push(Frame { pc, at, how: if index == 0 { "rip" } else { "unmapped" } });
                    }
                    break;
                }
                Entry::NoTable => {
                    frames.push(Frame { pc, at, how: "no-table" });
                    break;
                }
                Entry::Leaf => {
                    let ret = self.u64(regs[RSP]);
                    frames.push(Frame { pc, at, how: first("leaf") });
                    let Some(ret) = ret else { break };
                    regs[RSP] = regs[RSP].wrapping_add(8);
                    ret
                }
                Entry::Function(base, row) => {
                    frames.push(Frame { pc, at, how: first("unwind") });
                    let Some(ret) = self.unwind_one(base, row, pc, &mut regs)? else { break };
                    ret
                }
            };
            if ret < 0x10000 {
                break;
            }
            pc = ret;
        }
        Ok(frames)
    }
}

impl<M: Memory> Unwinder<'_, M> {
    /// `_walk`: the caller chain by the unwind tables; when the first frame cannot be unwound (no table), the frame-pointer
    /// chain and a labelled stack scan.
    pub fn walk_stack(&mut self, regs: &Regs, rip: u64, depth: usize, scan_bytes: usize) -> Result<Vec<Frame>, Malformed> {
        let frames = self.walk(regs, rip, depth)?;
        if frames.len() > 1 || frames.first().is_some_and(|f| f.how != "no-table" && f.how != "unmapped") {
            return Ok(frames);
        }
        let (memory, modules) = (self.memory, self.modules);
        let mut frames = vec![Frame { pc: rip, at: resolve(rip, modules), how: "rip" }];
        let mut seen = vec![rip];
        let (mut rbp, rsp) = (regs[RBP], regs[RSP]);
        for _ in 0..depth {
            // the frame-pointer chain
            if rbp < rsp || rbp - rsp > 1 << 20 || rbp & 7 != 0 {
                break;
            }
            let Some(word) = memory.read(rbp, 16).filter(|w| w.len() >= 16) else { break };
            let next = u64::from_le_bytes([word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7]]);
            let ret = u64::from_le_bytes([word[8], word[9], word[10], word[11], word[12], word[13], word[14], word[15]]);
            let Some(at) = resolve(ret, modules) else { break };
            frames.push(Frame { pc: ret, at: Some(at), how: "rbp-chain" });
            seen.push(ret);
            if next <= rbp {
                break;
            }
            rbp = next;
        }
        // a scan for plausible return addresses (marked as a guess)
        let stack = memory.read(rsp, scan_bytes).unwrap_or_default();
        for chunk in stack.as_chunks::<8>().0 {
            let word = u64::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]]);
            if seen.contains(&word) {
                continue;
            }
            if let Some(at) = resolve(word, modules)
                && frames.len() < depth
            {
                seen.push(word);
                frames.push(Frame { pc: word, at: Some(at), how: "stack-scan" });
            }
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A sparse byte map standing in for a process.
    #[derive(Default)]
    struct Fake(BTreeMap<u64, u8>);

    impl Fake {
        fn put(&mut self, address: u64, bytes: &[u8]) {
            for (i, b) in bytes.iter().enumerate() {
                self.0.insert(address + i as u64, *b);
            }
        }

        fn put64(&mut self, address: u64, value: u64) {
            self.put(address, &value.to_le_bytes());
        }
    }

    impl Memory for Fake {
        fn read(&self, address: u64, size: usize) -> Option<Vec<u8>> {
            (0..size as u64).map(|i| self.0.get(&(address + i)).copied()).collect()
        }
    }

    const BASE: u64 = 0x1_4000_0000;

    /// One module `app.exe` at BASE with a PE header whose exception directory has `rows` (begin, end, info).
    fn image(rows: &[Row]) -> Fake {
        let mut memory = Fake::default();
        let mut head = vec![0u8; 0x1000];
        head[..2].copy_from_slice(b"MZ");
        let lfanew = 0x80usize;
        head[0x3C..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());
        head[lfanew..lfanew + 4].copy_from_slice(b"PE\0\0");
        head[lfanew + 24..lfanew + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
        let directory = lfanew + 24 + 112 + 24;
        head[directory..directory + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        head[directory + 4..directory + 8].copy_from_slice(&((rows.len() * 12) as u32).to_le_bytes());
        memory.put(BASE, &head);
        for (i, row) in rows.iter().enumerate() {
            let at = BASE + 0x2000 + (i as u64) * 12;
            memory.put(at, &row.0.to_le_bytes());
            memory.put(at + 4, &row.1.to_le_bytes());
            memory.put(at + 8, &row.2.to_le_bytes());
        }
        memory
    }

    fn modules() -> Vec<Module> {
        vec![Module { base: BASE, size: 0x10000, name: "app.exe".into() }]
    }

    fn regs(rsp: u64) -> Regs {
        let mut r = [0u64; 16];
        r[RSP] = rsp;
        r
    }

    // (the original has no unit test for the unwinder; these check the codes it applies)
    #[test]
    fn a_function_with_a_push_and_an_allocation_unwinds_to_its_caller() {
        // f at 0x1000..0x1100: push rbx; sub rsp, 0x20 (UNWIND_INFO at 0x3000: version 1, prolog 5, 2 codes, no frame register)
        let mut memory = image(&[(0x1000, 0x1100, 0x3000)]);
        memory.put(BASE + 0x3000, &[1, 5, 2, 0]);
        memory.put(BASE + 0x3004, &[5, 0x42]); // offset 5, UWOP_ALLOC_SMALL, info 4 (0x24 -> 4*8+8 = 40)... see below
        memory.put(BASE + 0x3006, &[1, 0x30]); // offset 1, UWOP_PUSH_NONVOL, info 3 (rbx)
        // codes are in reverse prolog order: the allocation (offset 5) first, then the push (offset 1)
        let rsp = 0x7000u64;
        // alloc small info 4 -> 40 bytes; the pushed rbx sits at rsp + 40; the return address after it
        memory.put64(rsp + 40, 0xDEAD);
        memory.put64(rsp + 48, BASE + 0x500);
        let mods = modules();
        let mut unwinder = Unwinder::new(&memory, &mods);
        let frames = unwinder.walk(&regs(rsp), BASE + 0x1050, 3).unwrap();
        assert_eq!(frames[0], Frame { pc: BASE + 0x1050, at: Some("app.exe+0x1050".into()), how: "rip" });
        assert_eq!(frames[1].pc, BASE + 0x500);
        assert_eq!(frames[1].how, "leaf"); // the caller sits in no function of the table
    }

    #[test]
    fn a_pc_outside_every_function_is_a_leaf_and_reads_the_return_address_at_rsp() {
        let mut memory = image(&[(0x1000, 0x1100, 0x3000)]);
        memory.put(BASE + 0x3000, &[1, 0, 0, 0]);
        memory.put64(0x7000, BASE + 0x1050);
        let mods = modules();
        let mut unwinder = Unwinder::new(&memory, &mods);
        let frames = unwinder.walk(&regs(0x7000), BASE + 0x1800, 2).unwrap();
        assert_eq!(frames[0].how, "rip");
        assert_eq!(frames[1].pc, BASE + 0x1050);
        assert_eq!(frames[1].how, "unwind");
        // the second frame is a function with no codes: its return address is the word at the adjusted rsp
        let leaf = unwinder.walk(&regs(0x7000), BASE + 0x1800, 1).unwrap();
        assert_eq!(leaf.len(), 1);
    }

    #[test]
    fn an_unmapped_pc_is_one_rip_frame() {
        let memory = image(&[]);
        let mods = modules();
        let mut unwinder = Unwinder::new(&memory, &mods);
        let frames = unwinder.walk(&regs(0x7000), 0x1234, 4).unwrap();
        assert_eq!(frames, vec![Frame { pc: 0x1234, at: None, how: "rip" }]);
    }

    #[test]
    fn a_module_without_an_exception_directory_falls_back_to_the_frame_pointer_chain_and_a_stack_scan() {
        let mut memory = Fake::default();
        let mut head = vec![0u8; 0x1000];
        head[..2].copy_from_slice(b"MZ");
        head[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        head[0x80..0x84].copy_from_slice(b"PE\0\0");
        head[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
        memory.put(BASE, &head); // exception directory is empty
        let rsp = 0x7000u64;
        let rbp = 0x7010u64;
        memory.put(rsp, &[0u8; 0x40]); // the stack the scan reads
        memory.put64(rbp, 0x7040); // saved rbp
        memory.put64(rbp + 8, BASE + 0x300); // return address
        memory.put64(0x7040, 0); // the chain stops: next <= rbp
        memory.put64(0x7040 + 8, BASE + 0x400);
        memory.put64(rsp, BASE + 0x777); // a stray word the scan will find
        let mods = modules();
        let mut unwinder = Unwinder::new(&memory, &mods);
        let mut r = regs(rsp);
        r[RBP] = rbp;
        let frames = unwinder.walk_stack(&r, BASE + 0x100, 8, 0x40).unwrap();
        let hows: Vec<&str> = frames.iter().map(|f| f.how).collect();
        assert_eq!(hows[0], "rip");
        assert!(hows.contains(&"rbp-chain"));
        assert!(hows.contains(&"stack-scan"));
        assert_eq!(frames[1].pc, BASE + 0x300);
    }

    #[test]
    fn truncated_unwind_codes_are_malformed_like_the_original_index_error() {
        let mut memory = image(&[(0x1000, 0x1100, 0x3000)]);
        // one slot declared, but UWOP_ALLOC_LARGE needs the next slot as well
        memory.put(BASE + 0x3000, &[1, 0, 1, 0]);
        memory.put(BASE + 0x3004, &[0, 0x01]);
        let mods = modules();
        let mut unwinder = Unwinder::new(&memory, &mods);
        assert_eq!(unwinder.walk(&regs(0x7000), BASE + 0x1050, 2), Err(Malformed));
    }

    #[test]
    fn chained_entries_are_followed() {
        // the entry at 0x3000 chains to an entry at 0x3100 that pushes rbx
        let mut memory = image(&[(0x1000, 0x1100, 0x3000)]);
        memory.put(BASE + 0x3000, &[(1 | (UNW_FLAG_CHAININFO << 3)), 0, 0, 0]);
        memory.put(BASE + 0x3004, &[0, 0, 0, 0]); // (count + 1) & !1 = 0 slots, then the 12-byte chained row
        memory.put(BASE + 0x3004, &0u32.to_le_bytes());
        memory.put(BASE + 0x3008, &0u32.to_le_bytes());
        memory.put(BASE + 0x300C, &0x3100u32.to_le_bytes());
        // chain_at = base + info + 4 + 0 = 0x3004: begin, end, info
        memory.put(BASE + 0x3004, &0x1000u32.to_le_bytes());
        memory.put(BASE + 0x3008, &0x1100u32.to_le_bytes());
        memory.put(BASE + 0x3100, &[1, 1, 1, 0]);
        memory.put(BASE + 0x3104, &[1, 0x30, 0, 0]);
        memory.put64(0x7000, 0xBEEF); // the pushed rbx
        memory.put64(0x7008, BASE + 0x600);
        let mods = modules();
        let mut unwinder = Unwinder::new(&memory, &mods);
        let frames = unwinder.walk(&regs(0x7000), BASE + 0x1050, 2).unwrap();
        assert_eq!(frames[1].pc, BASE + 0x600);
    }
}
