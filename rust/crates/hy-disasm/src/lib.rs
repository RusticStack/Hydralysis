//! x86/x64 disassembly through the capstone C library.
//!
//! The text is produced by the same C engine the Python tools use (capstone 5.x), so mnemonic and operand
//! strings, lengths and the stop-at-first-undecodable-byte behaviour are identical by construction.

use capstone::arch::ArchOperand;
use capstone::arch::BuildsCapstone;
use capstone::arch::x86::{ArchMode, X86OperandType};
use capstone::{Capstone, Insn};

/// One decoded instruction (owned, so it outlives the decoder buffer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub address: u64,
    pub size: usize,
    pub mnemonic: String,
    pub op_str: String,
    /// Target of a direct `call imm`, if this instruction is one.
    pub direct_call: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum DisasmError {
    #[error("capstone: {0}")]
    Capstone(String),
}

/// A reusable decoder for 32- or 64-bit x86.
pub struct Decoder {
    cs: Capstone,
}

impl Decoder {
    pub fn new(bits: u32) -> Result<Self, DisasmError> {
        let mode = if bits == 32 { ArchMode::Mode32 } else { ArchMode::Mode64 };
        let cs = Capstone::new().x86().mode(mode).detail(true).build().map_err(|e| DisasmError::Capstone(e.to_string()))?;
        Ok(Self { cs })
    }

    /// Decode linearly from `address`, stopping at the first undecodable byte (capstone default, no skipdata)
    /// or after `max` instructions.
    pub fn decode(&self, code: &[u8], address: u64, max: usize) -> Result<Vec<Decoded>, DisasmError> {
        let insns = self.cs.disasm_all(code, address).map_err(|e| DisasmError::Capstone(e.to_string()))?;
        let mut out = Vec::new();
        for insn in insns.iter().take(max) {
            out.push(self.to_decoded(insn));
        }
        Ok(out)
    }

    fn to_decoded(&self, insn: &Insn) -> Decoded {
        let mnemonic = insn.mnemonic().unwrap_or("").to_string();
        let direct_call = (mnemonic == "call").then(|| self.cs.insn_detail(insn).ok()).flatten().and_then(|detail| {
            match detail.arch_detail().operands().first() {
                Some(ArchOperand::X86Operand(op)) => match op.op_type {
                    X86OperandType::Imm(v) => Some(v),
                    _ => None,
                },
                _ => None,
            }
        });
        Decoded { address: insn.address(), size: insn.len(), mnemonic, op_str: insn.op_str().unwrap_or("").to_string(), direct_call }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_x64_call_and_ret() {
        let d = Decoder::new(64).unwrap();
        let out = d.decode(&[0xE8, 0x0B, 0, 0, 0, 0xC3], 0x1000, 10).unwrap();
        assert_eq!(out[0].mnemonic, "call");
        assert_eq!(out[0].op_str, "0x1010");
        assert_eq!(out[0].direct_call, Some(0x1010));
        assert_eq!(out[1].mnemonic, "ret");
        assert_eq!(out[1].size, 1);
    }

    #[test]
    fn rip_relative_text_matches_capstone() {
        let d = Decoder::new(64).unwrap();
        let out = d.decode(&[0x48, 0x8D, 0x0D, 0x10, 0, 0, 0], 0x1000, 1).unwrap();
        assert_eq!(out[0].op_str, "rcx, [rip + 0x10]");
    }

    #[test]
    fn stops_at_undecodable() {
        let d = Decoder::new(64).unwrap();
        let out = d.decode(&[0x90, 0x06, 0x90], 0, 10).unwrap();
        assert_eq!(out.len(), 1);
    }
}
