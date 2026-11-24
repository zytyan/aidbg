use crate::{Result, disassembly, error, regs, trace::Trace};
use capstone::{AccessType, Capstone, Insn, RegId, prelude::*};
use std::collections::BTreeMap;

pub(super) struct Decoded {
    pub mnemonic: String,
    pub length: usize,
    pub memory: Vec<MemoryAccess>,
    pub registers: Vec<String>,
}

pub(super) struct MemoryAccess {
    address: u64,
    length: u64,
    access: AccessType,
}

impl MemoryAccess {
    pub fn overlaps(&self, address: u64, length: usize) -> bool {
        self.address < address.saturating_add(length as u64)
            && address < self.address.saturating_add(self.length)
    }
    pub fn reads(&self) -> bool {
        self.access.is_readable()
    }
    pub fn writes(&self) -> bool {
        self.access.is_writable()
    }
}

pub(super) fn decode(trace: &Trace, pc: u64, regs: &regs::Snapshot) -> Result<Decoded> {
    let (mut decoder, width) = disassembly::decoder(regs::ARCH)?;
    decoder.set_detail(true).map_err(|e| error(e.to_string()))?;
    let mut bytes = vec![0; width as usize];
    let got = trace.read_code_prefix(pc, &mut bytes)?;
    let insns = decoder
        .disasm_count(&bytes[..got], pc, 1)
        .map_err(|e| error(e.to_string()))?;
    let insn = insns
        .iter()
        .next()
        .ok_or_else(|| error("could not decode instruction"))?;
    let detail = decoder
        .insn_detail(insn)
        .map_err(|e| error(e.to_string()))?;
    let mnemonic = insn.mnemonic().unwrap_or_default().to_owned();
    let mut registers = detail
        .regs_read()
        .iter()
        .filter_map(|&reg| decoder.reg_name(reg))
        .collect::<Vec<_>>();
    let memory = memory_accesses(&decoder, insn, &detail, &regs.general, &mut registers);
    Ok(Decoded {
        mnemonic,
        length: insn.bytes().len(),
        memory,
        registers,
    })
}

fn raw(registers: &BTreeMap<String, String>, name: &str) -> Option<u64> {
    u64::from_str_radix(registers.get(name)?.trim_start_matches("0x"), 16).ok()
}

#[cfg(target_arch = "x86_64")]
fn memory_accesses(
    decoder: &Capstone,
    insn: &Insn<'_>,
    detail: &capstone::InsnDetail<'_>,
    registers: &BTreeMap<String, String>,
    used: &mut Vec<String>,
) -> Vec<MemoryAccess> {
    use capstone::arch::x86::X86OperandType;
    let arch = detail.arch_detail();
    let Some(x86) = arch.x86() else {
        return Vec::new();
    };
    let mnemonic = insn.mnemonic().unwrap_or_default();
    let register = |reg: RegId| -> Option<u64> {
        let Some(name) = decoder.reg_name(reg) else {
            return Some(0);
        };
        match name.as_str() {
            "riz" | "eiz" => Some(0),
            "rip" | "eip" => Some(insn.address().wrapping_add(insn.bytes().len() as u64)),
            "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" => {
                raw(registers, &format!("r{}", &name[1..])).map(|value| value & 0xffff_ffff)
            }
            "fs" | "gs" => raw(registers, &format!("{name}_base")),
            "cs" | "ds" | "es" | "ss" => Some(0),
            _ => name
                .strip_suffix('d')
                .and_then(|name| raw(registers, name))
                .map(|value| value & 0xffff_ffff)
                .or_else(|| raw(registers, &name)),
        }
    };
    let mut result = Vec::new();
    for operand in x86.operands() {
        match operand.op_type {
            X86OperandType::Reg(reg) if operand.access.is_some_and(AccessType::is_readable) => {
                if let Some(name) = decoder.reg_name(reg) {
                    used.push(name);
                }
            }
            X86OperandType::Mem(mem) if mnemonic != "lea" && !mnemonic.starts_with("prefetch") => {
                if let (Some(access), Some(base), Some(index), Some(segment)) = (
                    operand.access,
                    register(mem.base()),
                    register(mem.index()),
                    register(mem.segment()),
                ) {
                    let mut address = base
                        .wrapping_add(index.wrapping_mul(mem.scale() as u64))
                        .wrapping_add_signed(mem.disp());
                    if x86.addr_size() == 4 {
                        address &= 0xffff_ffff;
                    }
                    result.push(MemoryAccess {
                        address: address.wrapping_add(segment),
                        length: u64::from(operand.size),
                        access,
                    });
                }
            }
            _ => {}
        }
    }
    // Some instructions use the stack without a memory operand in the disassembly.
    if let Some(stack) = raw(registers, "rsp") {
        let width = if insn.bytes().first() == Some(&0x66) {
            2
        } else {
            8
        };
        if mnemonic.starts_with("pop") || mnemonic.starts_with("ret") {
            result.push(MemoryAccess {
                address: stack,
                length: width,
                access: AccessType::ReadOnly,
            });
        } else if mnemonic.starts_with("push") || matches!(mnemonic, "call" | "lcall") {
            result.push(MemoryAccess {
                address: stack.wrapping_sub(width),
                length: width,
                access: AccessType::WriteOnly,
            });
        }
    }
    result
}

#[cfg(target_arch = "aarch64")]
fn memory_accesses(
    decoder: &Capstone,
    insn: &Insn<'_>,
    detail: &capstone::InsnDetail<'_>,
    registers: &BTreeMap<String, String>,
    used: &mut Vec<String>,
) -> Vec<MemoryAccess> {
    use capstone::arch::arm64::{Arm64Extender, Arm64OperandType, Arm64Shift};
    let arch = detail.arch_detail();
    let Some(arm) = arch.arm64() else {
        return Vec::new();
    };
    let mnemonic = insn.mnemonic().unwrap_or_default();
    let register = |reg: RegId| -> Option<u64> {
        let Some(name) = decoder.reg_name(reg) else {
            return Some(0);
        };
        match name.as_str() {
            "xzr" | "wzr" => Some(0),
            "wsp" => Some(raw(registers, "sp")? & 0xffff_ffff),
            "fp" => raw(registers, "x29"),
            "lr" => raw(registers, "x30"),
            _ => name
                .strip_prefix('w')
                .and_then(|index| raw(registers, &format!("x{index}")))
                .map(|word| word & 0xffff_ffff)
                .or_else(|| raw(registers, &name)),
        }
    };
    let mut widths = Vec::new();
    let mut result = Vec::new();
    for operand in arm.operands() {
        match operand.op_type {
            Arm64OperandType::Reg(reg) => {
                if let Some(name) = decoder.reg_name(reg) {
                    if operand.access.is_none_or(AccessType::is_readable) {
                        used.push(name.clone());
                    }
                    widths.push(match name.as_bytes().first() {
                        Some(b'b') => 1,
                        Some(b'h') => 2,
                        Some(b'w' | b's') => 4,
                        Some(b'q' | b'v') => 16,
                        _ => 8,
                    });
                }
            }
            Arm64OperandType::Mem(mem) => {
                let (Some(base), Some(index)) = (register(mem.base()), register(mem.index()))
                else {
                    continue;
                };
                let index = match operand.ext {
                    Arm64Extender::ARM64_EXT_UXTB => u64::from(index as u8),
                    Arm64Extender::ARM64_EXT_UXTH => u64::from(index as u16),
                    Arm64Extender::ARM64_EXT_UXTW => u64::from(index as u32),
                    Arm64Extender::ARM64_EXT_SXTB => index as i8 as u64,
                    Arm64Extender::ARM64_EXT_SXTH => index as i16 as u64,
                    Arm64Extender::ARM64_EXT_SXTW => index as i32 as u64,
                    _ => index,
                };
                let index = match operand.shift {
                    Arm64Shift::Lsl(shift) => index.wrapping_shl(shift),
                    _ => index,
                };
                let length = if mnemonic.ends_with('b') {
                    1
                } else if mnemonic.ends_with('h') {
                    2
                } else if mnemonic.ends_with("sw") {
                    4
                } else if matches!(mnemonic, "ldp" | "stp" | "ldnp" | "stnp") {
                    widths.iter().sum()
                } else {
                    widths.last().copied().unwrap_or(1)
                };
                let access = if mnemonic.starts_with("ld") {
                    Some(AccessType::ReadOnly)
                } else if mnemonic.starts_with("st") {
                    Some(AccessType::WriteOnly)
                } else if mnemonic.starts_with("cas") || mnemonic.starts_with("swp") {
                    Some(AccessType::ReadWrite)
                } else {
                    operand.access
                };
                if let Some(access) = access {
                    result.push(MemoryAccess {
                        address: base
                            .wrapping_add(index)
                            .wrapping_add_signed(i64::from(mem.disp())),
                        length,
                        access,
                    });
                }
            }
            _ => {}
        }
    }
    result
}
