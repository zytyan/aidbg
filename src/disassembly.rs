use crate::{Result, error, hex, machine, modules, procfs, symbols};
use capstone::prelude::*;
use nix::{sys::uio, unistd::Pid};
use serde::Serialize;
use std::{fs::File, io::IoSliceMut, os::fd::AsRawFd, path::PathBuf};

const MAX_WINDOW: u32 = 128;
const MAX_LOOKBACK: u64 = 64 * 1024;

#[derive(Serialize)]
struct Instruction {
    address: String,
    bytes: String,
    mnemonic: Option<String>,
    operands: Option<String>,
}

#[derive(Serialize)]
pub struct Window {
    architecture: &'static str,
    address: String,
    boundary: &'static str,
    anchor: String,
    address_is_instruction_start: bool,
    truncated_before: bool,
    truncated_after: bool,
    instructions: Vec<Instruction>,
    byte_source: &'static str,
    pub(crate) warnings: Vec<crate::Diagnostic>,
}

pub(crate) fn decoder(architecture: &str) -> Result<(Capstone, u64)> {
    Ok(match architecture {
        "x86_64" => (
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .build()?,
            15,
        ),
        "aarch64" => (
            Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .build()?,
            4,
        ),
        _ => return Err(error("unsupported disassembly architecture")),
    })
}

pub fn disassemble(
    pid: i32,
    address: u64,
    before: u32,
    after: u32,
    start: Option<u64>,
) -> Result<Window> {
    disassemble_with(pid, address, before, after, start, |anchor, buffer| {
        let remote = [uio::RemoteIoVec {
            base: usize::try_from(anchor)?,
            len: buffer.len(),
        }];
        Ok(uio::process_vm_readv(
            Pid::from_raw(pid),
            &mut [IoSliceMut::new(buffer)],
            &remote,
        )?)
    })
}

pub(crate) fn disassemble_with(
    pid: i32,
    address: u64,
    before: u32,
    after: u32,
    start: Option<u64>,
    read: impl FnOnce(u64, &mut [u8]) -> Result<usize>,
) -> Result<Window> {
    let procdir = File::open(format!("/proc/{pid}"))?;
    let root = PathBuf::from(format!("/proc/self/fd/{}", procdir.as_raw_fd()));
    let start_ticks = procfs::start_ticks(&root)?;
    let exe = std::fs::metadata(root.join("exe"))?;
    let architecture = machine(&root)?;
    let mapping = modules::mapping_at(&root, address)?
        .filter(|m| m.executable())
        .ok_or_else(|| error("address is outside executable mappings"))?;
    decode_window(
        architecture,
        address,
        before,
        after,
        start,
        &mapping,
        symbols::code_start(&root, address),
        "process",
        |anchor, buffer| {
            let read = read(anchor, buffer)?;
            use std::os::unix::fs::MetadataExt;
            let current = std::fs::metadata(root.join("exe"))?;
            if procfs::start_ticks(&root)? != start_ticks
                || (exe.dev(), exe.ino()) != (current.dev(), current.ino())
            {
                return Err(error("target identity changed during disassembly"));
            }

            Ok(read)
        },
    )
}

pub(crate) fn decode_window(
    architecture: &'static str,
    address: u64,
    before: u32,
    after: u32,
    start: Option<u64>,
    mapping: &modules::Mapping,
    function_entry: Option<u64>,
    byte_source: &'static str,
    read: impl FnOnce(u64, &mut [u8]) -> Result<usize>,
) -> Result<Window> {
    if before > MAX_WINDOW || after > MAX_WINDOW {
        return Err(error("before and after must be in 0..=128"));
    }
    let (engine, width) = decoder(architecture)?;
    if start.is_some_and(|start| {
        start > address || !mapping.contains(start) || address - start > MAX_LOOKBACK
    }) {
        return Err(error(
            "start must be in the same mapping, at most 64 KiB before the address",
        ));
    }
    let (anchor, mut boundary) = if architecture == "aarch64" {
        let aligned = address & !3;
        if start.is_some_and(|s| s % 4 != 0) {
            return Err(error("AArch64 start must be four-byte aligned"));
        }
        (
            start.unwrap_or_else(|| {
                aligned
                    .saturating_sub(u64::from(before) * 4)
                    .max(mapping.start)
            }),
            "architecture_alignment",
        )
    } else if let Some(start) = start {
        (start, "explicit_start")
    } else if let Some(entry) =
        function_entry.filter(|entry| *entry <= address && address - entry <= MAX_LOOKBACK)
    {
        (entry, "function_entry")
    } else {
        (address, "uncertain")
    };
    // Capstone stops at invalid bytes. Decode AArch64 slots separately so a
    // single invalid word cannot obscure boundaries in the rest of the window.
    let end = (address & if width == 4 { !3 } else { u64::MAX })
        .saturating_add((u64::from(after) + 1) * width)
        .min(mapping.end);
    let mut buffer = vec![0; usize::try_from(end - anchor)?];
    let count = read(anchor, &mut buffer)?;
    buffer.truncate(count);

    let decode = |data: &[u8], start, count| -> Result<Vec<(u64, Instruction)>> {
        let decoded = if count == 0 {
            engine.disasm_all(data, start)?
        } else {
            engine.disasm_count(data, start, count)?
        };
        Ok(decoded
            .iter()
            .map(|insn| {
                (
                    insn.address(),
                    Instruction {
                        address: hex(insn.address()),
                        bytes: modules::id_hex(insn.bytes()),
                        mnemonic: insn.mnemonic().map(str::to_owned),
                        operands: insn.op_str().map(str::to_owned),
                    },
                )
            })
            .collect())
    };
    let mut result = Vec::new();
    if width == 4 {
        for (i, bytes) in buffer.chunks_exact(4).enumerate() {
            let pc = anchor + i as u64 * 4;
            let instruction = decode(bytes, pc, 1)?.pop().unwrap_or_else(|| {
                (
                    pc,
                    Instruction {
                        address: hex(pc),
                        bytes: modules::id_hex(bytes),
                        mnemonic: None,
                        operands: None,
                    },
                )
            });
            result.push(instruction);
        }
    } else {
        result = decode(&buffer, anchor, 0)?;
        if anchor != address
            && result
                .last()
                .is_none_or(|(pc, insn)| *pc + (insn.bytes.len() / 2) as u64 <= address)
        {
            // No uninterrupted decoding path reaches the requested address.
            boundary = "uncertain";
            result = decode(
                buffer
                    .get(usize::try_from(address - anchor)?..)
                    .unwrap_or_default(),
                address,
                usize::try_from(after)? + 1,
            )?;
        }
    }
    let position = result
        .partition_point(|(pc, _)| *pc <= address)
        .saturating_sub(1);
    let covers = result
        .get(position)
        .is_some_and(|(pc, insn)| *pc <= address && address - *pc < (insn.bytes.len() / 2) as u64);
    let count = position + if covers { 1 } else { 0 };
    let requested_end = count + after as usize;
    let lower = position.saturating_sub(before as usize);
    let exact = covers && boundary != "uncertain" && result[position].0 == address;
    Ok(Window {
        architecture,
        byte_source,
        warnings: if byte_source == "executable" {
            vec![crate::Diagnostic::new(
                "CORE_BYTES_UNAVAILABLE",
                "Instructions are from the verified executable because the core lacks these bytes",
                None,
            )]
        } else {
            Vec::new()
        },
        address: hex(address),
        boundary,
        anchor: hex(if boundary == "uncertain" {
            address
        } else {
            anchor
        }),
        address_is_instruction_start: exact,
        truncated_before: position < before as usize,
        truncated_after: !covers || result.len() < requested_end,
        instructions: result
            .into_iter()
            .take(requested_end)
            .skip(lower)
            .map(|(_, insn)| insn)
            .collect(),
    })
}

#[derive(Serialize)]
pub(crate) struct InstructionReference {
    pub(crate) instruction: String,
    kind: &'static str,
    mnemonic: Option<String>,
}

pub(crate) struct References {
    pub(crate) matches: Vec<InstructionReference>,
    pub(crate) decoded_end: u64,
    pub(crate) next_address: Option<u64>,
    pub(crate) skipped_words: usize,
}

pub(crate) fn references(
    architecture: &str,
    start: u64,
    code: &[u8],
    target: u64,
    resume_from: u64,
    limit: usize,
) -> Result<References> {
    let (mut engine, _) = decoder(architecture)?;
    engine.set_detail(true)?;
    let arm64 = architecture == "aarch64";
    if arm64 {
        engine.set_skipdata(true)?;
    }
    let instructions = engine.disasm_all(code, start)?;
    let mut arm = ArmReferences::default();
    let mut report = References {
        matches: Vec::new(),
        decoded_end: start,
        next_address: None,
        skipped_words: 0,
    };
    let targets: std::collections::BTreeSet<_> =
        if arm64 {
            use capstone::arch::{DetailsArchInsn, arm64::Arm64OperandType};
            instructions
                .iter()
                .filter(|insn| insn.id().0 != 0)
                .filter_map(|insn| {
                    let detail = engine.insn_detail(insn).ok()?;
                    if !control_flow(&detail) {
                        return None;
                    }
                    detail.arch_detail().arm64()?.operands().last().and_then(
                        |operand| match operand.op_type {
                            Arm64OperandType::Imm(value) => Some(value as u64),
                            _ => None,
                        },
                    )
                })
                .collect()
        } else {
            Default::default()
        };

    for instruction in instructions.iter() {
        let pc = instruction.address();
        let end = pc + instruction.bytes().len() as u64;
        if instruction.id().0 == 0 {
            arm.addresses.clear();
            report.skipped_words += (end - pc) as usize / 4;
            report.decoded_end = end;
            continue;
        }
        if targets.contains(&pc) {
            arm.addresses.clear();
        }
        let detail = engine.insn_detail(instruction)?;
        let kind = if arm64 {
            arm.reference(&engine, instruction, &detail, target)
        } else {
            x86_reference(&detail, end, target)
        };
        if pc >= resume_from
            && let Some(kind) = kind
        {
            if report.matches.len() == limit {
                report.next_address = Some(pc);
                break;
            }
            report.matches.push(InstructionReference {
                instruction: hex(pc),
                kind,
                mnemonic: instruction.mnemonic().map(str::to_owned),
            });
        }
        report.decoded_end = end;
    }
    Ok(report)
}

fn control_flow(detail: &InsnDetail<'_>) -> bool {
    use capstone::InsnGroupType::{CS_GRP_CALL, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET};

    detail.groups().iter().any(|group| {
        [CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_IRET].contains(&(group.0 as u32))
    })
}

fn x86_reference(detail: &InsnDetail<'_>, end: u64, target: u64) -> Option<&'static str> {
    use capstone::arch::{
        DetailsArchInsn,
        x86::{X86OperandType, X86Reg},
    };

    detail
        .arch_detail()
        .x86()?
        .operands()
        .find_map(|operand| match operand.op_type {
            X86OperandType::Imm(value) if control_flow(detail) && value as u64 == target => {
                Some("branch_target")
            }
            X86OperandType::Mem(memory)
                if memory.base().0 == X86Reg::X86_REG_RIP as u16
                    && end.checked_add_signed(memory.disp()) == Some(target) =>
            {
                Some("pc_relative")
            }
            _ => None,
        })
}

#[derive(Default)]
struct ArmReferences {
    addresses: std::collections::BTreeMap<RegId, u64>,
}

impl ArmReferences {
    fn reference(
        &mut self,
        engine: &Capstone,
        insn: &capstone::Insn<'_>,
        detail: &InsnDetail<'_>,
        target: u64,
    ) -> Option<&'static str> {
        use capstone::arch::{
            DetailsArchInsn,
            arm64::{Arm64OperandType::*, Arm64Shift},
        };

        let mnemonic = insn.mnemonic()?;
        let arch = detail.arch_detail();
        let operands = arch.arm64()?.operands().collect::<Vec<_>>();
        if control_flow(detail) || matches!(mnemonic, "brk" | "svc" | "hvc" | "smc") {
            self.addresses.clear();
            return operands.last().and_then(|operand| match operand.op_type {
                Imm(address) if control_flow(detail) && address as u64 == target => {
                    Some("branch_target")
                }
                _ => None,
            });
        }

        let mut found = operands.iter().find_map(|operand| match operand.op_type {
            Mem(memory)
                if memory.index() == RegId::INVALID_REG
                    && self
                        .addresses
                        .get(&memory.base())
                        .and_then(|base| base.checked_add_signed(i64::from(memory.disp())))
                        == Some(target) =>
            {
                match mnemonic {
                    name if name.starts_with("ld") => Some("read"),
                    name if name.starts_with("st") => Some("write"),
                    _ => None,
                }
            }
            _ => None,
        });
        let derived = match operands.as_slice() {
            [dst, immediate] if matches!(mnemonic, "adr" | "adrp") => {
                match (&dst.op_type, &immediate.op_type) {
                    (Reg(dst), Imm(address)) => Some((*dst, *address as u64)),
                    _ => None,
                }
            }
            [dst, base, displacement] if mnemonic == "add" => {
                match (&dst.op_type, &base.op_type, &displacement.op_type) {
                    (Reg(dst), Reg(base), Imm(displacement_value))
                        if engine.reg_name(*dst)?.starts_with('x') =>
                    {
                        let value = match displacement.shift {
                            Arm64Shift::Invalid | Arm64Shift::Lsl(0) => Some(*displacement_value),
                            Arm64Shift::Lsl(12) => displacement_value.checked_mul(4096),
                            _ => None,
                        };
                        self.addresses
                            .get(base)
                            .and_then(|base| base.checked_add_signed(value?))
                            .map(|value| (*dst, value))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        for register in detail.regs_write() {
            self.addresses.remove(register);
            if let Some(name) = engine.reg_name(*register) {
                let alias = name.strip_prefix('w').map(|number| format!("x{number}"));
                self.addresses.retain(|tracked, _| {
                    let tracked = engine.reg_name(*tracked);
                    tracked != alias || alias.is_none()
                });
            }
        }
        if let Some((register, address)) = derived {
            self.addresses.insert(register, address);
            if address == target {
                found = match mnemonic {
                    "adr" => Some("pc_relative"),
                    "add" => Some("address"),
                    _ => found,
                };
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aarch64_data_references_across_decode_gaps_and_pages() -> Result<()> {
        let words = [
            0x90000009u32, // adrp x9, 0x1000
            0x91022129,    // add x9, x9, #0x88
            0xb9000120,    // str w0, [x9]
            0xb9400120,    // ldr w0, [x9]
            0xffffffff,    // undecodable
            0xb9000120,    // str w0, [x9]; its base is no longer known
            0x9000000a,    // adrp x10, 0x1000
            0xf9404540,    // ldr x0, [x10, #0x88]
            0x2a1f03ea,    // mov w10, wzr
            0xb9008940,    // str w0, [x10, #0x88]; w10 clobbered x10
            0xd65f03c0,    // ret
        ];
        let code: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let first = references("aarch64", 0x1000, &code, 0x1088, 0x1000, 1)?;
        assert_eq!(first.matches[0].kind, "address");
        let resume = first.next_address.expect("second result");
        assert_eq!(resume, 0x1008);
        let rest = references("aarch64", 0x1000, &code, 0x1088, resume, 16)?;
        assert_eq!(rest.skipped_words, 1);
        let matches: Vec<_> = rest
            .matches
            .iter()
            .map(|item| (item.instruction.as_str(), item.kind))
            .collect();
        assert_eq!(
            matches,
            [("0x1008", "write"), ("0x100c", "read"), ("0x101c", "read")]
        );
        Ok(())
    }

    #[test]
    fn decodes_aarch64_little_endian_words() -> Result<()> {
        let (engine, width) = decoder("aarch64")?;
        let bytes = [0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6];
        let instructions = engine.disasm_all(&bytes, 0x1000)?;
        assert_eq!(width, 4);
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].mnemonic(), Some("nop"));
        assert_eq!(instructions[1].mnemonic(), Some("ret"));
        assert_eq!(instructions[1].address(), 0x1004);
        Ok(())
    }
}
