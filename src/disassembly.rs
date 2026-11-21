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
    if before > MAX_WINDOW || after > MAX_WINDOW {
        return Err(error("before and after must be in 0..=128"));
    }
    let procdir = File::open(format!("/proc/{pid}"))?;
    let root = PathBuf::from(format!("/proc/self/fd/{}", procdir.as_raw_fd()));
    let start_ticks = procfs::start_ticks(&root)?;
    let exe = std::fs::metadata(root.join("exe"))?;
    let architecture = machine(&root)?;
    let mapping = modules::mapping_at(&root, address)?
        .filter(|m| m.executable())
        .ok_or_else(|| error("address is outside executable mappings"))?;
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
    } else if let Some(entry) = symbols::code_start(&root, address)
        .filter(|entry| *entry <= address && address - entry <= MAX_LOOKBACK)
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
    let remote = [uio::RemoteIoVec {
        base: usize::try_from(anchor)?,
        len: buffer.len(),
    }];
    let read = uio::process_vm_readv(
        Pid::from_raw(pid),
        &mut [IoSliceMut::new(&mut buffer)],
        &remote,
    )?;
    buffer.truncate(read);
    use std::os::unix::fs::MetadataExt;
    let current = std::fs::metadata(root.join("exe"))?;
    if procfs::start_ticks(&root)? != start_ticks
        || (exe.dev(), exe.ino()) != (current.dev(), current.ino())
    {
        return Err(error("target identity changed during disassembly"));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

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
