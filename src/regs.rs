use crate::{Result, error, hex};
use gimli::Register;
use nix::errno::Errno;
use nix::libc;
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub struct Registers([Option<u64>; 33], Option<u64>);

pub(crate) const NT_ARM_PAC_MASK: u32 = 0x406;

impl Registers {
    pub fn empty() -> Self {
        Self([None; 33], None)
    }

    pub(crate) fn instruction_pac_mask(&self) -> u64 {
        self.1.unwrap_or_default()
    }

    pub(crate) fn set_instruction_pac_mask(&mut self, mask: u64) {
        self.1 = Some(mask);
    }

    pub fn get(&self, r: Register) -> Result<u64> {
        self.0
            .get(usize::from(r.0))
            .copied()
            .flatten()
            .ok_or_else(|| error(format!("DWARF register {} unavailable", r.0)))
    }

    pub fn set(&mut self, r: Register, value: Option<u64>) {
        if let Some(slot) = self.0.get_mut(usize::from(r.0)) {
            *slot = value;
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub const ARCH: &str = "x86_64";
#[cfg(target_arch = "x86_64")]
pub const PC: Register = gimli::X86_64::RA;
#[cfg(target_arch = "x86_64")]
pub const SP: Register = gimli::X86_64::RSP;
#[cfg(target_arch = "x86_64")]
pub const FP: Register = gimli::X86_64::RBP;

#[cfg(target_arch = "aarch64")]
pub const ARCH: &str = "aarch64";
#[cfg(target_arch = "aarch64")]
pub const PC: Register = gimli::AArch64::PC;
#[cfg(target_arch = "aarch64")]
pub const SP: Register = gimli::AArch64::SP;
#[cfg(target_arch = "aarch64")]
pub const FP: Register = gimli::AArch64::X29;

fn regset<const N: usize>(tid: i32, note: usize) -> Result<[u64; N]> {
    let mut words = [0; N];
    let size = size_of_val(&words);
    let mut iov = libc::iovec {
        iov_base: words.as_mut_ptr().cast(),
        iov_len: size,
    };
    // The kernel writes only to the writable initialized iovec and buffer.
    // Checking the returned length also handles a tracee with a different ABI.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET as _,
            tid,
            note,
            &mut iov as *mut libc::iovec,
        )
    };
    Errno::result(ret)?;
    if iov.iov_len != size {
        return Err(error(format!(
            "register set {note:#x} size {}, expected {size}",
            iov.iov_len
        )));
    }
    Ok(words)
}

pub struct Snapshot {
    pub general: BTreeMap<String, String>,
    pub stack: Registers,
}

#[cfg(target_arch = "x86_64")]
pub fn read(tid: i32) -> Result<Snapshot> {
    let raw = regset::<27>(tid, 1)?;
    let names = [
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx",
        "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds",
        "es", "fs", "gs",
    ];
    let dwarf_order = [10, 12, 11, 5, 13, 14, 4, 19, 9, 8, 7, 6, 3, 2, 1, 0, 16];
    let mut stack = Registers::empty();
    for (slot, idx) in stack.0.iter_mut().zip(dwarf_order) {
        *slot = Some(raw[idx]);
    }
    Ok(Snapshot {
        general: names
            .into_iter()
            .zip(raw)
            .map(|(name, value)| (name.to_owned(), hex(value)))
            .collect(),
        stack,
    })
}

#[cfg(target_arch = "aarch64")]
pub fn read(tid: i32) -> Result<Snapshot> {
    let raw = regset::<34>(tid, 1)?;
    let mut names: Vec<_> = (0..31).map(|n| format!("x{n}")).collect();
    names.extend(["sp".into(), "pc".into(), "pstate".into()]);
    let mut stack = Registers::empty();
    // NT_ARM_PAC_MASK is unavailable on hardware without address authentication.
    if let Ok([_, instruction]) = regset::<2>(tid, NT_ARM_PAC_MASK as usize) {
        stack.set_instruction_pac_mask(instruction);
    }
    for (slot, value) in stack.0.iter_mut().zip(raw) {
        *slot = Some(value);
    }
    Ok(Snapshot {
        general: names
            .into_iter()
            .zip(raw)
            .map(|(name, value)| (name, hex(value)))
            .collect(),
        stack,
    })
}

#[cfg(target_arch = "x86_64")]
const API_REGISTERS: &[(&str, usize)] = &[
    ("rax", 10),
    ("rbx", 5),
    ("rcx", 11),
    ("rdx", 12),
    ("rsi", 13),
    ("rdi", 14),
    ("rbp", 4),
    ("rsp", 19),
    ("r8", 9),
    ("r9", 8),
    ("r10", 7),
    ("r11", 6),
    ("r12", 3),
    ("r13", 2),
    ("r14", 1),
    ("r15", 0),
    ("rip", 16),
    ("rflags", 18),
    ("fs_base", 21),
    ("gs_base", 22),
];

#[cfg(target_arch = "aarch64")]
const API_REGISTERS: &[(&str, usize)] = &[
    ("x0", 0),
    ("x1", 1),
    ("x2", 2),
    ("x3", 3),
    ("x4", 4),
    ("x5", 5),
    ("x6", 6),
    ("x7", 7),
    ("x8", 8),
    ("x9", 9),
    ("x10", 10),
    ("x11", 11),
    ("x12", 12),
    ("x13", 13),
    ("x14", 14),
    ("x15", 15),
    ("x16", 16),
    ("x17", 17),
    ("x18", 18),
    ("x19", 19),
    ("x20", 20),
    ("x21", 21),
    ("x22", 22),
    ("x23", 23),
    ("x24", 24),
    ("x25", 25),
    ("x26", 26),
    ("x27", 27),
    ("x28", 28),
    ("x29", 29),
    ("x30", 30),
    ("sp", 31),
    ("pc", 32),
    ("cpsr", 33),
];

pub(crate) fn general_from_bytes(raw: &[u8]) -> Result<BTreeMap<String, String>> {
    API_REGISTERS
        .iter()
        .map(|&(name, index)| {
            let word = raw
                .get(index * 8..index * 8 + 8)
                .ok_or_else(|| error("truncated register data"))?;
            Ok((name.to_owned(), hex(u64::from_le_bytes(word.try_into()?))))
        })
        .collect()
}

pub(crate) fn api_general(mut general: BTreeMap<String, String>) -> Result<serde_json::Value> {
    #[cfg(target_arch = "x86_64")]
    general.insert("rflags".into(), general["eflags"].clone());
    #[cfg(target_arch = "aarch64")]
    general.insert("cpsr".into(), general["pstate"].clone());
    general.retain(|name, _| API_REGISTERS.iter().any(|(key, _)| key == name));
    Ok(serde_json::to_value(general)?)
}

pub(crate) fn api_read(tid: i32, full: bool) -> Result<serde_json::Value> {
    let mut value = api_general(read(tid)?.general)?;
    if full {
        add_vectors(&mut value, &fp_bytes(tid)?)?;
    }
    Ok(value)
}

fn fp_bytes(tid: i32) -> Result<Vec<u8>> {
    #[cfg(target_arch = "x86_64")]
    let raw = regset::<64>(tid, 2)?.to_vec();
    #[cfg(target_arch = "aarch64")]
    let raw = regset::<66>(tid, 2)?.to_vec();
    Ok(raw.into_iter().flat_map(u64::to_le_bytes).collect())
}

pub(crate) fn add_vectors(value: &mut serde_json::Value, raw: &[u8]) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    let (prefix, count, offset) = ("xmm", 16, 160);
    #[cfg(target_arch = "aarch64")]
    let (prefix, count, offset) = ("v", 32, 0);
    for i in 0..count {
        let start = offset + 16 * i;
        let bytes = raw
            .get(start..start + 16)
            .ok_or_else(|| error("truncated vector registers"))?;
        value[format!("{prefix}{i}")] = serde_json::json!(bytes);
    }
    #[cfg(target_arch = "aarch64")]
    for (name, start) in [("fpsr", 512), ("fpcr", 516)] {
        let word = raw
            .get(start..start + 4)
            .ok_or_else(|| error("truncated floating-point status"))?;
        value[name] = serde_json::json!(u32::from_le_bytes(word.try_into()?));
    }
    Ok(())
}

fn set_regset<T>(tid: i32, note: usize, raw: &mut [T]) -> Result<()> {
    let mut iov = libc::iovec {
        iov_base: raw.as_mut_ptr().cast(),
        iov_len: size_of_val(raw),
    };
    Errno::result(unsafe { libc::ptrace(libc::PTRACE_SETREGSET as _, tid, note, &mut iov) })?;
    Ok(())
}

pub(crate) fn api_write(tid: i32, values: &serde_json::Value) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    let mut raw = regset::<27>(tid, 1)?;
    #[cfg(target_arch = "aarch64")]
    let mut raw = regset::<34>(tid, 1)?;
    let values = values
        .as_object()
        .ok_or_else(|| error("expected register object"))?;
    let mut fp = None;
    let mut general = false;
    for (name, value) in values {
        if let Some(&(_, index)) = API_REGISTERS.iter().find(|(key, _)| key == name) {
            let address = value
                .as_str()
                .ok_or_else(|| error("expected a bigint register"))?;
            raw[index] = u64::from_str_radix(address.trim_start_matches("0x"), 16)?;
            general = true;
            continue;
        }
        if fp.is_none() {
            fp = Some(fp_bytes(tid)?);
        }
        let fp = fp.as_mut().unwrap();
        #[cfg(target_arch = "x86_64")]
        let (prefix, count, offset) = ("xmm", 16, 160);
        #[cfg(target_arch = "aarch64")]
        let (prefix, count, offset) = ("v", 32, 0);
        #[cfg(target_arch = "aarch64")]
        if let Some(start) = [("fpsr", 512), ("fpcr", 516)]
            .into_iter()
            .find_map(|(key, index)| (key == name).then_some(index))
        {
            let value = u32::try_from(
                value
                    .as_u64()
                    .ok_or_else(|| error("expected 32-bit register"))?,
            )?;
            fp[start..start + 4].copy_from_slice(&value.to_le_bytes());
            continue;
        }
        let slot = name
            .strip_prefix(prefix)
            .and_then(|suffix| suffix.parse::<usize>().ok())
            .filter(|index| *index < count)
            .ok_or_else(|| error(format!("unknown register {name}")))?;
        let bytes: [u8; 16] = serde_json::from_value(value.clone())?;
        let start = offset + slot * 16;
        fp[start..start + 16].copy_from_slice(&bytes);
    }
    if let Some(mut fp) = fp {
        set_regset(tid, 2, &mut fp)?;
    }
    if general {
        set_regset(tid, 1, &mut raw)?;
    }
    Ok(())
}
