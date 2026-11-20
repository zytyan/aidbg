use crate::{Result, error, hex};
use gimli::Register;
use nix::errno::Errno;
use nix::libc;
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub struct Registers([Option<u64>; 33]);

impl Registers {
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

fn prstatus<const N: usize>(tid: i32) -> Result<[u64; N]> {
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
            1_usize,
            &mut iov as *mut libc::iovec,
        )
    };
    Errno::result(ret)?;
    if iov.iov_len != size {
        return Err(error(format!(
            "NT_PRSTATUS size {}, expected {size}",
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
    let raw = prstatus::<27>(tid)?;
    let names = [
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx",
        "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds",
        "es", "fs", "gs",
    ];
    let dwarf_order = [10, 12, 11, 5, 13, 14, 4, 19, 9, 8, 7, 6, 3, 2, 1, 0, 16];
    let mut stack = Registers([None; 33]);
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
    let raw = prstatus::<34>(tid)?;
    let mut names: Vec<_> = (0..31).map(|n| format!("x{n}")).collect();
    names.extend(["sp".into(), "pc".into(), "pstate".into()]);
    let mut stack = Registers([None; 33]);
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
