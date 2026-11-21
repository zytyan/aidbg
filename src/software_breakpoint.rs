use crate::{Result, error};
use nix::{libc, sys::ptrace, unistd::Pid};

#[cfg(target_arch = "x86_64")]
pub(crate) const TRAP: u32 = 0xcc;
#[cfg(target_arch = "aarch64")]
pub(crate) const TRAP: u32 = 0xd420_0000;
#[cfg(target_arch = "x86_64")]
const WIDTH: usize = 1;
#[cfg(target_arch = "aarch64")]
const WIDTH: usize = 4;

fn word_location(address: u64) -> Result<(ptrace::AddressType, usize)> {
    if !address.is_multiple_of(WIDTH as u64) {
        return Err(error(
            "software breakpoint address is not instruction aligned",
        ));
    }
    Ok((
        (address & !7) as ptrace::AddressType,
        (address & 7) as usize,
    ))
}

// Preserve adjacent instructions in the same ptrace word. ARM Linux performs
// instruction-cache maintenance for ptrace writes to executable mappings.
pub(crate) fn read_instruction(tid: i32, address: u64) -> Result<u32> {
    let (aligned, offset) = word_location(address)?;
    let word = ptrace::read(Pid::from_raw(tid), aligned)?.to_ne_bytes();
    let mut bytes = [0; 4];
    bytes[..WIDTH].copy_from_slice(&word[offset..offset + WIDTH]);
    Ok(u32::from_ne_bytes(bytes))
}

pub(crate) fn write_instruction(tid: i32, address: u64, instruction: u32) -> Result<()> {
    let pid = Pid::from_raw(tid);
    let (aligned, offset) = word_location(address)?;
    let mut bytes = ptrace::read(pid, aligned)?.to_ne_bytes();
    bytes[offset..offset + WIDTH].copy_from_slice(&instruction.to_ne_bytes()[..WIDTH]);
    ptrace::write(pid, aligned, libc::c_long::from_ne_bytes(bytes))?;
    Ok(())
}

pub(crate) fn pc(tid: i32) -> Result<u64> {
    let regs = ptrace::getregs(Pid::from_raw(tid))?;
    #[cfg(target_arch = "x86_64")]
    return Ok(regs.rip);
    #[cfg(target_arch = "aarch64")]
    return Ok(regs.pc);
}

pub(crate) fn trap_address(tid: i32) -> Option<u64> {
    let pc = pc(tid).ok()?;
    pc.checked_sub(u64::from(cfg!(target_arch = "x86_64")))
}

pub(crate) fn set_pc(tid: i32, address: u64) -> Result<()> {
    let pid = Pid::from_raw(tid);
    let mut regs = ptrace::getregs(pid)?;
    #[cfg(target_arch = "x86_64")]
    {
        regs.rip = address;
    }
    #[cfg(target_arch = "aarch64")]
    {
        regs.pc = address;
    }
    ptrace::setregs(pid, regs)?;
    Ok(())
}
