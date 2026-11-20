use crate::Result;

pub(crate) const TRAP: u8 = 0xcc;

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::Result;
    use nix::{libc, sys::ptrace, unistd::Pid};

    // PTRACE_POKEDATA replaces a machine word. Align down so a breakpoint
    // at the end of a mapping never requires reading the next page.
    pub fn read_byte(tid: i32, address: u64) -> Result<u8> {
        let word = ptrace::read(Pid::from_raw(tid), (address & !7) as ptrace::AddressType)?;
        Ok(word.to_ne_bytes()[(address & 7) as usize])
    }

    pub fn write_byte(tid: i32, address: u64, byte: u8) -> Result<()> {
        let pid = Pid::from_raw(tid);
        let aligned = (address & !7) as ptrace::AddressType;
        let mut bytes = ptrace::read(pid, aligned)?.to_ne_bytes();
        bytes[(address & 7) as usize] = byte;
        ptrace::write(pid, aligned, libc::c_long::from_ne_bytes(bytes))?;
        Ok(())
    }

    pub fn pc(tid: i32) -> Result<u64> {
        Ok(ptrace::getregs(Pid::from_raw(tid))?.rip)
    }

    pub fn set_pc(tid: i32, address: u64) -> Result<()> {
        let pid = Pid::from_raw(tid);
        let mut regs = ptrace::getregs(pid)?;
        regs.rip = address;
        ptrace::setregs(pid, regs)?;
        Ok(())
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod imp {
    use super::Result;
    use crate::error;

    pub fn read_byte(_: i32, _: u64) -> Result<u8> {
        Err(error("software breakpoints require x86_64"))
    }
    pub fn write_byte(_: i32, _: u64, _: u8) -> Result<()> {
        Err(error("software breakpoints require x86_64"))
    }
    pub fn pc(_: i32) -> Result<u64> {
        Err(error("software breakpoints require x86_64"))
    }
    pub fn set_pc(_: i32, _: u64) -> Result<()> {
        Err(error("software breakpoints require x86_64"))
    }
}

pub(crate) use imp::{pc, read_byte, set_pc, write_byte};
