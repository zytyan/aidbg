use super::{HardwareSlots, Kind, Slots};
use crate::{Result, error};
use nix::{errno::Errno, libc};

const EXEC: usize = 0x402; // NT_ARM_HW_BREAK
const WATCH: usize = 0x403; // NT_ARM_HW_WATCH
const MAX: usize = 16;

struct Bank {
    words: [u64; 1 + 2 * MAX],
    capacity: usize,
}

impl Bank {
    fn read(tid: i32, note: usize) -> Result<Self> {
        let mut bank = Self {
            words: [0; 1 + 2 * MAX],
            capacity: 0,
        };
        let mut iov = bank.iov(MAX);
        Errno::result(unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                tid,
                note,
                &mut iov as *mut libc::iovec,
            )
        })?;
        bank.capacity = (bank.words[0] & 0xff) as usize;
        if bank.capacity > MAX || iov.iov_len < 8 + 16 * bank.capacity {
            return Err(error("invalid AArch64 hardware debug register bank"));
        }
        Ok(bank)
    }

    fn iov(&mut self, count: usize) -> libc::iovec {
        libc::iovec {
            iov_base: self.words.as_mut_ptr().cast(),
            iov_len: 8 + 16 * count,
        }
    }

    fn program(mut self, tid: i32, note: usize, requested: &[(u64, u64)]) -> Result<()> {
        if requested.len() > self.capacity {
            let kind = if note == EXEC {
                "execution breakpoint"
            } else {
                "watchpoint"
            };
            return Err(error(format!(
                "hardware {kind} slots exhausted ({} available)",
                self.capacity
            )));
        }
        let previous = (0..self.capacity)
            .rfind(|n| self.words[2 + 2 * n] & 1 != 0)
            .map_or(0, |n| n + 1);
        let count = previous.max(requested.len());
        if count == 0 {
            return Ok(());
        }
        for n in 0..count {
            let (addr, ctrl) = requested.get(n).copied().unwrap_or((0, 0));
            self.words[1 + 2 * n] = addr;
            self.words[2 + 2 * n] = ctrl;
        }
        let iov = self.iov(count);
        Errno::result(unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGSET,
                tid,
                note,
                &iov as *const libc::iovec,
            )
        })?;
        Ok(())
    }
}

pub(super) fn counts(tid: i32) -> Result<(usize, usize)> {
    Ok((
        Bank::read(tid, EXEC)?.capacity,
        Bank::read(tid, WATCH)?.capacity,
    ))
}

pub(super) fn program(tid: i32, slots: &Slots) -> Result<()> {
    program_raw(
        tid,
        &slots.map(|rule| rule.map(|rule| (rule.address, rule.kind))),
    )
}

pub(super) fn program_raw(tid: i32, slots: &HardwareSlots) -> Result<()> {
    let mut exec = Vec::new();
    let mut watch = Vec::new();
    const EL0_ENABLE: u64 = (2 << 1) | 1;
    for &(address, kind) in slots.iter().flatten() {
        match kind {
            Kind::Hardware => {
                if !address.is_multiple_of(4) {
                    return Err(error(
                        "AArch64 hardware execution address must be four-byte aligned",
                    ));
                }
                exec.push((address, EL0_ENABLE | (0xf << 5)));
            }
            Kind::Watch { length, access } => {
                let byte_mask = ((1u64 << length) - 1) << (address & 7);
                let access = match access {
                    super::WatchAccess::Read => 1,
                    super::WatchAccess::Write => 2,
                    super::WatchAccess::ReadWrite => 3,
                };
                watch.push((address & !7, EL0_ENABLE | (access << 3) | (byte_mask << 5)));
            }
            Kind::Software => unreachable!(),
        }
    }
    let exec_bank = Bank::read(tid, EXEC)?;
    let watch_bank = Bank::read(tid, WATCH)?;
    if exec.len() > exec_bank.capacity {
        return Err(error(format!(
            "hardware execution breakpoint slots exhausted ({} available)",
            exec_bank.capacity
        )));
    }
    if watch.len() > watch_bank.capacity {
        return Err(error(format!(
            "hardware watchpoint slots exhausted ({} available)",
            watch_bank.capacity
        )));
    }
    exec_bank.program(tid, EXEC, &exec)?;
    watch_bank.program(tid, WATCH, &watch)
}

pub(super) fn triggered(_: i32) -> Result<u64> {
    Ok(0)
}
pub(super) fn prepare_resume(_: i32, _: bool) -> Result<()> {
    Ok(())
}
