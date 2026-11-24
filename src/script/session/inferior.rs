use super::target::{DEADLINE, Live, parse_address};
use crate::{Result, breakpoint, error, hex, modules, regs, target_call, trace::Stop};
use nix::{
    libc,
    sys::{ptrace, signal::Signal},
    unistd::Pid,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Instant;

#[cfg(target_arch = "x86_64")]
const SYSCALL: &[u8] = &[0x0f, 0x05];
#[cfg(target_arch = "aarch64")]
const SYSCALL: &[u8] = &[0x01, 0, 0, 0xd4];
const RETURN_OFFSET: u64 = 16;
const STACK_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy)]
pub(super) struct Scratch {
    code: u64,
    size: u64,
}

impl Live {
    fn vdso_syscall(&self) -> Result<u64> {
        let (_, map) = modules::map_entries(&self.root)?
            .into_iter()
            .find(|(backing, _)| backing.path == b"[vdso]")
            .ok_or_else(|| error("NotSupport: target has no vDSO syscall entry"))?;
        let length = usize::try_from(map.end - map.start)?;
        if length > 1024 * 1024 {
            return Err(error("vDSO exceeds size limit"));
        }
        let mut bytes = vec![0; length];
        self.trace.read_memory(map.start, &mut bytes)?;
        let offset = bytes
            .windows(SYSCALL.len())
            .enumerate()
            .position(|(offset, code)| {
                code == SYSCALL && (cfg!(target_arch = "x86_64") || offset.is_multiple_of(4))
            })
            .ok_or_else(|| error("NotSupport: vDSO contains no syscall instruction"))?;
        Ok(map.start + offset as u64)
    }

    fn raw_syscall(
        &mut self,
        tid: i32,
        instruction: u64,
        number: u64,
        args: &[u64],
    ) -> Result<u64> {
        if args.len() > 6 {
            return Err(error("Linux syscalls accept at most six arguments"));
        }
        let original_stop = self
            .trace
            .threads
            .get(&tid)
            .and_then(|thread| thread.stop)
            .ok_or_else(|| error("syscall thread is not stopped"))?;
        if !matches!(
            original_stop,
            Stop::Interrupt
                | Stop::ExecBoundary
                | Stop::Step
                | Stop::Software { .. }
                | Stop::Breakpoint { .. }
        ) {
            return Err(error("syscall thread stopped for signal delivery"));
        }
        let pid = Pid::from_raw(tid);
        let original = ptrace::getregs(pid)?;
        let mut working = original;
        set_syscall(&mut working, instruction, number, args);
        let deadline = Instant::now() + DEADLINE;
        breakpoint::disarm(tid)?;
        let outcome = (|| -> Result<u64> {
            ptrace::setregs(pid, working)?;
            loop {
                let stop = self.trace.step_one(tid, deadline)?;
                let at = regs::read(tid)?.stack.get(regs::PC)?;
                // ARM64 Linux can report the single-step after SVC as
                // SI_USER with sender 0. The PC check below ties it to SVC.
                let synthetic_trap = matches!(stop, Some(Stop::Delivery(Signal::SIGTRAP)))
                    && ptrace::getsiginfo(pid).is_ok_and(|info| {
                        matches!(
                            info.si_code,
                            libc::TRAP_TRACE | libc::TRAP_BRKPT | libc::SI_KERNEL
                        ) || (cfg!(target_arch = "aarch64")
                            && info.si_code == libc::SI_USER
                            && unsafe { info.si_pid() } == 0)
                    });
                if at == instruction + SYSCALL.len() as u64
                    && (matches!(stop, Some(Stop::Step)) || synthetic_trap)
                {
                    self.trace.threads.get_mut(&tid).unwrap().stop = Some(Stop::Step);
                    return Ok(return_word(&ptrace::getregs(pid)?));
                }
                if at == instruction && matches!(stop, Some(Stop::Interrupt | Stop::Step)) {
                    continue;
                }
                return Err(error(
                    "syscall injection interrupted by a signal or target exit",
                ));
            }
        })();
        self.restore_inferior(tid, original, original_stop, None)?;
        outcome
    }

    pub fn prepare_scratch(&mut self, selected: Option<i32>) -> Result<()> {
        if self.scratch.is_some() {
            return Ok(());
        }
        let tid = selected
            .or_else(|| self.tids().first().copied())
            .ok_or_else(|| error("target process no longer exists"))?;
        self.with_frozen(|live| {
            let site = live.vdso_syscall()?;
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            let page = u64::try_from(page)
                .ok()
                .filter(|size| size.is_power_of_two())
                .ok_or_else(|| error("could not determine page size"))?;
            let size = page + STACK_BYTES;
            let code = syscall_ok(live.raw_syscall(
                tid,
                site,
                libc::SYS_mmap as u64,
                &[
                    0,
                    size,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                    u64::MAX,
                    0,
                ],
            )?)?;
            let setup = (|| {
                live.trace.write_memory(code, SYSCALL)?;
                // The call completes when PC reaches this mapped executable address.
                #[cfg(target_arch = "x86_64")]
                let nop = &[0x90];
                #[cfg(target_arch = "aarch64")]
                let nop = &[0x1f, 0x20, 0x03, 0xd5];
                live.trace.write_memory(code + RETURN_OFFSET, nop)?;
                syscall_ok(live.raw_syscall(
                    tid,
                    site,
                    libc::SYS_mprotect as u64,
                    &[code, page, (libc::PROT_READ | libc::PROT_EXEC) as u64],
                )?)?;
                Ok(())
            })();
            if let Err(err) = setup {
                let _ = live.raw_syscall(tid, site, libc::SYS_munmap as u64, &[code, size]);
                return Err(err);
            }
            live.scratch = Some(Scratch { code, size });
            Ok(())
        })
    }

    pub fn release_scratch(&mut self) {
        let Some(scratch) = self.scratch.take() else {
            return;
        };
        let Some(tid) = self.tids().first().copied() else {
            return;
        };
        let _ = self.with_stopped(tid, |live| {
            let site = live.vdso_syscall()?;
            live.raw_syscall(
                tid,
                site,
                libc::SYS_munmap as u64,
                &[scratch.code, scratch.size],
            )?;
            Ok(())
        });
    }

    pub fn syscall(&mut self, tid: i32, number: u64, args: &[u64]) -> Result<u64> {
        if let Some(scratch) = self.scratch {
            self.with_stopped(tid, |live| {
                live.raw_syscall(tid, scratch.code, number, args)
            })
        } else {
            self.with_frozen(|live| {
                let site = live.vdso_syscall()?;
                live.raw_syscall(tid, site, number, args)
            })
        }
    }

    pub fn memory_operation(&mut self, tid: i32, operation: &str, args: &Value) -> Result<Value> {
        let size = args["size"]
            .as_u64()
            .filter(|&size| size != 0)
            .ok_or_else(|| error("expected a positive mapping size"))?;
        let prot = || -> Result<u64> {
            let value = args["prot"].as_str().unwrap_or("rw");
            if !matches!(value, "none" | "r" | "w" | "x" | "rw" | "rx" | "wx" | "rwx") {
                return Err(error("invalid memory protection"));
            }
            Ok((i32::from(value.contains('r')) * libc::PROT_READ
                | i32::from(value.contains('w')) * libc::PROT_WRITE
                | i32::from(value.contains('x')) * libc::PROT_EXEC) as u64)
        };
        match operation {
            "allocate" => {
                let address = syscall_ok(self.syscall(
                    tid,
                    libc::SYS_mmap as u64,
                    &[
                        0,
                        size,
                        prot()?,
                        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                        u64::MAX,
                        0,
                    ],
                )?)?;
                Ok(json!(hex(address)))
            }
            "free" => {
                syscall_ok(self.syscall(
                    tid,
                    libc::SYS_munmap as u64,
                    &[parse_address(&args["address"])?, size],
                )?)?;
                Ok(Value::Null)
            }
            "protect" => {
                syscall_ok(self.syscall(
                    tid,
                    libc::SYS_mprotect as u64,
                    &[parse_address(&args["address"])?, size, prot()?],
                )?)?;
                Ok(Value::Null)
            }
            _ => unreachable!(),
        }
    }

    fn restore_inferior(
        &mut self,
        tid: i32,
        general: libc::user_regs_struct,
        stop: Stop,
        vectors: Option<&mut [u8]>,
    ) -> Result<()> {
        if self
            .trace
            .threads
            .get(&tid)
            .is_some_and(|thread| thread.stop.is_none())
        {
            self.trace.stop_thread(tid, Instant::now() + DEADLINE)?;
        }
        let thread = self
            .trace
            .threads
            .get_mut(&tid)
            .ok_or_else(|| error("target thread exited during injection"))?;
        if let Some(Stop::Delivery(signal)) = thread.stop
            && matches!(
                signal,
                Signal::SIGSEGV | Signal::SIGBUS | Signal::SIGILL | Signal::SIGFPE
            )
            && ptrace::getsiginfo(Pid::from_raw(tid)).is_ok_and(|info| info.si_code > 0)
        {
            // A synchronous fault from the injected call must not be delivered at the restored PC.
            thread.stop = Some(Stop::Interrupt);
        }
        if matches!(
            thread.stop,
            Some(Stop::Step | Stop::Interrupt | Stop::Breakpoint { .. })
        ) {
            thread.stop = Some(stop);
        }
        let general = ptrace::setregs(Pid::from_raw(tid), general);
        let vectors = vectors.map_or(Ok(()), |vectors| target_call::set_vectors(tid, vectors));
        let program = self.program(tid);
        general?;
        vectors?;
        program
    }

    pub fn call(&mut self, tid: i32, args: &Value) -> Result<Value> {
        let address = parse_address(&args["address"])?;
        if !modules::is_executable_address(&self.root, address)? {
            return Err(error("C function address is not executable"));
        }
        let arguments: Vec<Argument> = serde_json::from_value(args["args"].clone())?;
        if arguments.len() > 128 {
            return Err(error("too many C arguments"));
        }
        let returns = args["returns"].as_str().unwrap_or("void");
        let return_width = scalar_width(returns)?;
        let variadic = args["variadic"] == true;
        let fixed = args["fixed"].as_u64().unwrap_or(arguments.len() as u64) as usize;
        let mut int = Vec::new();
        let mut fp = Vec::new();
        let mut stack = Vec::new();
        for (index, argument) in arguments.into_iter().enumerate() {
            let floating = argument.kind.starts_with('f');
            let width = scalar_width(&argument.kind)?;
            if width != argument.bytes.len() || width == 0 {
                return Err(error("invalid C argument storage"));
            }
            let mut bytes = [0; 8];
            if argument.kind.starts_with('i') && argument.bytes[width - 1] & 0x80 != 0 {
                bytes.fill(0xff);
            }
            bytes[..width].copy_from_slice(&argument.bytes);
            let mut word = u64::from_le_bytes(bytes);
            if variadic && index >= fixed && argument.kind == "f32" {
                word = (f32::from_bits(word as u32) as f64).to_bits();
            }
            if floating && fp.len() < 8 {
                fp.push(word);
            } else if !floating && int.len() < if cfg!(target_arch = "x86_64") { 6 } else { 8 } {
                int.push(word);
            } else {
                stack.push(word);
            }
        }

        self.prepare_scratch(Some(tid))?;
        let scratch = self.scratch.unwrap();
        self.with_stopped(tid, |live| {
            let stop = live.trace.threads[&tid]
                .stop
                .ok_or_else(|| error("thread is not stopped"))?;
            if !matches!(
                stop,
                Stop::Interrupt
                    | Stop::ExecBoundary
                    | Stop::Step
                    | Stop::Breakpoint { .. }
                    | Stop::Software { .. }
            ) {
                return Err(error("function call thread stopped for signal delivery"));
            }
            let pid = Pid::from_raw(tid);
            let general = ptrace::getregs(pid)?;
            let mut vectors = target_call::read_vectors(tid)?;
            let caller = scratch.code + RETURN_OFFSET;
            let top = (scratch.code + scratch.size - (stack.len() * 8) as u64) & !15;
            let sp = top - if cfg!(target_arch = "x86_64") { 8 } else { 0 };
            let program = (|| -> Result<_> {
                if cfg!(target_arch = "x86_64") {
                    live.trace.write_memory(sp, &caller.to_le_bytes())?;
                }
                let bytes: Vec<_> = stack.into_iter().flat_map(u64::to_le_bytes).collect();
                if !bytes.is_empty() {
                    live.trace.write_memory(top, &bytes)?;
                }
                if !fp.is_empty() {
                    let mut working = vectors.clone();
                    #[cfg(target_arch = "x86_64")]
                    {
                        working[512] |= 2;
                    }
                    for (slot, word) in working[vector_offset()..].chunks_exact_mut(16).zip(&fp) {
                        slot.fill(0);
                        slot[..8].copy_from_slice(&word.to_le_bytes());
                    }
                    target_call::set_vectors(tid, &mut working)?;
                }
                let mut working = general;
                set_call(
                    &mut working,
                    address,
                    sp,
                    caller,
                    &int,
                    if variadic { fp.len() } else { 0 },
                );
                breakpoint::disarm(tid)?;
                ptrace::setregs(pid, working)?;
                let deadline = Instant::now() + DEADLINE;
                for _ in 0..20_000 {
                    let stop = live.trace.step_one(tid, deadline)?;
                    if !matches!(stop, Some(Stop::Step | Stop::Interrupt)) {
                        return Err(error("C call interrupted by a signal or breakpoint"));
                    }
                    let regs = regs::read(tid)?.stack;
                    if regs.get(regs::PC)? == caller && regs.get(regs::SP)? == top {
                        let bytes = if returns.starts_with('f') {
                            let vectors = target_call::read_vectors(tid)?;
                            vectors[vector_offset()..][..return_width].to_vec()
                        } else {
                            return_word(&ptrace::getregs(pid)?).to_le_bytes()[..return_width]
                                .to_vec()
                        };
                        return Ok(json!(bytes));
                    }
                }
                Err(error("C function exceeded the step budget"))
            })();
            live.restore_inferior(tid, general, stop, Some(&mut vectors))?;
            program
        })
    }
}

#[derive(Deserialize)]
struct Argument {
    kind: String,
    bytes: Vec<u8>,
}

pub(super) fn scalar_width(kind: &str) -> Result<usize> {
    match kind {
        "void" => Ok(0),
        "u8" | "i8" => Ok(1),
        "u16" | "i16" => Ok(2),
        "u32" | "i32" | "f32" => Ok(4),
        "u64" | "i64" | "ptr" | "f64" => Ok(8),
        _ => Err(error(
            "NotSupport: native calls require scalar C arguments and return types",
        )),
    }
}

fn syscall_ok(word: u64) -> Result<u64> {
    let signed = word as i64;
    if (-4095..0).contains(&signed) {
        Err(std::io::Error::from_raw_os_error(-signed as i32).into())
    } else {
        Ok(word)
    }
}

#[cfg(target_arch = "x86_64")]
fn set_syscall(regs: &mut libc::user_regs_struct, pc: u64, number: u64, args: &[u64]) {
    regs.rip = pc;
    regs.rax = number;
    regs.orig_rax = u64::MAX;
    let slots = [
        &mut regs.rdi,
        &mut regs.rsi,
        &mut regs.rdx,
        &mut regs.r10,
        &mut regs.r8,
        &mut regs.r9,
    ];
    for (slot, value) in slots.into_iter().zip(args) {
        *slot = *value;
    }
}
#[cfg(target_arch = "aarch64")]
fn set_syscall(regs: &mut libc::user_regs_struct, pc: u64, number: u64, args: &[u64]) {
    regs.pc = pc;
    regs.regs[8] = number;
    regs.regs[..args.len()].copy_from_slice(args);
}
#[cfg(target_arch = "x86_64")]
fn set_call(
    regs: &mut libc::user_regs_struct,
    pc: u64,
    sp: u64,
    _ret: u64,
    args: &[u64],
    xmm: usize,
) {
    regs.rip = pc;
    regs.rsp = sp;
    regs.rax = xmm as u64;
    regs.orig_rax = u64::MAX;
    let slots = [
        &mut regs.rdi,
        &mut regs.rsi,
        &mut regs.rdx,
        &mut regs.rcx,
        &mut regs.r8,
        &mut regs.r9,
    ];
    for (slot, value) in slots.into_iter().zip(args) {
        *slot = *value;
    }
}
#[cfg(target_arch = "aarch64")]
fn set_call(
    regs: &mut libc::user_regs_struct,
    pc: u64,
    sp: u64,
    ret: u64,
    args: &[u64],
    _fp: usize,
) {
    regs.pc = pc;
    regs.sp = sp;
    regs.regs[30] = ret;
    regs.regs[..args.len()].copy_from_slice(args);
}
fn return_word(regs: &libc::user_regs_struct) -> u64 {
    #[cfg(target_arch = "x86_64")]
    return regs.rax;
    #[cfg(target_arch = "aarch64")]
    return regs.regs[0];
}
fn vector_offset() -> usize {
    if cfg!(target_arch = "x86_64") { 160 } else { 0 }
}
