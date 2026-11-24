use crate::procfs::{Status, start_ticks};
use crate::trace::{Cleanup, Stop, StopInfo, Trace};
use crate::{
    Result, cpp_names, disassembly, error, hex, machine, modules, regs, rpc::TargetCallRequest,
    symbols,
};
use nix::{
    errno::Errno,
    libc,
    sys::{ptrace, signal::Signal},
    unistd::Pid,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs::File,
    os::fd::AsRawFd,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
enum Scalar {
    I32,
    U32,
    I64,
    U64,
    Bool,
    Ptr,
    F32,
    F64,
    Void,
}

impl Scalar {
    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "i32" => Self::I32,
            "u32" => Self::U32,
            "i64" => Self::I64,
            "u64" => Self::U64,
            "bool" => Self::Bool,
            "ptr" => Self::Ptr,
            "f32" => Self::F32,
            "f64" => Self::F64,
            "void" => Self::Void,
            _ => {
                return Err(error(
                    "expected i32, u32, i64, u64, bool, ptr, f32, f64 or void",
                ));
            }
        })
    }

    fn cxx(self) -> &'static str {
        match self {
            Self::I32 => "int",
            Self::U32 => "unsigned int",
            Self::I64 => "long",
            Self::U64 => "unsigned long",
            Self::Bool => "bool",
            Self::Ptr => "void*",
            Self::F32 => "float",
            Self::F64 => "double",
            Self::Void => "void",
        }
    }

    fn floating(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    fn encode(self, text: &str) -> Result<u64> {
        Ok(match self {
            Self::I32 => i64::from(text.parse::<i32>()?) as u64,
            Self::U32 => u64::from(text.parse::<u32>()?),
            Self::I64 => text.parse::<i64>()? as u64,
            Self::U64 | Self::Ptr => match text.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16)?,
                None => text.parse()?,
            },
            Self::Bool => match text {
                "true" | "1" => 1,
                "false" | "0" => 0,
                _ => return Err(error("expected true or false")),
            },
            Self::F32 => u64::from(text.parse::<f32>()?.to_bits()),
            Self::F64 => text.parse::<f64>()?.to_bits(),
            Self::Void => return Err(error("void is not an argument type")),
        })
    }

    fn decode(self, bits: u64) -> Value {
        match self {
            Self::I32 => json!(bits as i32),
            Self::U32 => json!(bits as u32),
            Self::I64 => json!(bits as i64),
            Self::U64 => json!(bits),
            Self::Bool => json!(bits as u8 != 0),
            Self::Ptr => json!(hex(bits)),
            Self::F32 => json!(f32::from_bits(bits as u32)),
            Self::F64 => json!(f64::from_bits(bits)),
            Self::Void => Value::Null,
        }
    }
}

#[derive(Serialize)]
pub struct Report {
    pid: i32,
    tid: i32,
    symbol: String,
    address: String,
    pub status: &'static str,
    steps: u32,
    return_value: Option<Value>,
    return_bits: Option<String>,
    stop: Option<StopInfo>,
    issue: Option<String>,
    registers_and_scratch_restored: bool,
    target_side_effects_possible: bool,
    cleanup: Cleanup,
}

#[cfg(target_arch = "x86_64")]
const VECTOR_NOTE: usize = 0x202; // NT_X86_XSTATE
#[cfg(target_arch = "aarch64")]
const VECTOR_NOTE: usize = 2; // NT_FPREGSET
#[cfg(target_arch = "x86_64")]
const VECTOR_OFFSET: usize = 160; // XMM0 in the legacy XSAVE region
#[cfg(target_arch = "aarch64")]
const VECTOR_OFFSET: usize = 0;

fn regset(request: libc::c_uint, tid: i32, note: usize, data: &mut [u8]) -> Result<usize> {
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    Errno::result(unsafe { libc::ptrace(request as _, tid, note, &mut iov as *mut libc::iovec) })?;
    Ok(iov.iov_len)
}

pub(crate) fn read_vectors(tid: i32) -> Result<Vec<u8>> {
    let mut data = vec![0; 65_536];
    let len = regset(libc::PTRACE_GETREGSET as _, tid, VECTOR_NOTE, &mut data)?;
    #[cfg(target_arch = "x86_64")]
    let valid = (576..=data.len()).contains(&len);
    #[cfg(target_arch = "aarch64")]
    let valid = len == 528;
    if !valid {
        return Err(error("unsupported vector register layout"));
    }
    data.truncate(len);
    Ok(data)
}

pub(crate) fn set_vectors(tid: i32, data: &mut [u8]) -> Result<()> {
    let len = regset(libc::PTRACE_SETREGSET as _, tid, VECTOR_NOTE, data)?;
    if len != data.len() {
        return Err(error("short vector register restore"));
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn set_general(
    saved: libc::user_regs_struct,
    start: u64,
    sp: u64,
    _ret: u64,
    args: &[u64],
) -> libc::user_regs_struct {
    let mut regs = saved;
    regs.rip = start;
    regs.rsp = sp;
    regs.rax = 0;
    for (dst, value) in [
        &mut regs.rdi,
        &mut regs.rsi,
        &mut regs.rdx,
        &mut regs.rcx,
        &mut regs.r8,
        &mut regs.r9,
    ]
    .into_iter()
    .zip(args)
    {
        *dst = *value;
    }
    regs
}

#[cfg(target_arch = "aarch64")]
fn set_general(
    saved: libc::user_regs_struct,
    start: u64,
    sp: u64,
    ret: u64,
    args: &[u64],
) -> libc::user_regs_struct {
    let mut regs = saved;
    regs.pc = start;
    regs.sp = sp;
    regs.regs[30] = ret;
    regs.regs[..args.len()].copy_from_slice(args);
    regs
}

fn assert_call_context(tid: i32, regs: &libc::user_regs_struct) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = tid;
        if regs.orig_rax != u64::MAX || regs.eflags & (1 << 10) != 0 {
            return Err(error(
                "thread is in a syscall or has a non-ABI direction flag",
            ));
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = regs;
        // Fixed FPSIMD restoration is valid only when extended vector state is absent.
        if unsafe { libc::getauxval(libc::AT_HWCAP) } & (1 << 22) != 0
            || unsafe { libc::getauxval(libc::AT_HWCAP2) } & (1 << 23) != 0
        {
            return Err(error(
                "live calls on SVE or SME systems require extended register restoration",
            ));
        }
        let mut syscall = [0u8; 4];
        if regset(libc::PTRACE_GETREGSET as _, tid, 0x404, &mut syscall)? != 4
            || i32::from_ne_bytes(syscall) != -1
        {
            return Err(error("thread is in a syscall"));
        }
    }
    Ok(())
}

fn result_word(regs: &libc::user_regs_struct) -> u64 {
    #[cfg(target_arch = "x86_64")]
    return regs.rax;
    #[cfg(target_arch = "aarch64")]
    return regs.regs[0];
}

fn synchronous_fault(tid: i32, stop: Stop) -> bool {
    matches!(
        stop,
        Stop::Delivery(Signal::SIGSEGV | Signal::SIGBUS | Signal::SIGILL | Signal::SIGFPE)
    ) && ptrace::getsiginfo(Pid::from_raw(tid)).is_ok_and(|info| info.si_code > 0)
}

pub fn run(
    req: TargetCallRequest,
    authorize: impl FnOnce(Option<&str>, &[String], u64) -> Result<()>,
) -> Result<Report> {
    let tid = req.tid.unwrap_or(req.pid);
    let max_steps = req.max_steps.unwrap_or(128);
    let budget = req.timeout_ms.unwrap_or(250);
    if !req.allow_side_effects {
        return Err(error(
            "explicit acknowledgement of target side effects is required",
        ));
    }
    if tid <= 0
        || !(1..=512).contains(&max_steps)
        || !(1..=500).contains(&budget)
        || !(1024..=65_536).contains(&req.scratch_length)
        || req.module.is_empty()
        || req.symbol.is_empty()
        || req.symbol.len() > 1024
    {
        return Err(error(
            "expected native PID/TID, module and symbol, 1024–65536 scratch bytes, 1–512 steps and 1–500 ms",
        ));
    }
    let mut int = Vec::new();
    let mut float = Vec::new();
    let mut types = Vec::new();
    for arg in &req.arguments {
        let (ty, text) = arg
            .split_once(':')
            .ok_or_else(|| error("argument must be TYPE:VALUE"))?;
        let ty = Scalar::parse(ty)?;
        let value = ty.encode(text)?;
        if ty.floating() {
            float.push(value)
        } else {
            int.push(value)
        }
        types.push(ty.cxx());
    }
    if int.len() > if cfg!(target_arch = "x86_64") { 6 } else { 8 } || float.len() > 8 {
        return Err(error(
            "scalar arguments exceed the architecture's register argument capacity",
        ));
    }
    let ret = Scalar::parse(&req.return_type)?;
    let scratch_end = req
        .scratch_address
        .checked_add(u64::from(req.scratch_length))
        .ok_or_else(|| error("scratch range overflows"))?;
    let dir = File::open(format!("/proc/{}", req.pid))?;
    let root = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    if Status::read(&root)?.field("Tgid") != Some(&req.pid.to_string())
        || machine(&root)? != regs::ARCH
    {
        return Err(error("expected a native process leader"));
    }
    let name = req.symbol.trim_start_matches("::");
    let signature = if name.contains('(') {
        name.to_owned()
    } else {
        format!("{name}({})", types.join(", "))
    };
    let signature = signature.replace(' ', "");
    let site = symbols::breakpoint_site_matching(&root, &req.module, req.instance, |raw| {
        raw == name
            || cpp_names::names(raw)
                .demangled_name
                .as_ref()
                .is_some_and(|demangled| demangled.replace(' ', "") == signature)
    })?;
    authorize(site.build_id.as_deref(), &site.symbols, site.address)?;
    let code_end = site
        .address
        .checked_add(site.size)
        .filter(|_| (1..=65_536).contains(&site.size))
        .ok_or_else(|| {
            error("target function must have a known executable size of 1–65536 bytes")
        })?;
    let code = site.address..code_end;
    let top = scratch_end & !15;
    let caller_sp = top - if cfg!(target_arch = "x86_64") { 8 } else { 0 };
    let budget = Duration::from_millis(budget.into());
    let (decoder, width) = disassembly::decoder(regs::ARCH)?;
    let deadline = Instant::now() + budget;
    let mut trace = Trace::new(req.pid, &root, start_ticks(&root)?);
    let mut report = Report {
        pid: req.pid,
        tid,
        symbol: req.symbol,
        address: hex(site.address),
        status: "failed",
        steps: 0,
        return_value: None,
        return_bits: None,
        stop: None,
        issue: None,
        registers_and_scratch_restored: false,
        target_side_effects_possible: false,
        cleanup: Cleanup::default(),
    };
    let mut restore = None;
    let result = (|| -> Result<&'static str> {
        trace.freeze(deadline)?;
        if trace
            .threads
            .get(&tid)
            .and_then(|t| t.stop)
            .is_none_or(|s| !matches!(s, Stop::Interrupt))
        {
            return Err(error("selected thread is not at a debugger interrupt stop"));
        }
        if !site.still_mapped(&root)?
            || !modules::mapping_at(&root, site.address)?
                .is_some_and(|map| map.contains(code.end - 1))
        {
            return Err(error("function mapping changed before the call"));
        }
        if !modules::mapping_at(&root, req.scratch_address)?
            .is_some_and(|map| map.contains(scratch_end - 1) && map.perms == "rw-p")
        {
            return Err(error(
                "scratch must be in one private read-write data mapping",
            ));
        }
        let pid = Pid::from_raw(tid);
        let general = ptrace::getregs(pid)?;
        assert_call_context(tid, &general)?;
        let saved = regs::read(tid)?.stack;
        let return_pc = saved.get(regs::PC)?;
        let active_sp = saved.get(regs::SP)?;
        if code.contains(&return_pc)
            || modules::mapping_at(&root, active_sp)?
                .is_some_and(|stack| stack.start < scratch_end && req.scratch_address < stack.end)
            || (req.scratch_address..scratch_end).contains(&active_sp)
            || active_sp
                .checked_sub(128)
                .is_some_and(|red_zone| req.scratch_address <= active_sp && scratch_end > red_zone)
        {
            return Err(error(
                "scratch overlaps the active stack or return PC is inside the call window",
            ));
        }
        let vectors = read_vectors(tid)?;
        let mut bytes = vec![0; req.scratch_length as usize];
        trace.read_memory(req.scratch_address, &mut bytes)?;
        restore = Some((general, vectors, bytes));
        if cfg!(target_arch = "x86_64") {
            trace.write_memory(caller_sp, &return_pc.to_le_bytes())?;
        }
        if !float.is_empty() {
            let mut vectors = restore.as_ref().expect("saved state").1.clone();
            #[cfg(target_arch = "x86_64")]
            {
                vectors[512] |= 2;
            } // Mark the legacy SSE state present.
            for (slot, value) in vectors[VECTOR_OFFSET..].chunks_exact_mut(16).zip(float) {
                slot.fill(0);
                slot[..8].copy_from_slice(&value.to_le_bytes());
            }
            set_vectors(tid, &mut vectors)?;
        }
        ptrace::setregs(
            pid,
            set_general(general, site.address, caller_sp, return_pc, &int),
        )?;

        loop {
            let regs = regs::read(tid)?.stack;
            let pc = regs.get(regs::PC)?;
            let sp = regs.get(regs::SP)?;
            if pc == return_pc && sp == top {
                let bits = if ret.floating() {
                    let vectors = read_vectors(tid)?;
                    u64::from_le_bytes(vectors[VECTOR_OFFSET..VECTOR_OFFSET + 8].try_into()?)
                } else {
                    result_word(&ptrace::getregs(pid)?)
                };
                report.return_value = Some(ret.decode(bits));
                report.return_bits = (!matches!(ret, Scalar::Void)).then(|| hex(bits));
                return Ok("complete");
            }
            if !code.contains(&pc) {
                return Ok("left_function");
            }
            if !(req.scratch_address + 128..=top).contains(&sp) {
                return Ok("left_scratch_stack");
            }
            if Instant::now() >= deadline {
                return Ok("timed_out");
            }
            if report.steps == max_steps {
                return Ok("step_limit");
            }
            let len = (code.end - pc).min(width) as usize;
            let mut bytes = [0; 15];
            trace.read_memory(pc, &mut bytes[..len])?;
            let instructions = decoder.disasm_count(&bytes[..len], pc, 1)?;
            let Some(instruction) = instructions.iter().next() else {
                return Ok("instruction_boundary");
            };
            if instruction
                .mnemonic()
                .is_none_or(crate::watch_step::step_barrier)
            {
                return Ok("instruction_boundary");
            }
            report.target_side_effects_possible = true;
            match trace.step_one(tid, deadline)? {
                Some(Stop::Step) => report.steps += 1,
                Some(stop) => {
                    report.stop = Some(stop.info());
                    if synchronous_fault(tid, stop) {
                        trace.threads.get_mut(&tid).expect("stopped thread").stop =
                            Some(Stop::Step);
                        return Ok("target_fault");
                    }
                    return Ok("interrupted");
                }
                None => return Ok("thread_exited"),
            }
        }
    })();
    match result {
        Ok(status) => report.status = status,
        Err(e) => {
            report.status = if Instant::now() >= deadline {
                "timed_out"
            } else {
                "failed"
            };
            report.issue = Some(e.to_string());
        }
    }
    if let Some((general, mut vectors, bytes)) = restore {
        let recovery = (|| -> Result<()> {
            if trace
                .threads
                .get(&tid)
                .is_some_and(|thread| thread.stop.is_none())
            {
                trace.freeze(Instant::now() + Duration::from_millis(250))?;
            }
            if !trace
                .threads
                .get(&tid)
                .is_some_and(|thread| thread.stop.is_some())
            {
                return Err(error(
                    "selected thread is no longer stopped for restoration",
                ));
            }
            // Attempt every restoration even if one operation fails.
            let scratch = trace.write_memory(req.scratch_address, &bytes);
            let fp = set_vectors(tid, &mut vectors);
            let gp = ptrace::setregs(Pid::from_raw(tid), general);
            scratch?;
            fp?;
            gp?;
            Ok(())
        })();
        match recovery {
            Ok(()) => report.registers_and_scratch_restored = true,
            Err(e) => {
                report.status = "cleanup_failed";
                report.issue = Some(format!("restore debugger call state: {e}"));
            }
        }
    }
    report.cleanup = trace.close();
    if !report.cleanup.ok() {
        report.status = "cleanup_failed";
    }
    Ok(report)
}
