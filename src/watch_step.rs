use crate::procfs::{Status, start_ticks};
use crate::regs::{self, PC};
use crate::trace::{Cleanup, Stop, Trace};
use crate::{Result, disassembly, error, hex, machine, modules, rpc::StepWatchRequest};
use serde::Serialize;
use std::{
    fs::File,
    os::fd::AsRawFd,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Serialize)]
struct Change {
    step: u32,
    instruction_pc: String,
    next_pc: String,
    before: String,
    after: String,
}

#[derive(Serialize)]
pub struct Report {
    pid: i32,
    tid: i32,
    mode: &'static str,
    status: &'static str,
    address: String,
    length: u32,
    pc_start: String,
    pc_end: String,
    steps: u32,
    stop: Option<crate::trace::StopInfo>,
    issue: Option<String>,
    changes: Vec<Change>,
    cleanup: Cleanup,
}

pub fn run(req: StepWatchRequest) -> Result<Report> {
    let tid = req.tid.unwrap_or(req.pid);
    let steps = req.max_steps.unwrap_or(128);
    let budget = req.timeout_ms.unwrap_or(250);
    let addr_end = req
        .address
        .checked_add(u64::from(req.length))
        .ok_or_else(|| error("watched address range overflows"))?;
    if !(1..=64).contains(&req.length)
        || !(1..=512).contains(&steps)
        || !(1..=500).contains(&budget)
        || tid <= 0
        || req.pc_end <= req.pc_start
        || req.pc_end - req.pc_start > 65_536
    {
        return Err(error(
            "expected a positive TID, 1–64 watched bytes, a PC window of at most 65536 bytes, 1–512 steps and 1–500 ms",
        ));
    }
    let dir = File::open(format!("/proc/{}", req.pid))?;
    let root = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    if Status::read(&root)?.field("Tgid") != Some(&req.pid.to_string()) {
        return Err(error("pass the process ID (thread-group leader)"));
    }
    let start = start_ticks(&root)?;
    let deadline = Instant::now() + Duration::from_millis(budget.into());
    let (decoder, width) = disassembly::decoder(regs::ARCH)?;
    let mut trace = Trace::new(req.pid, &root, start);
    let mut report = Report {
        pid: req.pid,
        tid,
        mode: "software_value_change",
        status: "failed",
        address: hex(req.address),
        length: req.length,
        pc_start: hex(req.pc_start),
        pc_end: hex(req.pc_end),
        steps: 0,
        stop: None,
        issue: None,
        changes: Vec::new(),
        cleanup: Cleanup::default(),
    };
    let result = (|| -> Result<&'static str> {
        trace.freeze(deadline)?;
        if machine(&root)? != regs::ARCH {
            return Err(error("target ABI does not match watch server"));
        }
        let code = modules::mapping_at(&root, req.pc_start)?
            .filter(|m| m.executable() && m.contains(req.pc_end - 1))
            .ok_or_else(|| error("PC window must fit in one executable mapping"))?;
        if !matches!(
            trace.threads.get(&tid).and_then(|thread| thread.stop),
            Some(Stop::Interrupt)
        ) {
            return Err(error("selected thread is not at a debugger interrupt stop"));
        }
        if !modules::mapping_at(&root, req.address)?
            .is_some_and(|m| m.contains(addr_end - 1) && m.perms.starts_with('r'))
        {
            return Err(error("watch window must fit in one readable mapping"));
        }
        let mut before = vec![0; req.length as usize];
        let mut after = before.clone();
        trace.read_memory(req.address, &mut before)?;
        let mut pc = regs::read(tid)?.stack.get(PC)?;
        let window = req.pc_start..req.pc_end;
        if !window.contains(&pc) {
            return Ok("outside_window");
        }
        while report.steps < steps {
            if Instant::now() >= deadline {
                return Ok("timed_out");
            }
            let len = usize::try_from((req.pc_end.min(code.end) - pc).min(width))?;
            let mut bytes = [0; 15];
            trace.read_memory(pc, &mut bytes[..len])?;
            let decoded = decoder.disasm_count(&bytes[..len], pc, 1)?;
            let Some(instruction) = decoded.iter().next() else {
                return Ok("instruction_boundary");
            };
            if instruction.mnemonic().is_none_or(step_barrier) {
                return Ok("instruction_boundary");
            }
            let stop = trace.step_one(tid, deadline)?;
            if !matches!(stop, Some(Stop::Step)) {
                report.stop = stop.map(Stop::info);
                return Ok(if stop.is_some() {
                    "interrupted"
                } else {
                    "thread_exited"
                });
            }
            report.steps += 1;
            let next = regs::read(tid)?.stack.get(PC)?;
            trace.read_memory(req.address, &mut after)?;
            if before != after {
                report.changes.push(Change {
                    step: report.steps,
                    instruction_pc: hex(pc),
                    next_pc: hex(next),
                    before: modules::id_hex(&before),
                    after: modules::id_hex(&after),
                });
                std::mem::swap(&mut before, &mut after);
            }
            if !window.contains(&next) {
                return Ok("left_window");
            }
            pc = next;
        }
        Ok("step_limit")
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
    report.cleanup = trace.close();
    if !report.cleanup.ok() {
        report.status = "cleanup_failed";
    }
    Ok(report)
}

pub(crate) fn step_barrier(name: &str) -> bool {
    matches!(
        name,
        "syscall" | "sysenter" | "int" | "int1" | "int3" | "svc" | "hvc" | "smc" | "brk"
    )
}
