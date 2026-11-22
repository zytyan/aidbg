use super::*;
use crate::rpc::{StepRunRequest, step_run_request::Mode};
use crate::{Diagnostic, disassembly, watch_step::step_barrier};
use serde_json::{Value, json};

impl Session<'_> {
    pub(super) fn step(&mut self, request: StepRunRequest) -> Result<Value> {
        if !self.launched || !self.paused {
            return Err(Diagnostic::new(
                "RUN_NOT_PAUSED",
                "Single-step requires a paused run",
                Some("Use pause_at_entry or run_pause."),
            )
            .into());
        }
        let mode = Mode::try_from(request.mode)?;
        let tid = request.tid.unwrap_or(self.pid);
        let max_steps = request.max_steps.unwrap_or(1024);
        let timeout = request.timeout_ms.unwrap_or(400);
        if tid <= 0 || !(1..=4096).contains(&max_steps) || !(1..=1000).contains(&timeout) {
            return Err(Diagnostic::new(
                "INVALID_ARGUMENT",
                "Expected a positive TID, 1–4096 steps and 1–1000 ms",
                None,
            )
            .into());
        }
        let mut report = Value::Null;
        self.control(|session| {
            report = session.step_stopped(tid, mode, max_steps, timeout)?;
            Ok(())
        })?;
        Ok(report)
    }

    fn step_stopped(&mut self, tid: i32, mode: Mode, limit: u32, timeout: u32) -> Result<Value> {
        if !self
            .trace
            .threads
            .get(&tid)
            .is_some_and(|thread| thread.stop.is_some())
        {
            return Err(Diagnostic::new(
                "THREAD_UNAVAILABLE",
                "Selected thread is not stopped in this run",
                None,
            )
            .into());
        }
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout));
        let registers = regs::read(tid)?.stack;
        let start = registers.get(regs::PC)?;
        let sp = registers.get(regs::SP)?;
        let (decoder, width) = disassembly::decoder(regs::ARCH)?;
        let decode = |pc| -> Result<_> {
            let mut bytes = [0; 15];
            let size = crate::trace::read_process_prefix(
                self.pid,
                pc,
                &mut bytes[..width as usize],
                || Instant::now() < deadline,
            )?;
            let instructions = decoder.disasm_count(&bytes[..size], pc, 1)?;
            Ok(instructions.iter().next().and_then(|inst| {
                inst.mnemonic()
                    .map(|name| (name.to_owned(), inst.bytes().len() as u64))
            }))
        };
        let return_site = match mode {
            Mode::Step => None,
            Mode::Next => decode(start)?.and_then(|(instruction, width)| {
                (instruction.starts_with("call")
                    || matches!(
                        instruction.as_str(),
                        "bl" | "blr" | "blraa" | "blrab" | "blraaz" | "blrabz"
                    ))
                .then(|| (start + width, sp))
            }),
            Mode::Out => {
                let maps = modules::read(self.root)?;
                let exe = std::fs::metadata(self.root.join("exe")).ok();
                let stack = unwind::Images::new().walk(
                    &self.trace,
                    registers,
                    &maps,
                    self.root,
                    exe.as_ref(),
                    deadline,
                );
                let caller = stack.frames.get(1).ok_or_else(|| {
                    Diagnostic::new("NO_CALLER_FRAME", "Could not unwind the caller", None)
                })?;
                Some(caller.return_site()?)
            }
        };
        let mut steps = 0;
        let mut pc = Some(start);
        let mut stop = None;
        let reason = loop {
            if Instant::now() >= deadline {
                break "timed_out";
            }
            if steps == limit {
                break "step_limit";
            }
            let here = pc.expect("step requires a live PC");
            if decode(here)?.is_none_or(|(name, _)| step_barrier(&name)) {
                break "instruction_boundary";
            }
            let stepped = match self.trace.step_one(tid, deadline) {
                Ok(stepped) => stepped,
                Err(_) if Instant::now() >= deadline => {
                    self.trace.freeze(Instant::now() + CONTROL_BUDGET)?;
                    pc = regs::read(tid)
                        .ok()
                        .and_then(|r| r.stack.get(regs::PC).ok());
                    break "timed_out";
                }
                Err(issue) => return Err(issue),
            };
            stop = stepped.map(Stop::info);
            let Some(stepped) = stepped else {
                pc = None;
                break "thread_exited";
            };
            let registers = regs::read(tid)?.stack;
            let current = registers.get(regs::PC)?;
            pc = Some(current);
            if !matches!(stepped, Stop::Step) {
                break "interrupted";
            }
            steps += 1;
            if return_site.is_none_or(|(address, depth)| {
                current == address && registers.get(regs::SP).is_ok_and(|sp| sp >= depth)
            }) {
                break "completed";
            }
        };
        Ok(
            json!({"pid": self.pid, "tid": tid, "pc_before": hex(start), "pc": pc.map(hex),
            "steps": steps, "stop_reason": reason, "stop": stop}),
        )
    }
}
