use crate::procfs::{Status, epoch_ms, start_ticks};
use crate::trace::{Cleanup, Stop, Trace};
use crate::{Result, Snapshot, error, hex, machine, modules, regs, rpc::FreezeMode};
use crate::{symbols, unwind};
use nix::errno::Errno;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SLOTS: usize = 4;
const CONTROL_BUDGET: Duration = Duration::from_millis(500);
const POLL_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Clone, Copy)]
pub enum Scope {
    Thread,
    Process,
}

impl Scope {
    fn name(self) -> &'static str {
        match self {
            Self::Thread => "thread",
            Self::Process => "process",
        }
    }
}

// The server constructs and verifies this internal program before arming a rule.
const SNAPSHOT: u8 = 1;
const RETURN: u8 = 0;

#[derive(Clone, Copy)]
struct Program {
    scope: Scope,
    budget: Duration,
}

impl Program {
    fn load(code: &[u8], budget_ms: u32) -> Result<Self> {
        let scope = match code {
            [SNAPSHOT, 0, RETURN] => Scope::Thread,
            [SNAPSHOT, 1, RETURN] => Scope::Process,
            _ => return Err(error("invalid breakpoint callback bytecode")),
        };
        if !(1..=500).contains(&budget_ms) {
            return Err(error("breakpoint budget must be in 1..=500 milliseconds"));
        }
        Ok(Self {
            scope,
            budget: Duration::from_millis(budget_ms.into()),
        })
    }

    fn execute(self, session: &Session<'_>, hit: &Hit, deadline: Instant, frozen: bool) -> Capture {
        let scope = self.scope;
        let mut snapshot = Snapshot::new(session.pid, FreezeMode::Required);
        snapshot.started_unix_ms = hit.unix_ms;
        snapshot.freeze_requested = scope.name();
        snapshot.freeze_achieved = if frozen { "all" } else { "some" };
        snapshot.all_threads_stopped_during_capture = frozen;
        snapshot.process.start_time_ticks_since_boot = Some(session.start.to_string());
        snapshot.process.architecture = Some(regs::ARCH);
        let thread = match scope {
            Scope::Thread => Some(hit.tid),
            Scope::Process => None,
        };
        let mut maps = Vec::new();
        let mut images = unwind::Images::new();
        let mut exe = None;
        if matches!(scope, Scope::Process) && !frozen {
            snapshot.issue("attach", None, "could not freeze the entire process");
        } else if Instant::now() < deadline {
            (maps, images, exe) =
                snapshot.collect_stopped(&session.trace, session.root, deadline, thread, true);
            snapshot.status = if snapshot.threads.is_empty() {
                "failed"
            } else if snapshot.issues.is_empty() {
                "complete"
            } else {
                "partial"
            };
        }
        if Instant::now() >= deadline {
            snapshot.issue(
                "capture",
                Some(hit.tid),
                "breakpoint callback deadline reached",
            );
            snapshot.status = "timed_out";
        }
        snapshot.capture_finished_unix_ms = epoch_ms();
        Capture {
            snapshot,
            maps,
            images,
            exe,
        }
    }
}

pub enum Location {
    Address(u64),
    Symbol {
        module: String,
        symbol: String,
        instance: Option<u64>,
    },
}

struct PreparedLocation {
    address: u64,
    site: Option<symbols::BreakpointSite>,
    start: Option<u64>,
}

impl PreparedLocation {
    fn resolve(pid: i32, location: Location) -> Result<Self> {
        match location {
            Location::Address(address) => Ok(Self {
                address,
                site: None,
                start: None,
            }),
            Location::Symbol {
                module,
                symbol,
                instance,
            } => {
                // Resolve on the caller's thread so file I/O cannot delay pending hits.
                let procdir = File::open(format!("/proc/{pid}"))?;
                let root = PathBuf::from(format!("/proc/self/fd/{}", procdir.as_raw_fd()));
                let start = start_ticks(&root)?;
                let site = symbols::breakpoint_site(&root, &module, &symbol, instance)?;
                Ok(Self {
                    address: site.address,
                    site: Some(site),
                    start: Some(start),
                })
            }
        }
    }

    fn valid(&self, root: &Path) -> Result<bool> {
        match &self.site {
            Some(site) => site.still_mapped(root),
            None => modules::is_executable_address(root, self.address),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Hardware,
    Software,
    Watch { length: usize, read_write: bool },
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Hardware => "hardware_execution",
            Self::Software => "software_execution",
            Self::Watch {
                read_write: false, ..
            } => "hardware_write",
            Self::Watch {
                read_write: true, ..
            } => "hardware_read_write",
        }
    }
}

#[derive(Serialize)]
struct WatchObservation {
    length: usize,
    access: &'static str,
    write_observed: Option<bool>,
    value_before: Option<String>,
    value_after: Option<String>,
    value_changed: Option<bool>,
}

pub fn capabilities() -> serde_json::Value {
    let x86 = cfg!(target_arch = "x86_64");
    serde_json::json!({
        "architecture": regs::ARCH,
        "hardware_execution": x86,
        "software_execution": x86,
        "shared_execution_and_watch_slots": if x86 { SLOTS } else { 0 },
        "watch_access": if x86 { vec!["write", "read_write"] } else { Vec::<&str>::new() },
        "watch_lengths": if x86 { vec![1, 2, 4, 8] } else { Vec::<usize>::new() },
        "watch_alignment": if x86 { Some("address must be aligned to length") } else { None },
    })
}

#[derive(Clone, Copy)]
struct Rule {
    id: u64,
    address: u64,
    program: Program,
    kind: Kind,
}

#[derive(Serialize)]
pub struct Installed {
    pub kind: &'static str,
    pub breakpoint_id: u64,
    pub address: String,
}

#[derive(Serialize)]
pub struct Event {
    pub breakpoint_id: u64,
    pub pid: i32,
    pub tid: i32,
    pub address: String,
    pub scope: &'static str,
    pub observed_unix_ms: u64,
    pub pause_ms: u64,
    pub capture_status: &'static str,
    pub resume_status: &'static str,
    pub detail: Option<String>,
    pub kind: &'static str,
    watch: Option<WatchObservation>,
}

pub struct Capture {
    snapshot: Snapshot,
    maps: Vec<modules::Module>,
    images: unwind::Images,
    exe: Option<std::fs::Metadata>,
}

impl Capture {
    pub fn into_snapshot(mut self) -> Snapshot {
        self.snapshot
            .finish_symbols(None, self.maps, self.images, self.exe.as_ref());
        self.snapshot
    }
}

pub type Publish = Arc<dyn Fn(Event, Capture) + Send + Sync>;
type Slots = [Option<Rule>; SLOTS];

enum Command {
    Install {
        id: u64,
        location: PreparedLocation,
        program: Program,
        kind: Kind,
        reply: mpsc::Sender<Result<Installed>>,
    },
    Remove {
        id: u64,
        reply: mpsc::Sender<Result<Option<Cleanup>>>,
    },
}

pub struct Worker {
    pid: i32,
    tx: Option<mpsc::Sender<Command>>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start(pid: i32, publish: Publish) -> Result<Self> {
        if !cfg!(target_arch = "x86_64") {
            return Err(error(
                "hardware execution breakpoints currently require x86_64",
            ));
        }
        let (tx, rx) = mpsc::channel();
        let thread = thread::Builder::new()
            .name(format!("aidbg-trace-{pid}"))
            .spawn(move || {
                if let Err(e) = Session::run(pid, publish, rx) {
                    eprintln!("aidbg: breakpoint session for {pid}: {e}");
                }
            })?;
        Ok(Self {
            pid,
            tx: Some(tx),
            thread: Some(thread),
        })
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| t.is_finished())
    }

    pub fn install(
        &self,
        id: u64,
        location: Location,
        scope: Scope,
        budget_ms: u32,
        kind: Kind,
    ) -> Result<Installed> {
        let operand = match scope {
            Scope::Thread => 0,
            Scope::Process => 1,
        };
        let program = Program::load(&[SNAPSHOT, operand, RETURN], budget_ms)?;
        let location = PreparedLocation::resolve(self.pid, location)?;
        let (reply, result) = mpsc::channel();
        self.send(Command::Install {
            id,
            location,
            program,
            kind,
            reply,
        })?;
        result
            .recv()
            .map_err(|_| error("breakpoint session ended during install"))?
    }

    pub fn remove(&self, id: u64) -> Result<Option<Cleanup>> {
        let (reply, result) = mpsc::channel();
        self.send(Command::Remove { id, reply })?;
        result
            .recv()
            .map_err(|_| error("breakpoint session ended during removal"))?
    }

    fn send(&self, command: Command) -> Result<()> {
        self.tx
            .as_ref()
            .expect("live worker")
            .send(command)
            .map_err(|_| error("breakpoint session has ended"))
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Session<'a> {
    pid: i32,
    root: &'a Path,
    start: u64,
    trace: Trace<'a>,
    slots: Slots,
    software: BTreeMap<u64, Rule>,
    watch_values: BTreeMap<u64, Option<u64>>,
    publish: Publish,
}

struct Hit {
    tid: i32,
    rule: Rule,
    observed: Instant,
    unix_ms: u64,
    watch: Option<WatchObservation>,
}

impl Session<'_> {
    fn run(pid: i32, publish: Publish, commands: mpsc::Receiver<Command>) -> Result<()> {
        // Open and validate from this tracer thread before attaching to any task.
        let procdir = File::open(format!("/proc/{pid}"));
        let target = (|| -> Result<_> {
            let procdir = procdir?;
            let root = PathBuf::from(format!("/proc/self/fd/{}", procdir.as_raw_fd()));
            let start = start_ticks(&root)?;
            if Status::read(&root)?.field("Tgid") != Some(&pid.to_string()) {
                return Err(error("pass the process ID (thread-group leader)"));
            }
            if machine(&root)? != regs::ARCH {
                return Err(error("target architecture differs from the tracer"));
            }
            Ok((procdir, root, start))
        })();
        let (_procdir, root, start) = match target {
            Ok(target) => target,
            Err(e) => {
                if let Ok(Command::Install { reply, .. }) = commands.recv() {
                    let _ = reply.send(Err(e));
                }
                return Ok(());
            }
        };

        let mut trace = Trace::new(pid, &root, start);
        trace.monitor();
        let mut session = Session {
            pid,
            root: &root,
            start,
            trace,
            slots: [None; SLOTS],
            software: BTreeMap::new(),
            watch_values: BTreeMap::new(),
            publish,
        };
        loop {
            session.trace.poll()?;
            session.trace.detach_foreign_children()?;
            if session.trace.exec_observed() || session.trace.foreign_software {
                return Ok(());
            }
            session.handle_stops()?;
            if !session.empty() && session.trace.threads.is_empty() {
                return Ok(());
            }
            match commands.recv_timeout(POLL_INTERVAL) {
                Ok(Command::Install {
                    id,
                    location,
                    program,
                    kind,
                    reply,
                }) => {
                    let result = session.install(id, location, program, kind);
                    let _ = reply.send(result);
                    if session.empty() {
                        return Ok(());
                    }
                }
                Ok(Command::Remove { id, reply }) => {
                    let result = session.remove(id);
                    let _ = reply.send(result);
                    if session.empty() {
                        return Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
    }

    fn empty(&self) -> bool {
        self.slots.iter().all(Option::is_none) && self.software.is_empty()
    }

    fn install(
        &mut self,
        id: u64,
        location: PreparedLocation,
        program: Program,
        kind: Kind,
    ) -> Result<Installed> {
        if location.start.is_some_and(|start| start != self.start) {
            return Err(error("target identity changed during symbol resolution"));
        }
        let address = location.address;
        let rule = Rule {
            id,
            address,
            program,
            kind,
        };
        if self.software.contains_key(&address)
            || self
                .slots
                .iter()
                .flatten()
                .any(|rule| rule.address == address)
        {
            return Err(error("a breakpoint already exists at this address"));
        }
        if let Kind::Watch { length, .. } = kind
            && (!matches!(length, 1 | 2 | 4 | 8) || !address.is_multiple_of(length as u64))
        {
            return Err(error(
                "watchpoint length must be 1, 2, 4, or 8 and the address must be aligned to length",
            ));
        }
        if kind == Kind::Software && self.software.len() == 32 {
            return Err(error(
                "software breakpoint slots exhausted (32 per session)",
            ));
        }
        let slot = if kind == Kind::Software {
            None
        } else {
            Some(
                self.slots
                    .iter()
                    .position(Option::is_none)
                    .ok_or_else(|| error("hardware breakpoint slots exhausted (4 shared slots)"))?,
            )
        };
        self.control(|session| {
            match kind {
                Kind::Hardware if !location.valid(session.root)? => {
                    return Err(error(
                        "breakpoint address no longer matches an executable mapping",
                    ));
                }
                Kind::Software => {
                    if !location.valid(session.root)? {
                        return Err(error("software breakpoint mapping changed"));
                    }
                    session.trace.patch(address)?;
                    session.software.insert(address, rule);
                }
                Kind::Watch { length, .. } => {
                    let end = address
                        .checked_add(length as u64 - 1)
                        .ok_or_else(|| error("invalid watchpoint range"))?;
                    modules::mapping_at(session.root, address)?
                        .filter(|m| m.contains(end))
                        .ok_or_else(|| error("watchpoint range is outside a mapped region"))?;
                    session
                        .watch_values
                        .insert(id, session.trace.read_word(address, length).ok());
                }
                _ => (),
            }
            if let Some(slot) = slot {
                let mut proposed = session.slots;
                proposed[slot] = Some(rule);
                session.replace_hardware(proposed)?;
            }
            Ok(())
        })?;
        Ok(Installed {
            kind: kind.name(),
            breakpoint_id: id,
            address: hex(address),
        })
    }

    fn remove(&mut self, id: u64) -> Result<Option<Cleanup>> {
        let software = self.software.values().find(|rule| rule.id == id).copied();
        let slot = self
            .slots
            .iter()
            .position(|entry| entry.is_some_and(|rule| rule.id == id));
        if software.is_none() && slot.is_none() {
            return Err(error("breakpoint ID not found"));
        }
        if self.software.len() + self.slots.iter().flatten().count() == 1 {
            let cleanup = self.trace.close();
            self.software.clear();
            self.slots = [None; SLOTS];
            self.watch_values.clear();
            return Ok(Some(cleanup));
        }
        self.control(|session| {
            if let Some(rule) = software {
                session.trace.unpatch(rule.address)?;
                session.software.remove(&rule.address);
            }
            if let Some(slot) = slot {
                let mut proposed = session.slots;
                proposed[slot] = None;
                session.replace_hardware(proposed)?;
                session.watch_values.remove(&id);
            }
            Ok(())
        })?;
        Ok(None)
    }

    fn replace_hardware(&mut self, proposed: Slots) -> Result<()> {
        if let Err(e) = self.program_stopped(&proposed) {
            if let Err(rollback) = self.program_stopped(&self.slots) {
                self.trace.close();
                self.software.clear();
                self.slots = [None; SLOTS];
                return Err(error(format!(
                    "{e}; hardware breakpoint rollback failed: {rollback}"
                )));
            }
            return Err(e);
        }
        self.slots = proposed;
        Ok(())
    }

    fn control(&mut self, update: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let deadline = Instant::now() + CONTROL_BUDGET;
        let frozen = self.trace.freeze(deadline);
        if self.trace.exec_observed() || self.trace.foreign_software {
            self.trace.close();
            self.software.clear();
            self.slots = [None; SLOTS];
            return Err(error("target address space changed"));
        }
        self.trace.rewind_software_stops()?;
        let mut hits = self.hits()?;
        self.observe_writes(&mut hits);
        let mut captured = self.capture_hits(hits, frozen.is_ok());
        let stepping = self.step_software_stops(frozen.is_ok(), &mut captured);
        let result = if stepping.is_ok() {
            frozen.and_then(|()| update(self))
        } else {
            Ok(())
        };
        let resume = stepping.and_then(|()| self.resume_stopped());
        self.finish_hits(captured, resume.as_ref().err().map(|error| error.as_ref()));
        if let Err(e) = resume {
            self.trace.close();
            self.software.clear();
            self.slots = [None; SLOTS];
            return Err(e);
        }
        result
    }

    fn program_stopped(&self, slots: &Slots) -> Result<()> {
        for (&tid, thread) in &self.trace.threads {
            if thread.stop.is_some() {
                hardware::program(tid, slots).map_err(|e| {
                    if matches!(
                        e.downcast_ref::<Errno>(),
                        Some(Errno::ENOSPC | Errno::EBUSY)
                    ) {
                        error(format!(
                            "hardware breakpoint slots exhausted on thread {tid}: {e}"
                        ))
                    } else {
                        error(format!("program hardware breakpoints on thread {tid}: {e}"))
                    }
                })?;
            }
        }
        Ok(())
    }

    fn hits(&self) -> Result<Vec<Hit>> {
        let mut hits = Vec::new();
        for (&tid, thread) in &self.trace.threads {
            match thread.stop {
                Some(Stop::Software {
                    address,
                    observed,
                    unix_ms,
                }) => {
                    if let Some(&rule) = self.software.get(&address) {
                        hits.push(Hit {
                            tid,
                            rule,
                            observed,
                            unix_ms,
                            watch: None,
                        });
                    }
                }
                Some(Stop::Breakpoint {
                    slots,
                    observed,
                    unix_ms,
                }) => {
                    let pc = regs::read(tid)?.stack.get(regs::PC)?;
                    for (slot, rule) in self.slots.iter().enumerate() {
                        let Some(rule) = *rule else { continue };
                        if slots & (1 << slot) != 0
                            && (rule.kind != Kind::Hardware || rule.address == pc)
                        {
                            hits.push(Hit {
                                tid,
                                rule,
                                observed,
                                unix_ms,
                                watch: None,
                            });
                        }
                    }
                }
                _ => (),
            }
        }
        Ok(hits)
    }

    fn observe_writes(&mut self, hits: &mut [Hit]) {
        let mut counts = BTreeMap::new();
        for hit in hits.iter() {
            *counts.entry(hit.rule.id).or_insert(0) += 1;
        }
        for hit in hits {
            let Kind::Watch { length, read_write } = hit.rule.kind else {
                continue;
            };
            let after = self.trace.read_word(hit.rule.address, length).ok();
            let before = self.watch_values.insert(hit.rule.id, after).flatten();
            hit.watch = Some(WatchObservation {
                length,
                access: if read_write { "read_write" } else { "write" },
                write_observed: (!read_write).then_some(true),
                value_before: if counts[&hit.rule.id] == 1 {
                    before.map(hex)
                } else {
                    None
                },
                value_after: after.map(hex),
                value_changed: if counts[&hit.rule.id] == 1 {
                    before.zip(after).map(|(a, b)| a != b)
                } else {
                    None
                },
            });
        }
    }

    fn step_software_stops(
        &mut self,
        frozen: bool,
        captured: &mut Vec<(Hit, Capture)>,
    ) -> Result<()> {
        let stops: Vec<_> = self
            .trace
            .threads
            .iter()
            .filter_map(|(&tid, t)| {
                if let Some(Stop::Software { address, .. }) = t.stop {
                    Some((tid, address))
                } else {
                    None
                }
            })
            .collect();
        if !stops.is_empty() && !frozen {
            return Err(error(
                "could not freeze peer threads for software breakpoint recovery",
            ));
        }
        for (tid, address) in stops {
            self.trace
                .step_software(tid, address, Instant::now() + CONTROL_BUDGET)?;
            if self
                .trace
                .threads
                .get(&tid)
                .is_some_and(|t| matches!(t.stop, Some(Stop::Breakpoint { .. })))
            {
                let mut hits: Vec<_> = self
                    .hits()?
                    .into_iter()
                    .filter(|hit| hit.tid == tid)
                    .collect();
                self.observe_writes(&mut hits);
                captured.extend(self.capture_hits(hits, true));
            }
        }
        Ok(())
    }

    fn capture_hits(&mut self, hits: Vec<Hit>, frozen: bool) -> Vec<(Hit, Capture)> {
        // All already-stopped threads share the earliest active deadline.
        let deadline = hits
            .iter()
            .map(|h| h.observed + h.rule.program.budget)
            .min();
        hits.into_iter()
            .map(|hit| {
                let deadline = deadline.expect("at least one hit");
                let capture = hit.rule.program.execute(self, &hit, deadline, frozen);
                (hit, capture)
            })
            .collect()
    }

    fn finish_hits(
        &self,
        captured: Vec<(Hit, Capture)>,
        resume: Option<&(dyn std::error::Error + Send + Sync)>,
    ) {
        for (hit, mut capture) in captured {
            let pause_ms = hit.observed.elapsed().as_millis() as u64;
            capture.snapshot.trace_window_ms = Some(pause_ms);
            (self.publish)(
                Event {
                    breakpoint_id: hit.rule.id,
                    pid: self.pid,
                    tid: hit.tid,
                    address: hex(hit.rule.address),
                    scope: hit.rule.program.scope.name(),
                    observed_unix_ms: hit.unix_ms,
                    pause_ms,
                    capture_status: capture.snapshot.status,
                    resume_status: if resume.is_none() {
                        "resumed"
                    } else {
                        "failed"
                    },
                    detail: resume.map(ToString::to_string),
                    kind: hit.rule.kind.name(),
                    watch: hit.watch,
                },
                capture,
            );
        }
    }

    fn handle_stops(&mut self) -> Result<()> {
        if self.stopped().is_empty() {
            return Ok(());
        }
        let needs_software_freeze = self
            .trace
            .threads
            .values()
            .any(|thread| matches!(thread.stop, Some(Stop::Software { .. })));
        let initial = self.hits()?;
        let capture_deadline = initial
            .iter()
            .any(|hit| matches!(hit.rule.program.scope, Scope::Process))
            .then(|| {
                initial
                    .iter()
                    .map(|hit| hit.observed + hit.rule.program.budget)
                    .min()
            })
            .flatten();
        let deadline = if needs_software_freeze {
            Some(Instant::now() + CONTROL_BUDGET)
        } else {
            capture_deadline
        };
        let frozen = deadline.is_some_and(|limit| self.trace.freeze(limit).is_ok());
        if self.trace.exec_observed() || self.trace.foreign_software {
            return Err(error("target address space changed"));
        }
        self.trace.rewind_software_stops()?;
        let mut hits = if deadline.is_some() {
            self.hits()?
        } else {
            initial
        };
        self.observe_writes(&mut hits);
        let mut captured = self.capture_hits(hits, frozen);
        let resume = self
            .step_software_stops(frozen, &mut captured)
            .and_then(|()| self.resume_stopped());
        self.finish_hits(captured, resume.as_ref().err().map(|error| error.as_ref()));
        resume
    }

    fn resume_stopped(&mut self) -> Result<()> {
        let mut failure = None;
        for tid in self.stopped() {
            if let Err(e) = self.resume(tid) {
                failure.get_or_insert(e);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn stopped(&self) -> BTreeSet<i32> {
        self.trace
            .threads
            .iter()
            .filter_map(|(&tid, thread)| thread.stop.map(|_| tid))
            .collect()
    }

    fn resume(&mut self, tid: i32) -> Result<()> {
        let thread = &self.trace.threads[&tid];
        if thread.newborn {
            hardware::program(tid, &self.slots)?;
        }
        if matches!(thread.stop, Some(Stop::Software { .. })) {
            return Err(error(
                "pending software breakpoint must execute its original instruction",
            ));
        }
        if let Some(Stop::Breakpoint { slots, .. }) = thread.stop {
            let pc = regs::read(tid)?.stack.get(regs::PC)?;
            let execution = self.slots.iter().enumerate().any(|(index, rule)| {
                slots & (1 << index) != 0
                    && rule.is_some_and(|r| r.kind == Kind::Hardware && r.address == pc)
            });
            hardware::prepare_resume(tid, execution)?;
        }
        self.trace.resume(tid)
    }
}

pub(crate) fn triggered(tid: i32) -> Result<u64> {
    hardware::triggered(tid)
}

pub(crate) fn disarm(tid: i32) -> Result<()> {
    hardware::program(tid, &[None; SLOTS])
}

#[cfg(target_arch = "x86_64")]
mod hardware {
    use super::{Kind, Slots};
    use crate::Result;
    use nix::{errno::Errno, libc, sys::ptrace, unistd::Pid};

    fn debug_offset(index: usize) -> usize {
        std::mem::offset_of!(libc::user, u_debugreg) + index * size_of::<u64>()
    }

    fn debug_register(tid: i32, index: usize, value: u64) -> Result<()> {
        Errno::result(unsafe {
            libc::ptrace(libc::PTRACE_POKEUSER, tid, debug_offset(index), value)
        })?;
        Ok(())
    }

    pub(super) fn triggered(tid: i32) -> Result<u64> {
        // The low four status bits identify the triggered debug registers.
        Ok(
            ptrace::read_user(Pid::from_raw(tid), debug_offset(6) as ptrace::AddressType)? as u64
                & 0xf,
        )
    }

    pub(super) fn program(tid: i32, slots: &Slots) -> Result<()> {
        debug_register(tid, 7, 0)?;
        let mut control = 0;
        for (index, slot) in slots.iter().enumerate() {
            if let Some(rule) = slot {
                debug_register(tid, index, rule.address)?;
                control |= 1 << (2 * index); // Local enable.
                if let Kind::Watch { length, read_write } = rule.kind {
                    let width = match length {
                        1 => 0,
                        2 => 1,
                        4 => 3,
                        8 => 2,
                        _ => unreachable!(),
                    };
                    control |=
                        ((if read_write { 3 } else { 1 }) | (width << 2)) << (16 + 4 * index);
                }
            }
        }
        debug_register(tid, 6, 0xffff_0ff0)?;
        debug_register(tid, 7, control)
    }

    pub(super) fn prepare_resume(tid: i32, execution: bool) -> Result<()> {
        debug_register(tid, 6, 0xffff_0ff0)?;
        if execution {
            let pid = Pid::from_raw(tid);
            let mut regs = ptrace::getregs(pid)?;
            // RF suppresses the execution breakpoint for the retried instruction.
            regs.eflags |= 1 << 16;
            ptrace::setregs(pid, regs)?;
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod hardware {
    use super::Slots;
    use crate::{Result, error};

    pub(super) fn program(_: i32, _: &Slots) -> Result<()> {
        Err(error(
            "hardware execution breakpoints currently require x86_64",
        ))
    }

    pub(super) fn triggered(_: i32) -> Result<u64> {
        Err(error("hardware breakpoints require x86_64"))
    }

    pub(super) fn prepare_resume(_: i32, _: bool) -> Result<()> {
        Err(error(
            "hardware execution breakpoints currently require x86_64",
        ))
    }
}
