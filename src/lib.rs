#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("aidbg supports Linux x86_64 and AArch64");

pub mod breakpoint;
pub mod code;
pub mod coredump;
mod cpp_names;
pub mod disassembly;
mod modules;
pub mod perf;
mod procfs;
mod regs;
pub mod rpc;
pub mod selection;
mod software_breakpoint;
pub mod symbols;
pub mod target_call;
mod trace;
mod unwind;
pub mod watch_step;

use procfs::{Memory, Signals, Status, epoch_ms, start_ticks, task_path};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn error(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::other(message.into()).into()
}

pub fn hex(v: u64) -> String {
    format!("0x{v:x}")
}

#[derive(Serialize)]
struct Issue {
    section: &'static str,
    tid: Option<i32>,
    message: String,
}

#[derive(Serialize)]
struct Process {
    pid: i32,
    name: Option<String>,
    executable: Option<String>,
    architecture: Option<&'static str>,
    start_time_ticks_since_boot: Option<String>,
    state_before: Option<String>,
}

#[derive(Serialize)]
struct Thread {
    tid: i32,
    name: Option<String>,
    state_before_seize: Option<String>,
    state_at_capture: Option<String>,
    stop: Option<trace::StopInfo>,
    signals: Option<Signals>,
    registers: Option<BTreeMap<String, String>>,
    stack: Option<unwind::Stack>,
}

#[derive(Serialize)]
pub struct Snapshot {
    freeze_requested: &'static str,
    freeze_achieved: &'static str,
    schema_version: u32,
    status: &'static str,
    started_unix_ms: u64,
    capture_finished_unix_ms: u64,
    trace_window_ms: Option<u64>,
    all_threads_stopped_during_capture: bool,
    process: Process,
    memory: Option<Memory>,
    modules: Vec<modules::ModuleInfo>,
    threads: Vec<Thread>,
    issues: Vec<Issue>,
    cleanup: trace::Cleanup,
}

impl Snapshot {
    fn new(pid: i32, mode: rpc::FreezeMode) -> Self {
        Self {
            freeze_requested: match mode {
                rpc::FreezeMode::Try => "try",
                rpc::FreezeMode::Never => "never",
                rpc::FreezeMode::Required => "required",
            },
            freeze_achieved: "none",
            schema_version: 1,
            status: "failed",
            started_unix_ms: epoch_ms(),
            capture_finished_unix_ms: 0,
            trace_window_ms: None,
            all_threads_stopped_during_capture: false,
            process: Process {
                pid,
                name: None,
                executable: None,
                architecture: None,
                start_time_ticks_since_boot: None,
                state_before: None,
            },
            memory: None,
            modules: vec![],
            threads: vec![],
            issues: vec![],
            cleanup: trace::Cleanup::default(),
        }
    }

    fn issue(&mut self, section: &'static str, tid: Option<i32>, message: impl ToString) {
        self.issues.push(Issue {
            section,
            tid,
            message: message.to_string(),
        });
    }

    fn acquire(&mut self, mode: rpc::FreezeMode) -> Result<()> {
        let pid = self.process.pid;
        // The open directory stays bound to this procfs instance even when
        // the numeric PID disappears during the snapshot.
        let procdir = File::open(format!("/proc/{pid}"))?;
        let root = PathBuf::from(format!("/proc/self/fd/{}", procdir.as_raw_fd()));
        let start = start_ticks(&root)?;
        self.process.start_time_ticks_since_boot = Some(start.to_string());
        let before = Status::read(&root)?;
        let requested = pid.to_string();
        if before.field("Tgid") != Some(&requested) {
            return Err(error("pass the process ID (thread-group leader)"));
        }
        self.process.name = before.name();
        self.process.state_before = before.state();
        if mode == rpc::FreezeMode::Never {
            self.read_identity(&root);
            self.memory = Some(before.memory());
            self.read_live_modules(&root);
            for tid in procfs::task_ids(&root)? {
                self.read_live_thread(&root, tid, None);
            }
            self.status = if self.issues.is_empty() {
                "complete"
            } else {
                "partial"
            };
            return Ok(());
        }
        // Probe ABI again after stopping. Live metadata is still useful in try
        // mode when registers are unavailable.
        self.read_identity(&root);
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut trace = trace::Trace::new(pid, &root, start);
        match trace.freeze(deadline) {
            Ok(()) => self.all_threads_stopped_during_capture = true,
            Err(e) => self.issue("attach", None, e),
        }
        self.freeze_achieved = if self.all_threads_stopped_during_capture {
            "all"
        } else if trace.threads.values().any(|t| t.stop.is_some()) {
            "some"
        } else {
            "none"
        };
        if mode == rpc::FreezeMode::Required && !self.all_threads_stopped_during_capture {
            self.finish_trace(&mut trace);
            return Ok(());
        }
        let (maps, images, exe) = self.collect_stopped(&trace, &root, deadline, None, false);
        if !self.all_threads_stopped_during_capture {
            match procfs::task_ids(&root) {
                Ok(ids) => {
                    for tid in ids {
                        if !trace.threads.contains_key(&tid) {
                            let before = trace.observed.get(&tid).and_then(Option::as_ref);
                            self.read_live_thread(&root, tid, before);
                        }
                    }
                }
                Err(e) => self.issue("thread_capture", None, e),
            }
        }
        self.threads.sort_unstable_by_key(|t| t.tid);
        self.finish_trace(&mut trace);
        self.status = if !self.cleanup.ok() {
            "failed"
        } else if self.all_threads_stopped_during_capture && self.issues.is_empty() {
            "complete"
        } else {
            "partial"
        };
        self.finish_symbols(Some(&root), maps, images, exe.as_ref());
        Ok(())
    }

    fn collect_stopped(
        &mut self,
        trace: &trace::Trace<'_>,
        root: &Path,
        deadline: Instant,
        hit: Option<i32>,
        budgeted: bool,
    ) -> (Vec<modules::Module>, unwind::Images, Option<fs::Metadata>) {
        let exe = fs::metadata(root.join("exe")).ok();
        // If an exec raced the initial probe, skip register collection on a
        // different ABI and use the executable observed at the stop.
        let same_abi = if trace.threads.values().any(|t| t.stop.is_some()) {
            match self.refresh_identity(root) {
                Ok(()) => true,
                Err(e) => {
                    self.issue("process", None, e);
                    false
                }
            }
        } else {
            false
        };
        let maps = match modules::read(root) {
            Ok(v) => v,
            Err(e) => {
                self.issue("modules", None, e);
                vec![]
            }
        };
        if let Ok(status) = Status::read(root) {
            self.process.name = status.name().or(self.process.name.take());
            self.memory = Some(status.memory());
        } else {
            self.issue("memory", None, "could not refresh process status");
        }
        let mut images = unwind::Images::new();
        for (&tid, captured) in &trace.threads {
            if hit.is_some_and(|hit| hit != tid) {
                continue;
            }
            if budgeted && Instant::now() >= deadline {
                self.issue("capture", Some(tid), "snapshot deadline reached");
                break;
            }
            let status = Status::read(&task_path(root, tid));
            let mut thread = Thread {
                tid,
                name: captured.before.as_ref().and_then(Status::name),
                state_before_seize: captured.before.as_ref().and_then(Status::state),
                state_at_capture: None,
                stop: captured.stop.map(trace::Stop::info),
                signals: None,
                registers: None,
                stack: None,
            };
            match status {
                Ok(status) => {
                    thread.name = status.name().or(thread.name);
                    thread.state_at_capture = status.state();
                    thread.signals = Some(status.signals());
                }
                Err(e) => self.issue("thread_status", Some(tid), e),
            }
            if same_abi && captured.stop.is_some() {
                match regs::read(tid) {
                    Ok(regs) => {
                        thread.registers = Some(regs.general);
                        if self.all_threads_stopped_during_capture || hit.is_some() {
                            let stack =
                                images.walk(trace, regs.stack, &maps, root, exe.as_ref(), deadline);
                            if !stack.complete {
                                self.issue("stack", Some(tid), &stack.stop_reason);
                            }
                            thread.stack = Some(stack);
                        }
                    }
                    Err(e) => self.issue("registers", Some(tid), e),
                }
            }
            self.threads.push(thread);
        }
        (maps, images, exe)
    }

    fn finish_symbols(
        &mut self,
        root: Option<&Path>,
        maps: Vec<modules::Module>,
        images: unwind::Images,
        exe: Option<&fs::Metadata>,
    ) {
        for thread in &mut self.threads {
            if let Some(stack) = &mut thread.stack {
                images.symbolize(stack);
            }
        }
        self.modules = maps
            .iter()
            .enumerate()
            .map(|(i, m)| images.module_info(i, m, root, exe))
            .collect();
    }

    fn finish_trace(&mut self, trace: &mut trace::Trace<'_>) {
        self.cleanup = trace.close();
        let unconfirmed: Vec<_> = self
            .cleanup
            .threads
            .iter()
            .filter(|t| {
                t.outcome == "detached" && t.group_stop_before_detach && !t.preserved_group_stop
            })
            .map(|t| t.tid)
            .collect();
        for tid in unconfirmed {
            self.issue(
                "cleanup",
                Some(tid),
                "group stop was not observed after detach",
            );
        }
        self.trace_window_ms = trace.started.map(|s| s.elapsed().as_millis() as u64);
        self.capture_finished_unix_ms = epoch_ms();
    }

    fn read_identity(&mut self, root: &Path) {
        match machine(root) {
            Ok(arch) => self.process.architecture = Some(arch),
            Err(e) => self.issue("process", None, e),
        }
        match fs::read_link(root.join("exe")) {
            Ok(path) => self.process.executable = Some(path.to_string_lossy().into_owned()),
            Err(e) => self.issue("process", None, e),
        }
    }

    fn read_live_modules(&mut self, root: &Path) {
        match modules::read(root) {
            Ok(maps) => {
                let exe = fs::metadata(root.join("exe")).ok();
                self.modules = maps
                    .iter()
                    .enumerate()
                    .map(|(i, m)| m.info(i, exe.as_ref(), m.image_kind(root)))
                    .collect();
            }
            Err(e) => self.issue("modules", None, e),
        }
    }

    fn read_live_thread(&mut self, root: &Path, tid: i32, before: Option<&Status>) {
        let status = match Status::read(&task_path(root, tid)) {
            Ok(status) => Some(status),
            Err(e) => {
                self.issue("thread_status", Some(tid), e);
                None
            }
        };
        self.threads.push(Thread {
            tid,
            name: status
                .as_ref()
                .and_then(Status::name)
                .or_else(|| before.and_then(Status::name)),
            state_before_seize: before.and_then(Status::state),
            state_at_capture: status.as_ref().and_then(Status::state),
            signals: status.as_ref().map(Status::signals),
            stop: None,
            registers: None,
            stack: None,
        });
    }

    fn refresh_identity(&mut self, root: &Path) -> Result<()> {
        let arch = machine(root)?;
        if arch != regs::ARCH {
            return Err(error("target architecture changed before capture"));
        }
        self.process.executable = Some(
            fs::read_link(root.join("exe"))?
                .to_string_lossy()
                .into_owned(),
        );
        Ok(())
    }

    pub fn run(pid: i32, mode: rpc::FreezeMode) -> Self {
        let mut result = Self::new(pid, mode);
        if let Err(e) = result.acquire(mode) {
            result.issue("process", None, e);
        }
        if result.capture_finished_unix_ms == 0 {
            result.capture_finished_unix_ms = epoch_ms();
        }
        result
    }
}

fn machine(root: &Path) -> Result<&'static str> {
    let mut h = [0u8; 20];
    File::open(root.join("exe"))?.read_exact(&mut h)?;
    if h[..6] != [0x7f, b'E', b'L', b'F', 2, 1] {
        return Err(error("expected a little-endian ELF64 tracee"));
    }
    match u16::from_le_bytes([h[18], h[19]]) {
        62 => Ok("x86_64"),
        183 => Ok("aarch64"),
        n => Err(error(format!("unsupported ELF machine {n}"))),
    }
}
