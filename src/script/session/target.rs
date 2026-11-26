use super::super::{
    CoreSymbols,
    core::{self, Target as Core},
};
use crate::{
    Result,
    breakpoint::{self, Kind, WatchAccess},
    code, coredump, disassembly, error, hex, modules, procfs, regs,
    rpc::{
        CoreMode, OpenCoreRequest, RunProcessRequest, SearchMemoryRequest, SearchSymbolsRequest,
        SymbolMatch,
    },
    symbols,
    trace::{Stop, Trace, read_process_prefix},
    unwind::Images,
};
use nix::{
    errno::Errno,
    libc,
    sys::{
        ptrace,
        signal::{Signal, kill},
    },
    unistd::Pid,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
        unix::fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

pub(super) const DEADLINE: Duration = Duration::from_millis(750);
const MAX_MEMORY: usize = 16 * 1024 * 1024;

pub(super) enum Target {
    Live(Live),
    Core(Box<Core>),
}

#[derive(Clone, Copy)]
struct Point {
    kind: Kind,
    address: u64,
    thread: Option<(i32, u64)>,
    active: bool,
    software_watch: bool,
    hits: u64,
}

struct PendingPoint {
    name: String,
    module: Option<String>,
    site: Option<symbols::BreakpointSite>,
    enabled: bool,
}

struct FrameImages {
    images: Images,
    modules: Vec<modules::Module>,
    executable: Option<fs::Metadata>,
    variables: BTreeMap<usize, Option<symbols::inspect::offline::DwarfImage>>,
    reuse_variable_context: bool,
}

struct VariableFrame {
    registers: regs::Registers,
    module: Option<usize>,
    link: Option<u64>,
    cfa: Option<u64>,
}

pub(super) struct Live {
    pub pid: i32,
    start: u64,
    pub root: PathBuf,
    pub(super) trace: Trace,
    launched: bool,
    exit_reported: bool,
    pub(super) stdio: Option<super::process_io::ProcessIo>,
    pub paused: BTreeSet<i32>,
    initial_attach: BTreeSet<i32>,
    pub callbacks: BTreeSet<i32>,
    stop_sequences: BTreeMap<i32, BTreeSet<u64>>,
    points: BTreeMap<u32, Point>,
    pending_points: BTreeMap<u32, PendingPoint>,
    loader_hook: Option<u64>,
    handled_stops: BTreeSet<i32>,
    syscall_catches: BTreeMap<Option<i32>, super::syscalls::Catch>,
    syscall_entries: BTreeMap<i32, super::syscalls::Entry>,
    programmed: BTreeMap<i32, u64>,
    watch_values: BTreeMap<u32, u64>,
    branch_record: BTreeMap<i32, (u64, bool)>,
    branches: Vec<Value>,
    suppress: BTreeSet<i32>,
    last_software_tid: i32,
    linked: Vec<(std::ops::Range<u64>, Vec<Value>)>,
    dwarf: Vec<super::dwarf::AttachedDwarf>,
    pub(super) scratch: Option<super::inferior::Scratch>,
}

pub(super) enum Event {
    Fork {
        parent: i32,
        old_threads: Vec<i32>,
        tid: i32,
    },
    Exec {
        tid: i32,
        executable: Option<PathBuf>,
    },
    Breakpoint {
        tid: i32,
        id: u32,
        address: u64,
        watch: Option<WatchHit>,
    },
    Syscall {
        tid: i32,
        row: Value,
    },
    Signal {
        tid: i32,
        number: i32,
        fault: Option<u64>,
        callback: bool,
    },
    Exit {
        tid: i32,
        process: bool,
        result: Option<crate::trace::LaunchExit>,
    },
}

pub(super) struct WatchHit {
    pub length: usize,
    pub before: Option<u64>,
    pub after: Option<u64>,
    pub access: Option<&'static str>,
}

impl WatchHit {
    fn new(
        length: usize,
        configured: WatchAccess,
        before: Option<u64>,
        after: Option<u64>,
    ) -> Self {
        let access = match configured {
            WatchAccess::Read => Some("read"),
            WatchAccess::Write => Some("write"),
            WatchAccess::ReadWrite if before.zip(after).is_some_and(|(a, b)| a != b) => {
                Some("write")
            }
            WatchAccess::ReadWrite => None,
        };
        Self {
            length,
            before,
            after,
            access,
        }
    }
}

impl Live {
    fn new(pid: i32, root: PathBuf, start: u64, mut trace: Trace, launched: bool) -> Self {
        trace.retired = Some(Vec::new());
        Self {
            pid,
            start,
            root,
            trace,
            launched,
            exit_reported: false,
            stdio: None,
            paused: BTreeSet::new(),
            initial_attach: BTreeSet::new(),
            callbacks: BTreeSet::new(),
            stop_sequences: BTreeMap::new(),
            points: BTreeMap::new(),
            pending_points: BTreeMap::new(),
            loader_hook: None,
            handled_stops: BTreeSet::new(),
            syscall_catches: BTreeMap::new(),
            syscall_entries: BTreeMap::new(),
            programmed: BTreeMap::new(),
            watch_values: BTreeMap::new(),
            branch_record: BTreeMap::new(),
            branches: Vec::new(),
            suppress: BTreeSet::new(),
            last_software_tid: 0,
            linked: Vec::new(),
            dwarf: Vec::new(),
            scratch: None,
        }
    }

    pub fn attach(pid: i32) -> Result<Self> {
        if pid <= 0 || pid == std::process::id() as i32 {
            return Err(error(
                "attach requires a positive target PID other than the debugger",
            ));
        }
        let root = PathBuf::from(format!("/proc/{pid}"));
        if procfs::Status::read(&root)?.field("Tgid") != Some(&pid.to_string()) {
            return Err(error("attach requires a process ID"));
        }
        let start = procfs::start_ticks(&root)?;
        if crate::machine(&root)? != regs::ARCH {
            return Err(error("target ABI does not match the debugger"));
        }
        let mut trace = Trace::new(pid, &root, start);
        trace.monitor();
        trace.freeze(Instant::now() + DEADLINE)?;
        let mut live = Self::new(pid, root, start, trace, false);
        live.paused.extend(live.trace.threads.keys().copied());
        live.initial_attach.clone_from(&live.paused);
        Ok(live)
    }

    pub fn launch(args: RunProcessRequest) -> Result<Self> {
        let path = Path::new(&args.path);
        if !path.is_absolute() {
            return Err(error("run requires an absolute server path"));
        }
        let path = CString::new(path.as_os_str().as_bytes())?;
        let arguments: Vec<_> = args
            .arg
            .into_iter()
            .map(CString::new)
            .collect::<std::result::Result<_, _>>()?;
        let argv: Vec<_> = std::iter::once(path.as_ptr())
            .chain(arguments.iter().map(|arg| arg.as_ptr()))
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let (gate, mut release) = io::pipe()?;
        let (stdio, child_io) = super::process_io::ProcessIo::new()?;
        let (report, exec_error) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        // Only async-signal-safe operations are used in the fork child.
        let pid = Errno::result(unsafe { libc::fork() })?;
        if pid == 0 {
            unsafe {
                libc::close(release.as_raw_fd());
                let mut token = 0u8;
                if libc::read(gate.as_raw_fd(), (&mut token as *mut u8).cast(), 1) != 1 {
                    libc::_exit(127);
                }
                libc::close(gate.as_raw_fd());
                libc::close(report.as_raw_fd());
                if libc::dup2(child_io.stdin.as_raw_fd(), 0) >= 0
                    && libc::dup2(child_io.stdout.as_raw_fd(), 1) >= 0
                    && libc::dup2(child_io.stderr.as_raw_fd(), 2) >= 0
                {
                    libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                    libc::execv(path.as_ptr(), argv.as_ptr());
                }
                let errno = Errno::last_raw().to_ne_bytes();
                libc::write(exec_error.as_raw_fd(), errno.as_ptr().cast(), errno.len());
                libc::_exit(127);
            }
        }
        drop((gate, exec_error, child_io));
        let root = PathBuf::from(format!("/proc/{pid}"));
        let launched = (|| {
            let start = procfs::start_ticks(&root)?;
            let mut trace = Trace::new(pid, &root, start);
            trace.seize_launched(false)?;
            release.write_all(&[1])?;
            drop(release);
            let deadline = Instant::now() + DEADLINE;
            loop {
                trace.poll()?;
                if trace.exec_observed() {
                    if crate::machine(&root)? != regs::ARCH {
                        return Err(error("target ABI does not match the debugger"));
                    }
                    trace.threads.get_mut(&pid).unwrap().stop = Some(Stop::ExecBoundary);
                    let mut live = Self::new(pid, root, start, trace, true);
                    live.stdio = Some(stdio);
                    live.paused.insert(pid);
                    return Ok(live);
                }
                if trace.threads.is_empty() {
                    use std::io::Read;
                    let mut errno = [0; 4];
                    File::from(report).read_exact(&mut errno)?;
                    return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(errno)).into());
                }
                if let Some(thread) = trace.threads.get(&pid)
                    && thread.stop.is_some()
                {
                    trace.resume(pid)?;
                }
                if Instant::now() >= deadline {
                    return Err(error("timed out waiting for exec"));
                }
                thread::sleep(Duration::from_millis(1));
            }
        })();
        if launched.is_err() {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(Pid::from_raw(pid), None);
        }
        launched
    }

    fn annotate_imports(
        &self,
        targets: &mut BTreeMap<u64, Vec<Value>>,
        imports: &symbols::RuntimeImports,
    ) {
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut resolved = BTreeMap::new();
        for reference in targets.values_mut().flatten() {
            if Instant::now() >= deadline {
                break;
            }
            let Ok(target) = parse_address(&reference["address"]) else {
                continue;
            };
            let slot = match reference["kind"].as_str() {
                Some("indirect_slot" | "pc_relative" | "read") => target,
                Some("branch_target") if imports.is_plt(target) => {
                    let mut code = [0; 24];
                    let Ok(size) = self.trace.read_code_prefix(target, &mut code) else {
                        continue;
                    };
                    let Ok(stub) =
                        disassembly::instruction_targets(regs::ARCH, target, &code[..size])
                    else {
                        continue;
                    };
                    let Some(slot) = stub
                        .values()
                        .flatten()
                        .take(4)
                        .find(|row| row["kind"] == "indirect_slot")
                        .and_then(|row| parse_address(&row["address"]).ok())
                    else {
                        continue;
                    };
                    slot
                }
                _ => continue,
            };
            let Some(requested) = imports.slots.get(&slot) else {
                continue;
            };
            reference["requested"] = json!(requested);
            reference["slot"] = json!(hex(slot));
            if !matches!(
                reference["kind"].as_str(),
                Some("indirect_slot" | "branch_target")
            ) {
                continue;
            }
            let binding = resolved.entry(slot).or_insert_with(|| {
                let mut bytes = [0; 8];
                self.trace.read_memory(slot, &mut bytes).ok()?;
                let observed = u64::from_le_bytes(bytes);
                let map = modules::mapping_at(&self.root, observed).ok()??;
                if observed == 0 || imports.is_plt(observed) || !map.executable() {
                    return None;
                }
                let row = symbols::symbol_at(self.pid, observed).ok()??;
                // Lazy binding stubs and addresses outside a symbol cannot establish
                // the name of a resolved function.
                if row["kind"] != "text" || row["match"] != "exact" {
                    return None;
                }
                Some((observed, row["name"].as_str()?.to_owned()))
            });
            if let Some((address, name)) = binding {
                reference["resolvedAddress"] = json!(hex(*address));
                reference["resolved"] = json!(name);
            }
        }
    }

    pub(super) fn resume_initial(&mut self) -> Result<()> {
        for tid in self.tids() {
            if matches!(
                self.trace.threads[&tid].stop,
                Some(Stop::Interrupt | Stop::ExecBoundary)
            ) {
                self.resume(tid)?;
                self.paused.remove(&tid);
            } else {
                // Let the normal event loop apply the policy for real stops.
                self.paused.remove(&tid);
            }
        }
        self.trace.poll()?;
        Ok(())
    }

    pub(super) fn resume_attach_stops(&mut self) -> Result<()> {
        for tid in self.tids() {
            if self.paused.contains(&tid)
                && !self.callbacks.contains(&tid)
                && !self.stop_sequences.contains_key(&tid)
                && matches!(
                    self.trace.threads[&tid].stop,
                    Some(Stop::Interrupt | Stop::ExecBoundary)
                )
            {
                self.resume(tid)?;
                self.paused.remove(&tid);
            }
        }
        self.trace.poll()?;
        Ok(())
    }

    pub(super) fn execution_state(&self) -> &'static str {
        if self.trace.threads.is_empty() {
            "exited"
        } else if self
            .trace
            .threads
            .values()
            .all(|thread| thread.stop.is_some())
        {
            "paused"
        } else if self
            .trace
            .threads
            .values()
            .any(|thread| thread.stop.is_some())
        {
            "mixed"
        } else {
            "running"
        }
    }

    pub(super) fn describe_status(&self) -> String {
        use std::fmt::Write;
        let mut text = String::new();
        let executable = fs::read_link(self.root.join("exe")).ok();
        match executable {
            Some(path) => writeln!(text, "Target: {} (PID {})", path.display(), self.pid),
            None => writeln!(text, "Target: PID {}", self.pid),
        }
        .unwrap();
        let stopped = self
            .trace
            .threads
            .values()
            .filter(|thread| thread.stop.is_some())
            .count();
        writeln!(
            text,
            "State: {}\nAttached: {}",
            self.execution_state(),
            !self.trace.threads.is_empty()
        )
        .unwrap();
        if !self.trace.threads.is_empty() {
            writeln!(
                text,
                "Threads: {} ({stopped} stopped)",
                self.trace.threads.len()
            )
            .unwrap();
        }
        if !self.trace.threads.is_empty() {
            let tids = self
                .trace
                .threads
                .keys()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            writeln!(text, "Thread IDs: {}", tids.join(", ")).unwrap();
        }
        for row in self.paused_stops() {
            if self
                .trace
                .threads
                .contains_key(&(row["tid"].as_i64().unwrap() as i32))
            {
                let reason = row["signalName"]
                    .as_str()
                    .or_else(|| row["reason"].as_str())
                    .unwrap();
                writeln!(text, "  Thread {}: {reason}", row["tid"]).unwrap();
            }
        }
        for (label, watches) in [("Breakpoints", false), ("Watchpoints", true)] {
            let mut heading = false;
            for (&id, point) in &self.points {
                if matches!(point.kind, Kind::Watch { .. }) != watches {
                    continue;
                }
                if !heading {
                    writeln!(text, "{label}:").unwrap();
                    heading = true;
                }
                let state = if point.active { "enabled" } else { "disabled" };
                let name = self
                    .pending_points
                    .get(&id)
                    .map(|pending| pending.name.as_str());
                writeln!(
                    text,
                    "  #{id} {state} {}{:#x} hits={} ({})",
                    name.map(|name| format!("{name} at ")).unwrap_or_default(),
                    point.address,
                    point.hits,
                    point.kind.name()
                )
                .unwrap();
            }
        }
        for (&id, point) in &self.pending_points {
            if !self.points.contains_key(&id) {
                let state = if point.enabled { "pending" } else { "disabled" };
                writeln!(text, "Breakpoint #{id}: {state} {}", point.name).unwrap();
            }
        }
        text
    }

    pub fn verify(&self) -> Result<()> {
        if self.trace.threads.is_empty() || procfs::start_ticks(&self.root).ok() != Some(self.start)
        {
            return Err(error("target process no longer exists"));
        }
        Ok(())
    }

    pub(super) fn record_point_hits(&mut self, id: u32, hits: u64) {
        if let Some(point) = self.points.get_mut(&id) {
            point.hits = hits;
        }
    }

    pub(super) fn paused_stops(&self) -> Vec<Value> {
        self.paused
            .union(&self.callbacks)
            .map(|tid| {
                let mut signal_name = None;
                let reason = match self.trace.threads.get(tid).and_then(|thread| thread.stop) {
                    Some(Stop::ExecBoundary) => "exec",
                    Some(Stop::Syscall) => "syscall",
                    Some(Stop::Breakpoint { .. } | Stop::Software { .. }) => "breakpoint",
                    Some(Stop::Step) => "step",
                    Some(Stop::Delivery(signal) | Stop::Group(signal)) => {
                        signal_name = Some(signal.to_string());
                        "signal"
                    }
                    Some(Stop::UnnamedDelivery(number)) => {
                        signal_name = Some(format!("SIG{number}"));
                        "signal"
                    }
                    _ if self.initial_attach.contains(tid) => "attach",
                    _ => "pause",
                };
                let mut row = json!({"tid":tid,"reason":reason});
                if let Some(name) = signal_name {
                    row["signalName"] = json!(name);
                }
                row
            })
            .collect()
    }

    pub(super) fn with_stopped<T>(
        &mut self,
        tid: i32,
        action: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.with_stopped_until(tid, Instant::now() + DEADLINE, action)
    }

    fn with_stopped_until<T>(
        &mut self,
        tid: i32,
        deadline: Instant,
        action: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.verify()?;
        let was_running = self
            .trace
            .threads
            .get(&tid)
            .is_some_and(|thread| thread.stop.is_none());
        self.trace.stop_thread(tid, deadline)?;
        let result = action(self);
        if was_running
            && matches!(
                self.trace.threads.get(&tid).and_then(|thread| thread.stop),
                Some(Stop::Interrupt)
            )
        {
            self.resume(tid)?;
        }
        result
    }

    pub(super) fn with_frozen<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.with_frozen_until(Instant::now() + DEADLINE, action)
    }

    fn with_frozen_until<T>(
        &mut self,
        deadline: Instant,
        action: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        self.verify()?;
        let previous: BTreeSet<_> = self
            .trace
            .threads
            .iter()
            .filter_map(|(&tid, thread)| thread.stop.map(|_| tid))
            .collect();
        let result = self.trace.freeze(deadline).and_then(|()| action(self));
        let cleanup = self.restore_temporary_stops(&previous);
        result.and_then(|value| cleanup.map(|()| value))
    }

    fn restore_temporary_stops(&mut self, previous: &BTreeSet<i32>) -> Result<()> {
        let mut cleanup = Ok(());
        for tid in self.tids() {
            if !previous.contains(&tid)
                && !self.paused.contains(&tid)
                && !self.callbacks.contains(&tid)
                && !self.traced(tid)
                && matches!(self.trace.threads[&tid].stop, Some(Stop::Interrupt))
                && let Err(err) = self.resume(tid)
            {
                cleanup = Err(err);
            }
        }
        cleanup
    }

    pub(super) fn tids(&self) -> Vec<i32> {
        self.trace.threads.keys().copied().collect()
    }

    fn identity(&self, tid: i32) -> Result<u64> {
        self.trace
            .threads
            .get(&tid)
            .map(|thread| thread.identity)
            .ok_or_else(|| error("thread no longer exists"))
    }

    fn original_tids(&self, tid: Option<i32>) -> Vec<i32> {
        tid.map_or_else(|| self.tids(), |tid| vec![tid])
    }

    fn snapshot(
        &mut self,
        tid: Option<i32>,
        context: bool,
        stop_timeout_ms: u32,
        limit: usize,
        thread_limit: Option<usize>,
    ) -> Result<Value> {
        self.verify()?;
        if let Some(tid) = tid {
            self.identity(tid)?;
        }
        let previous: BTreeSet<_> = self
            .trace
            .threads
            .iter()
            .filter_map(|(&tid, thread)| thread.stop.map(|_| tid))
            .collect();
        let mut threads_requested: BTreeSet<_> = match tid {
            Some(tid) => BTreeSet::from([tid]),
            None => procfs::task_ids(&self.root)
                .unwrap_or_else(|_| self.tids())
                .into_iter()
                .collect(),
        };
        let started = Instant::now();
        let stop_deadline = started + Duration::from_millis(stop_timeout_ms.into());
        let stopping = crate::snapshot_timing::phase("pause");
        let stop = if stop_timeout_ms == 0 {
            if threads_requested.is_subset(&previous) {
                Ok(())
            } else {
                Err(error("snapshot stop budget is zero"))
            }
        } else {
            match tid {
                Some(tid) => self.trace.stop_thread(tid, stop_deadline),
                None => self.trace.freeze(stop_deadline),
            }
        };
        drop(stopping);
        if tid.is_none() {
            threads_requested.extend(self.tids());
        }
        // Keep the complete operation inside the script slice while allowing
        // more time for collection when stopping the target was fast.
        let deadline = started + Duration::from_millis(1800);
        let collect = |live: &mut Self| -> Result<_> {
            live.trace.rewind_software_stops()?;
            let mut incomplete = Vec::new();
            if let Err(err) = &stop {
                incomplete.push(json!({"stage":"stop","error":err.to_string()}));
            }
            let registers_phase = crate::snapshot_timing::phase("registers");
            let mut captured = Vec::new();
            for &tid in threads_requested
                .iter()
                .take(thread_limit.unwrap_or(usize::MAX))
            {
                if live
                    .trace
                    .threads
                    .get(&tid)
                    .is_none_or(|thread| thread.stop.is_none())
                {
                    incomplete
                        .push(json!({"tid":tid,"stage":"stop","error":"thread did not stop"}));
                } else if Instant::now() >= deadline {
                    incomplete.push(
                        json!({"tid":tid,"stage":"registers","error":"snapshot deadline reached"}),
                    );
                } else {
                    match regs::read(tid) {
                        Ok(registers) => captured.push((tid, registers, Vec::new())),
                        Err(err) => incomplete
                            .push(json!({"tid":tid,"stage":"registers","error":err.to_string()})),
                    }
                }
            }
            drop(registers_phase);
            let mappings = match crate::snapshot_timing::measure("mappings", || live.mappings()) {
                Ok(mappings) => mappings,
                Err(err) => {
                    incomplete.push(json!({"stage":"mappings","error":err.to_string()}));
                    json!([])
                }
            };
            let mut variable_images = None;
            if !captured.is_empty() {
                match crate::snapshot_timing::measure("mappings", || live.frame_images()) {
                    Ok(mut images) => {
                        images.reuse_variable_context = stop.is_ok() && tid.is_none();
                        let count = captured.len();
                        for (index, (tid, registers, frames)) in captured.iter_mut().enumerate() {
                            let now = Instant::now();
                            let share =
                                deadline.saturating_duration_since(now) / (count - index) as u32;
                            if share.is_zero() {
                                incomplete.push(json!({"tid":tid,"stage":"frames","error":"snapshot deadline reached"}));
                                continue;
                            }
                            let frame_deadline = now + share;
                            match live.unwind_frames(
                                registers.stack,
                                limit,
                                frame_deadline,
                                &mut images,
                            ) {
                                Ok(rows) => {
                                    *frames = rows;
                                    if Instant::now() >= frame_deadline {
                                        incomplete.push(json!({"tid":tid,"stage":"frames","error":"snapshot unwind budget exhausted"}));
                                    }
                                }
                                Err(err) => incomplete.push(
                                    json!({"tid":tid,"stage":"frames","error":err.to_string()}),
                                ),
                            }
                        }
                        variable_images = Some(images);
                    }
                    Err(err) => incomplete.push(json!({"stage":"frames","error":err.to_string()})),
                }
            }
            let mut threads = Vec::with_capacity(captured.len());
            for (tid, registers, frames) in captured {
                let mut rows = Vec::with_capacity(frames.len());
                let mut skipped = false;
                for (mut row, stack) in frames {
                    if Instant::now() < deadline {
                        crate::snapshot_timing::measure("variables", || {
                            if let Some(images) = variable_images.as_mut() {
                                live.add_frame_values(&mut row, stack, images, deadline);
                            }
                        });
                    } else {
                        skipped = true;
                    }
                    rows.push(row);
                }
                if skipped {
                    incomplete.push(
                        json!({"tid":tid,"stage":"variables","error":"snapshot deadline reached"}),
                    );
                }
                let locals = rows.first().map(flatten_frame_values).unwrap_or_default();
                threads.push(json!({"tid":tid,"registers":regs::api_general(registers.general)?,"frames":rows,"locals":locals}));
            }
            let mut snapshot = json!({"timestamp":procfs::epoch_ms(),"threads":threads, "mappings":mappings, "threadCount":threads_requested.len(),
                "consistency":if stop.is_err() { "partial" } else if tid.is_some() { "thread" } else { "all-stopped" }});
            if thread_limit.is_some() {
                snapshot["frameLimit"] = json!(limit);
            }
            if let Some(limit) = thread_limit
                && threads_requested.len() > limit
            {
                snapshot["threadsOmitted"] = json!(threads_requested.len() - limit);
            }
            if context {
                if Instant::now() < deadline {
                    snapshot["context"] = live.process_context();
                } else {
                    incomplete.push(json!({"stage":"context","error":"snapshot deadline reached"}));
                }
            }
            if !incomplete.is_empty() {
                snapshot["incomplete"] = json!(incomplete);
            }
            Ok(snapshot)
        };
        let result = collect(self);
        let cleanup =
            crate::snapshot_timing::measure("restore", || self.restore_temporary_stops(&previous));
        crate::snapshot_timing::details(|| {
            let mut detail = json!({"pid":self.pid, "requested":threads_requested.len(),
                "restore_ok":cleanup.is_ok(), "state":self.execution_state(),
                "stopped_before":previous, "stopped_after":self.trace.threads.iter()
                    .filter_map(|(&tid,thread)| thread.stop.map(|_| tid)).collect::<Vec<_>>()});
            if let Ok(snapshot) = &result {
                let threads = snapshot["threads"].as_array().into_iter().flatten();
                let frames = threads
                    .clone()
                    .flat_map(|thread| thread["frames"].as_array().into_iter().flatten());
                detail["captured_threads"] = json!(threads.count());
                detail["frames"] = json!(frames.clone().count());
                detail["named_frames"] = json!(
                    frames
                        .clone()
                        .filter(|frame| frame["symbol"].is_string())
                        .count()
                );
                detail["source_frames"] = json!(
                    frames
                        .filter(|frame| frame["file"].is_string() && frame["line"].is_number())
                        .count()
                );
                detail["incomplete"] = snapshot["incomplete"].clone();
            }
            detail
        });
        result.and_then(|snapshot| cleanup.map(|()| snapshot))
    }

    fn process_context(&self) -> Value {
        let mut context = serde_json::Map::new();
        if let Ok(status) = fs::read_to_string(self.root.join("status")) {
            for (key, value) in status.lines().filter_map(|line| line.split_once(':')) {
                match key {
                    "State" => {
                        context.insert(key.into(), json!(value.trim()));
                    }
                    "TracerPid" | "Threads" => {
                        if let Ok(number) = value.trim().parse::<u32>() {
                            context.insert(key.into(), json!(number));
                        }
                    }
                    _ => {}
                }
            }
        }
        for key in ["syscall", "wchan"] {
            if let Ok(value) = fs::read_to_string(self.root.join(key)) {
                context.insert(key.into(), json!(value.trim()));
            }
        }
        if let Ok(entries) = fs::read_dir(self.root.join("fd")) {
            let fd: BTreeMap<_, _> = entries
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    let number = entry.file_name().to_str()?.parse::<u32>().ok()?;
                    let target = fs::read_link(entry.path()).ok()?;
                    Some((number, target.to_string_lossy().into_owned()))
                })
                .collect();
            context.insert("fd".into(), json!(fd));
        }
        Value::Object(context)
    }

    fn mappings(&self) -> Result<Value> {
        self.verify()?;
        Ok(json!(modules::map_entries(&self.root)?.into_iter().map(|(backing, map)|
            json!({"start":hex(map.start), "end":hex(map.end), "offset":hex(map.offset),
                "prot":map.perms, "name":String::from_utf8_lossy(&backing.path)})).collect::<Vec<_>>()))
    }

    pub(super) fn stop_summary(&self, tid: i32, event: &Value) -> Option<String> {
        use std::fmt::Write;
        let kind = event["kind"].as_str()?;
        if !matches!(kind, "breakpoint" | "watchpoint" | "signal") {
            return None;
        }
        let mut text = format!("Stopped: {}", event["signalName"].as_str().unwrap_or(kind));
        if event["signalName"] == "SIGSEGV"
            && let Ok(info) = ptrace::getsiginfo(Pid::from_raw(tid))
            && let Some(code) = match info.si_code {
                1 => Some("SEGV_MAPERR"),
                2 => Some("SEGV_ACCERR"),
                _ => None,
            }
        {
            write!(text, " ({code})").unwrap();
        }
        if let Some(id) = event["breakpointId"].as_u64() {
            write!(text, " #{id}").unwrap();
        }
        if let Some(count) = event["hitCount"].as_u64() {
            write!(text, " (hit {count})").unwrap();
        }
        let name = fs::read_to_string(procfs::task_path(&self.root, tid).join("comm")).ok();
        write!(text, "\nThread: {tid}").unwrap();
        if let Some(name) = name {
            write!(text, " {:?}", name.trim_end()).unwrap();
        }
        for (label, field) in [
            ("Fault address", "faultAddress"),
            ("Address", "address"),
            ("Old value", "before"),
            ("New value", "after"),
        ] {
            if let Some(value) = event[field].as_str() {
                write!(text, "\n{label}: {value}").unwrap();
            }
        }
        let deadline = Instant::now() + Duration::from_millis(40);
        let limit = if kind == "signal" { 3 } else { 1 };
        if let Ok(rows) = self.frames_until(tid, limit, deadline) {
            for (index, row) in rows.iter().enumerate() {
                let pc = row["pc"].as_str().unwrap_or_default();
                write!(text, "\n#{index} {pc}").unwrap();
                if let Some(name) = row["symbol"].as_str() {
                    write!(text, " <{name}>").unwrap();
                }
                if let Some((file, line)) = row["file"].as_str().zip(row["line"].as_u64()) {
                    write!(text, " {file}:{line}").unwrap();
                }
                if index == 0
                    && kind == "breakpoint"
                    && let Some(values) = row["parameters"].as_object()
                {
                    for (name, value) in values.iter().take(8) {
                        if !value["value"].is_null() {
                            let value = value["value"]
                                .as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| value["value"].to_string());
                            write!(
                                text,
                                "\n  {name}: {}",
                                value.chars().take(128).collect::<String>()
                            )
                            .unwrap();
                        }
                    }
                }
            }
        }
        if kind == "signal"
            && Instant::now() < deadline
            && let Ok(regs) = regs::read(tid)
            && let Ok(pc) = regs.stack.get(regs::PC)
            && let Ok(insn) = super::instruction::decode(&self.trace, pc, &regs)
        {
            write!(text, "\n=> {} {}", insn.mnemonic, insn.operands).unwrap();
            let registers = insn.registers.into_iter().collect::<BTreeSet<_>>();
            for (name, value) in registers
                .iter()
                .filter_map(|name| Some((name, regs.general.get(name)?)))
                .take(6)
            {
                write!(text, "\n   {name} = {value}").unwrap();
            }
        }
        Some(text)
    }

    fn frames(&self, tid: i32, limit: usize) -> Result<Vec<Value>> {
        self.frames_until(tid, limit, Instant::now() + DEADLINE)
    }

    fn frame_images(&self) -> Result<FrameImages> {
        Ok(FrameImages {
            images: Images::new(),
            modules: modules::read(&self.root)?,
            executable: fs::metadata(self.root.join("exe")).ok(),
            variables: BTreeMap::new(),
            reuse_variable_context: false,
        })
    }

    fn frames_until(&self, tid: i32, limit: usize, deadline: Instant) -> Result<Vec<Value>> {
        let regs = regs::read(tid)?.stack;
        let mut images = self.frame_images()?;
        Ok(self
            .unwind_frames(regs, limit, deadline, &mut images)?
            .into_iter()
            .map(|(mut row, registers)| {
                self.add_frame_values(&mut row, registers, &mut images, deadline);
                row
            })
            .collect())
    }

    fn unwind_frames(
        &self,
        regs: regs::Registers,
        limit: usize,
        deadline: Instant,
        loaded: &mut FrameImages,
    ) -> Result<Vec<(Value, VariableFrame)>> {
        let mut frame_registers = Vec::new();
        let unwind = crate::snapshot_timing::phase("unwind");
        let mut stack = loaded.images.walk_registers(
            &self.trace,
            regs,
            &loaded.modules,
            &self.root,
            loaded.executable.as_ref(),
            deadline,
            |_, registers| frame_registers.push(registers),
        );
        drop(unwind);
        stack.frames.truncate(limit);
        loaded.images.symbolize_until(
            &mut stack,
            deadline,
            &self.root,
            &loaded.modules,
            loaded.executable.as_ref(),
        );
        stack
            .frames
            .into_iter()
            .zip(frame_registers)
            .map(|(frame, registers)| {
                let inline_frames = if Instant::now() < deadline {
                    self.dwarf.iter().rev().find_map(|attached| {
                        let link = attached.link_address(frame.lookup_address)?;
                        let frames = attached.image.inline_frames(link, deadline).ok()?;
                        (!frames.is_empty()).then_some(frames)
                    }).unwrap_or(frame.inline_frames.clone())
                } else {
                    frame.inline_frames.clone()
                };
                let variable_frame = VariableFrame {
                    registers,
                    module: frame.module_id,
                    link: frame.link_pc,
                    cfa: frame.cfa,
                };
                let frame = serde_json::to_value(frame)?;
                let fp = registers.get(regs::FP).ok().map(hex);
                let source = (Instant::now() < deadline)
                    .then(|| {
                        self.attached_source(registers.get(regs::PC).ok()?)
                            .ok()
                            .flatten()
                    })
                    .flatten();
                let (file, line) = source.map_or_else(
                    || (frame["file"].clone(), frame["line"].clone()),
                    |source| (json!(source.file), json!(source.line)),
                );
                Ok((json!({"pc":frame["pc"],"lookupPc":frame["lookup_pc"],
                    "sp":frame["sp"],"fp":fp,"symbol":frame["function"],
                    "file":file,"line":line,"unwindMethod":frame["method"],
                    "missingDebugSections":frame["missing_debug_sections"], "inlineFrames":inline_frames}), variable_frame))
            })
            .collect()
    }

    fn add_frame_values(
        &self,
        row: &mut Value,
        frame: VariableFrame,
        images: &mut FrameImages,
        deadline: Instant,
    ) {
        let values = if images.reuse_variable_context
            && Instant::now() < deadline
            && self.dwarf.is_empty()
            && !crate::snapshot_timing::baseline()
            && let (Some(module), Some(link), Some(cfa)) = (frame.module, frame.link, frame.cfa)
            && let Ok(pc) = frame.registers.get(regs::PC)
            && let Some(bias) = pc.checked_sub(link)
        {
            self.unwound_frame_values(frame.registers, images, module, link, bias, cfa, deadline)
        } else {
            crate::snapshot_timing::count("variable_context_fallback");
            self.frame_values(frame.registers, deadline)
        };
        if let Ok(Value::Object(fields)) = values {
            for (key, value) in fields {
                if !value.is_null() {
                    row[key] = value;
                }
            }
        }
    }

    fn unwound_frame_values(
        &self,
        registers: regs::Registers,
        images: &mut FrameImages,
        module: usize,
        link: u64,
        bias: u64,
        cfa: u64,
        deadline: Instant,
    ) -> Result<Value> {
        use std::collections::btree_map::Entry;
        let context = crate::snapshot_timing::phase("variable_context");
        let image = match images.variables.entry(module) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(symbols::inspect::live_variable_image(
                &self.root,
                &images.modules[module],
                images.executable.as_ref(),
            )?),
        };
        let Some(mut image) = image.clone() else {
            return Ok(Value::Null);
        };
        image.bias = bias;
        let pc = registers.get(regs::PC)?;
        let frame = crate::unwind::OfflineFrame {
            regs: registers,
            pc,
            link: Some(link),
            lookup_pc: pc,
            cfa: Some(cfa),
        };
        crate::snapshot_timing::count("variable_context_reused");
        drop(context);
        image.frame_values(&self.trace, &frame, 64, deadline)
    }

    fn frame_values(&self, registers: regs::Registers, deadline: Instant) -> Result<Value> {
        if Instant::now() >= deadline {
            return Err(error("frame inspection deadline"));
        }
        let original = symbols::inspect::stopped_dwarf(&self.root, &self.trace, registers);
        let pc = registers.get(regs::PC)?;
        for attached in self.dwarf.iter().rev() {
            if let Some(link) = attached.link_address(pc)
                && attached.uniform_bias().is_some()
            {
                let frame = crate::unwind::OfflineFrame {
                    regs: registers,
                    pc,
                    link: Some(link),
                    lookup_pc: pc,
                    cfa: original.as_ref().ok().and_then(|(_, frame)| frame.cfa),
                };
                let values = attached
                    .image
                    .frame_values(&self.trace, &frame, 64, deadline);
                if values.is_ok() {
                    return values;
                }
            }
        }
        let (dwarf, frame) = original?;
        dwarf.frame_values(&self.trace, &frame, 64, deadline)
    }

    fn attached_source(&self, address: u64) -> Result<Option<symbols::Line>> {
        for attached in self.dwarf.iter().rev() {
            if let Some(link) = attached.link_address(address)
                && let Some(source) = attached.image.line(link)?
            {
                return Ok(Some(source));
            }
        }
        Ok(None)
    }

    fn evaluate(&self, tid: i32, expression: String) -> Result<Value> {
        let registers = regs::read(tid)?.stack;
        let report = symbols::inspect::inspect_stopped(
            self.pid,
            tid,
            expression,
            &self.root,
            &self.trace,
            registers,
            Instant::now() + DEADLINE,
            None,
        );
        Ok(serde_json::to_value(report)?)
    }

    pub(super) fn pause(&mut self, tid: Option<i32>) -> Result<Vec<i32>> {
        self.verify()?;
        match tid {
            Some(tid) => self.trace.stop_thread(tid, Instant::now() + DEADLINE)?,
            None => self.trace.freeze(Instant::now() + DEADLINE)?,
        }
        let tids = self.original_tids(tid);
        self.paused.extend(tids.iter().copied());
        Ok(tids)
    }

    fn slots(&self, tid: i32) -> Vec<(u32, Point)> {
        let identity = self.trace.threads[&tid].identity;
        self.points
            .iter()
            .filter(|(_, point)| {
                point.active
                    && !point.software_watch
                    && point.kind != Kind::Software
                    && point.thread.is_none_or(|thread| thread == (tid, identity))
            })
            .map(|(&id, &point)| (id, point))
            .collect()
    }

    pub(super) fn program(&mut self, tid: i32) -> Result<()> {
        let slots: Vec<_> = self
            .slots(tid)
            .into_iter()
            .map(|(_, point)| Some((point.address, point.kind)))
            .collect();
        breakpoint::session_program(tid, &slots)?;
        self.programmed.insert(tid, self.identity(tid)?);
        Ok(())
    }

    pub fn track_stop(&mut self, tid: i32, sequence: u64) {
        if self.paused.contains(&tid) {
            self.stop_sequences.entry(tid).or_default().insert(sequence);
        }
    }

    pub fn holds_stop(&self, tid: i32, sequence: u64) -> bool {
        self.paused.contains(&tid)
            && self
                .stop_sequences
                .get(&tid)
                .is_some_and(|stops| stops.contains(&sequence))
    }

    fn pending_signal(&self, tid: i32) -> bool {
        matches!(
            self.trace.threads.get(&tid).and_then(|thread| thread.stop),
            Some(Stop::Delivery(_) | Stop::UnnamedDelivery(_))
        )
    }

    pub(super) fn pass_signal(
        &mut self,
        tid: i32,
        sequence: Option<u64>,
        pass: bool,
    ) -> Result<()> {
        if !self.paused.contains(&tid)
            || self.callbacks.contains(&tid)
            || !self.pending_signal(tid)
            || sequence.is_some_and(|sequence| !self.holds_stop(tid, sequence))
        {
            return Err(error("this signal stop is no longer pending"));
        }
        if pass {
            self.resume(tid)?;
            self.paused.remove(&tid);
        } else {
            self.trace.threads.get_mut(&tid).unwrap().stop = Some(Stop::Interrupt);
        }
        Ok(())
    }

    fn resume(&mut self, tid: i32) -> Result<()> {
        self.initial_attach.remove(&tid);
        let Some(thread) = self.trace.threads.get(&tid) else {
            return Err(error("thread no longer exists"));
        };
        self.stop_sequences.remove(&tid);
        let Some(stop) = thread.stop else {
            return Ok(());
        };
        if self.programmed.get(&tid) != Some(&thread.identity)
            && self
                .points
                .values()
                .any(|p| p.kind != Kind::Software && !p.software_watch)
        {
            self.program(tid)?;
        }
        match stop {
            Stop::Software { address, .. } => {
                self.with_frozen(|live| {
                    live.trace
                        .step_software(tid, address, Instant::now() + DEADLINE)?;
                    Ok(())
                })?;
                if !matches!(
                    self.trace.threads.get(&tid).and_then(|thread| thread.stop),
                    Some(Stop::Step | Stop::Interrupt)
                ) {
                    self.handled_stops.remove(&tid);
                    return Ok(());
                }
            }
            Stop::Breakpoint { .. } => {
                if cfg!(target_arch = "aarch64") {
                    breakpoint::disarm(tid)?;
                    let stepped = self.trace.step_one(tid, Instant::now() + DEADLINE);
                    if self
                        .trace
                        .threads
                        .get(&tid)
                        .is_some_and(|thread| thread.stop.is_some())
                    {
                        self.program(tid)?;
                    }
                    if !matches!(stepped?, Some(Stop::Step | Stop::Interrupt)) {
                        self.handled_stops.remove(&tid);
                        return Ok(());
                    }
                } else {
                    let pc = regs::read(tid)?.stack.get(regs::PC)?;
                    breakpoint::session_prepare_resume(
                        tid,
                        self.slots(tid)
                            .iter()
                            .any(|(_, p)| p.kind == Kind::Hardware && p.address == pc),
                    )?;
                }
            }
            _ => {}
        }
        self.handled_stops.remove(&tid);
        self.trace.resume(tid)
    }

    pub(super) fn continue_threads(&mut self, tid: Option<i32>) -> Result<()> {
        if let Some(tid) = tid {
            self.identity(tid)?;
        }
        for tid in self.original_tids(tid) {
            if !self.paused.contains(&tid)
                || self.callbacks.contains(&tid)
                || self.pending_signal(tid)
            {
                continue;
            }
            if self.traced(tid) {
                self.trace.stop_thread(tid, Instant::now() + DEADLINE)?;
            } else {
                self.resume(tid)?;
            }
            self.paused.remove(&tid);
            self.initial_attach.remove(&tid);
        }
        Ok(())
    }

    fn update_point(&mut self, id: u32, point: Option<Point>) -> Result<()> {
        self.with_frozen(|live| {
            let previous = live.points.remove(&id);
            if let Some(point) = point { live.points.insert(id, point); }
            let affected = previous.or(point).ok_or_else(|| error("breakpoint no longer exists"))?;
            let update = if affected.software_watch {
                Ok(())
            } else if affected.kind == Kind::Software {
                let old = previous.is_some_and(|p| p.active);
                let new = point.is_some_and(|p| p.active);
                if old == new { Ok(()) } else if new {
                    live.trace.patch(affected.address)
                } else {
                    live.trace.rewind_software_stops().and_then(|()|live.trace.unpatch(affected.address)).map(|()| {
                    for thread in live.trace.threads.values_mut() {
                        if matches!(thread.stop, Some(Stop::Software { address, .. }) if address == affected.address) {
                            thread.stop = Some(Stop::Interrupt);
                        }
                    }
                    })
                }
            } else {
                live.tids().into_iter().try_for_each(|tid| live.program(tid))
            };
            if let Err(err) = update {
                live.points.remove(&id);
                if let Some(previous) = previous { live.points.insert(id, previous); }
                if affected.kind != Kind::Software && !affected.software_watch {
                    for tid in live.tids() { let _ = live.program(tid); }
                }
                return Err(err);
            }
            Ok(())
        })
    }

    fn refresh_pending_points(&mut self) -> Result<()> {
        for id in self.pending_points.keys().copied().collect::<Vec<_>>() {
            let pending = &self.pending_points[&id];
            if !pending.enabled {
                continue;
            }
            if let Some(site) = &pending.site {
                if site.still_mapped(&self.root)? {
                    continue;
                }
                self.update_point(id, None)?;
                self.pending_points.get_mut(&id).unwrap().site = None;
            }
            let pending = &self.pending_points[&id];
            let resolved = symbols::unique_breakpoint_location(
                self.pid,
                &self.root,
                pending.module.as_deref(),
                &pending.name,
                None,
                0,
                true,
                &[],
            );
            if let Ok((address, Some(site))) = resolved
                && !self.points.values().any(|point| {
                    point.active && point.kind == Kind::Software && point.address == address
                })
                && self.loader_hook != Some(address)
            {
                self.add_point(id, "software_breakpoint", address, &Value::Null)?;
                self.pending_points.get_mut(&id).unwrap().site = Some(site);
            }
        }
        Ok(())
    }

    fn install_loader_hook(&mut self) -> Result<()> {
        if self.loader_hook.is_some() || self.pending_points.is_empty() {
            return Ok(());
        }
        // The GNU loader also exposes its hook before DT_DEBUG is populated.
        let address = self.loader_rendezvous().map(|(addr, _)| addr).or_else(|| {
            symbols::unique_breakpoint_location(
                self.pid,
                &self.root,
                None,
                "_dl_debug_state",
                None,
                0,
                true,
                &[],
            )
            .ok()
            .map(|(addr, _)| addr)
        });
        let Some(address) = address else {
            return Ok(());
        };
        self.with_frozen(|live| live.trace.patch(address))?;
        self.loader_hook = Some(address);
        Ok(())
    }

    fn loader_rendezvous(&self) -> Option<(u64, u32)> {
        coredump::loader::rendezvous(&self.root, |at, bytes| self.trace.read_memory(at, bytes))
            .ok()
            .flatten()
    }

    fn add_point(&mut self, id: u32, kind: &str, address: u64, args: &Value) -> Result<()> {
        let software_watch = kind == "software_watchpoint";
        let kind = match kind {
            "software_breakpoint" => Kind::Software,
            "hardware_breakpoint" => Kind::Hardware,
            "hardware_watchpoint" | "software_watchpoint" => {
                let length = number(args, "length")? as usize;
                if !matches!(length, 1 | 2 | 4 | 8) || !address.is_multiple_of(length as u64) {
                    return Err(error(
                        "watchpoint length must be 1, 2, 4 or 8 and address aligned to it",
                    ));
                }
                let access = match args["access"].as_str() {
                    Some("write") => WatchAccess::Write,
                    Some("read") if software_watch || cfg!(target_arch = "aarch64") => {
                        WatchAccess::Read
                    }
                    Some("read") => {
                        return Err(error("NotSupport: x86 hardware cannot watch reads alone"));
                    }
                    Some("read_write") => WatchAccess::ReadWrite,
                    _ => return Err(error("invalid watchpoint access")),
                };
                Kind::Watch { length, access }
            }
            _ => return Err(error("unknown breakpoint type")),
        };
        if kind == Kind::Software
            && self
                .points
                .values()
                .any(|p| p.active && p.address == address && p.kind == kind)
        {
            return Err(error(
                "software breakpoint is already installed at this address",
            ));
        }
        let thread = args["tid"]
            .as_i64()
            .map(|tid| -> Result<_> {
                let tid = i32::try_from(tid)?;
                Ok((tid, self.identity(tid)?))
            })
            .transpose()?;
        let point = Point {
            kind,
            address,
            thread,
            active: true,
            software_watch,
            hits: 0,
        };
        self.update_point(id, Some(point))?;
        if let Kind::Watch { length, .. } = kind
            && let Ok(value) = self.trace.read_word(address, length)
        {
            self.watch_values.insert(id, value);
        }
        Ok(())
    }

    pub fn drain_io(&mut self) -> Result<()> {
        if let Some(stdio) = &mut self.stdio {
            stdio.drain()?;
        }
        Ok(())
    }

    pub fn tick(&mut self, signals: &BTreeSet<i32>) -> Result<Vec<Event>> {
        self.trace.poll()?;
        if self.trace.awaiting_fork() {
            if let Some((pid, start, root, trace)) = self.trace.take_fork_child()? {
                let parent = self.pid;
                let old_threads = self.tids();
                let mut child = Self::new(pid, root, start, trace, false);
                child.paused.insert(pid);
                child.stdio = self.stdio.take();
                child.dwarf = std::mem::take(&mut self.dwarf);
                if let Some(catch) = self.syscall_catches.get(&None).copied() {
                    child.syscall_catches.insert(None, catch);
                    child.trace.syscall_all = true;
                }
                child.pending_points = std::mem::take(&mut self.pending_points);
                for point in child.pending_points.values_mut() {
                    point.site = None;
                }
                self.close()?;
                *self = child;
                self.install_loader_hook()?;
                self.refresh_pending_points()?;
                return Ok(vec![Event::Fork {
                    parent,
                    old_threads,
                    tid: pid,
                }]);
            }
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        // A successful exec invalidates breakpoints and the scratch mapping.
        if self.trace.exec_observed() {
            self.trace.clear_patches();
            self.points.clear();
            self.loader_hook = None;
            for pending in self.pending_points.values_mut() {
                pending.site = None;
            }
            self.programmed.clear();
            self.watch_values.clear();
            self.branch_record.clear();
            self.linked.clear();
            self.dwarf.clear();
            self.scratch = None;
            self.paused
                .retain(|tid| self.trace.threads.contains_key(tid));
            for (&tid, thread) in &mut self.trace.threads {
                if matches!(thread.stop, Some(Stop::Event(_, libc::PTRACE_EVENT_EXEC))) {
                    thread.stop = Some(Stop::ExecBoundary);
                    self.paused.insert(tid);
                    self.handled_stops.remove(&tid);
                    self.stop_sequences.remove(&tid);
                    events.push(Event::Exec {
                        tid,
                        executable: fs::read_link(self.root.join("exe")).ok(),
                    });
                }
            }
            self.install_loader_hook()?;
            self.refresh_pending_points()?;
        }
        self.trace.detach_foreign_children()?;
        self.syscall_entries
            .retain(|tid, _| self.trace.threads.contains_key(tid));
        self.syscall_catches
            .retain(|tid, _| tid.is_none_or(|tid| self.trace.threads.contains_key(&tid)));
        self.trace
            .syscall_threads
            .retain(|tid| self.trace.threads.contains_key(tid));
        self.paused
            .retain(|tid| self.trace.threads.contains_key(tid));
        self.callbacks
            .retain(|tid| self.trace.threads.contains_key(tid));
        self.suppress.retain(|tid| self.callbacks.contains(tid));
        self.handled_stops
            .retain(|tid| self.trace.threads.contains_key(tid));
        self.branch_record.retain(|tid, (identity, _)| {
            self.trace
                .threads
                .get(tid)
                .is_some_and(|thread| thread.identity == *identity)
        });
        let retired = self
            .trace
            .retired
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default();
        for (tid, result) in retired {
            self.stop_sequences.remove(&tid);
            if tid != self.pid || !self.trace.threads.is_empty() {
                events.push(Event::Exit {
                    tid,
                    process: false,
                    result,
                });
            }
        }
        if self.trace.threads.is_empty() && !self.exit_reported {
            self.exit_reported = true;
            events.push(Event::Exit {
                tid: self.pid,
                process: true,
                result: self.trace.exit,
            });
        }
        for tid in self.tids() {
            if self.callbacks.contains(&tid) {
                continue;
            }
            let Some(stop) = self.trace.threads.get(&tid).and_then(|thread| thread.stop) else {
                continue;
            };
            if matches!(stop, Stop::Delivery(Signal::SIGCHLD))
                && !signals.contains(&(Signal::SIGCHLD as i32))
                && !self.paused.contains(&tid)
            {
                self.resume(tid)?;
                continue;
            }
            if matches!(stop, Stop::Software { address, .. } if Some(address) == self.loader_hook) {
                if self.loader_rendezvous().is_none_or(|(_, state)| state == 0) {
                    self.with_frozen(|live| live.refresh_pending_points())?;
                }
                self.resume(tid)?;
                continue;
            }
            if !self.handled_stops.contains(&tid) {
                let identity = self.identity(tid)?;
                let mut handled = true;
                let new_events: Vec<_> = match stop {
                    Stop::Software { address, .. } => self
                        .points
                        .iter()
                        .filter(|(_, p)| {
                            p.active
                                && p.kind == Kind::Software
                                && p.address == address
                                && p.thread.is_none_or(|thread| thread == (tid, identity))
                        })
                        .map(|(&id, _)| Event::Breakpoint {
                            tid,
                            id,
                            address,
                            watch: None,
                        })
                        .collect(),
                    Stop::Breakpoint { slots, address, .. } => {
                        let (hits, stepped) = self.hardware_hits(tid, slots, address)?;
                        // A real signal or breakpoint can interrupt the ARM watch step.
                        handled = !stepped
                            || matches!(
                                self.trace.threads.get(&tid).and_then(|thread| thread.stop),
                                Some(Stop::Step)
                            );
                        hits
                    }
                    Stop::Syscall => {
                        let catches = [
                            self.syscall_catches.get(&Some(tid)),
                            self.syscall_catches.get(&None),
                        ];
                        super::syscalls::read_stop(tid, &mut self.syscall_entries, catches)?
                            .into_iter()
                            .map(|row| Event::Syscall { tid, row })
                            .collect()
                    }
                    Stop::Delivery(signal) => {
                        let fault = matches!(
                            signal,
                            Signal::SIGSEGV | Signal::SIGILL | Signal::SIGBUS | Signal::SIGFPE
                        )
                        .then(|| {
                            ptrace::getsiginfo(Pid::from_raw(tid))
                                .ok()
                                .filter(|info| info.si_code > 0)
                                .map(|info| unsafe { info.si_addr() } as u64)
                        })
                        .flatten();
                        vec![Event::Signal {
                            tid,
                            number: signal as i32,
                            fault,
                            callback: signals.contains(&(signal as i32)),
                        }]
                    }
                    Stop::UnnamedDelivery(number) => {
                        vec![Event::Signal {
                            tid,
                            number,
                            fault: None,
                            callback: signals.contains(&number),
                        }]
                    }
                    _ => Vec::new(),
                };
                if handled {
                    self.handled_stops.insert(tid);
                }
                if !new_events.is_empty() {
                    if matches!(stop, Stop::Software { .. }) {
                        self.trace.rewind_software_stops()?;
                    }
                    let callbacks = new_events.iter().any(|event| {
                        !matches!(
                            event,
                            Event::Signal {
                                callback: false,
                                ..
                            }
                        )
                    });
                    events.extend(new_events);
                    if callbacks {
                        self.callbacks.insert(tid);
                    } else {
                        self.paused.insert(tid);
                    }
                    continue;
                }
            }
            if !self.paused.contains(&tid) && !self.traced(tid) {
                self.resume(tid)?;
            }
        }
        if let Some(tid) = self.next_software_thread() {
            let new_events = self.observe_instruction(tid)?;
            if !new_events.is_empty() {
                self.callbacks.insert(tid);
                events.extend(new_events);
            }
        }
        Ok(events)
    }

    fn hardware_hits(
        &mut self,
        tid: i32,
        slots: u64,
        address: Option<u64>,
    ) -> Result<(Vec<Event>, bool)> {
        let points: Vec<_> = self
            .slots(tid)
            .into_iter()
            .enumerate()
            .filter(|(index, (_, point))| {
                if cfg!(target_arch = "x86_64") {
                    slots & (1 << index) != 0
                } else {
                    address.is_some_and(|at| match point.kind {
                        Kind::Watch { length, .. } => at
                            .checked_sub(point.address)
                            .is_some_and(|offset| offset < length as u64),
                        _ => at == point.address,
                    })
                }
            })
            .map(|(_, point)| point)
            .collect();
        let mut hits: Vec<_> = points
            .into_iter()
            .map(|(id, point)| {
                let watch = match point.kind {
                    Kind::Watch { length, access } if cfg!(target_arch = "aarch64") => {
                        Some(WatchHit::new(length, access, None, None))
                    }
                    Kind::Watch { length, access } => {
                        Some(self.watch_hit(id, point.address, length, access))
                    }
                    _ => None,
                };
                Event::Breakpoint {
                    tid,
                    id,
                    address: point.address,
                    watch,
                }
            })
            .collect();
        let step = cfg!(target_arch = "aarch64")
            && hits
                .iter()
                .any(|hit| matches!(hit, Event::Breakpoint { watch: Some(_), .. }));
        if step {
            self.with_frozen(|live| {
                // ARM reports the watched instruction before it accesses memory.
                for hit in &mut hits {
                    if let Event::Breakpoint {
                        address,
                        watch: Some(watch),
                        ..
                    } = hit
                    {
                        watch.before = live.trace.read_word(*address, watch.length).ok();
                    }
                }
                breakpoint::disarm(tid)?;
                let stopped = live.trace.step_one(tid, Instant::now() + DEADLINE);
                if live
                    .trace
                    .threads
                    .get(&tid)
                    .is_some_and(|thread| thread.stop.is_some())
                    && !live.trace.exec_observed()
                {
                    live.program(tid)?;
                }
                if matches!(stopped?, Some(Stop::Step)) {
                    for hit in &mut hits {
                        if let Event::Breakpoint {
                            address,
                            watch: Some(watch),
                            ..
                        } = hit
                        {
                            watch.after = live.trace.read_word(*address, watch.length).ok();
                            if watch.access.is_none()
                                && watch.before.zip(watch.after).is_some_and(|(a, b)| a != b)
                            {
                                watch.access = Some("write");
                            }
                        }
                    }
                }
                Ok(())
            })?;
        }
        Ok((hits, step))
    }

    fn watch_hit(
        &mut self,
        id: u32,
        address: u64,
        length: usize,
        configured: WatchAccess,
    ) -> WatchHit {
        let current = self.trace.read_word(address, length).ok();
        let before = self.watch_values.get(&id).copied();
        if let Some(value) = current {
            self.watch_values.insert(id, value);
        }
        WatchHit::new(length, configured, before, current)
    }

    fn traced(&self, tid: i32) -> bool {
        self.branch_record.contains_key(&tid)
            || self.points.values().any(|p| {
                p.active
                    && p.software_watch
                    && p.thread.is_none_or(|(target, identity)| {
                        target == tid && self.trace.threads[&tid].identity == identity
                    })
            })
    }

    fn next_software_thread(&mut self) -> Option<i32> {
        let eligible = |&&tid: &&i32| {
            !self.paused.contains(&tid)
                && !self.callbacks.contains(&tid)
                && !self.trace.stepping(tid)
                && self.traced(tid)
        };
        let threads = self.trace.threads.keys();
        let tid = threads
            .clone()
            .filter(eligible)
            .copied()
            .find(|&tid| tid > self.last_software_tid)
            .or_else(|| threads.filter(eligible).copied().next())?;
        self.last_software_tid = tid;
        Some(tid)
    }

    fn observe_instruction(&mut self, tid: i32) -> Result<Vec<Event>> {
        self.with_frozen(|live| {
            let stop = live.trace.threads[&tid].stop;
            let deadline = Instant::now() + DEADLINE;
            // Give pending delivery and hardware stops their normal event handling.
            if !matches!(
                stop,
                Some(Stop::Interrupt | Stop::Step | Stop::ExecBoundary)
            ) {
                if live.handled_stops.contains(&tid) {
                    live.resume(tid)?;
                }
                return Ok(Vec::new());
            }
            let state = regs::read(tid)?;
            let pc = state.stack.get(regs::PC)?;
            let decoded = super::instruction::decode(&live.trace,pc,&state).ok();
            let identity = live.identity(tid)?;
            let watched: Vec<_> = live
                .points
                .iter()
                .filter(|(_, p)| {
                    p.active && p.software_watch
                        && p.thread.is_none_or(|target| target == (tid, identity))
                })
                .filter_map(|(&id, p)| {
                    let Kind::Watch { length, access } = p.kind else { return None; };
                    Some((id,p.address,length,access,live.trace.read_word(p.address,length).ok()?))
                })
                .collect();
            let stop = live.trace.step_one(tid, deadline);
            live.handled_stops.remove(&tid);
            if live.trace.stepping(tid) && Instant::now() >= deadline { return Ok(Vec::new()); }
            if !matches!(stop?,Some(Stop::Step)) { return Ok(Vec::new()); }
            if let Some((_,all)) = live.branch_record.get(&tid)
                && let Some(insn) = &decoded
                && branch_instruction(&insn.mnemonic)
                && let Ok(next) = regs::read(tid).and_then(|reg| reg.stack.get(regs::PC))
                && live.branches.len() < 256
            {
                let mut registers = state.general;
                if !all {
                    registers.retain(|name,_| insn.registers.contains(name)
                        || matches!(name.as_str(),"rip"|"pc"|"eflags"|"pstate"));
                }
                live.branches.push(json!({"kind":"branch","tid":tid,"pc":hex(pc),"nextPc":hex(next),
                    "taken":next != pc + insn.length as u64,"mnemonic":insn.mnemonic,"registers":registers}));
            }
            let mut events = Vec::new();
            for (id,address,length,configured,before) in watched {
                let after = live.trace.read_word(address,length).ok();
                let memory = decoded.iter().flat_map(|insn|&insn.memory).filter(|access|access.overlaps(address,length));
                let read = memory.clone().any(|access|access.reads());
                let write = after.is_some_and(|after|after != before) || memory.clone().any(|access|access.writes());
                let access = match configured {
                    WatchAccess::Read if read => Some("read"),
                    WatchAccess::Write | WatchAccess::ReadWrite if write => Some("write"),
                    WatchAccess::ReadWrite if read => Some("read"),
                    _ => None,
                };
                if access.is_some() {
                    events.push(Event::Breakpoint {tid,id,address,watch:Some(WatchHit {length,before:Some(before),after,access})});
                }
            }
            Ok(events)
        })
    }

    pub fn take_branches(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.branches)
    }

    pub fn finish_callback(&mut self, tid: i32, pause: Option<bool>, pass: Option<bool>) {
        self.callbacks.remove(&tid);
        self.suppress.remove(&tid);
        if let Some(thread) = self.trace.threads.get_mut(&tid) {
            let signal = matches!(
                thread.stop,
                Some(Stop::Delivery(_) | Stop::UnnamedDelivery(_))
            );
            let pause = if signal && pass != Some(true) {
                pause.or(Some(true))
            } else {
                pause
            };
            match pause {
                Some(true) => {
                    self.paused.insert(tid);
                }
                Some(false) => {
                    self.paused.remove(&tid);
                }
                None => {}
            }
            if signal && pass == Some(false) {
                thread.stop = Some(Stop::Interrupt);
            }
        }
    }

    fn close(&mut self) -> Result<()> {
        self.close_with_signal_delivery(true)
    }

    pub(super) fn kill_and_detach(&mut self, signal: i32) -> Result<bool> {
        self.verify()?;
        let fd = Errno::result(unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid, 0) })?;
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        self.verify()?;
        let cleanup = self.close_with_signal_delivery(false);
        let delivery = Errno::result(unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        });
        match delivery {
            Err(Errno::ESRCH) => cleanup.map(|()| true),
            Ok(_) => {
                cleanup?;
                let mut poll = libc::pollfd {
                    fd: pidfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // The process descriptor becomes readable once termination is confirmed.
                let timeout = if signal == libc::SIGKILL { 100 } else { 0 };
                Ok(unsafe { libc::poll(&mut poll, 1, timeout) } > 0
                    && poll.revents & libc::POLLIN != 0)
            }
            Err(issue) => Err(issue.into()),
        }
    }

    fn close_with_signal_delivery(&mut self, deliver_signals: bool) -> Result<()> {
        self.release_scratch();
        let cleanup = self.trace.close_with_signal_delivery(deliver_signals);
        if self.launched {
            let pid = Pid::from_raw(self.pid);
            if self.trace.exit.is_none() {
                let mut stdio = self.stdio.take();
                if let Some(io) = &mut stdio {
                    let _ = io.drain();
                    self.stdio = Some(io.archive_output());
                }
                let _ = thread::Builder::new()
                    .name("aidbg-reap".into())
                    .spawn(move || {
                        use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
                        if let Some(io) = &mut stdio {
                            io.close_input();
                            while matches!(
                                waitpid(pid, Some(WaitPidFlag::WNOHANG)),
                                Ok(WaitStatus::StillAlive) | Err(Errno::EINTR)
                            ) {
                                let _ = io.drain();
                                thread::sleep(Duration::from_millis(20));
                            }
                        } else {
                            while matches!(waitpid(pid, None), Err(Errno::EINTR)) {}
                        }
                    });
            }
            self.launched = false;
        }
        if cleanup.ok() {
            Ok(())
        } else {
            Err(error(format!(
                "ptrace cleanup: {}",
                serde_json::to_string(&cleanup)?
            )))
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Target {
    pub fn open(args: OpenCoreRequest) -> Result<(Self, Value)> {
        let path = Path::new(&args.path);
        if !path.is_absolute() {
            return Err(error("core_open requires an absolute server path"));
        }
        let core = core::open_path(path)?;
        let (target, info) = Core::open(
            "session-core".into(),
            core,
            CoreSymbols {
                executable: args.executable.map(PathBuf::from),
                debug_symbols: args.debug_symbols.map(PathBuf::from),
            },
            true,
        )?;
        Ok((Self::Core(Box::new(target)), serde_json::to_value(info)?))
    }

    pub fn live(&mut self) -> Result<&mut Live> {
        match self {
            Self::Live(live) => Ok(live),
            Self::Core(_) => Err(error("NotSupport: operation requires a live target")),
        }
    }

    fn pid(&self) -> i32 {
        match self {
            Self::Live(live) => live.pid,
            Self::Core(core) => core.session_pid(),
        }
    }

    pub fn snapshot(
        &mut self,
        tid: Option<i32>,
        context: bool,
        stop_timeout_ms: u32,
        limit: usize,
        thread_limit: Option<usize>,
    ) -> Result<Value> {
        if stop_timeout_ms > 1000 || !(1..=64).contains(&limit) {
            return Err(error(
                "snapshot requires a stop budget of 0..=1000 ms and a frame limit of 1..=64",
            ));
        }
        match self {
            Self::Live(live) => live.snapshot(tid, context, stop_timeout_ms, limit, thread_limit),
            Self::Core(core) => {
                let tids: Vec<_> = match tid {
                    Some(tid) => vec![tid],
                    None => serde_json::from_value::<Vec<ThreadId>>(core.threads())?
                        .into_iter()
                        .map(|row| row.tid)
                        .collect(),
                };
                let mut threads = Vec::new();
                let thread_count = tids.len();
                for tid in tids.into_iter().take(thread_limit.unwrap_or(usize::MAX)) {
                    let frames = core.session_frames(tid, limit)?;
                    let locals = flatten_frame_values(&frames[0]);
                    threads.push(json!({"tid":tid,"registers":core.session_registers(tid,false)?,"frames":frames,"locals":locals}));
                }
                let mut snapshot = json!({"timestamp":procfs::epoch_ms(), "threads":threads,
                    "mappings":core.session_mappings(), "threadCount":thread_count,
                    "consistency":if tid.is_some() { "thread" } else { "all-stopped" }});
                if thread_limit.is_some() {
                    snapshot["frameLimit"] = json!(limit);
                }
                if let Some(limit) = thread_limit
                    && thread_count > limit
                {
                    snapshot["threadsOmitted"] = json!(thread_count - limit);
                }
                Ok(snapshot)
            }
        }
    }

    pub fn read(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        if length > MAX_MEMORY || address.checked_add(length as u64).is_none() {
            return Err(error("memory access exceeds the maximum range"));
        }
        let mut bytes = vec![0; length];
        if bytes.is_empty() {
            return Ok(bytes);
        }
        match self {
            Self::Live(live) => {
                live.verify()?;
                live.trace.read_memory(address, &mut bytes)?;
            }
            Self::Core(core) => core.read_at(address, &mut bytes)?,
        }
        Ok(bytes)
    }

    pub fn read_prefix(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; length];
        let count = match self {
            Self::Live(live) => {
                live.verify()?;
                read_process_prefix(live.pid, address, &mut bytes, || true)?
            }
            Self::Core(core) => core.read_prefix(address, &mut bytes)?,
        };
        bytes.truncate(count);
        Ok(bytes)
    }

    pub fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        let live = self.live()?;
        live.verify()?;
        if bytes.is_empty() {
            return Ok(());
        }
        live.trace.write_memory(address, bytes)
    }

    fn symbols(&self, pattern: &str, mode: SymbolMatch, limit: u32) -> Result<Value> {
        let report = match self {
            Self::Live(live) => {
                live.verify()?;
                serde_json::to_value(symbols::search(live.pid, pattern, mode, None, limit, &[])?)?
            }
            Self::Core(core) => core.symbols(&SearchSymbolsRequest {
                pattern: pattern.into(),
                match_mode: mode as i32,
                limit: Some(limit),
                ..Default::default()
            })?,
        };
        let mut rows:Vec<_> = report["matches"].as_array().into_iter().flatten().map(|item| json!({
            "name":item["name"],"demangledName":item["demangled_name"],
            "address":item["runtime_address"],"size":item["size"],"module":item["module"]["path"]
        })).collect();
        if let Self::Live(live) = self {
            let matcher = symbols::Matcher::new(mode, pattern)?;
            rows.extend(
                live.linked
                    .iter()
                    .flat_map(|(_, symbols)| symbols)
                    .filter(|symbol| {
                        let name = symbol["name"].as_str().unwrap_or_default();
                        matcher.matches(name)
                    })
                    .cloned(),
            );
        }
        rows.truncate(limit as usize);
        Ok(json!(rows))
    }

    fn address(&self, arg: &Value) -> Result<u64> {
        match arg.as_str() {
            Some(text) if text.starts_with("0x") => parse_address(arg),
            Some(text) => {
                let matches = self.symbols(text, SymbolMatch::Exact, 2)?;
                let matches = matches.as_array().unwrap();
                match matches.as_slice() {
                    [symbol] => parse_address(&symbol["address"]),
                    [] => Err(error(format!("symbol {text} was not found"))),
                    _ => Err(error(format!("symbol {text} is ambiguous"))),
                }
            }
            None => Err(error("expected an address or symbol name")),
        }
    }

    fn source_location(&self, address: u64) -> Result<Value> {
        let resolved = match self {
            Self::Live(live) => {
                live.verify()?;
                if let Some(source) = live.attached_source(address)? {
                    return Ok(json!({"file":source.file,"line":source.line}));
                }
                serde_json::to_value(symbols::resolve(live.pid, address, &[])?)?
            }
            Self::Core(core) => core.resolve(address)?,
        };
        match (
            resolved["source_line"]["file"].as_str(),
            resolved["source_line"]["line"].as_u64(),
        ) {
            (Some(file), Some(line)) => Ok(json!({"file":file,"line":line})),
            _ => Ok(Value::Null),
        }
    }

    fn disassemble(&self, address: u64, count: usize) -> Result<Value> {
        if !(1..=128).contains(&count) {
            return Err(error("instruction count must be in 1..=128"));
        }
        let live = match self {
            Self::Live(live) => live,
            Self::Core(core) => {
                let result = core.disassemble(&crate::rpc::DisassembleRequest {
                    address,
                    start: Some(address),
                    before: Some(0),
                    after: Some(count as u32 - 1),
                    ..Default::default()
                })?;
                let window = serde_json::to_value(result)?;
                let (_, width) = disassembly::decoder(regs::ARCH)?;
                let code = self.read_prefix(address, width as usize * count)?;
                let targets = disassembly::instruction_targets(regs::ARCH, address, &code)?;
                return Ok(json!(
                    window["instructions"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(
                            |insn| json!({"address":insn["address"], "bytes":insn["bytes"],
                        "mnemonic":insn["mnemonic"].as_str().unwrap_or_default(),
                        "opStr":insn["operands"].as_str().unwrap_or_default(),
                        "references":parse_address(&insn["address"]).ok()
                            .and_then(|address| targets.get(&address)).map_or(&[][..],Vec::as_slice)})
                        )
                        .collect::<Vec<_>>()
                ));
            }
        };
        let (decoder, width) = disassembly::decoder(regs::ARCH)?;
        live.verify()?;
        let mut bytes = vec![0; width as usize * count];
        let got = live.trace.read_code_prefix(address, &mut bytes)?;
        bytes.truncate(got);
        let mut targets = disassembly::instruction_targets(regs::ARCH, address, &bytes)?;
        if !targets.is_empty()
            && let Some(imports) = symbols::runtime_imports(live.pid, address)
            && !imports.slots.is_empty()
        {
            live.annotate_imports(&mut targets, &imports);
        }
        let instructions = decoder
            .disasm_count(&bytes, address, count)
            .map_err(|e| error(e.to_string()))?;
        Ok(json!(
            instructions
                .iter()
                .map(
                    |insn| json!({"address":hex(insn.address()),"bytes":insn.bytes(),
            "mnemonic":insn.mnemonic().unwrap_or(""),"opStr":insn.op_str().unwrap_or(""),
            "references": targets.get(&insn.address()).map_or(&[][..], Vec::as_slice)})
                )
                .collect::<Vec<_>>()
        ))
    }

    pub fn operation(
        &mut self,
        op: &str,
        args: Value,
        state_dir: &Path,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Value> {
        let tid = || -> Result<i32> {
            Ok(i32::try_from(
                args["tid"]
                    .as_i64()
                    .ok_or_else(|| error("expected a thread ID"))?,
            )?)
        };
        let selector = || -> Result<Option<i32>> {
            if args["tid"] == "all" {
                Ok(None)
            } else {
                tid().map(Some)
            }
        };
        match op {
            "pid" => Ok(json!(self.pid())),
            "threads" => match self {
                Self::Live(live) => {
                    live.verify()?;
                    Ok(json!(live.tids()))
                }
                Self::Core(core) => Ok(json!(
                    core.threads()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|row| &row["tid"])
                        .collect::<Vec<_>>()
                )),
            },
            "identity" => match self {
                Self::Live(live) => Ok(json!(live.identity(tid()?)?.to_string())),
                Self::Core(core) => {
                    let tid = tid()?;
                    if core
                        .threads()
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|row| row["tid"] == tid)
                    {
                        Ok(json!("core"))
                    } else {
                        Err(error("thread no longer exists"))
                    }
                }
            },
            "status" => match self {
                Self::Core(_) => Ok(json!("S")),
                Self::Live(live) => {
                    let state = procfs::Status::read(&procfs::task_path(&live.root, tid()?))
                        .ok()
                        .and_then(|status| status.state());
                    Ok(json!(match state.as_deref() {
                        Some("R") => "R",
                        Some("D") => "D",
                        Some("Z" | "X") | None => "Unexists",
                        _ => "S",
                    }))
                }
            },
            "mappings" => match self {
                Self::Live(live) => live.mappings(),
                Self::Core(core) => Ok(core.session_mappings()),
            },
            "dataAt" => {
                let address = parse_address(&args["address"])?;
                let Self::Live(live) = self else {
                    return Ok(Value::Null);
                };
                live.verify()?;
                let Some(hit) = symbols::symbol_at(live.pid, address)? else {
                    return Ok(Value::Null);
                };
                Ok(json!(symbols::inspect::live_data_at(
                    &live.root,
                    &live.trace,
                    address,
                    &hit,
                    Instant::now() + Duration::from_millis(200),
                )))
            }
            "symbolAt" => {
                let address = parse_address(&args["address"])?;
                match self {
                    Self::Live(live) => {
                        live.verify()?;
                        Ok(json!(symbols::symbol_at(live.pid, address)?))
                    }
                    Self::Core(core) => Ok(json!(core.symbol_at(address))),
                }
            }
            "snapshot" => self.snapshot(
                args["tid"].as_i64().map(i32::try_from).transpose()?,
                args["context"] == true,
                u32::try_from(args["stopTimeoutMs"].as_u64().unwrap_or(1000))?,
                usize::try_from(args["frameLimit"].as_u64().unwrap_or(64))?,
                (args["presentation"] == true).then_some(32),
            ),
            "read" | "readPrefix" => {
                let length = usize::try_from(number(&args, "length")?)?;
                let address = parse_address(&args["address"])?;
                if length > MAX_MEMORY || address.checked_add(length as u64).is_none() {
                    return Err(error("memory read exceeds the maximum range"));
                }
                let result = if op == "read" {
                    self.read(address, length)
                } else {
                    self.read_prefix(address, length)
                };
                match result {
                    Ok(bytes) => Ok(json!(bytes)),
                    Err(err) if args["format"] == true => {
                        if let Self::Live(live) = self {
                            live.verify()?;
                        }
                        let local = err.is::<crate::unwind::MissingMemory>()
                            || err.downcast_ref::<nix::errno::Errno>().is_some_and(|code| {
                                matches!(*code, nix::errno::Errno::EFAULT | nix::errno::Errno::EIO)
                            })
                            || err
                                .downcast_ref::<crate::Diagnostic>()
                                .is_some_and(|diagnostic| diagnostic.code == "CORE_MEMORY_MISSING");
                        let message = err.to_string();
                        if local || message.starts_with("short remote read:") {
                            Ok(json!({"unreadable":message}))
                        } else {
                            Err(err)
                        }
                    }
                    Err(err) => Err(err),
                }
            }
            "xref" => {
                let address = |key: &str| args.get(key).map(parse_address).transpose();
                let optional_u32 = |key: &str| serde_json::from_value(args[key].clone());
                let request = SearchMemoryRequest {
                    pointer_value: Some(parse_address(&args["address"])?),
                    start: address("start")?,
                    end: address("end")?,
                    resume_from: address("resumeFrom")?,
                    instruction_references: args["instructionReferences"] == true,
                    alignment: optional_u32("alignment")?,
                    limit: optional_u32("limit")?,
                    max_scan_bytes: optional_u32("maxScanBytes")?,
                    ..Default::default()
                };
                match self {
                    Self::Live(live) => {
                        live.verify()?;
                        core::memory::search_live(live.pid, &request)
                    }
                    Self::Core(core) => core.search_memory(&request),
                }
            }
            "write" => {
                let bytes = serde_json::from_value::<Vec<u8>>(args["bytes"].clone())?;
                if bytes.len() > MAX_MEMORY {
                    return Err(error("memory write exceeds the maximum range"));
                }
                self.write(parse_address(&args["address"])?, &bytes)?;
                Ok(Value::Null)
            }
            "registers" => match self {
                Self::Live(live) => {
                    live.with_stopped(tid()?, |_| regs::api_read(tid()?, args["full"] == true))
                }
                Self::Core(core) => core.session_registers(tid()?, args["full"] == true),
            },
            "writeRegisters" => {
                self.live()?
                    .with_stopped(tid()?, |_| regs::api_write(tid()?, &args["values"]))?;
                Ok(Value::Null)
            }
            "backtrace" => {
                let tid = tid()?;
                let limit = args["limit"].as_u64().unwrap_or(64).min(1024) as usize;
                match self {
                    Self::Live(live) => {
                        live.with_stopped(tid, |live| Ok(json!(live.frames(tid, limit)?)))
                    }
                    Self::Core(core) => core.session_frames(tid, limit),
                }
            }
            "locals" => match self {
                Self::Live(live) => {
                    let tid = tid()?;
                    live.with_stopped(tid, |live| {
                        let values =
                            live.frame_values(regs::read(tid)?.stack, Instant::now() + DEADLINE)?;
                        Ok(json!(flatten_frame_values(&values)))
                    })
                }
                Self::Core(core) => Ok(json!(flatten_frame_values(
                    &core.session_top_values(tid()?, Instant::now() + DEADLINE)?
                ))),
            },
            "eval" => {
                let text = args["expr"]
                    .as_str()
                    .ok_or_else(|| error("expected expression"))?;
                let tid = tid()?;
                if let Some((name, arguments)) = inferior_expression(text) {
                    return self.evaluate_call(tid, name, &arguments);
                }
                let report = match self {
                    Self::Live(live) => {
                        live.with_stopped(tid, |live| live.evaluate(tid, text.into()))?
                    }
                    Self::Core(core) => core.inspect(
                        text,
                        &format!("session-core:{tid}:0"),
                        Instant::now() + DEADLINE,
                        None,
                    ),
                };
                evaluation(report)
            }
            "typeOfVar" => {
                let name = args["name"]
                    .as_str()
                    .filter(|name| !name.is_empty() && name.len() <= 1024)
                    .ok_or_else(|| error("expected a variable name"))?;
                let tid = if args["tid"].is_null() {
                    self.pid()
                } else {
                    tid()?
                };
                let deadline = Instant::now() + DEADLINE;
                let graph = match self {
                    Self::Live(live) => live.with_stopped(tid, |live| {
                        let registers = regs::read(tid)?.stack;
                        let pc = registers.get(regs::PC)?;
                        for attached in live.dwarf.iter().rev() {
                            if let Some(link) = attached.link_address(pc)
                                && let Some(graph) = attached.image.variable_type_graph(
                                    name,
                                    Some(link),
                                    deadline,
                                )?
                            {
                                return Ok(Some(graph));
                            }
                        }
                        symbols::inspect::variable_type_at_pc(&live.root, pc, name, deadline)
                    }),
                    Self::Core(core) => core.session_variable_type(tid, name, deadline),
                };
                match graph {
                    Ok(graph) => Ok(json!({"graph":graph})),
                    Err(err) if symbols::inspect::variable_query_limited(err.as_ref()) => {
                        Ok(json!({"diagnostic": format!("typeOfVar({name}): {err}")}))
                    }
                    Err(err) => Err(err),
                }
            }
            "pause" => Ok(json!(self.live()?.pause(selector()?)?)),
            "continue" => {
                self.live()?.continue_threads(selector()?)?;
                Ok(Value::Null)
            }
            "catchSyscall" => {
                let scope = selector()?;
                let live = self.live()?;
                let update = |live: &mut Live| {
                    if args["phase"].is_null() {
                        live.syscall_catches.remove(&scope);
                        if let Some(tid) = scope {
                            live.trace.syscall_threads.remove(&tid);
                            if !live.trace.syscall_all {
                                live.syscall_entries.remove(&tid);
                            }
                        } else {
                            live.trace.syscall_all = false;
                            live.syscall_entries
                                .retain(|tid, _| live.trace.syscall_threads.contains(tid));
                        }
                    } else {
                        let catch = super::syscalls::Catch::parse(&args)?;
                        if live.syscall_catches.is_empty() {
                            super::syscalls::verify_supported(scope.unwrap_or(live.pid))?;
                        }
                        live.syscall_catches.insert(scope, catch);
                        if let Some(tid) = scope {
                            live.trace.syscall_threads.insert(tid);
                        } else {
                            live.trace.syscall_all = true;
                        }
                    }
                    Ok(Value::Null)
                };
                match scope {
                    Some(tid) => live.with_stopped(tid, update),
                    None => live.with_frozen(update),
                }
            }
            "detach" => {
                self.live()?.close()?;
                Ok(Value::Null)
            }
            "syscall" => {
                let number = parse_address(&args["number"])?;
                let words = args["args"]
                    .as_array()
                    .ok_or_else(|| error("expected syscall arguments"))?
                    .iter()
                    .map(parse_address)
                    .collect::<Result<Vec<_>>>()?;
                let result = self.live()?.syscall(tid()?, number, &words)?;
                Ok(json!([(result as i64).to_string()]))
            }
            "stdio" => {
                let live = self.live()?;
                let io = live.stdio.as_mut().ok_or_else(|| {
                    error("NotSupport: process I/O is only available for launched targets")
                })?;
                Ok(match args["operation"].as_str() {
                    Some("stdout") => io.read(0),
                    Some("stderr") => io.read(1),
                    Some("combined") => io.read(2),
                    Some("write") => json!(
                        io.write(
                            args["data"]
                                .as_str()
                                .ok_or_else(|| error("stdin accepts a string"))?
                        )?
                    ),
                    Some("close") => {
                        io.close_input();
                        Value::Null
                    }
                    _ => return Err(error("unknown process I/O operation")),
                })
            }
            "prepareScratchPad" => {
                self.live()?.prepare_scratch(None)?;
                Ok(Value::Null)
            }
            "allocate" | "free" | "protect" => self.live()?.memory_operation(tid()?, op, &args),
            "call" => self.live()?.call(tid()?, &args),
            "prepare" => {
                if let Self::Live(live) = self {
                    live.verify()?;
                    symbols::inspect::warm_dwarf(live.pid);
                    live.prepare_scratch(None)?;
                }
                Ok(Value::Null)
            }
            "lineToAddr" => {
                let file = Path::new(
                    args["file"]
                        .as_str()
                        .ok_or_else(|| error("expected a source path"))?,
                );
                let line = number(&args, "line")?;
                if file.as_os_str().is_empty() || file.as_os_str().len() > 4096 || line == 0 {
                    return Err(error("expected a source path and a positive line number"));
                }
                let address = match self {
                    Self::Live(live) => {
                        live.verify()?;
                        let mut attached_addresses = BTreeSet::new();
                        for attached in &live.dwarf {
                            for link in attached.image.line_addresses(file, line)? {
                                attached_addresses.extend(attached.runtime_address(link));
                            }
                        }
                        if !attached_addresses.is_empty() {
                            return Ok(json!(
                                (attached_addresses.len() == 1)
                                    .then(|| hex(*attached_addresses.first().unwrap()))
                            ));
                        }
                        match symbols::breakpoint_line(&live.root, file, line, None, None) {
                            Ok(site) => Some(site.address),
                            Err(err)
                                if err.downcast_ref::<crate::Diagnostic>().is_some_and(
                                    |diagnostic| diagnostic.code == "LINE_UNAVAILABLE",
                                ) =>
                            {
                                None
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    Self::Core(core) => core.script_line_address(file, line)?,
                };
                Ok(json!(address.map(hex)))
            }
            "addrToLine" => self.source_location(parse_address(&args["address"])?),
            "listSource" => {
                let radius = args["radius"].as_u64().unwrap_or(5);
                if radius > 50 {
                    return Err(error("source context must be between 0 and 50 lines"));
                }
                list_source(
                    self.source_location(parse_address(&args["address"])?)?,
                    radius,
                    args["sourcePaths"].as_array().map_or(&[], Vec::as_slice),
                )
            }
            "address" => Ok(json!(hex(self.address(&args["at"])?))),
            "symbolPage" => {
                let cursor = if args["cursor"].is_null() {
                    symbols::script_page::Cursor::default()
                } else {
                    serde_json::from_value(args["cursor"].clone())?
                };
                let (items, next) = match self {
                    Self::Live(live) => {
                        live.verify()?;
                        symbols::script_page::live(live.pid, cursor)?
                    }
                    Self::Core(core) => core.script_symbols(cursor)?,
                };
                Ok(json!({"items":items,"next":next}))
            }
            "linkedSymbols" => Ok(match self {
                Self::Live(live) => {
                    live.verify()?;
                    json!(
                        live.linked
                            .iter()
                            .flat_map(|(_, symbols)| symbols)
                            .collect::<Vec<_>>()
                    )
                }
                Self::Core(_) => json!([]),
            }),
            "symbols" => {
                let pattern = args["pattern"]
                    .as_str()
                    .ok_or_else(|| error("expected symbol pattern"))?;
                let exact = self.symbols(pattern, SymbolMatch::Exact, 1)?;
                if exact.as_array().is_some_and(|rows| !rows.is_empty()) {
                    return Ok(exact);
                }
                for mode in [SymbolMatch::CppSignature, SymbolMatch::CppName] {
                    let found = self.symbols(pattern, mode, 2)?;
                    match found.as_array().map_or(0, Vec::len) {
                        0 => {}
                        1 => return Ok(found),
                        _ => {
                            return Err(error(format!(
                                "symbol {pattern} is ambiguous; use a full C++ signature or a mangled name"
                            )));
                        }
                    }
                }
                Ok(exact)
            }
            "disassemble" => self.disassemble(
                self.address(&args["at"])?,
                args["count"].as_u64().unwrap_or(16) as usize,
            ),
            "assemble" => Ok(serde_json::to_value(code::assemble(
                self.address(&args["at"])?,
                args["src"]
                    .as_str()
                    .ok_or_else(|| error("expected assembly source"))?,
            )?)?),
            "addPoint" => {
                let address = self.address(&args["at"])?;
                self.live()?.add_point(
                    number(&args, "id")? as u32,
                    args["kind"].as_str().unwrap_or_default(),
                    address,
                    &args,
                )?;
                Ok(json!(hex(address)))
            }
            "point" => {
                let live = self.live()?;
                let id = number(&args, "id")? as u32;
                let remove = args["remove"] == true;
                let enable = args["enable"] == true;
                if live.pending_points.contains_key(&id) {
                    if !enable && live.points.contains_key(&id) {
                        live.update_point(id, None)?;
                    }
                    if remove {
                        live.pending_points.remove(&id);
                    } else {
                        let pending = live.pending_points.get_mut(&id).unwrap();
                        pending.enabled = enable;
                        if !enable {
                            pending.site = None;
                        } else {
                            live.refresh_pending_points()?;
                        }
                    }
                    return Ok(Value::Null);
                }
                let existing = live
                    .points
                    .get(&id)
                    .copied()
                    .ok_or_else(|| error("breakpoint no longer exists"))?;
                if enable
                    && !existing.active
                    && existing.kind == Kind::Software
                    && live.points.values().any(|point| {
                        point.active
                            && point.address == existing.address
                            && point.kind == Kind::Software
                    })
                {
                    return Err(error(
                        "a software breakpoint is already installed at this address",
                    ));
                }
                live.update_point(
                    id,
                    (!remove).then_some(Point {
                        active: enable,
                        ..existing
                    }),
                )?;
                Ok(Value::Null)
            }
            "addPendingPoint" => {
                let live = self.live()?;
                let id = u32::try_from(number(&args, "id")?)?;
                let name = args["name"]
                    .as_str()
                    .filter(|name| !name.is_empty() && name.len() <= 1024)
                    .ok_or_else(|| error("expected a symbol name of up to 1024 bytes"))?;
                let module = serde_json::from_value(args["module"].clone())?;
                live.pending_points.insert(
                    id,
                    PendingPoint {
                        name: name.to_owned(),
                        module,
                        site: None,
                        enabled: true,
                    },
                );
                if let Err(issue) = live
                    .install_loader_hook()
                    .and_then(|()| live.refresh_pending_points())
                {
                    live.pending_points.remove(&id);
                    return Err(issue);
                }
                Ok(Value::Null)
            }
            "pendingPointAddress" => {
                let live = self.live()?;
                let id = u32::try_from(number(&args, "id")?)?;
                Ok(json!(
                    live.pending_points
                        .get(&id)
                        .and_then(|point| point.site.as_ref())
                        .map(|site| hex(site.address))
                ))
            }
            "step" => {
                let live = self.live()?;
                let tid = tid()?;
                live.stop_sequences.remove(&tid);
                live.step(tid, &args)?;
                Ok(Value::Null)
            }
            "recordBranch" => {
                let tid = tid()?;
                let live = self.live()?;
                let identity = live.identity(tid)?;
                live.branch_record
                    .insert(tid, (identity, args["allReg"] == true));
                Ok(Value::Null)
            }
            "preventOtherStops" => {
                let tid = tid()?;
                let live = self.live()?;
                if live.callbacks.contains(&tid) {
                    live.suppress.insert(tid);
                }
                Ok(Value::Null)
            }
            "linkObjAt" => {
                if let Self::Core(_) = self {
                    return Err(error("NotSupport: linking requires a live target"));
                }
                let path = Path::new(
                    args["path"]
                        .as_str()
                        .ok_or_else(|| error("expected object file path"))?,
                );
                let base = parse_address(&args["address"])?;
                let (image, symbols) = super::link::relocate(path, base, |name| {
                    let rows = self.symbols(name, SymbolMatch::Exact, 2)?;
                    match rows.as_array().unwrap().as_slice() {
                        [] => Ok(None),
                        [symbol] => parse_address(&symbol["address"]).map(Some),
                        _ => Err(error(format!("ambiguous external object symbol {name}"))),
                    }
                })?;
                let live = self.live()?;
                let end = base + image.len() as u64;
                live.with_frozen(|live| {
                    if !modules::mapping_at(&live.root, base)?.is_some_and(|map| {
                        map.perms.as_bytes().get(1) == Some(&b'w') && end <= map.end
                    }) {
                        return Err(error(
                            "linked object must fit in one writable target mapping",
                        ));
                    }
                    live.trace.write_memory(base, &image)?;
                    live.linked
                        .retain(|(range, _)| range.end <= base || range.start >= end);
                    live.linked.push((base..end, symbols));
                    Ok(())
                })?;
                Ok(Value::Null)
            }
            "coredump" => {
                let path = Path::new(
                    args["path"]
                        .as_str()
                        .ok_or_else(|| error("expected a core output path"))?,
                );
                self.live()?.coredump(
                    path,
                    args["kind"].as_str().unwrap_or_default(),
                    state_dir,
                    cancelled,
                )?;
                Ok(Value::Null)
            }
            "attachDwarf" => {
                let file = args["file"]
                    .as_str()
                    .filter(|file| !file.is_empty())
                    .ok_or_else(|| error("expected DWARF file path"))?;
                let path = fs::canonicalize(file)?;
                let files = match self {
                    Self::Live(live) => &live.dwarf,
                    Self::Core(core) => &core.attached_dwarf,
                };
                if files.len() >= 8 && !files.iter().any(|dwarf| dwarf.image.path == path) {
                    return Err(error("too many attached DWARF files"));
                }
                let (files, dwarf) = match self {
                    Self::Live(live) => {
                        live.verify()?;
                        let dwarf = super::dwarf::AttachedDwarf::load(
                            path.clone(),
                            &args["position"],
                            |object, path| {
                                super::dwarf::infer_bias(
                                    &live.root,
                                    object,
                                    path,
                                    Instant::now() + DEADLINE,
                                )
                            },
                        )?;
                        (&mut live.dwarf, dwarf)
                    }
                    Self::Core(core) => {
                        let dwarf = super::dwarf::AttachedDwarf::load(
                            path.clone(),
                            &args["position"],
                            |object, path| core.infer_dwarf_bias(object, path),
                        )?;
                        (&mut core.attached_dwarf, dwarf)
                    }
                };
                files.retain(|dwarf| dwarf.image.path != path);
                files.push(dwarf);
                Ok(Value::Null)
            }
            "fromDwarf" => Ok(json!(
                self.resolve_dwarf_type(
                    args["name"]
                        .as_str()
                        .ok_or_else(|| error("expected DWARF type name"))?,
                )?
            )),
            "types" => {
                let offset = args["offset"].as_u64().unwrap_or(0) as usize;
                let rows = self.type_graphs(
                    args["pattern"].as_str().unwrap_or("*"),
                    args["exact"] == true,
                    args["typesOnly"] != true,
                    offset,
                    33,
                )?;
                Ok(
                    json!({"items":rows.iter().take(32).map(|(name,graph)|json!({"name":name,"module":graph.module,"size":graph.size(),"graph":graph})).collect::<Vec<_>>(),
                          "next_offset":(rows.len()>32).then_some(offset+32)}),
                )
            }
            _ => Err(error(format!("NotSupport: {op}"))),
        }
    }

    fn evaluate_call(&mut self, tid: i32, name: &str, expressions: &[&str]) -> Result<Value> {
        if matches!(self, Self::Core(_)) {
            return Err(error("NotSupport: inferior calls require a live target"));
        }
        let mut graphs = self.type_graphs(name, true, true, 0, 2)?;
        if graphs.len() != 1 {
            return Err(error(
                "inferior call requires a unique DWARF function declaration",
            ));
        }
        let graph = graphs.pop().unwrap().1;
        let (signature, returns, variadic) = graph.signature().ok_or_else(|| {
            error("NotSupport: inferior call requires scalar or pointer arguments")
        })?;
        if expressions.len() < signature.len()
            || (!variadic && expressions.len() != signature.len())
        {
            return Err(error("incorrect C argument count"));
        }
        let rows = self.symbols(name, SymbolMatch::Exact, 2)?;
        let [symbol] = rows.as_array().unwrap().as_slice() else {
            return Err(error("inferior call requires a unique function symbol"));
        };
        let live = self.live()?;
        let mut arguments = Vec::new();
        for (index, expression) in expressions.iter().enumerate() {
            let value = if let Ok(integer) = parse_c_integer(expression) {
                Value::String(integer.to_string())
            } else if let Ok(float) = expression.parse::<f64>() {
                json!(float)
            } else {
                live.with_stopped(tid, |live| {
                    evaluation(live.evaluate(tid, (*expression).into())?)
                })?["value"]
                    .clone()
            };
            let kind =
                signature
                    .get(index)
                    .copied()
                    .unwrap_or(if value.is_f64() { "f64" } else { "i32" });
            let bytes = encode_scalar(kind, &value)?;
            arguments.push(json!({"kind":kind,"bytes":bytes}));
        }
        let result = live.call(
            tid,
            &json!({"address":symbol["address"],"args":arguments,"returns":returns,
            "fixed":signature.len(),"variadic":variadic}),
        )?;
        let mut bytes = [0; 8];
        let raw: Vec<u8> = serde_json::from_value(result)?;
        bytes[..raw.len()].copy_from_slice(&raw);
        let value = decode_scalar(returns, bytes);
        Ok(
            json!({"type":returns,"value":value,"text":value.as_str().map_or_else(||value.to_string(),str::to_owned)}),
        )
    }

    pub fn type_graphs(
        &self,
        pattern: &str,
        exact: bool,
        include_functions: bool,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<(String, symbols::inspect::type_graph::Graph)>> {
        if limit == 0 || offset > 200_000 || pattern.len() > 1024 {
            return Err(error("invalid DWARF query bounds"));
        }
        let deadline = Instant::now() + DEADLINE;
        match self {
            Self::Core(core) => {
                core.session_types(pattern, exact, include_functions, offset, limit, deadline)
            }
            Self::Live(live) => {
                live.verify()?;
                let mut rows = Vec::new();
                let mut skip = offset;
                for attached in live.dwarf.iter().rev() {
                    let (items, scanned) = attached.image.type_graphs(
                        pattern,
                        exact,
                        include_functions,
                        skip,
                        limit - rows.len(),
                        deadline,
                    )?;
                    rows.extend(items);
                    if rows.len() >= limit {
                        return Ok(rows);
                    }
                    skip = skip.saturating_sub(scanned);
                }
                rows.extend(symbols::inspect::type_graph::live_type_graphs(
                    &live.root,
                    pattern,
                    exact,
                    include_functions,
                    skip,
                    limit - rows.len(),
                    deadline,
                )?);
                Ok(rows)
            }
        }
    }

    pub(super) fn resolve_dwarf_type(
        &self,
        name: &str,
    ) -> Result<symbols::inspect::type_graph::Graph> {
        let mut matches = self.type_graphs(name, true, true, 0, 5)?;
        if matches.len() == 1 {
            return Ok(matches.pop().unwrap().1);
        }
        let missing = matches.is_empty();
        if missing {
            let stem: String = name
                .split_whitespace()
                .last()
                .unwrap_or_default()
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .take(12)
                .collect();
            if !stem.is_empty() {
                matches = self.type_graphs(&format!("*{stem}*"), false, false, 0, 5)?;
            }
        }
        let candidates = matches
            .iter()
            .map(|(name, graph)| {
                format!(
                    "{name} ({}, size {:?})",
                    graph.module.display(),
                    graph.size()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let reason = if missing {
            "DWARF type not found"
        } else {
            "ambiguous DWARF type"
        };
        Err(error(format!(
            "{reason}: {name:?}. Candidates: [{candidates}]"
        )))
    }
}

#[derive(serde::Deserialize)]
struct ThreadId {
    tid: i32,
}

fn flatten_frame_values(frame: &Value) -> Vec<Value> {
    ["locals", "parameters"]
        .into_iter()
        .flat_map(|field| {
            frame[field]
                .as_object()
                .into_iter()
                .flat_map(|rows| rows.values())
        })
        .cloned()
        .collect()
}

fn list_source(location: Value, radius: u64, source_paths: &[Value]) -> Result<Value> {
    let Some((path, line)) = location["file"].as_str().zip(location["line"].as_u64()) else {
        return Ok(Value::Null);
    };
    let original = Path::new(path);
    let mut resolved = original.to_path_buf();
    for rule in source_paths {
        let from = rule["from"]
            .as_str()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| error("expected a source path prefix"))?;
        let to = rule["to"]
            .as_str()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| error("expected a source path replacement"))?;
        if let Ok(suffix) = original.strip_prefix(from) {
            resolved = Path::new(to).join(suffix);
            break;
        }
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&resolved)
    {
        Ok(file) => file,
        Err(err) if !source_paths.is_empty() => {
            return Err(error(format!(
                "cannot read source {path} at {}: {err}",
                resolved.display()
            )));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Value::Null),
        Err(err) => return Err(err.into()),
    };
    if !file.metadata()?.is_file() {
        return Ok(Value::Null);
    }
    const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(error("source file exceeds 4 MiB"));
    }
    let lower = line.saturating_sub(radius).max(1);
    let upper = line.saturating_add(radius);
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<_> = text
        .lines()
        .enumerate()
        .map(|(index, text)| (index as u64 + 1, text))
        .skip_while(|(number, _)| *number < lower)
        .take_while(|(number, _)| *number <= upper)
        .map(|(number, text)| json!({"line":number,"text":text}))
        .collect();
    Ok(json!({"file":resolved,"originalFile":path,"line":line,"lines":lines}))
}

fn evaluation(report: Value) -> Result<Value> {
    let value = &report["result"];
    if value.is_null() {
        return Err(error(
            report["message"]
                .as_str()
                .or_else(|| report["issue"].as_str())
                .unwrap_or("expression could not be evaluated"),
        ));
    }
    let text = match &value["value"] {
        Value::String(text) => text.clone(),
        Value::Null => value["bytes"].as_str().unwrap_or("").to_owned(),
        value => value.to_string(),
    };
    Ok(json!({"type":value["type"]["name"], "value":value["value"], "text":text}))
}

fn number(args: &Value, key: &str) -> Result<u64> {
    args[key]
        .as_u64()
        .ok_or_else(|| error(format!("{key} must be a nonnegative integer")))
}

pub(super) fn parse_address(value: &Value) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or_else(|| error("expected a bigint address"))?;
    Ok(u64::from_str_radix(
        text.strip_prefix("0x")
            .ok_or_else(|| error("expected a bigint address"))?,
        16,
    )?)
}

impl Live {
    fn step(&mut self, tid: i32, args: &Value) -> Result<()> {
        if !self.paused.contains(&tid) && !self.callbacks.contains(&tid) {
            return Err(error("thread is not controlled by the debugger"));
        }
        let deadline = Instant::now() + DEADLINE;
        let mode = args["mode"].as_str().unwrap_or("step");
        let count = args["count"].as_u64().unwrap_or(1);
        if !(1..=10_000).contains(&count) {
            return Err(error("step count must be in 1..=10000"));
        }
        let until = matches!(mode, "until" | "untilFrame")
            .then(|| parse_address(&args["at"]))
            .transpose()?;
        let caller_sp = (mode == "untilFrame")
            .then(|| parse_address(&args["sp"]))
            .transpose()?;
        let (decoder, width) = disassembly::decoder(regs::ARCH)?;
        self.with_frozen(|live| {
            let mut remaining = count;
            let mut return_address = None;
            loop {
                let state = regs::read(tid)?.stack;
                let pc = state.get(regs::PC)?;
                if until == Some(pc)
                    && caller_sp.is_none_or(|sp| state.get(regs::SP).ok() == Some(sp))
                {
                    return Ok(());
                }
                let mut bytes = vec![0; width as usize];
                let got = live.trace.read_code_prefix(pc, &mut bytes)?;
                let insns = decoder
                    .disasm_count(&bytes[..got], pc, 1)
                    .map_err(|e| error(e.to_string()))?;
                let insn = insns
                    .iter()
                    .next()
                    .ok_or_else(|| error("could not decode instruction"))?;
                let mnemonic = insn.mnemonic().unwrap_or_default();
                let call = matches!(
                    mnemonic,
                    "call" | "lcall" | "bl" | "blr" | "blraa" | "blrab"
                );
                let ret = mnemonic.starts_with("ret");
                let branch = branch_instruction(mnemonic);
                if (mode == "branch" && branch)
                    || (mode == "call" && call && args["follow"] != true)
                {
                    remaining -= 1;
                    if remaining == 0 {
                        return Ok(());
                    }
                }
                if mode == "next" && call && return_address.is_none() {
                    return_address = Some(pc + insn.bytes().len() as u64);
                }
                let stop = live.trace.threads[&tid].stop;
                match stop {
                    Some(Stop::Software { address, .. }) => {
                        live.trace.step_software(tid, address, deadline)?;
                    }
                    Some(Stop::Breakpoint { .. }) => {
                        breakpoint::disarm(tid)?;
                        let stepped = live.trace.step_one(tid, deadline);
                        if live
                            .trace
                            .threads
                            .get(&tid)
                            .is_some_and(|thread| thread.stop.is_some())
                        {
                            live.program(tid)?;
                        }
                        stepped?;
                    }
                    _ => {
                        live.trace.step_one(tid, deadline)?;
                    }
                }
                live.handled_stops.remove(&tid);
                if live.suppress.contains(&tid)
                    && matches!(
                        live.trace.threads.get(&tid).and_then(|thread| thread.stop),
                        Some(Stop::Software { .. } | Stop::Breakpoint { .. })
                    )
                {
                    continue;
                }
                if !matches!(
                    live.trace.threads.get(&tid).and_then(|thread| thread.stop),
                    Some(Stop::Step | Stop::Interrupt)
                ) {
                    return Err(error(
                        "step interrupted by a signal, breakpoint or target exit",
                    ));
                }
                if mode == "finish" && ret {
                    return Ok(());
                }
                if mode == "step"
                    || (mode == "call" && call && args["follow"] == true)
                    || (mode == "next"
                        && (return_address.is_none()
                            || return_address == Some(regs::read(tid)?.stack.get(regs::PC)?)))
                {
                    remaining -= 1;
                    return_address = None;
                    if remaining == 0 {
                        return Ok(());
                    }
                }
            }
        })
    }

    fn coredump(
        &mut self,
        path: &Path,
        kind: &str,
        state_dir: &Path,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        if !path.is_absolute() {
            return Err(error("coredump output must be an absolute server path"));
        }
        let mode = match kind {
            "minimal" => CoreMode::CoreLite,
            "stack-4k" => CoreMode::CoreStack4k,
            "stack" => CoreMode::CoreStack,
            "standard" => CoreMode::CoreStandard,
            "extended" => CoreMode::CoreExtended,
            "full" => CoreMode::CoreFull,
            _ => return Err(error("unknown coredump kind")),
        };
        let options =
            coredump::CaptureOptions::new(mode, coredump::DEFAULT_TIMEOUT_MS, None, None)?
                .for_process(self.start);
        self.with_frozen(|live| {
            live.trace.rewind_software_stops()?;
            let dump = coredump::prepare_with_trace(
                live.pid,
                mode,
                options,
                state_dir,
                &|| cancelled.load(std::sync::atomic::Ordering::Relaxed),
                || {},
                Some((&mut live.trace, None)),
            )?;
            let mut temp = tempfile::NamedTempFile::new_in(
                path.parent()
                    .ok_or_else(|| error("missing output directory"))?,
            )?;
            temp.write_all(&dump.header)?;
            io::copy(&mut File::open(dump.payload.path())?, &mut temp)?;
            temp.persist_noclobber(path)?;
            Ok(())
        })
    }
}

fn branch_instruction(mnemonic: &str) -> bool {
    mnemonic.starts_with('j')
        || mnemonic.starts_with("ret")
        || mnemonic.starts_with("b.")
        || matches!(
            mnemonic,
            "call"
                | "lcall"
                | "bl"
                | "blr"
                | "blraa"
                | "blrab"
                | "b"
                | "br"
                | "cbz"
                | "cbnz"
                | "tbz"
                | "tbnz"
                | "loop"
                | "loope"
                | "loopne"
        )
}

fn inferior_expression(expression: &str) -> Option<(&str, Vec<&str>)> {
    let (name, tail) = expression.trim().split_once('(')?;
    let name = name.trim();
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':'))
    {
        return None;
    }
    let parameters = tail.strip_suffix(')')?.trim();
    let mut depth = 0u32;
    let mut start = 0;
    let mut args = Vec::new();
    for (offset, ch) in parameters.char_indices() {
        match ch {
            '(' | '[' => depth = depth.checked_add(1)?,
            ')' | ']' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                args.push(parameters[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    if !parameters.is_empty() {
        args.push(parameters[start..].trim());
    }
    Some((name, args))
}

fn parse_c_integer(text: &str) -> Result<i128> {
    let (negative, number) = text
        .strip_prefix('-')
        .map_or((false, text), |number| (true, number));
    let number = number.trim_end_matches(['u', 'U', 'l', 'L']);
    let (radix, text) = number
        .strip_prefix("0x")
        .or_else(|| number.strip_prefix("0X"))
        .map_or((10, number), |hex| (16, hex));
    let value = i128::from_str_radix(text, radix)?;
    Ok(if negative { -value } else { value })
}

fn encode_scalar(kind: &str, value: &Value) -> Result<Vec<u8>> {
    let width = super::inferior::scalar_width(kind)?;
    let text = value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned);
    let bits = match kind {
        "f32" => u64::from(text.parse::<f32>()?.to_bits()),
        "f64" => text.parse::<f64>()?.to_bits(),
        _ => {
            let n = parse_c_integer(&text)?;
            let signed = kind.starts_with('i');
            let limit = 1i128 << (8 * width - usize::from(signed));
            if n >= limit || n < if signed { -limit } else { 0 } {
                return Err(error("C argument is out of range"));
            }
            n as u64
        }
    };
    Ok(bits.to_le_bytes()[..width].to_vec())
}

fn decode_scalar(kind: &str, bytes: [u8; 8]) -> Value {
    let n = u64::from_le_bytes(bytes);
    match kind {
        "f32" => json!(f32::from_bits(n as u32)),
        "f64" => json!(f64::from_bits(n)),
        "ptr" => json!(hex(n)),
        "i64" => json!((n as i64).to_string()),
        "u64" => json!(n.to_string()),
        "i32" => json!(n as i32),
        "i16" => json!(n as i16),
        "i8" => json!(n as i8),
        "void" => Value::Null,
        _ => json!(n),
    }
}
