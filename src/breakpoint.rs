use crate::procfs::{Status, epoch_ms, start_ticks};
use crate::script::breakpoint::{
    Callback, CallbackResult, Engine, HitState, Limits, Realm, WatchState,
};
use crate::script::{
    LiveReplayPoint, LiveRunResult,
    live::{self, ExportModule},
};
use crate::trace::{Cleanup, Stop, Trace};
use crate::{Result, Snapshot, error, hex, machine, modules, regs, rpc::FreezeMode};
use crate::{symbols, unwind};
use nix::errno::Errno;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};

mod rules;
mod step;
pub use rules::CallbackSource;
use rules::{AttachedCallback, ExportCache, Update};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(target_arch = "x86_64")]
const SLOTS: usize = 4;
#[cfg(target_arch = "aarch64")]
const SLOTS: usize = 32;
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
    stop_after_hit: bool,
}

impl Program {
    fn snapshot(scope: Scope, budget_ms: u32) -> Result<Self> {
        let operand = match scope {
            Scope::Thread => 0,
            Scope::Process => 1,
        };
        Self::load(&[SNAPSHOT, operand, RETURN], budget_ms)
    }

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
            stop_after_hit: false,
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
        module: Option<String>,
        symbol: String,
        instance: Option<u64>,
        offset: u64,
        execution: bool,
    },
    Source {
        file: PathBuf,
        line: u64,
        module: Option<String>,
        instance: Option<u64>,
    },
    ModuleOffset {
        module: String,
        offset: u64,
        execution: bool,
        instance: Option<u64>,
        symbol: Option<String>,
    },
}

struct PreparedLocation {
    address: u64,
    site: Option<symbols::BreakpointSite>,
    start: Option<u64>,
}

impl PreparedLocation {
    fn resolve(pid: i32, location: Location, overrides: &[symbols::OverrideRule]) -> Result<Self> {
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
                offset,
                execution,
            } => {
                // Resolve on the caller's thread so file I/O cannot delay pending hits.
                let procdir = File::open(format!("/proc/{pid}"))?;
                let root = PathBuf::from(format!("/proc/self/fd/{}", procdir.as_raw_fd()));
                let start = start_ticks(&root)?;
                let (address, site) = symbols::unique_breakpoint_location(
                    pid,
                    &root,
                    module.as_deref(),
                    &symbol,
                    instance,
                    offset,
                    execution,
                    overrides,
                )?;
                Ok(Self {
                    address,
                    site,
                    start: Some(start),
                })
            }
            Location::Source {
                file,
                line,
                module,
                instance,
            } => {
                let procdir = File::open(format!("/proc/{pid}"))?;
                let root = PathBuf::from(format!("/proc/self/fd/{}", procdir.as_raw_fd()));
                let start = start_ticks(&root)?;
                let site =
                    symbols::breakpoint_line(&root, &file, line, module.as_deref(), instance)?;
                Ok(Self {
                    address: site.address,
                    site: Some(site),
                    start: Some(start),
                })
            }
            Location::ModuleOffset {
                module,
                offset,
                execution,
                instance,
                symbol,
            } => {
                let procdir = File::open(format!("/proc/{pid}"))?;
                let root = PathBuf::from(format!("/proc/self/fd/{}", procdir.as_raw_fd()));
                let start = start_ticks(&root)?;
                let (instance, offset) = if let Some(symbol) = symbol {
                    let (instance, offset) =
                        symbols::symbol_module_offset(pid, &module, &symbol, instance, offset)?;
                    (Some(instance), offset)
                } else {
                    (instance, offset)
                };
                let address =
                    symbols::resolve_module_offset(&root, &module, offset, execution, instance)?;
                Ok(Self {
                    address,
                    site: None,
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
    Watch { length: usize, access: WatchAccess },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchAccess {
    Read,
    Write,
    ReadWrite,
}
impl WatchAccess {
    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
        }
    }
    fn write_observed(self) -> Option<bool> {
        match self {
            Self::Read => Some(false),
            Self::Write => Some(true),
            Self::ReadWrite => None,
        }
    }
}
impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Hardware => "hardware_execution",
            Self::Software => "software_execution",
            Self::Watch {
                access: WatchAccess::Read,
                ..
            } => "hardware_read",
            Self::Watch {
                access: WatchAccess::Write,
                ..
            } => "hardware_write",
            Self::Watch {
                access: WatchAccess::ReadWrite,
                ..
            } => "hardware_read_write",
        }
    }
}

#[derive(Serialize)]
pub struct WatchObservation {
    length: usize,
    access: &'static str,
    pub write_observed: Option<bool>,
    #[serde(serialize_with = "watch_hex")]
    value_before: Option<u64>,
    #[serde(serialize_with = "watch_hex")]
    value_after: Option<u64>,
    #[serde(serialize_with = "watch_decimal")]
    value_before_decimal: Option<u64>,
    #[serde(serialize_with = "watch_decimal")]
    value_after_decimal: Option<u64>,
    value_changed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reported_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attribution: Option<&'static str>,
}

fn watch_hex<S: serde::Serializer>(
    value: &Option<u64>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    value.map(hex).serialize(serializer)
}

fn watch_decimal<S: serde::Serializer>(
    value: &Option<u64>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    value.map(|value| value.to_string()).serialize(serializer)
}

fn capabilities() -> serde_json::Value {
    let x86 = cfg!(target_arch = "x86_64");
    serde_json::json!({
        "architecture": regs::ARCH,
        "hardware_execution": true,
        "software_execution": true,
        "shared_execution_and_watch_slots": if x86 { SLOTS } else { 0 },
        "watch_access": if x86 { vec!["write", "read_write"] } else { vec!["read", "write", "read_write"] },
        "watch_lengths": [1, 2, 4, 8],
        "watch_alignment": "address must be aligned to length",
        "execution_alignment": if x86 { 1 } else { 4 },
        "execution_slots": if x86 { Some(SLOTS) } else { None },
        "watch_slots": if x86 { Some(SLOTS) } else { None },
        "software_value_change": true,
    })
}

pub fn probe_capabilities() -> Result<serde_json::Value> {
    #[cfg(target_arch = "x86_64")]
    return Ok(capabilities());
    #[cfg(target_arch = "aarch64")]
    {
        use nix::{
            libc,
            sys::{
                signal::{Signal, kill},
                wait::waitpid,
            },
            unistd::Pid,
        };
        // The child performs only an async-signal-safe syscall until reaped.
        let pid = Errno::result(unsafe { libc::fork() })?;
        if pid == 0 {
            loop {
                unsafe { libc::pause() };
            }
        }
        let result = capabilities_for(pid);
        let pid = Pid::from_raw(pid);
        let _ = kill(pid, Signal::SIGKILL);
        while matches!(waitpid(pid, None), Err(Errno::EINTR)) {}
        result
    }
}

#[cfg(target_arch = "aarch64")]
fn with_counts(exec: usize, watch: usize) -> serde_json::Value {
    let mut result = capabilities();
    result["execution_slots"] = exec.into();
    result["watch_slots"] = watch.into();
    result["hardware_execution"] = (exec > 0).into();
    if watch == 0 {
        result["watch_access"] = serde_json::json!([]);
        result["watch_lengths"] = serde_json::json!([]);
    }
    result
}

pub fn capabilities_for(pid: i32) -> Result<serde_json::Value> {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = pid;
        Ok(capabilities())
    }
    #[cfg(target_arch = "aarch64")]
    {
        let dir = File::open(format!("/proc/{pid}"))?;
        let root = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
        if Status::read(&root)?.field("Tgid") != Some(&pid.to_string())
            || machine(&root)? != regs::ARCH
        {
            return Err(error("expected a native process leader"));
        }
        let mut trace = Trace::new(pid, &root, start_ticks(&root)?);
        let counts = trace
            .freeze(Instant::now() + CONTROL_BUDGET)
            .and_then(|()| hardware::counts(pid));
        let cleanup = trace.close();
        if !cleanup.ok() {
            return Err(error("could not detach capability probe cleanly"));
        }
        let (exec, watch) = counts?;
        Ok(with_counts(exec, watch))
    }
}

#[derive(Clone, Copy)]
struct Rule {
    id: u64,
    address: u64,
    program: Program,
    kind: Kind,
    thread: Option<(i32, u64)>,
}

impl Rule {
    fn applies(self, tid: i32, identity: u64) -> bool {
        self.thread.is_none_or(|thread| thread == (tid, identity))
    }
}

#[derive(Serialize)]
pub struct Installed {
    pub kind: &'static str,
    pub breakpoint_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_revision: Option<u64>,
    pub address: String,
    pub stop_after_hit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    callback: Option<Limits>,
    #[serde(skip)]
    pub active: Weak<()>,
}

#[derive(Serialize)]
pub struct Event {
    pub breakpoint_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_revision: Option<u64>,
    pub pid: i32,
    pub tid: i32,
    pub address: String,
    pub instruction_pc: String,
    pub pc_relation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_context: Option<serde_json::Value>,
    pub scope: &'static str,
    pub observed_unix_ms: u64,
    pub pause_ms: u64,
    pub capture_status: &'static str,
    pub resume_status: &'static str,
    pub detail: Option<String>,
    pub kind: &'static str,
    pub watch: Option<WatchObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    callback: Option<CallbackResult>,
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

pub type Publish = Arc<dyn Fn(Event, Option<Capture>) + Send + Sync>;

struct Outcome {
    stop_context: Option<serde_json::Value>,
    pending: Option<(Result<HitState>, Instant)>,
    rule: Option<(u64, u64)>,
    snapshot: Option<Capture>,
    callback: Option<CallbackResult>,
}

// Keep every hit through architecture-specific stepping, even when no event
// will be published. A skipped watchpoint still affects attribution.
type CapturedHit = (Hit, Outcome);
type Slots = [Option<Rule>; SLOTS];
type HardwareSlots = [Option<(u64, Kind)>; SLOTS];

pub(crate) fn session_program(tid: i32, slots: &[Option<(u64, Kind)>]) -> Result<()> {
    let mut hardware = [None; SLOTS];
    if slots.len() > hardware.len() {
        return Err(error("hardware breakpoint slots exhausted"));
    }
    hardware[..slots.len()].copy_from_slice(slots);
    hardware::program_raw(tid, &hardware)
}

pub(crate) fn session_prepare_resume(tid: i32, execution: bool) -> Result<()> {
    hardware::prepare_resume(tid, execution)
}

fn live_result(
    breakpoint_ids: Vec<u64>,
    result: Result<serde_json::Value>,
    output: Vec<serde_json::Value>,
) -> LiveRunResult {
    match result {
        Ok(return_value) => LiveRunResult {
            status: "complete",
            stop_reason: "completed",
            breakpoint_ids,
            issue: None,
            return_value,
            output,
            active: Vec::new(),
        },
        Err(issue) => LiveRunResult {
            status: "failed",
            stop_reason: "runtime_error",
            breakpoint_ids: Vec::new(),
            issue: Some(issue.to_string()),
            return_value: serde_json::Value::Null,
            output,
            active: Vec::new(),
        },
    }
}

struct ScriptCommand {
    js: String,
    source: Arc<str>,
    replay_points: Vec<LiveReplayPoint>,
    budget: Duration,
    ids: Arc<AtomicU64>,
    reply: mpsc::Sender<Result<LiveRunResult>>,
}

enum Command {
    Script(ScriptCommand),
    Inspect(
        crate::rpc::InspectRequest,
        mpsc::Sender<Result<serde_json::Value>>,
    ),
    Disassemble(
        crate::rpc::DisassembleRequest,
        mpsc::Sender<Result<crate::disassembly::Window>>,
    ),
    Install {
        id: u64,
        location: PreparedLocation,
        program: Program,
        kind: Kind,
        tid: Option<i32>,
        callback: Option<CallbackSource>,
        sender: Weak<mpsc::SyncSender<Command>>,
        reply: mpsc::Sender<Result<Installed>>,
    },
    Update {
        id: u64,
        address: Option<u64>,
        callback: Option<CallbackSource>,
        sender: Weak<mpsc::SyncSender<Command>>,
        reply: mpsc::Sender<Result<Installed>>,
    },
    CaptureCore {
        mode: crate::rpc::CoreMode,
        options: crate::coredump::CaptureOptions,
        directory: PathBuf,
        reply: mpsc::Sender<Result<crate::coredump::Dump>>,
    },
    Capabilities(mpsc::Sender<Result<serde_json::Value>>),
    List(mpsc::Sender<Vec<Installed>>),
    ReadMemory(
        crate::rpc::ReadMemoryRequest,
        mpsc::Sender<Result<serde_json::Value>>,
    ),
    PointerChain(
        crate::rpc::PointerChainRequest,
        mpsc::Sender<Result<serde_json::Value>>,
    ),
    Step(
        crate::rpc::StepRunRequest,
        mpsc::Sender<Result<serde_json::Value>>,
    ),
    StageRule {
        id: u64,
        update: Arc<Update>,
        reply: mpsc::Sender<Result<()>>,
    },
    Remove {
        id: u64,
        reply: mpsc::Sender<Result<Option<Cleanup>>>,
    },
}

#[derive(Clone)]
pub struct Control(Arc<mpsc::SyncSender<Command>>);

#[derive(Clone)]
pub struct WeakControl(Weak<mpsc::SyncSender<Command>>);

impl WeakControl {
    pub fn upgrade(&self) -> Option<Control> {
        self.0.upgrade().map(Control)
    }
}

pub struct Commands(mpsc::Receiver<Command>);

impl Control {
    pub fn read_memory(&self, request: crate::rpc::ReadMemoryRequest) -> Result<serde_json::Value> {
        let (reply, result) = mpsc::channel();
        self.send(Command::ReadMemory(request, reply))?;
        result
            .recv()
            .map_err(|_| error("run ended during memory read"))?
    }

    pub fn pointer_chain(
        &self,
        request: crate::rpc::PointerChainRequest,
    ) -> Result<serde_json::Value> {
        let (reply, result) = mpsc::channel();
        self.send(Command::PointerChain(request, reply))?;
        result
            .recv()
            .map_err(|_| error("run ended during pointer chain"))?
    }

    pub fn step(&self, request: crate::rpc::StepRunRequest) -> Result<serde_json::Value> {
        let (reply, result) = mpsc::channel();
        self.send(Command::Step(request, reply))?;
        result.recv().map_err(|_| error("run ended during step"))?
    }
    pub fn list(&self) -> Result<Vec<Installed>> {
        let (reply, result) = mpsc::channel();
        self.send(Command::List(reply))?;
        result
            .recv()
            .map_err(|_| error("breakpoint session ended during list"))
    }

    pub fn capabilities(&self) -> Result<serde_json::Value> {
        let (reply, result) = mpsc::channel();
        self.send(Command::Capabilities(reply))?;
        result
            .recv()
            .map_err(|_| error("breakpoint session ended during capability probe"))?
    }

    pub fn capture_core(
        &self,
        mode: crate::rpc::CoreMode,
        options: crate::coredump::CaptureOptions,
        directory: PathBuf,
    ) -> Result<crate::coredump::Dump> {
        let (reply, result) = mpsc::channel();
        self.send(Command::CaptureCore {
            mode,
            options,
            directory,
            reply,
        })?;
        result
            .recv()
            .map_err(|_| error("breakpoint session ended during coredump"))?
    }

    pub fn downgrade(&self) -> WeakControl {
        WeakControl(Arc::downgrade(&self.0))
    }

    pub fn update(
        &self,
        id: u64,
        address: Option<u64>,
        callback: Option<CallbackSource>,
    ) -> Result<Installed> {
        let (reply, result) = mpsc::channel();
        self.send(Command::Update {
            id,
            address,
            callback,
            sender: Arc::downgrade(&self.0),
            reply,
        })?;
        result
            .recv()
            .map_err(|_| error("breakpoint session ended during update"))?
    }

    pub fn channel() -> (Self, Commands) {
        let (tx, rx) = mpsc::sync_channel(8);
        (Self(Arc::new(tx)), Commands(rx))
    }
}

pub struct Worker {
    control: Option<Control>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start(pid: i32, publish: Publish) -> Result<Self> {
        let (control, commands) = Control::channel();
        let thread = thread::Builder::new()
            .name(format!("aidbg-trace-{pid}"))
            .spawn(move || {
                if let Err(e) = Session::run(pid, publish, commands) {
                    eprintln!("aidbg: breakpoint session for {pid}: {e}");
                }
            })?;
        Ok(Self {
            control: Some(control),
            thread: Some(thread),
        })
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| t.is_finished())
    }

    pub fn control(&self) -> &Control {
        self.control.as_ref().expect("live worker")
    }
}

impl Control {
    pub fn install(
        &self,
        pid: i32,
        id: u64,
        location: Location,
        scope: Scope,
        budget_ms: u32,
        kind: Kind,
        tid: Option<i32>,
        callback: Option<CallbackSource>,
        stop_after_hit: bool,
        overrides: &[symbols::OverrideRule],
    ) -> Result<Installed> {
        let mut program = Program::snapshot(scope, budget_ms)?;
        program.stop_after_hit = stop_after_hit;
        let location = PreparedLocation::resolve(pid, location, overrides)?;
        let (reply, result) = mpsc::channel();
        self.send(Command::Install {
            id,
            location,
            program,
            kind,
            tid,
            callback,
            sender: Arc::downgrade(&self.0),
            reply,
        })?;
        result
            .recv()
            .map_err(|_| error("breakpoint session ended during install"))?
    }

    pub fn script_run(
        &self,
        js: String,
        source: String,
        replay_points: Vec<LiveReplayPoint>,
        budget: Duration,
        ids: Arc<AtomicU64>,
    ) -> Result<LiveRunResult> {
        let (reply, result) = mpsc::channel();
        self.send(Command::Script(ScriptCommand {
            js,
            source: source.into(),
            replay_points,
            budget,
            ids,
            reply,
        }))?;
        result
            .recv()
            .map_err(|_| error("debugger session ended during live script"))?
    }

    fn stage_rule(&self, id: u64, update: Arc<Update>) -> Result<()> {
        let (reply, result) = mpsc::channel();
        self.send(Command::StageRule { id, update, reply })?;
        result
            .recv()
            .map_err(|_| error("breakpoint session ended during rule update"))?
    }

    pub fn remove(&self, id: u64) -> Result<Option<Cleanup>> {
        let (reply, result) = mpsc::channel();
        self.send(Command::Remove { id, reply })?;
        result
            .recv()
            .map_err(|_| error("breakpoint session ended during removal"))?
    }

    pub fn inspect(&self, request: crate::rpc::InspectRequest) -> Result<serde_json::Value> {
        let (reply, result) = mpsc::channel();
        self.send(Command::Inspect(request, reply))?;
        result
            .recv()
            .map_err(|_| error("debugger session ended during inspection"))?
    }

    pub fn disassemble(
        &self,
        request: crate::rpc::DisassembleRequest,
    ) -> Result<crate::disassembly::Window> {
        let (reply, result) = mpsc::channel();
        self.send(Command::Disassemble(request, reply))?;
        result
            .recv()
            .map_err(|_| error("debugger session ended during disassembly"))?
    }

    fn send(&self, command: Command) -> Result<()> {
        self.0.try_send(command).map_err(|e| match e {
            mpsc::TrySendError::Full(_) => error("debugger command queue is full"),
            mpsc::TrySendError::Disconnected(_) => error("debugger session has ended"),
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.control.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) struct Session<'a> {
    pid: i32,
    root: &'a Path,
    start: u64,
    pub(crate) trace: Trace,
    pub(crate) paused: bool,
    held_tid: Option<i32>,
    pause_state: Option<Arc<AtomicBool>>,
    pending_breakpoint: bool,
    launched: bool,
    hardware: BTreeMap<u64, Rule>,
    software: BTreeMap<u64, Rule>,
    watch_values: BTreeMap<u64, Option<u64>>,
    callbacks: BTreeMap<u64, AttachedCallback>,
    active: BTreeMap<u64, Arc<()>>,
    live_sources: BTreeMap<u64, LiveSource>,
    exports: ExportCache,
    engine: Option<Rc<Engine>>,
    publish: Publish,
    live_script: Option<LiveScript>,
}

struct LiveScript {
    output: Vec<serde_json::Value>,
    waiting: live::AwaitEvents,
    reply: mpsc::Sender<Result<LiveRunResult>>,
    ids: Vec<u64>,
    events: Vec<(Event, Option<Capture>)>,
    overflow: bool,
    was_paused: bool,
    deadline: Instant,
}

struct LiveSource {
    key: u64,
    source: Arc<str>,
    ordinal: usize,
    requested_address: u64,
}

struct Hit {
    tid: i32,
    pc: u64,
    rule: Rule,
    observed: Instant,
    unix_ms: u64,
    watch: Option<WatchObservation>,
}

impl<'a> Session<'a> {
    pub(crate) fn new(
        pid: i32,
        root: &'a Path,
        start: u64,
        trace: Trace,
        publish: Publish,
        launched: bool,
    ) -> Self {
        Self {
            pid,
            root,
            start,
            trace,
            paused: false,
            held_tid: None,
            pause_state: None,
            pending_breakpoint: false,
            launched,
            hardware: BTreeMap::new(),
            software: BTreeMap::new(),
            watch_values: BTreeMap::new(),
            callbacks: BTreeMap::new(),
            active: BTreeMap::new(),
            live_sources: BTreeMap::new(),
            exports: ExportCache::default(),
            engine: None,
            publish,
            live_script: None,
        }
    }

    fn run(pid: i32, publish: Publish, commands: Commands) -> Result<()> {
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
                if let Ok(Command::Install { reply, .. }) = commands.0.recv() {
                    let _ = reply.send(Err(e));
                }
                return Ok(());
            }
        };

        let mut trace = Trace::new(pid, &root, start);
        trace.monitor();
        let mut session = Session::new(pid, &root, start, trace, publish, false);
        loop {
            session.trace.poll()?;
            session.trace.detach_foreign_children()?;
            if session.trace.exec_observed() || session.trace.foreign_software {
                return Ok(());
            }
            session.handle_stops()?;
            let detached = session.remove_exhausted()?;
            if detached || (!session.empty() && session.trace.threads.is_empty()) {
                return Ok(());
            }
            match commands.0.recv_timeout(POLL_INTERVAL) {
                Ok(command) => {
                    session.command(command);
                    if session.empty() {
                        return Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
    }

    pub(crate) fn service(&mut self, commands: &Commands, paused: &AtomicBool) {
        if self.live_script.is_some() {
            return;
        }
        if let Ok(command) = commands.0.try_recv() {
            match command {
                Command::Script(command) => self.script_run(command, paused),
                command => self.command(command),
            }
        }
    }

    fn command(&mut self, command: Command) {
        self.refresh_callbacks();
        match command {
            Command::Script(command) => {
                let _ = command
                    .reply
                    .send(Err(error("live scripts require a run target")));
            }
            Command::Install {
                id,
                location,
                program,
                kind,
                tid,
                callback,
                sender,
                reply,
            } => {
                let result = self.install(id, location, program, kind, tid, callback, sender);
                let _ = reply.send(result);
            }
            Command::Update {
                id,
                address,
                callback,
                sender,
                reply,
            } => {
                let _ = reply.send(self.update(id, address, callback, sender));
            }
            Command::CaptureCore {
                mode,
                options,
                directory,
                reply,
            } => {
                let _ = reply.send(self.capture_core(mode, options, &directory));
            }
            Command::Capabilities(reply) => {
                #[cfg(target_arch = "aarch64")]
                let result = {
                    let mut counts = None;
                    self.control(|session| {
                        counts = Some(hardware::counts(session.pid)?);
                        Ok(())
                    })
                    .map(|()| {
                        let (exec, watch) = counts.expect("capacity was probed");
                        with_counts(exec, watch)
                    })
                };
                #[cfg(target_arch = "x86_64")]
                let result = Ok(capabilities());
                let result = result.map(|mut document| {
                    let slots: Vec<_> = self
                        .trace
                        .threads
                        .iter()
                        .map(|(&tid, thread)| {
                            let mut execution = 0;
                            let mut watch = 0;
                            for rule in self
                                .hardware
                                .values()
                                .filter(|rule| rule.applies(tid, thread.identity))
                            {
                                if matches!(rule.kind, Kind::Watch { .. }) {
                                    watch += 1;
                                } else {
                                    execution += 1;
                                }
                            }
                            serde_json::json!({"tid": tid, "execution": execution, "watch": watch,
                            "shared": cfg!(target_arch = "x86_64").then_some(execution + watch)})
                        })
                        .collect();
                    document["used_slots"] = slots.into();
                    document
                });
                let _ = reply.send(result);
            }
            Command::List(reply) => {
                let mut points: Vec<_> = self
                    .hardware
                    .values()
                    .chain(self.software.values())
                    .map(|rule| self.installed(*rule))
                    .collect();
                points.sort_by_key(|point| point.breakpoint_id);
                let _ = reply.send(points);
            }
            Command::ReadMemory(request, reply) => {
                let _ = reply.send(crate::script::read_range(&request, |address, buffer| {
                    self.trace.read_code_prefix(address, buffer)
                }));
            }
            Command::PointerChain(request, reply) => {
                let _ = reply.send(crate::script::pointer_chain_with(
                    request.base,
                    request.offsets,
                    Vec::new(),
                    |address, buffer| self.trace.read_code_prefix(address, buffer),
                    crate::script::live_missing_memory,
                ));
            }
            Command::Step(request, reply) => {
                let _ = reply.send(self.step(request));
            }
            Command::StageRule { id, update, reply } => {
                let result = match self.callbacks.get_mut(&id) {
                    Some(callback) => callback.stage(update, |request| {
                        let engine = self
                            .engine
                            .as_ref()
                            .cloned()
                            .ok_or_else(|| error("live script runtime ended"))?;
                        self.exports.callback(engine, request)
                    }),
                    None => Ok(()),
                };
                let result = if self.runtime_poisoned() {
                    self.control(|_| Ok(())).and(result)
                } else {
                    result
                };
                let _ = reply.send(result);
            }
            Command::Remove { id, reply } => {
                let _ = reply.send(self.remove(id));
            }
            Command::Inspect(request, reply) => {
                let tid = request.tid.or(self.held_tid);
                let result = symbols::inspect::inspect_request_with_trace(
                    self.pid,
                    tid,
                    request,
                    self.root,
                    &mut self.trace,
                );
                let _ = reply.send(result);
            }
            Command::Disassemble(request, reply) => {
                let result = crate::disassembly::disassemble_with(
                    self.pid,
                    request.address,
                    request.before.unwrap_or(4),
                    request.after.unwrap_or(8),
                    request.start,
                    |address, buffer| self.trace.read_code_prefix(address, buffer),
                );
                let _ = reply.send(result);
            }
        }
    }

    pub(crate) fn reset_address_space(&mut self) -> Result<()> {
        self.pending_breakpoint = false;
        self.held_tid = None;
        self.trace.clear_patches();
        self.hardware.clear();
        self.software.clear();
        self.watch_values.clear();
        self.callbacks.clear();
        self.active.clear();
        self.live_sources.clear();
        self.exports.clear();
        self.engine = None;
        self.program_stopped(&self.hardware)
    }

    pub(crate) fn retire_inherited_patches(&mut self) -> Result<()> {
        self.trace.freeze(Instant::now() + CONTROL_BUDGET)?;
        self.trace.rewind_software_stops()?;
        let ids = self.software.values().map(|rule| rule.id).collect();
        self.disarm_stopped(&ids)?;
        for thread in self.trace.threads.values_mut() {
            if matches!(thread.stop, Some(Stop::Software { .. })) {
                thread.stop = Some(Stop::Interrupt);
            }
        }
        self.trace.foreign_software = false;
        self.pending_breakpoint = false;
        Ok(())
    }

    pub(crate) fn track_pause_state(&mut self, paused: Arc<AtomicBool>) {
        self.pause_state = Some(paused);
    }

    pub(crate) fn set_paused(&mut self, value: bool) {
        self.paused = value;
        if !value {
            self.held_tid = None;
        }
        if let Some(paused) = &self.pause_state {
            paused.store(value, Ordering::Release);
        }
    }

    fn hold_at(&mut self, tid: i32) {
        self.held_tid = Some(tid);
        self.set_paused(true);
    }

    pub(crate) fn empty(&self) -> bool {
        self.hardware.is_empty() && self.software.is_empty()
    }

    fn install(
        &mut self,
        id: u64,
        location: PreparedLocation,
        program: Program,
        kind: Kind,
        tid: Option<i32>,
        source: Option<CallbackSource>,
        sender: Weak<mpsc::SyncSender<Command>>,
    ) -> Result<Installed> {
        let mut installed = None;
        self.control(|session| {
            let callback = session.attach(id, source, &program, sender)?;
            installed = Some(session.install_stopped(id, location, program, kind, tid, callback)?);
            Ok(())
        })?;
        Ok(installed.expect("installation ran at a safe stop"))
    }

    fn attach(
        &mut self,
        id: u64,
        source: Option<CallbackSource>,
        program: &Program,
        sender: Weak<mpsc::SyncSender<Command>>,
    ) -> Result<Option<AttachedCallback>> {
        source
            .map(|source| {
                source.attach(id, sender, program.budget.as_millis() as u32, |request| {
                    let engine = self.shared_engine()?;
                    self.exports.callback(engine, request)
                })
            })
            .transpose()
    }

    fn capture_core(
        &mut self,
        mode: crate::rpc::CoreMode,
        options: crate::coredump::CaptureOptions,
        directory: &Path,
    ) -> Result<crate::coredump::Dump> {
        if self.paused {
            return self.capture_stopped_core(mode, options, directory);
        }
        let mut result = None;
        self.control(|session| {
            result = Some(session.capture_stopped_core(mode, options, directory)?);
            Ok(())
        })?;
        Ok(result.expect("coredump ran at a safe stop"))
    }

    fn capture_stopped_core(
        &mut self,
        mode: crate::rpc::CoreMode,
        options: crate::coredump::CaptureOptions,
        directory: &Path,
    ) -> Result<crate::coredump::Dump> {
        let session = self;
        let mut points = Vec::new();
        let mut sources = BTreeMap::new();
        for rule in session.hardware.values().chain(session.software.values()) {
            let mut point = symbols::resolve(session.pid, rule.address, &[])?.replay_location();
            let callback = session.callbacks.get(&rule.id);
            if let Some(callback) = callback
                && let Some((source, export)) = callback.replay_source()
            {
                let (id, revision) = callback.version().expect("registered source");
                let key = format!("{id}-{revision}");
                sources.insert(key.clone(), source);
                point["source"] = key.into();
                point["export"] = serde_json::json!(export);
            } else if let Some(live) = session.live_sources.get(&rule.id) {
                let key = format!("live-{}", live.key);
                sources.insert(key.clone(), &live.source);
                point["source"] = key.into();
                point["live"] = serde_json::json!({
                    "ordinal": live.ordinal,
                    "requested_address": hex(live.requested_address),
                });
            }
            point["breakpoint_id"] = rule.id.into();
            point["address"] = hex(rule.address).into();
            point["kind"] = rule.kind.name().into();
            point["scope"] = rule.program.scope.name().into();
            point["timeout_ms"] = (rule.program.budget.as_millis() as u64).into();
            if rule.program.stop_after_hit {
                point["stop_after_hit"] = true.into();
            }
            if let Kind::Watch { length, .. } = rule.kind {
                point["length"] = length.into();
            }
            if let Some((tid, _)) = rule.thread {
                point["thread"] = if tid == session.pid {
                    "leader"
                } else {
                    "specific"
                }
                .into();
            }
            points.push(point);
        }
        let replay = serde_json::json!({"breakpoints": points, "rules": sources});
        if serde_json::to_vec(&replay)?.len() > 1024 * 1024 {
            return Err(error("breakpoint replay metadata exceeds 1 MiB"));
        }
        let pid = session.pid;
        let dump = session.trace.with_unpatched(|trace| {
            crate::coredump::prepare_with_trace(
                pid,
                mode,
                options,
                directory,
                &|| false,
                || {},
                Some((trace, None)),
            )
        });
        let mut dump = dump?;
        dump.summary.breakpoint_replay = Some(replay);
        Ok(dump)
    }

    fn shared_engine(&mut self) -> Result<Rc<Engine>> {
        if let Some(engine) = &self.engine {
            if engine.poisoned() {
                return Err(error("live script runtime is being disarmed"));
            }
            return Ok(Rc::clone(engine));
        }
        let engine = Engine::new()?;
        self.engine = Some(Rc::clone(&engine));
        Ok(engine)
    }

    fn script_run(&mut self, command: ScriptCommand, paused: &AtomicBool) {
        let ScriptCommand {
            js,
            source,
            replay_points,
            budget,
            ids,
            reply,
        } = command;
        let replaying = !replay_points.is_empty();
        let replay_count = replay_points.len();
        let mut replay_points: BTreeMap<_, _> = replay_points
            .into_iter()
            .map(|point| (point.ordinal, point))
            .collect();
        let mut breakpoint_ids = Vec::new();
        let mut evaluation = None;
        let mut output = Vec::new();
        let mut setup = |session: &mut Self| {
            if replaying
                && (!session.paused
                    || replay_count != replay_points.len()
                    || replay_count > SLOTS + 32)
            {
                return Err(error(
                    "breakpoint replay requires a paused target and distinct install positions",
                ));
            }
            // A failed setup can leave QuickJS jobs queued. Isolate its engine
            // so they cannot affect callbacks installed by an earlier script.
            let realm = Realm::new(Engine::new()?)?;
            let mut ordinal = 0;
            let target = crate::script::breakpoint::StoppedTarget {
                pid: session.pid,
                root: session.root.to_path_buf(),
                tids: session.trace.threads.keys().copied().collect(),
                focus: session.held_tid,
            };
            let result = live::evaluate(
                &realm,
                &js,
                replaying,
                budget,
                target,
                &mut output,
                |request| {
                    ordinal += 1;
                    let requested_address = request.address;
                    let (location, tid) = if replaying {
                        let Some(point) = replay_points.remove(&ordinal) else {
                            return Ok(0);
                        };
                        if point.requested_address != requested_address
                            || point.kind != request.kind.name()
                            || point.module.is_empty()
                            || point.module.len() > 4096
                        {
                            return Err(error(
                                "the live script no longer matches its recorded breakpoint",
                            ));
                        }
                        (
                            Location::ModuleOffset {
                                module: point.module,
                                offset: point.offset,
                                execution: !matches!(request.kind, Kind::Watch { .. }),
                                instance: None,
                                symbol: None,
                            },
                            point.leader_only.then_some(session.pid),
                        )
                    } else {
                        (Location::Address(requested_address), request.tid)
                    };
                    if session.pending_breakpoint {
                        session.control(|_| Ok(()))?;
                    }
                    let id = ids.fetch_add(1, Ordering::Relaxed) + 1;
                    let location = PreparedLocation::resolve(session.pid, location, &[])?;
                    let program = Program::snapshot(Scope::Thread, request.timeout_ms)?;
                    let callback = request.handler.map(|handler| {
                        AttachedCallback::inline(Callback::new(
                            handler,
                            Rc::clone(&realm),
                            Limits {
                                max_hits: None,
                                pause_budget_ms: request.timeout_ms,
                            },
                        ))
                    });
                    session.install_stopped(id, location, program, request.kind, tid, callback)?;
                    breakpoint_ids.push(id);
                    session.live_sources.insert(
                        id,
                        LiveSource {
                            key: breakpoint_ids[0],
                            source: Arc::clone(&source),
                            ordinal,
                            requested_address,
                        },
                    );
                    Ok(id)
                },
            )
            .and_then(|evaluation| {
                if replaying && (breakpoint_ids.len() != replay_count || !replay_points.is_empty())
                {
                    return Err(error(
                        "the live script did not reinstall every recorded breakpoint",
                    ));
                }
                Ok(evaluation)
            });
            match result {
                Ok(result) => {
                    evaluation = Some(result);
                    Ok(())
                }
                Err(issue) => {
                    let installed = breakpoint_ids.drain(..).collect();
                    if let Err(rollback) = session.disarm_stopped(&installed) {
                        session.close_breakpoints();
                        return Err(error(format!(
                            "{issue}; live breakpoint rollback failed: {rollback}"
                        )));
                    }
                    Err(issue)
                }
            }
        };
        let setup = if self.paused && self.pending_breakpoint {
            setup(self)
        } else {
            self.control(setup)
        };
        let result = match setup.map(|()| evaluation.expect("live script ran")) {
            Ok(live::Evaluation::Continue(waiting)) => {
                self.live_script = Some(LiveScript {
                    output,
                    waiting,
                    reply,
                    ids: breakpoint_ids,
                    events: Vec::new(),
                    overflow: false,
                    was_paused: self.paused,
                    deadline: Instant::now() + budget,
                });
                self.paused = false;
                paused.store(false, Ordering::Relaxed);
                return;
            }
            Ok(live::Evaluation::ContinueReturning(value)) => {
                self.paused = false;
                paused.store(false, Ordering::Relaxed);
                Ok(value)
            }
            Ok(live::Evaluation::Complete(value)) => Ok(value),
            Err(issue) => Err(issue),
        };
        let mut result = live_result(breakpoint_ids, result, output);
        result.active = result
            .breakpoint_ids
            .iter()
            .filter_map(|id| {
                self.active
                    .get(id)
                    .map(|active| (*id, Arc::downgrade(active)))
            })
            .collect();
        let _ = reply.send(Ok(result));
    }

    pub(crate) fn finish_live_script(&mut self, paused: &AtomicBool, cancelled: bool) {
        let Some(script) = self.live_script.as_ref() else {
            return;
        };
        let exited = self.trace.exit.is_some();
        let exec = self.trace.exec_observed();
        let failure = if cancelled {
            Some("run ended while the live script was waiting for events")
        } else if exec {
            Some("target address space changed")
        } else if script.overflow {
            Some("live script event limit exceeded")
        } else if !exited && Instant::now() >= script.deadline {
            Some("live script timed out waiting for target exit")
        } else {
            None
        };
        if !exited && failure.is_none() {
            return;
        }
        let rollback = if failure.is_some() && !exited && !exec && !cancelled {
            let installed = script.ids.iter().copied().collect();
            self.paused = script.was_paused;
            paused.store(self.paused, Ordering::Relaxed);
            self.control(|session| session.disarm_stopped(&installed))
                .err()
        } else {
            None
        };
        let script = self.live_script.take().expect("pending live script");
        let result = if let Some(issue) = failure {
            if let Some(rollback) = rollback {
                self.close_breakpoints();
                Err(error(format!(
                    "{issue}; live breakpoint rollback failed: {rollback}"
                )))
            } else {
                Err(error(issue))
            }
        } else {
            script
                .events
                .iter()
                .map(|(event, _)| serde_json::to_value(event))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into)
                .and_then(|events| script.waiting.finish(&events))
        };
        let result = match result {
            Ok(value) => {
                for (event, capture) in script.events {
                    (self.publish)(event, capture);
                }
                Ok(value)
            }
            Err(issue) => Err(issue),
        };
        let _ = script
            .reply
            .send(Ok(live_result(script.ids, result, script.output)));
    }

    fn install_stopped(
        &mut self,
        id: u64,
        location: PreparedLocation,
        program: Program,
        kind: Kind,
        tid: Option<i32>,
        callback: Option<AttachedCallback>,
    ) -> Result<Installed> {
        if location.start.is_some_and(|start| start != self.start) {
            return Err(error("target identity changed during symbol resolution"));
        }
        if kind == Kind::Software && self.software.len() == 32 {
            return Err(error(
                "software breakpoint slots exhausted (32 per session)",
            ));
        }
        let thread = tid
            .map(|tid| {
                self.trace
                    .threads
                    .get(&tid)
                    .filter(|_| crate::procfs::task_path(self.root, tid).is_dir())
                    .map(|thread| (tid, thread.identity))
                    .ok_or_else(|| {
                        error(format!(
                            "thread {tid} is not a tracked thread of the target"
                        ))
                    })
            })
            .transpose()?;
        let rule = Rule {
            id,
            address: location.address,
            program,
            kind,
            thread,
        };
        self.place_stopped(rule, &location, None)?;
        if let Some(callback) = callback {
            self.callbacks.insert(id, callback);
        }
        self.active.insert(id, Arc::new(()));
        Ok(self.installed(rule))
    }

    fn installed(&self, rule: Rule) -> Installed {
        let callback = self.callbacks.get(&rule.id);
        let limits = callback.map(|callback| callback.runtime.limits);
        let version = callback.and_then(AttachedCallback::version);
        Installed {
            kind: rule.kind.name(),
            breakpoint_id: rule.id,
            address: hex(rule.address),
            stop_after_hit: rule.program.stop_after_hit,
            tid: rule.thread.map(|(tid, _)| tid),
            callback: limits,
            rule_id: version.map(|(id, _)| id),
            rule_revision: version.map(|(_, revision)| revision),
            active: Arc::downgrade(&self.active[&rule.id]),
        }
    }

    fn update(
        &mut self,
        id: u64,
        address: Option<u64>,
        source: Option<CallbackSource>,
        sender: Weak<mpsc::SyncSender<Command>>,
    ) -> Result<Installed> {
        let mut updated = None;
        self.control(|session| {
            let old = session
                .hardware
                .get(&id)
                .or_else(|| session.software.values().find(|rule| rule.id == id))
                .copied()
                .ok_or_else(|| {
                    crate::Diagnostic::new("BREAKPOINT_NOT_FOUND", "breakpoint ID not found", None)
                })?;
            let rule = Rule {
                address: address.unwrap_or(old.address),
                ..old
            };
            let replacement = session.attach(id, source, &rule.program, sender)?;
            if rule.address != old.address {
                let location =
                    PreparedLocation::resolve(session.pid, Location::Address(rule.address), &[])?;
                session.place_stopped(rule, &location, Some(old.address))?;
            }
            let previous = session
                .callbacks
                .get(&id)
                .and_then(AttachedCallback::version)
                .map_or(0, |(_, revision)| revision);
            if let Some(callback) = replacement {
                session.live_sources.remove(&id);
                session.callbacks.insert(id, callback);
            }
            if let Some(callback) = session.callbacks.get_mut(&id) {
                callback.follow_revision(previous);
            }
            updated = Some(session.installed(rule));
            Ok(())
        })?;
        Ok(updated.expect("update ran at a safe stop"))
    }

    fn place_stopped(
        &mut self,
        rule: Rule,
        location: &PreparedLocation,
        previous_address: Option<u64>,
    ) -> Result<()> {
        let address = rule.address;
        if self.software.contains_key(&address)
            || self.hardware.values().any(|other| {
                other.address == address
                    && (rule.kind != Kind::Hardware
                        || other.kind != Kind::Hardware
                        || rule.thread.is_none()
                        || other.thread.is_none()
                        || rule.thread == other.thread)
            })
        {
            return Err(error("a breakpoint already exists at this address"));
        }
        let watch_length = if let Kind::Watch { length, access } = rule.kind {
            if cfg!(target_arch = "x86_64") && access == WatchAccess::Read {
                return Err(crate::Diagnostic::new(
                    "UNSUPPORTED_WATCH_ACCESS",
                    "Hardware read-only watchpoints are unavailable on this architecture",
                    Some("Query breakpoint_capabilities for supported access modes."),
                )
                .into());
            }
            if !matches!(length, 1 | 2 | 4 | 8) || !address.is_multiple_of(length as u64) {
                return Err(error(
                    "watchpoint length must be 1, 2, 4, or 8 and the address must be aligned to length",
                ));
            }
            let end = address
                .checked_add(length as u64 - 1)
                .ok_or_else(|| error("invalid watchpoint range"))?;
            if modules::mapping_at(self.root, address)?.is_none_or(|map| !map.contains(end)) {
                return Err(error("watchpoint range is outside a mapped region"));
            }
            Some(length)
        } else {
            if !location.valid(self.root)? {
                return Err(error(
                    "breakpoint address no longer matches an executable mapping",
                ));
            }
            None
        };
        if rule.kind == Kind::Software {
            self.trace.patch(address)?;
            if let Some(previous) = previous_address {
                if let Err(issue) = self.trace.unpatch(previous) {
                    if let Err(rollback) = self.trace.unpatch(address) {
                        self.close_breakpoints();
                        return Err(error(format!(
                            "{issue}; software breakpoint rollback failed: {rollback}"
                        )));
                    }
                    return Err(issue);
                }
                self.software.remove(&previous);
            }
            self.software.insert(address, rule);
        } else {
            let mut proposed = self.hardware.clone();
            proposed.insert(rule.id, rule);
            self.replace_hardware(proposed)?;
        }
        if let Some(length) = watch_length {
            self.watch_values
                .insert(rule.id, self.trace.read_word(address, length).ok());
        }
        Ok(())
    }

    fn remove(&mut self, id: u64) -> Result<Option<Cleanup>> {
        let software = self.software.values().find(|rule| rule.id == id).copied();
        let hardware = self.hardware.contains_key(&id);
        if software.is_none() && !hardware {
            return Err(error("breakpoint ID not found"));
        }
        if !self.launched && self.software.len() + self.hardware.len() == 1 {
            return Ok(Some(self.close_breakpoints()));
        }
        self.control(|session| session.disarm_stopped(&BTreeSet::from([id])))?;
        Ok(None)
    }

    fn disarm_stopped(&mut self, ids: &BTreeSet<u64>) -> Result<()> {
        if ids.iter().any(|id| self.hardware.contains_key(id)) {
            let mut proposed = self.hardware.clone();
            proposed.retain(|id, _| !ids.contains(id));
            self.replace_hardware(proposed)?;
        }
        let patches: Vec<_> = self
            .software
            .values()
            .filter(|rule| ids.contains(&rule.id))
            .map(|rule| rule.address)
            .collect();
        for address in patches {
            self.trace.unpatch(address)?;
            self.software.remove(&address);
        }
        self.watch_values.retain(|id, _| !ids.contains(id));
        self.callbacks.retain(|id, _| !ids.contains(id));
        self.active.retain(|id, _| !ids.contains(id));
        self.live_sources.retain(|id, _| !ids.contains(id));
        Ok(())
    }

    fn runtime_poisoned(&self) -> bool {
        self.engine.as_ref().is_some_and(|engine| engine.poisoned())
            || self
                .callbacks
                .values()
                .any(|callback| callback.runtime.poisoned_group())
    }

    fn discard_poisoned_runtime(&mut self) -> Result<()> {
        if self.runtime_poisoned() {
            let ids = self
                .callbacks
                .iter()
                .filter_map(|(&id, callback)| callback.runtime.poisoned_group().then_some(id))
                .collect();
            self.disarm_stopped(&ids)?;
            if self.engine.as_ref().is_some_and(|engine| engine.poisoned()) {
                self.exports.clear();
                self.engine = None;
            }
        }
        Ok(())
    }

    pub(crate) fn remove_exhausted(&mut self) -> Result<bool> {
        if self.runtime_poisoned() {
            self.control(|_| Ok(()))?;
        }
        let ids: BTreeSet<_> = self
            .callbacks
            .iter()
            .filter(|(_, callback)| callback.runtime.exhausted())
            .map(|(&id, _)| id)
            .chain(
                self.hardware
                    .values()
                    .chain(self.software.values())
                    .filter(|rule| {
                        rule.thread.is_some_and(|(tid, identity)| {
                            self.trace
                                .threads
                                .get(&tid)
                                .is_none_or(|thread| thread.identity != identity)
                        })
                    })
                    .map(|rule| rule.id),
            )
            .collect();
        for id in ids {
            match self.remove(id) {
                Ok(Some(cleanup)) => {
                    if !cleanup.ok() {
                        return Err(error(
                            "could not cleanly detach the completed breakpoint callback",
                        ));
                    }
                    return Ok(true);
                }
                Ok(None) => (),
                Err(issue) => {
                    // A one-shot callback may have resumed a target that
                    // exited before the disarm could freeze it again.
                    self.trace.poll()?;
                    if self.trace.exit.is_some()
                        || (!self.launched && self.trace.threads.is_empty())
                    {
                        return Ok(true);
                    }
                    return Err(issue);
                }
            }
        }
        Ok(false)
    }

    fn close_breakpoints(&mut self) -> Cleanup {
        let cleanup = self.trace.close();
        self.software.clear();
        self.hardware.clear();
        self.watch_values.clear();
        self.callbacks.clear();
        self.active.clear();
        self.live_sources.clear();
        self.exports.clear();
        self.engine = None;
        cleanup
    }

    fn replace_hardware(&mut self, proposed: BTreeMap<u64, Rule>) -> Result<()> {
        let mut changes = Vec::new();
        for (&tid, thread) in &self.trace.threads {
            if thread.stop.is_none() {
                continue;
            }
            let previous = Self::thread_slots(&self.hardware, tid, thread.identity)?;
            let next = Self::thread_slots(&proposed, tid, thread.identity)?;
            if previous.map(|slot| slot.map(|rule| (rule.id, rule.address, rule.kind)))
                != next.map(|slot| slot.map(|rule| (rule.id, rule.address, rule.kind)))
            {
                changes.push((tid, previous, next));
            }
        }
        for (index, (tid, _, next)) in changes.iter().enumerate() {
            if let Err(issue) = Self::program_slots(*tid, next) {
                let mut failure = None;
                // A bank may have been partially written before the failing operation.
                for (tid, previous, _) in changes[..=index].iter().rev() {
                    if let Err(rollback) = Self::program_slots(*tid, previous) {
                        failure.get_or_insert(rollback);
                    }
                }
                if let Some(rollback) = failure {
                    self.close_breakpoints();
                    return Err(error(format!(
                        "{issue}; hardware breakpoint rollback failed: {rollback}"
                    )));
                }
                return Err(issue);
            }
        }
        self.hardware = proposed;
        Ok(())
    }

    fn control(&mut self, update: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        self.refresh_callbacks();
        let deadline = Instant::now() + CONTROL_BUDGET;
        let frozen = self.trace.freeze(deadline);
        if self.trace.exec_observed() || self.trace.foreign_software {
            if !self.launched {
                self.close_breakpoints();
            }
            return Err(error("target address space changed"));
        }
        self.trace.rewind_software_stops()?;
        let mut hits = self.hits()?;
        self.observe_writes(&mut hits);
        let mut captured = if std::mem::take(&mut self.pending_breakpoint) {
            Vec::new()
        } else {
            self.capture_hits(hits, frozen.is_ok())
        };
        let stepping = self
            .complete_hardware_hits(frozen.is_ok(), &mut captured)
            .and_then(|()| self.step_software_stops(frozen.is_ok(), &mut captured));
        let stepping = stepping.and_then(|()| self.consume_hardware_stops());
        let hold = captured
            .iter()
            .find_map(|(hit, _)| hit.rule.program.stop_after_hit.then_some(hit.tid));
        let mut result = Ok(());
        let resume = stepping.and_then(|()| {
            result = frozen.and_then(|()| {
                self.discard_poisoned_runtime()?;
                let updated = update(self);
                self.discard_poisoned_runtime()?;
                updated
            });
            if self.runtime_poisoned() && result.is_err() {
                return Err(error("could not disarm a failed live script runtime"));
            }
            if let Some(tid) = hold {
                self.hold_at(tid);
            }
            if self.launched {
                Ok(())
            } else {
                self.resume_stopped()
            }
        });
        self.finish_hits(
            captured,
            resume.as_ref().err().map(|error| error.as_ref()),
            hold.is_some() && resume.is_ok(),
        );
        if let Err(e) = resume {
            self.close_breakpoints();
            return Err(e);
        }
        result
    }

    fn thread_slots(rules: &BTreeMap<u64, Rule>, tid: i32, identity: u64) -> Result<Slots> {
        let mut slots = [None; SLOTS];
        for (index, rule) in rules
            .values()
            .filter(|rule| rule.applies(tid, identity))
            .enumerate()
        {
            let slot = slots.get_mut(index).ok_or_else(|| {
                error(format!(
                    "hardware breakpoint slots exhausted on thread {tid}"
                ))
            })?;
            *slot = Some(*rule);
        }
        Ok(slots)
    }

    fn program_stopped(&self, rules: &BTreeMap<u64, Rule>) -> Result<()> {
        for (&tid, thread) in &self.trace.threads {
            if thread.stop.is_some() {
                let slots = Self::thread_slots(rules, tid, thread.identity)?;
                Self::program_slots(tid, &slots)?;
            }
        }
        Ok(())
    }

    fn program_slots(tid: i32, slots: &Slots) -> Result<()> {
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
        })
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
                    if let Some(&rule) = self
                        .software
                        .get(&address)
                        .filter(|rule| rule.applies(tid, thread.identity))
                    {
                        hits.push(Hit {
                            tid,
                            pc: address,
                            rule,
                            observed,
                            unix_ms,
                            watch: None,
                        });
                    }
                }
                Some(Stop::Breakpoint {
                    slots,
                    address,
                    observed,
                    unix_ms,
                }) => {
                    let pc = regs::read(tid)?.stack.get(regs::PC)?;
                    let arm_distance = |rule: &Rule| match (rule.kind, address) {
                        (Kind::Hardware, Some(address)) if address == pc && rule.address == pc => {
                            Some(0)
                        }
                        (Kind::Watch { length, .. }, Some(address)) if address != pc => {
                            let offset = address.saturating_sub(rule.address);
                            Some(if address < rule.address {
                                rule.address - address
                            } else {
                                offset.saturating_sub(length as u64 - 1)
                            })
                        }
                        _ => None,
                    };
                    let installed = Self::thread_slots(&self.hardware, tid, thread.identity)?;
                    let nearest = if cfg!(target_arch = "aarch64") {
                        installed.iter().flatten().filter_map(arm_distance).min()
                    } else {
                        None
                    };
                    for (slot, rule) in installed.iter().enumerate() {
                        let Some(rule) = *rule else { continue };
                        if (cfg!(target_arch = "aarch64")
                            && nearest.is_some()
                            && arm_distance(&rule) == nearest)
                            || (slots & (1 << slot) != 0
                                && (rule.kind != Kind::Hardware || rule.address == pc))
                        {
                            hits.push(Hit {
                                tid,
                                pc,
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
        if cfg!(target_arch = "aarch64") {
            return;
        }
        let mut counts = BTreeMap::new();
        for hit in hits.iter() {
            *counts.entry(hit.rule.id).or_insert(0) += 1;
        }
        for hit in hits {
            let Kind::Watch { length, access } = hit.rule.kind else {
                continue;
            };
            let after = self.trace.read_word(hit.rule.address, length).ok();
            let before = self
                .watch_values
                .insert(hit.rule.id, after)
                .flatten()
                .filter(|_| counts[&hit.rule.id] == 1);
            hit.watch = Some(WatchObservation {
                length,
                access: access.name(),
                write_observed: access.write_observed(),
                value_before: before,
                value_after: after,
                value_before_decimal: before,
                value_after_decimal: after,
                value_changed: before.zip(after).map(|(a, b)| a != b),
                reported_address: None,
                attribution: None,
            });
        }
    }

    fn step_arm_hardware_stops(
        &mut self,
        frozen: bool,
        captured: &mut [CapturedHit],
    ) -> Result<()> {
        if !cfg!(target_arch = "aarch64") {
            return Ok(());
        }
        let pending: Vec<_> = self
            .trace
            .threads
            .iter()
            .filter_map(|(&tid, thread)| {
                if let Some(Stop::Breakpoint { address, .. }) = thread.stop {
                    Some((tid, address))
                } else {
                    None
                }
            })
            .collect();
        if !pending.is_empty() && !frozen {
            return Err(error(
                "could not freeze peer threads for hardware single-step",
            ));
        }
        for (tid, reported) in pending {
            let mut watches = Vec::new();
            for (hit, _) in captured.iter_mut().filter(|(hit, _)| hit.tid == tid) {
                if let Kind::Watch { length, access } = hit.rule.kind {
                    let before = self.trace.read_word(hit.rule.address, length).ok();
                    watches.push((hit, length, access, before));
                }
            }
            let unambiguous = watches.len() == 1;
            disarm(tid)?;
            let stop = self.trace.step_one(tid, Instant::now() + CONTROL_BUDGET)?;
            if self.trace.exec_observed() || self.trace.foreign_software {
                return Err(error(
                    "target address space changed during hardware single-step",
                ));
            }
            if let Some(thread) = self.trace.threads.get(&tid).filter(|_| stop.is_some()) {
                hardware::program(
                    tid,
                    &Self::thread_slots(&self.hardware, tid, thread.identity)?,
                )?;
            }
            for (hit, length, access, before) in watches {
                let exact = unambiguous
                    && reported.is_some_and(|a| {
                        a.checked_sub(hit.rule.address)
                            .is_some_and(|offset| offset < length as u64)
                    });
                let after = matches!(stop, Some(Stop::Step))
                    .then(|| self.trace.read_word(hit.rule.address, length).ok())
                    .flatten();
                hit.watch = Some(WatchObservation {
                    length,
                    access: access.name(),
                    write_observed: (exact && after.is_some())
                        .then(|| access.write_observed())
                        .flatten(),
                    value_before: before,
                    value_after: after,
                    value_before_decimal: before,
                    value_after_decimal: after,
                    value_changed: before.zip(after).map(|(a, b)| a != b),
                    reported_address: reported.map(hex),
                    attribution: Some(if exact { "exact" } else { "approximate" }),
                });
            }
        }
        Ok(())
    }

    fn step_software_stops(&mut self, frozen: bool, captured: &mut Vec<CapturedHit>) -> Result<()> {
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
            let pending_rearm =
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
                let mut after = self.capture_hits(hits, true);
                self.complete_hardware_hits(true, &mut after)?;
                if pending_rearm {
                    self.trace.rearm_software(address)?;
                }
                captured.extend(after);
            }
        }
        Ok(())
    }

    fn hit_deadline(&self, hit: &Hit) -> Instant {
        let budget = self
            .callbacks
            .get(&hit.rule.id)
            .map_or(hit.rule.program.budget, |callback| {
                Duration::from_millis(u64::from(callback.runtime.limits.pause_budget_ms))
            });
        hit.observed + budget
    }

    fn capture_hits(&mut self, hits: Vec<Hit>, frozen: bool) -> Vec<CapturedHit> {
        // All already-stopped threads share the earliest active deadline.
        let deadline = hits
            .iter()
            .filter(|hit| {
                self.callbacks
                    .get(&hit.rule.id)
                    .is_none_or(|cb| !cb.runtime.exhausted())
            })
            .map(|hit| self.hit_deadline(hit))
            .min();
        hits.into_iter()
            .map(|hit| {
                let mut outcome = Outcome {
                    stop_context: None,
                    pending: None,
                    rule: None,
                    snapshot: None,
                    callback: None,
                };
                if let Some(callback) = self.callbacks.get(&hit.rule.id) {
                    if !callback.runtime.exhausted() {
                        let deadline = deadline.expect("active hit");
                        let state = if Instant::now() >= deadline {
                            Err(error("callback pause budget exceeded"))
                        } else {
                            regs::read(hit.tid).map(|regs| HitState {
                                pid: self.pid,
                                tid: hit.tid,
                                address: hit.rule.address,
                                kind: hit.rule.kind.name(),
                                registers: regs.general,
                                stack: regs.stack,
                                proc_root: self.root.to_owned(),
                                watch: None,
                            })
                        };
                        if cfg!(target_arch = "aarch64")
                            && matches!(hit.rule.kind, Kind::Watch { .. })
                        {
                            outcome.pending = Some((state, deadline));
                        } else {
                            self.run_callback(&hit, &mut outcome, state, deadline, frozen);
                        }
                    }
                } else {
                    let deadline = deadline.expect("active hit");
                    outcome.snapshot = Some(hit.rule.program.execute(self, &hit, deadline, frozen));
                }
                if matches!(hit.rule.kind, Kind::Watch { .. })
                    && let Some(deadline) = deadline
                {
                    outcome.stop_context = Some(self.watch_context(&hit, deadline));
                }
                (hit, outcome)
            })
            .collect()
    }

    fn watch_context(&self, hit: &Hit, deadline: Instant) -> serde_json::Value {
        use serde_json::json;

        let deadline = deadline.min(Instant::now() + Duration::from_millis(25));
        let mut site = json!({"address": hex(hit.pc)});
        if Instant::now() < deadline
            && let Ok(location) = symbols::resolve(self.pid, hit.pc, &[])
        {
            site = location.stop_site();
        }
        let watched = if Instant::now() < deadline {
            symbols::resolve(self.pid, hit.rule.address, &[])
                .ok()
                .and_then(|location| location.symbol_location())
        } else {
            None
        };
        let args = match regs::read(hit.tid) {
            Ok(regs) => symbols::inspect::stopped_arguments(
                self.pid,
                self.root,
                &self.trace,
                regs.stack,
                deadline,
            ),
            Err(error) => json!({"status": "unavailable", "items": [], "issue": error.to_string()}),
        };
        json!({"site": site, "watched_symbol": watched, "args": args})
    }

    fn complete_hardware_hits(&mut self, frozen: bool, captured: &mut [CapturedHit]) -> Result<()> {
        self.step_arm_hardware_stops(frozen, captured)?;
        for (hit, outcome) in captured {
            if let Some((state, deadline)) = outcome.pending.take() {
                self.run_callback(hit, outcome, state, deadline, frozen);
            }
        }
        Ok(())
    }

    fn run_callback(
        &mut self,
        hit: &Hit,
        outcome: &mut Outcome,
        state: Result<HitState>,
        deadline: Instant,
        frozen: bool,
    ) {
        let state = state.and_then(|mut state| {
            if cfg!(target_arch = "aarch64")
                && matches!(hit.rule.kind, Kind::Watch { .. })
                && Instant::now() < deadline
            {
                state.stack = regs::read(hit.tid)?.stack;
            }
            state.watch = hit.watch.as_ref().map(|watch| WatchState {
                before: watch.value_before,
                after: watch.value_after,
                changed: watch.value_changed,
            });
            Ok(state)
        });
        let callback = self
            .callbacks
            .get_mut(&hit.rule.id)
            .expect("armed callback");
        if !callback.runtime.exhausted() {
            outcome.rule = callback.version();
            callback.count_hit();
            let report = callback.runtime.run(state, deadline);
            if report.snapshot {
                outcome.snapshot = Some(hit.rule.program.execute(self, hit, deadline, frozen));
            }
            outcome.callback = Some(report);
        }
    }

    fn finish_hits(
        &mut self,
        captured: Vec<CapturedHit>,
        resume: Option<&(dyn std::error::Error + Send + Sync)>,
        held: bool,
    ) {
        for (hit, mut outcome) in captured {
            let pause_ms = hit.observed.elapsed().as_millis() as u64;
            let capture_status = if let Some(snapshot) = &mut outcome.snapshot {
                snapshot.snapshot.trace_window_ms = Some(pause_ms);
                snapshot.snapshot.status
            } else if let Some(callback) = &outcome.callback {
                if callback.suppressed && resume.is_none() && !held {
                    continue;
                }
                callback.status
            } else {
                continue;
            };
            let event = Event {
                breakpoint_id: hit.rule.id,
                rule_id: outcome.rule.map(|(id, _)| id),
                rule_revision: outcome.rule.map(|(_, revision)| revision),
                pid: self.pid,
                tid: hit.tid,
                address: hex(hit.rule.address),
                instruction_pc: hex(hit.pc),
                pc_relation: if cfg!(target_arch = "x86_64") && hit.watch.is_some() {
                    "after_instruction"
                } else {
                    "at_instruction"
                },
                stop_context: outcome.stop_context,
                scope: hit.rule.program.scope.name(),
                observed_unix_ms: hit.unix_ms,
                pause_ms,
                capture_status,
                resume_status: if held {
                    "stopped"
                } else if resume.is_none() {
                    "resumed"
                } else {
                    "failed"
                },
                detail: resume.map(ToString::to_string),
                kind: hit.rule.kind.name(),
                watch: hit.watch,
                callback: outcome.callback,
            };
            if let Some(script) = self
                .live_script
                .as_mut()
                .filter(|script| script.ids.contains(&event.breakpoint_id))
            {
                if script.events.len() < 64 {
                    script.events.push((event, outcome.snapshot));
                } else {
                    script.overflow = true;
                }
            } else {
                (self.publish)(event, outcome.snapshot);
            }
        }
    }

    fn refresh_callbacks(&mut self) {
        self.exports.prune();
        let mut batch = BTreeMap::new();
        for callback in self.callbacks.values_mut() {
            if let Some(key) = callback.refresh(&mut batch) {
                self.exports.remove(key);
            }
        }
    }

    pub(crate) fn handle_stops(&mut self) -> Result<()> {
        if self.stopped().is_empty() {
            return Ok(());
        }
        self.refresh_callbacks();
        let needs_software_freeze = self.trace.threads.values().any(|thread| {
            matches!(thread.stop, Some(Stop::Software { .. }))
                || cfg!(target_arch = "aarch64")
                    && matches!(thread.stop, Some(Stop::Breakpoint { .. }))
        });
        let initial = self.hits()?;
        let capture_deadline = initial
            .iter()
            .any(|hit| matches!(hit.rule.program.scope, Scope::Process))
            .then(|| initial.iter().map(|hit| self.hit_deadline(hit)).min())
            .flatten();
        let deadline =
            if needs_software_freeze || initial.iter().any(|hit| hit.rule.program.stop_after_hit) {
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
        let mut captured = if std::mem::take(&mut self.pending_breakpoint) {
            Vec::new()
        } else {
            self.capture_hits(hits, frozen)
        };
        let hold = captured
            .iter()
            .find_map(|(hit, _)| hit.rule.program.stop_after_hit.then_some(hit.tid));
        // AArch64 watchpoints need a single-step to finish their before/after observation.
        let watch_needs_step = cfg!(target_arch = "aarch64")
            && captured
                .iter()
                .any(|(hit, _)| matches!(hit.rule.kind, Kind::Watch { .. }));
        if let Some(tid) = hold.filter(|_| !watch_needs_step) {
            if !frozen {
                self.trace.freeze(Instant::now() + CONTROL_BUDGET)?;
                self.trace.rewind_software_stops()?;
            }
            self.hold_at(tid);
            self.pending_breakpoint = true;
            self.finish_hits(captured, None, true);
            return Ok(());
        }
        let resume = self
            .complete_hardware_hits(frozen, &mut captured)
            .and_then(|()| self.step_software_stops(frozen, &mut captured))
            .and_then(|()| {
                if self.runtime_poisoned() {
                    self.consume_hardware_stops()?;
                    if !frozen {
                        self.trace.freeze(Instant::now() + CONTROL_BUDGET)?;
                        self.trace.rewind_software_stops()?;
                        let mut hits = self.hits()?;
                        self.observe_writes(&mut hits);
                        let mut extra = self.capture_hits(hits, true);
                        self.complete_hardware_hits(true, &mut extra)?;
                        self.step_software_stops(true, &mut extra)?;
                        self.consume_hardware_stops()?;
                        captured.extend(extra);
                    }
                    self.discard_poisoned_runtime()?;
                }
                if let Some(tid) = hold {
                    self.hold_at(tid);
                    self.consume_hardware_stops()
                } else {
                    self.held_tid = None;
                    self.resume_stopped()
                }
            });
        self.finish_hits(
            captured,
            resume.as_ref().err().map(|error| error.as_ref()),
            hold.is_some() && resume.is_ok(),
        );
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

    fn consume_hardware_stops(&mut self) -> Result<()> {
        // A consumed stop must not be attributed again after slots move.
        for tid in self.stopped() {
            if matches!(self.trace.threads[&tid].stop, Some(Stop::Breakpoint { .. })) {
                self.prepare_hardware_resume(tid)?;
                self.trace.threads.get_mut(&tid).unwrap().stop = Some(Stop::Interrupt);
            }
        }
        Ok(())
    }

    fn prepare_hardware_resume(&self, tid: i32) -> Result<()> {
        let thread = &self.trace.threads[&tid];
        let Some(Stop::Breakpoint { slots, .. }) = thread.stop else {
            return Ok(());
        };
        let pc = regs::read(tid)?.stack.get(regs::PC)?;
        let installed = Self::thread_slots(&self.hardware, tid, thread.identity)?;
        let execution = installed.iter().enumerate().any(|(index, rule)| {
            slots & (1 << index) != 0
                && rule.is_some_and(|rule| rule.kind == Kind::Hardware && rule.address == pc)
        });
        hardware::prepare_resume(tid, execution)
    }

    fn resume(&mut self, tid: i32) -> Result<()> {
        let thread = &self.trace.threads[&tid];
        if thread.newborn {
            hardware::program(
                tid,
                &Self::thread_slots(&self.hardware, tid, thread.identity)?,
            )?;
        }
        if matches!(thread.stop, Some(Stop::Software { .. })) {
            return Err(error(
                "pending software breakpoint must execute its original instruction",
            ));
        }
        if matches!(thread.stop, Some(Stop::Breakpoint { .. })) {
            self.prepare_hardware_resume(tid)?;
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
    use super::{HardwareSlots, Kind, Slots};
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
        program_raw(
            tid,
            &slots.map(|rule| rule.map(|rule| (rule.address, rule.kind))),
        )
    }

    pub(super) fn program_raw(tid: i32, slots: &HardwareSlots) -> Result<()> {
        debug_register(tid, 7, 0)?;
        let mut control = 0;
        for (index, slot) in slots.iter().enumerate() {
            if let Some((address, kind)) = *slot {
                debug_register(tid, index, address)?;
                control |= 1 << (2 * index); // Local enable.
                if let Kind::Watch { length, access } = kind {
                    let width = match length {
                        1 => 0,
                        2 => 1,
                        4 => 3,
                        8 => 2,
                        _ => unreachable!(),
                    };
                    control |= ((if access == super::WatchAccess::ReadWrite {
                        3
                    } else {
                        1
                    }) | (width << 2))
                        << (16 + 4 * index);
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

#[cfg(target_arch = "aarch64")]
#[path = "breakpoint/arm64.rs"]
mod hardware;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reused_tid_does_not_inherit_scoped_hardware_slots() {
        let all = Rule {
            id: 1,
            address: 0x1000,
            program: Program::snapshot(Scope::Thread, 100).unwrap(),
            kind: Kind::Hardware,
            thread: None,
        };
        let scoped = Rule {
            id: 2,
            address: 0x2000,
            thread: Some((1234, 1)),
            ..all
        };
        let rules = BTreeMap::from([(all.id, all), (scoped.id, scoped)]);
        let installed = |identity| {
            Session::thread_slots(&rules, 1234, identity)
                .unwrap()
                .into_iter()
                .flatten()
                .map(|rule| rule.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(installed(1), [1, 2]);
        assert_eq!(installed(2), [1]);
    }
}
