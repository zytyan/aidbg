pub(super) mod dwarf;
mod events;
mod files;
mod inferior;
mod instruction;
mod link;
mod native_value;
mod process_io;
mod source_map;
mod syscalls;
mod target;

use self::target::{Event, Live, Target};
use super::{MAX_SOURCE_BYTES, compiler::Compiler};
use crate::{Result, error, procfs, regs, rpc::*};
use rquickjs::{
    CatchResultExt, Context, Ctx, Exception, Function, Module, Object, Promise, Runtime,
    Value as JsValue,
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_GLOBALS: usize = 1024 * 1024;
const MAX_PENDING: usize = 64;
const SCRIPT_SLICE: Duration = Duration::from_secs(2);
const TICK: Duration = Duration::from_millis(5);

fn append_exit_status(output: &mut Value, exit: Option<crate::trace::LaunchExit>) {
    match exit {
        Some(crate::trace::LaunchExit::Code(code)) => output["exitCode"] = json!(code),
        Some(crate::trace::LaunchExit::Signal(signal)) => output["exitSignal"] = json!(signal),
        None => {}
    }
}

pub enum Command {
    Run(RunProcessRequest),
    Attach(i32),
    Core(OpenCoreRequest),
    Script(String),
    Input(String, std::result::Result<String, String>),
    Snapshot(Option<i32>, bool),
    Processes(crate::rpc::ProcessListRequest),
    SyscallTable(Option<u64>, Option<String>),
    SetForkPolicy(String),
    Result(Result<Value>),
}

type Message = (Command, oneshot::Sender<ToolReply>);

pub struct Worker {
    queue: mpsc::SyncSender<Message>,
    cancelled: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    pub fn start(state_dir: PathBuf) -> Result<Self> {
        let (queue, commands) = mpsc::sync_channel(32);
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let thread = thread::Builder::new()
            .name("aidbg-session".into())
            .spawn(move || {
                if let Err(err) = run(state_dir, commands, flag) {
                    eprintln!("aidbg session: {err}");
                }
            })?;
        Ok(Self {
            queue,
            cancelled,
            thread: Some(thread),
        })
    }

    pub fn request(&self, cmd: Command) -> Result<oneshot::Receiver<ToolReply>> {
        let (send, receive) = oneshot::channel();
        self.queue.try_send((cmd, send)).map_err(|err| match err {
            mpsc::TrySendError::Full(_) => error("debugger session queue is full"),
            mpsc::TrySendError::Disconnected(_) => error("debugger session has ended"),
        })?;
        Ok(receive)
    }

    pub fn shutdown(mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

struct Waiting {
    tid: Option<i32>,
    deadline: Instant,
    payload: Value,
}

struct State {
    target: Option<Target>,
    released_output: VecDeque<(i32, process_io::ProcessIo, Option<crate::trace::LaunchExit>)>,
    follow_fork: bool,
    generation: u64,
    state_dir: PathBuf,
    cancelled: Arc<AtomicBool>,
    waiting: BTreeMap<String, Waiting>,
    next_handler: u64,
    output: VecDeque<ScriptOutput>,
    output_size: usize,
    output_dropped: bool,
    target_error: Option<String>,
    signals: BTreeSet<i32>,
    events: events::Queue,
    dispatches: BTreeMap<i32, Vec<u64>>,
    reported_signals: VecDeque<Value>,
    started: Instant,
    source_maps: BTreeMap<u64, source_map::SourceMap>,
    timers: BTreeMap<u64, Instant>,
    next_timer: u64,
}

impl State {
    fn replace(&mut self, target: Option<Target>) -> Vec<i32> {
        let mut released = Vec::new();
        if let Some(Target::Live(mut previous)) = std::mem::replace(&mut self.target, target) {
            released.push(previous.pid);
            if let Some(stdio) = &mut previous.stdio {
                let _ = stdio.drain();
                self.released_output
                    .retain(|(pid, _, _)| *pid != previous.pid);
                self.released_output.push_back((
                    previous.pid,
                    stdio.archive_output(),
                    previous.trace.exit,
                ));
                if self.released_output.len() > 8 {
                    self.released_output.pop_front();
                }
            }
        }
        if let Some(Target::Live(live)) = &mut self.target {
            live.trace.follow_fork = self.follow_fork;
        }
        self.generation += 1;
        self.signals.clear();
        self.events.reset();
        self.dispatches.clear();
        self.reported_signals.clear();
        self.timers.clear();
        self.source_maps.clear();
        self.target_error = None;
        released
    }

    fn log(&mut self, script_id: u64, value: Value) {
        let json = value.to_string().into_bytes();
        if json.len() > MAX_OUTPUT {
            self.output_dropped = true;
            return;
        }
        while self.output_size + json.len() + 16 > MAX_OUTPUT {
            let Some(oldest) = self.output.pop_front() else {
                self.output_dropped = true;
                return;
            };
            self.output_size -= oldest.json.len() + 16;
            self.output_dropped = true;
        }
        self.output_size += json.len() + 16;
        self.output.push_back(ScriptOutput { script_id, json });
    }

    fn complete_callback(
        &mut self,
        tid: i32,
        token: u64,
        pause: Option<bool>,
        pass: Option<bool>,
        counts: &Value,
    ) {
        let Some(sequences) = self
            .dispatches
            .get(&tid)
            .filter(|sequences| sequences.first() == Some(&token))
        else {
            return;
        };
        let interested = sequences
            .iter()
            .any(|&sequence| self.events.interested(sequence));
        let pause = pause.or(interested
            .then_some(true)
            .filter(|_| sequences.iter().any(|&seq| self.events.is_breakpoint(seq))));
        let Some(Target::Live(live)) = &mut self.target else {
            return;
        };
        live.finish_callback(tid, pause, pass);
        let held = live.paused.contains(&tid);
        for sequence in self.dispatches.remove(&tid).unwrap() {
            live.track_stop(tid, sequence);
            self.events
                .complete(sequence, held, counts[sequence.to_string()].as_u64());
            if let Some(report) = self
                .reported_signals
                .iter_mut()
                .find(|row| row["sequence"] == sequence)
            {
                report["paused"] = json!(held);
            }
        }
    }

    fn register_event(&mut self, args: Value) -> Result<Value> {
        let request: events::Request = serde_json::from_value(args.clone())?;
        self.target.as_mut().ok_or_else(no_target)?.live()?;
        let (id, resume) = self.events.register(&request)?;
        if let Some((tid, token)) = args["handoffTid"].as_i64().zip(args["handoff"].as_u64()) {
            if self
                .dispatches
                .get(&(tid as i32))
                .and_then(|values| values.first())
                .copied()
                != Some(token)
            {
                self.events.remove(id);
                return Err(error("the callback no longer controls this stop"));
            }
            let pass = args["pass"].as_bool();
            self.complete_callback(
                tid as i32,
                token,
                Some(pass.is_none()),
                pass,
                &args["counts"],
            );
        }
        if resume {
            let live = self.target.as_mut().unwrap().live()?;
            if let Err(err) = live.continue_threads(request.tid) {
                self.events.remove(id);
                return Err(err);
            }
        }
        Ok(json!(id))
    }

    fn report_error(
        &mut self,
        id: Option<u64>,
        kind: &str,
        message: String,
        stack: Option<String>,
    ) {
        let mut report = json!({"kind":kind,"error":message,"message":message});
        let mut origin = None;
        if let Some(stack) = stack {
            let (stack, script, location) = source_map::remap(&stack, &self.source_maps);
            origin = script;
            report["stack"] = json!(stack);
            if let Some(location) = location {
                report["file"] = json!(location.file);
                report["line"] = json!(location.line);
                report["column"] = json!(location.column);
            }
        }
        let id = id.or(origin);
        if let Some(id) = id {
            report["scriptId"] = json!(id);
        }
        self.log(id.unwrap_or_default(), report);
    }

    fn operation(&mut self, op: &str, args: Value) -> Result<Value> {
        match op {
            "clock" => Ok(json!(self.started.elapsed().as_millis() as u64)),
            "reportError" => {
                self.report_error(
                    None,
                    args["kind"].as_str().unwrap_or("callback_error"),
                    args["message"]
                        .as_str()
                        .unwrap_or("script callback failed")
                        .into(),
                    args["stack"].as_str().map(str::to_owned),
                );
                Ok(Value::Null)
            }
            "setTimer" => {
                if self.timers.len() >= 1024 {
                    return Err(error("too many pending script timers"));
                }
                let ms = args["ms"]
                    .as_u64()
                    .filter(|&ms| ms <= 86_400_000)
                    .ok_or_else(|| error("timer duration must be in 0..=86400000 milliseconds"))?;
                self.next_timer += 1;
                self.timers
                    .insert(self.next_timer, Instant::now() + Duration::from_millis(ms));
                Ok(json!(self.next_timer))
            }
            "clearTimer" => {
                if let Some(id) = args["id"].as_u64() {
                    self.timers.remove(&id);
                }
                Ok(Value::Null)
            }
            "eventWait" => self.register_event(args),
            "waitOutput" => {
                let tid = args["tid"]
                    .as_i64()
                    .and_then(|tid| i32::try_from(tid).ok())
                    .filter(|&tid| tid > 0)
                    .ok_or_else(|| error("invalid thread ID"))?;
                let (stdio, exit, released, ended) = match self.target.as_mut() {
                    Some(Target::Live(live))
                        if live.pid == tid || live.trace.threads.contains_key(&tid) =>
                    {
                        (
                            live.stdio
                                .as_mut()
                                .ok_or_else(|| error("target has no captured output"))?,
                            live.trace.exit,
                            false,
                            live.trace.threads.is_empty(),
                        )
                    }
                    _ => self
                        .released_output
                        .iter_mut()
                        .find(|(pid, _, _)| *pid == tid)
                        .map(|(_, stdio, exit)| (stdio, *exit, true, exit.is_some()))
                        .ok_or_else(|| error("target has no captured output"))?,
                };
                stdio.drain()?;
                let (mut result, drained) = stdio.wait_output();
                result["released"] = json!(released);
                result["ended"] = json!(ended && drained);
                if drained {
                    append_exit_status(&mut result, exit);
                }
                Ok(result)
            }
            "ask" => {
                if self.waiting.len() >= MAX_PENDING {
                    return Err(error("too many waiting input handlers"));
                }
                let payload = &args["payload"];
                if !payload.is_object() && !payload.is_array() {
                    return Err(error("ask requires a JSON object or array"));
                }
                if payload.to_string().len() > 16 * 1024 {
                    return Err(error("ask payload exceeds 16 KiB"));
                }
                let timeout = args["timeoutMs"]
                    .as_u64()
                    .unwrap_or(events::DEFAULT_TIMEOUT_MS);
                if timeout > 86_400_000 {
                    return Err(error("timeoutMs must be in 0..=86400000"));
                }
                let tid = args["tid"].as_i64().map(i32::try_from).transpose()?;
                self.next_handler += 1;
                let handler = format!("input-{}", self.next_handler);
                self.waiting.insert(
                    handler.clone(),
                    Waiting {
                        tid,
                        payload: payload.clone(),
                        deadline: Instant::now() + Duration::from_millis(timeout),
                    },
                );
                Ok(json!(handler))
            }
            "signal" => {
                self.target
                    .as_mut()
                    .ok_or_else(no_target)?
                    .live()?
                    .verify()?;
                let signal = signal_number(&args["signal"])?;
                if args["remove"] == true {
                    self.signals.remove(&signal);
                } else {
                    self.signals.insert(signal);
                }
                Ok(json!(signal))
            }
            "callbackDone" => {
                if args["generation"].as_u64() == Some(self.generation)
                    && let Some(tid) = args["tid"].as_i64().and_then(|tid| i32::try_from(tid).ok())
                    && let Some(token) = args["token"].as_u64()
                {
                    self.complete_callback(
                        tid,
                        token,
                        args["pause"].as_bool(),
                        args["pass"].as_bool(),
                        &args["counts"],
                    );
                }
                Ok(Value::Null)
            }
            "passSignal" => {
                if args["generation"].as_u64() != Some(self.generation) {
                    return Err(error("this signal stop is no longer pending"));
                }
                let tid = args["tid"]
                    .as_i64()
                    .and_then(|n| i32::try_from(n).ok())
                    .ok_or_else(|| error("invalid thread ID"))?;
                let sequence = serde_json::from_value(args["sequence"].clone())?;
                let pass = args["pass"]
                    .as_bool()
                    .ok_or_else(|| error("expected a boolean signal decision"))?;
                self.target
                    .as_mut()
                    .ok_or_else(no_target)?
                    .live()?
                    .pass_signal(tid, sequence, pass)?;
                Ok(Value::Null)
            }
            "log" => {
                let id = args["id"]
                    .as_u64()
                    .ok_or_else(|| error("invalid script ID"))?;
                self.log(id, args["value"].clone());
                Ok(Value::Null)
            }
            "setForkPolicy" => {
                self.follow_fork = match args["mode"].as_str() {
                    Some("parent") => false,
                    Some("child") => true,
                    Some("both") => {
                        return Err(error(
                            "NotSupport: following both processes requires multi-instance debugging",
                        ));
                    }
                    _ => return Err(error("expected parent, child, or both")),
                };
                if let Some(Target::Live(live)) = &mut self.target {
                    live.trace.follow_fork = self.follow_fork;
                }
                Ok(Value::Null)
            }
            "detach" => {
                self.target.as_mut().ok_or_else(no_target)?.operation(
                    op,
                    args,
                    &self.state_dir,
                    &self.cancelled,
                )?;
                self.replace(None);
                Ok(Value::Null)
            }
            "kill" => {
                let signal = if args.get("signal").is_some() {
                    signal_number(&args["signal"])?
                } else {
                    nix::libc::SIGKILL
                };
                let live = self.target.as_mut().ok_or_else(no_target)?.live()?;
                let result = live.kill_and_detach(signal);
                if live.trace.threads.is_empty() {
                    self.replace(None);
                }
                result.map(|()| Value::Null)
            }
            _ => self.target.as_mut().ok_or_else(no_target)?.operation(
                op,
                args,
                &self.state_dir,
                &self.cancelled,
            ),
        }
    }

    fn tool_reply(&mut self, result: Result<Value>, pending: &[Pending<'_>]) -> ToolReply {
        let (result_json, error) = match result {
            Ok(value) => (value.to_string().into_bytes(), None),
            Err(err) => (Vec::new(), Some(err.to_string())),
        };
        self.output_size = 0;
        ToolReply {
            result_json,
            error,
            paused_threads: match &self.target {
                Some(Target::Live(live)) => live.paused.union(&live.callbacks).copied().collect(),
                _ => Vec::new(),
            },
            paused_stops_json: match &self.target {
                Some(Target::Live(live)) => json!(live.paused_stops()).to_string().into_bytes(),
                _ => Vec::new(),
            },
            waiting_inputs: self
                .waiting
                .iter()
                .map(|(handler, state)| WaitingInput {
                    handler: handler.clone(),
                    tid: state.tid,
                    payload_json: state.payload.to_string().into_bytes(),
                })
                .collect(),
            script_output: self.output.drain(..).collect(),
            output_dropped: std::mem::take(&mut self.output_dropped),
            running_scripts: pending.iter().map(|script| script.id).collect(),
            target_error: self.target_error.clone(),
            waiting_events_json: json!(self.events.status()).to_string().into_bytes(),
            signals_json: json!(self.reported_signals.drain(..).collect::<Vec<_>>())
                .to_string()
                .into_bytes(),
            pending_events: self.events.len() as u32,
            event_queue_full: self.events.len() >= events::QUEUE_LIMIT,
            process_output_json: Vec::new(),
        }
    }
}

fn no_target() -> Box<dyn std::error::Error + Send + Sync> {
    error("select a target with run, attach or core_open")
}

fn signal_number(signal: &Value) -> Result<i32> {
    if let Some(n) = signal.as_i64() {
        if (1..=64).contains(&n) {
            return Ok(n as i32);
        }
    }
    if let Some(name) = signal.as_str() {
        let name = name.to_ascii_uppercase();
        let name = if name.starts_with("SIG") {
            name
        } else {
            format!("SIG{name}")
        };
        if let Ok(signal) = name.parse::<nix::sys::signal::Signal>() {
            return Ok(signal as i32);
        }
    }
    Err(error("unknown signal"))
}

struct Pending<'js> {
    id: u64,
    generation: u64,
    module: Module<'js, rquickjs::module::Evaluated>,
    promise: Promise<'js>,
    declarations: String,
}

#[derive(Default)]
struct Exports {
    modules: BTreeMap<u64, String>,
    keys: BTreeMap<String, u64>,
}

impl Exports {
    fn declarations(&self) -> String {
        use std::fmt::Write;
        let mut text = String::from("interface AidbgGlobals {\n");
        for (key, id) in &self.keys {
            let key = serde_json::to_string(key).unwrap();
            let _ = writeln!(
                text,
                "readonly {key}: (typeof import(\"aidbg-export-{id}\"))[{key}];"
            );
        }
        text.push_str("}\n");
        for (id, declarations) in &self.modules {
            let _ = writeln!(
                text,
                "declare module \"aidbg-export-{id}\" {{\n{declarations}\n}}"
            );
        }
        text
    }

    fn merge(&mut self, id: u64, keys: Vec<String>, definitions: String) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut next = self.keys.clone();
        next.extend(keys.into_iter().map(|key| (key, id)));
        let active: BTreeSet<_> = next.values().copied().collect();
        let bytes = definitions.len()
            + next.keys().map(|key| key.len() + 80).sum::<usize>()
            + self
                .modules
                .iter()
                .filter(|(id, _)| active.contains(id))
                .map(|(_, definitions)| definitions.len())
                .sum::<usize>();
        if bytes > MAX_GLOBALS {
            return Err(error("export declarations exceed the session limit"));
        }
        self.keys = next;
        self.modules.retain(|id, _| active.contains(id));
        self.modules
            .insert(id, definitions.replace("export declare ", "export "));
        Ok(())
    }
}

fn declarations() -> String {
    let api = include_str!("../../docs/debugger.d.ts").replace("export declare ", "export ");
    let node = include_str!("session/node.d.ts");
    format!(
        r#"declare module "aidbg" {{
{api}
}}
{node}
interface AidbgGlobals {{}}
declare const dbg: import("aidbg").Debugger;
declare const m: import("aidbg").TypeSystem;
declare const $: AidbgGlobals & import("aidbg").GlobalScope;
declare const console: import("aidbg").Console;
declare const setTimeout: typeof import("aidbg").setTimeout;
declare const clearTimeout: typeof import("aidbg").clearTimeout;
declare const queueMicrotask: typeof import("aidbg").queueMicrotask;
declare const sleep: typeof import("aidbg").sleep;
declare const AbortController: typeof import("aidbg").AbortController;
type AbortSignal = import("aidbg").AbortSignal;
"#
    )
}

fn run(
    state_dir: PathBuf,
    commands: mpsc::Receiver<Message>,
    cancelled: Arc<AtomicBool>,
) -> Result<()> {
    let deadline = Rc::new(std::cell::Cell::new(Instant::now() + SCRIPT_SLICE));
    let flag = cancelled.clone();
    let runtime = Runtime::new()?;
    files::install(&runtime);
    runtime.set_memory_limit(96 * 1024 * 1024);
    runtime.set_max_stack_size(512 * 1024);
    let limit = deadline.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        flag.load(Ordering::Relaxed) || Instant::now() >= limit.get()
    })));
    let context = Context::full(&runtime)?;
    let state = Rc::new(RefCell::new(State {
        target: None,
        released_output: VecDeque::new(),
        follow_fork: false,
        generation: 0,
        state_dir,
        cancelled: cancelled.clone(),
        waiting: BTreeMap::new(),
        next_handler: 0,
        output: VecDeque::new(),
        output_size: 0,
        output_dropped: false,
        target_error: None,
        signals: BTreeSet::new(),
        events: events::Queue::default(),
        dispatches: BTreeMap::new(),
        reported_signals: VecDeque::new(),
        started: Instant::now(),
        source_maps: BTreeMap::new(),
        timers: BTreeMap::new(),
        next_timer: 0,
    }));
    let mut compiler = Compiler::with_session_api(&declarations(), true);
    let result = context.with(|ctx| {
        ctx.store_userdata(files::Jobs::default()).map_err(|_| error("cannot initialize filesystem jobs"))?;
        let mut pending = Vec::new();
        let mut exports = Exports::default();
        let mut next_script = 0;
        let host = state.clone();
        let operation = Function::new(ctx.clone(), move |ctx: Ctx<'_>, op:String, args:String| {
            let result = serde_json::from_str(&args).map_err(Into::into)
                .and_then(|args| host.borrow_mut().operation(&op, args));
            match result {
                Ok(value) => Ok(value.to_string()),
                Err(err) => {
                    let message = err.to_string();
                    if let Some(reason) = message.strip_prefix("NotSupport: ") {
                        let exception = Exception::from_message(ctx.clone(), reason)?;
                        exception.as_object().set("name", "NotSupport")?;
                        Err(exception.throw())
                    } else { Err(Exception::throw_message(&ctx, &message)) }
                }
            }
        })?;
        let api: Object = ctx.eval(include_str!("session/runtime.js")).catch(&ctx).map_err(|err| error(err.to_string()))?;
        let initialize: Function = api.get("initialize")?;
        let generation_state = state.clone();
        let generation = Function::new(ctx.clone(), move || generation_state.borrow().generation)?;
        initialize.call::<_, ()>((operation, regs::ARCH, generation))?;
        native_value::install(&ctx, &api)?;
        let dispatch: Function = api.get("dispatch")?;
        let event_result: Function = api.get("eventResult")?;
        let fire_timer: Function = api.get("fireTimer")?;
        let input: Function = api.get("input")?;
        let publish: Function = api.get("publish")?;
        let reset: Function = api.get("reset")?;
        let mut current_generation = 0;
        while !cancelled.load(Ordering::Relaxed) {
            deadline.set(Instant::now() + SCRIPT_SLICE);
            tick(&state, &dispatch, &input, &ctx)?;
            fire_timers(&state,&fire_timer)?;
            files::poll(&ctx)?;
            pump(&ctx, &state, &publish, &mut exports, &mut pending)?;
            resolve_events(&state,&event_result)?;
            pump(&ctx, &state, &publish, &mut exports, &mut pending)?;
            sync_generation(&state, &input, &reset, &mut exports, &mut current_generation)?;
            let (command, reply) = match commands.recv_timeout(TICK) {
                Ok(message) => message,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            if cancelled.load(Ordering::Relaxed) || reply.is_closed() { continue; }
            deadline.set(Instant::now() + SCRIPT_SLICE);
            let generation = current_generation;
            let result = (|| -> Result<Value> {
                match command {
                    Command::Run(args) => {
                        let mut target = Live::launch(args)?;
                        let scratchpad = target.prepare_scratch(None)
                            .or_else(|_| target.prepare_scratch(None));
                        let pid = target.pid;
                        let released = state.borrow_mut().replace(Some(Target::Live(target)));
                        Ok(json!({"pid":pid,"state":"paused","reason":"exec","released":released,"scratchpad":scratchpad.is_ok(),
                            "scratchpad_error":scratchpad.err().map(|err|err.to_string())}))
                    }
                    Command::Attach(pid) => {
                        let existing = matches!(&state.borrow().target, Some(Target::Live(live)) if live.pid == pid && live.verify().is_ok());
                        if !existing {
                            let mut target = Live::attach(pid)?;
                            let scratchpad = target.prepare_scratch(None);
                            let released = state.borrow_mut().replace(Some(Target::Live(target)));
                            return Ok(json!({"pid":pid,"state":"attached","reason":"attach","released":released,"scratchpad":scratchpad.is_ok(),
                                "scratchpad_error":scratchpad.err().map(|err|err.to_string())}));
                        }
                        Ok(json!({"pid":pid,"state":"attached","released":[]}))
                    }
                    Command::Core(args) => {
                        let (target, mut info) = Target::open(args)?;
                        info["released"] = json!(state.borrow_mut().replace(Some(target)));
                        Ok(info)
                    }
                    Command::Snapshot(tid, context) => {
                        let mut state = state.borrow_mut();
                        state.target.as_mut().ok_or_else(no_target)?.snapshot(tid, context)
                    }
                    Command::Input(handler, result) => {
                        if state.borrow_mut().waiting.remove(&handler).is_none() { return Err(error("input handler is not waiting")); }
                        deliver(&input, &handler, result)?;
                        Ok(json!({"handler":handler}))
                    }
                    Command::Script(src) => {
                        if src.len() > MAX_SOURCE_BYTES { return Err(error("script source exceeds 64 KiB")); }
                        if pending.len() >= MAX_PENDING { return Err(error("too many running scripts")); }
                        let id = next_script;
                        next_script += 1;
                        let (diagnostics, compiled) = compiler.session_compile(&src,&exports.declarations(),id,|name| {
                            let state = state.borrow();
                            let target = state.target.as_ref().ok_or_else(no_target)?;
                            target.resolve_dwarf_type(name)
                        })?;
                        let Some((js,declarations,map)) = compiled else {
                            return Ok(json!({"script_id":id,"status":"check_failed","diagnostics":diagnostics}));
                        };
                        let mut current = state.borrow_mut();
                        if current.source_maps.len()>=512 {current.source_maps.pop_first();}
                        current.source_maps.insert(id,source_map::SourceMap::parse(&map)?);
                        drop(current);
                        let js = format!("const console = globalThis.__aidbgConsole({id}, {generation});\n{js}");
                        deadline.set(Instant::now() + SCRIPT_SLICE);
                        let (module, promise) = Module::declare(ctx.clone(), format!("script-{id}.js"), js)
                            .and_then(|module| module.eval()).catch(&ctx).map_err(|err| error(err.to_string()))?;
                        pending.push(Pending { id, generation, module, promise, declarations });
                        Ok(json!({"script_id":id,"status":"accepted"}))
                    }
                    Command::Processes(args) => processes(args),
                    Command::SyscallTable(id, name) => Ok(syscalls::query(id, name.as_deref())),
                    Command::SetForkPolicy(mode) => state.borrow_mut().operation("setForkPolicy", json!({"mode":mode})),
                    Command::Result(result) => result,
                }
            })();
            sync_generation(&state, &input, &reset, &mut exports, &mut current_generation)?;
            deadline.set(Instant::now() + SCRIPT_SLICE);
            tick(&state, &dispatch, &input, &ctx)?;
            fire_timers(&state,&fire_timer)?;
            pump(&ctx, &state, &publish, &mut exports, &mut pending)?;
            resolve_events(&state,&event_result)?;
            pump(&ctx, &state, &publish, &mut exports, &mut pending)?;
            sync_generation(&state, &input, &reset, &mut exports, &mut current_generation)?;
            if !reply.is_closed() {
                let mut state = state.borrow_mut();
                let mut message = state.tool_reply(result, &pending);
                let output_cursor = match state.target.as_ref() {
                    Some(Target::Live(live)) => live.stdio.as_ref().map(|stdio| {
                        let (mut value,cursor) = stdio.mcp_output();
                        value["pid"] = json!(live.pid);
                        append_exit_status(&mut value, live.trace.exit);
                        message.process_output_json = value.to_string().into_bytes();
                        cursor
                    }),
                    _ => None,
                };
                match reply.send(message) {
                    Ok(()) => {
                        if let Some(cursor) = output_cursor
                            && let Some(Target::Live(live)) = state.target.as_mut()
                            && let Some(stdio) = &mut live.stdio
                        {
                            stdio.acknowledge(cursor);
                        }
                    }
                    Err(message) => {
                        state.output_size = message.script_output.iter().map(|row|row.json.len()+16).sum();
                        state.output = message.script_output.into();
                        state.output_dropped = message.output_dropped;
                        state.reported_signals = serde_json::from_slice(&message.signals_json).unwrap_or_default();
                    }
                }
            }
        }
        state.borrow_mut().replace(None);
        Ok(())
    });
    context.with(|ctx| {
        let _ = ctx.remove_userdata::<files::Jobs>();
    });
    result
}

fn sync_generation(
    state: &RefCell<State>,
    input: &Function<'_>,
    reset: &Function<'_>,
    exports: &mut Exports,
    previous: &mut u64,
) -> Result<()> {
    let generation = state.borrow().generation;
    if generation == *previous {
        return Ok(());
    }
    *previous = generation;
    let handlers = std::mem::take(&mut state.borrow_mut().waiting);
    for (handler, _) in handlers {
        deliver(input, &handler, Err("target changed".into()))?;
    }
    reset.call::<_, ()>(())?;
    *exports = Exports::default();
    Ok(())
}

fn deliver(
    input: &Function<'_>,
    handler: &str,
    result: std::result::Result<String, String>,
) -> Result<()> {
    let (ok, data) = match result {
        Ok(data) => (true, data),
        Err(message) => (false, message),
    };
    input.call::<_, ()>((handler, ok, data))?;
    Ok(())
}

fn tick(
    state: &RefCell<State>,
    dispatch: &Function<'_>,
    input: &Function<'_>,
    ctx: &Ctx<'_>,
) -> Result<()> {
    let now = Instant::now();
    let expired: Vec<_> = state
        .borrow()
        .waiting
        .iter()
        .filter(|(_, wait)| now >= wait.deadline)
        .map(|(handler, _)| handler.clone())
        .collect();
    for handler in expired {
        state.borrow_mut().waiting.remove(&handler);
        deliver(input, &handler, Err("input timed out".into()))?;
    }
    let events = {
        let mut state = state.borrow_mut();
        let backpressure = state.events.len() >= events::QUEUE_LIMIT;
        let State {
            target, signals, ..
        } = &mut *state;
        if let Some(Target::Live(live)) = target {
            let events = live.drain_io().and_then(|()| {
                if backpressure {
                    Ok(Vec::new())
                } else {
                    let events = live.tick(signals)?;
                    if events
                        .iter()
                        .any(|event| matches!(event, Event::Exit { process: true, .. }))
                    {
                        live.drain_io()?;
                    }
                    Ok(events)
                }
            });
            for branch in live.take_branches() {
                state.log(0, branch);
            }
            events
        } else {
            Ok(Vec::new())
        }
    };
    let rows = match events {
        Ok(rows) => rows,
        Err(err) => {
            let mut state = state.borrow_mut();
            state.replace(None);
            state.target_error = Some(err.to_string());
            return Ok(());
        }
    };
    let mut by_tid = BTreeMap::<i32, Vec<Value>>::new();
    {
        let mut state = state.borrow_mut();
        let active = match &state.target {
            Some(Target::Live(live)) => live.tids(),
            _ => Vec::new(),
        };
        state.events.resurrect(active);
        for event in rows {
            match event {
                Event::Fork {
                    parent,
                    old_threads,
                    tid,
                } => {
                    state.events.follow_fork(old_threads);
                    state.dispatches.clear();
                    state.reported_signals.clear();
                    let sequence = state.events.push(
                        json!({"kind":"fork","reason":"fork","parentPid":parent,"tid":tid,"paused":true}),
                        true,
                    );
                    if let Some(Target::Live(live)) = &mut state.target {
                        live.track_stop(tid, sequence);
                    }
                }
                Event::Exec { tid, executable } => {
                    let sequence = state.events.push(
                        json!({"kind":"exec","reason":"exec","tid":tid,"executable":executable,"paused":true}),
                        true,
                    );
                    if let Some(Target::Live(live)) = &mut state.target {
                        live.track_stop(tid, sequence);
                    }
                }
                Event::Breakpoint {
                    tid,
                    id,
                    address,
                    watch,
                } => {
                    let mut row = json!({"kind":if watch.is_some() {"watchpoint"} else {"breakpoint"},
                        "reason":"breakpoint","tid":tid,"breakpointId":id,"address":crate::hex(address),"paused":true});
                    if let Some(watch) = watch {
                        row["length"] = json!(watch.length);
                        row["before"] = json!(watch.before.map(crate::hex));
                        row["after"] = json!(watch.after.map(crate::hex));
                        row["access"] = json!(watch.access);
                    }
                    row["sequence"] = json!(state.events.push(row.clone(), false));
                    by_tid.entry(tid).or_default().push(row);
                }
                Event::Syscall { tid, mut row } => {
                    row["sequence"] = json!(state.events.push(row.clone(), false));
                    by_tid.entry(tid).or_default().push(row);
                }
                Event::Signal {
                    tid,
                    number,
                    fault,
                    callback,
                } => {
                    let name = nix::sys::signal::Signal::try_from(number)
                        .map_or_else(|_| format!("SIG{number}"), |s| s.to_string());
                    let mut row = json!({"kind":"signal","reason":"signal","tid":tid,"signalNumber":number,"signalName":name,
                        "faultAddress":fault.map(crate::hex),"paused":true});
                    let sequence = state.events.push(row.clone(), !callback);
                    if !callback && let Some(Target::Live(live)) = &mut state.target {
                        live.track_stop(tid, sequence);
                    }
                    row["sequence"] = json!(sequence);
                    state.reported_signals.push_back(row.clone());
                    if callback {
                        by_tid.entry(tid).or_default().push(row);
                    }
                }
                Event::Exit {
                    tid,
                    process,
                    result,
                } => {
                    let mut row = json!({"kind":"exit","stopReason":"exit","tid":tid,"scope":if process {"process"} else {"thread"}});
                    match result {
                        Some(crate::trace::LaunchExit::Code(code)) => {
                            row["reason"] = json!("code");
                            row["code"] = json!(code);
                        }
                        Some(crate::trace::LaunchExit::Signal(signal)) => {
                            row["reason"] = json!("signal");
                            row["signal"] = json!(signal);
                        }
                        None => {
                            row["reason"] = json!("unknown");
                        }
                    }
                    state.events.push(row, true);
                    if let Some(sequences) = state.dispatches.remove(&tid) {
                        for sequence in sequences {
                            state.events.complete(sequence, false, None);
                        }
                    }
                }
            }
        }
    }
    for (tid, rows) in by_tid {
        let sequences: Vec<_> = rows
            .iter()
            .map(|row| row["sequence"].as_u64().unwrap())
            .collect();
        let token = sequences[0];
        state.borrow_mut().dispatches.insert(tid, sequences);
        if let Err(err) = dispatch
            .call::<_, ()>((tid, token, json!(rows).to_string()))
            .catch(ctx)
        {
            let mut state = state.borrow_mut();
            state.log(0, json!({"kind":"callback_error","error":err.to_string()}));
            state.complete_callback(tid, token, None, None, &Value::Null);
        }
    }
    Ok(())
}

fn fire_timers(state: &RefCell<State>, fire: &Function<'_>) -> Result<()> {
    let expired = {
        let mut state = state.borrow_mut();
        let now = Instant::now();
        let mut expired = Vec::new();
        state.timers.retain(|&id, &mut deadline| {
            if deadline <= now {
                expired.push((deadline, id));
                false
            } else {
                true
            }
        });
        expired.sort_unstable();
        expired
    };
    for (_, id) in expired {
        fire.call::<_, ()>((id,))?;
    }
    Ok(())
}

fn resolve_events(state: &RefCell<State>, function: &Function<'_>) -> Result<()> {
    let results = {
        let mut state = state.borrow_mut();
        let State { events, target, .. } = &mut *state;
        events.poll(
            Instant::now(),
            |tid,sequence| matches!(target.as_ref(),Some(Target::Live(live)) if live.holds_stop(tid,sequence)),
        )
    };
    for (id, result) in results {
        function.call::<_, ()>((id, result.to_string()))?;
    }
    Ok(())
}

fn pump<'js>(
    ctx: &Ctx<'js>,
    state: &RefCell<State>,
    publish: &Function<'js>,
    exports: &mut Exports,
    pending: &mut Vec<Pending<'js>>,
) -> Result<()> {
    for _ in 0..256 {
        if !ctx.execute_pending_job() {
            break;
        }
    }
    let generation = state.borrow().generation;
    pending.retain(|script| {
        let Some(result) = script.promise.result::<JsValue>() else {
            return script.generation == generation;
        };
        if script.generation != generation {
            return false;
        }
        let result = match result.catch(ctx) {
            Ok(_) => (|| -> Result<()> {
                let namespace = script.module.namespace()?;
                let keys = namespace
                    .keys::<String>()
                    .collect::<rquickjs::Result<Vec<_>>>()?;
                exports.merge(script.id, keys.clone(), script.declarations.clone())?;
                publish.call::<_, ()>((namespace, json!(keys).to_string()))?;
                Ok(())
            })(),
            Err(err) => {
                let stack = match &err {
                    rquickjs::CaughtError::Exception(exception) => exception.stack(),
                    _ => None,
                };
                state.borrow_mut().report_error(
                    Some(script.id),
                    "script_error",
                    exception_text(ctx, err),
                    stack,
                );
                return false;
            }
        };
        match result {
            Ok(()) => state
                .borrow_mut()
                .log(script.id, json!({"kind":"script_complete"})),
            Err(err) => state.borrow_mut().report_error(
                Some(script.id),
                "script_error",
                err.to_string(),
                None,
            ),
        }
        false
    });
    Ok(())
}

fn exception_text<'js>(ctx: &Ctx<'js>, error: rquickjs::CaughtError<'js>) -> String {
    use rquickjs::{Coerced, FromJs};
    match error {
        rquickjs::CaughtError::Exception(exception) => {
            let name = exception
                .as_object()
                .get::<_, String>("name")
                .unwrap_or_else(|_| "Error".into());
            let message = exception.message().unwrap_or_default();
            if name == "Error" {
                message
            } else {
                format!("{name}: {message}")
            }
        }
        rquickjs::CaughtError::Value(value) => Coerced::<String>::from_js(ctx, value)
            .map(|value| value.0)
            .unwrap_or_else(|_| "script rejected".into()),
        other => other.to_string(),
    }
}

fn processes(args: crate::rpc::ProcessListRequest) -> Result<Value> {
    let fields = if args.fields.is_empty() {
        vec![
            "pid",
            "ppid",
            "name",
            if args.threads { "tid" } else { "threads" },
        ]
    } else {
        args.fields.iter().map(String::as_str).collect()
    };
    if let Some(field) = fields.iter().find(|&&field| {
        !matches!(field, "pid" | "ppid" | "name" | "threads" | "tid" | "args")
            || (field == "tid" && !args.threads)
    }) {
        return Err(error(format!("invalid process list field {field:?}")));
    }
    if args.limit == Some(0) {
        return Err(error("process list limit must be positive"));
    }
    let pattern = args.pattern.as_deref().map(str::to_lowercase);
    let mut rows = Vec::new();
    for entry in fs::read_dir("/proc")?.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let path = entry.path();
        let Ok(status) = procfs::Status::read(&path) else {
            continue;
        };
        if procfs::is_kernel_thread(&path, &status) {
            continue;
        }
        let name = status.name().unwrap_or_default();
        let command_line: Vec<_> = if fields.contains(&"args") || pattern.is_some() {
            let cmdline = fs::read(path.join("cmdline")).unwrap_or_default();
            cmdline
                .strip_suffix(&[0])
                .unwrap_or(&cmdline)
                .split(|&byte| byte == 0)
                .filter(|arg| !arg.is_empty() || !cmdline.is_empty())
                .map(|arg| String::from_utf8_lossy(arg).into_owned())
                .collect()
        } else {
            Vec::new()
        };
        if let Some(pattern) = &pattern
            && !pid.to_string().contains(pattern)
            && !name.to_lowercase().contains(pattern)
            && !command_line.join(" ").to_lowercase().contains(pattern)
        {
            continue;
        }
        let ppid = status
            .field("PPid")
            .and_then(|value| value.parse::<i32>().ok());
        let count = status
            .field("Threads")
            .and_then(|value| value.parse::<u32>().ok());
        let mut row = serde_json::Map::new();
        for field in &fields {
            let value = match *field {
                "pid" => json!(pid),
                "ppid" => json!(ppid),
                "name" => json!(name),
                "threads" => json!(count),
                "args" => json!(command_line),
                _ => continue,
            };
            row.insert((*field).into(), value);
        }
        if args.threads {
            let Ok(tasks) = fs::read_dir(path.join("task")) else {
                continue;
            };
            for task in tasks.flatten() {
                let Some(tid) = task
                    .file_name()
                    .to_str()
                    .and_then(|value| value.parse::<i32>().ok())
                else {
                    continue;
                };
                let mut thread = row.clone();
                if fields.contains(&"tid") {
                    thread.insert("tid".into(), json!(tid));
                }
                rows.push((pid, tid, thread));
            }
        } else {
            rows.push((pid, pid, row));
        }
    }
    rows.sort_by_key(|(pid, tid, _)| (*pid, *tid));
    let offset = args.offset as usize;
    let limit = args.limit.map_or(usize::MAX, |limit| limit as usize);
    let next = offset.saturating_add(limit);
    let next_offset = (next < rows.len()).then_some(next);
    let items: Vec<_> = rows
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(_, _, row)| row)
        .collect();
    Ok(json!({"items":items,"next_offset":next_offset}))
}
