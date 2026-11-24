mod inferior;
mod instruction;
mod link;
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

pub enum Command {
    Run(RunProcessRequest),
    Attach(i32),
    Core(OpenCoreRequest),
    Script(String),
    Input(String, std::result::Result<String, String>),
    Snapshot(Option<i32>),
    Processes,
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
    deadline: Option<Instant>,
}

struct State {
    target: Option<Target>,
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
}

impl State {
    fn replace(&mut self, target: Option<Target>) {
        self.target = target;
        self.generation += 1;
        self.signals.clear();
        self.target_error = None;
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

    fn operation(&mut self, op: &str, args: Value) -> Result<Value> {
        match op {
            "generation" => Ok(json!(self.generation)),
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
                    && let Some(Target::Live(live)) = &mut self.target
                    && let Some(tid) = args["tid"].as_i64().and_then(|tid| i32::try_from(tid).ok())
                {
                    live.finish_callback(tid, args["pause"].as_bool(), args["pass"] != false);
                }
                Ok(Value::Null)
            }
            "log" => {
                let id = args["id"]
                    .as_u64()
                    .ok_or_else(|| error("invalid script ID"))?;
                self.log(id, args["value"].clone());
                Ok(Value::Null)
            }
            "wait" => {
                if self.waiting.len() >= MAX_PENDING {
                    return Err(error("too many waiting input handlers"));
                }
                let deadline = match args["seconds"].as_f64() {
                    Some(seconds) if (0.0..=86400.0).contains(&seconds) => {
                        Some(Instant::now() + Duration::from_secs_f64(seconds))
                    }
                    Some(_) => return Err(error("timeoutSec must be between 0 and 86400")),
                    None => None,
                };
                let tid = args["tid"].as_i64().and_then(|tid| i32::try_from(tid).ok());
                self.next_handler += 1;
                let handler = format!("input-{}", self.next_handler);
                self.waiting
                    .insert(handler.clone(), Waiting { tid, deadline });
                Ok(json!(handler))
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
            waiting_inputs: self
                .waiting
                .iter()
                .map(|(handler, state)| WaitingInput {
                    handler: handler.clone(),
                    tid: state.tid,
                })
                .collect(),
            script_output: self.output.drain(..).collect(),
            output_dropped: std::mem::take(&mut self.output_dropped),
            running_scripts: pending.iter().map(|script| script.id).collect(),
            target_error: self.target_error.clone(),
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
    format!(
        r#"declare module "aidbg" {{
{api}
}}
interface AidbgGlobals {{}}
declare const dbg: import("aidbg").Debugger;
declare const m: import("aidbg").TypeSystem;
declare const $: AidbgGlobals & import("aidbg").GlobalScope;
declare const console: import("aidbg").Console;
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
    runtime.set_memory_limit(96 * 1024 * 1024);
    runtime.set_max_stack_size(512 * 1024);
    let limit = deadline.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || {
        flag.load(Ordering::Relaxed) || Instant::now() >= limit.get()
    })));
    let context = Context::full(&runtime)?;
    let state = Rc::new(RefCell::new(State {
        target: None,
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
    }));
    let mut compiler = Compiler::with_session_api(&declarations(), true);
    context.with(|ctx| {
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
        initialize.call::<_, ()>((operation, regs::ARCH))?;
        let dispatch: Function = api.get("dispatch")?;
        let input: Function = api.get("input")?;
        let publish: Function = api.get("publish")?;
        let reset: Function = api.get("reset")?;
        let mut current_generation = 0;
        while !cancelled.load(Ordering::Relaxed) {
            deadline.set(Instant::now() + SCRIPT_SLICE);
            tick(&state, &dispatch, &input, &ctx)?;
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
                        state.borrow_mut().replace(Some(Target::Live(target)));
                        Ok(json!({"pid":pid,"state":"paused","scratchpad":scratchpad.is_ok(),
                            "scratchpad_error":scratchpad.err().map(|err|err.to_string())}))
                    }
                    Command::Attach(pid) => {
                        let existing = matches!(&state.borrow().target, Some(Target::Live(live)) if live.pid == pid && live.verify().is_ok());
                        if !existing {
                            let mut target = Live::attach(pid)?;
                            let scratchpad = target.prepare_scratch(None);
                            state.borrow_mut().replace(Some(Target::Live(target)));
                            return Ok(json!({"pid":pid,"state":"attached","scratchpad":scratchpad.is_ok(),
                                "scratchpad_error":scratchpad.err().map(|err|err.to_string())}));
                        }
                        Ok(json!({"pid":pid,"state":"attached"}))
                    }
                    Command::Core(args) => {
                        let (target, info) = Target::open(args)?;
                        state.borrow_mut().replace(Some(target));
                        Ok(info)
                    }
                    Command::Snapshot(tid) => {
                        let mut state = state.borrow_mut();
                        state.target.as_mut().ok_or_else(no_target)?.snapshot(tid)
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
                            let mut rows = target.type_graphs(name,true,0,2)?;
                            if rows.len() != 1 {
                                return Err(error(format!("expected one DWARF type named {name:?}, found {}",rows.len())));
                            }
                            Ok(rows.pop().unwrap().1)
                        })?;
                        let Some((js,declarations)) = compiled else {
                            return Ok(json!({"script_id":id,"status":"check_failed","diagnostics":diagnostics}));
                        };
                        let js = format!("const console = globalThis.__aidbgConsole({id}, {generation});\n{js}");
                        deadline.set(Instant::now() + SCRIPT_SLICE);
                        let (module, promise) = Module::declare(ctx.clone(), format!("script-{id}.js"), js)
                            .and_then(|module| module.eval()).catch(&ctx).map_err(|err| error(err.to_string()))?;
                        pending.push(Pending { id, generation, module, promise, declarations });
                        Ok(json!({"script_id":id,"status":"accepted"}))
                    }
                    Command::Processes => processes(),
                    Command::Result(result) => result,
                }
            })();
            sync_generation(&state, &input, &reset, &mut exports, &mut current_generation)?;
            deadline.set(Instant::now() + SCRIPT_SLICE);
            tick(&state, &dispatch, &input, &ctx)?;
            pump(&ctx, &state, &publish, &mut exports, &mut pending)?;
            sync_generation(&state, &input, &reset, &mut exports, &mut current_generation)?;
            if !reply.is_closed() {
                let mut state = state.borrow_mut();
                let message = state.tool_reply(result, &pending);
                if let Err(message) = reply.send(message) {
                    state.output_size = message.script_output.iter().map(|row|row.json.len()+16).sum();
                    state.output = message.script_output.into();
                    state.output_dropped = message.output_dropped;
                }
            }
        }
        state.borrow_mut().replace(None);
        Ok(())
    })
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
        .filter(|(_, wait)| wait.deadline.is_some_and(|time| now >= time))
        .map(|(handler, _)| handler.clone())
        .collect();
    for handler in expired {
        state.borrow_mut().waiting.remove(&handler);
        deliver(input, &handler, Err("input timed out".into()))?;
    }
    let events = {
        let mut state = state.borrow_mut();
        let State {
            target, signals, ..
        } = &mut *state;
        if let Some(Target::Live(live)) = target {
            let events = live.tick(signals);
            for branch in live.take_branches() {
                state.log(0, branch);
            }
            events
        } else {
            Ok(Vec::new())
        }
    };
    let events = match events {
        Ok(events) => events,
        Err(err) => {
            let mut state = state.borrow_mut();
            state.replace(None);
            state.target_error = Some(err.to_string());
            return Ok(());
        }
    };
    let mut by_tid = BTreeMap::<i32, Vec<Value>>::new();
    for event in events {
        match event {
            Event::Breakpoint { tid, id, watch } => {
                let mut value = json!({"id":id});
                if let Some(watch) = watch {
                    value["length"] = json!(watch.length);
                    value["before"] = json!(watch.before.map(crate::hex));
                    value["after"] = json!(watch.after.map(crate::hex));
                    value["access"] = json!(watch.access);
                }
                by_tid.entry(tid).or_default().push(value);
            }
            Event::Signal { tid, number, fault } => {
                let name = nix::sys::signal::Signal::try_from(number)
                    .map_or_else(|_| format!("SIG{number}"), |s| s.to_string());
                by_tid
                    .entry(tid)
                    .or_default()
                    .push(json!({"number":number,"name":name,"fault":fault.map(crate::hex)}));
            }
        }
    }
    for (tid, events) in by_tid {
        if let Err(err) = dispatch
            .call::<_, ()>((tid, json!(events).to_string()))
            .catch(ctx)
        {
            let mut state = state.borrow_mut();
            state.log(0, json!({"kind":"callback_error","error":err.to_string()}));
            if let Some(Target::Live(live)) = &mut state.target {
                live.finish_callback(tid, None, true);
            }
        }
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
        let result = result
            .catch(ctx)
            .map_err(|err| error(exception_text(ctx, err)))
            .and_then(|_| {
                if script.generation != generation {
                    return Ok(());
                }
                let namespace = script.module.namespace()?;
                let keys = namespace
                    .keys::<String>()
                    .collect::<rquickjs::Result<Vec<_>>>()?;
                exports.merge(script.id, keys.clone(), script.declarations.clone())?;
                publish.call::<_, ()>((namespace, json!(keys).to_string()))?;
                Ok(())
            });
        let event = match result {
            Ok(()) => json!({"kind":"script_complete"}),
            Err(err) => json!({"kind":"script_error","error":err.to_string()}),
        };
        if script.generation == generation {
            state.borrow_mut().log(script.id, event);
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

fn processes() -> Result<Value> {
    let mut rows = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let path = entry.path();
        let Ok(status) = procfs::Status::read(&path) else {
            continue;
        };
        let cmdline = fs::read(path.join("cmdline")).unwrap_or_default();
        let args: Vec<_> = cmdline
            .strip_suffix(&[0])
            .unwrap_or(&cmdline)
            .split(|&byte| byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(String::from_utf8_lossy)
            .collect();
        rows.push((pid, json!({"pid":pid,"ppid":status.field("PPid").and_then(|n| n.parse::<u32>().ok()),
            "uid":status.field("Uid").and_then(|uid| uid.split_whitespace().next()?.parse::<u32>().ok()),
            "name":status.name(),"state":status.state(),"arg":args})));
    }
    rows.sort_by_key(|(pid, _)| *pid);
    Ok(json!({"processes":rows.into_iter().map(|(_, row)| row).collect::<Vec<_>>()}))
}
