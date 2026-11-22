use crate::{
    Result, error, regs::Registers, symbols::inspect::inspect_stopped, trace, unwind::UnwindMemory,
};
use rquickjs::{
    BigInt, CatchResultExt, CaughtError, Coerced, Context, Ctx, Exception, FromJs, Function,
    Module, Object, Persistent, Runtime, Value, function::Constructor,
};
use serde::Serialize;
use serde_json::{Value as Json, json};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};

const MAX_OUTPUT: usize = 16 * 1024;
const MAX_ROWS: usize = 32;
const MAX_HITS: u32 = 1000;

#[derive(Clone, Copy, Serialize)]
pub(crate) struct Limits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_hits: Option<u32>,
    pub pause_budget_ms: u32,
}

pub(crate) struct Callback {
    // Drop the persistent JS function before dropping the context/runtime.
    function: Persistent<Function<'static>>,
    realm: Rc<Realm>,
    legacy: bool,
    pub limits: Limits,
    hits: u64,
    disabled: bool,
}

pub(crate) struct Engine {
    runtime: Runtime,
    deadline: Rc<Cell<Instant>>,
    poisoned: Cell<bool>,
}

pub(crate) struct Realm {
    data_view: Persistent<Constructor<'static>>,
    encode: Persistent<Function<'static>>,
    pub context: Context,
    pub engine: Rc<Engine>,
}

impl Engine {
    pub fn new() -> Result<Rc<Self>> {
        let deadline = Rc::new(Cell::new(Instant::now()));
        let clock = Rc::clone(&deadline);
        let runtime = Runtime::new()?;
        runtime.set_memory_limit(16 * 1024 * 1024);
        runtime.set_max_stack_size(256 * 1024);
        runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= clock.get())));
        Ok(Rc::new(Self {
            runtime,
            deadline,
            poisoned: Cell::new(false),
        }))
    }

    pub fn set_deadline(&self, deadline: Instant) {
        self.deadline.set(deadline);
    }

    pub fn check_jobs(&self) {
        if self.runtime.is_job_pending() {
            self.poison();
        }
    }

    pub fn poison(&self) {
        self.poisoned.set(true);
    }

    pub fn diagnose(&self, failure: CaughtError<'_>, limit: usize) -> String {
        if matches!(&failure, CaughtError::Error(rquickjs::Error::Allocation))
            || matches!(&failure, CaughtError::Exception(exception)
                if exception.message().as_deref() == Some("out of memory"))
        {
            self.poison();
        }
        failure.to_string().chars().take(limit).collect()
    }

    pub fn poisoned(&self) -> bool {
        self.poisoned.get()
    }
}

impl Realm {
    pub fn new(engine: Rc<Engine>) -> Result<Rc<Self>> {
        engine.set_deadline(Instant::now() + Duration::from_millis(50));
        let context = Context::full(&engine.runtime)?;
        let (data_view, encode) = context.with(|ctx| {
            let globals = ctx.globals();
            globals.remove("SharedArrayBuffer")?;
            globals.remove("Atomics")?;
            let ctor: Constructor = globals.get("DataView")?;
            let encode: Function = ctx.eval(ENCODE_VALUE)?;
            Ok::<_, rquickjs::Error>((Persistent::save(&ctx, ctor), Persistent::save(&ctx, encode)))
        })?;
        Ok(Rc::new(Self {
            context,
            engine,
            data_view,
            encode,
        }))
    }
}

pub(crate) struct HitState {
    pub pid: i32,
    pub tid: i32,
    pub address: u64,
    pub kind: &'static str,
    pub registers: BTreeMap<String, String>,
    pub watch: Option<WatchState>,
    pub stack: Registers,
    pub proc_root: PathBuf,
}

pub(crate) struct WatchState {
    pub before: Option<u64>,
    pub after: Option<u64>,
    pub changed: Option<bool>,
}

#[derive(Default)]
pub(super) struct Actions {
    closed: bool,
    fields: Vec<OutputField>,
    output_bytes: usize,
    snapshot: bool,
    disable: bool,
}

impl Actions {
    pub(super) fn output(&self) -> Vec<Json> {
        self.fields.iter().map(OutputField::json).collect()
    }
}

#[derive(Serialize)]
pub(crate) struct CallbackResult {
    pub hit: u64,
    pub status: &'static str,
    pub output: Vec<Json>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub output_text: Vec<String>,
    pub issue: Option<String>,
    #[serde(skip)]
    pub snapshot: bool,
    #[serde(skip)]
    pub suppressed: bool,
    pub disarming: bool,
}

impl Callback {
    pub fn load(js: &str, max_budget_ms: u32) -> Result<Self> {
        let engine = Engine::new()?;
        let realm = Realm::new(engine)?;
        let (function, limits) = realm.context.with(|ctx| install(ctx, js, max_budget_ms))?;
        realm.engine.check_jobs();
        if realm.engine.poisoned() {
            return Err(error("breakpoint rule setup must be synchronous"));
        }
        Ok(Self {
            legacy: true,
            ..Self::new(function, realm, limits)
        })
    }

    pub fn new(function: Persistent<Function<'static>>, realm: Rc<Realm>, limits: Limits) -> Self {
        Self {
            function,
            realm,
            limits,
            legacy: false,
            hits: 0,
            disabled: false,
        }
    }

    pub fn poisoned_group(&self) -> bool {
        !self.legacy && self.realm.engine.poisoned()
    }

    pub fn replace_handler(&mut self, candidate: Callback) {
        self.function = candidate.function;
        self.realm = candidate.realm;
    }

    pub fn exhausted(&self) -> bool {
        self.disabled
            || self.realm.engine.poisoned()
            || self
                .limits
                .max_hits
                .is_some_and(|max| self.hits >= u64::from(max))
    }

    pub fn run(&mut self, hit: Result<HitState>, deadline: Instant) -> CallbackResult {
        self.hits = self.hits.saturating_add(1);
        self.realm.engine.set_deadline(deadline);
        let actions = Rc::new(RefCell::new(Some(Actions::default())));
        let execution = if Instant::now() >= deadline {
            Err("callback pause budget exceeded".into())
        } else {
            hit.map_err(|e| e.to_string()).and_then(|hit| {
                self.realm.context.with(|ctx| {
                    let result = (|| {
                        let callback = self.function.clone().restore(&ctx)?;
                        let data_view = self.realm.data_view.clone().restore(&ctx)?;
                        let encode = self.realm.encode.clone().restore(&ctx)?;
                        invoke(
                            ctx.clone(),
                            callback,
                            data_view,
                            encode,
                            hit,
                            Rc::clone(&actions),
                            deadline,
                        )
                    })();
                    result
                        .catch(&ctx)
                        .map_err(|e| self.realm.engine.diagnose(e, 1024))
                })
            })
        };
        self.realm.engine.check_jobs();
        let execution = match execution {
            Ok(_) if self.realm.engine.poisoned() => {
                Err("breakpoint callbacks must be synchronous".into())
            }
            result => result,
        };
        let Actions {
            fields,
            snapshot,
            disable,
            ..
        } = actions.borrow_mut().take().unwrap_or_default();
        let (status, issue, suppressed) = if Instant::now() >= deadline {
            (
                "timed_out",
                Some("callback pause budget exceeded".into()),
                false,
            )
        } else {
            match execution {
                Ok(suppressed) => ("complete", None, suppressed),
                Err(issue) => ("failed", Some(issue), false),
            }
        };
        self.disabled = disable || issue.is_some();
        let snapshot = snapshot && issue.is_none() && !suppressed;
        CallbackResult {
            hit: self.hits,
            status,
            issue,
            output: fields.iter().map(OutputField::json).collect(),
            output_text: fields.iter().map(OutputField::text).collect(),
            snapshot,
            suppressed,
            disarming: self.exhausted(),
        }
    }
}

fn bounded_error(error: String) -> String {
    error.chars().take(1024).collect()
}

fn install<'js>(
    ctx: Ctx<'js>,
    js: &str,
    max_budget_ms: u32,
) -> Result<(Persistent<Function<'static>>, Limits)> {
    let selected = Rc::new(RefCell::new(None));
    let result = (|| -> rquickjs::Result<_> {
        let globals = ctx.globals();
        globals.remove("SharedArrayBuffer")?;
        globals.remove("Atomics")?;
        let rule = Rc::clone(&selected);
        let defined = Cell::new(false);
        globals.set(
            "defineRule",
            Function::new(ctx.clone(), move |ctx: Ctx<'js>, arg: Object<'js>| {
                if defined.replace(true) {
                    return Err(Exception::throw_message(
                        &ctx,
                        "defineRule must be called exactly once",
                    ));
                }
                let callback: Function<'js> = arg.get("onHit")?;
                let hits = integer_option(&ctx, &arg, "maxHits", 100, MAX_HITS)?;
                let budget =
                    integer_option(&ctx, &arg, "pauseBudgetMs", max_budget_ms, max_budget_ms)?;
                *rule.borrow_mut() = Some((
                    Persistent::save(&ctx, callback),
                    Limits {
                        max_hits: Some(hits),
                        pause_budget_ms: budget,
                    },
                ));
                Ok(())
            })?,
        )?;

        // Module setup runs before this callback is armed.
        let (module, promise) =
            Module::declare(ctx.clone(), "breakpoint.js", js.as_bytes())?.eval()?;
        promise.finish::<()>()?;
        globals.remove("defineRule")?;
        Ok(module)
    })();
    // Take the value even when evaluation failed. The closure can otherwise
    // retain a reference to its own runtime through the persistent function.
    let rule = selected.borrow_mut().take();
    let module = result
        .catch(&ctx)
        .map_err(|e| error(bounded_error(e.to_string())))?;
    if let Some(rule) = rule {
        return Ok(rule);
    }
    if !module.namespace()?.contains_key("default")? {
        return Err(error(
            "breakpoint rule must call defineRule exactly once or export a default function",
        ));
    }
    let handler: Value<'_> = module.get("default")?;
    let handler = handler
        .into_function()
        .ok_or_else(|| error("breakpoint rule default export must be a function"))?;
    Ok((
        Persistent::save(&ctx, handler),
        Limits {
            max_hits: None,
            pause_budget_ms: max_budget_ms,
        },
    ))
}

pub(crate) fn integer_option<'js>(
    ctx: &Ctx<'js>,
    object: &Object<'js>,
    name: &str,
    default: u32,
    max: u32,
) -> rquickjs::Result<u32> {
    let value: Value<'js> = object.get(name)?;
    if value.is_undefined() {
        return Ok(default);
    }
    match value.as_number() {
        Some(value) if value.fract() == 0.0 && (1.0..=f64::from(max)).contains(&value) => {
            Ok(value as u32)
        }
        _ => Err(Exception::throw_type(
            ctx,
            &format!("{name} must be an integer in 1..={max}"),
        )),
    }
}

fn invoke<'js>(
    ctx: Ctx<'js>,
    callback: Function<'js>,
    data_view: Constructor<'js>,
    encode: Function<'js>,
    state: HitState,
    actions: Rc<RefCell<Option<Actions>>>,
    deadline: Instant,
) -> rquickjs::Result<bool> {
    let intrinsics = Rc::new(RefCell::new(Some((data_view, encode))));
    let _clear = CloseHit {
        intrinsics: Rc::clone(&intrinsics),
        actions: Rc::clone(&actions),
    };
    let hit = Object::new(ctx.clone())?;
    hit.set("pid", state.pid)?;
    hit.set("tid", state.tid)?;
    hit.set("address", BigInt::from_u64(ctx.clone(), state.address)?)?;
    hit.set("kind", state.kind)?;
    let registers = Object::new(ctx.clone())?;
    for (name, bits) in state.registers {
        if let Ok(bits) = u64::from_str_radix(bits.strip_prefix("0x").unwrap_or(&bits), 16) {
            registers.set(name, BigInt::from_u64(ctx.clone(), bits)?)?;
        }
    }
    hit.set("registers", registers)?;
    if let Some(watch) = state.watch {
        let observation = Object::new(ctx.clone())?;
        if let Some(before) = watch.before {
            observation.set("valueBefore", BigInt::from_u64(ctx.clone(), before)?)?;
        }
        if let Some(after) = watch.after {
            observation.set("valueAfter", BigInt::from_u64(ctx.clone(), after)?)?;
        }
        if let Some(changed) = watch.changed {
            observation.set("changed", changed)?;
        }
        hit.set("watch", observation)?;
    }

    let read = Rc::new(HitReader {
        pid: state.pid,
        tid: state.tid,
        root: state.proc_root,
        registers: state.stack,
        tids: vec![state.tid],
        frame_regs: RefCell::default(),
        deadline,
        actions: Rc::clone(&actions),
    });
    bind_scope(&ctx, &hit, &read, &intrinsics)?;
    let snapshot_actions = Rc::clone(&actions);
    hit.set(
        "snapshot",
        Function::new(ctx.clone(), move |ctx: Ctx<'js>| {
            let mut slot = snapshot_actions.borrow_mut();
            let actions = slot
                .as_mut()
                .filter(|actions| !actions.closed)
                .ok_or_else(|| Exception::throw_message(&ctx, "debug read scope has ended"))?;
            actions.snapshot = true;
            Ok::<(), rquickjs::Error>(())
        })?,
    )?;

    hit.set(
        "disable",
        Function::new(ctx.clone(), move |ctx: Ctx<'js>| {
            let mut slot = actions.borrow_mut();
            let actions = slot
                .as_mut()
                .filter(|actions| !actions.closed)
                .ok_or_else(|| Exception::throw_message(&ctx, "debug read scope has ended"))?;
            actions.disable = true;
            Ok::<(), rquickjs::Error>(())
        })?,
    )?;

    let returned: Value<'js> = callback.call((hit,))?;
    if returned.is_promise() {
        return Err(Exception::throw_message(
            &ctx,
            "breakpoint callbacks must be synchronous",
        ));
    }
    Ok(returned.as_bool() == Some(false))
}

pub(crate) struct StoppedTarget {
    pub pid: i32,
    pub root: PathBuf,
    pub tids: Vec<i32>,
    pub focus: Option<i32>,
}

pub(super) fn setup_scope<'js>(
    ctx: &Ctx<'js>,
    scope: &Object<'js>,
    realm: &Realm,
    target: StoppedTarget,
    actions: Rc<RefCell<Option<Actions>>>,
    deadline: Instant,
) -> rquickjs::Result<CloseHit<'js>> {
    let tid = target
        .focus
        .filter(|tid| target.tids.contains(tid))
        .or_else(|| target.tids.contains(&target.pid).then_some(target.pid))
        .or_else(|| target.tids.first().copied())
        .unwrap_or(target.pid);
    let read = Rc::new(HitReader {
        pid: target.pid,
        tid,
        root: target.root,
        registers: crate::regs::read(tid)
            .map(|value| value.stack)
            .unwrap_or_else(|_| Registers::empty()),
        tids: target.tids,
        frame_regs: RefCell::default(),
        deadline,
        actions: Rc::clone(&actions),
    });
    let intrinsics = Rc::new(RefCell::new(Some((
        realm.data_view.clone().restore(ctx)?,
        realm.encode.clone().restore(ctx)?,
    ))));
    let close = CloseHit {
        intrinsics: Rc::clone(&intrinsics),
        actions,
    };
    bind_scope(ctx, scope, &read, &intrinsics)?;
    Ok(close)
}

fn bind_scope<'js>(
    ctx: &Ctx<'js>,
    scope: &Object<'js>,
    read: &Rc<HitReader>,
    intrinsics: &HitIntrinsics<'js>,
) -> rquickjs::Result<()> {
    let deadline = read.deadline;
    let output = Rc::clone(&read.actions);
    let memory_intrinsics = Rc::clone(intrinsics);
    super::debugger::bind(
        ctx,
        scope,
        Rc::clone(read),
        deadline,
        move |ctx| {
            memory_intrinsics
                .borrow()
                .as_ref()
                .map(|(constructor, _)| constructor.clone())
                .ok_or_else(|| Exception::throw_message(ctx, "debug read scope has ended"))
        },
        move |ctx, expression, label, report| {
            emit_field(
                ctx,
                &output,
                OutputField {
                    label: label.unwrap_or(expression),
                    value: FieldValue::Json(report),
                },
            )
        },
    )?;
    let state = Rc::clone(&read.actions);
    let emit_intrinsics = Rc::clone(intrinsics);
    scope.set(
        "emit",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>,
                  label: String,
                  value: Value<'js>,
                  options: rquickjs::function::Opt<Object<'js>>| {
                if state.borrow().as_ref().is_none_or(|actions| actions.closed) {
                    return Err(Exception::throw_message(&ctx, "debug read scope has ended"));
                }
                if Instant::now() >= deadline {
                    return Err(Exception::throw_message(
                        &ctx,
                        "callback pause budget exceeded",
                    ));
                }
                let kind: Option<String> = match options.0 {
                    Some(options) => options.get("kind")?,
                    None => None,
                };
                let encode = emit_intrinsics
                    .borrow()
                    .as_ref()
                    .expect("active synchronous callback")
                    .1
                    .clone();
                let field = OutputField {
                    label,
                    value: FieldValue::read(&ctx, &encode, value, kind.as_deref())?,
                };
                emit_field(&ctx, &state, field)
            },
        )?,
    )?;
    Ok(())
}

// A script can retain the hit object. Drop native closures' JS references at
// the end of the call so they cannot keep the realm alive through a Rust cycle.
type HitIntrinsics<'js> = Rc<RefCell<Option<(Constructor<'js>, Function<'js>)>>>;

pub(super) struct CloseHit<'js> {
    intrinsics: HitIntrinsics<'js>,
    actions: Rc<RefCell<Option<Actions>>>,
}

impl Drop for CloseHit<'_> {
    fn drop(&mut self) {
        self.intrinsics.borrow_mut().take();
        if let Some(actions) = self.actions.borrow_mut().as_mut() {
            actions.closed = true;
        }
    }
}

struct HitReader {
    pid: i32,
    tid: i32,
    root: PathBuf,
    registers: Registers,
    tids: Vec<i32>,
    frame_regs: RefCell<BTreeMap<String, (i32, Registers)>>,
    deadline: Instant,
    actions: Rc<RefCell<Option<Actions>>>,
}

impl HitReader {
    fn selected(&self, frame: Option<&str>) -> Result<(i32, Registers)> {
        match frame {
            None => Ok((self.tid, self.registers)),
            Some(handle) => self
                .frame_regs
                .borrow()
                .get(handle)
                .copied()
                .ok_or_else(|| {
                    crate::Diagnostic::new(
                        "NO_FRAME_CONTEXT",
                        "Frame is absent from this stopped target",
                        None,
                    )
                    .into()
                }),
        }
    }
}

impl super::debugger::Debugger for HitReader {
    fn threads(&self) -> Result<Json> {
        Ok(json!(
            self.tids
                .iter()
                .map(|tid| json!({"tid": tid}))
                .collect::<Vec<_>>()
        ))
    }

    fn modules(&self) -> Result<Json> {
        let modules = crate::modules::read(&self.root)?;
        let exe = std::fs::metadata(self.root.join("exe")).ok();
        Ok(json!(
            modules
                .iter()
                .enumerate()
                .map(|(id, module)| module.info(id, exe.as_ref(), None))
                .collect::<Vec<_>>()
        ))
    }

    fn frames(&self, tid: i32, deadline: Instant) -> Result<Json> {
        if !self.tids.contains(&tid) {
            return Err(error("TID is absent from this stopped target"));
        }
        let regs = if tid == self.tid {
            self.registers
        } else {
            crate::regs::read(tid)?.stack
        };
        let maps = crate::modules::read(&self.root)?;
        let exe = std::fs::metadata(self.root.join("exe")).ok();
        let mut images = crate::unwind::Images::new();
        let mut stored = self.frame_regs.borrow_mut();
        let mut stack = images.walk_registers(
            self,
            regs,
            &maps,
            &self.root,
            exe.as_ref(),
            deadline,
            |i, mut regs| {
                if i > 0 {
                    let pc = regs
                        .get(crate::regs::PC)
                        .ok()
                        .and_then(|pc| pc.checked_sub(1));
                    regs.set(crate::regs::PC, pc);
                }
                stored.insert(format!("live:{tid}:{i}"), (tid, regs));
            },
        );
        images.symbolize(&mut stack);
        let mut frames: Vec<_> = stack.frames.iter().enumerate().map(|(i, frame)| {
            let value = json!(frame);
            json!({"handle": format!("live:{tid}:{i}"), "pc": value["pc"],
                "function": value["function"], "file": value["file"], "line": value["line"], "column": value["column"]})
        }).collect();
        if let Some(first) = frames.first_mut() {
            let deadline = self
                .deadline
                .min(Instant::now() + std::time::Duration::from_millis(25));
            first["args"] = crate::symbols::inspect::stopped_arguments(
                self.pid, &self.root, self, regs, deadline,
            );
        }
        Ok(json!(frames))
    }

    fn inspect(
        &self,
        expression: String,
        frame: Option<&str>,
        expand: Option<crate::rpc::InspectExpansion>,
        deadline: Instant,
    ) -> Result<Json> {
        let (tid, registers) = match self.selected(frame) {
            Ok(selected) => selected,
            Err(error) => {
                return Ok(json!({
                    "status": "invalid_frame", "result": null, "issue": error.to_string(), "code": "NO_FRAME_CONTEXT",
                }));
            }
        };
        let report = inspect_stopped(
            self.pid, tid, expression, &self.root, self, registers, deadline, expand,
        );
        Ok(serde_json::to_value(report)?)
    }

    fn discover(
        &self,
        kind: crate::symbols::inspect::Discovery,
        frame: Option<&str>,
        pattern: &str,
        page: (usize, usize),
        deadline: Instant,
    ) -> Result<Json> {
        let (_, registers) = self.selected(frame)?;
        crate::symbols::inspect::discover_stopped(
            &self.root, self, registers, kind, pattern, page, deadline,
        )
    }

    fn read_prefix(&self, address: u64, bytes: &mut [u8]) -> Result<usize> {
        trace::read_process_prefix(self.pid, address, bytes, || Instant::now() < self.deadline)
    }

    fn check(&self, deadline: Instant) -> Result<()> {
        if self
            .actions
            .borrow()
            .as_ref()
            .is_none_or(|actions| actions.closed)
        {
            return Err(error("debug read scope has ended"));
        }
        if Instant::now() >= deadline {
            return Err(error("callback pause budget exceeded"));
        }
        Ok(())
    }
}

impl UnwindMemory for HitReader {
    fn read_word(&self, address: u64, size: usize) -> Result<u64> {
        if Instant::now() >= self.deadline {
            return Err(error("callback pause budget exceeded"));
        }
        trace::read_process_word(self.pid, address, size)
    }
}

pub(super) const ENCODE_VALUE: &str = r#"(() => {
    const call = Function.prototype.call.bind(Function.prototype.call);
    const { getOwnPropertyDescriptor, getPrototypeOf } = Object;
    const byteArray = Uint8Array;
    const typed = getPrototypeOf(byteArray.prototype);
    const typedTag = getOwnPropertyDescriptor(typed, Symbol.toStringTag).get;
    const view = DataView.prototype;
    const getters = proto => ["buffer", "byteOffset", "byteLength"]
        .map(key => getOwnPropertyDescriptor(proto, key).get);
    const viewGetters = getters(view);
    return value => {
        if (call(typedTag, value) === "Uint8Array") return value;
        const [buffer, offset, length] = viewGetters;
        let backing;
        try { backing = call(buffer, value); }
        catch { return undefined; }
        return new byteArray(backing, call(offset, value), call(length, value));
    };
})()"#;

fn emit_field(
    ctx: &Ctx<'_>,
    actions: &RefCell<Option<Actions>>,
    field: OutputField,
) -> rquickjs::Result<()> {
    let size = field.text().len();
    let mut slot = actions.borrow_mut();
    let actions = slot
        .as_mut()
        .filter(|actions| !actions.closed)
        .ok_or_else(|| Exception::throw_message(ctx, "debug read scope has ended"))?;
    if actions.fields.len() >= MAX_ROWS || actions.output_bytes + size > MAX_OUTPUT {
        return Err(Exception::throw_message(
            ctx,
            "breakpoint callback output limit exceeded",
        ));
    }
    actions.output_bytes += size;
    actions.fields.push(field);
    Ok(())
}

pub(super) struct OutputField {
    pub(super) label: String,
    pub(super) value: FieldValue,
}

impl OutputField {
    pub(super) fn json(&self) -> Json {
        let value = match &self.value {
            FieldValue::Integer(value) => {
                Json::Number(value.to_string().parse().expect("bigint is a JSON integer"))
            }
            FieldValue::Float(value) => json!(value),
            FieldValue::Pointer(_) | FieldValue::Bytes(_) => json!(self.value.text()),
            FieldValue::Text(value) => json!(value),
            FieldValue::Boolean(value) => json!(value),
            FieldValue::Null => Json::Null,
            FieldValue::Json(value) => value.clone(),
        };
        json!({"label": self.label, "value": value})
    }

    fn text(&self) -> String {
        let label = json!(self.label).to_string();
        format!("{}: {}", &label[1..label.len() - 1], self.value.text())
    }
}

pub(super) enum FieldValue {
    Integer(num_bigint::BigInt),
    Float(f64),
    Pointer(u64),
    Bytes(Vec<u8>),
    Text(String),
    Boolean(bool),
    Null,
    Json(Json),
}

impl FieldValue {
    pub(super) fn read<'js>(
        ctx: &Ctx<'js>,
        encode: &Function<'js>,
        value: Value<'js>,
        kind: Option<&str>,
    ) -> rquickjs::Result<Self> {
        if kind == Some("json") {
            return super::runtime::serialize_return(ctx, value).map(Self::Json);
        }
        if kind.is_some() || value.is_big_int() {
            if !value.is_big_int() || kind.is_some_and(|name| name != "pointer") {
                return Err(Exception::throw_type(
                    ctx,
                    "pointer output requires a bigint",
                ));
            }
            let Coerced(text) = Coerced::<String>::from_js(ctx, value)?;
            if kind.is_some() {
                return text.parse().map(Self::Pointer).map_err(|_| {
                    Exception::throw_range(ctx, "pointer must fit in an unsigned 64-bit integer")
                });
            }
            if text.len() > MAX_OUTPUT {
                return Err(Exception::throw_range(ctx, "oversized integer"));
            }
            let integer = text
                .parse()
                .map_err(|_| Exception::throw_type(ctx, "invalid bigint"))?;
            return Ok(Self::Integer(integer));
        }
        if let Some(number) = value.as_number() {
            if number.fract() == 0.0
                && number.abs() <= 9_007_199_254_740_991.0
                && !(number == 0.0 && number.is_sign_negative())
            {
                return Ok(Self::Integer(num_bigint::BigInt::from(number as i64)));
            }
            return Ok(Self::Float(number));
        }
        if let Some(text) = value.as_string() {
            return Ok(Self::Text(text.to_string()?));
        }
        if let Some(boolean) = value.as_bool() {
            return Ok(Self::Boolean(boolean));
        }
        if value.is_null() {
            return Ok(Self::Null);
        }
        if value.is_object()
            && let Some(view) = encode.call::<_, Option<rquickjs::TypedArray<u8>>>((value,))?
        {
            let bytes = view
                .as_bytes()
                .filter(|bytes| bytes.len() <= MAX_OUTPUT / 3)
                .ok_or_else(|| Exception::throw_range(ctx, "invalid or oversized byte view"))?;
            return Ok(Self::Bytes(bytes.to_vec()));
        }
        Err(Exception::throw_type(
            ctx,
            "emit expects a scalar value or byte view",
        ))
    }

    fn text(&self) -> String {
        match self {
            Self::Integer(integer) => {
                let sign = if integer.sign() == num_bigint::Sign::Minus {
                    "-"
                } else {
                    ""
                };
                format!("{integer} {sign}0x{:x}", integer.magnitude())
            }
            Self::Float(value) => format!("{value} f64 0x{:016x}", value.to_bits()),
            Self::Pointer(address) => format!("0x{address:x}"),
            Self::Bytes(bytes) => bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            Self::Text(text) => json!(text).to_string(),
            Self::Boolean(value) => value.to_string(),
            Self::Null => "null".into(),
            Self::Json(value) => value.to_string(),
        }
    }
}
