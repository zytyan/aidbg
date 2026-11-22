use super::breakpoint::{Actions, Engine, Realm, StoppedTarget, integer_option, setup_scope};
use crate::{Result, breakpoint::Kind, error};
use rquickjs::{
    BigInt, CatchResultExt, Coerced, Ctx, Exception, FromJs, Function, Module, Object, Persistent,
    Promise, Value, function::Opt,
};
use serde::Serialize;
use serde_json::Value as Json;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    time::{Duration, Instant},
};

pub(crate) type Handler = Persistent<Function<'static>>;
const SETUP_BUDGET: Duration = Duration::from_secs(1);

pub(crate) struct Install {
    pub kind: Kind,
    pub address: u64,
    pub handler: Option<Handler>,
    pub tid: Option<i32>,
    pub timeout_ms: u32,
}

#[derive(Serialize)]
pub struct RunResult {
    pub status: &'static str,
    pub stop_reason: &'static str,
    pub breakpoint_ids: Vec<u64>,
    pub issue: Option<String>,
    pub return_value: Json,
    pub output: Vec<Json>,
    #[serde(skip)]
    pub active: Vec<(u64, std::sync::Weak<()>)>,
}

#[derive(Default)]
struct Orchestration {
    active: bool,
    continuing: bool,
    resolve: Option<Handler>,
}

pub(crate) enum Evaluation {
    Complete(Json),
    Continue(AwaitEvents),
    ContinueReturning(Json),
}

pub(crate) struct AwaitEvents {
    promise: Persistent<Promise<'static>>,
    resolve: Handler,
    namespace: Option<Persistent<Object<'static>>>,
    budget: Duration,
    realm: Rc<Realm>,
}

impl AwaitEvents {
    pub fn finish(self, events: &[Json]) -> Result<Json> {
        let engine = &self.realm.engine;
        let deadline = Instant::now() + self.budget;
        engine.set_deadline(deadline);
        let result = self.realm.context.with(|ctx| {
            let run = || {
                let values = rquickjs::Array::from_js(
                    &ctx,
                    ctx.json_parse(
                        serde_json::to_vec(events)
                            .map_err(|e| Exception::throw_message(&ctx, &e.to_string()))?,
                    )?,
                )?;
                let bigint: Function = ctx.globals().get("BigInt")?;
                for (i, event) in events.iter().enumerate() {
                    let Some(fields) = event["callback"]["output"].as_array() else {
                        continue;
                    };
                    let row: Object = values.get(i)?;
                    let callback: Object = row.get("callback")?;
                    let output: rquickjs::Array = callback.get("output")?;
                    for (j, field) in fields.iter().enumerate() {
                        let Json::Number(number) = &field["value"] else {
                            continue;
                        };
                        let integer = number.to_string();
                        if integer
                            .trim_start_matches('-')
                            .bytes()
                            .all(|byte| byte.is_ascii_digit())
                            && number
                                .as_i64()
                                .is_none_or(|value| value.unsigned_abs() > 9_007_199_254_740_991)
                        {
                            let field: Object = output.get(j)?;
                            field.set("value", bigint.call::<_, Value>((integer,))?)?;
                        }
                    }
                }
                self.resolve.restore(&ctx)?.call::<_, ()>((values,))?;
                let mut value = self.promise.restore(&ctx)?.finish::<Value>()?;
                if let Some(namespace) = self.namespace {
                    value = super::runtime::call_default(&ctx, namespace.restore(&ctx)?)?;
                    if let Some(promise) = value.clone().into_promise() {
                        value = promise.finish()?;
                    }
                }
                super::runtime::serialize_return(&ctx, value)
            };
            run()
                .catch(&ctx)
                .map_err(|e| error(engine.diagnose(e, 4096)))
        });
        engine.check_jobs();
        if engine.poisoned() || Instant::now() >= deadline {
            return Err(error("live script completion exceeded its runtime limits"));
        }
        result
    }
}

// The JS function can escape into a breakpoint closure. Only the slot
// survives evaluation, and the guard clears it before the Rust borrow ends.
type InstallFn = unsafe fn(*mut (), Install) -> Result<u64>;
type InstallSlot = Cell<Option<(*mut (), InstallFn)>>;

struct ClearSlot(Rc<InstallSlot>);

impl Drop for ClearSlot {
    fn drop(&mut self) {
        self.0.set(None);
    }
}

pub(crate) fn evaluate<F>(
    realm: &Rc<Realm>,
    js: &str,
    replaying: bool,
    budget: Duration,
    target: StoppedTarget,
    output: &mut Vec<Json>,
    mut install: F,
) -> Result<Evaluation>
where
    F: FnMut(Install) -> Result<u64>,
{
    unsafe fn call<F: FnMut(Install) -> Result<u64>>(
        pointer: *mut (),
        request: Install,
    ) -> Result<u64> {
        // SAFETY: evaluate sets the slot from an exclusive borrow of this F.
        unsafe { (&mut *pointer.cast::<F>())(request) }
    }
    let slot = Rc::new(Cell::new(Some((
        (&mut install as *mut F).cast(),
        call::<F> as InstallFn,
    ))));
    let guard = ClearSlot(Rc::clone(&slot));
    let state = Rc::new(RefCell::new(Orchestration {
        active: true,
        ..Orchestration::default()
    }));
    let actions = Rc::new(RefCell::new(Some(Actions::default())));
    let result = evaluate_with(realm, budget, |ctx| {
        let dbg = Object::new(ctx.clone())?;
        let _scope = setup_scope(
            &ctx,
            &dbg,
            realm,
            target,
            Rc::clone(&actions),
            Instant::now() + budget,
        )?;
        install_api(ctx.clone(), dbg, slot, Rc::clone(&state))?;
        let (module, completion) =
            Module::declare(ctx.clone(), "live.js", js.as_bytes())?.eval()?;
        let namespace = module.namespace()?;
        let wait = |promise, namespace| {
            if replaying {
                return Err(Exception::throw_message(
                    &ctx,
                    "breakpoint replay cannot wait for live events",
                ));
            }
            let resolve = state.borrow_mut().resolve.take().ok_or_else(|| {
                Exception::throw_message(
                    &ctx,
                    "live script is waiting without dbg.events() and must complete synchronously",
                )
            })?;
            Ok(Evaluation::Continue(AwaitEvents {
                promise,
                resolve,
                namespace,
                budget,
                realm: Rc::clone(realm),
            }))
        };
        match completion.finish::<()>() {
            Ok(()) => {}
            Err(rquickjs::Error::WouldBlock) => {
                return wait(
                    Persistent::save(&ctx, completion),
                    Some(Persistent::save(&ctx, namespace)),
                );
            }
            Err(e) => return Err(e),
        }
        let value = super::runtime::call_default(&ctx, namespace)?;
        let value = if let Some(promise) = value.clone().into_promise() {
            match promise.finish::<Value>() {
                Ok(value) => value,
                Err(rquickjs::Error::WouldBlock) => {
                    return wait(Persistent::save(&ctx, promise), None);
                }
                Err(e) => return Err(e),
            }
        } else {
            value
        };
        let value = super::runtime::serialize_return(&ctx, value)?;
        let mut state = state.borrow_mut();
        state.resolve.take();
        Ok(if state.continuing && !replaying {
            Evaluation::ContinueReturning(value)
        } else {
            Evaluation::Complete(value)
        })
    });
    let mut state = state.borrow_mut();
    state.active = false;
    state.resolve.take();
    drop(guard);
    if let Some(actions) = actions.borrow().as_ref() {
        *output = actions.output();
    }
    result
}

fn install_api<'js>(
    ctx: Ctx<'js>,
    dbg: Object<'js>,
    slot: Rc<InstallSlot>,
    state: Rc<RefCell<Orchestration>>,
) -> rquickjs::Result<()> {
    let control = Rc::clone(&state);
    let installs = Rc::clone(&slot);
    dbg.set(
        "continue",
        Function::new(ctx.clone(), move |ctx: Ctx<'js>| {
            let mut state = control.borrow_mut();
            if !state.active || state.continuing {
                return Err(Exception::throw_message(
                    &ctx,
                    "dbg.continue() can be requested once during live script setup",
                ));
            }
            state.continuing = true;
            installs.set(None);
            Ok(())
        })?,
    )?;
    dbg.set(
        "events",
        Function::new(ctx.clone(), move |ctx: Ctx<'js>| {
            let mut state = state.borrow_mut();
            if !state.active || !state.continuing || state.resolve.is_some() {
                return Err(Exception::throw_message(
                    &ctx,
                    "await dbg.events() once after dbg.continue()",
                ));
            }
            let (promise, resolve, _) = Promise::new(&ctx)?;
            state.resolve = Some(Persistent::save(&ctx, resolve));
            Ok(promise)
        })?,
    )?;
    for (name, kind) in [
        ("hardwareBreakpoint", Kind::Hardware),
        ("softwareBreakpoint", Kind::Software),
    ] {
        let slot = Rc::clone(&slot);
        dbg.set(
            name,
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>,
                      address: BigInt<'js>,
                      callback: Opt<Value<'js>>,
                      options: Opt<Object<'js>>| {
                    install(&ctx, &slot, kind, address, callback.0, options.0)
                },
            )?,
        )?;
    }
    dbg.set(
        "watchpoint",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>,
                  address: BigInt<'js>,
                  length: f64,
                  access: String,
                  callback: Value<'js>,
                  options: Opt<Object<'js>>| {
                let length = match length {
                    1.0 => 1,
                    2.0 => 2,
                    4.0 => 4,
                    8.0 => 8,
                    _ => {
                        return Err(Exception::throw_range(
                            &ctx,
                            "watchpoint length must be 1, 2, 4, or 8",
                        ));
                    }
                };
                let access = match access.as_str() {
                    "write" => crate::breakpoint::WatchAccess::Write,
                    "read" => crate::breakpoint::WatchAccess::Read,
                    "read_write" => crate::breakpoint::WatchAccess::ReadWrite,
                    _ => {
                        return Err(Exception::throw_type(
                            &ctx,
                            "watchpoint access must be read, write or read_write",
                        ));
                    }
                };
                if !callback.is_function() {
                    return Err(Exception::throw_type(&ctx, "callback must be a function"));
                }
                install(
                    &ctx,
                    &slot,
                    Kind::Watch { length, access },
                    address,
                    Some(callback),
                    options.0,
                )
            },
        )?,
    )?;
    ctx.globals().set("dbg", dbg)
}

fn install<'js>(
    ctx: &Ctx<'js>,
    slot: &InstallSlot,
    kind: Kind,
    address: BigInt<'js>,
    callback: Option<Value<'js>>,
    options: Option<Object<'js>>,
) -> rquickjs::Result<Object<'js>> {
    let (data, call) = slot.get().ok_or_else(|| {
        Exception::throw_message(
            ctx,
            "breakpoints can only be installed by a live script at top level",
        )
    })?;
    let Coerced(address) = Coerced::<String>::from_js(ctx, address.into_value())?;
    let address = address
        .parse::<u64>()
        .ok()
        .filter(|address| *address > 0)
        .ok_or_else(|| {
            Exception::throw_range(ctx, "address must be a nonzero unsigned 64-bit bigint")
        })?;
    let (tid, timeout_ms) = match options {
        None => (None, 100),
        Some(options) => {
            let tid: Value = options.get("tid")?;
            let tid = if tid.is_undefined() {
                None
            } else {
                Some(
                    tid.as_number()
                        .filter(|n| n.fract() == 0.0 && (1.0..=f64::from(i32::MAX)).contains(n))
                        .ok_or_else(|| {
                            Exception::throw_range(ctx, "tid must be a positive Linux thread ID")
                        })? as i32,
                )
            };
            (tid, integer_option(ctx, &options, "timeoutMs", 100, 500)?)
        }
    };
    let handler = callback
        .filter(|value| !value.is_undefined())
        .map(|value| {
            value
                .into_function()
                .ok_or_else(|| Exception::throw_type(ctx, "callback must be a function"))
                .map(|function| Persistent::save(ctx, function))
        })
        .transpose()?;
    // SAFETY: the slot is thread-local and valid until evaluation returns.
    let id = unsafe {
        call(
            data,
            Install {
                kind,
                address,
                handler,
                tid,
                timeout_ms,
            },
        )
    }
    .map_err(|e| Exception::throw_message(ctx, &e.to_string()))?;
    let handle = Object::new(ctx.clone())?;
    handle.set("id", id)?;
    Ok(handle)
}

pub(crate) struct ExportModule {
    handlers: BTreeMap<String, Handler>,
    pub realm: Rc<Realm>,
}

impl ExportModule {
    pub fn load(engine: Rc<Engine>, js: &str) -> Result<Self> {
        let realm = Realm::new(engine)?;
        let handlers = evaluate_module(
            &realm,
            js,
            |_| Ok(()),
            |ctx, module| {
                let synchronous: Function = ctx.eval(
                "((proto, getPrototypeOf) => fn => getPrototypeOf(fn) === proto)(Function.prototype, Object.getPrototypeOf)",
            )?;
                let mut handlers = BTreeMap::new();
                for key in module.namespace()?.keys::<String>() {
                    let name = key?;
                    if name == "default" {
                        return Err(Exception::throw_type(&ctx, "use named callback exports"));
                    }
                    let function: Function = module.get(name.as_str())?;
                    if !synchronous.call::<_, bool>((function.clone(),))? {
                        return Err(Exception::throw_type(
                            &ctx,
                            "callback exports must be synchronous functions",
                        ));
                    }
                    handlers.insert(name, Persistent::save(&ctx, function));
                }
                if handlers.is_empty() {
                    return Err(Exception::throw_type(
                        &ctx,
                        "expected at least one named callback export",
                    ));
                }
                Ok(handlers)
            },
        )?;
        Ok(Self { handlers, realm })
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.handlers.keys().map(String::as_str)
    }

    pub fn handler(&self, name: &str) -> Result<Handler> {
        self.handlers
            .get(name)
            .cloned()
            .ok_or_else(|| error(format!("missing callback export {name}")))
    }
}

fn evaluate_module<T>(
    realm: &Realm,
    js: &str,
    setup: impl for<'js> FnOnce(Ctx<'js>) -> rquickjs::Result<()>,
    extract: impl for<'js> FnOnce(
        Ctx<'js>,
        Module<'js, rquickjs::module::Evaluated>,
    ) -> rquickjs::Result<T>,
) -> Result<T> {
    evaluate_with(realm, SETUP_BUDGET, |ctx| {
        setup(ctx.clone())?;
        let (module, completion) =
            Module::declare(ctx.clone(), "live.js", js.as_bytes())?.eval()?;
        let Some(completion) = completion.result::<()>() else {
            realm.engine.poison();
            return Err(Exception::throw_message(
                &ctx,
                "live scripts must complete synchronously",
            ));
        };
        completion?;
        extract(ctx, module)
    })
}

fn evaluate_with<T>(
    realm: &Realm,
    budget: Duration,
    run: impl for<'js> FnOnce(Ctx<'js>) -> rquickjs::Result<T>,
) -> Result<T> {
    let engine = &realm.engine;
    let deadline = Instant::now() + budget;
    engine.set_deadline(deadline);
    let result = realm.context.with(|ctx| {
        run(ctx.clone())
            .catch(&ctx)
            .map_err(|e| error(engine.diagnose(e, 4096)))
    });
    engine.check_jobs();
    if result.is_ok() && engine.poisoned() {
        return Err(error("live scripts must complete synchronously"));
    }
    if Instant::now() >= deadline {
        return Err(error("live script setup exceeded timeout_ms"));
    }
    result
}
