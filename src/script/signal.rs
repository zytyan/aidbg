use crate::{Result, error};
use nix::sys::signal::Signal;
use rquickjs::{
    BigInt, CatchResultExt, Context, Ctx, Exception, Function, Module, Object, Persistent, Runtime,
    Value,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    time::{Duration, Instant},
};

pub(crate) struct Handlers {
    callbacks: BTreeMap<Signal, Persistent<Function<'static>>>,
    action: Rc<Cell<Option<bool>>>,
    deadline: Rc<Cell<Instant>>,
    context: Context,
    runtime: Runtime,
}

pub(crate) struct SignalEvent {
    pub pid: i32,
    pub tid: i32,
    pub signal: Signal,
    pub code: i32,
    pub fault_address: Option<u64>,
}

fn supported(signal: Signal) -> bool {
    !matches!(
        signal,
        Signal::SIGKILL | Signal::SIGSTOP | Signal::SIGSTKFLT | Signal::SIGPWR
    )
}

fn js_error(message: impl ToString) -> Box<dyn std::error::Error + Send + Sync> {
    error(message.to_string().chars().take(1024).collect::<String>())
}

impl Handlers {
    pub fn load(js: &str) -> Result<Self> {
        let deadline = Rc::new(Cell::new(Instant::now() + Duration::from_millis(100)));
        let runtime = Runtime::new()?;
        runtime.set_memory_limit(16 * 1024 * 1024);
        runtime.set_max_stack_size(256 * 1024);
        let clock = deadline.clone();
        runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= clock.get())));
        let context = Context::full(&runtime)?;
        let action = Rc::new(Cell::new(None));
        let callbacks = context.with(|ctx| install(ctx, js, action.clone()))?;
        if runtime.is_job_pending() {
            return Err(error("signal script setup must be synchronous"));
        }
        Ok(Self {
            callbacks,
            action,
            deadline,
            context,
            runtime,
        })
    }

    pub fn contains(&self, signal: Signal) -> bool {
        self.callbacks.contains_key(&signal)
    }

    pub fn invoke(&mut self, event: SignalEvent, deadline: Instant) -> Result<bool> {
        let Some(handler) = self.callbacks.get(&event.signal) else {
            return Ok(false);
        };
        self.deadline
            .set(deadline.min(Instant::now() + Duration::from_millis(100)));
        self.action.set(Some(false));
        let result = self.context.with(|ctx| {
            let call = || -> rquickjs::Result<()> {
                let arg = Object::new(ctx.clone())?;
                arg.set("pid", event.pid)?;
                arg.set("tid", event.tid)?;
                arg.set("signal", event.signal as i32)?;
                arg.set("name", event.signal.as_str())?;
                arg.set("code", event.code)?;
                if let Some(address) = event.fault_address {
                    arg.set("faultAddress", BigInt::from_u64(ctx.clone(), address)?)?;
                } else {
                    arg.set("faultAddress", Value::new_null(ctx.clone()))?;
                }
                let result: Value = handler.clone().restore(&ctx)?.call((arg,))?;
                if result.is_promise() {
                    return Err(Exception::throw_message(
                        &ctx,
                        "signal callbacks must be synchronous",
                    ));
                }
                Ok(())
            };
            call().catch(&ctx).map_err(js_error)
        });
        let dump = self.action.replace(None).unwrap_or(false);
        let result = result.and_then(|()| {
            if self.runtime.is_job_pending() {
                return Err(error("signal callbacks must be synchronous"));
            }
            Ok(dump)
        });
        if result.is_err() {
            // A failed handler may have queued work. Discard its registrations.
            self.callbacks.clear();
        }
        result
    }
}

fn install<'js>(
    ctx: Ctx<'js>,
    js: &str,
    action: Rc<Cell<Option<bool>>>,
) -> Result<BTreeMap<Signal, Persistent<Function<'static>>>> {
    let registered = Rc::new(RefCell::new(Some(BTreeMap::new())));
    let callbacks = registered.clone();
    let setup = || -> rquickjs::Result<()> {
        let globals = ctx.globals();
        globals.remove("SharedArrayBuffer")?;
        globals.remove("Atomics")?;
        let builtins = Object::new(ctx.clone())?;
        for signal in Signal::iterator().filter(|&s| supported(s)) {
            builtins.set(signal.as_str(), signal as i32)?;
        }
        globals.set("builtins", builtins)?;
        let dbg = Object::new(ctx.clone())?;
        dbg.set(
            "onSignal",
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, number: i32, callback: Function<'js>| {
                    let signal = Signal::try_from(number)
                        .ok()
                        .filter(|&s| supported(s))
                        .ok_or_else(|| {
                            Exception::throw_type(&ctx, "expected a supported signal")
                        })?;
                    let mut callbacks = callbacks.borrow_mut();
                    let callbacks = callbacks.as_mut().ok_or_else(|| {
                        Exception::throw_message(&ctx, "onSignal is only available during setup")
                    })?;
                    if callbacks.contains_key(&signal) {
                        return Err(Exception::throw_message(
                            &ctx,
                            "signal already has a callback",
                        ));
                    }
                    callbacks.insert(signal, Persistent::save(&ctx, callback));
                    Ok(())
                },
            )?,
        )?;
        dbg.set(
            "coredump",
            Function::new(ctx.clone(), move |ctx: Ctx<'js>, mode: String| {
                if mode != "full" || action.get() != Some(false) {
                    return Err(Exception::throw_message(
                        &ctx,
                        "coredump requires mode full and can be requested once per signal callback",
                    ));
                }
                action.set(Some(true));
                Ok(())
            })?,
        )?;
        globals.set("dbg", dbg)?;
        Module::evaluate(ctx.clone(), "signal.js", js.as_bytes())?.finish::<()>()
    };
    let result = setup().catch(&ctx).map_err(js_error);
    let callbacks = registered.borrow_mut().take().unwrap_or_default();
    result?;
    Ok(callbacks)
}
