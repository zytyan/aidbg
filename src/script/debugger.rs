use super::runtime::{
    as_js, debug_value, debugger_reply, expansion, frame_handle, memory_view, page,
};
use crate::{Result, rpc::InspectExpansion};
use rquickjs::{
    BigInt, Ctx, Exception, Function, Object, Value,
    function::{Constructor, Opt},
};
use serde_json::Value as Json;
use std::ops::Deref;
use std::time::Instant;

use crate::symbols::inspect::Discovery;

pub(super) trait Debugger {
    fn check(&self, deadline: Instant) -> Result<()> {
        if Instant::now() >= deadline {
            return Err(crate::error("debugger time budget exceeded"));
        }
        Ok(())
    }
    fn threads(&self) -> Result<Json>;
    fn frames(&self, tid: i32, deadline: Instant) -> Result<Json>;
    fn modules(&self) -> Result<Json>;
    fn read_prefix(&self, address: u64, bytes: &mut [u8]) -> Result<usize>;
    fn discover(
        &self,
        kind: Discovery,
        frame: Option<&str>,
        pattern: &str,
        page: (usize, usize),
        deadline: Instant,
    ) -> Result<Json>;
    fn inspect(
        &self,
        expression: String,
        frame: Option<&str>,
        expand: Option<InspectExpansion>,
        deadline: Instant,
    ) -> Result<Json>;
}

pub(super) fn bind<'js, T: Debugger + 'static, H: Clone + Deref<Target = T> + 'js>(
    ctx: &Ctx<'js>,
    scope: &Object<'js>,
    target: H,
    deadline: Instant,
    data_view: impl Fn(&Ctx<'js>) -> rquickjs::Result<Constructor<'js>> + 'js,
    print: impl Fn(&Ctx<'js>, String, Option<String>, Json) -> rquickjs::Result<()> + 'js,
) -> rquickjs::Result<()> {
    let reader = target.clone();
    scope.set(
        "threads",
        Function::new(ctx.clone(), move |ctx: Ctx<'js>| {
            js(&ctx, reader.check(deadline))?;
            as_js(&ctx, js(&ctx, reader.threads())?)
        })?,
    )?;
    let reader = target.clone();
    scope.set(
        "frames",
        Function::new(ctx.clone(), move |ctx: Ctx<'js>, tid: i32| {
            js(&ctx, reader.check(deadline))?;
            as_js(&ctx, js(&ctx, reader.frames(tid, deadline))?)
        })?,
    )?;
    let reader = target.clone();
    scope.set(
        "modules",
        Function::new(ctx.clone(), move |ctx: Ctx<'js>| {
            js(&ctx, reader.check(deadline))?;
            as_js(&ctx, js(&ctx, reader.modules())?)
        })?,
    )?;
    let reader = target.clone();
    scope.set(
        "memory",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, address: BigInt<'js>, length: f64| {
                js(&ctx, reader.check(deadline))?;
                let constructor = data_view(&ctx)?;
                memory_view(&ctx, address, length, &constructor, |addr, bytes| {
                    js(&ctx, reader.read_prefix(addr, bytes))
                })
            },
        )?,
    )?;
    for (name, kind) in [("globals", Discovery::Globals), ("types", Discovery::Types)] {
        let reader = target.clone();
        scope.set(
            name,
            Function::new(
                ctx.clone(),
                move |ctx: Ctx<'js>, pattern: Opt<String>, options: Opt<Object<'js>>| {
                    js(&ctx, reader.check(deadline))?;
                    let page = page(&ctx, options, deadline)?;
                    debugger_reply(
                        &ctx,
                        reader.discover(
                            kind,
                            None,
                            pattern.0.as_deref().unwrap_or("*"),
                            page,
                            deadline,
                        ),
                    )
                },
            )?,
        )?;
    }
    let reader = target.clone();
    scope.set(
        "locals",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, first: Opt<Value<'js>>, second: Opt<Object<'js>>| {
                js(&ctx, reader.check(deadline))?;
                let (frame, options) = match first.0 {
                    Some(first) if first.is_string() => (Some(first), second.0),
                    Some(first) => match first.into_object() {
                        Some(object) if object.contains_key("handle")? => {
                            (Some(object.into_value()), second.0)
                        }
                        options => (None, options.or(second.0)),
                    },
                    None => (None, second.0),
                };
                let handle = frame.map(|value| frame_handle(&ctx, value)).transpose()?;
                let page = page(&ctx, Opt(options), deadline)?;
                debugger_reply(
                    &ctx,
                    reader.discover(Discovery::Locals, handle.as_deref(), "*", page, deadline),
                )
            },
        )?,
    )?;
    let reader = target.clone();
    scope.set(
        "inspect",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, expression: String, options: Opt<Object<'js>>| {
                debug_value(
                    &ctx,
                    inspect(&*reader, &ctx, expression, options.0.as_ref(), deadline)?,
                )
            },
        )?,
    )?;
    scope.set(
        "printVal",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, expression: String, options: Opt<Object<'js>>| {
                let report = inspect(
                    &*target,
                    &ctx,
                    expression.clone(),
                    options.0.as_ref(),
                    deadline,
                )?;
                let label = options
                    .0
                    .map(|options| options.get::<_, Option<String>>("label"))
                    .transpose()?
                    .flatten();
                print(&ctx, expression, label, report)
            },
        )?,
    )?;
    Ok(())
}

fn inspect<'js>(
    target: &impl Debugger,
    ctx: &Ctx<'js>,
    expression: String,
    options: Option<&Object<'js>>,
    deadline: Instant,
) -> rquickjs::Result<Json> {
    js(ctx, target.check(deadline))?;
    let frame = options
        .map(|options| options.get::<_, Option<Value>>("frame"))
        .transpose()?
        .flatten()
        .map(|frame| frame_handle(ctx, frame))
        .transpose()?;
    js(
        ctx,
        target.inspect(expression, frame.as_deref(), expansion(options)?, deadline),
    )
}

fn js<T>(ctx: &Ctx<'_>, result: Result<T>) -> rquickjs::Result<T> {
    result.map_err(|error| Exception::throw_message(ctx, &error.to_string()))
}
